// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package userdata_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/internal/nftest"
	"github.com/google/nftables/userdata"
	"github.com/vishvananda/netlink"
)

var enableSysTests = flag.Bool("run_system_tests", false, "Run tests that operate against the live kernel")

type nftCliMetainfo struct {
	Version           string `json:"version,omitempty"`
	ReleaseName       string `json:"release_name,omitempty"`
	JSONSchemaVersion int    `json:"json_schema_version,omitempty"`
}

type nftCliTable struct {
	Family string `json:"family,omitempty"`
	Name   string `json:"name,omitempty"`
	Handle int    `json:"handle,omitempty"`
}

type nftCliChain struct {
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Name   string `json:"name,omitempty"`
	Handle int    `json:"handle,omitempty"`
}

type nftCliExpr struct{}

type nftCliRule struct {
	Family  string       `json:"family,omitempty"`
	Table   string       `json:"table,omitempty"`
	Chain   string       `json:"chain,omitempty"`
	Handle  int          `json:"handle,omitempty"`
	Comment string       `json:"comment,omitempty"`
	Expr    []nftCliExpr `json:"expr"`
}

type nftCommand struct {
	Ruleset interface{}  `json:"ruleset"`
	Table   *nftCliTable `json:"table,omitempty"`
	Chain   *nftCliChain `json:"chain,omitempty"`
	Rule    *nftCliRule  `json:"rule,omitempty"`
}

type nftCliObject struct {
	Metainfo *nftCliMetainfo `json:"metainfo,omitempty"`
	Table    *nftCliTable    `json:"table,omitempty"`
	Chain    *nftCliChain    `json:"chain,omitempty"`
	Rule     *nftCliRule     `json:"rule,omitempty"`
	Add      *nftCommand     `json:"add,omitempty"`
	Flush    *nftCommand     `json:"flush,omitempty"`
}

type nftCli struct {
	Nftables []nftCliObject `json:"nftables"`
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func TestExpressions(t *testing.T) {
	devices := []string{"dummy0"}

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	nft, newNS := nftest.OpenSystemConn(t, true)
	defer nftest.CleanupSystemConn(t, newNS)

	la := netlink.NewLinkAttrs()
	la.Name = "dummy0"
	la.TxQLen = 1500
	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}

	input := `
	table inet test-table { # handle 49
        set test-set { # handle 2
                type ifname
                elements = { dummy0 }
        }

        flowtable test-flowtable {
                hook ingress priority 5
								devices = { dummy0 }
        }

        chain test-chain { # handle 3
                type filter hook forward priority -150; policy accept;
                iifname != @test-set return
                oifname != @test-set return
                ct state established ct packets > 20 flow add @test-flowtable counter
        }
}
`

	d := exec.Command("nft", "--debug=netlink", "-f", "-")
	stdin, err := d.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, input)
	}()

	out, err := d.CombinedOutput()
	if err != nil {
		t.Fatalf("error executing command %s : %v", string(out), err)
	}
	t.Logf("------------------------ Output after nft commands:\n%s", string(out))

	d = exec.Command("nft", "list", "ruleset")
	out1, err := d.CombinedOutput()
	if err != nil {
		t.Fatalf("error executing command %s : %v", string(out1), err)
	}
	t.Logf("------------------------ nft list ruleset:\n%s", string(out1))

	// dump with go-nftables
	table := &nftables.Table{
		Name:   "test-table",
		Family: nftables.TableFamilyINet,
	}
	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	chain := &nftables.Chain{
		Name:  "test-chain",
		Table: table,
	}

	rules, err := nft.GetRules(table, chain)
	if err != nil {
		// t.Fatal(err)
	}

	buf := bytes.NewBufferString("")
	for _, rule := range rules {
		fmt.Fprintf(buf, "\n")
		for _, exp := range rule.Exprs {
			fmt.Fprintf(buf, "%#v,\n", exp)
		}
	}
	t.Logf("------------------------ go-nftables dump\n%s\n", buf.String())

	nft.FlushRuleset()
	// add + delete + add for flushing all the table
	table = nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "test-table",
	})

	devicesSet := &nftables.Set{
		Table:        table,
		Name:         "test-set",
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
	}

	elements := []nftables.SetElement{}
	for _, dev := range devices {
		elements = append(elements, nftables.SetElement{
			Key: ifname(dev),
		})
	}

	if err := nft.AddSet(devicesSet, elements); err != nil {
		t.Errorf("failed to add Set %s : %v", devicesSet.Name, err)
	}

	flowtable := &nftables.Flowtable{
		Table:    table,
		Name:     "test-flowtable",
		Devices:  devices,
		Hooknum:  nftables.FlowtableHookIngress,
		Priority: nftables.FlowtablePriorityRef(5),
	}
	nft.AddFlowtable(flowtable)

	chain = nft.AddChain(&nftables.Chain{
		Name:     "test-chain",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle, // before DNAT
	})

	// only offload devices that are being tracked
	// TODO: check if this is really needed, we are using a set in addition
	// to the flowtable.
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, SourceRegister: false, Register: 0x1},
			&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetName: "test-set", Invert: true},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, SourceRegister: false, Register: 0x1},
			&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetName: "test-set", Invert: true},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeySTATE, Direction: 0x0},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 0x4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: 0x1, Register: 0x1, Data: []uint8{0x0, 0x0, 0x0, 0x0}},
			&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeyPKTS, Direction: 0x0},
			&expr.Cmp{Op: expr.CmpOpGt, Register: 0x1, Data: binaryutil.NativeEndian.PutUint64(20)},
			&expr.FlowOffload{Name: "test-flowtable"},
			&expr.Counter{},
		},
	})

	if err := nft.Flush(); err != nil {
		t.Fatal(err)
	}

	d = exec.Command("nft", "list", "ruleset")
	out2, err := d.CombinedOutput()
	if err != nil {
		t.Fatalf("error executing command %s : %v", string(out2), err)
	}

	t.Logf("------------------------ nft list ruleset:\n%s", string(out2))

	nft.DelTable(table)

	if err := nft.Flush(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out1, out2) {
		t.Fatalf("failed to match output: %s", cmp.Diff(string(out1), string(out2)))
	}

}

func TestCommentInteropGo2Cli(t *testing.T) {
	wantComment := "my comment"

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Name:   "userdata-table",
		Family: nftables.TableFamilyIPv4,
	})

	chain := c.AddChain(&nftables.Chain{
		Name:  "userdata-chain",
		Table: table,
	})

	c.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: userdata.AppendString(nil, userdata.TypeComment, wantComment),
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	out := bytes.NewBuffer(nil)
	d := exec.Command("nft", "-j", "list", "table", "userdata-table")
	d.Stdout = out
	if err := d.Run(); err != nil {
		t.Fatal(err)
	}

	var outJson nftCli
	if err := json.Unmarshal(out.Bytes(), &outJson); err != nil {
		t.Fatal()
	}

	found := 0
	for _, e := range outJson.Nftables {
		if e.Rule == nil || e.Rule.Handle == 0 {
			continue
		}

		if e.Rule.Comment != wantComment {
			t.Fatal()
		}

		found++
	}

	if found != 1 {
		t.Fatalf("found %d rules", found)
	}

	c.DelTable(table)

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestCommentInteropCli2Go(t *testing.T) {
	wantComment := "my comment"

	inJson := nftCli{
		Nftables: []nftCliObject{
			{
				Metainfo: &nftCliMetainfo{
					JSONSchemaVersion: 1,
				},
			},
			{
				Flush: &nftCommand{
					Ruleset: nil,
				},
			},
			{
				Add: &nftCommand{
					Table: &nftCliTable{
						Family: "ip",
						Name:   "userdata-table",
					},
				},
			},
			{
				Add: &nftCommand{
					Chain: &nftCliChain{
						Family: "ip",
						Name:   "userdata-chain",
						Table:  "userdata-table",
					},
				},
			},
			{
				Add: &nftCommand{
					Rule: &nftCliRule{
						Family:  "ip",
						Table:   "userdata-table",
						Chain:   "userdata-chain",
						Comment: wantComment,
						Expr:    []nftCliExpr{},
					},
				},
			},
		},
	}

	in := bytes.NewBuffer(nil)
	if err := json.NewEncoder(in).Encode(inJson); err != nil {
		t.Fatal()
	}

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	d := exec.Command("nft", "-j", "-f", "-")
	d.Stdin = in
	if err := d.Run(); err != nil {
		t.Fatal(err)
	}

	table := &nftables.Table{
		Name:   "userdata-table",
		Family: nftables.TableFamilyIPv4,
	}

	chain := &nftables.Chain{
		Name:  "userdata-chain",
		Table: table,
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != 1 {
		t.Fatal()
	}

	if comment, ok := userdata.GetString(rules[0].UserData, userdata.TypeComment); !ok {
		t.Fatalf("failed to find comment")
	} else if comment != wantComment {
		t.Fatalf("comment mismatch %q != %q", comment, wantComment)
	}
}
