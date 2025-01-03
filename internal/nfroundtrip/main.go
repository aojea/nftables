package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		log.Fatalf("need to specify the table and chain to list")
	}

	c, err := nftables.New(
		nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			for _, msg := range req {
				log.Printf("header:\n%d\n%s | %s\n%d\n%d",
					msg.Header.Length,
					msg.Header.Type.String(), msg.Header.Flags.String(),
					msg.Header.Sequence,
					msg.Header.PID)
				log.Printf("data:\n%s", nfdump(msg.Data))
			}
			return req, nil
		}),
	)
	if err != nil {
		log.Fatalf("nftables.New() failed: %v", err)
	}

	table, err := c.ListTableOfFamily(args[0], nftables.TableFamilyINet)
	if err != nil {
		log.Fatalf("ListTableOfFamily failed: %v", err)
	}

	chain, err := c.ListChain(table, args[1])
	if err != nil {
		log.Fatalf("ListChain failed: %v", err)
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		log.Fatalf("GetRules failed: %v", err)
	}
	for _, rule := range rules {
		log.Printf("rule position %d", rule.Position)
		for _, exp := range rule.Exprs {
			fmt.Printf("%#v\n", exp)
		}
	}
}
