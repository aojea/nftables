package nftest

import (
	"log"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

// OpenSystemConn returns a netlink connection that tests against
// the running kernel in a separate network namespace.
// nftest.CleanupSystemConn() must be called from a defer to cleanup
// created network namespace.
func OpenSystemConn(t *testing.T, enableSysTests bool) (*nftables.Conn, netns.NsHandle) {
	t.Helper()
	if !enableSysTests {
		t.SkipNow()
	}
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in nftest.CleanupSystemConn().
	runtime.LockOSThread()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New() failed: %v", err)
	}
	opts := []nftables.ConnOption{nftables.WithNetNSFd(int(ns))}
	if false {
		opts = append(opts, nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			for _, msg := range req {
				log.Printf("header:\n%d\n%s | %s\n%d\n%d\n",
					msg.Header.Length,
					msg.Header.Type.String(), msg.Header.Flags.String(),
					msg.Header.Sequence,
					msg.Header.PID)
				log.Printf("data:\n%s", nfdump(msg.Data))
				ad, err := netlink.NewAttributeDecoder(msg.Data)
				if err != nil {
					log.Printf("failed to create attribute decoder: %v", err)
					continue
				}
				for ad.Next() {
					log.Printf("tlv:\n%d|%d|%d", ad.Type(), ad.Len(), ad.TypeFlags())
					log.Printf("attr:%s\n", ad.String())
				}
			}
			return req, nil
		}))
	}

	c, err := nftables.New(opts...)
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}
	return c, ns
}

func CleanupSystemConn(t *testing.T, newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
}
