package resolvers

import (
	"context"
	"errors"
	"github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"testing"
)

func TestNewHIP5Resolver(t *testing.T) {
	dummyResolver := resolver.DefaultResolver{
		Query: func(ctx context.Context, name string, qtype uint16) *resolver.DNSResult {
			return &resolver.DNSResult{
				Records: nil,
				Secure:  false,
				Err:     resolver.ErrServFail,
			}
		},
	}

	synced := false
	stub := &resolver.Stub{DefaultResolver: dummyResolver}

	h := NewHIP5Resolver(stub, "0.0.0.0", func() bool {
		return synced
	})

	h.queryExtension = func(ctx context.Context, tld string) ([]*dns.NS, error) {
		if tld != "com" {
			t.Fatalf("got tld = %s, want %s", tld, "com")
		}

		return []*dns.NS{{Ns: "bQHW1R4+11NRs0iWlCxlwyZZ1BxFVXqkNt+gszVTVl0=._example."}}, nil
	}

	var errNoPancakes = errors.New("couldn't make pancakes")
	h.RegisterHandler("_example", func(ctx context.Context, qname string, qtype uint16, ns *dns.NS) ([]dns.RR, error) {
		return nil, errNoPancakes
	})

	// has no hip-5 extension but shouldn't resolve until synced
	_, _, err := h.LookupIP(context.Background(), "ip", "example.net")
	if !errors.Is(err, errNotSynced) {
		t.Fatalf("got err = %v, want %v", err, errNotSynced)
	}

	// chain synced
	synced = true

	_, _, err = h.LookupIP(context.Background(), "ip", "example.com")
	if !errors.Is(err, errNoPancakes) {
		t.Fatalf("got err = %v, want %v", err, errNoPancakes)
	}
}
