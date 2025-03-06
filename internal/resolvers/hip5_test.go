package resolvers

import (
	"context"
	"errors"
	"fmt"
	"github.com/randomlogin/sane/resolver"
	"github.com/miekg/dns"
	"testing"
	"time"
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

	h.exchangeRoot = testExchangeRootFunc(t, "com.",
		[]dns.RR{testRR("forever. 300 IN NS root-extension._example.")})

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

func testRR(str string) dns.RR {
	rr, err := dns.NewRR(str)
	if err != nil {
		panic(err)
	}

	return rr
}

type rootFunc func(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error)

func testExchangeRootFunc(t *testing.T, tld string, nsRRs []dns.RR) rootFunc {
	return func(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error) {
		m.Rcode = dns.RcodeSuccess
		if m.Question[0].Name != tld {
			t.Fatalf("got tld = %s, want %s", m.Question[0].Name, tld)
		}

		m.Ns = nsRRs
		return m, 0, nil
	}
}

func TestHIP5CNames(t *testing.T) {
	recursive := map[string]*resolver.DNSResult{
		"example.com.": {
			Records: []dns.RR{testRR("example.com. 80000   IN      A       93.184.216.34")},
		},
		"secure.test.": {
			Records: []dns.RR{testRR("secure.test. 80000   IN      A       93.184.216.34")},
			Secure:  true,
		},
		"blog.secure.test.": {
			Records: []dns.RR{
				testRR("_443._tcp.secure.test. 80000   IN   A   1.1.1.1"),
				testRR("_443._tcp.secure.test. 80000   IN   A   1.0.0.1"),
			},
			Secure: true,
		},
	}

	hip5Data := map[string][]dns.RR{
		"secure.forever.":            {testRR("secure.forever. 300  IN  CNAME secure.test.")},
		"blog.secure.forever.":       {testRR("blog.secure.forever. 300  IN  CNAME blog.secure.test.")},
		"loop.forever.":              {testRR("loop.forever. 300 IN CNAME loop.forever.")},
		"hello.forever.":             {testRR("hello.forever. 300 IN CNAME example.com.")},
		"hello2.forever.":            {testRR("hello2.forever. 300 IN CNAME hello.forever.")},
		"hello3.forever.":            {testRR("hello3.forever. 300 IN CNAME hello2.forever.")},
		"redirect.forever.":          {testRR("redirect.forever. 300 IN CNAME secure.forever.")},
		"redirect-insecure.forever.": {testRR("redirect-insecure.forever. 300 IN CNAME hello.forever.")},
		"indirect-loop.forever.":     {testRR("indirect-loop.forever. 300 IN CNAME loop.forever.")},
	}

	tests := map[string]*resolver.DNSResult{
		"secure.forever.": {
			Records: recursive["secure.test."].Records,
			Secure:  true,
		},
		"blog.secure.forever.": {
			Records: recursive["blog.secure.test."].Records,
			Secure:  true,
		},
		"loop.forever.": {
			Records: []dns.RR{},
			Err:     errBadCNAMETarget,
		},
		"hello.forever.": {
			Records: recursive["example.com."].Records,
		},
		"redirect.forever.": {
			Records: recursive["secure.test."].Records,
			Secure:  true,
		},
		"redirect-insecure.forever.": {
			Records: recursive["example.com."].Records,
		},
		"indirect-loop.forever.": {
			Err: errBadCNAMETarget,
		},
		"hello3.forever.": {
			Records: recursive["example.com."].Records,
		},
		"hello12.forever.": {
			Err: errMaxDepthReached,
		},
	}

	// long CNAME chain
	for i := 4; i < 13; i++ {
		name := fmt.Sprintf("hello%d.forever.", i)
		prev := fmt.Sprintf("hello%d.forever.", i-1)
		hip5Data[name] = []dns.RR{testRR(name + " 300 IN CNAME " + prev)}
	}

	dummyResolver := resolver.DefaultResolver{
		Query: func(ctx context.Context, name string, qtype uint16) *resolver.DNSResult {
			if res, ok := recursive[name]; ok {
				return res
			}

			return &resolver.DNSResult{
				Records: nil,
				Secure:  false,
				Err:     resolver.ErrServFail,
			}
		},
	}

	stub := &resolver.Stub{DefaultResolver: dummyResolver}

	h := NewHIP5Resolver(stub, "0.0.0.0", func() bool {
		return true
	})

	h.exchangeRoot = testExchangeRootFunc(t, "forever.",
		[]dns.RR{testRR("forever. 300 IN NS bQHW1R4+11NRs0iWlCxlwyZZ1BxFVXqkNt+gszVTVl0=._example.")})

	h.RegisterHandler("_example", func(ctx context.Context, qname string, qtype uint16, ns *dns.NS) ([]dns.RR, error) {
		if ans, ok := hip5Data[qname]; ok {
			return ans, nil
		}

		return nil, fmt.Errorf("unexpected qname = %s", qname)
	})

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ips, secure, err := h.LookupIP(context.Background(), "ip4", name)
			if err != test.Err {
				if err == nil || test.Err == nil || !errors.Is(err, test.Err) {
					t.Fatalf("got err = %v, want = %v", err, test.Err)
				}
			}

			if secure != test.Secure {
				t.Fatalf("got secure = %v, want = %v", secure, test.Secure)
			}

			if len(ips) != len(test.Records) {
				t.Fatalf("got results len = %d, want %d", len(ips), len(test.Records))
			}
		})
	}
}
