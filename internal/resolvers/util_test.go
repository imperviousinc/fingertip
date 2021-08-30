package resolvers

import (
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestLastNLabels(t *testing.T) {
	tests := []struct {
		name string
		n    int
		out  string
	}{
		{
			name: "example.com",
			n:    1,
			out:  "com",
		},
		{
			name: "www.test.example.",
			n:    2,
			out:  "test.example",
		},
		{
			name: "www.example.FOO.",
			n:    5,
			out:  "www.example.foo",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := LastNLabels(test.name, test.n)
			if out != test.out {
				t.Fatalf("got %s, want %s", out, test.out)
			}
		})
	}
}

func Test_getTTL(t *testing.T) {
	if ttl := getTTL([]dns.RR{
		testRR("example. 300 IN A 127.0.0.1"),
	}); ttl != 300*time.Second {
		t.Fatalf("got ttl = %v, want %v", ttl, 300*time.Second)
	}

	if ttl := getTTL([]dns.RR{
		testRR("example. 5 IN A 127.0.0.1"),
	}); ttl != time.Minute {
		t.Fatalf("got ttl = %v, want %v", ttl, time.Minute)
	}

	if ttl := getTTL([]dns.RR{
		testRR("example. 0 IN A 127.0.0.1"),
		testRR("example. 300 IN A 127.0.0.1"),
	}); ttl != time.Minute {
		t.Fatalf("got ttl = %v, want %v", ttl, time.Minute)
	}
}
