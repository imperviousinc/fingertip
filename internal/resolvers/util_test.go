package resolvers

import (
	"testing"
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
