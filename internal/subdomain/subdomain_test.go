package subdomain

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// Only names that resolve are reported, and the order never varies.
func TestEnumerateReportsOnlyWhatResolves(t *testing.T) {
	live := map[string][]string{
		"staging.example.com": {"203.0.113.10"},
		"api.example.com":     {"203.0.113.11", "203.0.113.12"},
	}
	var looked atomic.Int64
	res := Enumerate(context.Background(), Options{
		Domain: "example.com",
		Labels: []string{"api", "staging", "nope", "alsonope"},
		Resolver: func(_ context.Context, host string) ([]string, error) {
			looked.Add(1)
			if a, ok := live[host]; ok {
				return a, nil
			}
			return nil, errors.New("no such host")
		},
	})

	if got := len(res.Hosts); got != 2 {
		t.Fatalf("reported %d hosts, want 2: a name that does not resolve is not a "+
			"discovery, and reporting it would send the operator chasing nothing", got)
	}
	// Sorted: a scan of an unchanged domain must produce an unchanged report,
	// and goroutine completion order is not stable.
	if res.Hosts[0].Name != "api.example.com" || res.Hosts[1].Name != "staging.example.com" {
		t.Errorf("order is %s, %s; not sorted", res.Hosts[0].Name, res.Hosts[1].Name)
	}
	// The addresses are the evidence that the name exists.
	if len(res.Hosts[0].Addrs) != 2 {
		t.Errorf("api.example.com carries %d addresses, want the 2 it resolved to",
			len(res.Hosts[0].Addrs))
	}
	// And how many were tried, so a report can state its own coverage.
	if res.Tried != 4 {
		t.Errorf("Tried = %d, want 4: a report that does not say how many names it "+
			"asked about implies it asked about all of them", res.Tried)
	}
	if looked.Load() != 4 {
		t.Errorf("%d lookups for 4 labels", looked.Load())
	}
}

// Nothing is looked up without a domain and a list. A default that guessed
// either would send DNS traffic nobody asked for.
func TestEnumerateDoesNothingWithoutBothInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    Options
	}{
		{"no domain", Options{Labels: []string{"api"}}},
		{"no labels", Options{Domain: "example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var looked atomic.Int64
			tc.o.Resolver = func(context.Context, string) ([]string, error) {
				looked.Add(1)
				return []string{"203.0.113.1"}, nil
			}
			if res := Enumerate(context.Background(), tc.o); len(res.Hosts) != 0 {
				t.Errorf("reported %d hosts", len(res.Hosts))
			}
			if looked.Load() != 0 {
				t.Errorf("%d DNS lookups were made", looked.Load())
			}
		})
	}
}

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"app.example.com":         "example.com",
		"example.com":             "example.com",
		"deep.nested.example.com": "example.com",
		"EXAMPLE.COM":             "example.com",
		"example.com:8443":        "example.com",
		"localhost":               "",
		"":                        "",
	} {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
	// Known limitation, stated rather than hidden: the last two labels are not
	// the registrable domain under a multi-label public suffix. The effect is
	// bounded -- names under it do not resolve -- and -domain overrides it.
	if got := RegistrableDomain("app.example.co.uk"); got != "co.uk" {
		t.Errorf("got %q; the simple rule is documented to behave this way", got)
	}
}
