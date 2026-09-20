package supabase

import (
	"context"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/subdomain"
	"github.com/eppser/unruly/scan"
)

// stubResolve answers for a fixed set of hosts and never touches the network.
func stubResolve(up map[string]bool) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, host string) ([]string, error) {
		if up[host] {
			return []string{"192.0.2.1"}, nil
		}
		return nil, nil
	}
}

// The stage must report exactly what the code it replaced reported.
//
// Transcribed from cmd/unruly/main.go as it stood before 2aef490:
//
//	sd := subdomain.Enumerate(ctx, subdomain.Options{
//		Domain: domain, Labels: wordlist.Subdomains(),
//		Concurrency: o.concurrency, Timeout: timeout,
//	})
//	if len(sd.Hosts) > 0 {
//		names := ...
//		all = append(all, finding.SubdomainsFound(domain, names, sd.Tried))
//	}
//
// It was the last ported stage with no parity test. The resolver seam exists
// precisely so this needs no network, so there was never a good reason.
func TestTheSubdomainStageAgreesWithTheCodeItReplaced(t *testing.T) {
	opts := subdomain.Options{
		Domain: "example.invalid", Labels: []string{"api", "staging", "dev"},
		Concurrency: 2, Timeout: 2 * time.Second,
		Resolver: stubResolve(map[string]bool{
			"api.example.invalid": true, "dev.example.invalid": true}),
	}

	// --- the original expression, transcribed ---------------------------
	var old []finding.Finding
	sd := subdomain.Enumerate(context.Background(), opts)
	if len(sd.Hosts) > 0 {
		names := make([]string, 0, len(sd.Hosts))
		for _, h := range sd.Hosts {
			names = append(names, h.Name)
		}
		old = append(old, finding.SubdomainsFound(opts.Domain, names, sd.Tried))
	}

	// --- the stage ------------------------------------------------------
	st := &scan.State{}
	if _, err := (scan.Pipeline{SubdomainStage{Opts: opts}}).
		Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	got := st.Findings()

	if len(old) == 0 {
		t.Fatal("the transcribed path produced no finding, so this compares nothing")
	}
	if len(got) != len(old) {
		t.Fatalf("the stage produced %d findings, the code it replaced produced %d",
			len(got), len(old))
	}
	if got[0].ID != old[0].ID || got[0].Description != old[0].Description {
		t.Fatalf("the stage disagrees with the code it replaced:\n stage: %s / %s\n old:   %s / %s",
			got[0].ID, got[0].Description, old[0].ID, old[0].Description)
	}
}

// -timeout must bind subdomain enumeration.
//
// The port restated three of the four option fields and dropped Timeout, so
// every lookup silently used the subdomain package's own 5s default no matter
// what the operator asked for. That is the exact failure this repository has
// hit three times before -- a control present in the API and absent from the
// behaviour -- and it survived because TestDeclaredControlsAreUsed walks
// internal/ and asks whether a package reads its OWN field. Nothing asked
// whether the caller passed one.
//
// The stage now takes subdomain.Options whole, which is what its three sibling
// stages do and what makes the field impossible to forget.
func TestSubdomainEnumerationHonoursTheTimeout(t *testing.T) {
	slow := func(ctx context.Context, host string) ([]string, error) {
		select {
		case <-time.After(3 * time.Second):
			return []string{"192.0.2.1"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	st := &scan.State{}
	start := time.Now()
	if _, err := (scan.Pipeline{SubdomainStage{Opts: subdomain.Options{
		Domain: "example.invalid", Labels: []string{"api"},
		Concurrency: 1, Timeout: 50 * time.Millisecond, Resolver: slow,
	}}}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	out, ok := scan.Get[subdomain.Result](st)
	if !ok {
		t.Fatal("the subdomain stage published no result")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("enumeration took %v with -timeout set to 50ms: the timeout is not "+
			"reaching the resolver, so the operator's control does not bind this stage",
			elapsed)
	}
	if len(out.Hosts) != 0 {
		t.Errorf("a lookup that outlived the timeout still counted as a resolving host")
	}
}
