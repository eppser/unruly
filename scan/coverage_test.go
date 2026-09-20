package scan

import "testing"

// What a provider says about the scan AS A WHOLE, in provider-neutral terms.
//
// The last four artifact reads in cmd/unruly are not narration. They feed the
// scan summary and the coverage finding: how many relations were discovered,
// how many schemas examined, where the candidate names came from, and whether
// anyone can obtain an authenticated role. Those are real scan-level outputs
// and they belong to the command.
//
// But main was getting them by reading supabase.Vocabulary, supabase.Schemas,
// supabase.EnumerateOutcome and surface.Result -- four backend types, to
// produce four integers. So the command imported a backend to count things.
//
// Coverage is the neutral shape. The PROVIDER translates its own artifacts into
// it, because the provider is the only thing that knows what its artifacts
// mean; the command reads only this. A second backend fills in the same struct
// or leaves fields zero, and neither the command nor this type changes.
func TestCoverageCarriesTheScanLevelFactsWithoutABackendType(t *testing.T) {
	st := &State{}
	Put(st, Coverage{Relations: 7, Schemas: 2, OpenSignup: true})

	c, ok := Get[Coverage](st)
	if !ok {
		t.Fatal("no coverage was published, so the command has nothing to summarise")
	}
	if c.Relations != 7 || c.Schemas != 2 || !c.OpenSignup {
		t.Errorf("coverage = %+v, want the values that were published", c)
	}
}

// ABSENT COVERAGE IS NOT AN EMPTY SCAN.
//
// A provider that published nothing has said nothing about how much it
// covered, which is different from one that ran and covered zero relations.
// The command must be able to tell those apart before it prints "0 relations
// discovered" -- that sentence is a measurement, and printing it for a
// provider that never reported would be inventing one.
func TestAbsentCoverageIsDistinguishableFromZeroCoverage(t *testing.T) {
	st := &State{}
	// Something else has run, so the artifact map exists: the mid-pipeline
	// case, which is the only one that exercises the lookup.
	Put(st, struct{ other int }{1})

	if _, ok := Get[Coverage](st); ok {
		t.Error("a provider that published no coverage reported as having published some")
	}

	Put(st, Coverage{})
	c, ok := Get[Coverage](st)
	if !ok {
		t.Fatal("a provider that published empty coverage reported as absent; " +
			"covering nothing is not the same as saying nothing")
	}
	if c.Relations != 0 {
		t.Errorf("coverage = %+v, want the empty value that was published", c)
	}
}

// What the scan OBSERVED about access, in provider-neutral terms.
//
// Intent verification compares a manifest against what was measured. The
// measurements live in a backend's own artifacts -- probe.Result knows which
// relations anon could read -- and the command must not read those, so the
// provider translates them into this.
//
// Only facts the scan ESTABLISHED belong here. A relation nobody probed
// produces no observation, which is what makes an expectation about it
// unverified rather than satisfied.
func TestAccessObservationsTravelInProviderNeutralTerms(t *testing.T) {
	st := &State{}
	Put(st, Access{Observed: []AccessFact{
		{Resource: "invoices", Operation: "read", Subject: "anonymous", Allowed: true},
		{Resource: "payslips", Operation: "read", Subject: "anonymous", Allowed: false},
	}})

	a, ok := Get[Access](st)
	if !ok {
		t.Fatal("no access observations were published, so nothing can be verified " +
			"against an intent manifest")
	}
	if len(a.Observed) != 2 {
		t.Fatalf("published %d observations, want 2", len(a.Observed))
	}
	if !a.Observed[0].Allowed || a.Observed[1].Allowed {
		t.Errorf("observations = %+v, want the values that were published", a.Observed)
	}
}

func TestMergeAccessKeepsDistinctSourcesAndDropsExactDuplicates(t *testing.T) {
	a := Access{Observed: []AccessFact{{Resource: "invoices", Operation: "read",
		Subject: "owner", Scope: "own", Allowed: true}}}
	b := Access{Observed: []AccessFact{
		{Resource: "/admin", Operation: "read", Subject: "anonymous", Allowed: false},
		a.Observed[0],
	}}
	got := MergeAccess(a, b)
	if len(got.Observed) != 2 {
		t.Fatalf("merged access lost a source or kept a duplicate: %+v", got.Observed)
	}
}
