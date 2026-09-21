package main

import (
	"strings"
	"testing"
)

// The flag exists, is off by default, and says what it costs.
//
// A previous commit's error text advertised -classifier before the flag was
// defined; the flag audit caught it, which is what that audit is for. An
// operator following advice into "flag provided but not defined" gets no scan
// at all.
func TestClassifierFlagsExistAndAreOffByDefault(t *testing.T) {
	o := &options{}
	fs := newFlagSet(o)
	for _, name := range []string{"classifier", "classifier-model", "classifier-threshold"} {
		f := fs.CommandLine.Lookup(name)
		if f == nil {
			t.Fatalf("-%s is not defined", name)
		}
		if strings.TrimSpace(f.Usage) == "" {
			t.Errorf("-%s has no usage text", name)
		}
	}
	if o.classifier != "" {
		t.Errorf("classifier endpoint defaults to %q; this feature is off until an "+
			"operator points it somewhere", o.classifier)
	}
	// The default must be the measured one. Ungated, the best model tested
	// tagged 12% of ordinary columns; the gate is what buys that back.
	if o.classifierThreshold != 80 {
		t.Errorf("default threshold %v, want 80 -- the value the benchmark was run at",
			o.classifierThreshold)
	}
}

// The usage text has to warn, because the feature changes what the report
// asserts. A reader who does not know that model classes are opinions will
// treat them as the proofs the rest of the report contains.
func TestTheClassifierFlagSaysWhatItChanges(t *testing.T) {
	o := &options{}
	u := newFlagSet(o).CommandLine.Lookup("classifier").Usage
	for _, want := range []string{"model", "rules"} {
		if !strings.Contains(strings.ToLower(u), want) {
			t.Errorf("usage %q does not mention %q", u, want)
		}
	}
}
