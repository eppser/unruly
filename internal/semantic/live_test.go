package semantic_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/semantic"
)

// End to end against a real server, skipped unless one is configured.
func TestAgainstARealLocalModel(t *testing.T) {
	ep := os.Getenv("UNRULY_CLASSIFIER")
	if ep == "" {
		t.Skip("set UNRULY_CLASSIFIER to run this against a local model server")
	}
	c, err := semantic.New(semantic.Options{
		Endpoint: ep, Model: os.Getenv("UNRULY_CLASSIFIER_MODEL"),
		Threshold: 0.5, Timeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ col, val, want string }{
		{"anschrift", "Hauptstrasse 14, 10115 Berlin", "location"},
		{"diagnose", "Typ-2-Diabetes, Metformin 500mg", "health"},
		{"bestellnummer", "ORD-100234", ""},
	} {
		start := time.Now()
		got, err := c.Classify(context.Background(), tc.col, []string{tc.val})
		if err != nil {
			t.Fatalf("%s: %v", tc.col, err)
		}
		t.Logf("%-14s -> %-12q p=%.3f  %v", tc.col, got.Class, got.P, time.Since(start).Round(time.Millisecond))
		if got.Class != tc.want {
			t.Logf("   (wanted %q -- a 3B general model is not the 4B measured config)", tc.want)
		}
	}
}
