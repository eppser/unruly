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

// How long a wide table actually takes, against a real server.
//
// Serial against parallel over the same columns, same process, same warm
// model. The ratio is LOGGED, not asserted, because it depends entirely on
// whether the server can reuse the prompt prefix. Measured on this machine
// with a 1.9kB prompt:
//
//	Ollama, no prefix reuse:        340ms/request at concurrency 1, 2, 4 and 8
//	llama.cpp, cache_prompt off:    203ms/request, equally flat
//	llama.cpp, cache_prompt on:     33ms at 1, 23 at 2, 17 at 4, 17 at 8
//
// Flat is the expected result, not a bug: a 1.9kB prompt saturates the GPU
// with prompt processing, and concurrency cannot overlap work that is already
// compute-bound. Only once caching removes that work does the remaining
// overhead overlap, and parallelism starts paying -- about 2x.
//
// So the assertion is only that the pool does not COST time. A parallel path
// slower than the serial one is a defect wherever it runs.
func TestParallelBeatsSerialAgainstARealLocalModel(t *testing.T) {
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
	cols := []string{
		"anschrift", "diagnose", "kreditkarte", "iban", "telefon", "email",
		"geburtsdatum", "passnummer", "kennzeichen", "gehalt", "blutgruppe",
		"benutzername", "sitzung", "religion", "biometrie", "standort",
	}
	vals := map[string][]string{}
	for _, col := range cols {
		vals[col] = []string{"beispielwert-" + col}
	}
	ctx := context.Background()

	// Warm the model, so the first request's load time is not in either number.
	if _, err := c.Classify(ctx, "warmup", []string{"x"}); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	for _, col := range cols {
		if _, err := c.Classify(ctx, col, vals[col]); err != nil {
			t.Fatal(err)
		}
	}
	serial := time.Since(start)

	start = time.Now()
	if _, err := semantic.Augment(ctx, c, cols, vals, map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	parallel := time.Since(start)

	t.Logf("%d columns: serial %v (%v/column), parallel %v (%v/column), %.1fx",
		len(cols), serial.Round(time.Millisecond), (serial / time.Duration(len(cols))).Round(time.Millisecond),
		parallel.Round(time.Millisecond), (parallel / time.Duration(len(cols))).Round(time.Millisecond),
		float64(serial)/float64(parallel))
	// A 10% band, because on a server with no prefix reuse the two are the
	// same number and the difference between them is noise. Asserting
	// parallel < serial there would be a coin flip dressed up as a check.
	if parallel > serial+serial/10 {
		t.Errorf("parallel took %v against %v serial: the worker pool is costing "+
			"time instead of saving it", parallel, serial)
	}
}
