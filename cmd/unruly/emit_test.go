package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

// writtenIDs replays what a Writers actually emitted, in emission order.
// finding.Writer is a struct rather than an interface, so the only honest way
// to see what reached the report is to read the bytes it produced.
func writtenIDs(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var f struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("report line is not JSON: %q (%v)", line, err)
		}
		ids = append(ids, f.ID)
	}
	return ids
}

// Every exit must write the canonical report, not the order things happened.
//
// scanTarget has three exits and only one of them sorted and deduplicated. The
// other two -- a scan that found another backend but no Supabase credential,
// and one that stopped because PostgREST answered PGRST125 and could not be
// located -- wrote findings in append order with duplicates intact. Both write
// a stored report an operator keeps.
//
// finding.Sort is the canonical order this project grades against:
// internal/parity measures agreement after it and eval-determinism grades byte
// identity between two scans. A report written in a different order on a
// different code path is not comparable to any other report the tool produces.
func TestEmitAllWritesTheCanonicalReport(t *testing.T) {
	dup := finding.Finding{ID: "unruly-b", Severity: finding.High, Resource: "r1"}
	in := []finding.Finding{
		{ID: "unruly-c", Severity: finding.Low, Resource: "r2"},
		dup,
		{ID: "unruly-a", Severity: finding.Critical, Resource: "r0"},
		dup,
	}
	var buf bytes.Buffer
	w := finding.Writers{{Out: &buf, JSON: true, MinSev: finding.Info}}

	out, worst, _, err := emitAll(w, in)
	if err != nil {
		t.Fatal(err)
	}
	got := writtenIDs(t, &buf)
	if len(got) != len(out) {
		t.Fatalf("wrote %d findings but returned %d; the caller counts what it was "+
			"handed and would report a different number than it wrote",
			len(got), len(out))
	}
	if len(out) != 3 {
		t.Errorf("got %d findings from 4 with one repeated; the duplicate survived",
			len(out))
	}
	// Canonical order, not append order. Append order here starts with unruly-c.
	var sorted []finding.Finding
	sorted = append(sorted, in...)
	finding.Sort(sorted)
	sorted = finding.Dedup(sorted)
	for i := range sorted {
		if got[i] != sorted[i].ID {
			t.Fatalf("written order differs from finding.Sort at %d: wrote %q, "+
				"canonical is %q", i, got[i], sorted[i].ID)
		}
	}
	if worst != finding.Critical {
		t.Errorf("worst severity is %v, want Critical -- the exit code keys on this",
			worst)
	}
}

// An empty report is Info, not a panic or a stale severity.
func TestEmitAllOnNothingIsInfo(t *testing.T) {
	var buf bytes.Buffer
	w := finding.Writers{{Out: &buf, JSON: true, MinSev: finding.Info}}
	out, worst, blind, err := emitAll(w, nil)
	if err != nil || len(out) != 0 || worst != finding.Info || len(blind) != 0 {
		t.Errorf("got %d findings, worst=%v, err=%v", len(out), worst, err)
	}
}
