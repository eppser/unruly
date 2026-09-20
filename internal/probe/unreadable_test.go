package probe

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
)

// The blind spot that was only ever written in a comment.
//
// Per-verb "not assessed" notes are deliberately gated on readability: a
// relation that refuses SELECT offers no row to aim an UPDATE at and no way to
// create one to DELETE, so without the gate every correctly hardened table
// collects two coverage findings and exit 3 stops meaning anything. That gate
// is right.
//
// What it leaves is a real limit the operator never sees. On a relation this
// scan cannot read, UPDATE and DELETE are not established AT ALL, and the
// source says so in a comment. A policy granting INSERT and UPDATE without
// SELECT -- rarer than FOR ALL, which grants SELECT too and so lands inside
// the gate -- is invisible and unannounced.
//
// One scan-level statement covers it without the per-relation noise the gate
// exists to prevent.
func TestUnreadableRelationsAreDeclaredUnmeasuredForWrites(t *testing.T) {
	r := Result{Relations: []Relation{
		{Name: "open_table", Read: postgrest.ReadExposed},
		{Name: "locked_a", Read: postgrest.ReadEmpty},
		{Name: "locked_b", Read: postgrest.ReadDenied},
	}}
	var got string
	for _, f := range r.Findings("http://h/rest/v1", false) {
		if f.ID == "unruly-surface-not-assessed" &&
			strings.Contains(f.Resource, "write") {
			got = f.Description
		}
	}
	if got == "" {
		t.Fatal("two relations could not be read, so UPDATE and DELETE were never " +
			"established on either, and the report says nothing about it")
	}
	for _, want := range []string{"locked_a", "locked_b"} {
		if !strings.Contains(got, want) {
			t.Errorf("the statement does not name %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "open_table") {
		t.Errorf("a readable relation is named in the unreadable list:\n%s", got)
	}
}

// And a project whose relations are all readable gets no such note: the whole
// point of the readability gate is that coverage findings nobody can act on
// are noise.
func TestNothingIsDeclaredWhenEveryRelationCouldBeRead(t *testing.T) {
	r := Result{Relations: []Relation{
		{Name: "a", Read: postgrest.ReadExposed},
		{Name: "b", Read: postgrest.ReadExposed},
	}}
	for _, f := range r.Findings("http://h/rest/v1", false) {
		if f.ID == "unruly-surface-not-assessed" && strings.Contains(f.Resource, "write") {
			t.Errorf("emitted a blind-spot note for a project with no blind spot: %s",
				f.Description)
		}
	}
}

// The statement must not move the exit code.
//
// A relation that returns no rows cannot have UPDATE or DELETE established
// against it, so this fires on every project with a single correctly protected
// table. If it counted as blindness, a hardened project would exit 3 and be
// indistinguishable from an unreachable one — which is the inversion the exit
// code exists to prevent, and which is exactly what happened on the audit
// after this finding was added with the untested claim that it would not.
func TestTheWriteBlindSpotDoesNotMakeAHardenedProjectLookUnmeasured(t *testing.T) {
	r := Result{Relations: []Relation{
		{Name: "locked_a", Read: postgrest.ReadEmpty},
		{Name: "locked_b", Read: postgrest.ReadDenied},
	}}
	fs := r.Findings("http://h/rest/v1", false)
	if blind, what := finding.CoverageIncomplete(fs); blind {
		t.Errorf("a project whose relations are all correctly protected reads as "+
			"unmeasured (%v), so `unruly ... && echo secure` stops working for the "+
			"people who did everything right", what)
	}
}
