package surface

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// A finding's ID is its stable contract: reports are filtered on it, triage
// rules key off it, and changing one silently breaks every consumer. These
// tests pin the IDs to the conditions that must produce them, so the audit in
// internal/eval can tell a covered check from a merely reachable one.

func TestOpenSignupFindingID(t *testing.T) {
	c := client.New(client.Options{ProjectRef: "x", BaseURL: "http://x", AnonKey: "k"})
	f, ok := authFinding(c, AuthConfig{Reachable: true, DisableSignup: false})
	if !ok {
		t.Fatal("open signup must produce a finding")
	}
	if f.ID != "supabase-open-signup" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if _, ok := authFinding(c, AuthConfig{Reachable: true, DisableSignup: true}); ok {
		t.Error("closed signup must produce nothing")
	}
}

func TestRoutineFindingID(t *testing.T) {
	c := client.New(client.Options{ProjectRef: "x", BaseURL: "http://x", AnonKey: "k"})
	f := buildRoutineFinding(c, "admin_reset_password", finding.Medium, "", "")
	if f.ID != "supabase-rpc-discoverable" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if f.Resource != "admin_reset_password" {
		t.Errorf("routine name must be the resource, got %q", f.Resource)
	}
}

// A public bucket is world-readable object storage. Supabase's own dashboard
// makes this a checkbox, and the difference between a public avatar bucket and
// a public invoices bucket is invisible to the platform.
func TestPublicStorageBucketFindingID(t *testing.T) {
	c := client.New(client.Options{ProjectRef: "x", BaseURL: "http://x", AnonKey: "k"})
	f := bucketFinding(c, Bucket{Name: "invoices", ID: "invoices", Public: true})
	if f.ID != "supabase-public-storage-bucket" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if f.Resource != "invoices" {
		t.Errorf("the bucket name must be the resource, got %q", f.Resource)
	}
	if f.Evidence.Request == "" {
		t.Error("a public bucket finding must carry a replayable request")
	}
}

// A routine that hands rows to the anonymous role is a different finding from
// a routine whose name is guessable, and must outrank it. The scanner was
// making this exact request already and throwing the body away.
func TestRoutineDataFindingID(t *testing.T) {
	c := client.New(client.Options{ProjectRef: "x", BaseURL: "http://x", AnonKey: "k"})
	rows := []map[string]any{{"id": 1, "actor": "admin", "action": "purge"}}
	f := routineDataFinding(c, "admin_read_audit_log", 5, rows, false, "", 200)
	if f.ID != "supabase-rpc-returns-data" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if f.Severity <= finding.Medium {
		t.Errorf("data leaving the database must outrank a name leak, got %s", f.Severity)
	}
	if f.Evidence.Rows != 5 || len(f.Evidence.Sample) == 0 {
		t.Error("the finding must carry the rows it received as proof")
	}
	if got := strings.Join(f.Evidence.Columns, ","); got != "action,actor,id" {
		t.Errorf("columns must be sorted and complete, got %q", got)
	}
	// Redaction must drop the values and keep the shape.
	r := routineDataFinding(c, "admin_read_audit_log", 5, rows, true, "", 200)
	if len(r.Evidence.Sample) != 0 {
		t.Error("-redact must suppress the sampled rows")
	}
	if r.Evidence.Rows != 5 || len(r.Evidence.Columns) == 0 {
		t.Error("-redact must keep the count and the column names, which are the finding")
	}
}

// Writing to a bucket is control, not disclosure: a file an attacker places is
// served from a domain browsers already trust. It must outrank the public-read
// finding, and its remediation must not be "make the bucket private", which
// closes reads and leaves the INSERT policy exactly where it was.
func TestStorageWriteFindingID(t *testing.T) {
	c := client.New(client.Options{ProjectRef: "x", BaseURL: "http://x", AnonKey: "k"})
	f := bucketWriteFinding(c, "public-uploads", "")
	if f.ID != "supabase-storage-anon-write" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	read := bucketFinding(c, Bucket{Name: "public-uploads", Public: true})
	if f.Severity <= read.Severity {
		t.Errorf("upload must outrank public read: %s vs %s", f.Severity, read.Severity)
	}
	if !strings.Contains(f.Description, "does NOT fix this") {
		t.Error("the finding must say that making the bucket private leaves the write open")
	}
	if strings.Contains(f.Remediation, "SET public = false") {
		t.Error("that remediation closes reads and does nothing about the write")
	}
	// A probe that could not clean up has changed the target, and the operator
	// needs the filename.
	r := bucketWriteFinding(c, "public-uploads", "probe_123.txt")
	if !strings.Contains(r.Description, "probe_123.txt") {
		t.Error("a probe object left behind must be named so it can be removed")
	}
}
