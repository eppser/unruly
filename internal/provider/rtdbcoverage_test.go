package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/testrec"
)

// A Realtime Database that answers 200 with nothing has not been assessed.
//
// rtdbReadable treats a 200 carrying `null` as "nothing readable", which is
// correct as far as it goes. What the scan then does is stay silent, and a
// report with no Realtime findings reads as a database that was checked and
// found sound.
//
// Those are different facts. A 200 with no keys at the ROOT means either the
// database is open and empty, or this is not the database we think it is --
// and the second is reachable in ordinary operation, not just in a lab. The
// databaseURL comes out of the application's own bundle; a project that was
// renamed, moved region, or shipped a stale config points the probe somewhere
// that answers politely and holds nothing.
//
// Measured on the Firebase emulator, which selects a namespace with ?ns=: with
// the namespace wrong, EVERY path answered 200 null -- including admin_tokens,
// which is denied when addressed correctly. A scan against that reports a
// clean database and is wrong, with no error anywhere.
//
// A denied path answers 401, so the discriminator exists and is cheap: if the
// root says 200-and-empty rather than 401, say so.
func TestARealtimeDatabaseThatAnswersEmptyIsDisclosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	}))
	defer srv.Close()

	out := rtdbFindings(context.Background(),
		Detection{Project: "p", RTDB: srv.URL},
		ScanOptions{
			Client:     client.New(client.Options{Timeout: 5e9}),
			Candidates: []string{"open_chat", "admin_tokens"},
		})

	var note *string
	for i := range out {
		if out[i].ID == "unruly-surface-not-assessed" {
			d := out[i].Description
			note = &d
		}
	}
	if note == nil {
		var ids []string
		for _, f := range out {
			ids = append(ids, f.ID)
		}
		t.Fatalf("the Realtime Database answered 200 with no keys to every request "+
			"and the scan reported %v. A report with no Realtime findings reads as a "+
			"database that was checked and found sound; this one was not "+
			"distinguishable from the wrong namespace", ids)
	}
	if !strings.Contains(*note, srv.URL) {
		t.Errorf("the disclosure does not name the host it could not assess: %q", *note)
	}
}

// And a database that genuinely refuses is NOT the same case: 401 at the root
// means the rules answered, so the surface was assessed and found closed.
// Emitting the note there would put a coverage line on every correctly locked
// project, which is how a disclosure becomes noise and then gets ignored.
func TestARealtimeDatabaseThatRefusesIsNotDisclosedAsUnassessed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Permission denied"}`))
	}))
	defer srv.Close()

	out := rtdbFindings(context.Background(),
		Detection{Project: "p", RTDB: srv.URL},
		ScanOptions{
			Client:     client.New(client.Options{Timeout: 5e9}),
			Candidates: []string{"open_chat"},
		})
	for _, f := range out {
		if f.ID == "unruly-surface-not-assessed" {
			t.Errorf("a database that answered 401 was reported as not assessed: %q. "+
				"The rules replied, so the surface WAS assessed and found closed.",
				f.Description)
		}
	}
}

// The Realtime probe asks for key names, never values.
//
// rtdbReadable appends "?shallow=true", and the comment above it says so: "key
// names, no values". Nothing tested it. Dropping the parameter turns a probe
// that lists what exists into one that DOWNLOADS every value in a readable
// subtree -- somebody else's messages, tokens and personal data, copied to
// prove they were readable, when the key names already prove it.
//
// That is the difference between demonstrating exposure and taking advantage
// of it, and it is the promise -measure makes explicit. Probed with
// scripts/verify-break.sh: the change survived fourteen tests.
func TestTheRealtimeProbeAsksForKeyNamesAndNotValues(t *testing.T) {
	var asked testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Keys whose VALUES are the thing that must not be retrieved.
		_, _ = w.Write([]byte(`{"d1":{"secret":"hunter2"},"d2":{"secret":"hunter3"}}`))
	}))
	defer srv.Close()

	out := rtdbFindings(context.Background(),
		Detection{Project: "p", RTDB: srv.URL},
		ScanOptions{
			Client:     client.New(client.Options{Timeout: 5e9}),
			Candidates: []string{"open_chat"},
		})
	if len(out) == 0 {
		t.Fatal("nothing reported for a readable database, so this test measured nothing")
	}
	if asked.Len() == 0 {
		t.Fatal("no request was recorded")
	}
	for _, u := range asked.Entries() {
		if !strings.Contains(u, "shallow=true") {
			t.Errorf("the probe asked for %q without shallow=true, so the server returns "+
				"VALUES and not key names. The key names already prove the subtree is "+
				"readable; the values are somebody else's data and this scan has no "+
				"business copying them", u)
		}
	}
	// And the values must not reach the report even though the stub sent them.
	for _, f := range out {
		rendered := fmt.Sprintf("%s %v", f.Description, f.Evidence.Sample)
		if strings.Contains(rendered, "hunter2") {
			t.Errorf("a value the server volunteered reached the report: %s", rendered)
		}
	}
}

// A readable root settles the tree, so the per-path probes must not run.
//
// "One request settles the whole tree, and a readable root makes every path
// below it moot" -- and without the short-circuit the scan asks about every
// candidate anyway. That is one metered request per guessed name against
// somebody's project, to re-establish what the first answer already proved,
// and a finding per path where one is correct.
func TestAReadableRootStopsTheProbingThere(t *testing.T) {
	var asked testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"open_chat":true,"admin_tokens":true}`))
	}))
	defer srv.Close()

	out := rtdbFindings(context.Background(),
		Detection{Project: "p", RTDB: srv.URL},
		ScanOptions{
			Client:     client.New(client.Options{Timeout: 5e9}),
			Candidates: []string{"open_chat", "admin_tokens", "billing", "users"},
		})
	if n := asked.Len(); n != 1 {
		t.Errorf("the root answered and the scan made %d request(s): %v. A readable root "+
			"proves every path below it; asking again spends the project owner's quota "+
			"to learn nothing", n, asked.Entries())
	}
	if len(out) != 1 {
		t.Errorf("%d findings for a readable root, want 1: one statement about the tree, "+
			"not one per guessed name", len(out))
	}
}
