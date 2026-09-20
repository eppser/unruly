package pocketbase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eppser/unruly/scan"
)

// fakePB models the measured behaviour: a members-only collection answers 200
// with zero rows to an anonymous caller and returns the row once a token is
// presented, signup succeeds, and an account can delete itself.
type fakePB struct {
	mu         sync.Mutex
	accounts   int
	deletes    int
	denyDelete bool
}

func (f *fakePB) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		authed := r.Header.Get("Authorization") != ""
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/users/records"):
			f.mu.Lock()
			f.accounts++
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"id":"acct1","email":"x@y.invalid"}`))
		case strings.Contains(r.URL.Path, "auth-with-password"):
			_, _ = w.Write([]byte(`{"token":"tok","record":{"id":"acct1"}}`))
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/users/records/"):
			if f.denyDelete {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"message":"Only superusers can perform this action.","status":403}`))
				return
			}
			f.mu.Lock()
			f.deletes++
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/members_only/"):
			// Measured: 200 with zero rows anonymously, the row once authed.
			if authed {
				_, _ = w.Write([]byte(`{"items":[{"id":"m1","secret":"card-4999999999999999"}],"totalItems":1}`))
				return
			}
			_, _ = w.Write([]byte(`{"items":[],"totalItems":0}`))
		case strings.Contains(r.URL.Path, "/already_public/"):
			_, _ = w.Write([]byte(`{"items":[{"id":"p1"}],"totalItems":1}`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Only superusers can perform this action.","status":403}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Without consent the scan does NOT create an account, and says so.
//
// Signing up writes to the target: it puts a real user in the operator's
// database. That is a write, and writes are opt-in. But silently skipping the
// check would leave a members-only collection -- invisible to any anonymous
// probe, because it answers 200 with zero rows -- unexamined and unmentioned,
// which is the false negative this scanner exists to eliminate.
func TestWithoutConsentNoAccountIsCreatedAndTheGapIsReported(t *testing.T) {
	f := &fakePB{}
	srv := f.server(t)
	st := &scan.State{Target: srv.URL}
	stage := EscalationStage{Client: pbTestClient(srv.URL), Base: srv.URL, Collections: []string{"members_only"}}

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if f.accounts != 0 {
		t.Errorf("created %d account(s) without consent", f.accounts)
	}
	var said bool
	for _, x := range st.Findings() {
		if x.ID == "unruly-surface-not-assessed" && strings.Contains(x.Resource, "escalation") {
			said = true
		}
	}
	if !said {
		t.Error("escalation was skipped and the report does not say so, so a " +
			"members-only collection reads as absent rather than unexamined")
	}
}

// With consent, a collection that yields rows only to a signed-up caller is
// reported, and the rows are the evidence.
func TestAMembersOnlyCollectionIsReportedAsAnEscalationGain(t *testing.T) {
	f := &fakePB{}
	srv := f.server(t)
	st := &scan.State{Target: srv.URL}
	stage := EscalationStage{Client: pbTestClient(srv.URL), Base: srv.URL, Consent: true,
		Collections: []string{"members_only"}}

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	var got bool
	for _, x := range st.Findings() {
		if x.ID == "pocketbase-authenticated-escalation" && x.Resource == "members_only" {
			got = true
			if len(x.Evidence.Sample) == 0 {
				t.Error("no sampled rows on the escalation finding")
			}
		}
	}
	if !got {
		b, _ := json.Marshal(st.Findings())
		t.Errorf("the gain was not reported: %s", b)
	}
}

// A collection already readable anonymously is NOT an escalation gain.
//
// The gain is the DIFFERENCE. Reporting a collection that returns the same
// rows to both callers would double-count an exposure the anonymous pass
// already reported, and inflate the count an operator triages by.
func TestAnAlreadyPublicCollectionIsNotAGain(t *testing.T) {
	f := &fakePB{}
	srv := f.server(t)
	st := &scan.State{Target: srv.URL}
	stage := EscalationStage{Client: pbTestClient(srv.URL), Base: srv.URL, Consent: true,
		Collections: []string{"already_public"}}

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, x := range st.Findings() {
		if x.ID == "pocketbase-authenticated-escalation" {
			t.Errorf("a collection readable anonymously was reported as an escalation "+
				"gain, double-counting it: %+v", x)
		}
	}
}

// The account the scan created is removed afterwards.
func TestTheCreatedAccountIsDeleted(t *testing.T) {
	f := &fakePB{}
	srv := f.server(t)
	st := &scan.State{Target: srv.URL}
	stage := EscalationStage{Client: pbTestClient(srv.URL), Base: srv.URL, Consent: true, Collections: []string{"members_only"}}

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if f.accounts != 1 || f.deletes != 1 {
		t.Errorf("created %d and deleted %d: a scan that signs up and does not clean "+
			"up leaves a real user in the operator's database", f.accounts, f.deletes)
	}
}

// If cleanup FAILS, the report says so rather than staying quiet.
//
// A scanner that cannot remove what it created has left residue, and the
// operator has to be told which account to delete by hand. Silence here is the
// worst outcome: the account persists and nobody knows.
func TestFailedCleanupIsReportedNotSwallowed(t *testing.T) {
	f := &fakePB{denyDelete: true}
	srv := f.server(t)
	st := &scan.State{Target: srv.URL}
	stage := EscalationStage{Client: pbTestClient(srv.URL), Base: srv.URL, Consent: true, Collections: []string{"members_only"}}

	if _, err := (scan.Pipeline{stage}).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	var warned bool
	for _, x := range st.Findings() {
		if strings.Contains(strings.ToLower(x.Description), "could not be removed") ||
			strings.Contains(x.ID, "residue") {
			warned = true
		}
	}
	if !warned {
		t.Error("the account could not be deleted and the report does not mention it, " +
			"so the operator is never told an account was left behind")
	}
}
