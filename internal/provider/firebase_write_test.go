package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/testrec"
)

// The three outcomes a write probe can have, against a server that produces
// each on demand.
//
// Two of them cannot be produced against the lab at all. A project whose rules
// allow create and refuse delete is a shape people write deliberately, and it
// is the one that decides whether this scanner leaves a document behind -- so
// the branch that reports residue would otherwise ship having never run.
func TestFirebaseWriteProbeClassifiesEveryOutcome(t *testing.T) {
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE" && mode == "residue":
			w.WriteHeader(403)
		case r.Method == "DELETE":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
		case mode == "refused":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":{"message":"PERMISSION_DENIED"}}`))
		case mode == "malformed":
			// A 400 is OUR bad request, not their open rule. Reporting an
			// exposure on the strength of it would be reporting our own bug as
			// the target's.
			w.WriteHeader(400)
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"name":"projects/p/databases/(default)/documents/c/d"}`))
		}
	}))
	defer srv.Close()
	c := client.New(client.Options{Timeout: 5e9})
	ctx := context.Background()

	for _, tc := range []struct {
		mode string
		want writeOutcome
	}{
		{"accepted", writeAccepted},
		{"refused", writeRefused},
		{"residue", writeResidue},
		{"malformed", writeUnknown},
	} {
		mode = tc.mode
		if got, _ := firestoreWritable(ctx, c, srv.URL, "k", "coll", "id"); got != tc.want {
			t.Errorf("firestore %s: outcome %v, want %v", tc.mode, got, tc.want)
		}
		if got, _ := rtdbWritable(ctx, c, srv.URL, "/path", "id"); got != tc.want {
			t.Errorf("rtdb %s: outcome %v, want %v", tc.mode, got, tc.want)
		}
	}
}

// The Realtime Database probe must address a CHILD.
//
// A PUT to a node REPLACES it. Writing at /orders.json to prove /orders is
// writable would delete every order in the database, which is not a probe, it
// is an outage caused by a scan. Nothing else in the suite would notice: the
// finding would be correct, the report would be right, and the target would be
// empty.
func TestRealtimeWriteProbeNeverAddressesTheNodeItself(t *testing.T) {
	var puts testrec.Log
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			puts.Add(r.URL.Path)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	rtdbWritable(context.Background(), client.New(client.Options{Timeout: 5e9}),
		srv.URL, "/orders", "probe-id")
	got := puts.Last()
	if got == "/orders.json" || !strings.HasPrefix(got, "/orders/") {
		t.Errorf("the probe wrote to %q; a PUT there replaces the node and destroys "+
			"everything under it. It must address a child that did not exist", got)
	}
}

// Rules are not SQL, and the fix plan pipes SQL into psql.
func TestFirebaseWriteFindingsAreFixedInARulesFile(t *testing.T) {
	for _, f := range []finding.Finding{
		firestoreWriteFinding("https://x/documents", "orders", "curl ...", false),
		rtdbWriteFinding("https://x", "/orders", "curl ...", false),
	} {
		if f.Severity != finding.Critical {
			t.Errorf("%s is %s; anonymous write is control over somebody's data",
				f.ID, f.Severity)
		}
		if f.FixKind != finding.FixRulesFile {
			t.Errorf("%s says its fix is %q: a rules change routed into the SQL plan "+
				"would be pasted into psql, where it is a syntax error", f.ID, f.FixKind)
		}
		if f.Evidence.Request == "" {
			t.Errorf("%s carries no replayable request", f.ID)
		}
	}

	// The residue variant has to say the document is still there, and name it.
	left := firestoreWriteFinding("https://x/documents", "orders", "curl ...", true)
	if !strings.Contains(left.Description, "could NOT be removed") ||
		!strings.Contains(left.Description, probeMarker) {
		t.Errorf("a probe left behind is not named as such:\n%s", left.Description)
	}
	if r := residueFinding("firestore", "https://x/documents/orders/probe"); r.Severity != finding.High {
		t.Errorf("residue is %s; somebody has to act on it", r.Severity)
	}
}

// Without consent, and under -no-residue, the verb is reported unmeasured
// rather than silently skipped.
func TestFirebaseWriteIsGatedAndSaysSo(t *testing.T) {
	d := Detection{Provider: "firebase", Project: "p", Credential: "k"}
	for _, tc := range []struct {
		name string
		o    ScanOptions
		want string
	}{
		{"no consent", ScanOptions{}, "-write -yes-i-own-this"},
		{"no residue", ScanOptions{Write: true, NoResidue: true}, "-no-residue"},
	} {
		fs := writeFindings(context.Background(), d, tc.o, []string{"orders"}, nil)
		if len(fs) != 1 || !strings.Contains(fs[0].Description, tc.want) {
			t.Errorf("%s: got %d finding(s), want one naming %q", tc.name, len(fs), tc.want)
		}
	}
}
