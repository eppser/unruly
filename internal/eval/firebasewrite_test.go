package eval_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/exploit"
	"github.com/eppser/unruly/internal/identity"
)

// Anonymous WRITE to Firestore and the Realtime Database.
//
// Read exposure was measured from the first Firebase commit and write exposure
// was declared unmeasurable -- the provider said so in its own Cannot(), which
// is honest and was still a critical nobody could report. `allow read, write:
// if true` is ONE rule. People write it as one rule. A scanner that reports
// half of it tells an operator their exposure is disclosure when it is
// control, and a file a stranger can place is a file other people's browsers
// load.
//
// The lab has both halves on purpose: public_writable and /public_writable are
// open to writes, and locked_secrets and /locked are not. Reporting the second
// pair would be the false positive that matters most here, because an operator
// who is sent to re-check a rule that is already correct stops reading the
// report.
func TestFirebaseAnonymousWriteIsReportedWhereItExists(t *testing.T) {
	k, apiKey := loadFirebaseLab(t)
	site := firebaseSite(t, k, apiKey)
	defer site.Close()
	vocab := firebaseVocab(t, k)

	// Writes are a mutation, so nothing is attempted without consent. A scan
	// without -write must say the verb was not measured rather than say
	// nothing, because silence here reads as "no write exposure".
	quiet := firebaseScan(t, site.URL, []string{"-vocab", vocab})
	if strings.Contains(quiet, "firebase-firestore-anon-write") ||
		strings.Contains(quiet, "firebase-rtdb-anon-write") {
		t.Error("a scan without -write reported write exposure, so it wrote to the " +
			"target without being asked")
	}
	if !strings.Contains(quiet, "anonymous write") {
		t.Error("a scan without -write says nothing at all about writes; absence of a " +
			"finding for a check that never ran is not evidence")
	}

	report := firebaseScan(t, site.URL, []string{"-vocab", vocab,
		"-write", "-yes-i-own-this"})

	for _, want := range []string{"firebase-firestore-anon-write", "firebase-rtdb-anon-write"} {
		if !strings.Contains(report, want) {
			t.Errorf("%s was not reported, and the lab's rules admit exactly that write. "+
				"Anonymous write is control rather than disclosure and is the check "+
				"this scanner was missing against every alternative", want)
		}
	}
	if !strings.Contains(report, "public_writable") {
		t.Error("no write finding names the collection the rules open")
	}

	// Precision, scoped to the write findings themselves.
	//
	// Scoped because the first version was not, and it was wrong: it failed on
	// authed_profiles, which the report names for a completely correct reason
	// -- with -write the scan signs up, and a collection that refuses
	// anonymous callers and answers a fresh account IS the escalation finding.
	// A precision check that fires on a true finding somewhere else does not
	// measure precision, it measures string matching.
	written := map[string]bool{}
	for _, f := range findingsIn(report) {
		if strings.HasSuffix(f.ID, "-anon-write") {
			written[strings.TrimPrefix(f.Resource, "/")] = true
		}
	}
	for _, closed := range []string{"locked_secrets", "owner_docs", "authed_profiles", "locked"} {
		if written[closed] {
			t.Errorf("%s refuses writes and the scan reports it as writable: sending an "+
				"operator to re-check a rule that is already correct is how a report "+
				"stops being read", closed)
		}
	}
	if len(written) == 0 {
		t.Error("no write findings at all, so the precision half asserted nothing")
	}
}

// Nothing is left behind.
//
// The probe creates a document and removes it. If removal fails the finding
// says so and names the marker, because a document this scanner created and
// cannot delete is residue the operator did not agree to. This checks the
// normal path: after a full write scan, the lab holds exactly what it held
// before.
func TestFirebaseWriteProbeRemovesWhatItCreates(t *testing.T) {
	k, apiKey := loadFirebaseLab(t)
	site := firebaseSite(t, k, apiKey)
	defer site.Close()

	report := firebaseScan(t, site.URL, []string{"-vocab", firebaseVocab(t, k),
		"-write", "-yes-i-own-this"})
	if strings.Contains(report, "could NOT be removed") {
		t.Error("the write probe left a document behind on a project whose rules let " +
			"it delete one")
	}

	// Measured against the target rather than against the report, because the
	// report is the thing under test.
	if left := labProbeResidue(t, k, apiKey); len(left) > 0 {
		t.Errorf("the lab still holds %v after the scan: a write probe that cleans up "+
			"only in its own opinion is not one", left)
	}
}

// labProbeResidue asks the lab directly what the scan left.
func labProbeResidue(t *testing.T, k *exploit.FirebaseKey, apiKey string) []string {
	t.Helper()
	var left []string
	for _, c := range []string{"public_writable", "public_notes"} {
		body := httpGet(t, firestoreListURL(k.ProjectID, c, apiKey))
		if strings.Contains(body, "unruly_write_probe") {
			left = append(left, "firestore:"+c)
		}
	}
	for _, p := range []string{"public_writable", "public"} {
		body := httpGet(t, strings.TrimSuffix(k.RTDB, "/")+"/"+p+".json")
		if strings.Contains(body, "unruly_write_probe") {
			left = append(left, "rtdb:/"+p)
		}
	}
	return left
}

// findingsIn decodes a JSONL report.
func findingsIn(report string) []reportLine {
	var out []reportLine
	for _, line := range strings.Split(strings.TrimSpace(report), "\n") {
		if line == "" {
			continue
		}
		var f reportLine
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		out = append(out, f)
	}
	return out
}

// httpGet reads a URL with no credential beyond what is in it.
func httpGet(t *testing.T, u string) string {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("reading %s: %v", redactedURL(u), err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b)
}

func firestoreListURL(project, collection, apiKey string) string {
	return fmt.Sprintf(
		"https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents/%s?key=%s",
		project, url.PathEscape(collection), url.QueryEscape(apiKey))
}

// redactedURL keeps the API key out of a failure message. It is public by
// design and printing it into a log that gets pasted around is still avoidable.
func redactedURL(u string) string {
	if i := strings.Index(u, "key="); i >= 0 {
		return u[:i+4] + "..."
	}
	return u
}

// -no-residue measures the escalation tier instead of skipping it.
//
// It used to skip: the recorded reason was that account removal needs a
// privileged credential, which is true of Supabase and false of Firebase --
// Identity Toolkit's accounts:delete takes the account's OWN idToken. So on
// every Firebase project that had never been scanned, the highest-value
// finding this tool has was reported unmeasured for a reason that did not
// hold.
//
// The account is created, asked, and deleted. It is deliberately not stored:
// a remembered credential that no longer exists is worse than none, because
// the next run signs in, fails, and concludes the project changed.
func TestFirebaseNoResidueMeasuresEscalationAndLeavesNothing(t *testing.T) {
	k, apiKey := loadFirebaseLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Start from a project with no probe account, whatever earlier runs did.
	// This also exercises the delete path before the code under test uses it.
	email := "unruly-probe-" + k.ProjectID + "@example.invalid"
	removeProbeAccount(t, apiKey, email)

	d, o := firebaseLab(t)
	o.Write = true
	o.NoResidue = true
	t.Setenv("UNRULY_CONFIG_DIR", t.TempDir()) // no stored identity to fall back on

	var escalated bool
	for _, f := range assessFirebase(ctx, d, o) {
		if f.ID == "firebase-firestore-authenticated-read" {
			escalated = true
		}
		if f.ID == "unruly-probe-account-left-behind" {
			t.Errorf("the scan reports leaving an account behind under -no-residue: %s",
				f.Description)
		}
	}
	if !escalated {
		t.Error("-no-residue did not measure what a signed-up user can read. The lab's " +
			"authed_profiles is exactly that rule, and refusing to measure it reports " +
			"the most common Firebase misconfiguration as absent")
	}
	if got := identity.List(); len(got) != 0 {
		t.Errorf("an ephemeral account was written to the identity store (%v): the next "+
			"run would sign in with a credential that no longer exists and conclude "+
			"the project had changed", got)
	}

	// Measured against the target rather than against the report.
	if probeAccountExists(t, apiKey, email) {
		t.Error("the account is still there after a -no-residue scan, which is the one " +
			"thing that flag promises")
	}
}

// removeProbeAccount deletes the scanner's probe account if it exists.
func removeProbeAccount(t *testing.T, apiKey, email string) {
	t.Helper()
	for _, pw := range []string{"123456", "unruly-Pr0be-98f3a1c7!"} {
		tok := signIn(t, apiKey, email, pw)
		if tok == "" {
			continue
		}
		body := strings.NewReader(`{"idToken":"` + tok + `"}`)
		resp, err := http.Post(idtEndpoint("delete", apiKey), "application/json", body)
		if err == nil {
			resp.Body.Close()
		}
		return
	}
}

func probeAccountExists(t *testing.T, apiKey, email string) bool {
	t.Helper()
	for _, pw := range []string{"123456", "unruly-Pr0be-98f3a1c7!"} {
		if signIn(t, apiKey, email, pw) != "" {
			return true
		}
	}
	return false
}

// signIn returns an idToken, or empty when the account is not there.
func signIn(t *testing.T, apiKey, email, password string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"email": email, "password": password, "returnSecureToken": true,
	})
	resp, err := http.Post(idtEndpoint("signInWithPassword", apiKey),
		"application/json", strings.NewReader(string(b)))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var got struct {
		IDToken string `json:"idToken"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(raw, &got)
	return got.IDToken
}

func idtEndpoint(method, apiKey string) string {
	return "https://identitytoolkit.googleapis.com/v1/accounts:" + method +
		"?key=" + url.QueryEscape(apiKey)
}
