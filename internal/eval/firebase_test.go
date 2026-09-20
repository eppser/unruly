package eval_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/engine"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/identity"
	"github.com/eppser/unruly/internal/provider"
	"github.com/eppser/unruly/scan"
)

// assessFirebase deliberately enters through the public engine contract. Live
// evals used to call a provider-only Assess dispatcher, which let that path
// remain healthy while the command/engine path was disconnected.
func assessFirebase(ctx context.Context, d provider.Detection, o provider.ScanOptions) []finding.Finding {
	in := scan.Inputs{
		Client: o.Client, Seeds: append([]string(nil), o.Candidates...),
		Credential: d.Credential,
		Controls: scan.Controls{Write: o.Write, Invoke: o.Invoke,
			Measure: o.Measure, NoResidue: o.NoResidue},
		Limits: scan.Limits{Collections: o.MaxCollections, SampleRows: o.SampleRows},
		SeedSet: scan.SeedSet{Merged: append([]string(nil), o.Candidates...),
			Supplied:  append([]string(nil), o.Supplied...),
			Harvested: append([]string(nil), o.Harvested...)},
	}
	r := engine.Run(ctx, engine.Request{Providers: []engine.ProviderTarget{{
		Detection: d, Inputs: in, Consent: scan.Consent{Write: o.Write || o.Invoke},
	}}})
	return r.Findings
}

// Graded against the Firebase lab, whose posture is known by construction:
// FirebaseMap/lab/firestore.rules and database.rules.json.
//
// Both halves are asserted. Two collections and two paths are open and must be
// found; three collections and two paths are correctly configured and must NOT
// be reported. The second half is what separates this from a tool that reports
// every name it tried.
func firebaseLab(t *testing.T) (provider.Detection, provider.ScanOptions) {
	t.Helper()
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1 to run live evals")
	}
	raw, err := os.ReadFile("../../.secrets/firebase-lab-config.json")
	if err != nil {
		t.Skip("firebase lab config absent (.secrets/ is gitignored)")
	}
	var cfg struct {
		APIKey    string `json:"apiKey"`
		ProjectID string `json:"projectId"`
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.APIKey == "" {
		t.Skip("firebase lab config unusable")
	}
	// One place, because patching this test by test is how it took three
	// audits to stop failing on it. Every live Firebase check here reads
	// Firestore, and under a 429 none of them can look: the reports come back
	// empty and the suite grades world-readable collections as unreported.
	// That is the false negative this project exists to refuse, produced by
	// its own tests.
	requireFirestoreQuota(t, cfg.ProjectID, cfg.APIKey)

	d := provider.Detection{
		Provider: "firebase", Project: cfg.ProjectID, Credential: cfg.APIKey,
		RTDB: "https://" + cfg.ProjectID + "-default-rtdb.europe-west1.firebasedatabase.app",
	}
	return d, provider.ScanOptions{
		Client: client.New(client.Options{BaseURL: "https://firestore.googleapis.com", Retries: 1}),
		Candidates: []string{
			// open
			"public_notes", "public_writable", "public", "public_writable_path",
			// closed, and the point of the test
			"locked_secrets", "owner_docs", "authed_profiles", "locked", "authed",
			// never existed
			"definitely_not_here_xyz",
		},
		SampleRows: 3,
	}
}

func TestFirebaseFindsTheOpenAndIgnoresTheRest(t *testing.T) {
	d, o := firebaseLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	got := map[string]string{} // resource -> id
	for _, f := range assessFirebase(ctx, d, o) {
		got[f.Resource] = f.ID
	}

	// Open by construction: rules say allow read: if true.
	for _, want := range []string{"public_notes", "public_writable"} {
		if got[want] != "firebase-firestore-anon-read" {
			t.Errorf("%s is world-readable and was not reported (got %q)", want, got[want])
		}
	}
	if got["/public"] != "firebase-rtdb-anon-read" {
		t.Errorf("RTDB /public is world-readable and was not reported (got %q)", got["/public"])
	}

	// Closed by construction. Reporting any of these is a false positive, and
	// the last one never existed at all -- Firestore answers 403 identically
	// for protected and absent, so a tool that infers existence from a refusal
	// invents it.
	for _, mustNot := range []string{
		"locked_secrets", "owner_docs", "authed_profiles",
		"definitely_not_here_xyz", "/locked", "/authed",
	} {
		if id, ok := got[mustNot]; ok && strings.Contains(id, "anon-read") {
			t.Errorf("false positive: %s is not readable anonymously, reported as %s",
				mustNot, id)
		}
	}
}

// Recall is a lower bound and the report has to say so, or "nothing found"
// reads as "nothing there" for a database whose names cannot be enumerated.
func TestFirebaseReportsItsOwnRecallBound(t *testing.T) {
	d, o := firebaseLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var said bool
	for _, f := range assessFirebase(ctx, d, o) {
		if f.ID == "unruly-surface-not-assessed" && strings.Contains(f.Resource, "firestore") {
			said = true
			if !strings.Contains(f.Evidence.Reason, "lower bound") {
				t.Errorf("the bound is not stated as one: %s", f.Evidence.Reason)
			}
		}
	}
	if !said {
		t.Error("no finding records that Firestore recall is bounded by the names tried")
	}
}

// Values must not be retrieved: the probes are shallow=true and a __name__
// projection precisely so exposure can be established without copying data.
func TestFirebaseEvidenceCarriesNamesNotValues(t *testing.T) {
	d, o := firebaseLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, f := range assessFirebase(ctx, d, o) {
		if !strings.Contains(f.ID, "anon-read") {
			continue
		}
		if len(f.Evidence.Columns) == 0 {
			t.Errorf("%s carries no proof at all", f.Resource)
		}
		if len(f.Evidence.Sample) > 0 {
			t.Errorf("%s carries retrieved field values; the Firebase probes are "+
				"name-only by design", f.Resource)
		}
		for _, seeded := range []string{"person@example.invalid", "sk_live_deadbeefcafe"} {
			if strings.Contains(f.Evidence.Reason+strings.Join(f.Evidence.Columns, " "), seeded) {
				t.Errorf("%s leaked a seeded value into its evidence", f.Resource)
			}
		}
	}
}

// The escalation flip, graded against the lab.
//
// authed_profiles refuses anonymous callers and answers an account created
// seconds earlier. owner_docs refuses BOTH, because it is scoped to
// request.auth.uid and a fresh account matches no document. Reporting the first
// and staying silent about the second is the entire difference between
// measuring and reading the rule text.
func TestFirebaseEscalationReportsTheDeltaOnly(t *testing.T) {
	d, o := firebaseLab(t)
	o.Write = true // signing up creates an account; the lab is ours
	// Isolated store: a test must not write to the operator's real config.
	t.Setenv("UNRULY_CONFIG_DIR", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	byID := map[string]string{}
	for _, f := range assessFirebase(ctx, d, o) {
		byID[f.Resource] = f.ID
	}

	if byID["authed_profiles"] != "firebase-firestore-authenticated-read" {
		t.Errorf("authed_profiles flips from refused to readable on signup and was not "+
			"reported as an escalation (got %q)", byID["authed_profiles"])
	}
	// Scoped correctly: signing up gains nothing, so nothing may be claimed.
	for _, mustNot := range []string{"owner_docs", "locked_secrets", "definitely_not_here_xyz"} {
		if id, ok := byID[mustNot]; ok && strings.Contains(id, "read") {
			t.Errorf("false positive: %s gains nothing from an account, reported as %s",
				mustNot, id)
		}
	}
	// Already public: repeating it as an escalation would drown the delta.
	if byID["public_notes"] == "firebase-firestore-authenticated-read" {
		t.Error("a collection anonymous callers already read was reported as an escalation")
	}
	// And signup being open is itself the fact that makes the above matter.
	if byID["auth:signup"] != "firebase-auth-open-signup" {
		t.Errorf("open signup was not reported (got %q)", byID["auth:signup"])
	}
}

// Without -write, the tool must say the question was not asked rather than
// implying the answer is no.
func TestFirebaseSignupIsGatedAndSaysSo(t *testing.T) {
	d, o := firebaseLab(t)
	o.Write = false
	t.Setenv("UNRULY_CONFIG_DIR", t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var said bool
	for _, f := range assessFirebase(ctx, d, o) {
		if f.ID == "firebase-auth-open-signup" {
			t.Error("an account was created without -write")
		}
		if strings.Contains(f.Resource, "firebase-auth") &&
			strings.Contains(f.Evidence.Reason, "creates an account") {
			said = true
		}
	}
	if !said {
		t.Error("signup was not tested and the report does not say so, which reads as " +
			"'no escalation exists'")
	}
}

// The account is created once and reused, or scanning a project twice leaves
// two accounts in somebody's user table.
func TestFirebaseIdentityIsReusedAcrossRuns(t *testing.T) {
	d, o := firebaseLab(t)
	o.Write = true
	dir := t.TempDir()
	t.Setenv("UNRULY_CONFIG_DIR", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	assessFirebase(ctx, d, o)
	first := identity.List()
	if len(first) != 1 {
		t.Fatalf("expected one remembered account, got %d", len(first))
	}
	assessFirebase(ctx, d, o)
	second := identity.List()
	if len(second) != 1 || second[0].Email != first[0].Email {
		t.Errorf("a second scan created another account: %v then %v", first, second)
	}
	if second[0].Password == "" {
		t.Error("the stored record cannot be used to sign back in")
	}
}

// The platform assumption the Firebase design rests on.
//
// Everything about how Firestore and the Realtime Database are reported follows
// from one measured fact: a refusal does not distinguish "protected" from "does
// not exist". That is why this tool reports readable collections and nothing
// else, why it states recall as a lower bound, and why the benchmark can say a
// 403-means-protected rule produces claims that are not collections.
//
// If Google ever separates the two -- a 404 for absent, a 403 for protected --
// then existence becomes decidable, "protected" becomes a measurement, and a
// whole class of finding this tool currently refuses to emit becomes available.
// That would be good news, and the way to hear it is a failing test rather than
// a report that is quietly less useful than it could be.
//
// This is the threat model's "what would falsify this" section, made executable.
func TestFirestoreStillCannotDistinguishAbsentFromProtected(t *testing.T) {
	d, o := firebaseLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	base := "https://firestore.googleapis.com/v1/projects/" + d.Project +
		"/databases/(default)/documents"
	get := func(collection string) int {
		return o.Client.Get(ctx, base+"/"+collection+"?key="+d.Credential+"&pageSize=1", nil).Status
	}

	// Known by construction from FirebaseMap/lab/firestore.rules.
	readable := get("public_notes")
	protected := get("locked_secrets")
	absent := get("collection_that_has_never_existed_" + strings.ToLower(d.Project))

	if readable != 200 {
		t.Fatalf("public_notes answered %d; the lab is not in the state this test "+
			"reasons about", readable)
	}
	if protected != absent {
		t.Errorf("PLATFORM CHANGED: a protected collection answered %d and one that has "+
			"never existed answered %d. Existence is now decidable, which means "+
			"'protected' has become a measurement this tool could report and currently "+
			"refuses to. Revisit firestoreFindings, the recall-bound finding, and "+
			"benchmark/firebase.md.", protected, absent)
	}
	if protected != 403 {
		t.Errorf("a protected collection answered %d, not 403; the classification in "+
			"firestoreReadable keys on that", protected)
	}
}

// The same assumption for the Realtime Database, which reaches it by a
// different route: a denied path and a missing one both answer 401.
func TestRTDBStillCannotDistinguishAbsentFromDenied(t *testing.T) {
	d, o := firebaseLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	get := func(path string) int {
		return o.Client.Get(ctx, strings.TrimSuffix(d.RTDB, "/")+"/"+path+".json?shallow=true", nil).Status
	}
	if open := get("public"); open != 200 {
		t.Fatalf("/public answered %d; the lab is not in the state this test reasons about", open)
	}
	denied, absent := get("locked"), get("path_that_has_never_existed_here")
	if denied != absent {
		t.Errorf("PLATFORM CHANGED: a denied path answered %d and a missing one %d. "+
			"Absence and protection are no longer one observation; the reporting rules "+
			"for RTDB can be tightened.", denied, absent)
	}
}

// Remote Config: the finding is the content, never the reachability.
//
// The template answers anyone holding the web API key, which is the product
// working as designed -- a client fetches its configuration before it has a
// user. Reporting that is reporting a feature. The lab's template mixes three
// innocuous parameters with a credential and an internal endpoint, and both
// halves are graded: a scanner that reports the flags is noise, one that misses
// the key is useless.
func TestRemoteConfigReportsSecretsAndNotFlags(t *testing.T) {
	d, o := firebaseLab(t)
	raw, err := os.ReadFile("../../.secrets/firebase-lab-config.json")
	if err != nil {
		t.Skip("firebase lab config absent")
	}
	var cfg struct {
		AppID string `json:"appId"`
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.AppID == "" {
		t.Skip("no appId in the lab config; Remote Config will not answer without it")
	}
	d.AppID = cfg.AppID

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var f *finding.Finding
	for _, got := range assessFirebase(ctx, d, o) {
		if got.ID == "firebase-remote-config-secret" {
			g := got
			f = &g
		}
	}
	if f == nil {
		t.Fatal("the template carries a credential-shaped value and nothing was reported")
	}
	if f.Severity != finding.Critical {
		t.Errorf("severity %s; a credential served to every client is critical", f.Severity)
	}

	named := strings.Join(f.Evidence.Columns, ",")
	for _, must := range []string{"stripe_secret_key", "internal_admin_endpoint"} {
		if !strings.Contains(named, must) {
			t.Errorf("%s is in the template and was not named: %q", must, named)
		}
	}
	// The precision half. These are ordinary configuration and reporting them
	// would make the finding noise.
	for _, mustNot := range []string{"feature_new_dashboard", "max_items_per_page", "welcome_headline"} {
		if strings.Contains(named, mustNot) {
			t.Errorf("%s is an ordinary flag and was reported: %q", mustNot, named)
		}
	}
	// And the value must never be quoted: the value IS the secret, so a finding
	// that carries it is a second copy of it.
	whole := f.Description + f.Evidence.Reason + strings.Join(f.Evidence.Columns, " ") +
		f.Evidence.Request + f.Remediation
	if strings.Contains(whole, "sk_live_FAKErcfixture") {
		t.Error("the finding republishes the credential it is reporting")
	}
}
