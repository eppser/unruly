package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/classify"
	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/sample"
)

// Assessing a Firebase project.
//
// Two databases, two different problems.
//
// The Realtime Database is decidable. One request against the root either
// returns the whole tree or refuses, and ?shallow=true answers it with key
// names and no values, so exposure is established without copying anything.
//
// Firestore is not. Collection names cannot be enumerated -- listCollectionIds
// is admin-only and there is no near-miss hint -- so a scanner can only ask
// about names it already holds. Worse, a collection that is protected and one
// that never existed BOTH answer 403, measured against the lab. That bounds
// what may honestly be reported: "readable" is a measurement, "protected" is
// not, and a tool that brute-forces names and reports each 403 as a collection
// it discovered is publishing guesses dressed as findings.
//
// So Firestore recall is a lower bound and says so, in a finding that drives
// the same exit code as any other surface the scan could not see.

// ScanOptions is what an assessment needs from the caller. Kept small on
// purpose: a provider that needs more of the scanner's internals is a provider
// nobody outside this repository can write.
type ScanOptions struct {
	Client *client.Client
	// Candidates are names to ask about, already merged from the pinned
	// wordlist and whatever vocabulary was harvested from the application.
	// Firestore has no discovery oracle, so this list IS the recall.
	Candidates []string
	// Measure suppresses value retrieval: names only, nothing copied.
	Measure bool
	// MaxCollections bounds how many Firestore collection names are probed.
	// Zero is unbounded.
	//
	// This is a budget for somebody ELSE's money. Every probe is a query,
	// Firestore bills at least one document read per query, and the free tier
	// is 50,000 a day -- so an unbounded scan of a project with the pinned
	// list costs its owner roughly 719 reads. Measured: a day of development
	// against this project's own lab exhausted that quota, after which Google
	// answered 429 to everything.
	MaxCollections int
	// Write authorises mutations. Signing up creates an account, so the auth
	// and escalation probes are gated on it exactly as the Supabase ones are.
	Write bool
	// SampleRows bounds how many documents are quoted as proof.
	SampleRows int
	// Invoke authorises CALLING things. Reading a document is a read; calling
	// a Cloud Function runs somebody's code, which is a different consent.
	Invoke bool
	// Supplied is the vocabulary the OPERATOR named, with -vocab.
	//
	// Kept apart from Harvested because the two are different kinds of claim.
	// Harvested is whatever the page happened to contain; supplied is an
	// assertion that these names exist. Where a budget has to cut, it cuts
	// guesses before assertions -- otherwise an operator can name a function,
	// watch config-key noise sort ahead of it, and get silence back.
	Supplied []string
	// Harvested is the vocabulary taken from the application's OWN bundles,
	// separate from Candidates because the two answer different questions.
	// Candidates is "names worth asking about", which for a read probe can be
	// a pinned list of hundreds. Function names cannot: probing one RUNS it,
	// so the only defensible source is the set the application itself names.
	Harvested []string
	// NoResidue forbids LEAVING anything on the target.
	//
	// Not the same as forbidding every mutation, and the difference was worth
	// finding. The reason recorded here for refusing to sign up was that
	// "account removal needs a privileged credential". That is true of
	// Supabase -- deleting a GoTrue user needs the service_role key, which is
	// why the Supabase path still refuses -- and it is FALSE of Firebase:
	// Identity Toolkit's accounts:delete takes the account's own idToken.
	//
	// So under -no-residue this backend signs in to a stored account when
	// there is one, and otherwise creates an account, asks its questions and
	// deletes it again. Refusing outright reported the highest-value Firebase
	// finding as unmeasured on every project that had never been scanned,
	// which is most of them. If the delete is refused, the account IS residue
	// and the report says so.
	//
	// This package was EXEMPT from the audit's no-residue check, on the
	// recorded grounds that its only POST is Firestore's runQuery -- which is
	// a read. That was true of the path the exemption's guard test exercises
	// and false of this one, which runs only under -write.
	NoResidue bool
}

// assess is the Firebase implementation behind firebaseAssessmentStage. It is
// deliberately unexported: integrations and evals execute detections through
// engine.Run, so there is only one registry execution contract.
func (firebase) assess(ctx context.Context, d Detection, o ScanOptions) []finding.Finding {
	var out []finding.Finding
	anonFS := firestoreFindings(ctx, d, o)
	out = append(out, anonFS...)
	anonRT := rtdbFindings(ctx, d, o)
	out = append(out, anonRT...)

	// Write is probed only where READ already succeeded. Firestore creates a
	// collection implicitly on first write, so probing a guessed name does not
	// fail against a collection that is not there -- it makes one. The
	// readable set is the set already proven to exist.
	out = append(out, writeFindings(ctx, d, o,
		resourcesOf(anonFS, "firebase-firestore-anon-read"),
		resourcesOf(anonRT, "firebase-rtdb-anon-read"))...)

	out = append(out, storageFindings(ctx, d, o)...)
	out = append(out, functionFindings(ctx, d, o)...)
	out = append(out, remoteConfigFindings(ctx, d, o)...)

	// Three surfaces need the web API key, and each returns in silence without
	// one. Say so once, here, rather than three times or not at all.
	//
	// The guard is right: Google's client APIs are keyed, and a scan with no
	// key to present has no business guessing one. The silence is not. A
	// report carrying no Firestore, no Auth and no Remote Config findings
	// reads as three surfaces that were checked and came back sound.
	//
	// Measured against firebase-lab-000000, which is why this is worth a line
	// rather than a footnote: a collection whose rule is `allow read: if true`
	// answers 200 WITH DOCUMENTS to a request carrying `key=` empty, while a
	// collection that cannot exist answers 403. The rules are evaluated
	// whether or not a key is presented, so the surface skipped here may be
	// wide open. That is not a reason to probe without one -- one project's
	// API-key configuration does not generalise, and App Check or key
	// restrictions change it -- it is a reason to disclose.
	if d.Credential == "" {
		out = append(out, finding.Finding{
			ID:       "unruly-surface-not-assessed",
			Name:     "Firebase surfaces skipped for want of an API key",
			Severity: finding.Info,
			// "unruly", not a surface name. The other not-assessed disclosures
			// name the one surface they are about -- postgrest, rtdb -- and
			// this one spans three, so naming any of them would misdescribe
			// it. KnownProtocols keeps "unruly" for exactly this: a statement
			// about the scan rather than about the target.
			Protocol: "unruly",
			Matched:  d.Project,
			Resource: "firebase:no-credential",
			Description: "No web API key was recovered from the application, so Firestore, " +
				"Auth and Remote Config were never probed on project " + d.Project + ". " +
				"Their absence from this report is not a statement that they are sound. " +
				"The key is not a secret -- Google documents it as public and it ships in " +
				"every client bundle -- so supplying one with -k, or pointing -site at a " +
				"page that loads the app, turns this from unexamined into measured.",
			Remediation: "-- Nothing to fix. Re-run with the application's public web API\n" +
				"-- key so these three surfaces are examined rather than skipped.",
		})
	}

	auth, session := authFindings(ctx, d, o)
	out = append(out, auth...)
	if session != nil {
		out = append(out, escalationFindings(ctx, d, o, session, anonFS)...)
		out = append(out, finishSession(ctx, d, o, session)...)
	}
	finding.Sort(out)
	return finding.Dedup(out)
}

// resourcesOf is the resource named by every finding with this id.
func resourcesOf(fs []finding.Finding, id string) []string {
	var out []string
	for _, f := range fs {
		if f.ID == id {
			out = append(out, f.Resource)
		}
	}
	return out
}

// escalationFindings re-asks every question as a signed-up user and reports
// only what CHANGED.
//
// Reporting everything the authenticated role can read would drown the answer:
// most of it is the same data anonymous callers already get, and repeating it
// says nothing. What matters is the delta, because that is precisely the set a
// rule was written to protect and open signup hands over anyway.
//
// A collection that stays refused for both is the precision control. On the lab
// owner_docs is scoped to request.auth.uid, so a fresh account matches no
// document and gains nothing; a scanner that reported it would be reading the
// rule text instead of measuring.
func escalationFindings(ctx context.Context, d Detection, o ScanOptions, st *authState,
	anonFS []finding.Finding) []finding.Finding {

	already := map[string]bool{}
	for _, f := range anonFS {
		already[f.Resource] = true
	}
	// Same client, carrying the session. Firestore takes the token as a bearer
	// beside the API key, which identifies the project.
	authed := o.Client.WithBearer(st.IDToken)
	base := firestoreDocsURL(d.Project)
	key := url.QueryEscape(d.Credential)

	names := append([]string{}, o.Candidates...)
	sort.Strings(names)
	var out []finding.Finding
	for _, name := range names {
		if already[name] {
			continue // anonymous already reads it; signing up gained nothing
		}
		probe := probeFirestore(ctx, authed, base, key, name)
		if probe.Terminal != "" {
			break
		}
		if !probe.Readable {
			continue
		}
		out = append(out, escalationFinding(base, name, probe.Documents))
	}
	return out
}

// ---------------------------------------------------------------- firestore

// firestoreHost is where Firestore lives. A variable, not a constant, so a
// test can point the collection probes at a stub -- which is what lets the
// budget be graded without spending anybody's quota to do it.
var firestoreHost = "https://firestore.googleapis.com"

func firestoreDocsURL(project string) string {
	return firestoreHost + "/v1/projects/" + project +
		"/databases/(default)/documents"
}

func firestoreFindings(ctx context.Context, d Detection, o ScanOptions) []finding.Finding {
	if d.Credential == "" || len(o.Candidates) == 0 {
		return nil
	}
	base := firestoreDocsURL(d.Project)
	key := url.QueryEscape(d.Credential)

	names := append([]string{}, o.Candidates...)
	sort.Strings(names) // determinism: request order is not an input
	// Spread, not truncated. Taking the first N alphabetically would spend the
	// whole budget on names beginning with a, and the gap in the resulting
	// lower bound would be one contiguous slice of the list that nothing in
	// the report identifies. Take keeps n items sampled across the whole
	// vocabulary, which is the same rule the seed and page budgets follow.
	// Strided is the wrong tool here and the test caught me using it: it
	// REORDERS and keeps everything, so the budget was honoured by nothing.
	names = sample.Take(names, o.MaxCollections)
	var out []finding.Finding
	var readable int
	var attempted int
	var terminal string
	for _, name := range names {
		attempted++
		probe := probeFirestore(ctx, o.Client, base, key, name)
		if probe.Terminal != "" {
			terminal = probe.Terminal
			break
		}
		if !probe.Readable {
			// 403 here means protected OR absent, indistinguishable. Reporting
			// it either way would be an invention.
			continue
		}
		readable++
		out = append(out, firestoreReadFinding(d, base, key, name, probe.Documents, o))
	}
	if terminal != "" {
		out = append(out, finding.NotAssessedVerb(base, "firestore", "READ",
			fmt.Sprintf("Firestore returned a project-level terminal response after %d "+
				"request(s): %s. Further collection-name probes would receive the same "+
				"answer, so the scan stopped instead of spending the remaining %d "+
				"candidates. No per-collection access decision can be inferred, and the "+
				"response does not establish a billed document-read count",
				attempted, terminal, len(names)-attempted)))
		return out
	}
	// The bound is reported whether or not anything was found: a Firestore scan
	// that finds nothing has established that the names it tried were not
	// readable, which is a different statement from "this project is sound".
	//
	// And what it cost is reported with it. Every one of those probes is a
	// query, Firestore bills a minimum of one document read per query, and the
	// free tier is 50,000 reads a day -- so a scan is not free for the person
	// being scanned, and on a project without billing it consumes a quota
	// their application shares. Found the hard way: a day of development
	// against this project's own lab exhausted it, and Google then answered
	// 429 to everything, which is a status that says nothing at all about
	// anybody's rules.
	//
	// An operator is entitled to know the bill before they get it, and to be
	// able to bound it -- -max-collections does that, and lowering it lowers
	// this number and the recall it buys together.
	out = append(out, finding.NotAssessedVerb(base, "firestore", "READ",
		fmt.Sprintf("Firestore collection names cannot be enumerated: listCollectionIds "+
			"is admin-only, there is no near-miss hint, and a protected collection and one "+
			"that does not exist both answer 403. %d name(s) were tried and %d were "+
			"readable; every other name in this project is unmeasured, so this is a lower "+
			"bound and not a clean result. %d query request(s) were issued. Firestore "+
			"queries can consume project quota and may be billable depending on their "+
			"outcome; this scan does not claim a document-read charge it cannot observe. "+
			"Use -max-collections to bound traffic, at the cost of the recall it buys",
			attempted, readable, attempted)))
	return out
}

// firestoreReadable asks whether a collection returns documents, retrieving
// document NAMES only.
//
// runQuery selecting __name__ is the data-minimising probe: it answers with
// document paths and timestamps and no field values. pageSize=0 does not work
// -- Firestore ignores it and returns the documents anyway, measured.
// firestoreQuery is the exact body the probe sends.
//
// Shared with the evidence so the published command reproduces the observation.
// It did not: the curl omitted the __name__ projection entirely, so replaying
// the tool's own evidence returned full documents -- field values included --
// while the finding stated that values were never retrieved.
func firestoreQuery(collection string) []byte {
	b, _ := json.Marshal(map[string]any{
		"structuredQuery": map[string]any{
			"from":   []map[string]string{{"collectionId": collection}},
			"select": map[string]any{"fields": []map[string]string{{"fieldPath": "__name__"}}},
			"limit":  5,
		},
	})
	return b
}

// firestoreReadEvidence is the anonymous probe, as a command.
func firestoreReadEvidence(collection string) string {
	return "curl -sS -X POST '$FIRESTORE_BASE:runQuery?key=$FIREBASE_API_KEY' " +
		"-H 'Content-Type: application/json' -d '" + string(firestoreQuery(collection)) + "'"
}

// firestoreAuthedEvidence is the same probe carrying an account's token.
func firestoreAuthedEvidence(collection string) string {
	return "curl -sS -X POST '$FIRESTORE_BASE:runQuery?key=$FIREBASE_API_KEY' " +
		"-H 'Authorization: Bearer $ID_TOKEN' -H 'Content-Type: application/json' " +
		"-d '" + string(firestoreQuery(collection)) + "'"
}

type firestoreProbe struct {
	Documents []string
	Readable  bool
	Terminal  string
}

func probeFirestore(ctx context.Context, c *client.Client, base, key, collection string) firestoreProbe {
	body := firestoreQuery(collection)
	resp := c.Do(ctx, "POST", base+":runQuery?key="+key, body,
		map[string]string{"Content-Type": "application/json"})
	if resp.Err != nil {
		return firestoreProbe{}
	}
	if resp.Status != 200 {
		return firestoreProbe{Terminal: firestoreTerminal(resp.Status, resp.Body)}
	}
	var rows []struct {
		Document struct {
			Name string `json:"name"`
		} `json:"document"`
	}
	if json.Unmarshal(resp.Body, &rows) != nil {
		return firestoreProbe{}
	}
	var names []string
	for _, r := range rows {
		if r.Document.Name == "" {
			continue // a readTime-only element: the query matched nothing
		}
		names = append(names, r.Document.Name[strings.LastIndex(r.Document.Name, "/")+1:])
	}
	return firestoreProbe{Documents: names, Readable: len(names) > 0}
}

func firestoreReadable(ctx context.Context, c *client.Client, base, key, collection string) ([]string, bool) {
	probe := probeFirestore(ctx, c, base, key, collection)
	return probe.Documents, probe.Readable
}

// firestoreTerminal recognises answers that apply to the whole project, not
// to the collection name. Continuing after one only repeats the same request
// shape and can burn thousands of candidates without measuring one rule.
func firestoreTerminal(status int, body []byte) string {
	var envelope struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)
	reason := ""
	for _, detail := range envelope.Error.Details {
		if detail.Reason != "" {
			reason = detail.Reason
			break
		}
	}
	terminalReasons := map[string]bool{
		"SERVICE_DISABLED": true, "BILLING_DISABLED": true,
		"CONSUMER_INVALID": true, "PROJECT_DELETED": true,
		"API_KEY_INVALID": true,
	}
	if terminalReasons[reason] {
		return reason
	}
	if status == http.StatusTooManyRequests {
		return "quota or rate limit exhausted"
	}
	if status == http.StatusUnauthorized {
		return "request credential rejected"
	}
	message := strings.ToLower(envelope.Error.Message)
	if strings.Contains(message, "api has not been used") ||
		strings.Contains(message, "api is disabled") ||
		strings.Contains(message, "billing") && strings.Contains(message, "disabled") {
		if reason != "" {
			return reason
		}
		return envelope.Error.Status + ": " + envelope.Error.Message
	}
	return ""
}

// reasonForDocs states the count, and names the collection when its name is
// what raised the rating.
func reasonForDocs(n int, sensitive []string) string {
	r := fmt.Sprintf("%d document(s) returned to an unauthenticated caller", n)
	if len(sensitive) > 0 {
		r += "; " + strings.Join(sensitive, ", ")
	}
	return r
}

func firestoreReadFinding(d Detection, base, key, collection string, docs []string, o ScanOptions) finding.Finding {
	sev := finding.High
	// The collection NAME, not its contents. Firestore is probed for document
	// identifiers only, so a collection called payment_methods or user_secrets
	// is rated by what its owner named it -- the same signal, and the same
	// classifier, that decides a Supabase relation's severity from its columns.
	//
	// Document identifiers are deliberately NOT classified: they are usually
	// generated, and a UUID says nothing about what it points at.
	sensitive := classify.Names([]string{collection})
	if len(sensitive) > 0 {
		sev = finding.Critical
	}
	return finding.Finding{
		ID:       "firebase-firestore-anon-read",
		Name:     "Firestore collection is readable by anyone",
		Severity: sev,
		Protocol: "firestore",
		Matched:  base + "/" + collection,
		Resource: collection,
		Description: "The collection " + collection + " returns documents to a caller " +
			"holding only the web API key, which every visitor's browser has. Firestore " +
			"has no row-level security separate from its rules file, so this is the rules " +
			"file allowing it. Document identifiers are quoted as proof; field values were " +
			"deliberately not retrieved.",
		FixKind: finding.FixRulesFile,
		Remediation: "-- Firestore rules are not SQL; edit firestore.rules and deploy.\n" +
			"-- Replace the rule covering this collection with one that names who may read:\n" +
			"--   match /" + collection + "/{doc} {\n" +
			"--     allow read: if request.auth != null && request.auth.uid == resource.data.owner;\n" +
			"--   }\n" +
			"-- Beware 'allow read: if request.auth != null' on its own: signup is open by\n" +
			"-- default, so that grants access to anyone willing to create an account.\n" +
			"-- Then: firebase deploy --only firestore:rules",
		Evidence: finding.Evidence{
			Request: strings.Replace(firestoreReadEvidence(collection),
				"$FIRESTORE_BASE", base, 1),
			Status:  200,
			Columns: docs,
			Reason:  reasonForDocs(len(docs), sensitive),
		},
	}
}

// ---------------------------------------------------------------- rtdb

func rtdbFindings(ctx context.Context, d Detection, o ScanOptions) []finding.Finding {
	host := d.RTDB
	if host == "" {
		return nil
	}
	var out []finding.Finding

	// The root first. One request settles the whole tree, and a readable root
	// makes every path below it moot.
	rootKeys, rootOK, rootAnswered := rtdbProbe(ctx, o.Client, host, "")
	if rootOK {
		return append(out, rtdbFinding(host, "/", rootKeys, true))
	}
	// A root that answered 200 and held nothing is not the same as one that
	// refused. The rules did not reply, so nothing about this database was
	// established -- and a report with no Realtime findings reads as one that
	// was checked and found sound.
	//
	// Reachable in ordinary operation, not just against an emulator: the
	// databaseURL comes out of the application's own bundle, so a project that
	// was renamed, moved region, or shipped a stale config sends this probe
	// somewhere that answers politely and holds nothing. Measured against the
	// Firebase emulator, which selects its namespace with ?ns=: with the
	// namespace wrong, every path answered 200 null -- including one that is
	// denied when addressed correctly.
	if rootAnswered {
		out = append(out, finding.Finding{
			ID:       "unruly-surface-not-assessed",
			Name:     "Realtime Database answered but volunteered nothing",
			Severity: finding.Info,
			Protocol: "rtdb",
			Matched:  host,
			Resource: "rtdb:" + host,
			Description: "The Realtime Database at " + host + " answered 200 with no keys " +
				"at the root, so its rules never replied and nothing here was established. " +
				"That is an empty database with an open root, or an address that is not " +
				"this project's: databaseURL is read from the application's own bundle, " +
				"and a stale one answers exactly like this. A database whose rules refuse " +
				"answers 401 instead, which is why silence here is reported rather than " +
				"assumed to mean sound.",
			Remediation: "-- Nothing to fix in the database. Confirm the databaseURL the\n" +
				"-- application ships is the one you expect, then re-run.",
		})
	}
	names := append([]string{}, o.Candidates...)
	sort.Strings(names)
	for _, p := range names {
		if keys, ok := rtdbReadable(ctx, o.Client, host, p); ok {
			out = append(out, rtdbFinding(host, "/"+p, keys, false))
		}
	}
	return out
}

// rtdbReadable uses shallow=true: key names, no values. A denied path and a
// missing one both answer 401, so only a positive is reportable.
func rtdbReadable(ctx context.Context, c *client.Client, host, path string) ([]string, bool) {
	keys, ok, _ := rtdbProbe(ctx, c, host, path)
	return keys, ok
}

// rtdbProbe also reports whether the server ANSWERED 200. A 200 carrying null
// and a 401 both mean "no keys came back" and they are not the same fact: the
// first is an empty-or-misaddressed database, the second is the rules
// replying. Callers that need to tell those apart use this.
func rtdbProbe(ctx context.Context, c *client.Client, host, path string) ([]string, bool, bool) {
	u := strings.TrimSuffix(host, "/") + "/" + path + ".json?shallow=true"
	resp := c.Get(ctx, u, nil)
	if resp.Err != nil || resp.Status != 200 {
		return nil, false, false
	}
	var m map[string]any
	if json.Unmarshal(resp.Body, &m) != nil || len(m) == 0 {
		// null, or a scalar: nothing enumerable, nothing proven -- but the
		// server did answer 200, which the caller may need to know.
		return nil, false, true
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, true, true
}

// reasonFor states the count, and names the keys that raised the rating when
// any did. A severity the reader cannot account for is one they cannot
// overrule.
func reasonFor(n int, sensitive []string) string {
	r := fmt.Sprintf("%d top-level key(s) returned with no credential", n)
	if len(sensitive) > 0 {
		r += "; " + strings.Join(sensitive, ", ")
	}
	return r
}

func rtdbFinding(host, path string, keys []string, root bool) finding.Finding {
	sev := finding.High
	what := "The path " + path + " is readable"
	// The key names are already in hand -- ?shallow=true returns them and
	// nothing else -- so what this path holds can be rated without retrieving
	// any of it. The same classifier decides a Supabase relation's severity
	// from its column names; a scanner that answered the question differently
	// per backend would be reporting an accident of its own structure as a
	// judgement about the data.
	sensitive := classify.Names(keys)
	if len(sensitive) > 0 {
		sev = finding.Critical
	}
	if root {
		sev = finding.Critical
		what = "The ENTIRE database is readable from its root"
	}
	return finding.Finding{
		ID:       "firebase-rtdb-anon-read",
		Name:     "Realtime Database is readable by anyone",
		Severity: sev,
		Protocol: "rtdb",
		Matched:  strings.TrimSuffix(host, "/") + path + ".json",
		Resource: path,
		Description: what + " by a caller with no credential at all — the Realtime " +
			"Database accepts unauthenticated requests, so this needs not even the API " +
			"key. Top-level key names are quoted as proof; values were deliberately not " +
			"retrieved, which ?shallow=true makes possible.",
		FixKind: finding.FixRulesFile,
		Remediation: "-- Realtime Database rules are JSON, not SQL; edit database.rules.json.\n" +
			"-- A readable root is almost never intended:\n" +
			"--   {\"rules\": {\".read\": false, \".write\": false,\n" +
			"--     \"public\": {\".read\": true}}}\n" +
			"-- Then: firebase deploy --only database",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + strings.TrimSuffix(host, "/") + path + ".json?shallow=true'",
			Status:  200,
			Columns: keys,
			Reason:  reasonFor(len(keys), sensitive),
		},
	}
}

// escalationFinding is a named constructor for the same reason its siblings
// are: a finding built inline inside a network loop can only be exercised by
// reaching the network, so the coverage audit counted this id as one no
// offline test builds.
func escalationFinding(base, name string, docs []string) finding.Finding {
	return finding.Finding{
		ID:       "firebase-firestore-authenticated-read",
		Name:     "Collection is readable by anyone who signs up",
		Severity: finding.High,
		Protocol: "firestore",
		Matched:  base + "/" + name,
		Resource: name,
		Description: "The collection " + name + " refuses anonymous callers and returns " +
			"documents to an account created moments ago with the public web API key. " +
			"This is the shape of a rule written as 'allow read: if request.auth != " +
			"null', which reads as secured: with signup open, the set of people it " +
			"admits is everyone. Anonymous refusal is what makes this look safe in " +
			"every scan that never signs up.",
		FixKind: finding.FixRulesFile,
		Remediation: "-- Scope the rule to the caller rather than to the existence of one:\n" +
			"--   match /" + name + "/{doc} {\n" +
			"--     allow read: if request.auth != null && request.auth.uid == resource.data.owner;\n" +
			"--   }\n" +
			"-- Then: firebase deploy --only firestore:rules",
		Evidence: finding.Evidence{
			Request: strings.Replace(firestoreAuthedEvidence(name), "$FIRESTORE_BASE", base, 1),
			Status:  200,
			Columns: docs,
			Reason: fmt.Sprintf("refused anonymously, %d document(s) returned to a "+
				"newly created account", len(docs)),
		},
	}
}
