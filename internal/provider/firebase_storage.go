package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
)

// Cloud Storage, where existence IS decidable -- unlike Firestore.
//
// This is the one Firebase surface where a scanner may honestly say
// "protected". Measured against the lab, whose project has no bucket
// provisioned:
//
//	GET /v0/b/<project>.firebasestorage.app/o   404
//	GET /v0/b/<project>.appspot.com/o           404
//
// A bucket that does not exist answers 404. A bucket that exists and whose
// rules refuse the anonymous caller answers 403, and one that lists answers
// 200. Three distinct answers, so the ambiguity that forces silence on
// Firestore -- where protected and absent are both 403 -- does not apply here.
//
// The bucket name is taken from the application's own config and never
// guessed. Bucket names are a GLOBAL namespace: a name assembled from the
// company's own is a request to whoever owns that name, who is very likely not
// the target.

// storageHost is where Cloud Storage lives. A variable so a test can point the
// probe at a stub, for the same reason identityToolkit is one: a unit test
// asserting what this scanner does must not send its traffic to Google.
var storageHost = "https://firebasestorage.googleapis.com"

// storageFindings assesses the declared Cloud Storage bucket.
func storageFindings(ctx context.Context, d Detection, o ScanOptions) []finding.Finding {
	if d.Bucket == "" {
		return nil
	}
	listURL := storageHost + "/v0/b/" +
		url.PathEscape(d.Bucket) + "/o"
	if d.Credential != "" {
		listURL += "?key=" + url.QueryEscape(d.Credential)
	}
	r := o.Client.Do(ctx, "GET", listURL, nil, nil)
	if r.Err != nil {
		return []finding.Finding{finding.NotAssessedVerb(listURL, d.Bucket, "READ",
			"the storage endpoint did not answer, so whether the bucket is readable "+
				"is unknown: "+r.Err.Error())}
	}

	switch {
	case r.Status == 404:
		// Declared and absent. Worth saying quietly: a config naming a bucket
		// that does not exist is a loose end, not an exposure.
		return []finding.Finding{storageAbsentFinding(d, listURL)}
	case r.Status == 403 || r.Status == 401:
		// The one place this scanner can say "protected" about Firebase.
		return []finding.Finding{storageProtectedFinding(d, listURL, r.Status)}
	case r.Status != 200:
		return []finding.Finding{finding.NotAssessedVerb(listURL, d.Bucket, "READ",
			fmt.Sprintf("the storage endpoint answered HTTP %d, which is neither a "+
				"listing nor a refusal, so nothing about this bucket was established",
				r.Status))}
	}

	var out struct {
		Items []struct {
			Name        string `json:"name"`
			ContentType string `json:"contentType"`
			Size        string `json:"size"`
		} `json:"items"`
	}
	if json.Unmarshal(r.Body, &out) != nil {
		return []finding.Finding{finding.NotAssessedVerb(listURL, d.Bucket, "READ",
			"the storage endpoint answered 200 with a body this scan could not parse")}
	}
	if len(out.Items) == 0 {
		// A 200 with no items is a bucket that permits listing and holds
		// nothing. The permission is real and worth reporting; the impact is
		// not, so it is not rated as though data were exposed.
		return []finding.Finding{storageEmptyListingFinding(d, listURL)}
	}

	names := make([]string, 0, len(out.Items))
	for _, it := range out.Items {
		names = append(names, it.Name)
	}
	sort.Strings(names)
	return []finding.Finding{storageOpenFinding(d, listURL, names)}
}

// storageOpenFinding reports a bucket anyone can list.
func storageOpenFinding(d Detection, where string, names []string) finding.Finding {
	sev := finding.High
	why := "object names alone"
	// The names ARE the evidence, and the classifier reads them the same way it
	// reads column names: a bucket of invoices and passport scans is a
	// different report from a bucket of theme images.
	if kinds := probe.SensitiveColumns(objectTokens(names)); len(kinds) > 0 {
		sev = finding.Critical
		why = strings.Join(kinds, ", ")
	}
	shown := names
	if len(shown) > 10 {
		shown = shown[:10]
	}
	return finding.Finding{
		ID:       "firebase-storage-anon-read",
		Name:     "Cloud Storage bucket lists its contents to anyone",
		Severity: sev,
		Protocol: "storage",
		Matched:  where,
		Resource: d.Bucket,
		Description: fmt.Sprintf(
			"The bucket %s returned a listing of %d object(s) to a request carrying "+
				"nothing but the web API key, which every visitor's browser has. Storage "+
				"rules decide this and these allow it: the names below are what any "+
				"stranger sees, and each one can then be fetched by URL. Recognised in "+
				"the names: %s.", d.Bucket, len(names), why),
		FixKind: finding.FixRulesFile,
		Remediation: "-- Not a database change: Cloud Storage has its own rules file.\n" +
			"--   storage.rules, then `firebase deploy --only storage`\n" +
			"--\n" +
			"--   rules_version = '2';\n" +
			"--   service firebase.storage {\n" +
			"--     match /b/{bucket}/o {\n" +
			"--       match /{allPaths=**} {\n" +
			"--         allow read, write: if request.auth != null\n" +
			"--                            && request.auth.uid == resource.metadata.owner;\n" +
			"--       }\n" +
			"--     }\n" +
			"--   }\n" +
			"--\n" +
			"-- `if request.auth != null` alone is NOT enough where signup is open:\n" +
			"-- anybody can become authenticated in one request. Scope to the owner.\n" +
			"-- Objects already listed must be treated as disclosed; rotate anything\n" +
			"-- among them that acts as a credential.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + where + "'",
			Status:  200,
			Reason:  fmt.Sprintf("%d object(s) listed anonymously", len(names)),
			Columns: shown,
		},
	}
}

// objectTokens turns object names into the shape the column classifier reads.
//
// A filename is not a column name and must not be handed to the classifier as
// one. SensitiveColumns anchors on the WHOLE name -- "passport" matches,
// "passport-scan.jpg" does not -- which is right for columns, where a name is a
// single identifier, and useless for storage, where it carries an extension, a
// date and a directory.
//
// So the transformation is explicit and local to this check: drop the
// extension, split on the separators filenames use, classify the parts.
// Loosening SensitiveColumns to substring-match instead would have changed
// every relational finding in the tool to buy this one, and traded away the
// precision that keeps a column called "keyboard" out of the credential bucket.
func objectTokens(names []string) []string {
	var out []string
	for _, n := range names {
		if i := strings.LastIndex(n, "."); i > 0 {
			n = n[:i] // the extension classifies nothing
		}
		out = append(out, strings.FieldsFunc(n, func(r rune) bool {
			return r == '/' || r == '_' || r == '-' || r == '.' || r == ' '
		})...)
	}
	return out
}

// storageProtectedFinding records that the bucket exists and refused.
//
// Info, and reported rather than silent: it is the answer to "was Storage
// looked at", which a report with no storage line cannot give.
func storageProtectedFinding(d Detection, where string, status int) finding.Finding {
	return finding.Finding{
		ID:       "firebase-storage-protected",
		Name:     "Cloud Storage bucket exists and refused the anonymous caller",
		Severity: finding.Info,
		Protocol: "storage",
		Matched:  where,
		Resource: d.Bucket,
		Description: fmt.Sprintf(
			"The bucket %s answered HTTP %d, so it exists and its rules refuse a caller "+
				"holding only the web API key. This is a positive result rather than an "+
				"absence: Cloud Storage answers 404 for a bucket that does not exist, so "+
				"a refusal here means something is there and is closed. Firestore cannot "+
				"be reported this way -- protected and absent are both 403 there -- which "+
				"is why this scanner claims 'protected' about Storage and never about "+
				"collections.", d.Bucket, status),
		FixKind: finding.FixRulesFile,
		Remediation: "-- Nothing to fix. Recorded so the report can distinguish a bucket\n" +
			"-- that was checked and refused from one nobody asked about.\n" +
			"-- What is NOT established: whether a signed-up user can read it. Rules of\n" +
			"-- the form `allow read: if request.auth != null` refuse an anonymous\n" +
			"-- caller exactly like this one and admit anybody who registers. Re-run\n" +
			"-- with -write -yes-i-own-this on a project you own to measure that tier.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + where + "'",
			Status:  status,
			Reason:  fmt.Sprintf("HTTP %d: the bucket exists and denied the listing", status),
		},
	}
}

// storageEmptyListingFinding reports a listable but empty bucket.
func storageEmptyListingFinding(d Detection, where string) finding.Finding {
	return finding.Finding{
		ID:       "firebase-storage-anon-read",
		Name:     "Cloud Storage bucket permits anonymous listing",
		Severity: finding.Low,
		Protocol: "storage",
		Matched:  where,
		Resource: d.Bucket,
		Description: fmt.Sprintf(
			"The bucket %s allowed an anonymous listing and returned no objects. The "+
				"permission is real and the bucket is empty today, so this is rated on "+
				"what it grants rather than on what it currently exposes: anything "+
				"uploaded later is public the moment it lands.", d.Bucket),
		FixKind: finding.FixRulesFile,
		Remediation: "-- Same rules file as a bucket that does list. An empty bucket with\n" +
			"-- open rules is a bucket that will leak the first thing put in it:\n" +
			"--   storage.rules, then `firebase deploy --only storage`",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + where + "'",
			Status:  200,
			Reason:  "listing permitted, zero objects present",
		},
	}
}

// storageAbsentFinding records a bucket the application names and that is not
// there. A loose end rather than an exposure.
func storageAbsentFinding(d Detection, where string) finding.Finding {
	return finding.Finding{
		ID:       "firebase-storage-absent",
		Name:     "The application names a Cloud Storage bucket that does not exist",
		Severity: finding.Info,
		Protocol: "storage",
		Matched:  where,
		Resource: d.Bucket,
		Description: fmt.Sprintf(
			"The configuration shipped to browsers names the bucket %s, and Cloud "+
				"Storage answers 404 for it: no such bucket. Nothing is exposed. It is "+
				"recorded because a name in a config is a name somebody may later create "+
				"-- bucket names are a global namespace, and one an application already "+
				"points at is worth owning before somebody else does.", d.Bucket),
		FixKind: finding.FixRulesFile,
		Remediation: "-- Nothing exposed. Either provision the bucket or take the name out\n" +
			"-- of the client configuration, so the application is not pointing at a\n" +
			"-- name it does not control.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + where + "'",
			Status:  404,
			Reason:  "no such bucket",
		},
	}
}
