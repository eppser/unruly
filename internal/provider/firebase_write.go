package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Anonymous WRITE to Firestore and the Realtime Database.
//
// Read exposure was measured from the start and write exposure was declared
// unmeasurable -- the provider said so in its own Cannot(), which is honest
// and was still a critical nobody could report. `allow read, write: if true`
// is one rule, people write it as one rule, and a scanner that reports half of
// it tells an operator their exposure is disclosure when it is control. A file
// a stranger can place is a file other people's browsers will execute.
//
// Three rules govern how this is done, and each exists because the obvious
// implementation is dangerous:
//
//  1. Never write at a path root. RTDB PUT REPLACES the node it addresses, so
//     a probe at /orders.json would delete every order in the database. The
//     probe addresses a child key that did not exist a moment ago.
//  2. Never overwrite. Firestore's documentId is chosen fresh, so the probe
//     creates rather than replaces, and a collision cannot destroy a document
//     somebody else wrote.
//  3. Always remove, and say so when removal fails. A document this scanner
//     created and cannot delete is residue the operator did not agree to.
//
// Under -no-residue the probe is not attempted at all and the verb is reported
// unmeasured, for the same reason signup is: consent to write is not consent
// to leave something behind.

// probeMarker is the field and key name written. Recognisable on sight, so an
// operator finding one in their database knows immediately what put it there.
const probeMarker = "unruly_write_probe"

// writeOutcome is what a write probe established.
type writeOutcome int

const (
	writeRefused  writeOutcome = iota // the rules said no
	writeAccepted                     // written, and removed again
	writeResidue                      // written, and NOT removed
	writeUnknown                      // the request never got an answer
)

// firestoreWritable creates one document and deletes it again.
func firestoreWritable(ctx context.Context, c *client.Client, base, key, collection,
	id string) (writeOutcome, string) {

	body, _ := json.Marshal(map[string]any{
		"fields": map[string]any{
			probeMarker: map[string]any{"stringValue": "safe to delete"},
		},
	})
	u := fmt.Sprintf("%s/%s?key=%s&documentId=%s", base, collection, key, id)
	resp := c.Do(ctx, "POST", u, body, map[string]string{"Content-Type": "application/json"})
	switch {
	case resp.Err != nil:
		return writeUnknown, resp.Request
	case resp.Status == 403 || resp.Status == 401:
		return writeRefused, resp.Request
	case resp.Status != 200:
		// 400 is a malformed document, 409 a collision. Neither says the rules
		// admitted the write, and calling either a finding would report an
		// exposure on the strength of our own bad request.
		return writeUnknown, resp.Request
	}
	del := c.Do(ctx, "DELETE", fmt.Sprintf("%s/%s/%s?key=%s", base, collection, id, key),
		nil, nil)
	if del.Err != nil || del.Status != 200 {
		return writeResidue, resp.Request
	}
	return writeAccepted, resp.Request
}

// rtdbWritable writes one child key and deletes it again.
func rtdbWritable(ctx context.Context, c *client.Client, host, path,
	id string) (writeOutcome, string) {

	// The child, never the parent. A PUT to the parent replaces everything
	// under it, which on a real project is data loss caused by a scan.
	child := strings.TrimSuffix(host, "/") + "/" +
		strings.Trim(path+"/"+id, "/") + ".json"
	resp := c.Do(ctx, "PUT", child, []byte(`{"`+probeMarker+`":"safe to delete"}`),
		map[string]string{"Content-Type": "application/json"})
	switch {
	case resp.Err != nil:
		return writeUnknown, resp.Request
	case resp.Status == 401 || resp.Status == 403:
		return writeRefused, resp.Request
	case resp.Status != 200:
		return writeUnknown, resp.Request
	}
	del := c.Do(ctx, "DELETE", child, nil, nil)
	if del.Err != nil || del.Status != 200 {
		return writeResidue, resp.Request
	}
	return writeAccepted, resp.Request
}

// firestoreWriteFinding reports a collection anyone can write to.
func firestoreWriteFinding(base, collection, request string, left bool) finding.Finding {
	f := finding.Finding{
		ID:       "firebase-firestore-anon-write",
		Name:     "Firestore collection accepts documents from anyone",
		Severity: finding.Critical,
		Protocol: "firestore",
		Matched:  base + "/" + collection,
		Resource: collection,
		Description: "A caller holding only the public web API key created a document in " +
			collection + " and it was accepted. The rule on this collection admits writes " +
			"from anybody, so a stranger can add records your application will read back " +
			"and your team will treat as its own data. This is control rather than " +
			"disclosure: what can be written can be used to place content other people's " +
			"browsers load.",
		Evidence: finding.Evidence{
			Request: request,
			Status:  200,
			Reason: "a document carrying " + probeMarker + " was created by a caller " +
				"holding only the public web API key, and removed again",
		},
		FixKind:     finding.FixRulesFile,
		Remediation: firestoreWriteFix(collection),
	}
	if left {
		f.Description += " The probe document could NOT be removed afterwards and is " +
			"still there; it is the only document in this collection whose " +
			probeMarker + " field is set, and deleting it is safe."
	}
	return f
}

func firestoreWriteFix(collection string) string {
	return "// firestore.rules -- rules are not SQL. Deploy with:\n" +
		"//   firebase deploy --only firestore:rules\n" +
		"//\n" +
		"// The rule that produced this finding allows write to anyone. Scope it to\n" +
		"// the caller who owns the document, or refuse writes from clients entirely\n" +
		"// and route them through a Cloud Function that checks what it is given.\n" +
		"match /" + collection + "/{document} {\n" +
		"  allow read: if <your read rule>;\n" +
		"  allow create, update, delete: if request.auth != null\n" +
		"    && request.auth.uid == request.resource.data.owner;\n" +
		"}\n"
}

// rtdbWriteFinding reports a path anyone can write to.
func rtdbWriteFinding(host, path, request string, left bool) finding.Finding {
	f := finding.Finding{
		ID:       "firebase-rtdb-anon-write",
		Name:     "Realtime Database path accepts writes from anyone",
		Severity: finding.Critical,
		Protocol: "rtdb",
		Matched:  strings.TrimSuffix(host, "/") + path,
		Resource: path,
		Description: "A caller with no credential at all wrote a key under " + path +
			" and it was accepted. Realtime Database rules cascade, so this applies to " +
			"everything beneath that path as well: anyone can add, and by the same rule " +
			"replace, data under it. A PUT to a node REPLACES it, which is why this was " +
			"established with a child key that did not previously exist rather than by " +
			"writing at the path itself.",
		Evidence: finding.Evidence{
			Request: request,
			Status:  200,
			Reason: "a child key carrying " + probeMarker + " was written with no " +
				"credential at all, and removed again",
		},
		FixKind:     finding.FixRulesFile,
		Remediation: rtdbWriteFix(path),
	}
	if left {
		f.Description += " The probe key could NOT be removed afterwards and is still " +
			"there, carrying " + probeMarker + "; deleting it is safe."
	}
	return f
}

func rtdbWriteFix(path string) string {
	return "// database.rules.json -- rules are JSON, not SQL. Deploy with:\n" +
		"//   firebase deploy --only database\n" +
		"//\n" +
		"// A rule at a node governs everything beneath it and cannot be narrowed\n" +
		"// further down, so a true .write here grants the whole subtree.\n" +
		"{\n" +
		"  \"rules\": {\n" +
		"    \"" + strings.Trim(path, "/") + "\": {\n" +
		"      \".read\": \"<your read rule>\",\n" +
		"      \".write\": \"auth != null && auth.uid === $uid\"\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
}

// writeFindings probes the collections and paths that were shown READABLE.
//
// Only those, deliberately. A write probe on a name nothing is known about
// would create a document in a collection that may not exist, on the strength
// of a guess -- and Firestore creates a collection implicitly on first write,
// so a wrong guess does not fail, it MAKES the thing it was asking about. The
// readable set is the set already proven to be there.
//
// That is a recall bound and it is stated in the report: a collection that
// refuses reads and accepts writes is real (a drop box is exactly that shape)
// and is not measured here.
func writeFindings(ctx context.Context, d Detection, o ScanOptions,
	readableFS, readableRT []string) []finding.Finding {

	base := firestoreDocsURL(d.Project)
	if !o.Write {
		return []finding.Finding{finding.NotAssessedVerb(base, "firebase", "WRITE",
			"establishing whether anyone can write means writing, which creates a "+
				"document or a key on the target. That is a mutation, so it is gated: "+
				"re-run with -write -yes-i-own-this on a project you own. Until then a "+
				"collection or path that accepts anonymous writes is unmeasured, not "+
				"absent -- and `allow read, write: if true` is one rule, so a readable "+
				"collection is where to look first")}
	}
	if o.NoResidue {
		return []finding.Finding{finding.NotAssessedVerb(base, "firebase", "WRITE",
			"-no-residue withdraws consent to leave anything behind, and a write probe "+
				"cannot promise that: the document it creates is removed with the same "+
				"public credential that created it, and a rule allowing create while "+
				"refusing delete is a rule people write on purpose")}
	}

	var out []finding.Finding
	// The id is derived from the scan's own marker rather than from a clock or
	// a random source, so two runs against an unchanged target produce the
	// same request and the report stays byte-identical.
	id := probeMarker + "-" + probeDocSuffix
	for _, c := range readableFS {
		switch outcome, req := firestoreWritable(ctx, o.Client, base, d.Credential, c, id); outcome {
		case writeAccepted:
			out = append(out, firestoreWriteFinding(base, c, req, false))
		case writeResidue:
			out = append(out, firestoreWriteFinding(base, c, req, true))
			out = append(out, residueFinding("firestore", base+"/"+c+"/"+id))
		}
	}
	for _, p := range readableRT {
		if p == "/" {
			// The root. Writing a child of the root is still a write to the
			// database, but the finding would name "/" and tell an operator
			// nothing about where to look, and every named path beneath it is
			// covered by its own probe.
			continue
		}
		switch outcome, req := rtdbWritable(ctx, o.Client, d.RTDB, p, id); outcome {
		case writeAccepted:
			out = append(out, rtdbWriteFinding(d.RTDB, p, req, false))
		case writeResidue:
			out = append(out, rtdbWriteFinding(d.RTDB, p, req, true))
			out = append(out, residueFinding("rtdb", strings.TrimSuffix(d.RTDB, "/")+p+"/"+id))
		}
	}
	return out
}

// probeDocSuffix keeps the probe's name fixed across runs. Determinism is a
// property of the whole report, and an identifier carrying a timestamp would
// break it for every scan of every project.
const probeDocSuffix = "safe-to-delete"

// residueFinding reports what the scan could not clean up.
func residueFinding(protocol, where string) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probe-document-left-behind",
		Name:     "This scan created a document it could not remove",
		Severity: finding.High,
		Protocol: protocol,
		Matched:  where,
		Resource: where,
		Description: "The write probe created " + where + " and the delete that should " +
			"have followed was refused. The rules admit creation and not deletion, " +
			"which is a shape people write deliberately. Remove it with a privileged " +
			"credential; it carries the field " + probeMarker + " and nothing else " +
			"depends on it. This is a statement about this scan rather than about the " +
			"target, and it is high because somebody has to act on it.",
		Evidence: finding.Evidence{
			Reason: "delete refused after create succeeded",
		},
		FixKind:     finding.FixConsole,
		Remediation: "// Delete " + where + " from the Firebase console, or with the\n// Admin SDK.\n",
	}
}
