package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
)

// Remote Config, where reachability is not the finding.
//
// The template is fetchable by anyone holding the web API key, and that is the
// product working: a client fetches its own configuration before it has a user.
// A scanner reporting "Remote Config is publicly readable" is reporting a
// feature, which is the same error as reporting a 403 as a discovered
// collection.
//
// What can be a finding is the CONTENT. Templates routinely carry third-party
// API keys, internal endpoints and feature flags naming unreleased work,
// because the console looks like a settings page and a value put there is
// invisible until somebody reads the client's network tab. Measured on the lab:
// a template containing stripe_secret_key comes back in full to a request
// carrying nothing but the public key.
//
// So the check classifies every entry and reports only what it recognises,
// which is the same discrimination the relational side needs between a table of
// customer records and a table of marketing copy.
//
// Values are never quoted. The value IS the secret, and a finding that
// republishes it turns a report into a second copy -- the mutation suite has an
// entry for exactly that mistake elsewhere in this tool.

// internalHost marks a value that names somewhere not meant to be public.
var internalHostWords = []string{"internal", "admin", "staging", "preprod",
	"corp", "intranet", "private", "vpn", "backoffice"}

// probeInstanceID identifies this client to Remote Config. Deliberately NOT in
// the "unruly-" namespace: that prefix is the finding-id namespace, and a
// string literal sitting in it is indexed as a finding nobody documented.
const probeInstanceID = "unrulyscan"

// remoteConfigHostOverride lets a test point the fetch at a stub, for the same
// reason functionHostOverride exists: a test asserting what this scanner does
// with a refusal must not ask Google for one.
var remoteConfigHostOverride string

func remoteConfigHost() string {
	if remoteConfigHostOverride != "" {
		return remoteConfigHostOverride
	}
	return "https://firebaseremoteconfig.googleapis.com"
}

func remoteConfigFindings(ctx context.Context, d Detection, o ScanOptions) []finding.Finding {
	u := remoteConfigHost() + "/v1/projects/" + d.Project +
		"/namespaces/firebase:fetch?key=" + url.QueryEscape(d.Credential)
	// Not asked at all. The appId is not a secret -- it ships in the config
	// object every page hands its browsers -- but a scan that never saw one
	// cannot fetch the template, and saying nothing here reads exactly like a
	// template with nothing in it. Remote Config is where a project's own
	// secrets go when somebody wants to change them without shipping a
	// release, so the difference is worth a line.
	if d.Credential == "" || d.AppID == "" {
		return []finding.Finding{remoteConfigNotAssessed(u,
			"the application published no appId (or no web API key), and the Remote "+
				"Config template is addressed by both. Nothing was fetched, so nothing "+
				"is known about what this project keeps there -- which is not the same "+
				"as knowing it keeps nothing")}
	}
	body, _ := json.Marshal(map[string]string{
		"appId": d.AppID, "appInstanceId": probeInstanceID,
	})
	resp := o.Client.Do(ctx, "POST", u, body,
		map[string]string{"Content-Type": "application/json"})
	if resp.Err != nil || resp.Status != 200 {
		// A refusal is not an empty template, and a 429 least of all.
		return []finding.Finding{remoteConfigNotAssessed(u,
			fmt.Sprintf("the Remote Config fetch did not answer (HTTP %d), so the "+
				"template was never read. Absence of a finding here is absence of a "+
				"measurement", resp.Status))}
	}
	var got struct {
		Entries map[string]string `json:"entries"`
		State   string            `json:"state"`
	}
	if json.Unmarshal(resp.Body, &got) != nil || len(got.Entries) == 0 {
		// NO_TEMPLATE, or nothing configured. Fetchability alone is not a
		// finding, so there is nothing to say.
		return nil
	}

	credentials, internal := classifyRemoteConfig(got.Entries)
	if len(credentials) == 0 && len(internal) == 0 {
		return nil
	}
	return []finding.Finding{remoteConfigFinding(d, u, credentials, internal, len(got.Entries))}
}

// classifyRemoteConfig sorts parameter names into what a reader must act on.
// Names only: the caller never sees a value leave this function.
func classifyRemoteConfig(entries map[string]string) (credentials, internal []string) {
	names := make([]string, 0, len(entries))
	for k := range entries {
		names = append(names, k)
	}
	sort.Strings(names) // determinism: map order is not a scan input

	for _, name := range names {
		v := entries[name]
		switch {
		// A credential SHAPE in the value is the strongest signal there is: it
		// does not depend on whoever named the parameter.
		case creds.SecretKey.MatchString(v), creds.JWT.MatchString(v),
			creds.MgmtToken.MatchString(v), creds.PGConn.MatchString(v),
			strings.HasPrefix(v, "sk_live_"), strings.HasPrefix(v, "sk_test_"):
			credentials = append(credentials, name)
		// Otherwise the NAME, using the same classifier the relational side
		// uses, so "stripe_secret_key" is recognised even when the value is a
		// shape nobody has pinned.
		case len(probe.SensitiveColumns([]string{name})) > 0:
			credentials = append(credentials, name)
		case namesSomewhereInternal(v):
			internal = append(internal, name)
		}
	}
	return credentials, internal
}

func namesSomewhereInternal(v string) bool {
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		return false
	}
	host := strings.ToLower(v)
	for _, w := range internalHostWords {
		if strings.Contains(host, w) {
			return true
		}
	}
	return false
}

func remoteConfigFinding(d Detection, endpoint string, credentials, internal []string, total int) finding.Finding {
	sev := finding.Low
	what := "names an internal endpoint"
	if len(credentials) > 0 {
		sev = finding.Critical
		what = "carries something shaped like a credential"
	}
	var parts []string
	if len(credentials) > 0 {
		parts = append(parts, "credential-shaped: "+strings.Join(credentials, ", "))
	}
	if len(internal) > 0 {
		parts = append(parts, "internal endpoint: "+strings.Join(internal, ", "))
	}
	return finding.Finding{
		ID:       "firebase-remote-config-secret",
		Name:     "Remote Config serves a secret to every client",
		Severity: sev,
		Protocol: "firebase-remoteconfig",
		Matched: "https://firebaseremoteconfig.googleapis.com/v1/projects/" + d.Project +
			"/namespaces/firebase:fetch",
		Resource: "remoteconfig",
		Description: fmt.Sprintf(
			"The Remote Config template is fetchable by anyone holding the web API key, "+
				"which every visitor's browser has -- that part is the product working as "+
				"designed. What is not is the content: of %d parameter(s), one or more %s. "+
				"Anything in this template is public, and has been since it was published; "+
				"treat it as disclosed rather than as something to remove quietly.",
			total, what),
		FixKind: finding.FixConsole,
		Remediation: "-- Not a rules change: Remote Config has no rules. Anything here is\n" +
			"-- public by design, so the fix is to stop putting secrets in it.\n" +
			"--  1. ROTATE the credentials named below. They are disclosed, and removing\n" +
			"--     them from the template does not un-disclose them.\n" +
			"--  2. Delete the parameters:\n" +
			"--     Firebase Console -> Engage -> Remote Config\n" +
			"--  3. Move the values to the server side. A client that needs to act on a\n" +
			"--     secret needs a server endpoint that holds it, not a copy of it.",
		Evidence: finding.Evidence{
			Request: "curl -sS -X POST '" + endpoint + "' -H 'Content-Type: application/json' " +
				// Double quotes, so the shell expands $FIREBASE_APP_ID. Inside
				// single quotes it never did: the command sent the literal
				// string as the app id and Remote Config answered 403, so an
				// operator replaying the tool's own evidence concluded the tool
				// was wrong. Found by replaying it rather than by reading it.
				//
				// appInstanceId is what the probe actually sends, not "probe".
				"-d \"{\\\"appId\\\":\\\"$FIREBASE_APP_ID\\\",\\\"appInstanceId\\\":\\\"" + probeInstanceID + "\\\"}\"",
			Status: 200,
			// Parameter NAMES, never values. The value is the secret, and a
			// finding that quotes it is a second copy of it.
			Columns: append(append([]string{}, credentials...), internal...),
			Reason:  strings.Join(parts, "; "),
		},
	}
}

// remoteConfigNotAssessed reports that the template was never read.
func remoteConfigNotAssessed(u, detail string) finding.Finding {
	return finding.Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "Remote Config was not assessed",
		Severity: finding.Info,
		Protocol: "firebase-remoteconfig",
		// The key is dropped from the URL exactly as remoteConfigFinding drops
		// it: it is public, and a report is still not the place to reprint a
		// credential for the reader's convenience.
		Matched:     strings.SplitN(u, "?key=", 2)[0],
		Resource:    "remoteconfig",
		Description: "Remote Config was not measured: " + detail + ".",
	}
}
