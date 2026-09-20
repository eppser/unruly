// Package discover recovers a Supabase project reference and credential from a
// public application, with no prior knowledge.
//
// Existing scanners look in one place: a createClient(url, key) call in the JS
// bundle. That misses the channel that actually leaks on modern deployments.
// On the reference target every shipped bundle was clean — the application had
// moved all Supabase access server-side — yet the project reference was sitting
// in a response header on every single page:
//
//	content-security-policy: ... connect-src 'self' https://<ref>.supabase.co
//
// One unauthenticated request recovers it, no JavaScript parsing involved.
// The header is a security control leaking the thing it protects.
package discover

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/assets"
	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/finding"
)

var (
	// A Supabase project ref is 20 lowercase alphanumerics.
	reRef = regexp.MustCompile(`([a-z0-9]{20})\.supabase\.co`)

	// A declared API origin, for deployments that have no project ref.
	//
	// The managed product's URL contains the reference, so reRef finds the
	// origin and the base URL for free. A SELF-HOSTED deployment declares
	// something like https://supabase.mycompany.com, which matches no
	// reference at all -- and the scan then fell back to treating the WEBSITE
	// as the API origin. Measured on a fixture declaring both a URL and a
	// working key: "no project ref discovered; treating <site> as the API
	// origin", 16,558 requests to a static file server, 0 relations, and a
	// report with nothing above info. The bundle said where the API was and
	// nothing read it.
	//
	// Corroboration is the variable NAME. A bare URL in a bundle means
	// nothing; one assigned to something spelling out supabase and url --
	// SUPABASE_URL, VITE_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_URL, supabaseUrl --
	// is the application telling us its own backend address.
	reDeclaredURL = regexp.MustCompile(
		`(?i)[A-Z0-9_]*SUPABASE[A-Z0-9_]*URL["']?\s*[:=]\s*["'](https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)["']`)
	// Legacy JWT keys and the newer publishable format.
	// Credential shapes live in internal/creds so that every channel which
	// reads application content sees the same set. Two shapes were added here
	// and reached only this file.

)

// Headers that have been observed to carry a project reference.
var refHeaders = []string{
	"content-security-policy",
	"content-security-policy-report-only",
	"access-control-allow-origin",
	"link",
	"report-to",
}

// scanDeclaredURL records the first API origin the application declares for
// itself. First, not last: bundles repeat the value, and a stable choice keeps
// repeated scans of an unchanged site byte-identical.
func scanDeclaredURL(body, where string, res *Result) {
	if res.BaseURL != "" {
		return
	}
	m := reDeclaredURL.FindStringSubmatch(body)
	if m == nil {
		return
	}
	res.BaseURL = strings.TrimRight(m[1], "/")
	res.BaseURLSource = where
}

// Result is what blackbox discovery recovered.
type Result struct {
	ProjectRef string
	AnonKey    string
	// RefSource names the channel the reference leaked through.
	RefSource string
	// BaseURL is an API origin the application declared for itself, used when
	// no project reference was found. Self-hosted deployments have no
	// reference, so without this the scan has no idea where their API is.
	BaseURL string
	// BaseURLSource names where the declared origin was read, so a reader can
	// check it rather than take it.
	BaseURLSource string
	// KeySource names where a credential was found, empty if none.
	KeySource string
	// LoginWall is set when the page that was read looks like a sign-in
	// screen rather than the application. Credentials live in the bundle the
	// app loads AFTER authenticating, so "no key found" here means "you were
	// shown the door", not "this is not a Supabase application".
	LoginWall bool
	// Assets are the JS bundles that were inspected.
	Assets   []string
	Findings []finding.Finding
	Requests int
}

// Options configures discovery.
type Options struct {
	Site       string
	Timeout    time.Duration
	MaxBundles int
	// Limiter is the scan-wide request budget, shared so -rl governs every
	// stage rather than only the PostgREST one.
	Limiter *client.Limiter
	// UserAgent identifies the scan to the site being read. Empty means the
	// build default.
	//
	// The same hole the limiter had, in the control next to it: -user-agent
	// reached the PostgREST client and not this stage, which is the one that
	// fetches somebody's WEB pages. Measured against a recording stub: 134
	// requests, none carrying the override. An operator setting it to point at
	// a page explaining who they are -- which is what its help suggests -- was
	// identifying themselves to the API and staying anonymous to the web server
	// whose logs a human actually reads.
	UserAgent string
	// Web, when set, is the scan-wide client for application traffic, and this
	// stage sends every request through it.
	//
	// It used to build its own bare http.Client. That client had no retry
	// policy, no circuit breaker, and its own connection pool -- so a site
	// answering 429 to everything was asked 131 times with no backoff, while
	// the database at the other end of the same scan was treated correctly.
	// The website and the database belong to the same person; they did not
	// consent twice.
	//
	// Nil keeps the private client, which is what this package's own tests use.
	Web *client.Client
	// Observe receives each fetched document while its bytes are in memory.
	// Discovery does not interpret providers or execute scans; the caller may
	// feed the document to a registry, a vocabulary extractor or nothing.
	// Keeping this callback fact-shaped breaks the dependency from acquisition
	// back into provider orchestration and avoids retaining multi-megabyte
	// bundles solely for a later detection pass.
	Observe func(site, where, body string)
}

// Run performs unauthenticated discovery against a site.
// Two package-level variables lived here -- a limiter and a user agent, each
// set from the options on every Run because the fetch helper was not passed
// them. Both are gone: the client carries the limiter, the user agent, the
// timeout and the retry policy together, so there is nothing left to smuggle
// in through a global. That also removes the quiet hazard of mutable package
// state, which two concurrent scans in one process would have shared.

func Run(ctx context.Context, o Options) Result {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxBundles <= 0 {
		o.MaxBundles = 10
	}
	// Normalised, because prospect lists carry real URLs rather than tidy
	// origins. A site of
	//
	//	https://host/project/X?site=A&view3d=false
	//
	// with "/" appended lands the slash inside the QUERY -- ...&view3d=false/ --
	// which is a different request from the one intended and a nonsense
	// "matched" URL in every finding built from it.
	site := normaliseSite(o.Site)
	// One implementation, and it is the one that ships. This used to fall back
	// to a bare http.Client when no client was supplied -- which is what every
	// test in this package did, so the tests graded a path production never
	// took while the path it did take was covered nowhere. A test proving
	// something about unshipped code is worse than no test, because it also
	// stops anyone looking.
	web := o.Web
	if web == nil {
		web = client.NewApplication(client.AppOptions{
			Site: o.Site, Timeout: o.Timeout, Limiter: o.Limiter,
			UserAgent: o.UserAgent,
		})
	}
	res := Result{}

	get := func(u string) (string, http.Header, bool) {
		r := web.Do(ctx, http.MethodGet, u, nil, nil)
		res.Requests++
		if r.Err != nil {
			return "", r.Header, false
		}
		return string(r.Body), r.Header, true
	}

	body, hdr, ok := get(site)
	if !ok {
		return res
	}

	// ---- headers first: cheapest and most reliable channel ----------------
	for _, h := range refHeaders {
		v := hdr.Get(h)
		if v == "" {
			continue
		}
		if m := reRef.FindStringSubmatch(v); m != nil {
			res.ProjectRef, res.RefSource = m[1], h
			res.Findings = append(res.Findings, refLeakFinding(site, h, v, m[1]))
			break
		}
	}

	// ---- then the HTML body ----------------------------------------------
	if res.ProjectRef == "" {
		if m := reRef.FindStringSubmatch(body); m != nil {
			res.ProjectRef, res.RefSource = m[1], "html"
		}
	}
	scanDeclaredURL(body, "html", &res)
	scanCreds(site, body, &res)
	if o.Observe != nil {
		o.Observe(site, site, body)
	}
	res.LoginWall = looksLikeLogin(body)

	// ---- then shipped JS assets ------------------------------------------
	//
	// Script discovery lives in internal/assets because this package and
	// internal/enumerate both did it, both matched the same short list of
	// framework path prefixes, and both required a leading slash -- so a page
	// serving <script src="script.js"> had its credentials missed by both.
	assets := assets.Scripts(site, body)
	if len(assets) > o.MaxBundles {
		assets = assets[:o.MaxBundles]
	}
	for _, a := range assets {
		js, _, ok := get(a)
		if !ok {
			continue
		}
		res.Assets = append(res.Assets, a)
		if res.ProjectRef == "" {
			if m := reRef.FindStringSubmatch(js); m != nil {
				res.ProjectRef, res.RefSource = m[1], "js-bundle"
			}
		}
		scanDeclaredURL(js, a, &res)
		// `a` is already absolute -- assets.Scripts resolves every reference
		// against the site through SameOrigin, which returns u.String() for an
		// absolute ref and base.ResolveReference for a relative one. Prepending
		// the site again produced
		//
		//	https://site.example/https://site.example/assets/index-a1b2.js
		//
		// which is not just an ugly log line: this string is the KeySource and
		// becomes the Matched URL of the service_role and management-token
		// findings, so the evidence address on a critical finding did not
		// resolve. It is fetched via `a`, so the request always went to the
		// right place and only the report was wrong.
		scanCreds(a, js, &res)
		if o.Observe != nil {
			o.Observe(site, a, js)
		}
	}

	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	return res
}

// scanCreds records any credential shipped to the browser.
func scanCreds(where, content string, res *Result) {
	// A service/secret key in client-side code is unconditionally critical:
	// it bypasses row-level security entirely.
	if m := creds.SecretKey.FindString(content); m != "" {
		res.Findings = append(res.Findings, secretKeyFinding(where, m))
	}
	for _, tok := range creds.JWT.FindAllString(content, -1) {
		role := jwtRole(tok)
		switch role {
		case "service_role":
			res.Findings = append(res.Findings, secretKeyFinding(where, tok))
		case "anon":
			if res.AnonKey == "" {
				res.AnonKey, res.KeySource = tok, where
			}
		}
	}
	if m := creds.Publishable.FindString(content); m != "" && res.AnonKey == "" {
		res.AnonKey, res.KeySource = m, where
	}
	if m := creds.MgmtToken.FindString(content); m != "" {
		res.Findings = append(res.Findings, managementTokenFinding(where, m))
	}
	for _, m := range creds.PGConn.FindAllStringSubmatch(content, -1) {
		if creds.PlaceholderPassword(m[1]) {
			continue
		}
		res.Findings = append(res.Findings, connectionStringFinding(where, m[0], m[1]))
	}
}

func managementTokenFinding(where, token string) finding.Finding {
	return finding.Finding{
		ID:       "supabase-management-token-exposed",
		Name:     "Supabase Management API token in client-side content",
		Severity: finding.Critical,
		Protocol: "http",
		Matched:  where,
		Resource: "management-token",
		Description: "A Supabase personal access token (sbp_) was found in content served to " +
			"browsers. This authenticates the Management API, which is scoped to the ACCOUNT " +
			"rather than to this project: whoever holds it can list every project in the " +
			"organisation, read their API keys and database passwords, rotate or revoke " +
			"those keys, create new projects, and delete existing ones. It is a wider " +
			"compromise than any row-level security finding in this report, and it does not " +
			"stop at the project being scanned.",
		Remediation: "-- 1. Revoke this token NOW at supabase.com/dashboard/account/tokens. It " +
			"is public and must be assumed used.\n" +
			"-- 2. Remove it from the client bundle. The Management API is not a browser API; " +
			"nothing that reaches a browser has any use for this token.\n" +
			"-- 3. Review the organisation's audit log, and treat every project's keys and " +
			"database password as compromised until rotated.\n" +
			"-- 4. Check the git history and deployed previews for the same token, which " +
			"outlive the fix.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + where + "' | grep -oE " + `'sbp_[A-Za-z0-9]+'`,
			Reason:  "token prefix " + safePrefix(token),
			// Prefix only, so a holder of several tokens can tell which leaked
			// without the report becoming another copy of it.
			Response: safePrefix(token) + "…",
		},
	}
}

func connectionStringFinding(where, uri, password string) finding.Finding {
	masked := strings.Replace(uri, ":"+password+"@", ":[REDACTED]@", 1)
	return finding.Finding{
		ID:       "supabase-db-connection-string-exposed",
		Name:     "Postgres connection string with credentials in client-side content",
		Severity: finding.Critical,
		Protocol: "http",
		Matched:  where,
		Resource: "database-credentials",
		Description: "A Postgres URI carrying a password was found in content served to " +
			"browsers. This is direct database access: it does not go through PostgREST, so " +
			"row-level security, the anon role and every policy discussed elsewhere in this " +
			"report are irrelevant to whoever holds it. It permits reading and writing every " +
			"table, reading auth.users, and altering the schema itself.",
		Remediation: "-- 1. Rotate the database password NOW (Supabase: Settings > Database > " +
			"Reset database password). The connection string is public and must be assumed " +
			"used.\n" +
			"-- 2. Remove it from the client bundle. A database URI has no purpose in code that " +
			"reaches a browser; server-side code should read it from the environment.\n" +
			"-- 3. Check the git history and any deployed previews for the same string, which " +
			"outlive the fix.\n" +
			"-- 4. Audit for damage: review auth.users, and any table a stranger could have " +
			"altered.",
		Evidence: finding.Evidence{
			// Reproducible without republishing the password, the same rule the
			// service_role finding follows.
			Request: "curl -sS '" + where + "' | grep -oE " +
				`'postgres(ql)?://[^[:space:]]+'`,
			Reason:   "connection URI found in client-side content",
			Response: masked,
		},
	}
}

func refLeakFinding(site, header, value, ref string) finding.Finding {
	return finding.Finding{
		ID:       "supabase-project-ref-disclosure",
		Name:     "Supabase project reference disclosed in a response header",
		Severity: finding.Info,
		Protocol: "http",
		Matched:  site,
		Resource: header,
		Description: "The " + header + " response header names the project's Supabase origin. " +
			"This identifies the backend to anyone who requests the page, and is the first " +
			"step of every automated Supabase scan. It is not itself a vulnerability, but it " +
			"removes any obscurity around which project to attack.",
		Remediation: "-- If the browser no longer talks to Supabase directly (all access is " +
			"server-side), remove the origin from connect-src:\n" +
			"  content-security-policy: ...; connect-src 'self'",
		Evidence: finding.Evidence{
			Request:  "curl -sSI '" + site + "'",
			Reason:   ref,
			Response: header + ": " + truncate(value, 200),
		},
	}
}

func secretKeyFinding(where, key string) finding.Finding {
	return finding.Finding{
		ID:       "supabase-service-key-exposed",
		Name:     "Supabase service_role key shipped to the browser",
		Severity: finding.Critical,
		Protocol: "http",
		Matched:  where,
		Resource: "service_role",
		Description: "A service_role/secret key was found in client-side content. This key " +
			"bypasses row-level security completely and grants full read and write access to " +
			"every table, bucket and function in the project.",
		Remediation: "-- 1. Revoke this key in the Supabase dashboard immediately.\n" +
			"-- 2. Move all privileged access behind a server-side route.\n" +
			"-- 3. Treat every record in the project as compromised and rotate any secrets it held.",
		Evidence: finding.Evidence{
			// Reproducible by hand, and without quoting the key: the same
			// search that found it, against the same URL. A critical finding
			// that a reader cannot verify independently asks to be trusted,
			// which is the one thing a scanner should never ask for.
			Request: "curl -sS '" + where + "' | grep -oE " +
				"'(eyJ[A-Za-z0-9_-]+[.]){2}[A-Za-z0-9_-]+|sb_secret_[A-Za-z0-9]+'",
			Reason:   "key prefix " + safePrefix(key),
			Response: safePrefix(key) + "…",
		},
	}
}

// jwtRole decodes the role claim without verifying the signature. Verification
// is impossible without the project secret and unnecessary: we only need to
// know what the token claims to be.
// jwtRole reads the role claim. The decoding lives in internal/creds because
// three packages had three implementations of it, two of which missed a
// service_role key whose payload contained a single space.
func jwtRole(tok string) string { return creds.JWTRole(tok) }

func safePrefix(k string) string {
	if len(k) > 12 {
		return k[:12]
	}
	return k
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// normaliseSite turns whatever the operator or a target list supplied into a
// URL that can be fetched and joined against.
//
// Query strings and fragments are dropped: they address a view inside an
// application, not the document that ships its credentials, and keeping them
// makes every derived URL wrong. A path is KEPT, because an application really
// can live under one and its bundle references resolve relative to it.
func normaliseSite(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimRight(raw, "/")
	}
	u.RawQuery, u.Fragment = "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// looksLikeLogin recognises a sign-in screen.
//
// Deliberately conservative: a password input is the one element a login page
// has and a landing page does not. Matching on the words "login" or "sign in"
// alone would fire on every marketing site with a header link.
//
// This changes only what the scan SAYS. A page that cannot be told apart from
// a login wall still yields no credentials either way; the difference is
// whether the operator is told "this is not a Supabase application" or "point
// me at something past the sign-in".
func looksLikeLogin(body string) bool {
	low := strings.ToLower(body)
	// A password input is decisive on its own.
	if strings.Contains(low, `type="password"`) || strings.Contains(low, "type='password'") {
		return true
	}
	// Measured on a real site that reached this branch: the sign-in page
	// carried a <form> and the words "Sign In" but no password input, because
	// the field is rendered after the first step. A form AND sign-in wording
	// together is specific enough; either alone fires on any marketing page
	// with a header link.
	if !strings.Contains(low, "<form") {
		return false
	}
	for _, phrase := range []string{"sign in", "signin", "log in", "login", "anmelden", "connexion"} {
		if strings.Contains(low, phrase) {
			return true
		}
	}
	return false
}
