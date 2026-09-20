// Package history looks for credentials the application used to ship.
//
// Every scanner surveyed checks the CURRENT bundle, which answers the wrong
// question. A project that moved its Supabase access server-side has clean
// bundles today and gets a clean bill of health — while the key it shipped for
// the previous three months is still valid, still archived, and still grants
// exactly what it always did.
//
// That is the situation on the reference target: Supabase access moved
// server-side, no bundle now contains a credential, and the anon key issued
// before that change remains valid until 2036. Rotation is a separate action
// from removal, and nothing prompts anyone to take it.
//
// So the question worth asking is not "is a key exposed now" but "was a key
// ever exposed, and is it still the key in use". Archived copies of the
// application answer it, and a public archive is a legitimate source: it holds
// only what the site served publicly.
package history

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/finding"
)

var (
// Shapes come from internal/creds; see the note there.
)

// Snapshot is one archived asset that contained a credential.
type Snapshot struct {
	Timestamp string
	URL       string
	// Key is the credential recovered, truncated for reporting.
	KeyPrefix string
	// Role is the credential's claimed role.
	Role string
	// StillCurrent is true when it matches the key the scan is using, meaning
	// the exposure was never remediated by rotation.
	StillCurrent bool
}

// Result is the outcome of a historical scan.
type Result struct {
	Captures  int
	Scanned   int
	Snapshots []Snapshot
	Findings  []finding.Finding
	Requests  int
}

// Options configures the historical scan.
type Options struct {
	Site string
	// UserAgent identifies the scan to the site. Empty means the build
	// default. This stage reads somebody's WEB server, so it is the traffic a
	// human is most likely to see in a log.
	UserAgent string
	// CurrentKey is the credential in use now. Comparing against it is what
	// separates "leaked and rotated" from "leaked and still live".
	CurrentKey string
	// MaxAssets bounds how many archived captures are fetched.
	MaxAssets int
	Timeout   time.Duration
	// Limiter is the scan-wide request budget, shared so -rl governs every
	// stage rather than only the PostgREST one.
	Limiter *client.Limiter
	// Redact suppresses the recovered key prefix. Sixteen characters of a JWT
	// is not enough to use, but it is enough to correlate, and a redacted
	// report should carry nothing an outsider could match against a leak.
	Redact bool
	// ArchiveBase overrides the Wayback Machine origin. Empty means
	// DefaultArchiveBase. Set it to point at a mirror, an offline replay of a
	// CDX response, or a test server -- without it this package cannot be
	// exercised at all, which is how both of its findings came to have no
	// positive-path test.
	ArchiveBase string
}

// Run queries the Wayback Machine for archived scripts and looks for
// credentials in them. It is entirely read-only and touches only the archive.
// limiter is the scan-wide budget, set by Run. A nil limiter is unlimited
// and safe to call.
var limiter *client.Limiter

// DefaultArchiveBase is the public Wayback Machine.
const DefaultArchiveBase = "https://web.archive.org"

// historyUA identifies this stage to the site being read.
var historyUA = client.UserAgent()

func Run(ctx context.Context, o Options) Result {
	if o.UserAgent != "" {
		historyUA = o.UserAgent
	}
	if o.ArchiveBase == "" {
		o.ArchiveBase = DefaultArchiveBase
	}
	o.ArchiveBase = strings.TrimSuffix(o.ArchiveBase, "/")
	if o.MaxAssets <= 0 {
		o.MaxAssets = 60
	}
	if o.Timeout <= 0 {
		// The archive is slow; a short timeout here manufactures false negatives.
		o.Timeout = 60 * time.Second
	}
	limiter = o.Limiter
	res := Result{}
	host := hostOf(o.Site)
	if host == "" {
		return res
	}
	hc := &http.Client{Timeout: o.Timeout}

	captures := cdxQuery(ctx, hc, o.ArchiveBase, host, &res)
	res.Captures = len(captures)
	if len(captures) == 0 {
		return res
	}
	// Deterministic order, and a deterministic subset when the cap binds.
	sort.Slice(captures, func(i, j int) bool {
		if captures[i].original != captures[j].original {
			return captures[i].original < captures[j].original
		}
		return captures[i].timestamp < captures[j].timestamp
	})
	if len(captures) > o.MaxAssets {
		captures = captures[:o.MaxAssets]
	}

	seen := map[string]bool{}
	for _, c := range captures {
		body, ok := fetchArchived(ctx, hc, o.ArchiveBase, c.timestamp, c.original, &res)
		if !ok {
			continue
		}
		res.Scanned++
		for _, tok := range credentials(body) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			snap := Snapshot{
				Timestamp:    c.timestamp,
				URL:          c.original,
				KeyPrefix:    prefix(tok),
				Role:         claimedRole(tok),
				StillCurrent: o.CurrentKey != "" && tok == o.CurrentKey,
			}
			res.Snapshots = append(res.Snapshots, snap)
		}
	}
	sort.Slice(res.Snapshots, func(i, j int) bool {
		return res.Snapshots[i].Timestamp < res.Snapshots[j].Timestamp
	})

	for _, s := range res.Snapshots {
		res.Findings = append(res.Findings, snapshotFinding(o.ArchiveBase, o.Site, s, o.Redact))
	}
	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	return res
}

type capture struct{ timestamp, original string }

// cdxQuery asks the Wayback CDX index for archived scripts.
func cdxQuery(ctx context.Context, hc *http.Client, base, host string, res *Result) []capture {
	q := url.Values{}
	q.Set("url", host+"*")
	q.Set("output", "text")
	q.Set("fl", "timestamp,original")
	q.Set("collapse", "urlkey")
	q.Set("filter", "original:.*\\.js")
	q.Set("limit", "400")
	u := base + "/cdx/search/cdx?" + q.Encode()

	body, ok := get(ctx, hc, u, res)
	if !ok {
		return nil
	}
	var out []capture
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 2 || len(f[0]) < 8 {
			continue
		}
		out = append(out, capture{timestamp: f[0], original: f[1]})
	}
	return out
}

// fetchArchived retrieves the raw archived bytes. The id_ suffix asks the
// archive for the original response rather than its rewritten viewer copy.
func fetchArchived(ctx context.Context, hc *http.Client, base, ts, original string, res *Result) (string, bool) {
	return get(ctx, hc, base+"/web/"+ts+"id_/"+original, res)
}

// get fetches from the archive with bounded retries.
//
// The Wayback CDX index answers 503 under load often enough that a single
// attempt regularly returns nothing, which would silently report a site as
// having no archived credentials. A false "nothing found" is exactly the
// failure this tool exists to avoid, so transient archive errors are retried
// rather than accepted. Backoff is fixed, not random, to keep runs comparable.
func get(ctx context.Context, hc *http.Client, u string, res *Result) (string, bool) {
	limiter.Wait(ctx)
	const attempts = 3
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return "", false
			case <-time.After(time.Duration(i) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", false
		}
		req.Header.Set("User-Agent", historyUA)
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		res.Requests++
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			// Drain rather than close: this path retries against the same
			// host, which is exactly when the connection is worth keeping.
			client.Discard(resp)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			client.Discard(resp)
			return "", false
		}
		b, err := client.ReadBody(resp, 8<<20)
		if err != nil {
			continue
		}
		return string(b), true
	}
	return "", false
}

// credentials pulls Supabase-shaped credentials out of a body.
func credentials(body string) []string {
	var out []string
	for _, t := range creds.JWT.FindAllString(body, -1) {
		if r := claimedRole(t); r == "anon" || r == "service_role" {
			out = append(out, t)
		}
	}
	out = append(out, creds.Publishable.FindAllString(body, -1)...)
	out = append(out, creds.SecretKey.FindAllString(body, -1)...)
	// A Management API token and a Postgres URI are credentials too, and an
	// archive is the one place a secret that was "removed" still works. These
	// reached only the live-site channel when they were added, which is the
	// reason internal/creds exists.
	out = append(out, creds.MgmtToken.FindAllString(body, -1)...)
	for _, m := range creds.PGConn.FindAllStringSubmatch(body, -1) {
		if !creds.PlaceholderPassword(m[1]) {
			out = append(out, m[0])
		}
	}
	sort.Strings(out)
	return out
}

func snapshotFinding(archiveBase, site string, s Snapshot, redact bool) finding.Finding {
	when := humanTimestamp(s.Timestamp)
	shown := s.KeyPrefix
	if redact {
		shown = "[redacted]"
	}

	// A service_role key is catastrophic regardless of age. An anon key that is
	// STILL the current key means the exposure was never actually remediated.
	// An anon key that has since been rotated is history, and reported as such.
	var (
		sev  finding.Severity
		id   string
		name string
		desc string
	)
	switch {
	case strings.HasPrefix(s.KeyPrefix, "sbp_"):
		sev, id = finding.Critical, "supabase-historic-service-key-exposed"
		name = "Management API token found in an archived copy of the site"
		desc = fmt.Sprintf("A Supabase personal access token was served publicly on %s and is "+
			"preserved in a public archive. It authenticates the Management API, which is "+
			"scoped to the ACCOUNT: every project's keys and database passwords, and the "+
			"ability to delete them. Removing it from the bundle did nothing -- the archive "+
			"still serves it. Revoke it at supabase.com/dashboard/account/tokens.", when)
	case strings.HasPrefix(s.KeyPrefix, "postgres"):
		sev, id = finding.Critical, "supabase-historic-service-key-exposed"
		name = "Database connection string found in an archived copy of the site"
		desc = fmt.Sprintf("A Postgres URI carrying a password was served publicly on %s and is "+
			"preserved in a public archive. It is direct database access, past PostgREST and "+
			"therefore past row-level security. Rotate the database password: the archive "+
			"cannot be un-published.", when)
	case s.Role == "service_role" || strings.HasPrefix(s.KeyPrefix, "sb_secret_"):
		sev, id = finding.Critical, "supabase-historic-service-key-exposed"
		name = "service_role key found in an archived copy of the site"
		desc = fmt.Sprintf("A service_role credential was served publicly on %s and is preserved "+
			"in a public archive. It bypasses row-level security entirely. Assume it is compromised.", when)
	case s.StillCurrent:
		sev, id = finding.High, "supabase-historic-key-not-rotated"
		name = "Publicly archived key is still the key in use"
		desc = fmt.Sprintf("This project shipped its anon key to browsers on %s, and a public "+
			"archive still serves that copy. The key recovered from the archive is byte-identical "+
			"to the one this scan is using, so the credential was removed from the bundle but "+
			"never rotated. Anyone who read the archive holds a working key. Current bundles "+
			"being clean is not remediation.", when)
	default:
		sev, id = finding.Info, "supabase-historic-key-rotated"
		name = "Archived copy contains a superseded key"
		desc = fmt.Sprintf("An anon key was served publicly on %s and remains in a public archive, "+
			"but it no longer matches the key in use, so it appears to have been rotated. "+
			"No action needed; recorded for completeness.", when)
	}

	return finding.Finding{
		ID:          id,
		Name:        name,
		Severity:    sev,
		Protocol:    "http",
		Matched:     archiveBase + "/web/" + s.Timestamp + "id_/" + s.URL,
		Resource:    s.Role,
		Description: desc,
		Remediation: `-- Rotate the key rather than only removing it from the bundle:

-- 1. Supabase dashboard -> Project Settings -> API Keys -> roll the key.
-- 2. Update every deployment that uses it.
-- 3. If the exposed key was service_role, treat all data as compromised and
   rotate any secrets stored in the database as well.

-- Removing a credential from the current build does not revoke it. Archives,
-- forks, browser caches and previous deployments keep serving the old copy.`,
		Evidence: finding.Evidence{
			Request:  "curl -sS --compressed '" + archiveBase + "/web/" + s.Timestamp + "id_/" + s.URL + "'",
			Reason:   fmt.Sprintf("role=%s key=%s… archived %s", s.Role, shown, when),
			Response: shown + "…",
		},
	}
}

// claimedRole decodes a JWT's role claim without verifying the signature.
// claimedRole reads the role claim; see internal/creds for why there is only
// one implementation of this now.
func claimedRole(tok string) string { return creds.JWTRole(tok) }

// humanTimestamp renders a CDX timestamp (YYYYMMDDhhmmss) as a date.
func humanTimestamp(ts string) string {
	if len(ts) < 8 {
		return ts
	}
	return ts[0:4] + "-" + ts[4:6] + "-" + ts[6:8]
}

func prefix(k string) string {
	if len(k) > 16 {
		return k[:16]
	}
	return k
}

func hostOf(site string) string {
	u, err := url.Parse(site)
	if err != nil || u.Host == "" {
		return strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(site, "https://"), "http://"), "/")
	}
	return u.Host
}
