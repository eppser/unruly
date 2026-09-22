package browserscan

import (
	"regexp"
	"strings"

	"github.com/eppser/unruly/internal/creds"
)

// Backend is one database an application's own front end points at.
type Backend struct {
	Kind string `json:"kind"` // supabase, firebase, pocketbase, neon
	Ref  string `json:"ref"`  // project reference, where the platform has one
	Base string `json:"base"` // API origin
	Key  string `json:"key"`  // publishable key, where the platform uses one
}

// Patterns are the CLI's, so the browser recognises what the CLI recognises.
var (
	reSupabaseRef = regexp.MustCompile(`([a-z0-9]{20})\.supabase\.co`)

	// Firebase ships a config object. projectId is enough to reach Firestore
	// and, by convention, the default Realtime Database.
	reFbProject  = regexp.MustCompile(`["']?projectId["']?\s*[:=]\s*["']([a-z0-9][a-z0-9-]{3,58}[a-z0-9])["']`)
	reFbAPIKey   = regexp.MustCompile(`["']?apiKey["']?\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{20,})["']`)
	reFbDatabase = regexp.MustCompile(`["']?databaseURL["']?\s*[:=]\s*["'](https?://[^"']+)["']`)
	reFbLegacy   = regexp.MustCompile(`https?://([a-z0-9-]+)\.firebaseio\.com`)
	reFbRTDBNew  = regexp.MustCompile(`https?://([a-z0-9-]+)-default-rtdb\.[a-z0-9-]+\.firebasedatabase\.app`)

	// PocketBase is addressed by its own origin, so the client construction is
	// the only reliable marker.
	rePocketBase = regexp.MustCompile(`new\s+PocketBase\(\s*["']([^"']+)["']`)

	// Neon's Data API is PostgREST behind a Neon host.
	reNeon = regexp.MustCompile(`https://([a-z0-9-]+\.apirest\.[a-z0-9.-]+\.neon\.tech)`)
)

// DetectBackends finds every database an application points at, from its own
// page and bundles.
//
// A browser can reach all of these. Measured from a github.io origin, Firebase
// RTDB and Firestore echo the origin back, Firebase Storage and PocketBase
// answer with "*". An earlier version of this page called three of them "CLI
// only", which was this prototype's scope dressed up as a platform limit.
//
// Ordered: Supabase first, because it is the one probed most thoroughly here,
// then whatever else the application uses.
func DetectBackends(text string) []Backend {
	var out []Backend
	seen := map[string]bool{}
	add := func(b Backend) {
		k := b.Kind + "\x00" + b.Ref + b.Base
		if !seen[k] {
			seen[k] = true
			out = append(out, b)
		}
	}

	if m := reSupabaseRef.FindStringSubmatch(text); m != nil {
		b := Backend{Kind: "supabase", Ref: m[1], Base: "https://" + m[1] + ".supabase.co"}
		if k := creds.Publishable.FindString(text); k != "" {
			b.Key = k
		} else if k := creds.JWT.FindString(text); k != "" && creds.JWTRole(k) == "anon" {
			b.Key = k
		}
		add(b)
	}

	// Firebase: a project id, or a database URL that names one.
	fb := Backend{Kind: "firebase"}
	if m := reFbProject.FindStringSubmatch(text); m != nil {
		fb.Ref = m[1]
	}
	if m := reFbAPIKey.FindStringSubmatch(text); m != nil {
		fb.Key = m[1]
	}
	if m := reFbDatabase.FindStringSubmatch(text); m != nil {
		fb.Base = strings.TrimRight(m[1], "/")
		if fb.Ref == "" {
			if n := reFbRTDBNew.FindStringSubmatch(m[1]); n != nil {
				fb.Ref = n[1]
			} else if n := reFbLegacy.FindStringSubmatch(m[1]); n != nil {
				fb.Ref = n[1]
			}
		}
	}
	if fb.Ref == "" {
		if m := reFbLegacy.FindStringSubmatch(text); m != nil {
			fb.Ref, fb.Base = m[1], "https://"+m[1]+".firebaseio.com"
		} else if m := reFbRTDBNew.FindStringSubmatch(text); m != nil {
			fb.Ref = m[1]
		}
	}
	if fb.Ref != "" {
		add(fb)
	}

	if m := rePocketBase.FindStringSubmatch(text); m != nil {
		add(Backend{Kind: "pocketbase", Base: strings.TrimRight(m[1], "/")})
	}
	if m := reNeon.FindStringSubmatch(text); m != nil {
		add(Backend{Kind: "neon", Base: "https://" + m[1]})
	}
	return out
}
