// Package provider is the seam between this scanner's shared core and the
// backend-specific checks.
//
// The core owns everything that is true regardless of backend: findings,
// evidence, redaction, severity, exit codes, the request budget and the audit
// harness. A provider owns recognition, its exhaustive capability declaration,
// and the stages that assess one recognised instance.
//
// The seam is drawn at DETECTION first, deliberately. It is the part every
// backend needs, it is decidable from a surface that has already been fetched
// once, and it is where the accuracy of everything downstream is set: a scanner
// that misidentifies the backend spends its whole run asking a database the
// wrong questions.
//
// Adding a backend means implementing Detector in its own package and
// registering it. Nothing in the core changes.
package provider

import (
	"net/http"
	"sort"
	"sync"
)

// Surface is an application as fetched, once, for every provider to inspect.
//
// Passing the bytes rather than a URL is what keeps detection cheap: the site
// and its bundles are downloaded a single time and each provider reads the same
// copy. A Detect that made requests of its own would multiply a scan's cost by
// the number of backends this tool learns to recognise, and would put load on a
// stranger's site to answer a question that is already answerable offline.
type Surface struct {
	Site    string
	HTML    string
	Scripts map[string]string // url -> body
	Headers http.Header
}

// Detection is a positive identification, with what the scan needs to proceed.
type Detection struct {
	// Provider is the canonical name, and the prefix of the finding ids the
	// provider emits.
	Provider string
	// Project identifies the backend instance: a Supabase project ref, a
	// Firebase projectId.
	Project string
	// Credential is the client-side key. In BOTH backends this is public by
	// design -- Supabase's anon key and Firebase's web API key are meant to
	// ship in the bundle -- so finding one is not itself a finding. It is the
	// address, not the secret.
	Credential string
	// Source names where the identification came from, so a reader can check
	// it rather than take it.
	Source string
	// Reason states what made this a positive, in one line, for the report.
	Reason string
	// RTDB is the Realtime Database origin when one was identified. Firebase
	// only; empty for backends that have no such thing.
	RTDB string
	// Bucket is the Cloud Storage bucket the application declares. Firebase
	// only. Named by the config object, so it needs no guessing -- and a
	// guessed bucket would be a request to somebody else's project, since the
	// name is a global namespace.
	Bucket string
	// AppID identifies the client app. Remote Config will not answer without
	// it, which is why detection carries it rather than the scan guessing.
	AppID string
}

// Detector recognises one backend.
type Detector interface {
	Limited
	Staged
	Name() string
	Detect(Surface) (Detection, bool)
}

// Endpoint is implemented by a provider whose assessment speaks to an API
// origin the core cannot know.
//
// It exists because the core was deriving it: the client for every non-Supabase
// backend was built with BaseURL "https://" + provider + ".googleapis.com".
// That is right for exactly one backend and silently wrong for the next one --
// a provider named appwrite would have been handed a client pointed at
// appwrite.googleapis.com, and every probe it made would have gone to a host
// with no relationship to the target. A backend's own address is the most
// backend-specific fact there is, so it belongs to the provider, not to a
// string concatenation in main.
//
// Optional: a provider that addresses everything absolutely returns "".
type Endpoint interface {
	APIBase(Detection) string
}

// APIBase reports the origin a provider's assessment speaks to, or "" when the
// provider addresses its services absolutely.
func APIBase(d Detection) string {
	mu.RLock()
	defer mu.RUnlock()
	for _, det := range detectors {
		if det.Name() != d.Provider {
			continue
		}
		if e, ok := det.(Endpoint); ok {
			return e.APIBase(d)
		}
		return ""
	}
	return ""
}

var (
	mu        sync.RWMutex
	detectors []Detector
)

// Register adds a detector. Call from an init function.
func Register(d Detector) {
	if err := validateCapabilities(d); err != nil {
		panic(err)
	}
	if err := validatePreparation(d); err != nil {
		panic(err)
	}
	mu.Lock()
	defer mu.Unlock()
	detectors = append(detectors, d)
	sort.Slice(detectors, func(i, j int) bool { return detectors[i].Name() < detectors[j].Name() })
}

// Registered lists the detector names, in the order Detect consults them.
func Registered() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(detectors))
	for _, d := range detectors {
		out = append(out, d.Name())
	}
	return out
}

// Detect returns every backend recognised in a surface.
//
// Every one, not the first: an application may legitimately use two backends,
// and picking a winner would hide the second. Order is by provider name so a
// report of an unchanged site is byte-identical between runs.
func Detect(s Surface) []Detection {
	mu.RLock()
	defer mu.RUnlock()
	var out []Detection
	for _, d := range detectors {
		if got, ok := d.Detect(s); ok {
			out = append(out, got)
		}
	}
	return out
}

// bodies yields the HTML and every script, so a detector reads one loop rather
// than repeating the same traversal with its own bug in it.
func bodies(s Surface) map[string]string {
	out := make(map[string]string, len(s.Scripts)+1)
	if s.HTML != "" {
		out[s.Site] = s.HTML
	}
	for u, b := range s.Scripts {
		out[u] = b
	}
	return out
}

// sortedKeys keeps traversal order independent of map iteration, which is the
// difference between a report that diffs cleanly and one that does not.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DetectIn runs every detector against a single document, as it is fetched.
//
// The alternative was to retain every bundle so detection could run afterwards
// over all of them at once. A built application's JavaScript is routinely
// megabytes, and this scanner's rule is not to keep data the report does not
// need -- so detection happens while the bytes are already in hand, and only
// the verdict is kept.
func DetectIn(site, where, body string) []Detection {
	return Detect(Surface{Site: site, Scripts: map[string]string{where: body}})
}

// Merge adds detections not already present, keyed by provider and project.
// Deterministic: the result is sorted, so a report of an unchanged site is
// byte-identical between runs.
func Merge(into []Detection, add ...Detection) []Detection {
	seen := map[string]bool{}
	for _, d := range into {
		seen[d.Provider+"/"+d.Project] = true
	}
	for _, d := range add {
		k := d.Provider + "/" + d.Project
		if seen[k] {
			continue
		}
		seen[k] = true
		into = append(into, d)
	}
	sort.Slice(into, func(i, j int) bool {
		if into[i].Provider != into[j].Provider {
			return into[i].Provider < into[j].Provider
		}
		return into[i].Project < into[j].Project
	})
	return into
}
