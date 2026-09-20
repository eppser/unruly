package provider

import (
	"context"
	"regexp"
	"strings"

	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// Firebase detection.
//
// The trap here is the API key. Firebase web keys look like AIzaSy... — and so
// do Google Maps keys, YouTube Data keys and every other browser key Google
// issues. A detector that fires on the key shape alone reports Firebase on any
// site with a map on it, which is a large fraction of the web. So the key is
// never sufficient on its own.
//
// A positive needs a project IDENTITY plus corroboration: either the key sits
// beside a projectId in a config object, or a Firebase-specific host appears.
// Those hosts belong to no other product:
//
//	<project>.firebaseio.com                       Realtime Database (legacy)
//	<project>-default-rtdb.<region>.firebasedatabase.app   Realtime Database
//	firebasestorage.googleapis.com/v0/b/<bucket>   Cloud Storage for Firebase
//	<project>.firebaseapp.com                      Auth handler / hosting
//
// identitytoolkit.googleapis.com is deliberately NOT sufficient by itself: it
// is the Identity Platform endpoint and is used by Google Cloud projects that
// have nothing to do with Firebase.
var (
	fbProjectID  = regexp.MustCompile(`["']?projectId["']?\s*[:=]\s*["']([a-z0-9][a-z0-9-]{3,58}[a-z0-9])["']`)
	fbAPIKey     = regexp.MustCompile(`["']?apiKey["']?\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{20,})["']`)
	fbAppID      = regexp.MustCompile(`["']?appId["']?\s*[:=]\s*["'](\d+:\d+:[a-z]+:[0-9a-f]+)["']`)
	fbBucket     = regexp.MustCompile(`["']?storageBucket["']?\s*[:=]\s*["']([a-z0-9][a-z0-9._-]{2,220})["']`)
	fbRTDBLegacy = regexp.MustCompile(`https?://([a-z0-9-]+)\.firebaseio\.com`)
	fbRTDB       = regexp.MustCompile(`https?://([a-z0-9-]+?)(?:-default-rtdb)?\.([a-z0-9-]+)\.firebasedatabase\.app`)
	fbAuthDomain = regexp.MustCompile(`([a-z0-9-]+)\.firebaseapp\.com`)
	fbStorage    = regexp.MustCompile(`firebasestorage\.googleapis\.com/v0/b/([a-z0-9.-]+)`)
	// The config's own databaseURL is authoritative for the Realtime Database
	// origin, and better than inferring it from a hostname pattern: the region
	// is in the host, self-hosted and emulated deployments do not match the
	// managed shapes at all, and this is where every real application puts it.
	fbDatabaseURL = regexp.MustCompile(`["']?databaseURL["']?\s*[:=]\s*["'](https?://[^"']+)["']`)
)

type firebase struct{}

func init() { Register(firebase{}) }

func (firebase) Name() string { return "firebase" }

// APIBase is the Firebase management origin. The Firestore, RTDB and Remote
// Config probes all address their own hosts absolutely -- firestore.googleapis
// .com, the project's databaseURL, firebaseremoteconfig.googleapis.com -- so
// this is the origin for anything that has no host of its own.
func (firebase) APIBase(Detection) string { return "https://firebase.googleapis.com" }

func (firebase) Detect(s Surface) (Detection, bool) {
	docs := bodies(s)
	for _, where := range sortedKeys(docs) {
		body := docs[where]
		if !strings.Contains(body, "firebase") && !strings.Contains(body, "AIza") {
			continue // cheap reject before any regex runs
		}

		project, key, appID, bucket := "", "", "", ""
		if m := fbProjectID.FindStringSubmatch(body); m != nil {
			project = m[1]
		}
		if m := fbAPIKey.FindStringSubmatch(body); m != nil {
			key = m[1]
		}
		if m := fbAppID.FindStringSubmatch(body); m != nil {
			appID = m[1]
		}
		if m := fbBucket.FindStringSubmatch(body); m != nil {
			bucket = m[1]
		}

		// Corroboration: a host that belongs to Firebase and nothing else.
		host, rtdb := "", ""
		if m := fbDatabaseURL.FindStringSubmatch(body); m != nil {
			rtdb = strings.TrimSuffix(m[1], "/")
		}
		for _, re := range []*regexp.Regexp{fbRTDBLegacy, fbRTDB, fbAuthDomain} {
			if m := re.FindStringSubmatch(body); m != nil {
				host = m[0]
				if re != fbAuthDomain && rtdb == "" {
					// Only when the config did not declare one: the region
					// lives in the hostname, so this cannot be rebuilt from the
					// project id later.
					rtdb = m[0]
				}
				if project == "" {
					// The subdomain names the project when the config object
					// was minified past recognition. No trimming needed: the
					// pattern puts -default-rtdb in a non-capturing group, so
					// the capture is already the bare project.
					project = m[1]
				}
				break
			}
		}
		if host == "" {
			if m := fbStorage.FindStringSubmatch(body); m != nil {
				host = m[0]
				if project == "" {
					project = strings.TrimSuffix(strings.TrimSuffix(m[1],
						".firebasestorage.app"), ".appspot.com")
				}
			}
		}

		switch {
		case project != "" && key != "":
			return Detection{
				Provider: "firebase", Project: project, Credential: key, Source: where,
				RTDB: rtdb, AppID: appID, Bucket: bucket,
				Reason: "a Firebase config object carrying both projectId and apiKey",
			}, true
		case project != "" && host != "":
			return Detection{
				Provider: "firebase", Project: project, Credential: key, Source: where,
				RTDB: rtdb, AppID: appID, Bucket: bucket,
				Reason: "a Firebase-specific host (" + host + ") naming the project",
			}, true
		}
		// A bare AIza key with nothing else is a Google browser key. It could
		// belong to Maps, and reporting it as Firebase would be a guess.
	}
	return Detection{}, false
}

// Cannot declares what a Firebase scan does not establish.
//
// Both entries are things this provider genuinely does not answer, and both
// were silent before: a reader saw findings about what can be READ and had no
// way to tell that nothing had been asked about the rest.
func (firebase) Cannot() map[Capability]string {
	return map[Capability]string{
		CapWrite: "write is probed only where READ already succeeded. Firestore " +
			"creates a collection implicitly on the first write, so probing a guessed " +
			"name would not fail against a collection that is not there -- it would " +
			"MAKE the thing it was asking about. A collection or path that refuses " +
			"reads and accepts writes is a real shape, a drop box is exactly that, and " +
			"this scan does not reach it",
		CapListing: "Firestore's listCollectionIds is administrator-only, and a " +
			"collection that is protected answers 403 identically to one that has " +
			"never existed. What exists therefore cannot be enumerated, recall is a " +
			"lower bound, and \"protected\" is never claimed",
	}
}

func (firebase) Measures() []Capability {
	return []Capability{CapRead, CapWrite, CapEscalate, CapStorage, CapExecute, CapRealtime}
}

// Stages puts Firebase behind the same executable-plan contract as every
// other provider. firebaseAssessmentStage initially wraps the mature assessor
// as one coarse stage; the engine boundary is still complete, and individual
// Firebase surfaces can be split without changing the command.
func (firebase) Stages(d Detection, in scan.Inputs) []scan.Stage {
	candidates := in.Seeds
	if len(in.SeedSet.Merged) > 0 {
		candidates = in.SeedSet.Merged
	}
	return []scan.Stage{firebaseAssessmentStage{Detection: d, Options: ScanOptions{
		Client: in.Client, Candidates: candidates,
		Measure: in.Controls.Measure, MaxCollections: in.Limits.Collections,
		Write: in.Controls.Write || in.Write, SampleRows: in.Limits.SampleRows,
		Invoke: in.Controls.Invoke, Supplied: in.SeedSet.Supplied,
		Harvested: in.SeedSet.Harvested, NoResidue: in.Controls.NoResidue,
	}}}
}

type firebaseAssessmentStage struct {
	Detection Detection
	Options   ScanOptions
}

func (firebaseAssessmentStage) Name() string { return "firebase.assessment" }

func (s firebaseAssessmentStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: s.Name(),
		Produces:      []scan.ArtifactType{scan.ArtifactOf[scan.Access]()},
		MutatesTarget: s.Options.Write || s.Options.Invoke}
}

func (s firebaseAssessmentStage) Run(ctx context.Context, st *scan.State) error {
	if s.Options.Client == nil {
		return errFirebaseNoClient
	}
	before, _ := s.Options.Client.Stats()
	fs := firebase{}.assess(ctx, s.Detection, s.Options)
	st.Add(fs...)
	scan.Put(st, firebaseAccess(fs))
	after, _ := s.Options.Client.Stats()
	st.Attribute(s.Name(), int(after-before))
	return nil
}

var errFirebaseNoClient = findingError("firebase: no shared client supplied")

type findingError string

func (e findingError) Error() string { return string(e) }

func firebaseAccess(fs []finding.Finding) scan.Access {
	var out scan.Access
	for _, f := range fs {
		fact := scan.AccessFact{Resource: f.Resource}
		switch f.ID {
		case "firebase-firestore-anon-read", "firebase-rtdb-anon-read":
			fact.Operation, fact.Subject, fact.Allowed = "read", "anonymous", true
		case "firebase-firestore-anon-write", "firebase-rtdb-anon-write":
			fact.Operation, fact.Subject, fact.Allowed = "write", "anonymous", true
		case "firebase-firestore-authenticated-read":
			fact.Operation, fact.Subject, fact.Allowed = "read", "authenticated", true
		default:
			continue
		}
		out.Observed = append(out.Observed, fact)
	}
	return scan.MergeAccess(out)
}
