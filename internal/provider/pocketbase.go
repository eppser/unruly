package provider

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	pbstage "github.com/eppser/unruly/backend/pocketbase"
	"github.com/eppser/unruly/scan"
)

func init() { Register(pocketbase{}) }

// pocketbase recognises a PocketBase deployment from an application bundle.
//
// PocketBase has no project ref and no publishable key, so there is nothing to
// recognise except the origin itself -- a deployment IS its URL. The SDK is
// constructed with that URL as a literal, which makes the constructor the one
// reliable signal, and makes the origin fall out of detection rather than
// having to be guessed.
type pocketbase struct{}

func (pocketbase) Name() string { return "pocketbase" }

// pbConstructor matches `new PocketBase("origin")` and the newless call the
// SDK also permits. The origin is required: the product NAME on its own is not
// a deployment.
//
// Without that requirement a blog post about PocketBase, or a bundle comment
// naming a dependency, produces a confident scan of a host that does not
// exist. The constructor with an origin is the evidence.
var pbConstructor = regexp.MustCompile(`(?:new\s+)?PocketBase\s*\(\s*([^)]*)\)`)

func (p pocketbase) Detect(s Surface) (Detection, bool) {
	// Sorted so the choice cannot depend on map iteration: detection order
	// feeds report order, and eval-determinism grades byte identity.
	for _, name := range sortedKeys(s.Scripts) {
		if d, ok := p.detectIn(name, s.Site, s.Scripts[name]); ok {
			return d, true
		}
	}
	if d, ok := p.detectIn(s.Site, s.Site, s.HTML); ok {
		return d, true
	}
	return Detection{}, false
}

func (p pocketbase) detectIn(where, site, body string) (Detection, bool) {
	// All matches, then the lowest origin, rather than the first match: a
	// bundle may construct several clients and "whichever appeared first in
	// this file" is not a stable answer across minifier runs.
	ms := pbConstructor.FindAllStringSubmatch(body, -1)
	if len(ms) == 0 {
		return Detection{}, false
	}
	origins := make([]string, 0, len(ms))
	for _, m := range ms {
		if h := originOf(m[1]); h != "" {
			origins = append(origins, h)
		}
	}

	// The constructor named no origin: a relative URL, an empty string, or an
	// expression evaluated at run time.
	//
	// That is not a failure to detect, it is a DIFFERENT DEPLOYMENT SHAPE, and
	// plausibly the commoner one -- PocketBase serves the application itself,
	// and then the client is constructed with "/" or the page origin.
	// Measured on PocketBase's own admin bundle, which reads
	// new PocketBase('${i}'). Requiring an absolute origin missed all of them.
	//
	// The evidence is still the constructor. Falling back to the SITE is sound
	// precisely because the constructor is there: something on this page builds
	// a PocketBase client against an origin it did not have to name, which is
	// what a self-hosted deployment looks like. The Reason says the origin was
	// inferred, so a reader can check the inference rather than take it.
	//
	// Supabase deliberately does NOT do this: its self-hosted origin is
	// unknowable from a bundle, which is why it ships -base-url. The
	// difference is what the evidence supports.
	inferred := false
	if len(origins) == 0 {
		if originOf(site) == "" {
			return Detection{}, false
		}
		origins = append(origins, originOf(site))
		inferred = true
	}
	sort.Strings(origins)
	origin := origins[0]
	reason := "the application constructs a PocketBase client for " + origin
	if inferred {
		reason = "the application constructs a PocketBase client without naming an " +
			"origin, so this site serves its own PocketBase at " + origin
	}

	return Detection{
		Provider: "pocketbase",
		// The FULL origin, scheme included, not just the host.
		//
		// For PocketBase the origin is the instance identity: there is no
		// project ref, and http://host and https://host are different
		// deployments. Keeping only the host forced APIBase to invent a
		// scheme, which addressed every plaintext instance -- including the
		// local lab on http://127.0.0.1:8090 -- at the wrong URL.
		//
		// The alternative was another provider-specific field on Detection
		// beside RTDB and Bucket, which is the drift this rebuild exists to
		// stop.
		Project: origin,
		// No Credential: PocketBase ships no client key. The origin is the
		// whole address, and there is no public token to mistake for a secret.
		Source: where,
		Reason: reason,
	}, true
}

// originOf keeps scheme and host and discards the rest, so a constructor
// written with a trailing path still yields an address requests can be built
// from.
func originOf(raw string) string {
	raw = strings.TrimSpace(raw)
	// The constructor's argument is captured raw now, because it may be a
	// relative path, an empty string or an expression -- shapes a
	// quote-anchored pattern cannot see. So the quotes come off here instead.
	raw = strings.Trim(raw, `"'`+"`")
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// APIBase reports the origin every request is addressed to.
//
// PocketBase implements Endpoint because its address cannot be derived by the
// core: it is not a subdomain of a vendor, it is wherever the operator put it.
func (pocketbase) APIBase(d Detection) string { return d.Project }

// Stages is the work a detected PocketBase instance contributes.
//
// Everything the stage needs comes from the detection (the origin) and the
// inputs (the candidate names, the operator's flags). main learns nothing
// about PocketBase, which is the property that makes a backend contributable
// by someone who has never read main.go.
func (pocketbase) Stages(d Detection, in scan.Inputs) []scan.Stage {
	base := d.Project
	if base == "" {
		return nil
	}
	// Pinned names ship with every instance: PocketBase creates the users
	// auth collection and its system tables on first run, so these are
	// present on essentially every deployment and cost four requests to
	// confirm. They are MERGED with whatever was harvested rather than
	// replacing it -- a pinned list alone finds only what every install has.
	names := append([]string(nil), in.Seeds...)
	names = append(names, defaultCollections...)
	// The client comes from the seam. A stage built without one refuses to run
	// rather than making its own, so the operator's -rate-limit and -timeout
	// cannot silently fail to bind.
	names = dedup(names)
	return []scan.Stage{
		pbstage.CollectionStage{
			Base: base, Collections: names, Redact: in.Redact, Client: in.Client,
		},
		pbstage.EscalationStage{
			Base: base, Collections: names, Redact: in.Redact,
			Consent: in.Controls.Write || in.Write, Client: in.Client,
		},
	}
}

// defaultCollections are created by PocketBase itself on first run, measured
// on a fresh v0.39.11 instance.
var defaultCollections = []string{"users"}

func dedup(xs []string) []string {
	seen := make(map[string]bool, len(xs))
	out := xs[:0:0]
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// Cannot declares what a PocketBase scan does not establish.
//
// Every entry was MEASURED against a running instance and is written down in
// docs/pocketbase-ground-truth.md. That is why this was worth adding rather
// than a nicety: the limits were known, documented in the repository, and
// absent from the report a scan produces. Documented-but-undisclosed is the
// worst of both -- the project knows and the reader does not.
func (pocketbase) Cannot() map[Capability]string {
	return map[Capability]string{
		CapStorage: "file fields and the /api/files delivery path are not probed. A " +
			"collection rule and a file-token rule are separate decisions, so collection " +
			"read results cannot be promoted into a claim about stored files",
		CapWrite: "update and delete permission cannot be established without writing. " +
			"A probe against a fake record id answers 404 for BOTH a rule that is open " +
			"to everyone and an expression rule that matched nothing, byte for byte, so " +
			"only 403 is conclusive -- and 403 is conclusive in the NEGATIVE. This scan " +
			"can say a verb is denied; it cannot say a verb is permitted unless -write " +
			"is given",
		CapListing: "GET /api/collections answers 401 to anyone but a superuser, so what " +
			"exists cannot be enumerated and the candidate list IS the recall. A " +
			"collection absent from this report was not guessed, which is not the same " +
			"as not being there",
		CapExecute: "JS hooks are not examined. A hook runs before a collection's rules " +
			"and can serve whatever it likes, and from outside a deployment there may be " +
			"no sound way to see that one exists. Every rule reported here can be correct " +
			"while a hook hands the same data to anyone",
		CapRealtime: "whether relation changes reach anonymous listeners is not " +
			"established. POST /api/realtime returns 204 for ANY collection name, " +
			"including one that does not exist, so acceptance proves nothing -- rules " +
			"are enforced at DELIVERY. Proving delivery means CAUSING a change, which a " +
			"read-only scan will not do",
	}
}

func (pocketbase) Measures() []Capability { return []Capability{CapRead, CapEscalate} }

// NOT DECLARED, deliberately: weak or default superuser credentials. The admin
// API answers 401 by default on /api/settings, /api/backups, /api/logs and
// /api/collections, so a reachable login page is not itself an exposure --
// guessable credentials would be, and nothing here tests them. That is a check
// nobody has written, not something the protocol prevents measuring. Declaring
// it here would dress a gap in the WORK as a limit of the TARGET, and it would
// then read as permanently unfixable rather than as a to-do.
