package scan

import (
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/semantic"
)

// SeedSet preserves provenance while providers derive their candidate names.
// Merged is retained for providers whose protocol has one undifferentiated
// namespace; the other fields let a provider prefer operator assertions over
// guesses when probing has side effects or cost.
type SeedSet struct {
	Merged      []string
	Pinned      []string
	Harvested   []string
	Advertised  []string
	Supplied    []string
	SourcesRead int
}

// Limits are scan-wide traffic and evidence bounds. A provider consumes the
// limits relevant to its protocol and cannot invent a private default without
// making that divergence visible in its plan tests.
type Limits struct {
	Relations   int
	RPC         int
	Columns     int
	Collections int
	SampleRows  int
}

// Controls are operator decisions shared by every backend.
type Controls struct {
	Write        bool
	Invoke       bool
	NoResidue    bool
	Measure      bool
	SkipRealtime bool
	Subdomains   bool
	History      bool
	// Classifier is an optional local model consulted about columns the
	// deterministic rules could not read. nil is the default and a working
	// no-op; a backend that ignores it simply reports rule classes only.
	Classifier semantic.Asker
}

// Deployment describes application-level context a backend may use for
// history, previews or domain discovery.
type Deployment struct {
	Site         string
	ArchiveBase  string
	PreviewHosts []string
	Domain       string
	UserAgent    string
}

// Inputs are the operator's choices and the scan's upstream discoveries, in
// the form every backend can consume.
//
// It exists because Stages(Detection) alone could only build stages that need
// nothing but the identification, and no real stage is like that: each one
// needs the candidate names found upstream and the flags the operator set. A
// seam that cannot carry those forces every provider to reach around it, which
// is exactly how the orchestration ended up inside main the first time.
//
// The field list is deliberately short and grows one field at a time, each
// justified by a stage that needs it and a test that fails without it. The
// failure to avoid is a struct every backend must accept and only one
// populates -- that is worse than the honest asymmetry it would replace.
// Anything meaningful to a single backend belongs to that backend's own
// package, the way probe.Result is handed between Supabase stages.
type Inputs struct {
	// Seeds are candidate relation or collection names discovered upstream:
	// pinned lists, vocabulary harvested from the application, names
	// advertised by the target, and names supplied by an operator or agent.
	//
	// A backend given none of them says nothing rather than inventing any.
	Seeds []string
	// SeedSet is the provenance-preserving form. Seeds remains the merged form
	// for small providers and backwards-compatible external integrations.
	SeedSet SeedSet

	// Redact removes sampled VALUES from findings while keeping them usable,
	// which every backend must honour identically or -redact means something
	// different depending on what the target happens to run.
	Redact bool

	// Client is the shared, rate-limited HTTP client the operator's flags were
	// applied to. It travels with the work because the alternative is each
	// backend building its own, and a stage that does that quietly substitutes
	// package defaults for -rate-limit and -timeout: the flag is accepted, the
	// stage is unpaced, and nothing says so.
	//
	// A backend that receives none must say so rather than improvise one.
	Client      *client.Client
	Limiter     *client.Limiter
	Timeout     time.Duration
	Concurrency int

	// Write is the operator's -write -yes-i-own-this, and it is consent rather
	// than a preference. A backend must check it before BUILDING a request,
	// not before reporting one: a probe whose result is discarded has still
	// changed somebody's data.
	Write      bool
	Controls   Controls
	Limits     Limits
	Deployment Deployment

	// Bearer is a credential the operator supplied for the target, empty when
	// they supplied none.
	//
	// It is separate from Client because its ABSENCE is information a backend
	// has to act on rather than route around. On Neon there is no anonymous
	// tier to fall back to: without a bearer every name answers identically,
	// so the honest contribution is to report the surface unassessed and skip
	// the stages that would otherwise present a refusal as a measurement.
	Bearer string
	// Credential is the public client credential belonging to the detected
	// backend. Bearer is an authenticated identity used for comparisons.
	Credential string

	// Shared routine budgets are mutable because secondary schemas and the
	// default schema draw from one allowance.
	ExtraRoutines *Budget
	RPCRoutines   *Budget
}
