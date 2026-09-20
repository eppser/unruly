package supabase

import (
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/history"
	"github.com/eppser/unruly/internal/preview"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/subdomain"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

// Config is everything a Supabase scan needs that is NOT another stage's
// result: the operator's flags, the shared clients, and the budgets.
//
// The distinction is the whole point. Every field here is known before the
// scan starts, which is what lets Stages() produce the complete ordered list
// up front instead of the caller building each stage as the values for it
// happen to become available. That was the shape scanTarget had, and it is why
// adding, removing or handing off a Supabase stage meant editing the command.
type Config struct {
	Client *client.Client
	// Limiter and Timeout are the operator's traffic controls, shared so every
	// stage honours one budget rather than each keeping its own.
	Limiter *client.Limiter
	Timeout time.Duration

	AnonKey     string
	ElevatedKey string
	Site        string
	UserAgent   string
	ArchiveBase string
	// PreviewHosts are extra deployment hosts to check, already split.
	PreviewHosts []string
	// Domain is the registrable domain for subdomain enumeration, resolved by
	// the caller because it is derived from the site URL.
	Domain string

	// Seed sources. Harvested and Supplied describe THIS target; Advertised
	// comes from the OpenAPI document; Pinned is the same everywhere.
	Sources SeedSources
	// HarvestSources is how many documents the harvest actually read. Zero
	// with a site set is the difference between "the application told us
	// nothing" and "we never asked".
	HarvestSources int

	Concurrency     int
	SampleRows      int
	MaxRelation     int
	MaxRPC          int
	MaxColumnProbes int

	Write     bool
	NoResidue bool
	Measure   bool
	Invoke    bool
	Redact    bool

	SkipRoutes     bool
	SkipRealtime   bool
	SkipSubdomains bool
	CheckHistory   bool

	// ExtraRoutines and RPCRoutines are shared allowances. The schemas pass
	// and the surface pass draw on the same RPC budget, so it travels as a
	// budget rather than an int -- see SurfaceStage.RPCRoutines.
	ExtraRoutines *scan.Budget
	RPCRoutines   *scan.Budget
}

// Stages is the complete, ordered Supabase scan.
//
// ORDER IS A DEPENDENCY GRAPH, not a preference. Stages hand each other typed
// artifacts, so probing before enumeration finds no relations to probe, and
// the escalation compare before probing has nothing to compare against. It is
// also what fixes finding order, and two scans of an unchanged project have to
// produce identical bytes.
//
// A stage the operator turned off is WRAPPED, never omitted. The rule this
// project applies to its own checks: a row marked "not run" is not a pass. A
// scan that silently drops a surface reads exactly like a scan that found it
// clean, and two flags here once did precisely that.
func Stages(cfg Config) []scan.Stage {
	budget := func(b *scan.Budget) *scan.Budget {
		if b == nil {
			return scan.NewBudget(0)
		}
		return b
	}
	extra, rpc := budget(cfg.ExtraRoutines), budget(cfg.RPCRoutines)

	// enabled wraps a stage the operator turned off, so it reports itself
	// rather than disappearing.
	enabled := func(on bool, reason string, s scan.Stage) scan.Stage {
		if on {
			return s
		}
		return scan.Skip(s, reason)
	}

	return []scan.Stage{
		VocabularyStage{Sources: cfg.Sources, MaxRPC: cfg.MaxRPC,
			Site: cfg.Site, HarvestSources: cfg.HarvestSources},
		EnumerateStage{
			Client: cfg.Client, MaxRelation: cfg.MaxRelation,
			Concurrency: cfg.Concurrency,
		},
		SelfCheckStage{Client: cfg.Client},
		ProbeStage{
			Client: cfg.Client, Redact: cfg.Redact,
			Opts: probe.Options{
				Write:           cfg.Write,
				SampleRows:      cfg.SampleRows,
				Concurrency:     cfg.Concurrency,
				NoResidue:       cfg.NoResidue,
				Measure:         cfg.Measure,
				MaxColumnProbes: cfg.MaxColumnProbes,
			},
		},
		SchemasStage{
			Client: cfg.Client, Concurrency: cfg.Concurrency,
			Write: cfg.Write, NoResidue: cfg.NoResidue, Measure: cfg.Measure,
			Invoke: cfg.Invoke, Redact: cfg.Redact,
			SampleRows: cfg.SampleRows, MaxColumnProbes: cfg.MaxColumnProbes,
			ExtraRoutines: extra, RPCRoutines: rpc,
		},
		SurfaceStage{
			Client: cfg.Client, RoutineCap: cfg.MaxRPC, RPCRoutines: rpc,
			Opts: surface.Options{
				BucketSeeds:    wordlist.Buckets(cfg.Sources.Harvested),
				Concurrency:    cfg.Concurrency,
				FunctionSeeds:  wordlist.Functions(),
				AllowWrite:     cfg.Write,
				NoResidue:      cfg.NoResidue,
				AllowInvoke:    cfg.Invoke,
				AllowFunctions: cfg.Invoke,
				Redact:         cfg.Redact,
			},
		},
		GraphQLStage{
			Client: cfg.Client, SampleRows: cfg.SampleRows,
			Concurrency: cfg.Concurrency, Redact: cfg.Redact, Measure: cfg.Measure,
		},
		// The application-routes stage USED TO BE HERE and is now
		// backend/application: probing an application's own endpoints for
		// inconsistent authorisation has nothing to do with PostgREST or RLS,
		// and keeping it here meant a project with a different backend -- or
		// none -- never had its routes probed at all.
		enabled(!cfg.SkipRealtime, "-no-realtime was set",
			RealtimeStage{
				Client: cfg.Client, AnonKey: cfg.AnonKey,
				Write: cfg.Write, NoResidue: cfg.NoResidue, Timeout: cfg.Timeout,
			}),
		enabled(cfg.Site != "" && cfg.CheckHistory,
			"no -site was supplied, or -history was not set",
			HistoryStage{Opts: history.Options{
				Site: cfg.Site, CurrentKey: cfg.AnonKey, Redact: cfg.Redact,
				ArchiveBase: cfg.ArchiveBase, Limiter: cfg.Limiter,
				Timeout: cfg.Timeout, UserAgent: cfg.UserAgent,
			}}),
		enabled(cfg.Site != "" || len(cfg.PreviewHosts) > 0,
			"no -site and no -preview hosts were supplied",
			PreviewStage{Opts: preview.Options{
				Site: cfg.Site, Hosts: cfg.PreviewHosts, CurrentKey: cfg.AnonKey,
				Limiter: cfg.Limiter, Timeout: cfg.Timeout,
			}}),
		enabled(!cfg.SkipSubdomains && cfg.Domain != "",
			"-subdomains was not set, or the site has no registrable domain",
			SubdomainStage{Opts: subdomain.Options{
				Domain: cfg.Domain, Labels: wordlist.Subdomains(),
				Concurrency: cfg.Concurrency, Timeout: cfg.Timeout,
			}}),
		// NOT wrapped on ElevatedKey. The token may be MINTED after this list
		// is built, so a decision taken here would disable the pass on the one
		// path that needs it. The stage declines internally when it has
		// neither a supplied nor a published credential, and skippedChecks
		// accounts for that silence.
		scan.Stage(
			EscalationStage{
				Client: cfg.Client, ElevatedKey: cfg.ElevatedKey,
				Concurrency: cfg.Concurrency, SampleRows: cfg.SampleRows,
				Redact: cfg.Redact, Measure: cfg.Measure,
			}),
		// LAST, and never skipped. It translates what the stages above
		// published into the neutral scan.Coverage the command reports on, so
		// the command never reads a backend type to count things.
		CoverageStage{},
	}
}
