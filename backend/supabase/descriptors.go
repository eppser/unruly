package supabase

import (
	"github.com/eppser/unruly/internal/graphql"
	"github.com/eppser/unruly/internal/history"
	"github.com/eppser/unruly/internal/preview"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/selfcheck"
	"github.com/eppser/unruly/internal/subdomain"
	"github.com/eppser/unruly/internal/surface"
	"github.com/eppser/unruly/scan"
)

// What each stage requires and produces, declared.
//
// The list in Stages() was already ordered by these dependencies and tested
// against nine of them by hand. Declaring them moves that from a test that
// knows the answers to a property the plan can be checked against -- including
// by a plan nobody wrote a test for, which is the case that matters when
// somebody adds a stage.
//
// The artifact names are the Go types' names, so the two cannot drift far
// without being obvious.
var (
	ArtVocabulary = scan.ArtifactOf[Vocabulary]()
	ArtRelations  = scan.ArtifactOf[EnumerateOutcome]()
	ArtSelfCheck  = scan.ArtifactOf[selfcheck.Result]()
	ArtProbe      = scan.ArtifactOf[probe.Result]()
	ArtSchemas    = scan.ArtifactOf[Schemas]()
	ArtSurface    = scan.ArtifactOf[surface.Result]()
	ArtGraphQL    = scan.ArtifactOf[graphql.Result]()
	ArtRealtime   = scan.ArtifactOf[RealtimeOutcome]()
	ArtHistory    = scan.ArtifactOf[history.Result]()
	ArtPreview    = scan.ArtifactOf[preview.Result]()
	ArtSubdomain  = scan.ArtifactOf[subdomain.Result]()
	ArtEscalation = scan.ArtifactOf[Escalation]()
	ArtCredential = scan.ArtifactOf[Credential]()
	ArtCoverage   = scan.ArtifactOf[scan.Coverage]()
	ArtAccess     = scan.ArtifactOf[scan.Access]()
)

func (VocabularyStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: "vocabulary", Produces: []scan.ArtifactType{ArtVocabulary}}
}

func (EnumerateStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: "relations",
		Requires: []scan.ArtifactType{ArtVocabulary},
		Produces: []scan.ArtifactType{ArtRelations}}
}

func (SelfCheckStage) Describe() scan.StageDescriptor {
	// Judges the oracles on what enumeration observed, so it needs that
	// result -- the self-check is not a synthetic probe, which is the whole
	// reason it runs after enumeration rather than before.
	return scan.StageDescriptor{ID: "selfcheck", Requires: []scan.ArtifactType{ArtRelations},
		Produces: []scan.ArtifactType{ArtSelfCheck}}
}

func (ProbeStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: "probe",
		Requires: []scan.ArtifactType{ArtRelations},
		Produces: []scan.ArtifactType{ArtProbe}}
}

func (s SchemasStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: "schemas",
		Requires: []scan.ArtifactType{ArtVocabulary},
		Produces: []scan.ArtifactType{ArtSchemas},
		// THIS stage as configured, not the type. The same pass with writes
		// off mutates nothing, and a descriptor that said otherwise would
		// refuse every ordinary scan -- which is how a safety check comes to
		// be switched off.
		MutatesTarget: s.Write}
}

func (s SurfaceStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: "surface",
		Requires: []scan.ArtifactType{ArtVocabulary},
		Produces: []scan.ArtifactType{ArtSurface},
		// Invoking a routine or an Edge Function RUNS it -- it sends email,
		// charges cards, writes to queues -- which is why both are behind
		// -write -invoke and why either one makes this a mutator.
		MutatesTarget: s.Opts.AllowWrite || s.Opts.AllowInvoke}
}

func (GraphQLStage) Describe() scan.StageDescriptor {
	// A GraphQL read is only a BYPASS if REST could not read it, so the probe
	// result is required rather than optional: without it every readable
	// relation would be reported as a bypass.
	return scan.StageDescriptor{ID: "graphql",
		Requires: []scan.ArtifactType{ArtRelations, ArtProbe},
		Produces: []scan.ArtifactType{ArtGraphQL}}
}

func (r RealtimeStage) Describe() scan.StageDescriptor {
	// Schemas is OPTIONAL: absent means no extra schema was discovered, which
	// is the common case, and the default schema is examined either way.
	return scan.StageDescriptor{ID: "realtime",
		Requires: []scan.ArtifactType{ArtRelations, ArtProbe},
		Optional: []scan.ArtifactType{ArtSchemas},
		Produces: []scan.ArtifactType{ArtRealtime},
		// Proving delivery means CAUSING a change, so the delivery probe is
		// the mutating part and it is the only part gated on -write.
		MutatesTarget: r.Write}
}

func (h HistoryStage) Describe() scan.StageDescriptor {
	// Asking a public archive what a site used to serve tells a party that is
	// NOT the target what is being scanned. Declared only when the pass is
	// actually configured to run, so a scan that never touches an archive is
	// not described as one that does.
	return scan.StageDescriptor{ID: "history", Produces: []scan.ArtifactType{ArtHistory},
		SendsSecrets: h.Opts.Site != ""}
}

func (PreviewStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: "preview", Produces: []scan.ArtifactType{ArtPreview}}
}

func (SubdomainStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: "subdomains", Produces: []scan.ArtifactType{ArtSubdomain}}
}

func (EscalationStage) Describe() scan.StageDescriptor {
	// Credential is OPTIONAL because the token may instead have been supplied
	// on the command line, in which case no stage produces one.
	return scan.StageDescriptor{ID: "escalation",
		Requires: []scan.ArtifactType{ArtProbe, ArtRelations},
		Optional: []scan.ArtifactType{ArtSchemas, ArtCredential, ArtSurface},
		Produces: []scan.ArtifactType{ArtEscalation}}
}

func (CoverageStage) Describe() scan.StageDescriptor {
	// Everything it reads is optional: a scan cut short still has a coverage
	// figure, a smaller one, and refusing to publish would leave the command
	// unable to tell "covered nothing" from "said nothing".
	return scan.StageDescriptor{ID: "coverage",
		Optional: []scan.ArtifactType{
			ArtRelations, ArtVocabulary, ArtSchemas, ArtSurface, ArtProbe, ArtEscalation,
		},
		Produces: []scan.ArtifactType{ArtCoverage, ArtAccess}}
}
