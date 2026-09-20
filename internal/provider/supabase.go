package provider

import (
	"context"
	"regexp"
	"strings"

	supabasestage "github.com/eppser/unruly/backend/supabase"
	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/subdomain"
	"github.com/eppser/unruly/scan"
)

// Supabase detection.
//
// The trap here is the mirror image of Firebase's. A page that merely MENTIONS
// supabase.co is not a Supabase application: the population study that this
// scanner was measured against found sites whose only reference was an image
// loaded from somebody else's storage bucket, several of them the hosting
// platform's own logo. Those projects belong to a stranger, and scanning one
// because a logo pointed at it is exactly the mistake this tool exists not to
// make.
//
// So a positive needs the project ref AND a credential that belongs to it, or
// a ref appearing in an API position rather than an asset URL. A ref alone,
// found only inside a storage path, is not a detection.
var (
	sbRef     = regexp.MustCompile(`([a-z0-9]{20})\.supabase\.co`)
	sbStorage = regexp.MustCompile(`([a-z0-9]{20})\.supabase\.co/storage/v1/`)
	sbAPI     = regexp.MustCompile(`([a-z0-9]{20})\.supabase\.co/(?:rest|auth|realtime|functions|graphql)/`)
)

type supabase struct{}

func init() { Register(supabase{}) }

func (supabase) Name() string { return "supabase" }

func (supabase) Measures() []Capability { return append([]Capability(nil), allCapabilities...) }

func (supabase) Cannot() map[Capability]string { return nil }

func (supabase) APIBase(d Detection) string {
	if d.Provider != "supabase" || d.Project == "" {
		return ""
	}
	if strings.Contains(d.Project, "://") {
		return strings.TrimRight(d.Project, "/")
	}
	return "https://" + d.Project + ".supabase.co"
}

func (supabase) DescribePreparation(_ Detection, in scan.Inputs) PreparationDescriptor {
	attempts := 1
	if in.Client != nil {
		if retries := in.Client.Retries(); retries > 0 {
			attempts += retries
		}
	}
	// Prefix check, one alternate mount at most, and OpenAPI acquisition.
	return PreparationDescriptor{ID: "supabase.prepare", MaxRequests: 3 * attempts}
}

func (supabase) Prepare(ctx context.Context, d Detection, in scan.Inputs) Preparation {
	p := Preparation{Detection: d, Inputs: in}
	if in.Client == nil {
		return p
	}
	before, _ := in.Client.Stats()
	moved, to, verdict := probe.ResolveRestPrefix(ctx, in.Client)
	switch verdict {
	case probe.PrefixMoved:
		p.Inputs.Client = moved
		p.Findings = append(p.Findings,
			finding.RestPrefixCorrected(in.Client.BaseURL(), in.Client.RestPrefix(), to))
	case probe.PrefixWrongAndUnresolved:
		p.Findings = append(p.Findings,
			finding.RestPrefixUnresolved(in.Client.BaseURL(), in.Client.RestPrefix()))
		p.Stop = true
	}
	// OpenAPI is acquisition, not assessment. Fetch it only after the provider
	// has settled on the actual PostgREST mount, and preserve the names as
	// advertised seeds. Every advertised name is still probed before it can
	// affect a finding.
	if !p.Stop {
		p.Inputs.SeedSet.Advertised = append(p.Inputs.SeedSet.Advertised,
			probe.SchemaNames(ctx, p.Inputs.Client)...)
	}
	after, _ := in.Client.Stats() // clones share the authoritative counter
	p.Requests = int(after - before)
	p.Spending = []scan.StageSpend{{Stage: "supabase.preparation", Requests: p.Requests}}
	return p
}

// Stages translates the provider-neutral engine inputs into the Supabase
// plan. The command no longer imports backend/supabase or knows its stage
// order; adding a Supabase stage changes this provider and its tests only.
func (supabase) Stages(d Detection, in scan.Inputs) []scan.Stage {
	credential := in.Credential
	if credential == "" {
		credential = d.Credential
	}
	write := in.Controls.Write || in.Write
	extra, rpc := in.ExtraRoutines, in.RPCRoutines
	if extra == nil {
		extra = scan.NewBudget(in.Limits.RPC / 2)
	}
	if rpc == nil {
		rpc = scan.NewBudget(in.Limits.RPC)
	}
	seeds := in.SeedSet
	if len(seeds.Merged) == 0 && len(in.Seeds) > 0 &&
		len(seeds.Pinned)+len(seeds.Harvested)+len(seeds.Advertised)+len(seeds.Supplied) == 0 {
		// A generic caller cannot state provenance it does not have. Treat its
		// merged names as supplied rather than pretending the scanner found them.
		seeds.Supplied = append([]string(nil), in.Seeds...)
	}
	domain := in.Deployment.Domain
	if domain == "" && in.Deployment.Site != "" {
		domain = subdomain.RegistrableDomain(hostOfURL(in.Deployment.Site))
	}
	return supabasestage.Stages(supabasestage.Config{
		Client: in.Client, Limiter: in.Limiter, Timeout: in.Timeout,
		AnonKey: credential, ElevatedKey: in.Bearer,
		Site: in.Deployment.Site, UserAgent: in.Deployment.UserAgent,
		ArchiveBase:  in.Deployment.ArchiveBase,
		PreviewHosts: append([]string(nil), in.Deployment.PreviewHosts...),
		Domain:       domain,
		Sources: supabasestage.SeedSources{
			Pinned: seeds.Pinned, Harvested: seeds.Harvested,
			Advertised: seeds.Advertised, Supplied: seeds.Supplied,
		},
		HarvestSources: seeds.SourcesRead,
		Concurrency:    in.Concurrency, SampleRows: in.Limits.SampleRows,
		MaxRelation: in.Limits.Relations, MaxRPC: in.Limits.RPC,
		MaxColumnProbes: in.Limits.Columns,
		Write:           write, Invoke: in.Controls.Invoke, NoResidue: in.Controls.NoResidue,
		Measure: in.Controls.Measure, Redact: in.Redact,
		SkipRealtime:   in.Controls.SkipRealtime,
		SkipSubdomains: !in.Controls.Subdomains,
		CheckHistory:   in.Controls.History,
		ExtraRoutines:  extra, RPCRoutines: rpc,
	})
}

func hostOfURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

func (supabase) Detect(s Surface) (Detection, bool) {
	docs := bodies(s)
	for _, where := range sortedKeys(docs) {
		body := docs[where]
		if !strings.Contains(body, "supabase") && !strings.Contains(body, "sb_publishable") {
			continue
		}

		// A key that names its own project is the strongest signal there is:
		// a managed anon key is a JWT whose claims carry the ref, so key and
		// identity corroborate each other in one object.
		for _, tok := range creds.JWT.FindAllString(body, -1) {
			if creds.JWTRole(tok) != "anon" {
				continue
			}
			ref := creds.JWTProjectRef(tok)
			if ref == "" {
				if m := sbRef.FindStringSubmatch(body); m != nil {
					ref = m[1]
				}
			}
			if ref != "" {
				return Detection{
					Provider: "supabase", Project: ref, Credential: tok, Source: where,
					Reason: "an anon key shipped in the bundle for project " + ref,
				}, true
			}
		}
		if m := creds.Publishable.FindString(body); m != "" {
			if r := sbRef.FindStringSubmatch(body); r != nil {
				return Detection{
					Provider: "supabase", Project: r[1], Credential: m, Source: where,
					Reason: "a publishable key shipped in the bundle for project " + r[1],
				}, true
			}
		}

		// No credential. A ref in an API position still identifies a backend
		// this application talks to; a ref that appears ONLY in a storage URL
		// does not, because that is what a hotlinked image looks like.
		if m := sbAPI.FindStringSubmatch(body); m != nil {
			return Detection{
				Provider: "supabase", Project: m[1], Source: where,
				Reason: "the application calls the API of project " + m[1] +
					", though no key was recovered from this surface",
			}, true
		}
		if sbRef.MatchString(body) && !sbStorage.MatchString(body) {
			if m := sbRef.FindStringSubmatch(body); m != nil {
				return Detection{
					Provider: "supabase", Project: m[1], Source: where,
					Reason: "project " + m[1] + " is referenced outside a storage path",
				}, true
			}
		}
	}
	return Detection{}, false
}
