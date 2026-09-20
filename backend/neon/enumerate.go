package neon

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// EnumerateStage recovers table names the Data API volunteers.
//
// Neon's Data API is PostgREST, and PostgREST answers a near-miss name with
// PGRST205 and a hint naming the real one. internal/provider's Cannot() used to
// declare enumeration impossible here because the OpenAPI root is not served --
// true, and the wrong conclusion, because the root is not the only oracle.
// Measured against the live lab on 2026-08-22: `rls_disable` draws "Perhaps you
// meant the table 'public.rls_disabled'", and an unrelated name draws nothing,
// which is what makes it evidence about this schema rather than noise.
//
// The oracle is internal/enumerate, unchanged. This stage supplies a client and
// reads the result; if it needed its own oracle the shared package would not be
// shared, and that reuse is the point.
type EnumerateStage struct {
	// Base is the Data API root.
	Base string
	// Seeds are candidate names, from the application's vocabulary.
	Seeds []string
	// Token authenticates the probe.
	//
	// Required, and not for tidiness: a headerless request is refused
	// identically for every name, so an unauthenticated oracle draws no hints
	// and enumeration reports nothing -- indistinguishable from a project with
	// no tables.
	Token string
	// Concurrency bounds in-flight probes.
	Concurrency int
	// Client carries the shared limiter.
	Client *client.Client
}

// Relations is the provider-internal handoff from enumeration to every probe
// tier. It closes the recall gap where names volunteered by the API were
// reported but not actually tested until a second scan.
type Relations struct{ Names []string }

func (EnumerateStage) Name() string { return "neon-relations" }

func (EnumerateStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: (EnumerateStage{}).Name(),
		Produces: []scan.ArtifactType{scan.ArtifactOf[Relations]()}}
}

func (s EnumerateStage) Run(ctx context.Context, st *scan.State) error {
	if s.Client == nil {
		return errNoClient
	}
	scan.Put(st, Relations{Names: mergeRelationNames(s.Seeds)})
	if s.Token == "" {
		st.Add(finding.Finding{
			ID:       "unruly-surface-not-assessed",
			Name:     "Table names were not enumerated",
			Severity: finding.Info,
			Protocol: "postgrest",
			Matched:  s.Base,
			Resource: "enumerating what exists",
			Description: "Enumeration needs a token. On this API a request with no " +
				"Authorization header is refused before any name is consulted, so the " +
				"hint oracle answers nothing and the result would be an empty list -- " +
				"which reads exactly like a project with no tables. Re-run with " +
				"-user-jwt to enumerate, or treat what follows as covering only the " +
				"names the application itself disclosed.",
		})
		return nil
	}

	// Based on s.Base with a bare prefix, because internal/enumerate probes
	// c.RestURL(name) rather than any field of this stage. Handing it the
	// scan-wide client sent every probe to a path that does not exist and the
	// stage reported that the API volunteered nothing -- true of the URL it
	// asked, false of the API.
	c := s.Client.WithBase(s.Base).WithRestPrefix("/").WithBearer(s.Token)
	conc := s.Concurrency
	if conc <= 0 {
		conc = neonProbeConcurrency
	}
	en := enumerate.Run(ctx, c, enumerate.Options{Seeds: s.Seeds, Concurrency: conc})
	st.Attribute(s.Name(), en.Requests)
	all := append([]string(nil), s.Seeds...)
	for _, relation := range en.Relations {
		all = append(all, relation.Name)
	}
	scan.Put(st, Relations{Names: mergeRelationNames(all)})

	// Names the SERVER volunteered are the finding. A name that came from the
	// wordlist and happened to exist is a guess that landed, which is a
	// different claim and is counted separately.
	var hinted []string
	for _, r := range en.Relations {
		if r.Source == "hint" {
			hinted = append(hinted, r.Name)
		}
	}
	sort.Strings(hinted)

	if len(hinted) == 0 {
		st.Add(finding.Finding{
			ID:       "unruly-surface-not-assessed",
			Name:     "The hint oracle volunteered no table name",
			Severity: finding.Info,
			Protocol: "postgrest",
			Matched:  s.Base,
			Resource: "enumerating what exists",
			Description: fmt.Sprintf(
				"%d candidate name(s) were probed and the API volunteered none, so the "+
					"tables reported here are only those the application itself named. "+
					"This is a LOWER BOUND rather than an inventory: PostgREST hints on a "+
					"near miss, and a candidate unlike anything in the schema draws "+
					"nothing, so silence means the guesses were far off rather than that "+
					"the schema is small.", en.SeedCount),
		})
		return nil
	}

	st.Add(finding.Finding{
		ID:       "neon-relations-disclosed",
		Name:     "The Data API volunteers table names it was not asked for",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  s.Base,
		Resource: strings.Join(hinted, ","),
		Description: fmt.Sprintf(
			"PostgREST answered %d near-miss name(s) with a hint naming a real table: %s. "+
				"The names came from the SERVER rather than from a guess that happened to "+
				"land, which is what makes this disclosure rather than reconnaissance. It "+
				"is not itself an exposure -- a name is not data -- and it is what turns "+
				"a scan of names somebody already knew into a scan of what is actually "+
				"there, so it is reported for the same reason a relation inventory is.",
			len(hinted), strings.Join(hinted, ", ")),
		Remediation: "-- The hint is a PostgREST feature and is not configurable per table.\n" +
			"-- What it discloses is limited by what the API role may see, so the fix is\n" +
			"-- the GRANTs rather than the hint:\n" +
			"--   REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated;\n" +
			"-- then grant back only what the application needs. A table no role may\n" +
			"-- reach is still named by the oracle, so treat names as public.",
		Evidence: finding.Evidence{
			Request: fmt.Sprintf(
				`curl -s -H "Authorization: Bearer $NEON_TOKEN" '%s/%s?select=*'`,
				s.Base, nearMissOf(hinted[0])),
			Status: 404,
			Reason: fmt.Sprintf("a near miss for %s drew a hint naming it", hinted[0]),
		},
	})
	return nil
}

func mergeRelationNames(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range groups {
		for _, name := range group {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func relationNames(st *scan.State, fallback []string) []string {
	if got, ok := scan.Get[Relations](st); ok {
		return append([]string(nil), got.Names...)
	}
	return append([]string(nil), fallback...)
}

// nearMissOf produces the probe that draws a hint for a name: the name with its
// last character removed, which is what the oracle is built on.
func nearMissOf(name string) string {
	if len(name) < 2 {
		return name
	}
	return name[:len(name)-1]
}
