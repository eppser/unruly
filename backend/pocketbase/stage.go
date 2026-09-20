package pocketbase

import (
	"context"
	"errors"
	"sort"
	"strconv"

	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// CollectionStage establishes what an anonymous caller can read from each
// candidate collection.
//
// It reports ONLY collections that returned rows. A collection that answered
// 403 is denied, and one that answered 404 is not there; neither is an
// exposure, and a 200 with an empty items array is not one either. That last
// case is the whole reason this stage is careful: PocketBase's default users
// collection carries the expression rule id = @request.auth.id, which filters
// every row away and still answers 200, so a status-driven check would report
// it as leaking on every install in the world.
type CollectionStage struct {
	// Base is the instance origin, scheme included.
	Base string
	// Collections are the candidate names to try.
	Collections []string
	// Redact removes sampled values while keeping the finding usable.
	Redact bool
	// Client carries the shared limiter and the operator's controls. Supplied
	// by the caller, never built here: a stage that made its own would quietly
	// substitute package defaults for -rate-limit and -timeout.
	Client *client.Client
}

// errNoClient is returned when a stage is run without a client. The caller
// owns the controls, so the caller owns the client.
var errNoClient = errors.New("pocketbase: no client supplied; the caller must pass one so -rate-limit and -timeout bind")

func (CollectionStage) Name() string { return "collections" }

func (CollectionStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: (CollectionStage{}).Name()}
}

// Run probes every candidate and records what came back.
func (s CollectionStage) Run(ctx context.Context, st *scan.State) error {
	if s.Client == nil {
		// An error rather than a default: building a client here would
		// substitute package defaults for -rate-limit and -timeout, and the
		// operator would never learn their flags did not bind this stage.
		return errNoClient
	}
	// Sorted so output does not depend on the order candidates were supplied.
	// Report order is graded byte-for-byte by eval-determinism, and the caller
	// assembles this list from pinned names plus whatever was harvested, which
	// is not a stable order.
	names := append([]string(nil), s.Collections...)
	sort.Strings(names)

	var requests int
	for _, name := range names {
		r := ReadState(ctx, s.Client, s.Base, name)
		requests++
		if !r.Exposed {
			// Denied, absent, or filtered empty. None of these is a finding,
			// and saying nothing about them is what keeps precision.
			continue
		}
		st.Add(readExposed(s.Base, name, r, s.Redact))
	}
	st.Attribute(s.Name(), requests)
	return nil
}

// readExposed builds the finding for a collection that handed rows to an
// anonymous caller.
func readExposed(base, collection string, r Read, redact bool) finding.Finding {
	// Redaction drops the values and keeps the finding usable, which is the
	// convention the Supabase side already follows: the COLUMN NAMES are
	// schema rather than data, and naming them is what lets a reader act on a
	// redacted report without the report becoming a second copy of the leak.
	rows := r.Sample
	reason := strconv.Itoa(len(r.Sample)) + " record(s) returned to an anonymous caller"
	if redact {
		rows = nil
		if cols := columnsOf(r.Sample); len(cols) > 0 {
			reason += "; columns " + strings.Join(cols, ", ")
		}
	}
	return finding.Finding{
		ID:       "pocketbase-anon-read-exposed",
		Name:     "A collection is readable by anyone",
		Severity: finding.High,
		Protocol: "pocketbase",
		Matched:  base + "/api/collections/" + collection + "/records",
		Resource: collection,
		Description: "An anonymous request listed " + strconv.Itoa(len(r.Sample)) +
			" record(s) from the collection \"" + collection + "\". PocketBase applies " +
			"the collection's listRule to this request, so the rule currently permits " +
			"the whole world. The rows below were actually returned; this is not an " +
			"inference from a status code.",
		// Every line a comment: operators pipe -fix straight into psql and the
		// eval executes these blocks verbatim. PocketBase is configured
		// through rules, not SQL, so this must be readable and inert.
		Remediation: "-- PocketBase rules are not SQL; change them in the admin UI or in a\n" +
			"-- migration, then restart is not required.\n" +
			"--\n" +
			"-- Collection: " + collection + "\n" +
			"--   listRule / viewRule are currently open to unauthenticated callers.\n" +
			"--\n" +
			"-- To close them entirely, set both to null (superuser only).\n" +
			"-- To scope them to the owning user instead, set each to:\n" +
			"--   @request.auth.id != \"\" && user = @request.auth.id\n" +
			"--\n" +
			"-- An EMPTY STRING rule means open to the world; null means superuser only.\n" +
			"-- The two are one character apart and are the whole boundary.",
		Evidence: finding.Evidence{
			Reason:  reason,
			Request: r.Request,
			Sample:  rows,
		},
	}
}

// columnsOf lists the field names present in the sampled rows, sorted.
//
// Sorted because JSON object iteration is not ordered and the redacted report
// is graded for byte identity like every other.
func columnsOf(rows []map[string]any) []string {
	seen := map[string]bool{}
	for _, r := range rows {
		for k := range r {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
