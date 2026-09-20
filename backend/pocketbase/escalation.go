package pocketbase

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/scan"
)

// probeEmail is the address the escalation account is created under.
//
// CONSTANT, not random. Two scans of an unchanged project must produce
// byte-identical reports, and an address that varied would differ in every
// replayable request the escalation findings carry.
//
// The cost of a constant is a collision, and the collision is INFORMATION: if
// this address already exists, a previous scan created it and failed to remove
// it. That is residue an operator needs told about, so it is reported rather
// than sidestepped with a second address -- which would hide the leak and
// leave two accounts behind instead of one.
const probeEmail = "unruly-probe@example.invalid"

// probePassword is fixed too. It is not a secret: the account exists for
// seconds, holds nothing, and is deleted by the scan that made it.
//
// Deliberately NOT hyphen-lowercase. The first spelling was
// "unruly-probe-account", which matches the shape of a finding id, and
// the id-coverage guard duly reported a password as an undocumented finding
// nothing tested. A constant that can be mistaken for an identifier will be.
const probePassword = "unrulyProbeAccount2026"

// EscalationStage measures what registering an account buys an attacker.
//
// It exists because of a measurement. A PocketBase collection ruled
// `@request.auth.id != ""` answers 200 with ZERO ROWS to an anonymous caller:
// no status, message or body distinguishes it from an empty collection or from
// the default users collection. An entire class of exposure is unreachable
// without performing the signup, and PocketBase ships users.createRule = ""
// so any stranger can perform it.
type EscalationStage struct {
	Base        string
	Collections []string
	Redact      bool
	// Consent is the operator's -write -yes-i-own-this. Signing up WRITES to
	// the target -- it puts a real user in somebody's database -- so without
	// consent no account is created and the gap is reported instead.
	Consent bool
	// Client carries the shared limiter and the operator's controls. Supplied
	// by the caller, never built here: a stage that made its own would quietly
	// substitute package defaults for -rate-limit and -timeout.
	Client *client.Client
}

func (EscalationStage) Name() string { return "escalation" }

func (s EscalationStage) Describe() scan.StageDescriptor {
	return scan.StageDescriptor{ID: s.Name(), MutatesTarget: s.Consent}
}

type acct struct{ token, id string }

// Run signs up, diffs, and removes the account it created.
func (s EscalationStage) Run(ctx context.Context, st *scan.State) error {
	if s.Client == nil {
		// An error rather than a default: building a client here would
		// substitute package defaults for -rate-limit and -timeout, and the
		// operator would never learn their flags did not bind this stage.
		return errNoClient
	}
	if !s.Consent {
		st.Add(finding.NotAssessedStage(s.Base, "escalation",
			"measuring what a registered account can reach requires CREATING one, which "+
				"writes a real user into the target; re-run with -write -yes-i-own-this. "+
				"Collections ruled @request.auth.id != \"\" answer 200 with zero rows to an "+
				"anonymous caller, so they are indistinguishable from empty ones without "+
				"this step"))
		return nil
	}

	a, err := s.signUp(ctx)
	if err != nil {
		st.Add(finding.NotAssessedStage(s.Base, "escalation", err.Error()))
		return nil
	}

	names := append([]string(nil), s.Collections...)
	sort.Strings(names)
	requests := 2
	for _, name := range names {
		anon := ReadState(ctx, s.Client, s.Base, name)
		authed := readAs(ctx, s.Client, s.Base, name, a.token)
		requests += 2
		// The GAIN is the difference. A collection returning the same rows to
		// both callers was already reported by the anonymous pass, and
		// reporting it again inflates the number an operator triages by.
		if len(authed.Sample) > len(anon.Sample) {
			st.Add(escalationGain(s.Base, name, anon, authed, s.Redact))
		}
	}

	// Cleanup, then VERIFY it. A 204 proves one request succeeded; only a
	// failed re-authentication proves the account is gone. This project has
	// already made the other mistake: one DELETE, one 204, and an account left
	// behind that only a listing revealed.
	s.remove(ctx, a)
	requests += 2
	if s.stillAuthenticates(ctx) {
		st.Add(residueLeft(s.Base))
	}
	st.Attribute(s.Name(), requests)
	return nil
}

func (s EscalationStage) post(ctx context.Context, path, token string, body any) (int, []byte) {
	b, _ := json.Marshal(body)
	hdr := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		hdr["Authorization"] = token
	}
	resp := s.Client.Do(ctx, http.MethodPost, s.Base+path, b, hdr)
	if resp.Err != nil {
		return 0, nil
	}
	return resp.Status, resp.Body
}

func (s EscalationStage) signUp(ctx context.Context) (acct, error) {
	code, _ := s.post(ctx, "/api/collections/users/records", "", map[string]string{
		"email": probeEmail, "password": probePassword, "passwordConfirm": probePassword,
	})
	if code != http.StatusOK {
		return acct{}, errSignup(code)
	}
	code, body := s.post(ctx, "/api/collections/users/auth-with-password", "",
		map[string]string{"identity": probeEmail, "password": probePassword})
	if code != http.StatusOK {
		return acct{}, errSignup(code)
	}
	var out struct {
		Token  string `json:"token"`
		Record struct {
			ID string `json:"id"`
		} `json:"record"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return acct{}, err
	}
	return acct{token: out.Token, id: out.Record.ID}, nil
}

func (s EscalationStage) remove(ctx context.Context, a acct) {
	s.Client.Do(ctx, http.MethodDelete,
		s.Base+"/api/collections/users/records/"+a.id, nil,
		map[string]string{"Authorization": a.token})
}

// stillAuthenticates is the verification: if the account can still log in, it
// was not removed, whatever the DELETE returned.
func (s EscalationStage) stillAuthenticates(ctx context.Context) bool {
	code, _ := s.post(ctx, "/api/collections/users/auth-with-password", "",
		map[string]string{"identity": probeEmail, "password": probePassword})
	return code == http.StatusOK
}

type signupErr int

func (e signupErr) Error() string {
	return "the escalation account could not be created (status " + strconv.Itoa(int(e)) +
		"); if the address already exists a previous scan left it behind, and it should " +
		"be removed by hand: " + probeEmail
}

func errSignup(code int) error { return signupErr(code) }

// escalationGain reports rows a registered account can read that an anonymous
// caller cannot.
func escalationGain(base, collection string, anon, authed Read, redact bool) finding.Finding {
	rows := authed.Sample
	reason := strconv.Itoa(len(authed.Sample)) + " record(s) returned to a registered " +
		"account, " + strconv.Itoa(len(anon.Sample)) + " to an anonymous one"
	if redact {
		rows = nil
		if cols := columnsOf(authed.Sample); len(cols) > 0 {
			reason += "; columns " + joinCols(cols)
		}
	}
	return finding.Finding{
		ID:       "pocketbase-authenticated-escalation",
		Name:     "Registering an account unlocks a collection",
		Severity: finding.High,
		Protocol: "pocketbase",
		Matched:  base + "/api/collections/" + collection + "/records",
		Resource: collection,
		Description: "Anyone can register on this instance, and a registered account can " +
			"read \"" + collection + "\" while an anonymous caller cannot. The collection " +
			"answers 200 with zero rows to a stranger, so it is indistinguishable from an " +
			"empty one until an account exists; the rows below were returned to an account " +
			"created by this scan and deleted afterwards.",
		Remediation: "-- PocketBase rules are not SQL; change them in the admin UI or a\n" +
			"-- migration.\n" +
			"--\n" +
			"-- Collection: " + collection + "\n" +
			"--   its rule admits any authenticated caller, e.g. @request.auth.id != \"\"\n" +
			"--\n" +
			"-- Scope it to the owner instead:\n" +
			"--   @request.auth.id != \"\" && user = @request.auth.id\n" +
			"--\n" +
			"-- And close registration if it is not meant to be open: set the users\n" +
			"-- collection createRule to null. It ships as an EMPTY STRING, which means\n" +
			"-- anyone in the world may create an account.",
		Evidence: finding.Evidence{
			Reason:  reason,
			Request: authed.Request,
			Sample:  rows,
		},
	}
}

// residueLeft reports an account this scan created and could not remove.
func residueLeft(base string) finding.Finding {
	return finding.Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "This scan left an account behind",
		Severity: finding.Info,
		Protocol: "unruly",
		Matched:  base,
		Resource: "escalation:residue",
		Description: "The escalation probe created the account " + probeEmail + " and it " +
			"could NOT be removed: it still authenticates after the delete. Nothing else " +
			"in this report is affected, but the account is real and should be deleted " +
			"by hand.",
		Remediation: "-- Delete the account this scan created:\n" +
			"--   " + probeEmail + "\n" +
			"-- It can be removed from the PocketBase admin UI under the users collection.",
		Evidence: finding.Evidence{
			Reason: "the probe account still authenticates after deletion was attempted",
		},
	}
}

func joinCols(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += ", "
		}
		out += c
	}
	return out
}
