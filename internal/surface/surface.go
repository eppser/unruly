// Package surface covers the Supabase services that sit beside PostgREST:
// GoTrue auth configuration, storage buckets, and RPC routines.
//
// Two things here are worth calling out.
//
// RPC enumeration reuses the hint oracle. PostgREST volunteers routine names
// the same way it volunteers relation names, and on the reference target this
// recovered all three token-gated SECURITY DEFINER admin routines with no
// prior knowledge. Those routines are precisely the ones an operator assumes
// are private, because they are not referenced from any client bundle.
//
// Auth configuration matters because `anon` is not the only role an attacker
// can hold. When signup is open, anyone can obtain an `authenticated` JWT, and
// RLS policies written `TO authenticated` are frequently far more permissive
// than the anon ones. Testing only the anon role understates exposure. Actually
// creating an account is a mutation, so it is gated behind the same ownership
// confirmation as write probing.
package surface

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/postgrest"
	"github.com/eppser/unruly/internal/sample"
)

// AuthConfig is the subset of GoTrue settings that affects exposure.
type AuthConfig struct {
	Reachable        bool
	DisableSignup    bool            `json:"disable_signup"`
	MailerAutoconfim bool            `json:"mailer_autoconfirm"`
	PhoneAutoconfirm bool            `json:"phone_autoconfirm"`
	SAMLEnabled      bool            `json:"saml_enabled"`
	External         map[string]bool `json:"external"`
}

// SignupOpen reports whether an attacker can mint an authenticated identity.
func (a AuthConfig) SignupOpen() bool { return a.Reachable && !a.DisableSignup }

// Result aggregates the non-PostgREST surfaces.
type Result struct {
	Auth     AuthConfig
	Buckets  []Bucket
	Routines []string
	// Callable records, per disclosed routine, whether the anonymous role may
	// actually execute it. PostgREST names routines in its hint regardless of
	// EXECUTE privilege, so the two must be measured separately.
	//
	// Absent from the map means INDETERMINATE, not false: see callableRoutines.
	Callable map[string]bool
	// RoutineBudgetBound is true when -max-rpc-probes truncated the candidate
	// list, so the routines reported are a lower bound.
	RoutineBudgetBound bool
	// RoutineCandidatesWanted is how many candidates would have been probed
	// without the cap.
	RoutineCandidatesWanted int
	// StorageReachable distinguishes "no public buckets" from "could not ask".
	StorageReachable bool
	Functions        []EdgeFunction
	// FunctionsUnresolved counts function names whose probe got no usable
	// answer, so the function list is a lower bound.
	FunctionsUnresolved int
	Findings            []finding.Finding
	Requests            int
	// RequestsBy attributes those requests to the sub-stage that made them.
	//
	// "surface" was one ledger entry covering routine discovery, bucket
	// probing, Edge Functions and auth, and it was the largest spender on a
	// real target: 4,406 of 12,068 requests, buying four routine disclosures.
	// A ledger exists so an operator can see where their traffic went, and the
	// biggest line in it said only "surface". Reasoning from an opaque bucket
	// has already cost this project one wrong investigation, when a mislabelled
	// stage sent it looking at storage for a spend that was elsewhere.
	RequestsBy map[string]int
}

// EdgeFunction is a deployed Deno function and how it treats anonymous callers.
type EdgeFunction struct {
	Name string
	// Status is the response to an anonymous invocation.
	Status int
	// RequiresJWT is true when the platform rejected the call before the
	// function ran, i.e. verify_jwt is on.
	RequiresJWT bool
	// Snippet is a short excerpt of the response body.
	Snippet string
	// unresolved marks a probe that got no usable answer, so the name was
	// neither shown to exist nor ruled out.
	unresolved bool
}

// Invokable reports whether an anonymous caller actually reached the function.
func (f EdgeFunction) Invokable() bool { return !f.RequiresJWT }

// Bucket is a storage bucket visible to the scanning role.
type Bucket struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Public bool   `json:"public"`
	// Objects are the first few files the bucket serves, when they could be
	// listed. Evidence rather than assertion.
	Objects []string `json:"-"`
}

// Options configures surface scanning.
type Options struct {
	// Redact suppresses response bodies captured from the target. An Edge
	// Function's response is arbitrary application output -- a user record, a
	// token, whatever the function returns -- and this package's own finding
	// text notes that functions commonly hold the service_role key. It was
	// being emitted verbatim under -redact, the same leak the application
	// route probe had.
	Redact bool
	// BucketSeeds are candidate storage bucket names. Buckets cannot be
	// enumerated by the anonymous role, so they are reached by name or not at
	// all.
	BucketSeeds []string
	// RoutineGuesses are candidate routine names probed VERBATIM rather than
	// trimmed into stems.
	//
	// The stem strategy assumes a seed is a real name that must be trimmed to
	// become a near miss. A COMPOSED guess is already an approximation, and
	// trimming it pushes it past the similarity threshold instead of onto it.
	// Measured against a routine named admin_read_audit_log:
	//
	//	admin_audit_log  (whole)   HINT
	//	admin_audit_lo   (n-1)     no hint
	//	admin_audit      (3n/4)    no hint
	//
	// So composing better seeds achieved nothing until they stopped being
	// trimmed. Two different jobs that both looked like "candidate names".
	RoutineGuesses []string
	// RoutineSeeds are candidate names for the RPC hint oracle. Reusing the
	// harvested application vocabulary keeps this deterministic and generic.
	RoutineSeeds []string
	Concurrency  int
	// MaxCandidates bounds RPC probing. Sorted before truncation, so the cap
	// is deterministic.
	MaxCandidates int
	// FunctionSeeds are candidate Edge Function names.
	FunctionSeeds []string
	// AllowFunctions permits probing Edge Functions.
	//
	// The discriminator requires a POST: the platform answers 404 for absent,
	// 401 when verify_jwt rejects the caller, and anything else means the
	// request reached the function — which is to say the function RAN. A
	// deployed function with verify_jwt off is invoked by the act of detecting
	// it, and Edge Functions send email, charge cards and write to queues.
	//
	// Off by default, for the same reason routes are not POSTed to and
	// routines are not called. The cost is total for this check: without it no
	// Edge Function is detected at all, which the scan states rather than
	// leaving as an apparently clean result.
	AllowFunctions bool
	// AllowWrite permits writes to discovered surfaces: currently an object
	// uploaded to a public bucket and deleted again. Small, but a write.
	AllowWrite bool
	// NoResidue withdraws permission for any probe that could leave something
	// behind on the target, which for this package means the bucket upload.
	//
	// The upload deletes itself afterwards and reports honestly when it
	// cannot. That is not what the flag asks for: a bucket granting INSERT
	// but not DELETE keeps the file, which is the storage version of exactly
	// the table case -no-residue was built for. This field did not exist
	// until an audit swept every mutating request in the tree and found that
	// NoResidue reached one package out of three that write.
	NoResidue bool
	// Schema qualifies routine names in findings and in the SQL they carry.
	// The templates said public.%s literally, so a routine in another exposed
	// schema got remediation naming the WRONG schema explicitly -- which does
	// not fail safe: it either errors or revokes on some other function.
	Schema string
	// AllowInvoke permits CALLING discovered routines to learn whether the
	// anonymous role may execute them.
	//
	// There is no way to ask "may I call this" without calling it. PostgREST
	// checks EXECUTE when the statement runs, so the probe invokes the routine
	// and reads what comes back — and a routine that is callable RUNS. Verified
	// on a fixture: POSTing {} to a zero-argument function executed its body,
	// which is exactly what an admin routine named purge, reset or delete does
	// for a living, and SECURITY DEFINER ones run with the owner's rights.
	//
	// Off by default. Without it, disclosure is still reported and callability
	// is reported as unknown, which is true.
	AllowInvoke bool
}

// Routines runs ONLY the RPC surface, for a client addressing a schema other
// than the default.
//
// Auth, storage and Edge Functions are project-wide: they are not per-schema
// and re-running them once per schema would issue the same requests again and
// report the same findings several times. Routines are per-schema, and the
// hint oracle works there -- measured against a routine in a non-default
// schema:
//
//	GET /rest/v1/rpc/admin_rebuild_metric
//	Accept-Profile: reporting
//	-> "Perhaps you meant to call the function reporting.admin_rebuild_metrics"
//
// Without this, a SECURITY DEFINER routine in an exposed reporting schema --
// callable by anon, reading a table anon cannot read -- is invisible to the
// scan, which is the shape of finding this tool exists for.
func Routines(ctx context.Context, c *client.Client, o Options) Result {
	if o.Concurrency <= 0 {
		o.Concurrency = client.DefaultConcurrency
	}
	res := Result{Callable: map[string]bool{}}
	res.Routines = enumerateRoutines(ctx, c, o, &res)
	if o.AllowInvoke {
		res.Callable = callableRoutines(ctx, c, res.Routines, o, &res)
	}
	for _, r := range res.Routines {
		callable, known := res.Callable[r]
		res.Findings = append(res.Findings, routineFinding(c, r, callable, known, o.Schema))
	}
	addSQLExecutionFindings(ctx, c, o, &res)
	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	return res
}

// Run inspects auth, storage and RPC surfaces.
// addSQLExecutionFindings runs the arbitrary-SQL probe and records its cost.
//
// It exists as one function because the routine stage runs in two places --
// Run for the default schema and Routines for each additional exposed one --
// and the first version of this check was added to only one of them. The scan
// then reported nothing while a unit test against the same fixture passed,
// which is the exact shape of every silent-blindness bug this scanner was
// written to find in other tools.
//
// It is NOT gated on AllowInvoke, unlike callableRoutines. That probe POSTs,
// which runs the routine, and is gated for good reason. This one GETs, which
// PostgREST serves inside a read-only transaction, and the statement it sends
// computes 42 and touches nothing. Hiding the most serious finding this
// scanner can produce behind a flag most scans never pass would put the worst
// case behind the safest default.
func addSQLExecutionFindings(ctx context.Context, c *client.Client, o Options, res *Result) {
	fs, reqs := sqlExecutionFindings(ctx, c, res.Routines, o.Schema)
	res.Findings = append(res.Findings, fs...)
	res.spend("surface-sql", reqs)
}

// spend records n requests against a sub-stage. Every increment goes through
// here so the total and the attribution cannot disagree.
func (r *Result) spend(stage string, n int) {
	if r.RequestsBy == nil {
		r.RequestsBy = map[string]int{}
	}
	r.RequestsBy[stage] += n
	r.Requests += n
}

func Run(ctx context.Context, c *client.Client, o Options) Result {
	if o.Concurrency <= 0 {
		o.Concurrency = client.DefaultConcurrency
	}
	res := Result{}

	// Auth and storage are separate services. When one cannot be reached, say
	// so: SignupOpen() on a zero-value config is false, and an empty bucket
	// list is empty, so a failed fetch of either produces exactly the output of
	// a correctly locked-down project. "I could not check" must not render as
	// "there is nothing to find" — the mistake this tool exists to correct.
	res.Auth = fetchAuth(ctx, c, &res)
	if !res.Auth.Reachable {
		res.Findings = append(res.Findings, uncheckedFinding(c, "auth",
			c.BaseURL()+"/auth/v1/settings",
			"Public signup, auto-confirm and enabled providers were not assessed. If signup "+
				"is open, anyone can hold the `authenticated` role, and policies written TO "+
				"authenticated are routinely far looser than the anonymous ones."))
	} else {
		if f, ok := authFinding(c, res.Auth); ok {
			res.Findings = append(res.Findings, f)
		}
		// Reported separately from open signup, because the tiers cost an
		// attacker different amounts: signup costs one request and leaves a
		// record, anonymous sign-in costs nothing and leaves none.
		if f, ok := AnonymousSignInFinding(c, res.Auth); ok {
			res.Findings = append(res.Findings, f)
		}
	}

	var storageOK bool
	res.Buckets, storageOK = fetchBuckets(ctx, c, &res)
	res.StorageReachable = storageOK

	// Is there a storage service here at all?
	//
	// The name sweep below runs unconditionally on purpose -- see its comment --
	// but that reasoning is about a service that EXISTS and lies about its
	// buckets. Where none is mounted, it spends the whole bucket wordlist
	// learning nothing: measured at 2,983 requests against the bare-PostgREST
	// fixture, 42% of that scan, for zero findings.
	//
	// The signal is who answered, not the status code. A host with no storage
	// lets PostgREST field the path and it says so:
	//
	//	no storage   {"code":"PGRST125","message":"Invalid path specified..."}
	//	storage      {"statusCode":"400",...,"code":"InvalidRequest"}
	//
	// Measured against the bare fixture and against two real projects, one of
	// which has buckets and one of which has none -- both answered in the
	// storage shape, so the test is for the service, not for its contents. A
	// PostgREST error code cannot come back from an origin where storage is
	// mounted, which is what makes skipping safe rather than merely cheaper.
	noStorageService := !storageOK && postgrestClaimedStoragePath(ctx, c, &res)
	// Listing is the privileged path and returns [] to the anonymous role even
	// when a public bucket exists — which is how a project serving invoices to
	// anyone with the URL passed the storage check. Name probing is the only
	// way to see what a stranger sees, so it runs whether or not the list
	// succeeded, and its results are merged in.
	var named []Bucket
	if !noStorageService {
		named = probeBuckets(ctx, c, o, &res)
	}
	if len(named) > 0 {
		known := map[string]bool{}
		for _, b := range res.Buckets {
			known[b.Name] = true
		}
		for _, b := range named {
			if !known[b.Name] {
				res.Buckets = append(res.Buckets, b)
			}
		}
		sort.Slice(res.Buckets, func(i, j int) bool { return res.Buckets[i].Name < res.Buckets[j].Name })
		// A bucket found by name IS reachable, whatever the list endpoint said.
		res.StorageReachable = true
		storageOK = true
	}
	if !storageOK {
		why := "Public storage buckets were not assessed. A public bucket serves every " +
			"object in it by URL, with no authentication and no row-level security check."
		if noStorageService {
			why = "No storage service is mounted at this origin: PostgREST answered the " +
				"storage path itself, so there are no buckets here and none were probed. " +
				"This is a fact about the deployment, not a gap in the scan."
		}
		res.Findings = append(res.Findings, uncheckedFinding(c, "storage",
			c.BaseURL()+"/storage/v1/bucket", why))
	}
	for _, b := range res.Buckets {
		if b.Public {
			// Name what is inside. "This bucket is public" is a claim; a list
			// of the files it serves is something an operator can act on.
			b.Objects = listBucketObjects(ctx, c, b.Name, 10)
			res.spend("surface-sql", 1)
			if o.AllowWrite && !o.NoResidue {
				writable, residue := probeBucketWrite(ctx, c, b.Name, &res)
				if writable {
					res.Findings = append(res.Findings, bucketWriteFinding(c, b.Name, residue))
				}
				// Whenever a probe object could not be removed, regardless of
				// what else was concluded.
				//
				// This used to be an `else if`, so the residue finding fired
				// only when the bucket was NOT proven writable -- and the
				// common case is the opposite: a bucket that grants INSERT and
				// refuses DELETE is writable AND keeps the object. The
				// operator was told in the prose of the write finding, but the
				// canonical id never appeared, so anyone filtering on
				// unruly-probe-object-left-behind to answer "did this
				// scan leave anything behind" got nothing.
				//
				// Confirmed against a bucket built for it on the lab: upload
				// 200, delete 403, and the id had never been emitted by any
				// scan of any target.
				if residue != "" {
					res.Findings = append(res.Findings, residueFinding(c, b.Name, residue))
				}
			}
			res.Findings = append(res.Findings, bucketFinding(c, b))
		}
	}

	if o.AllowFunctions {
		res.Functions = enumerateFunctions(ctx, c, o, &res)
	}
	for _, fn := range res.Functions {
		if fn.Invokable() {
			res.Findings = append(res.Findings, functionFinding(c, fn, o.Redact))
		}
	}

	res.Routines = enumerateRoutines(ctx, c, o, &res)
	// Disclosure is not the same as access. Measure which of the disclosed
	// routines the anonymous role can actually invoke, rather than inferring
	// it from the name.
	if o.AllowInvoke {
		res.Callable = callableRoutines(ctx, c, res.Routines, o, &res)
	} else {
		res.Callable = map[string]bool{}
	}
	for _, r := range res.Routines {
		callable, known := res.Callable[r]
		res.Findings = append(res.Findings, routineFinding(c, r, callable, known, o.Schema))
	}
	addSQLExecutionFindings(ctx, c, o, &res)

	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	return res
}

// goTrueKeys are fields GoTrue's /settings response always carries. At least
// one must be present before the payload is treated as GoTrue's.
//
// Without this check any 200 with a JSON body was accepted, and because
// disable_signup is absent from such a body it decoded to false, which
// SignupOpen reads as signup being OPEN. Absence of a field was being treated
// as evidence of permissiveness -- the same mistake as reading an empty
// enumeration as a clean project, one surface over.
//
// Measured: a host answering {"ok":true} to every path produced
// supabase-open-signup against something that is not an auth server at all.
var goTrueKeys = []string{
	"external", "disable_signup", "mailer_autoconfirm", "external_email_enabled",
	"external_phone_enabled", "saml_enabled", "phone_autoconfirm",
}

func fetchAuth(ctx context.Context, c *client.Client, res *Result) AuthConfig {
	resp := c.Get(ctx, c.BaseURL()+"/auth/v1/settings", nil)
	res.spend("auth", 1)
	var a AuthConfig
	if resp.Err != nil || resp.Status != 200 {
		return a
	}
	// Decode twice: once loosely to confirm this is GoTrue, once into the
	// typed struct. A settings payload that names none of GoTrue's own fields
	// is some other service, and reporting its signup policy would be
	// reporting on a service that has none.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body, &raw); err != nil {
		return a
	}
	var recognised bool
	for _, k := range goTrueKeys {
		if _, ok := raw[k]; ok {
			recognised = true
			break
		}
	}
	if !recognised {
		return a
	}
	if err := json.Unmarshal(resp.Body, &a); err != nil {
		return a
	}
	a.Reachable = true
	return a
}

// postgrestClaimedStoragePath reports whether PostgREST answered the storage
// endpoint, which proves no storage service is mounted at this origin.
func postgrestClaimedStoragePath(ctx context.Context, c *client.Client, res *Result) bool {
	resp := c.Get(ctx, c.BaseURL()+"/storage/v1/bucket", nil)
	res.spend("storage", 1)
	if resp.Err != nil {
		return false // no answer at all says nothing; probing is still the honest choice
	}
	code, _, _ := resp.DecodeError()
	return strings.HasPrefix(code, "PGRST")
}

// fetchBuckets returns the buckets and whether the service answered at all.
func fetchBuckets(ctx context.Context, c *client.Client, res *Result) ([]Bucket, bool) {
	resp := c.Get(ctx, c.BaseURL()+"/storage/v1/bucket", nil)
	res.spend("storage", 1)
	if resp.Err != nil || resp.Status != 200 {
		return nil, false
	}
	// Must be a JSON ARRAY. A catch-all host answering {"ok":true} fails this,
	// where a lenient decode into a slice of structs would silently yield an
	// empty list and read as "no public buckets".
	var bs []Bucket
	if err := json.Unmarshal(resp.Body, &bs); err != nil {
		return nil, false
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].Name < bs[j].Name })
	return bs, true
}

// uncheckedFinding records a surface the scan could not assess. It is info, not
// a vulnerability: nothing is known to be wrong. What is being reported is the
// absence of knowledge, which the rest of the report would otherwise imply it
// had.
func uncheckedFinding(_ *client.Client, surface, endpoint, impact string) finding.Finding {
	return finding.Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "Surface could not be assessed",
		Severity: finding.Info,
		Protocol: "unruly",
		Matched:  endpoint,
		Resource: surface,
		Description: "The " + surface + " service did not answer, so this scan says nothing " +
			"about it. " + impact + " Absence of findings for this surface is not evidence " +
			"that it is sound.",
		Remediation: "-- If the project is self-hosted, this service may not be deployed, in which " +
			"case there is nothing to assess and this finding can be ignored. If it should be " +
			"reachable, confirm the endpoint is exposed and rerun; on a managed project it is " +
			"served from the same origin as PostgREST.",
		Evidence: finding.Evidence{
			Request: "curl -sS '" + endpoint + "' -H 'apikey: $SUPABASE_ANON_KEY'",
			Reason:  "no usable response from " + endpoint,
		},
	}
}

// enumerateRoutines drives the function arm of the hint oracle.
//
// Calling an exact routine name with the wrong signature returns hint:null, so
// probing real names directly reveals nothing. Near-miss names are what make
// the oracle talk, which is why seeds are truncated before use.
func enumerateRoutines(ctx context.Context, c *client.Client, o Options, res *Result) []string {
	seen := map[string]bool{}
	// The cap has existed since early on and truncated in silence: the
	// relation budget got a "lower bound" note when it was added, and the
	// older RPC budget never did. An audit pointed out that a scan stopping at
	// the routine budget reads as one that finished.
	// Three cuts per seed is the most routineCandidates can ever produce, so
	// this asks for the untruncated list without a sentinel that means
	// "unlimited" — 0 already means "use the default cap".
	wanted := routineCandidates(o.RoutineSeeds, len(o.RoutineSeeds)*3+1)
	candidates := routineCandidates(o.RoutineSeeds, o.MaxCandidates)
	if len(wanted) > len(candidates) {
		res.RoutineBudgetBound = true
		res.RoutineCandidatesWanted = len(wanted)
	}
	// Guesses are probed as-is, and are additional to the stem budget: they
	// are cheap relative to the seed list and are the only way a compound name
	// is ever reached.
	candidates = append(candidates, dedupSorted(sortedCopy(o.RoutineGuesses))...)
	candidates = dedupSorted(sortedCopy(candidates))

	// A direct hit is only evidence on a host where a miss looks different. A
	// single-page app serves index.html with 200 for every unknown route --
	// which is how essentially every React deployment is configured -- so
	// without this control the 200 branch below reports a routine for every
	// candidate probed. That is not hypothetical: it is what the
	// not-Supabase precision eval caught the moment the branch was added,
	// naming admin, admin_, admin_ad, admin_app ... one phantom per prefix.
	//
	// The hint path needs no such guard. A hint is a PostgREST error body
	// naming a real function, which a catch-all cannot fabricate, so it stays
	// trustworthy even here and discovery keeps working with direct hits off.
	directHitsDiscriminate := false
	ctrlName := ControlRoutineName
	if ctrl := c.Get(ctx, c.RPCURL(ctrlName), nil); ctrl.Err == nil {
		ccode, _, _ := ctrl.DecodeError()
		directHitsDiscriminate = ctrl.Status == 404 && ccode == "PGRST202"
	}
	res.spend("routines", 1)

	type out struct{ name string }
	results := client.Map(ctx, o.Concurrency, candidates, func(ctx context.Context, name string) out {
		// GET, not POST: this stage runs in EVERY scan, including one with no
		// flags at all, and POST to a routine that exists RUNS it. The console
		// says "routines were not invoked" while this was doing exactly that,
		// and the same message warns that functions "send email, charge cards
		// and write to queues".
		//
		// PostgREST serves GET /rpc/x inside a READ-ONLY transaction, which
		// makes existence decidable without side effects. Measured against a
		// deliberately side-effecting routine in the lab, counting the rows it
		// writes:
		//
		//	GET  /rpc/volatile_side_effect -> 405 25006, 0 rows written
		//	POST /rpc/volatile_side_effect -> 200,       1 row  written
		//
		// The hint oracle this stage depends on is byte-identical either way:
		//
		//	"Perhaps you meant to call the function public.admin_read_audit_log"
		//
		// so nothing is traded for the safety. 25006 is a bonus rather than a
		// cost -- it proves the routine attempts a write, which POST cannot
		// tell you because POST simply performs it.
		resp := c.Get(ctx, c.RPCURL(name), nil)
		if resp.Err != nil {
			return out{}
		}
		code, _, hint := resp.DecodeError()
		if fn, ok := postgrest.HintedFunction(hint); ok {
			return out{name: fn}
		}
		// A direct hit yields no hint, so the POST version threw these away and
		// discovered a real name only via a near-miss for it. Two states are
		// sound evidence that the routine exists:
		//
		//	200          -> it ran read-only and returned
		//	405 + 25006  -> it exists and tried to write, so it was refused
		//
		// A routine anon may not EXECUTE is deliberately NOT here: PostgREST
		// omits it from the role's schema cache and answers 404 PGRST202,
		// exactly as for a name that does not exist. Measured, not assumed --
		// and indistinguishable means it must not be claimed.
		// 25006 is self-validating: a Postgres SQLSTATE inside a PostgREST
		// error body cannot come from a catch-all router, so it needs no
		// control. A bare 200 does.
		if code == "25006" || (resp.Status == 200 && directHitsDiscriminate) {
			return out{name: name}
		}
		return out{}
	})
	res.spend("routines", len(candidates))

	for _, r := range results {
		if r.name != "" && !seen[r.name] {
			seen[r.name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// enumerateFunctions probes Edge Function names.
//
// The platform answers before the function runs, which makes the outcome a
// clean three-way discriminator rather than a guess:
//
//	404              -> no function by that name
//	401              -> deployed, and verify_jwt rejects anonymous callers
//	anything else    -> deployed AND reached without credentials
//
// The last case is the finding. An Edge Function deployed with verify_jwt off
// runs with whatever secrets its environment holds — commonly the service_role
// key — so an unauthenticated invocation can do far more than the anon role.
// profileCurl is the header a reproduction needs to reach a non-default
// schema. PostgREST addresses relations and routines by BARE name and takes
// the schema from a header, so without it the command hits public and answers
// "Searched for the function public.x" -- which is what running the emitted
// evidence for a reporting-schema routine actually did.
func profileCurl(schema string) string {
	if schema == "" {
		return ""
	}
	return " -H 'Accept-Profile: " + schema + "' -H 'Content-Profile: " + schema + "'"
}

// ControlRoutineName is the routine name the direct-hit control probe asks
// for. Nothing may define it; a host that answers it as though it exists is a
// host whose answers do not distinguish routines.
const ControlRoutineName = "unruly_control_routine_that_cannot_exist"

// ControlFunctionName is the Edge Function name the control probe asks for. It
// cannot be deployed on any real project, and is fixed rather than random so
// runs stay comparable.
const ControlFunctionName = "unruly_control_function_that_cannot_exist"

func itoa(i int) string { return strconv.Itoa(i) }

func enumerateFunctions(ctx context.Context, c *client.Client, o Options, res *Result) []EdgeFunction {
	seeds := append([]string{}, o.FunctionSeeds...)
	sort.Strings(seeds)
	seeds = dedupSorted(seeds)
	if len(seeds) == 0 {
		return nil
	}

	base := c.BaseURL() + "/functions/v1/"

	// Control probe first, same pattern as the Realtime check. A name that
	// cannot exist must be REFUSED for any other answer to mean anything.
	//
	// Without it, scanning a host that is not a Supabase project at all
	// produced 392 findings: example.com answers 405 to POST on every path,
	// and 405 was being read as "the function ran". A response that the server
	// gives to every path is not evidence about any path.
	// The name is a probe target, not a finding id. It read like one for
	// several iterations and was carried in a coverage allowlist as a check
	// that had never fired -- it could not fire, because no finding was ever
	// built from it. Naming it in the underscore style the other control
	// probes use removes the ambiguity.
	ctrl := c.Do(ctx, "POST", base+ControlFunctionName, []byte(`{}`), nil)
	res.spend("edge-functions", 1)
	// A control that did not complete is not a control that passed.
	//
	// This read `ctrl.Err == nil && ...`, so a transport failure on the
	// control probe skipped the guard entirely and probing continued as
	// though discrimination had been established. That is this project's
	// central mistake -- could-not-measure treated as nothing-wrong -- sitting
	// in the one place where the consequence is high-severity phantoms: with
	// no discrimination, a catch-all host answers every function name, and any
	// privileged-looking name in the pinned list is reported HIGH.
	//
	// The lab's own Cloudflare Worker is such a host: it serves 200 and HTML
	// for every path, including /functions/v1/<control>. So the difference
	// between "the control answered 404" and "the control never answered" is
	// the difference between a clean edge-function pass and a report claiming
	// delete-user-test is deployed and open.
	if ctrl.Err != nil {
		res.Findings = append(res.Findings, uncheckedFinding(c, "edge-functions", base,
			"Edge Functions were not assessed. The control probe for a function name that "+
				"cannot exist never completed ("+ctrl.Err.Error()+"), so this scan could "+
				"not establish that the host tells a deployed function apart from an "+
				"absent one. Without that, every candidate name would look deployed. "+
				"Absence of Edge Function findings below is not evidence that none are "+
				"exposed."))
		return nil
	}
	if classifyFunction(ctrl.Status) != functionAbsent {
		// The host answers every function name, so no answer identifies a
		// function. Returning nil alone would report zero Edge Functions,
		// which reads as a project that has none.
		res.Findings = append(res.Findings, uncheckedFinding(c, "edge-functions",
			base,
			"Edge Functions were not assessed. A control probe for a function name that "+
				"cannot exist was answered as though the function is deployed (HTTP "+
				itoa(ctrl.Status)+"), so every candidate name would look deployed. This "+
				"happens behind a catch-all router or a CDN, or when the host is not a "+
				"Supabase functions endpoint at all."))
		return nil
	}

	out := client.Map(ctx, o.Concurrency, seeds, func(ctx context.Context, name string) EdgeFunction {
		resp := c.Do(ctx, "POST", base+name, []byte(`{}`), nil)
		if resp.Err != nil {
			return EdgeFunction{unresolved: true}
		}
		switch classifyFunction(resp.Status) {
		case functionAbsent:
			return EdgeFunction{}
		case functionUnresolved:
			return EdgeFunction{unresolved: true}
		case functionProtected:
			return EdgeFunction{Name: name, Status: resp.Status, RequiresJWT: true}
		}
		return EdgeFunction{
			Name:    name,
			Status:  resp.Status,
			Snippet: truncate(strings.TrimSpace(string(resp.Body)), 200),
		}
	})
	res.spend("edge-functions", len(seeds))

	var fns []EdgeFunction
	for _, f := range out {
		if f.unresolved {
			res.FunctionsUnresolved++
			continue
		}
		if f.Name != "" {
			fns = append(fns, f)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Name < fns[j].Name })
	// Names that got no usable answer are neither present nor absent, and
	// silence about them would read as absence.
	if res.FunctionsUnresolved > 0 {
		res.Findings = append(res.Findings, functionsUnresolvedFinding(
			c, res.FunctionsUnresolved, len(seeds)))
	}
	return fns
}

type functionState int

const (
	functionAbsent functionState = iota
	functionProtected
	functionReached
	// functionUnresolved means the probe got no usable answer: the name was
	// neither shown to exist nor ruled out.
	functionUnresolved
)

// classifyFunction maps a status to what it says about an Edge Function.
//
// The subtlety is 405. A function that exists answers POST — it may succeed,
// fail, or reject the body, but it answers. A 405 means the route does not
// handle POST at all, which is what a plain web server says about every path.
// Reading it as "reached" turned any non-Supabase host into hundreds of
// findings. 3xx is the same story: a redirect is the server routing us
// elsewhere, not a function running.
func classifyFunction(status int) functionState {
	switch {
	case status == 404 || status == 405 || status == 501:
		return functionAbsent
	case status >= 300 && status < 400:
		return functionAbsent
	case status == 401 || status == 403:
		return functionProtected
	// A rate limit is not a function. Everything not explicitly absent or
	// protected fell through to "reached", so a 429 became "Edge Function
	// invokable without authentication" -- at HIGH severity for any
	// privileged-looking name, because that is what the severity rule keys on.
	// A 429 is the gateway declining to answer; it says nothing at all about
	// whether a function is deployed behind it.
	//
	// 5xx deliberately stays with "reached". A deployed function that throws
	// answers 500, and Supabase returns 404 for a name it has no function for,
	// so a 500 here really is evidence of something running. That decision has
	// its own tests and this change does not touch it.
	case status == 429:
		return functionUnresolved
	}
	return functionReached
}

func functionFinding(c *client.Client, fn EdgeFunction, redact bool) finding.Finding {
	sev := finding.Medium
	if looksPrivileged(fn.Name) {
		sev = finding.High
	}
	return finding.Finding{
		ID:       "supabase-edge-function-no-jwt",
		Name:     "Edge Function invokable without authentication",
		Severity: sev,
		Protocol: "functions",
		Matched:  c.BaseURL() + "/functions/v1/" + fn.Name,
		Resource: fn.Name,
		Description: fmt.Sprintf(
			"Edge Function %q was reached by an unauthenticated POST (HTTP %d). It is deployed "+
				"with verify_jwt disabled, so anyone can invoke it. Functions commonly hold the "+
				"service_role key in their environment, which bypasses row-level security "+
				"entirely, so an open function can be a wider hole than any RLS mistake.",
			fn.Name, fn.Status),
		Remediation: fmt.Sprintf(`# Require a JWT unless the function is deliberately public
# (a payment webhook, for example, which must verify its own signature instead):
supabase functions deploy %s --no-verify-jwt=false

# If it must stay public, verify the caller inside the function and never trust
# the request body alone. Check any provider signature before acting on it.`, fn.Name),
		Evidence: finding.Evidence{
			Request:  fmt.Sprintf("curl -sS -X POST '%s/functions/v1/%s' -d '{}'", c.BaseURL(), fn.Name),
			Status:   fn.Status,
			Response: redactSnippet(fn.Snippet, redact),
			Reason:   fmt.Sprintf("HTTP %d without credentials", fn.Status),
		},
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// callableRoutines checks which disclosed routines the role may invoke.
//
// Measured on the hardened fixture: a routine with
// REVOKE ALL ON FUNCTION ... FROM PUBLIC, anon, authenticated is STILL named in
// PostgREST's hint, because the hint is built from the schema cache and knows
// nothing about privileges. Calling it returns:
//
//	42501 "permission denied for function internal_recalculate_ledger"
//
// which is a different code path from a routine that runs and rejects its
// arguments. Without this the finding would tell an operator to revoke EXECUTE
// on a routine whose EXECUTE is already revoked.
// A routine is absent from the returned map when callability could not be
// established, which is different from establishing that it cannot be called.
func callableRoutines(ctx context.Context, c *client.Client, names []string, o Options, res *Result) map[string]bool {
	out := map[string]bool{}
	if len(names) == 0 {
		return out
	}
	sorted := append([]string{}, names...)
	sort.Strings(sorted)

	type result struct {
		name     string
		callable bool
		known    bool
		// rows and sample capture what the routine RETURNED.
		//
		// This request was already being made, and its body was already being
		// thrown away. An audit put it bluntly: the scanner POSTed {} to
		// admin_read_audit_log -- byte for byte the request the exploit
		// harness makes -- received five rows from a table whose RLS has no
		// policy at all, discarded them, and reported "[medium] disclosed via
		// PostgREST hint". A name leak. The data was in memory.
		rows   int
		sample []map[string]any
		// status is what the call was answered with, kept so the finding can
		// print the answer beside the command that produced it.
		status int
	}
	got := client.Map(ctx, 8, sorted, func(ctx context.Context, name string) result {
		resp := c.Do(ctx, "POST", c.RPCURL(name), []byte(`{}`), nil)
		if resp.Err != nil {
			return result{name: name}
		}
		code, msg, _ := resp.DecodeError()
		switch {
		case code == "42501" && strings.Contains(msg, "permission denied for function"):
			// Postgres refused on privilege. Definitive.
			return result{name: name, callable: false, known: true}
		case code == "PGRST202":
			// PostgREST could not resolve a signature taking no arguments, and
			// answered from its own schema cache WITHOUT ever asking Postgres.
			// No privilege check happened, so nothing was learned:
			//
			//   admin_purge_submissions(p_token text)
			//     {}                -> PGRST202   (says nothing)
			//     {"p_token":"x"}   -> 42501      (the truth)
			//
			// The argument names cannot be discovered from outside, so this is
			// genuinely indeterminate rather than merely unmeasured. Treating
			// it as callable was wrong and reported a revoked routine as
			// reachable.
			return result{name: name, known: false}
		}
		// Reached Postgres and was not refused on privilege. Read what came
		// back: a routine that returns rows to the anonymous role has handed
		// over data, which is a different and much larger finding than a
		// routine whose name is guessable.
		r := result{name: name, callable: true, known: true}
		var rows []map[string]any
		r.status = resp.Status
		if json.Unmarshal(resp.Body, &rows) == nil {
			r.rows = len(rows)
			if n := len(rows); n > 0 {
				if n > 3 {
					n = 3
				}
				r.sample = rows[:n]
			}
		}
		return r
	})
	res.spend("routines-invoke", len(sorted))
	for _, r := range got {
		if r.known {
			out[r.name] = r.callable
		}
		if r.rows > 0 {
			res.Findings = append(res.Findings, routineDataFinding(c, r.name, r.rows, r.sample, o.Redact, o.Schema, r.status))
		}
	}
	return out
}

// routineDataFinding reports a routine that returned rows to the anonymous
// role.
//
// Critical, and above the disclosure finding for the same routine, because the
// two describe different things. Disclosure says a name is guessable.
// This says data came out. The usual cause is SECURITY DEFINER over a relation
// whose RLS has no policy: the direct read is empty, the routine returns the
// rows, and an operator auditing their policies sees nothing wrong.
// routineDataFinding reports a routine that handed rows to an anonymous
// caller. It takes the schema for the same reason readFinding does: the SQL it
// emits has to name the object Postgres will resolve.
//
// This was missed when the other routine constructor was qualified. Both
// build SQL about a routine; only one was fixed, so the CRITICAL finding --
// the one that matters most -- kept emitting
//
//	REVOKE EXECUTE ON FUNCTION public.rebuild_daily_revenue FROM ...
//
// for a routine in the reporting schema. Executing it against the fixture is
// what found it: "could not find a function named public.rebuild_daily_revenue".
func routineDataFinding(c *client.Client, name string, rows int, sample []map[string]any, redact bool, schema string, status int) finding.Finding {
	qualifier, resource := "public", name
	if schema != "" {
		qualifier, resource = schema, schema+"."+name
	}
	ev := finding.Evidence{
		Status: status,
		Request: fmt.Sprintf("curl -sS -X POST '%s' -H 'apikey: $SUPABASE_ANON_KEY' "+
			"-H 'Content-Type: application/json'%s -d '{}'", c.RPCURL(name), profileCurl(schema)),
		Reason: fmt.Sprintf("returned %d rows to the anonymous role", rows),
		Rows:   rows,
	}
	if !redact {
		ev.Sample = sample
	}
	if len(sample) > 0 {
		cols := make([]string, 0, len(sample[0]))
		for k := range sample[0] {
			cols = append(cols, k)
		}
		sort.Strings(cols)
		ev.Columns = cols
	}
	return finding.Finding{
		ID:       "supabase-rpc-returns-data",
		Name:     "Routine returns data to the anonymous role",
		Severity: finding.Critical,
		Protocol: "postgrest",
		Matched:  c.RPCURL(name),
		Resource: resource,
		Description: fmt.Sprintf(
			"Calling %s with no arguments and only the public anon key returned %d rows. "+
				"This is data leaving the database, not merely a routine name being "+
				"guessable. A SECURITY DEFINER routine executes as its owner and ignores the "+
				"row-level security of the relations it reads, so a table that is correctly "+
				"protected against a direct SELECT can be readable in full through a function "+
				"that wraps it — and an operator auditing their policies would see nothing "+
				"wrong.", name, rows),
		Remediation: fmt.Sprintf(`-- Take EXECUTE away from the public roles. PUBLIC holds it by
-- default, so revoking from anon alone changes nothing:
REVOKE EXECUTE ON FUNCTION %[2]s.%[1]s FROM PUBLIC, anon, authenticated;

-- If the routine must stay callable, make it respect the caller's policies
-- rather than the owner's privileges:
-- ALTER FUNCTION %[2]s.%[1]s SECURITY INVOKER;

-- Review every SECURITY DEFINER routine in the schema:
-- SELECT p.proname, p.prosecdef FROM pg_proc p
-- JOIN pg_namespace n ON n.oid = p.pronamespace
-- WHERE n.nspname = '%[2]s' AND p.prosecdef ORDER BY p.proname;`, name, qualifier),
		Evidence: ev,
	}
}

// routineCandidates turns application vocabulary into near-miss probes.
//
// Naive expansion (every seed plus three truncations) cost 6200 extra requests
// against the reference target to surface three routines. Two observations cut
// that sharply without losing recall:
//
//   - SQL routine names are overwhelmingly snake_case, so seeds containing an
//     underscore are far likelier to sit near a real routine name.
//   - The oracle responds to a near miss, so probing the full seed is usually
//     wasted; one short truncation per seed is enough to trigger it.
func routineCandidates(seeds []string, max int) []string {
	if max <= 0 {
		max = 1200
	}
	var snake, plain []string
	for _, s := range seeds {
		if len(s) < 6 || len(s) > 40 {
			continue
		}
		if strings.Contains(s, "_") {
			snake = append(snake, s)
		} else {
			plain = append(plain, s)
		}
	}
	sort.Strings(snake)
	sort.Strings(plain)

	// Truncation depth is not a free parameter. PostgREST matches on
	// similarity, so a one-character trim is frequently still an exact-enough
	// match to return hint:null, while a half-length stem is reliably a near
	// miss. Measured on the reference target: len-1 alone recovered 1 of 4
	// routines; adding the 3/4 and 1/2 stems recovered all 4.
	cuts := []func(int) int{
		func(n int) int { return n / 2 },
		func(n int) int { return n * 3 / 4 },
		func(n int) int { return n - 1 },
	}
	var out []string
	add := func(xs []string) {
		for _, s := range xs {
			for _, cut := range cuts {
				if len(out) >= max {
					return
				}
				if c := cut(len(s)); c >= 4 && c < len(s) {
					out = append(out, s[:c])
				}
			}
		}
	}
	// snake_case first so the cap, if it binds, spends the budget on the
	// higher-signal set -- and STRIDED, so that what the cap keeps is spread
	// across the whole seed list instead of its opening pages.
	//
	// This mattered. The seeds are sorted, the cap was applied by taking them
	// in order, and the cap binds on every real scan (1,200 of 7,547 against
	// the reference project). So the probed set was the alphabetically first
	// ~400 seeds: measured on a vocabulary spanning 25 prefixes, the budget
	// reached 10 of them and stopped at "import". A project whose routines are
	// named update_*, validate_*, verify_* or write_* could not be found at
	// all, and the report said only "1200 of 7547 candidates probed" -- true,
	// and giving no hint that the 1,200 all came from the front of the
	// alphabet.
	//
	// Alphabetical order carries no information about which name is likelier
	// to sit near a real routine, so the old sample was arbitrary AND biased.
	// A stride is equally arbitrary, deterministic in the same way, and
	// unbiased with respect to the name space. It also wastes less: adjacent
	// seeds are frequently near-duplicates whose stems collide and dedup away.
	seedBudget := max / len(cuts)
	add(sample.Strided(snake, seedBudget))
	add(sample.Strided(plain, seedBudget))

	sort.Strings(out)
	return dedupSorted(out)
}

// ---------------------------------------------------------------- findings

func authFinding(c *client.Client, a AuthConfig) (finding.Finding, bool) {
	if !a.SignupOpen() {
		return finding.Finding{}, false
	}
	sev := finding.Low
	extra := ""
	// Auto-confirm means an attacker reaches a usable authenticated session
	// with no mailbox at all, which turns an open signup into a live
	// privilege boundary rather than a theoretical one.
	if a.MailerAutoconfim || a.PhoneAutoconfirm {
		sev = finding.Medium
		extra = " Auto-confirm is on, so an attacker obtains a usable session immediately, " +
			"without controlling any mailbox or phone number."
	}
	return finding.Finding{
		ID:       "supabase-open-signup",
		Name:     "Public signup is enabled",
		Severity: sev,
		Protocol: "gotrue",
		Matched:  c.BaseURL() + "/auth/v1/settings",
		Resource: "auth",
		Description: "Anyone can create an account and hold an `authenticated` JWT." + extra +
			" This matters because row-level security policies written TO authenticated are " +
			"often far more permissive than the anonymous ones, so scanning only as `anon` " +
			"understates real exposure. Review every policy that grants access to authenticated.",
		Remediation: `-- Review policies that trust any authenticated user:
SELECT schemaname, tablename, policyname, roles, cmd, qual
FROM pg_policies
WHERE 'authenticated' = ANY (roles)
ORDER BY tablename;

-- Scope them to the owning user rather than the role, for example:
-- CREATE POLICY "own_rows" ON your_table
--   FOR SELECT TO authenticated USING (user_id = (select auth.uid()));

-- If self-service signup is not required, disable it in
-- Authentication > Providers, or set disable_signup = true.`,
		Evidence: finding.Evidence{
			Request: fmt.Sprintf("curl -sS '%s/auth/v1/settings' -H 'apikey: $SUPABASE_ANON_KEY'", c.BaseURL()),
			Reason:  fmt.Sprintf("disable_signup=false mailer_autoconfirm=%t", a.MailerAutoconfim),
			Response: fmt.Sprintf(`{"disable_signup":false,"mailer_autoconfirm":%t,"external":{%s}}`,
				a.MailerAutoconfim, enabledProviders(a.External)),
		},
	}, true
}

func enabledProviders(m map[string]bool) string {
	var on []string
	for k, v := range m {
		if v {
			on = append(on, `"`+k+`":true`)
		}
	}
	sort.Strings(on)
	return strings.Join(on, ",")
}

// assetBuckets are names whose whole purpose is to be served publicly.
//
// A public bucket is not a misconfiguration in Supabase; it is the documented
// way to serve avatars and product images, and the CDN in front of it exists
// for exactly that. Measured over 200 real sites, every one of the 24 public
// buckets found was reported at MEDIUM, and they were called things like
// "images". A severity people learn to ignore is worse than no severity.
var assetBuckets = map[string]bool{
	"images": true, "image": true, "public": true, "assets": true, "avatars": true,
	"avatar": true, "logos": true, "logo": true, "media": true, "photos": true,
	"thumbnails": true, "icons": true, "banners": true, "covers": true,
	"product-images": true, "public-assets": true, "static": true,
}

// sensitiveBuckets are names that suggest the objects were not meant for the
// open web. The signal is the same shape as the sensitive-column rules: the
// NAME the operator chose, which is deterministic and costs no requests.
var sensitiveBuckets = regexp.MustCompile(
	`(?i)(document|invoice|receipt|contract|export|backup|dump|private|internal|` +
		`confidential|kyc|passport|licence|license|identity|payslip|payroll|resume|cv|` +
		`medical|report|statement|attachment|upload)`)

// bucketSeverity grades a public bucket by what its name suggests it holds.
//
// The name is a heuristic and the finding says so. It is also the only signal
// available without downloading somebody's objects, which this scanner will
// not do: the evidence lists object NAMES, and a reader who recognises them
// can grade it better than any rule here.
func bucketSeverity(name string) (finding.Severity, string) {
	switch {
	case sensitiveBuckets.MatchString(name):
		return finding.Medium, "the bucket name suggests contents that were not meant " +
			"for the open web"
	case assetBuckets[strings.ToLower(name)]:
		return finding.Info, "the name is one of the conventional asset buckets, which " +
			"are meant to be public; this is reported so the object list can be checked, " +
			"not because it is wrong"
	}
	return finding.Low, "the bucket name gives no indication either way"
}

func bucketFinding(c *client.Client, b Bucket) finding.Finding {
	sev, why := bucketSeverity(b.Name)
	return finding.Finding{
		ID:       "supabase-public-storage-bucket",
		Name:     "Storage bucket is public",
		Severity: sev,
		Protocol: "storage",
		Matched:  c.BaseURL() + "/storage/v1/object/list/" + b.Name,
		Resource: b.Name,
		Description: "Bucket " + b.Name + " is marked public, so every object in it is " +
			"readable by URL without authentication and without any RLS check. Graded on " +
			"the bucket NAME: " + why + ". That is a heuristic. The object names listed " +
			"below are the real signal, and a reader who recognises them can grade this " +
			"better than any rule can.",
		Remediation: fmt.Sprintf(`-- Make the bucket private and gate access with a policy:
UPDATE storage.buckets SET public = false WHERE name = '%s';

-- CREATE POLICY "%s_owner_read" ON storage.objects
--   FOR SELECT TO authenticated
--   USING (bucket_id = '%s' AND owner = (select auth.uid()));`, b.Name, b.Name, b.Name),
		Evidence: finding.Evidence{
			// The replay command fetches an OBJECT, not the bucket list. The
			// list endpoint answers [] to the anonymous role even for a public
			// bucket, so a reader pasting it would see nothing and conclude
			// the finding was wrong.
			Request: fmt.Sprintf("curl -sS '%s/storage/v1/object/public/%s/<object>'",
				c.BaseURL(), b.Name),
			Reason:  bucketReason(b),
			Columns: b.Objects,
		},
	}
}

// bucketReason states how the bucket was established to be public, because
// "public=true" is only true of the path that could read the flag.
func bucketReason(b Bucket) string {
	if len(b.Objects) > 0 {
		return fmt.Sprintf("public bucket serving %d listed object(s)", len(b.Objects))
	}
	return "a probe for a missing object returned Object not found rather than " +
		"Bucket not found, which only an existing bucket does"
}

func routineFinding(c *client.Client, name string, callable, known bool, schema string) finding.Finding {
	sev := finding.Info
	note := ""
	if !known {
		// Say so rather than guessing. Guessing "callable" overstates a locked
		// routine; guessing "not callable" hides a live one.
		note = " Callability could NOT be determined: the routine takes arguments this scan " +
			"cannot know, so PostgREST answered from its schema cache without ever reaching " +
			"the privilege check. Confirm by calling it with its real arguments and looking " +
			"for \"permission denied for function\"."
		if looksPrivileged(name) {
			// Low, not Medium. Medium is what a routine gets once it has been
			// SHOWN to be callable, and this one has not been shown to be
			// anything -- the name looks privileged and the privilege check was
			// never reached. Rating a guess the same as a demonstration is how a
			// correctly hardened project ends up with a medium it cannot act on:
			// the hardened fixture revokes EXECUTE from this exact routine and
			// still scored medium, because PostgREST's hint comes from the schema
			// cache, which knows nothing about privileges.
			sev = finding.Low
		}
		return buildRoutineFinding(c, name, sev, note, schema)
	}
	// A routine that is merely NAMED is an information leak. One the role can
	// actually invoke is an attack surface. Rating them alike would either
	// inflate every scan or hide the ones that matter.
	if !callable {
		note = " EXECUTE is not granted to this role: calling it returns " +
			"\"permission denied for function\". The name leaks, the routine does not run. " +
			"PostgREST builds its hint from the schema cache, which knows nothing about " +
			"privileges, so disclosure persists even after EXECUTE is correctly revoked."
	} else if looksPrivileged(name) {
		// Callable AND privileged-sounding: the case worth waking someone for.
		sev = finding.Medium
		note = " The anonymous role can invoke it, and the name suggests a privileged " +
			"operation. If it is SECURITY DEFINER it runs with the owner's rights and " +
			"bypasses RLS entirely, so its own argument checks are the only thing standing " +
			"between an anonymous caller and its effects."
	} else {
		note = " The anonymous role can invoke it."
	}
	return buildRoutineFinding(c, name, sev, note, schema)
}

func buildRoutineFinding(c *client.Client, name string, sev finding.Severity, note, schema string) finding.Finding {
	qualifier := "public"
	resource := name
	if schema != "" {
		qualifier = schema
		resource = schema + "." + name
	}
	return finding.Finding{
		ID:       "supabase-rpc-discoverable",
		Name:     "RPC routine discoverable by anonymous callers",
		Severity: sev,
		Protocol: "postgrest",
		Matched:  c.RPCURL(name),
		Resource: resource,
		Description: "PostgREST disclosed routine " + resource + " to an anonymous caller through " +
			"its fuzzy-match hint on a near-miss name." + note,
		Remediation: fmt.Sprintf(`-- Revoke from PUBLIC as well as the API roles. PostgreSQL grants
-- EXECUTE to PUBLIC by default when a function is created, so revoking from
-- anon alone is a NO-OP: the role still reaches the routine through PUBLIC.
-- Verified on a fixture — after REVOKE ... FROM anon the ACL still read
-- "=X/postgres", which is PUBLIC holding EXECUTE, and the call still ran.
REVOKE EXECUTE ON FUNCTION %[1]s.%[2]s FROM PUBLIC, anon, authenticated;

-- With overloaded routines the argument types are required to disambiguate:
--   REVOKE EXECUTE ON FUNCTION %[1]s.fn(text, integer) FROM PUBLIC, anon;
-- List the signatures with:
--   SELECT oid::regprocedure FROM pg_proc WHERE proname = '%[2]s';

-- Note: revoking EXECUTE does not suppress the name. PostgREST builds its hint
-- from the schema cache, which knows nothing about privileges, so the routine
-- stays discoverable even once it can no longer be called.

-- If it is SECURITY DEFINER, verify it validates its own arguments and pin
-- its search_path:
-- ALTER FUNCTION %[1]s.%[2]s SET search_path = %[1]s, pg_temp;

-- Prefer authorisation in the database over a shared secret passed as an
-- argument; a literal token in a function body is readable by anyone who can
-- inspect the routine definition.`, qualifier, name),
		Evidence: finding.Evidence{
			// GET, because that is what discovery sends. A POST here would
			// INVOKE the routine, which is exactly what discovery stopped
			// doing: an evidence command telling the auditor to run something
			// the scanner refuses to run is worse than no command at all.
			Request: fmt.Sprintf("curl -sS '%s' -H 'apikey: $SUPABASE_ANON_KEY'%s",
				c.RPCURL(truncateName(name)), profileCurl(schema)),
			// Offered, not performed. The routine was disclosed by a hint on a
			// near-miss name; this scan did not call it, and a command nobody
			// ran cannot state what it answered.
			Suggested: true,
			Reason:    "disclosed via PostgREST hint",
		},
	}
}

var privilegedTokens = []string{"admin", "internal", "private", "sudo", "root", "grant",
	"revoke", "delete", "drop", "reset", "impersonate", "elevate", "promote", "secret"}

func looksPrivileged(name string) bool {
	l := strings.ToLower(name)
	for _, t := range privilegedTokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

func truncateName(n string) string {
	if len(n) > 3 {
		return n[:len(n)-1]
	}
	return n
}

func dedupSorted(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// redactSnippet drops a captured response body when redaction is on, while
// still recording that a body was returned -- the length is what makes the
// finding actionable ("it answered, with content") without reproducing the
// content in a report headed for a ticket.
func redactSnippet(snippet string, redact bool) string {
	if snippet == "" {
		return snippet
	}
	if redact {
		return fmt.Sprintf("[redacted: %d bytes returned]", len(snippet))
	}
	return maskCredentials(snippet)
}

// maskCredentials cuts credential-shaped strings down to a prefix, ALWAYS,
// whether or not -redact was asked for.
//
// An Edge Function's response is arbitrary application output, and this
// package's own finding text says functions commonly hold the service_role
// key. Quoted verbatim, a report saying "this function answers without
// credentials" would ship the credential it found -- and a report is something
// people paste into tickets.
//
// Sampled ROWS are deliberately left alone. There the data IS the exposure
// being reported: a table storing api_key is a critical finding whose proof is
// the rows, and redacting it by default would weaken the headline. A response
// body is illustrative rather than the claim, and the evidence command shows
// the reader how to fetch it in full themselves.
//
// Sixteen characters identify which key without being usable, the same
// compromise the archived-key findings make.
func maskCredentials(s string) string {
	for _, re := range maskPatterns {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			if len(m) <= 16 {
				return m
			}
			return m[:16] + "…[truncated: a credential, retrieve it yourself if needed]"
		})
	}
	return s
}

// maskPatterns are every credential shape that must never survive into a
// report, from internal/creds so this list cannot fall behind the detectors.
//
// It had its own copies of two of them, and that was a leak rather than
// duplication: an Edge Function whose response body contained a Postgres
// connection string or a Management API token was quoted verbatim, because the
// masker did not know those shapes existed. The finding that says a function
// leaks a credential would have been another copy of it.
var maskPatterns = []*regexp.Regexp{
	creds.JWT, creds.SecretKey, creds.MgmtToken, creds.PGConn,
}

// sortedCopy returns a sorted copy, leaving the caller's slice alone. Sorting
// an Options field in place would make a second Run see different input, which
// is a determinism bug waiting to be blamed on the network.
func sortedCopy(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

// residueFinding reports a probe object this scan could not remove.
//
// High, like its relation counterpart, and for the same reason: every other
// unruly-* finding says the scan could not SEE something, while this one
// says the scan CHANGED something. A file exists in somebody's bucket because
// this tool put it there and could not take it back. That is work the operator
// has to do, and burying it among coverage notes would be the tool hiding its
// own mess.
func residueFinding(c *client.Client, bucket, object string) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probe-object-left-behind",
		Name:     "Write probe left an object it could not delete",
		Severity: finding.High,
		Protocol: "storage",
		Matched:  strings.TrimSuffix(c.BaseURL(), "/") + "/storage/v1/object/" + bucket + "/" + object,
		Resource: bucket,
		Description: fmt.Sprintf(
			"The anonymous upload probe placed %q in %q and could not remove it: the bucket "+
				"grants INSERT to the anonymous role but not DELETE, which is a common "+
				"policy pairing. The object is still there. Whether the bucket counts as "+
				"anonymously writable was NOT established — the read-back did not confirm "+
				"the object — so this is reported on its own rather than as part of a write "+
				"finding.", object, bucket),
		Remediation: fmt.Sprintf("Delete the probe object:\n"+
			"  curl -X DELETE '%s/storage/v1/object/%s/%s' \\\n"+
			"    -H 'apikey: $SUPABASE_SERVICE_KEY' -H 'Authorization: Bearer $SUPABASE_SERVICE_KEY'\n"+
			"-- Then re-run with -no-residue to skip probes that can leave one behind.",
			strings.TrimSuffix(c.BaseURL(), "/"), bucket, object),
		Evidence: finding.Evidence{
			Reason: "upload accepted, delete refused",
		},
	}
}

// functionsUnresolvedFinding reports Edge Function names that could not be
// classified, so their silence is not read as absence.
func functionsUnresolvedFinding(c *client.Client, unresolved, probed int) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probes-unresolved",
		Name:     "Edge Function probes got no usable answer",
		Severity: finding.Info,
		Protocol: "functions",
		Matched:  c.BaseURL() + "/functions/v1/",
		Resource: "edge-functions",
		Description: fmt.Sprintf(
			"%d of %d Edge Function names answered with a server error or a rate limit, "+
				"which says nothing about whether the function exists. Those names were "+
				"neither confirmed nor ruled out, so the functions reported are a LOWER "+
				"BOUND. Reading a 5xx as a live function is how a transient gateway error "+
				"becomes a high-severity finding, so it is counted here instead.",
			unresolved, probed),
		Remediation: "-- Re-run when the platform is healthy. If the errors persist, invoke a " +
			"known function by hand to see whether the Functions gateway is serving at all.",
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d of %d function probes unresolved", unresolved, probed),
		},
	}
}
