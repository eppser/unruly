# Adding a backend

This scanner is a shared core plus one package per backend. The core owns
everything that is true regardless of which backend is being scanned: findings,
evidence, redaction, severity, exit codes, the request budget, the rate limit,
and the audit harness. A provider owns recognition, an exhaustive capability
manifest, and the stages that assess a recognised instance.

If you find yourself needing a third thing from the core, that is a signal the
seam is in the wrong place. Say so rather than reaching around it.

## The contract

```go
type Detector interface {
    Limited
    Staged
    Name() string                       // canonical, and the prefix of your finding ids
    Detect(Surface) (Detection, bool)   // offline, over bytes already fetched
}
```

Addressing is optional; preparation is an optional provider-owned lifecycle
hook for work that must happen before its stage graph is constructed:

```go
APIBase(Detection) string               // your origin; "" if you address absolutely
DescribePreparation(Detection, scan.Inputs) PreparationDescriptor // includes a positive MaxRequests
Prepare(context.Context, Detection, scan.Inputs) Preparation
```

Register from an `init` and nothing in the core changes:

```go
func init() { Register(mybackend{}) }
```

`internal/provider/contract_test.go` contains a complete second backend written
to this contract. It is about forty lines, and it is the shortest description of
what you have to write.

## Assess in stages, not in one function

Every provider returns a list of stages. A small provider may wrap a mature
assessor in one stage while it is decomposed further, but there is no parallel
`Assess` execution path. The alternative has been measured: the Supabase scan was one 1,390-line
function with twelve author-marked stage boundaries and about thirty variables
crossing them, and that is the mechanical reason it could not sit behind this
seam at all — there was no boundary to lift.

```go
type Stage interface {
    Name() string                            // stable; it appears in coverage reporting
    Describe() scan.StageDescriptor
    Run(ctx context.Context, st *scan.State) error
}
```

An error from `Run` means *this surface could not be assessed*, not *the scan
failed*. `scan.Pipeline` runs the rest regardless and turns the error into a
`SkippedStage` finding, because the version that returned early left realtime,
storage and historical exposure unexamined while the report looked complete.

Your backend exports one function that returns the whole ordered list:

```go
func Stages(cfg Config) []scan.Stage
```

`Config` holds everything known before the scan starts — the operator's flags,
the shared clients, the budgets — and nothing that is another stage's result.
That distinction is the point of the whole exercise. When the list can be built
up front, adding, removing or handing off a stage is an edit to your package;
when it cannot, the caller ends up constructing each stage as the values for it
arrive, which is what `cmd/unruly` used to do and why every Supabase change was
a change to the command.

## Hand values to later stages as typed artifacts

Stages share `scan.State` and nothing else. A value one stage produces and
another consumes goes through the typed store:

```go
scan.Put(st, Relations{Names: names})       // keyed by its Go type
rel, ok := scan.Get[Relations](st)          // ok distinguishes absent from empty
combined := scan.MergeAccess(first, second) // merge neutral access from pipelines
kind := scan.ArtifactOf[Relations]()         // descriptor identity from the Go type
```

`scan.Get` returns two values on purpose. Absent is not zero: "no relations were
discovered" and "the discovery stage never ran" are different facts, and a
single return value collapses them into the one that reads as good news.

The store is keyed by type, so two stages cannot collide unless they genuinely
share a type, and `scan.State` never names a provider type — which is what lets
one pipeline carry Supabase and application stages without the core knowing
either exists.

Scan-level facts that any backend can produce travel in provider-neutral terms:
`scan.Coverage` for relation and schema counts, `scan.Access` and
`scan.AccessFact` for who could reach what, `scan.ApplicationCoverage` for
route/origin denominators, and `scan.Inputs` for what the operator supplied.
Put those rather than inventing a parallel vocabulary, or the renderer learns
your backend's nouns.

## Declare what your stages need, and let the plan be checked

Every runnable stage must implement `scan.Describer`:

```go
func (s SchemasStage) Describe() scan.StageDescriptor {
    return scan.StageDescriptor{
        ID:            "schemas",
        Requires:      []scan.ArtifactType{scan.ArtifactOf[Vocabulary]()},
        Produces:      []scan.ArtifactType{scan.ArtifactOf[Schemas]()},
        MutatesTarget: s.Write,
    }
}
```

`scan.Validate` then checks the graph **before the first request**: a consumer
above its producer, a missing producer, two stages sharing an `ID`. Get that
wrong without the declaration and the symptom is a stage that quietly finds
nothing, at the far end of a scan that has already spent thousands of requests
on somebody else's server.

`Optional` is load-bearing rather than decorative: an optional artifact produced
by a *later* stage can never be read, so declaring it as optional is still a
planning error and is reported as one.

Describe the **configured** stage, not the type. `MutatesTarget: s.Write` is
right; a constant `true` refuses plans that were never going to write.

`scan.CheckConsent` uses the same two flags to refuse a plan the operator has
not authorised: `scan.Consent{Write: ...}` for anything that changes the target,
`ThirdParty` for anything that tells a stranger what is being scanned.
Both are checked inside the stages too. The plan-level check exists because
six stages each remembering is six chances to forget, and the one added
tomorrow starts out forgetting.

## Say what is happening while it happens

`st.Note` is how a stage narrates itself, at `scan.Info`, `scan.Warn` or
`scan.Error` — a `scan.NoteLevel`:

```go
st.Note(scan.Warn, "%d of %d hosts refused the anon key", refused, total)
```

The pipeline stamps the current stage on every note, so notes self-attribute and
the command does not have to know which backend produced them. Narration that
lives in `cmd/unruly` is narration that has to be edited when your stage list
changes, which is the thing this seam exists to prevent.

Two more pieces of the core belong to you rather than to the command:

- `scan.NewBudget(n)` and `*scan.Budget` — one request budget, shared by every
  stage. A stage that keeps its own is a stage that spends past the operator's
  cap.
- `scan.Skip(stage, reason)` — wrap a stage that must not run this time. It does
  not run, and it is still reported, which is the difference between a scan that
  did not look and a scan that says it did not look.

## Detect offline, over bytes the scan already has

`Detect` is handed a `Surface`: the application's HTML, its scripts, and its
response headers, downloaded once and shared by every provider. Do not make
requests from `Detect`.

Two reasons, and the second matters more than the first. A `Detect` that fetches
multiplies a scan's cost by the number of backends this tool learns to
recognise. And it puts load on a stranger's site to answer a question that is
already answerable from bytes in hand — for most targets, every provider but one
would be making requests purely to conclude "not mine".

## Require corroboration

The client-side key is public in every backend worth scanning. Supabase's anon
key and Firebase's web API key are *designed* to ship in the bundle, so finding
one is not a finding — it is an address.

Firebase's detector requires a project identity **plus** corroboration: either
the key sits in a config object that also names a `projectId`, or a
Firebase-specific host appears that belongs to no other product. A Google API
key on its own is not enough, because Google issues the same key shape for Maps,
and a scanner that reports every Maps key as a Firebase project is reporting
noise at whatever severity it chose.

Ask what else could produce the string you are matching. If the answer is "a
different product entirely", you need a second signal.

## Declare your own address

`APIBase` exists because the core used to derive it: the client for every
non-Supabase backend was built with `"https://" + provider + ".googleapis.com"`.
That is correct for exactly one backend and silently wrong for the next — a
provider named `appwrite` would have been handed a client pointed at
`appwrite.googleapis.com`, and every probe it made would have gone to a host
with no relationship to the target.

A backend's address is the most backend-specific fact there is. Return yours, or
return `""` if your assessment addresses every service absolutely (Firebase's
does: Firestore, RTDB and Remote Config each live on their own host).

## What a finding must carry

The core's rules apply to your findings exactly as they apply to the built-in
ones, and the audit enforces every one of them:

- **A canonical id**, prefixed with your provider name, documented in
  `docs/checks.md`, and placed in a row of `docs/threat-model.md`. A check that
  fits nowhere in the threat model is noise, and the audit will say so.
- **A protocol** from `finding.KnownProtocols`. Consumers group on this field.
- **Proof**, not a boolean: real sampled evidence and a request the reader can
  replay. A finding nobody can check is a finding nobody should act on.
- **Remediation** that is executed verbatim — by the eval, and by operators
  piping it into `psql`. Every non-SQL line must be a `--` comment.
- **Never republish the secret.** If the finding is "this value is exposed",
  naming the parameter is the evidence; quoting the value makes the report a
  second copy of it.

## Declare what you cannot measure

Every provider implements the exhaustive capability manifest. `Measures`
names what is assessed and `Cannot` names what is not, with a reason:

```go
func (mybackend) Cannot() map[Capability]string {
    return map[Capability]string{
        CapWrite: "no sound write probe exists for this API: a refused write and an
            accepted one return the same status",
    }
}

func (mybackend) Measures() []Capability {
    return []Capability{CapRead, CapStorage}
}
```

Registration rejects a provider unless all seven attacker outcomes appear in
at least one side. A capability in both is partially measured: the limitation
states the uncovered boundary. This exists because the surface not implemented
is precisely the surface a contributor is least likely to remember to mention.

Firebase declares two, and both were silent before: it has no write probe for
Firestore or the Realtime Database, and it cannot enumerate what exists because
`listCollectionIds` is administrator-only and a protected collection answers
403 identically to one that never existed.

## Say what you could not see

The hardest rule, and the one that separates this tool from the alternatives:
**where existence is undecidable, claim nothing.**

Firestore is the worked example. `listCollectionIds` is admin-only, and a
collection that is protected and one that never existed both answer 403. So
"protected" is not a claim this scanner can make about Firestore, and it does
not make it. Measured against OpenFirebase's own top-50 wordlist, that tool
reports 50 protected collections on our lab, of which **zero** exist.

Report recall as a lower bound, emit `unruly-surface-not-assessed` for what you
could not reach, and let the exit code carry it: could-not-measure is 3, and 3
is not clean.

## Evals first

Every capability needs an eval that fails without the code. Before you commit,
break your check and watch the eval fail — a test that passes for a reason other
than the one you believe is worse than no test, because it also stops anyone
else from looking.

The coverage audit builds its profile from the **offline** suite, so every
finding id needs an emit site a test executes without the network, in addition
to whatever live grading you do against a lab you own.
