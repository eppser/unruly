# Contributing

## The soundness rule

One rule matters more than the rest, because breaking it is how every scanner
this project replaces became untrustworthy:

> **A probe whose negative result is indistinguishable from "nothing was there"
> is not a probe. It is a coin flip with a plausible story attached.**

This was learned three separate times during development, each time by writing
a check that looked obviously correct and measuring it:

| Probe | Why it was unsound |
|---|---|
| Zero-match `DELETE`/`PATCH` for write access | RLS filters rows silently rather than erroring, so a protected relation and a wide-open one both answer `204`. Flagged 16 of 21 relations falsely. |
| Unknown-column `INSERT` as a canary | PostgREST rejects unknown columns from its own schema cache *before* issuing SQL, so `PGRST204` comes back identically either way. |
| Realtime subscription acknowledgement | Supabase acknowledges a subscription for a relation that does not exist. Flagged 21 of 21 relations, 13 correctly protected. |
| Synthetic probe for the hint oracle in `selfcheck` | Drew no hint because nothing in the schema resembled the made-up name, and concluded the oracle was broken while enumeration was recovering 21 of 21. |

This is no longer a matter of remembering. `internal/soundness` makes it a test
obligation:

```go
soundness.Require(t, soundness.Probe{
    Name:          "insert-write-discriminator",
    Detects:       "whether the anonymous role may INSERT into a relation",
    PositiveInput: "m_rls_selnone_insanon_nn (INSERT policy TO anon)",
    Positive:      func() soundness.Outcome { return writeOutcome(ctx, c, "m_rls_selnone_insanon_nn") },
    NegativeInput: "m_rls_selnone_insnone_nn (RLS on, no policy)",
    Negative:      func() soundness.Outcome { return writeOutcome(ctx, c, "m_rls_selnone_insnone_nn") },
}, "reached", "blocked")
```

`Require` runs both controls and fails when they cannot be told apart. It also
fails when the verdicts are inverted, because a probe that reports every open
relation as protected discriminates perfectly and is still wrong.

`fixtures/matrix` generates a relation for every RLS configuration, so a
known-open and a known-protected control exist by construction for any probe
you need to test. Use the `_nn` (NOT NULL) variants so no probe row can land
and the test stays repeatable.

`TestZeroMatchDeleteIsCaught` keeps the harness honest: it hands `Require` the
real rejected probe and asserts it is still rejected.

**Passing controls prove discrimination, not correctness.** A soundness test
asks whether two known-opposite inputs can be told apart. It does not ask
whether the mechanism you meant to test is the one doing the telling. The
routine-callability probe passed its controls while never once performing a
privilege check: its positive control took an argument, so PostgREST answered
`PGRST202` from its schema cache and the probe scored a signature mismatch as
"callable". Choose controls that exercise the mechanism, and say in the test
why they do.

**Verify the control itself.** A broken control produces a correct-looking
result from a broken input, and reads as a pass. This bit us through a fixture,
not a probe: three copies of `mint-jwt.py` had drifted, and the matrix fixture
held a version predating `--role`. It did not reject the unknown argument — it
emitted an `anon` token into a file named `authenticated.jwt`. That token was
one commit away from becoming the negative control for the escalation soundness
test, where it would have "proved" the probe finds no privilege gains.

There is now one `fixtures/mint-jwt.py`, and it decodes the token it just
produced to check the role claim matches what was asked for.

Before adding a check, answer this in the pull request:

1. **What is the control?** Give an input whose correct answer is known and
   *opposite*. A write probe must be run against a relation known to be
   protected. An enumeration oracle must be run against a name that cannot
   exist. If both inputs produce the same response, the check does not work and
   no amount of tuning will fix it.
2. **What does the negative mean?** If "no signal" could mean either "secure"
   or "my probe missed", say so in the finding rather than staying silent.
3. **What happens when the platform changes?** Prefer a runtime control probe
   over an assumption baked in at authoring time. `internal/realtime` suppresses
   its own findings when its control probe shows the signal is uninformative,
   and would resume automatically if that changed.

## Evals come first

Add the expectation before the code. `evals/targets/*.yaml` declares what is
true about a target; `make eval` grades a scan against it on recall *and*
precision. Precision is not optional — a check that flags everything scores
perfect recall and is worthless, which is why `fixtures/hardened` exists and
must stay near-silent.

New behaviour needs a fixture case whose posture is known by construction, not
a note that it was tried against somebody's project once.

## Wordlists are generated, not curated

`data/*.txt` are produced combinatorially by `data/gen_wordlists.py` so they
cannot encode the answers of the projects this tool was developed against. CI
regenerates them and fails on any difference.

If an eval fails because a name is missing, add the *rule* that produces that
class of name, not the name. Adding the single string that turns a red eval
green is the most tempting way to make this tool quietly useless on every
project except the ones it was built against.

## `make test` is offline whatever your shell says

The live evals are opt-in via `UNRULY_LIVE`, and `make test` unsets it
explicitly. A contributor with that variable exported — likely, since running
the evals is the other half of the workflow — otherwise turned the offline
target into a live run, which executed the graded evals BEFORE
`fixtures-reset`, left probe rows behind, and failed the real graded run later
in `make ci` with a row-count mismatch that read like a scanner bug.

A target that describes itself as offline must be offline regardless of the
environment it is invoked from.

## Determinism

Two scans of an unchanged target must produce byte-identical JSONL. In
practice: sort before emitting, collect concurrent results by input index
rather than completion order, and never let a timestamp or map iteration order
reach the output. `go test ./...` runs offline and must stay that way — the
default suite needs no network, no fixtures and no credentials.

## Fixtures bind fixed ports

Only one checkout can run the fixtures at a time, and on macOS the checkout
must sit under a path Docker Desktop shares. A clone under `/private/tmp`
mounts the schema directory as EMPTY: Postgres starts with no tables and logs
`ignoring /docker-entrypoint-initdb.d/*` rather than failing, so `make eval`
reports missing relations that look like scanner bugs.

Both problems were found by cloning the repository and running `make eval` in
the clone — something no amount of running it in place would have surfaced.

## Before opening a pull request

```
make lint      # gofmt + vet
make test      # offline suite
make eval      # fixtures up, recall and precision graded
```

## Before you push

```sh
make ci-offline
```

That is exactly what the offline CI job runs — build, lint, vet, race, tests,
cross-compiled release binaries, the mutation suite and the committed-credential
scan — and it needs no Docker, no credentials and no network. If it passes
locally it passes there.

The fixture job additionally needs Docker (`make fixtures-up`), and the
exploit-lab evals need credentials a fork cannot have, so they are not in CI
and are not expected of you.
