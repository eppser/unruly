# Benchmark

> **Current priority: corpus breadth.** This file measures two targets. Two
> targets can only show that a scanner works on two targets, and one of them —
> the reference target — has been the headline example long enough that improvements
> risk being tuned to it. A corpus of ten-plus deliberately dissimilar projects
> is being built under `benchmark/corpus/`, with the reference target excluded and each
> project's ground truth established WITHOUT running the scanner: an answer key
> derived from the tool's own output proves only that the tool agrees with
> itself.
>
> **Landed 2026-08-19, extended 2026-08-23.** `benchmark/corpus/` holds 16
> projects and 1,204 claims, verified from a cold start by
> `benchmark/corpus/verify.sh`: 1,193 hold and 11 do not, both shortfalls named
> in `corpus/README.md` rather than averaged away. Ground truth was established
> without running this scanner: from the DDL, and then by direct `psql` and
> `curl` against each running stack, with every write claim actually performed
> against a marker row and read back out of the database. `METHOD.md` records
> what could NOT be verified — including one cell that cannot be tested here at
> all, and why.
>
> The two targets below remain the realism check — a real application and a
> real project — while the corpus is the coverage check.
>
> **Scored 2026-08-20, re-scored 2026-08-23.** `cmd/benchmark` runs the real
> binary end to end against each corpus project and grades the REPORT, so a
> relation the scan never recovered counts as a false negative exactly as an
> operator would experience it. Fifteen of sixteen projects, current numbers in
> `RESULTS.md`:
>
> | dimension | recall | precision | n |
> |---|---|---|---|
> | relation-discovery | 91.1% | 100% | 101 |
> | read-exposure | 89.5% | 100% | 57 |
> | write-exposure | 100% | 100% | 6 |
> | routine-discovery | 83.3% | 100% | 6 |
> | escalation-gains | 100% | 100% | 8 |
> | exit-code | 100% | 100% | 1 |
> | protected-not-flagged | 100% | 100% | 43 |
> | data-classification | 100% | 100% | 9 |
>
> `data-classification` is new and grades something no other dimension does:
> not whether a relation was found, but what the report says is IN it. Project
> 16 is the only one that claims it, and a project making no claim is not
> scored on it — absent is not zero, here as everywhere else.
>
> No false positives anywhere in the corpus. What recall is still missing is
> named rather than averaged away: `Ünïcödé`, `ünïcödé` and `𝕂𝕒𝕣𝕥𝕖` on a
> project that ships no application, so the pinned list is the whole recall
> and no list should hold a double-struck spelling of Karte;
> `billing_accounts` on the proxy project, which that project's own README
> says a correct scanner must NOT decide either way; and
> `mnemosyne_key_rotation_audit`, which is refused to `anon` and therefore
> filtered out of the OpenAPI document as well — measured, not assumed.
>
> **The head-to-head could not be extended to the corpus, and the reason is
> itself a result.** The alternatives address a target only by project
> reference: `supascan` computes every request from
> `https://{project_ref}.supabase.co` (`models.py:30`, a computed property
> with no setter, no flag and no environment variable), and
> `srdaniellp/supabase-scanner` accepts a manual URL but force-prepends
> `https://`, turning `http://127.0.0.1:54401` into
> `https://http://127.0.0.1:54401`. The corpus is fourteen local stacks,
> precisely so its ground truth can be established with `psql`. Neither tool
> can be pointed at one — which also means neither can scan a self-hosted or
> proxied Supabase at all, the deployment shape projects 06, 07 and 11 model.
> The two-target comparison below therefore remains the head-to-head, and it
> is measured against real Supabase projects.


The README claims the best of eight surveyed open-source Supabase scanners
found 1 of 21 relations on a target where unruly finds all 21. That is a
strong claim about other people's work, so the method is written down here and
the numbers were re-measured rather than recalled.

## What is compared, per backend, and what is not

    Supabase     best of EIGHT surveyed open-source scanners, on the corpus below
    Firebase     measured against OpenFirebase, in benchmark/firebase.md
    PocketBase   NO COMPARABLE TOOL FOUND

For PocketBase a search for a security scanner, a rules collection or an audit
tool returned none: only general misconfiguration scanners and write-ups of
PocketBase misconfiguration patterns. So there is no head-to-head to report,
and claiming to be more accurate than alternatives that do not exist would be a
worse statement than making none.

What IS claimed for PocketBase is accuracy against measured ground truth in
both directions: recall on a deliberately vulnerable instance, precision on a
hardened one carrying THE SAME COLLECTION NAMES, so a clean result there means
the rules were read correctly rather than that nothing was present to find.

Two things a practitioner write-up of PocketBase audits lists that this scanner
does NOT cover, stated so a reader does not assume otherwise:

  weak or default superuser credentials  The admin API answers 401 by default
      -- measured on /api/settings, /api/backups, /api/logs and
      /api/collections -- so a reachable login page is not itself an exposure
      and reporting one would be over-reporting. Guessable credentials WOULD
      be, and nothing here tests them.
  JS hook misuse  Hooks can bypass collection rules entirely. Nothing here
      examines them, and from outside a deployment there may be no sound way
      to.

## Target

A real application, not a fixture: `example-app.test`, project ref
`examplerefexampleref`. Its ground truth was established by hand and is
recorded in `evals/targets/the reference target.yaml` — 21 relations, of which 7 leak
rows to the anonymous role, 5 accept anonymous writes, and 13 are correctly
protected.

Every tool was given the same two inputs: the project reference and the anon
key. None had to discover anything the others did not.

**Correction, measured later.** That statement was not true of the headline
number. unruly's 21/21 came from a run given the SITE
(`-u https://example-app.test`), which lets it harvest vocabulary from the
application — an input the other tools were never handed. On the inputs they
actually got, project reference and anon key alone, it found **19 of 21** when
this was written and finds **21 of 21** as of 2026-08-20 (see below). The
conclusion survives the correction and the number does not, so the number is
fixed here rather than left standing because it flattered.

## Metric

**Relations discovered**, out of the 21 that exist. This is deliberately the
most generous possible metric for the other tools: it counts a relation as
found if the tool merely *names* it anywhere in its output, regardless of
whether it classified the relation correctly, reported anything useful about
it, or produced evidence.

A stricter metric — correct read/write classification, or proof-carrying
evidence — would widen the gap, because a tool that never names a relation
cannot have classified it.

## Results

Measured 2026-08-15. Each tool run once, single attempt, same target and
credentials.

| Tool | Relations discovered | Time |
|---|---|---|
| `dbx0/supascan` | 0 / 21 | 0.7s |
| `chungxon/supabase-scanner` | 0 / 21 | 1.1s |
| `srdaniellp/supabase-scanner` | 1 / 21 | 15.3s |
| **unruly**, ref + key only | **21 / 21** | 56s |
| **unruly**, given the site | **21 / 21** | 24s |

Re-measured 2026-08-18, after the discovery changes of that day (declared API
origin, credential precedence, REST mount-path correction): ref and key alone
still recovers all 21 — 7 read-exposed and 14 reported protected. The claim is
re-run rather than carried forward, because a number nobody re-measures is a
number that quietly stops being true.

The ref-and-key figure was 19/21 when this correction was first written. What
closed the gap is described under the second target: the seeds were the limit,
not the oracle.

**Re-measured 2026-08-20, and it is now 21 of 21 on ref and key alone.** The
input the other tools were given no longer costs anything: 21 relations,
19,059 requests, 26.6s, with the retry pass -- the near-miss expansion that
fires when the first sweep finds little -- accounting for 15,180 of those
requests. Given the site as well, the same 21 in 11,754 requests and 24.4s,
which is what the extra vocabulary buys: the same answer for 38% of the
traffic.

Three changes since the 19 closed the last two, and none of them was aimed at
this target: the pinned list stopped being English-only, the hint oracle
stopped discarding names whose alphabet was not Latin, and the OpenAPI
document -- already fetched to identify PostgREST, and until then thrown away
-- became a seed source. The measurement was re-run because the pipeline
underneath it changed, not because anything suggested it had moved.

The testbed's row counts were recorded before and after and are unchanged, and
no probe row exists: the measurement changed nothing on the project it
measured.

**Re-measured 2026-08-19**, after the day's HTTP and classification work: the
three application-fetching stages were moved onto one shared client, and the
severity classifier was extended to read sampled values and to serve both
backends. Discovery was rewritten underneath, so the number was re-run rather
than assumed to survive.

| Mode | Relations | Time (2026-08-18) | Time (2026-08-19) |
|---|---|---|---|
| ref + key only | 21 / 21 | 56s | **26s** |
| given the site | 21 / 21 | 24s | **23s** |

Recall unchanged, and read exposure still 7 relations, matching ground truth.
The ref-and-key run is more than twice as fast, which is not a tuning result:
that path previously opened a separate connection pool per subsystem and let a
stalled stage run its whole plan, and both were consequences of three private
HTTP clients rather than one.

The timing was taken three times (26s, 27s, 24s) before being written down. A
single measurement of a network-bound number is an anecdote, and this file has
already had to correct one headline figure that nobody re-ran.

Both runs were read-only. The target's row counts were recorded before and
after and are identical, so the measurement changed nothing on the project it
measured.

A note for anyone reproducing this: two of the target's tables, `agent_runs`
and `daily_snapshot`, are appended to by the live application, so their counts
drift on their own. Verify a scan's own before/after delta rather than equality
with any recorded snapshot -- checking against a stale figure reports a
violation that did not happen.

## A second target

One target is a story. The Supabase lab (`fixtures/supabase-lab/answer-key.yaml`) is a
different Supabase project with independently established ground truth: 7
relations, one `SECURITY DEFINER` routine that returns rows to anon, and one
public bucket serving an invoice to anyone with the URL.

Measured 2026-08-15, every tool given the project reference and the anon key:

| Tool | Relations | Routines | Buckets |
|---|---|---|---|
| `dbx0/supascan` | 0 / 7 | 0 / 1 | 0 / 1 |
| `chungxon/supabase-scanner` | 0 / 7 | — | — |
| **unruly**, ref + key only | **7 / 7** | 0 / 1 | **1 / 1** |
| **unruly**, given the site | **7 / 7** | **1 / 1** | **1 / 1** |

Two things this makes plain that the first target did not.

The category failure reproduces: both tools completed successfully — exit 0,
no errors — and reported nothing. supascan printed "No RPC functions found"
and "No storage buckets found" for a project with a routine that hands over an
audit log and a bucket that serves invoices unauthenticated.

And measuring the second target found a real gap, since fixed. On ref-and-key
alone unruly originally reached 2 of 7 here, against 19 of 21 on the first
target — recall swinging wildly with how conventional a schema's names happen
to be. Probing by hand showed the oracle would answer for all seven
(`customer_record` hints `customer_records`), so the seeds were the limit, not
the oracle. Expanding the pinned list into near-misses — n-1 stems, and
modifier plus singular noun — takes it to 7 of 7 here and 21 of 21 there.

That expansion costs about 13,000 extra probes and roughly 40 seconds, so it
runs ONLY when the cheap path produced nothing — either no vocabulary could be
harvested, or the first pass found no relations. An application's own
vocabulary is better than any expansion of a generic list, and paying this on
every scan would slow the good path to improve the fallback.

The cost is not slack. Sampling the candidate list was measured and rejected:
recall falls almost linearly with the sample (1,718 probes → 3 of 7; 3,435 → 4;
6,870 → 5; 13,740 → 7), because each relation needs its own near miss and the
oracle's iterative rounds do not compensate. That is what full recall costs on
a project with no application to read.

`srdaniellp/supabase-scanner` is absent from this table: it presents an
interactive menu and could not be driven non-interactively here. That is a
limitation of this measurement, not a finding about the tool, and it is left
blank rather than scored zero — a tool that did not run has not failed.

`supascan` completes in under a second and reports `"findings": []` with
`"risk_score": 0` against a database that has five anonymously writable
relations. It is the most capable tool in the set by feature list, and it is
fast precisely because it stops: PostgREST's OpenAPI root is `service_role`-only
now, its enumerator returns an empty slice on the resulting 401, and nothing
downstream distinguishes that from a project with no relations.

`srdaniellp` finds `sessions` — the one relation whose name appears in its
90-entry generic wordlist. The other 20 are domain-specific
(`signatory_submissions`, `zero_day_series`, `agent_runs`) and no wordlist
contains them.

## Reproducing

```sh
# clone the tools
for r in dbx0/supascan chungxon/supabase-scanner srdaniellp/supabase-scanner; do
  git clone --depth 1 "https://github.com/$r"
done

# run each against the same target, then count how many of the 21 relation
# names from evals/targets/the reference target.yaml appear in its output
```

Environment notes, since two of these tools would not start on a stock macOS
Python: `chungxon` needs Python 3.10 or newer (it annotates `dict | None`), and
`srdaniellp` needs `requests`. Both failures look exactly like a tool finding
nothing if the exit code is not checked. They were run under a 3.14 virtualenv.

Two measurement notes, both learned by getting them wrong first:

- Score with a shell **array**, not a space-separated string. In zsh
  `for r in $LIST` does not word-split, so every tool scores 0 — including the
  one you are trying to show works. That mistake produced a first run in which
  all four tools scored 0/21, which was believable enough to nearly publish.
- unruly's JSON output contains *findings*, not every relation it
  discovered. Counting relation names in the findings file gives 7, not 21,
  because the 13 correctly protected relations produce no finding by design.
  The discovery count comes from the scan's own summary line.

## Scope and fairness

These tools are free software written by people solving their own problem, and
several are clearly early. The comparison is not a judgement of effort. It is
evidence for one specific claim: that the category shares a failure mode —
reporting "no findings" when the tool could not look — and that the failure is
silent in every case measured.

`supabase/splinter`, Supabase's own linter, is excluded because it is not
comparable: it runs *inside* the database with full catalogue access and will
beat any external scanner at describing configuration. It cannot answer whether
that configuration is reachable from the internet, which is the question these
tools exist for.

## `make benchmark` exits 1, and that is the honest result

The runner requires EVERY dimension of EVERY project to be perfect before it
exits 0. Two are not, deliberately and durably: `09-huge-schema` recovers 69%
of relations and 60% of read exposure by sampling a schema too large to probe
exhaustively, and `13-rpc-security-definer` misses one routine that is refused
to `anon` and is therefore absent from the OpenAPI document as well.

Those shortfalls are named in the report rather than averaged away, which is
the point -- but it does mean a nonzero exit here is the normal state of this
corpus, not a regression. Read the totals, not the exit code. It is also why
this target is not an audit stage: a check that is always red teaches people to
ignore it.

## A vendor console as the alternative

The comparisons above are against other scanners. Corpus project
`15-grant-vs-rls` measures something different: the tool a developer is most
likely to actually consult, which is their provider's own dashboard.

Neon's console warns, of a project whose tables were built for this repository:

> `anon_readable`, `rls_disabled`, `open_guestbook`, `owner_only` have RLS
> disabled. All authenticated users can view all rows in these table(s).

`owner_only` answers **403 / 42501** to every caller, authenticated or not,
because no role holds a GRANT on it. PostgreSQL refuses before Row-Level
Security is ever consulted, so RLS state does not describe reachability. The
console reads `relrowsecurity` and stops.

Measured on the same four tables, reproduced as ordinary PostgreSQL so the
comparison is about the reasoning and not about Neon:

| | reports the table nobody can read | clears the table anybody can read |
|---|---|---|
| Neon console | yes — `owner_only` | not applicable; it flags on RLS state alone |
| unruly | no | no |

`15-grant-vs-rls`, `protected-not-flagged`: **100% precision**. The scanner is
silent about `rls_off_ungranted` — the false positive — and reports
`rls_on_permissive`, where RLS is *enabled* and a permissive policy hands every
row to anyone. A tool reasoning from RLS state gets both ends wrong at once.

This is not a claim that Neon's product is insecure. The console is a
configuration view and is accurate about configuration. It is evidence for the
same claim the scanner comparisons make: **a signal that describes settings is
not a measurement of what a stranger can reach**, and treating one as the other
produces false positives and false negatives from the same mistake.
