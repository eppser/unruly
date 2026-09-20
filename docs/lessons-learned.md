# Lessons learned — batch scanning with unruly

Running log of what the scanning pipeline taught us, to feed both the research
paper and improvements to unruly. One dated section per run or finding.
Template at the bottom.

## 2026-08-16 — pipeline bring-up (lab fixture smoke test)

**Setup.** `scripts/scan-batch.py` against the local lab fixture
(`fixtures/lab`, bare PostgREST at `http://127.0.0.1:54321`, `-rest-prefix /`)
plus a deliberately unreachable target.

**What happened.**

- The runner's extra-flag passthrough used `argparse.REMAINDER`, which keeps
  the literal `--`. Go's flag package read it as end-of-flags and silently
  dropped `-k` and `-rest-prefix`. The scan "worked" — 19,004 requests, exit
  3 — but every probe was a 401 and the only output was capability-degraded
  infos. **A harness bug produced a correct-looking run.** What caught it was
  the scanner's own self-report (`15867 of 15867 probes rejected with
  401/403`), not the exit code and not the harness. Lesson: always read the
  `unruly-*` info findings before trusting a batch's numbers; a run where
  `capability-degraded` or `probe-budget-exhausted` fires is not data about
  the target.
- Unreachable target: the tool itself exits 3 with
  `surface-not-assessed` findings — no special-casing needed in the runner.
- Timeout and unexpected-exit paths (tested with a shim binary): retried once,
  recorded in the manifest, batch continued, runner exit 3.
- Determinism spot-check: re-scan byte-identical, as promised.

**Action items.**

- [ ] Batch analysis should flag any target whose findings include
      `unruly-capability-degraded` as "partially blind", and exclude it
      from aggregate recall statistics.
- [ ] Consider a runner-side preflight: one control request per target
      before the real scan, so a dropped `-k` fails in seconds, not after
      19k requests.

## 2026-08-18 — storage-api in the lab: attempted, not landed

**Setup.** Adding `public.ecr.aws/supabase/storage-api:v1.11.13` to
`fixtures/lab/docker-compose.yml`, to grade `supabase-public-storage-bucket`,
`supabase-storage-anon-write` and `unruly-probe-object-left-behind` locally.
Those three are currently graded ONLY through the cloud exploit lab's answer
key, which needs network access and a secret CI does not have -- the same
argument that justified the GoTrue fixture, which did land.

**What happened.** The container starts and answers `/status`, but seeding a
bucket with a readable object does not work yet. Four blockers, in the order
they appeared; the first three are solved and worth not rediscovering.

1. *initdb ordering.* `00_auth_roles.sql` sorts BEFORE `00_roles.sql`, so a
   `GRANT ... TO authenticator` in the former fails: the role does not exist
   yet. Postgres exits 3 and every dependent container reports "dependency
   failed to start", which names the symptom and not the cause. Fix: a
   separate `00a_` file, which sorts after `00_roles.sql`.

2. *Database-level permission.* storage-api's migrations create objects at the
   database level, so its role needs `GRANT CREATE ON DATABASE`. Without it:
   "Migration failed. Reason: permission denied for database fixture".

3. *Credentials at start time.* Storage authenticates callers against the
   project's JWTs, so it needs them BEFORE it starts, and the fixture mints
   them rather than committing them (a JWT-shaped string in the tree trips the
   secret scan). A gitignored `.env` beside the compose file works: docker
   compose reads it automatically.

4. *NOT SOLVED -- search_path after SET ROLE.* storage-api connects as
   `supabase_storage_admin` and switches role per request. Role-level
   `search_path` settings are applied at LOGIN, not on `SET ROLE`, so after the
   switch `storage.objects` resolves as `objects` and fails with
   `relation "objects" does not exist`. Setting `search_path` on every role it
   switches into did not fix it, so the mechanism is not yet understood.
   Granting `service_role` membership to the admin role got past the RLS
   denial, which is progress but not the same problem.

The attempt was backed out rather than left half-configured: a fixture that
starts but cannot be seeded adds a surface that answers and proves nothing,
which is worse than no fixture at all.

**Action items.**

- [ ] Establish what storage-api actually sets `search_path` to per request
      (its own `SET`, or PGOPTIONS, or the role default) before trying again.
      Reading the image's migration/connection code is cheaper than guessing.
- [ ] Alternative worth pricing: serve the storage ENDPOINTS from the gateway
      with static objects, as the hardened fixture already does for the clean
      case. It grades the scanner's probe logic and its bucket-existence
      reasoning without running storage-api at all -- less realistic, and it
      would have taken a fraction of the time.

## 2026-08-18 — three audit runs lost to a misleading diagnostic

**Setup.** `make audit` after adding the GraphQL and Realtime wiring evals.
Reported `19 passed, 0 failed, 2 not run` three times running, always the same
two: eval-fixtures and eval-exitcode, both "fixture unreachable twice,
including after a restart".

**What happened.** The fixture was reachable the whole time -- curl answered 200
before and after every run. The real error, once the log was read instead of the
summary, was `dial tcp 127.0.0.1:54321: connect: can't assign requested
address`: EADDRNOTAVAIL, the HOST out of ephemeral ports. Measured at the time:
11,410 sockets in TIME_WAIT to that one port, against a range of 16,384. A few
minutes later it was 6.

The cause was mine -- repeated full audits plus an 11,816-request scan of the
testbed, back to back. But three runs were spent on Docker instead, because the
message said "Bring the fixtures up... If Docker itself is down, colima start".
I removed an orphaned container, added --remove-orphans, restarted the daemon,
and re-ran, all on the strength of a sentence that named the wrong cause.

A diagnostic that names the wrong cause is worse than no diagnostic, because it
is followed. This one was written to prevent exactly this class of confusion --
"a measurement that could not be taken presenting as a measurement that came
back bad" -- and it caused an instance of it.

**Action items.**

- [x] Split the two dial failures. EADDRNOTAVAIL now says the host is out of
      ports, gives the netstat command to confirm, and says restarting Docker
      will not help and has been tried. Matched on the errno rather than the
      message text, which differs by platform and Go version.
- [x] Reuse one pool across clients. Done by sharing the http.Transport, keyed
      by pool size: 11,410 TIME_WAIT before, 38 after a full audit. curl in the
      replay evals still dials its own, which is a much smaller burst.

## 2026-08-20 — a guard for committing during an audit, attempted and withdrawn

**Setup.** After `git add -A` during a `make audit` committed
`cmd/unruly/main.go` with `if !o.write` rewritten to `if false` -- the line
telling a reader that a scan without `-write` did NOT test INSERT -- a
pre-commit hook was written to refuse commits while `scripts/mutate.py` owns
the tree.

**What happened.** Three detection mechanisms, none demonstrated working:

- A lock file the harness wrote. Observed absent during a real audit while
  mutate.py was alive with a `go test` child, i.e. past the line that writes
  it. Never explained.
- `pgrep -f`. Matched nothing on this macOS while the process was plainly
  visible to `ps -eo command`.
- A grep over the whole `ps` line. Matched the shell running the hook, because
  that shell's own command line quoted the pattern, so every commit was
  refused -- and a test that looked like a success ("refused 3 times of 3")
  was measuring exactly that self-match.

The attempts to verify were worse than the attempts to build. Runs launched as
`(cmd &)` from a tool call did not survive, so several "the hook refused"
results were taken against no running harness at all. Two runs that DID start
were killed when the shell exited, leaving a mutated `internal/client/client.go`
and a mutated `README.md` in the tree -- the exact failure the hook was meant
to prevent, caused by testing for it. `git reset --hard`, used to undo probe
commits, destroyed uncommitted work three separate times.

The control was reverted rather than shipped. A guard that cannot be shown to
guard is the pattern this repository exists to refuse, and shipping one with a
test that only checks its shape would have been worse than the exposure.

**What actually protects the tree today.** The harness restores every file it
mutates, on normal exit and on SIGINT/SIGTERM/SIGHUP; and its baseline refuses
to start against a tree a killed run left dirty, which is what caught both
leftovers above. Neither protects against a commit taken mid-run. The remaining
control is behavioural: do not edit or commit while `make audit` is running,
and never `git add -A` during one.

**Action items.**
- [ ] If this is attempted again, verify the detection against a run started
      with a durable background mechanism, not a subshell, and assert the
      refusal happens while a process is provably alive.
- [ ] Consider instead having `make audit` snapshot `git status` at the start
      and fail loudly at the end if tracked files changed underneath it.

## 2026-08-20 — what "delete anything unnecessary" found

**Setup.** Backlog item 16 asks for a lean-architecture pass. Measured rather
than eyeballed: every exported func, type and method under `internal/`, counted
against every reference in `internal/` and `cmd/`, tests included.

**What happened.** 288 exported declarations. Three had no reference anywhere,
and two of those -- `finding.MarshalJSON` and `finding.UnmarshalJSON` -- are
interface methods `encoding/json` calls implicitly, which no textual analysis
can see and deleting either would silently change every report. The one genuine
find was `eval.Score.F1`, a harmonic mean nothing computes, now removed.

A first pass looked much worse: 51 identifiers with no cross-package
`pkg.Name` reference. Almost all were types returned by exported functions --
a caller writes `en := enumerate.Run(...)` and never spells `enumerate.Result`
-- so the analysis was measuring how Go infers types, not what the code needs.
Worth recording because the number was alarming and wrong.

**The other half of "lean" is what a scan costs the target.** A full scan of
the local lab: 5,955 requests for 24 relations. Routine discovery is 3,534 of
them, 59%, split evenly between the default schema and the one extra schema.
Relation discovery is 2,308. That is a deliberate recall choice -- a schema
whose relation names are not in the vocabulary can still hold a discoverable
routine -- and it is bounded by `-max-rpc-probes` and reported when the bound
binds. It is not waste, but it is the dominant cost and the first place to look
if the budget ever needs cutting.

**Action items.**
- [x] Remove `eval.Score.F1`.
- [ ] If request cost becomes a complaint, the routine sweep is 59% of it and
      the extra-schema half is the part with the weakest expected return.

## 2026-08-20 — stopping the expansion when it "stops paying", attempted and withdrawn

**Setup.** The expansion pass costs 15,180 requests on the reference target and
everything it finds there is found early, so the sweep was made to stop after
eight consecutive 256-candidate chunks produced nothing. Chunked rather than
continuous so the stop point stays deterministic: probes complete in whatever
order the network returns them, and "stop after N quiet probes" would stop
somewhere different every run and move the relation set with it.

**What happened.** Two measurements, and the second killed it.

The first attempt counted only resolved relations as yield, and the reference
target went from 21 relations to 20. The candidate that mattered arrived as a
HINT from a family guess rather than as a direct hit, and the chunk that
produced it was scored as quiet. Counting hints as yield fixed that: 21
relations in 8,655 requests and 16.5s, against 19,059 and 26.6s.

Then the exploit lab: **2 relations, where the full sweep finds 7.** Its
relations are generic English names spread through the cross product with no
family structure, so a run of two thousand quiet candidates is not evidence the
sweep is finished -- it is evidence that the next hit has not arrived yet.

**Withdrawn.** A threshold could be raised until both known targets pass, and
that is fitting a heuristic to the two targets that happen to be measurable.
The cost of being wrong is five relations reported as absent on somebody's
project, which is the exact failure this scanner exists to refuse; the benefit
is run time. The trade is not close.

**What survives.** The families-first ordering, which has no recall cost and
reaches 21 of 21 at `-max-relation-probes 500` on a target with families, and
the knowledge that an operator who knows their own schema can bound the sweep
deliberately.

**Action items.**
- [ ] If this is attempted again, the stop rule needs a signal that
      distinguishes "the candidate list has run out of ideas" from "the hits
      are sparse here", and neither yield nor a gap length is that signal.

## Template

```
## YYYY-MM-DD — <run or topic>

**Setup.** targets, flags, binary version.

**What happened.** observations, with manifest/findings references.

**Action items.** checkboxes; link the commit/issue when done.
```
