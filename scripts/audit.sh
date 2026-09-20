#!/usr/bin/env bash
# One command an auditor can run to reproduce every claim this project makes.
#
# The report has THREE states per check, not two. "Did not run" is reported as
# loudly as "failed", because a suite that silently skips half of itself and
# prints a row of ticks is the exact failure this scanner exists to detect --
# and this repository has hit it in its own harness twice: every `make eval-*`
# once passed from cache without executing, and a dead Docker daemon has
# repeatedly produced recall numbers that described the harness rather than the
# tool.
#
# Exit codes mirror the scanner's own contract, deliberately:
#
#   0  every check ran and passed
#   1  a check failed
#   3  everything that ran passed, but some checks could not run
#
# Usage:
#   scripts/audit.sh                 # everything available in this environment
#   scripts/audit.sh --offline       # only what needs no Docker and no credentials
#   scripts/audit.sh --out FILE      # also write the report to FILE

set -uo pipefail
cd "$(dirname "$0")/.."

OFFLINE_ONLY=0
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --offline) OFFLINE_ONLY=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Logs are kept, not discarded. The first version deleted them on exit, so the
# one check that failed could not be investigated afterwards -- by me or by an
# auditor. A report that says FAIL and throws away the evidence is asking to be
# taken on trust.
LOGDIR="audit-logs"
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"

# The offline section must be genuinely offline, which means running it WITHOUT
# the credentials this script sources for the live section. It did not, and the
# consequence was not theoretical: `make race` picked up an anon key, ran the
# live evals early -- before the fixtures were even started -- and failed. The
# audit then reported a race-detector failure, which is not what happened.
#
# "Offline" is a property of the environment a check runs in, not a label on a
# Makefile target.
OFFLINE_ENV=(env -u SUPABASE_ANON_KEY -u SUPABASE_SERVICE_KEY -u SUPABASE_ACCESS_TOKEN
             -u SUPABASE_URL -u UNRULY_LIVE -u UNRULY_FIXTURE_KEY
             -u UNRULY_SATURATION)

PASSED=0; FAILED=0; SKIPPED=0; RETRIED=0
ROWS=""

emit() { ROWS="${ROWS}$1"$'\n'; }

# environmentFailure reports whether a failed check failed because the test
# environment went away rather than because the scanner is wrong.
#
# Needed because the environment DOES go away: the Docker VM on this machine
# has died thirteen times during this project, twice in the middle of an audit
# run. The first complete audit recorded `race` and `eval-remediation` as FAIL
# for that reason, and both passed on their own immediately afterwards. Calling
# that a failure is the same error as calling an unreachable target clean --
# the scan's verdict describing the harness instead of the subject.
#
# The markers are specific: each is printed by this repository's own fixture
# guard or by the Docker client, so a genuine assertion failure cannot match.
environmentFailure() {
  grep -qE 'FIXTURE NOT REACHABLE|is not reachable \(|Cannot connect to the Docker daemon|dial tcp .*: connect: connection refused' "$1"
}

# run NAME CLAIM COMMAND...
run() {
  local name="$1" claim="$2"; shift 2
  local log="$LOGDIR/$name.log"
  printf '  %-22s ' "$name" >&2
  local status=0
  "$@" >"$log" 2>&1 || status=$?
  # Exit 3 is this project's could-not-measure code, used by the scanner
  # itself and graded by eval-exitcode. A check that reports it has not found
  # a defect and has not cleared the target: it could not look. Rendering that
  # as FAIL turns a drifted or rate-limited LABORATORY into a red audit
  # blaming the scanner, which is the confusion the exploit runners were just
  # fixed to stop making one level down. "Not run" is the honest row, and this
  # file's own header says it is reported as loudly as failed.
  if [ "$status" -eq 3 ]; then
    printf 'not run (could not measure)\n' >&2
    SKIPPED=$((SKIPPED+1))
    emit "| \`$name\` | _not run_ | $claim — **the check could not measure; full log: \`$log\`** |"
    echo "--- $name could not measure, last 15 lines (full log: $log) ---" >&2
    tail -15 "$log" >&2
    return 0
  fi
  if [ "$status" -eq 0 ]; then
    # A check whose tests ALL skipped exits 0 and reported "pass".
    #
    # Go prints "ok" for a package where every test called t.Skip, so a check
    # that could not look was recorded here as one that looked and found
    # nothing -- and the summary line said "all checks ran and passed" while
    # eval-exploit-firebase had run six tests and skipped every one of them on
    # an exhausted Firestore quota.
    #
    # This file's own header says "Did not run is reported as loudly as
    # failed", and the report repeats it: a row marked not run is not a pass.
    # That rule was applied to preconditions this script knows about -- Docker
    # down, offline requested -- and not to a suite that skips itself at
    # runtime. The gate was overstating its own coverage, which is the exact
    # failure the scanner refuses to make about a target.
    if grep -q -- '--- SKIP' "$log" && ! grep -q -- '--- PASS' "$log"; then
      local n; n=$(grep -c -- '--- SKIP' "$log")
      printf 'not run (%s test(s) skipped, none ran)\n' "$n" >&2
      SKIPPED=$((SKIPPED+1))
      emit "| \`$name\` | _not run_ | $claim — **every test skipped ($n), so this check looked at nothing** |"
      return 0
    fi
    printf 'pass\n' >&2
    PASSED=$((PASSED+1))
    emit "| \`$name\` | **pass** | $claim |"
  elif environmentFailure "$log"; then
    # The VM has died fifteen times during this project, and it dies under
    # cumulative load -- so it is the LAST fixture check that keeps being lost,
    # five audits running. Losing a check to that is not information about the
    # scanner, so restart the fixtures and give it exactly one more go.
    #
    # One retry, and only after an ENVIRONMENT failure. A check that fails on
    # its merits is never re-run: retrying a real failure until it passes is
    # how a flaky suite becomes a green one that means nothing.
    printf 'environment died, restarting fixtures and retrying once ... ' >&2
    RETRIED=$((RETRIED+1))
    # `make fixtures-up` restarts CONTAINERS. When the daemon itself is gone --
    # which is what actually happens here -- it cannot help, and the first
    # version of this retry failed for that reason. Recovering the daemon is
    # environment-specific, so it is configuration rather than something this
    # script pretends to know:
    #
    #   UNRULY_DOCKER_RESTART='colima stop -p lab; colima start -p lab'
    #
    # Unset means no restart is attempted, which is correct for CI, where a
    # dead daemon is a real failure of the runner rather than local flakiness.
    if ! docker ps >/dev/null 2>&1 && [ -n "${UNRULY_DOCKER_RESTART:-}" ]; then
      printf 'daemon down, running UNRULY_DOCKER_RESTART ... ' >&2
      eval "$UNRULY_DOCKER_RESTART" >"$LOGDIR/$name.docker-restart.log" 2>&1
    fi
    ( make fixtures-up && make fixtures-check ) >"$LOGDIR/$name.retry-setup.log" 2>&1
    if "$@" >"$log.retry" 2>&1; then
      printf 'pass (on retry)\n' >&2
      PASSED=$((PASSED+1))
      emit "| \`$name\` | **pass** | $claim — _passed on retry after the fixtures were restarted_ |"
    elif environmentFailure "$log.retry"; then
      printf 'still not run\n' >&2
      SKIPPED=$((SKIPPED+1))
      emit "| \`$name\` | _not run_ | $claim — **fixture unreachable twice, including after a restart** |"
    else
      printf 'FAIL\n' >&2
      FAILED=$((FAILED+1))
      emit "| \`$name\` | **FAIL** | $claim — failed on retry; full log: \`$log.retry\` |"
      echo "--- $name failed on retry, last 15 lines ---" >&2
      tail -15 "$log.retry" >&2
    fi
  else
    printf 'FAIL\n' >&2
    FAILED=$((FAILED+1))
    emit "| \`$name\` | **FAIL** | $claim — full log: \`$log\` |"
    echo "--- $name failed, last 15 lines (full log: $log) ---" >&2
    tail -15 "$log" >&2
  fi
}

# liveChecks resets the lab, runs the checks that need it, and resets again.
#
# The reset used to be two bare calls whose status was thrown away. A reset
# that fails leaves the lab holding whatever the last run wrote, and every
# check below then grades against data nobody chose -- reporting FAIL, which
# reads as a regression in the scanner rather than a laboratory that could not
# be returned to its seed state. Same confusion the exploit runners were fixed
# to stop making; the fix there was to say "could not measure" instead.
#
# The reset AFTER matters differently: those checks already ran and their
# results stand, but the lab is left dirty and the NEXT run inherits it. That
# is reported rather than skipped, because there is nothing here left to skip.
liveChecks() {
  if ! make lab-reset >"$LOGDIR/lab-reset.log" 2>&1; then
    local i=0
    for t in $LIVE_CHECKS; do
      skip "$t" "${LIVE_CLAIMS[$i]}" \
        "the lab could not be returned to its seed state, so these would grade against unknown data"
      i=$((i+1))
    done
    echo "--- lab-reset failed, last 15 lines ---" >&2
    tail -15 "$LOGDIR/lab-reset.log" >&2
    return 0
  fi
  local i=0
  for t in $LIVE_CHECKS; do run "$t" "${LIVE_CLAIMS[$i]}" make "$t"; i=$((i+1)); done
  if ! make lab-reset >>"$LOGDIR/lab-reset.log" 2>&1; then
    printf '  %-22s %s\n' "lab-reset" "FAILED AFTER THE RUN -- the lab is not at its seed state" >&2
    emit "| \`lab-reset\` | **FAIL** | the lab is returned to its seed state after the live checks — **it was not, so the next run starts from whatever this one wrote**; full log: \`$LOGDIR/lab-reset.log\` |"
    FAILED=$((FAILED+1))
  fi
}

# skip NAME CLAIM REASON
skip() {
  printf '  %-22s not run (%s)\n' "$1" "$3" >&2
  SKIPPED=$((SKIPPED+1))
  emit "| \`$1\` | _not run_ | $2 — **$3** |"
}

echo "unruly audit" >&2
echo >&2

# ---- environment, so a later run can tell drift from disagreement ----------
GO_VERSION="$(go version 2>/dev/null || echo 'go: not installed')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="clean"
[ -n "$(git status --porcelain 2>/dev/null)" ] && GIT_DIRTY="MODIFIED (results describe uncommitted code)"
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'unavailable')"
# The PocketBase release the fixtures pin. Recorded for the same reason the
# image digests below are: every measured claim in
# docs/pocketbase-ground-truth.md is version-specific, and PocketBase has
# changed the users.createRule default between releases. A fixture that
# silently upgraded would invalidate the truth table while every check stayed
# green.
PB_VERSION="$(grep -oE '^VERSION="\$\{PB_VERSION:-[0-9.]+' fixtures/pocketbase/setup.sh | grep -oE '[0-9.]+$' || echo 'unknown')"
# Image tags are pinned in the compose files; record them rather than trusting
# that "latest" meant the same thing on both runs.
IMAGES="$(grep -rhoE 'image: [^ ]+' fixtures/*/docker-compose.yml 2>/dev/null | sort -u | sed 's/image: //' | tr '\n' ' ')"

HAVE_DOCKER=0
if [ "$DOCKER_VERSION" != "unavailable" ]; then HAVE_DOCKER=1; fi

HAVE_LAB=0
# The live-target section of the audit is not part of the public tree.
#
# It ran the scanner against a real application the author owns, using
# credentials from .secrets/, and its value was reproducing findings on a
# system whose ground truth was established by hand. Neither the credentials
# nor the target ship here, so the block is removed rather than left to fail
# on a machine that has neither. Everything else in this script runs offline
# against the fixtures and the corpus.

# ---- offline: no Docker, no credentials, runnable by a fork ---------------
echo "offline (no Docker, no credentials)" >&2
run build      "the tree compiles" "${OFFLINE_ENV[@]}"                                   go build ./...
run vet        "no vet diagnostics" "${OFFLINE_ENV[@]}"                                  go vet ./...
run lint       "gofmt-clean; checks without rewriting" "${OFFLINE_ENV[@]}"               make lint-check
run unit       "every package's tests pass" "${OFFLINE_ENV[@]}"                          go test ./... -count=1
run race       "no data races under the detector" "${OFFLINE_ENV[@]}"                    make race
run mutation   "each decision the scanner makes is checked by a test; a mutation that survives is a claim nothing verifies" "${OFFLINE_ENV[@]}" python3 scripts/mutate.py
run coverage   "every finding id has an emit site the OFFLINE suite executes" "${OFFLINE_ENV[@]}" make coverage-offline
run eval-neon  "the Neon backend agrees with its answer key: the escalation is reported, the three protected tables are not, and a key that parses to nothing fails loudly" "${OFFLINE_ENV[@]}" make eval-neon
run release    "the cross-compiled binaries build and the Linux ones are statically linked" "${OFFLINE_ENV[@]}" make release-check

# ---- pocketbase: needs the pinned binary; no Docker, no credentials -------
#
# Its own phase, NOT part of the fixtures block above. PocketBase's fixtures
# are two native binaries on 8090/8091, not a compose stack, so gating them on
# HAVE_DOCKER would make them skip for a reason that has nothing to do with
# them -- and a check that skips with a false stated cause is worse than one
# that skips honestly.
#
# This existed as `make eval-pocketbase` and was never in the audit, so the
# entire second backend -- the detector, the collection stage, the escalation
# probe, and the three status-code traps that took two retractions to get
# right -- was graded by a target nobody ran. "make audit green" said nothing
# about it.
# Ports the audit provisions on. NOT the documented 8090/8091 defaults: those
# are what an operator reads about and reaches for by hand, and they are also
# what everything else on a developer's machine reaches for. Measured here --
# an ssh port-forward held 8090, setup.sh could not bind, and before the
# readiness probe was fixed the whole graded suite ran against it.
#
# Picking an unlikely pair means the gate does not depend on the operator's
# machine being quiet. setup.sh still refuses if even these are taken, and
# says what holds them.
# Ports the audit provisions on: whatever the operating system says is free.
#
# Guessing does not work. 8090/8091 are the documented defaults and an ssh
# port-forward held 8090 on this machine; moving to 8790/8791 on the reasoning
# that they were "unlikely to be in use" collided with a Python process on the
# very next run. Two guesses, two collisions -- and a rarer collision is a
# worse one, because it is the kind nobody recognises when it finally happens.
#
# bind(port 0) asks the kernel for one nothing holds. The socket never
# connects, so there is no TIME_WAIT and the port is usable immediately. A
# window remains between this probe and PocketBase's bind, and that is what
# setup.sh's lsof check covers: ask for a free port, and refuse loudly if
# something takes it anyway.
#
# setup.sh keeps 8090/8091 as its defaults on purpose. An operator following
# docs/pocketbase-ground-truth.md by hand expects the ports the doc names; a
# fixture that moved under them would be worse than one that occasionally
# collides, now that the collision says so out loud.
freeport() {
  python3 -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
PB_VULN_PORT="${PB_VULN_PORT:-$(freeport)}"
PB_HARD_PORT="${PB_HARD_PORT:-$(freeport)}"
echo >&2; echo "pocketbase (needs the pinned binary; no Docker, no credentials)" >&2
PB_CLAIM="recall and precision against a deliberately vulnerable PocketBase and a hardened one, \
including the two answers that look like findings and are not, and a cross-check that an \
independent implementation can actually retrieve what the scanner reports"
if [ "$OFFLINE_ONLY" = "1" ]; then
  skip "eval-pocketbase" "$PB_CLAIM" "--offline requested"
elif ! { PB_VULN_PORT=$PB_VULN_PORT PB_HARD_PORT=$PB_HARD_PORT fixtures/pocketbase/setup.sh --down
         PB_VULN_PORT=$PB_VULN_PORT PB_HARD_PORT=$PB_HARD_PORT fixtures/pocketbase/setup.sh; } \
       >"$LOGDIR/pocketbase-up.log" 2>&1; then
  # --down first, because this script has no trap: an interrupted run leaves
  # its instances holding the ports, and the next run would then refuse to
  # start with a true message about a stale cause. --down only kills processes
  # matching this repo's fixture paths, so it cannot touch anything else
  # listening there.
  # Downloading a pinned release needs the network the first time. Say which
  # it was rather than reporting a bare failure.
  skip "eval-pocketbase" "$PB_CLAIM" "the PocketBase fixtures could not be provisioned"
else
  run eval-pocketbase "$PB_CLAIM" env PB_VULN_PORT="$PB_VULN_PORT" PB_HARD_PORT="$PB_HARD_PORT" make eval-pocketbase
  PB_VULN_PORT=$PB_VULN_PORT PB_HARD_PORT=$PB_HARD_PORT fixtures/pocketbase/setup.sh --down >>"$LOGDIR/pocketbase-up.log" 2>&1 || true
fi

# ---- fixtures: needs Docker, still no credentials -------------------------
echo >&2; echo "fixtures (needs Docker; no credentials, no cloud account)" >&2
FIXTURE_CHECKS="eval-fixtures eval-exitcode eval-notsupabase eval-edge eval-redaction eval-templates eval-determinism eval-coverage eval-exploit-local eval-remediation"
declare -a FIXTURE_CLAIMS=(
  "recall and precision against a vulnerable fixture and a hardened one"
  "the exit-code contract CI depends on: 0 clean, 2 findings, 3 could-not-measure"
  "near-silence against hosts that are not Supabase"
  "Edge Function classification against the real edge-runtime"
  "-redact removes sampled data and keeps the finding usable"
  "the worked examples inside every -fix actually execute"
  "repeated identical scans produce byte-identical reports"
  "every finding's emit site is executed with the fixtures up"
  "an independent implementation exploits the local fixture, and the scan agrees with what it could and could not do"
  "applying the tool's own -fix output closes the findings it reported"
)
if [ "$OFFLINE_ONLY" = "1" ]; then
  i=0
  for t in $FIXTURE_CHECKS; do
    skip "$t" "${FIXTURE_CLAIMS[$i]}" "--offline requested"; i=$((i+1))
  done
elif [ "$HAVE_DOCKER" = "0" ]; then
  i=0
  for t in $FIXTURE_CHECKS; do
    skip "$t" "${FIXTURE_CLAIMS[$i]}" "Docker unavailable"; i=$((i+1))
  done
else
  make fixtures-up >"$LOGDIR/fixtures-up.log" 2>&1
  if make fixtures-check >>"$LOGDIR/fixtures-up.log" 2>&1; then
    make fixtures-reset >>"$LOGDIR/fixtures-up.log" 2>&1
    i=0
    for t in $FIXTURE_CHECKS; do
      run "$t" "${FIXTURE_CLAIMS[$i]}" make "$t"; i=$((i+1))
    done
  else
    i=0
    for t in $FIXTURE_CHECKS; do
      skip "$t" "${FIXTURE_CLAIMS[$i]}" "fixtures did not come up"; i=$((i+1))
    done
  fi
fi

# ---- live: needs the exploit lab's credentials ---------------------------
echo >&2; echo "live (needs the exploit lab: a real Supabase project and a deployed Worker)" >&2
LIVE_CHECKS="exploitcheck eval-exploitability eval-graphql eval-noresidue eval-exploit-firebase"
declare -a LIVE_CLAIMS=(
  "every vulnerability in the answer key is actually exploitable, with retrieved data as proof"
  "cross-check: everything the scanner reports at high or above is exploitable, and everything exploitable is reported"
  "pg_graphql is not more permissive than PostgREST, which is why the bypass finding has never fired"
  "-no-residue writes NOTHING to a real project: rows and objects counted with the service key before and after, while write exposure is still reported"
  "an independent implementation reads the Firebase lab, the scan agrees, and the rules that are already correct are not reported"
)
if [ "$OFFLINE_ONLY" = "1" ]; then
  i=0; for t in $LIVE_CHECKS; do skip "$t" "${LIVE_CLAIMS[$i]}" "--offline requested"; i=$((i+1)); done
elif [ "$HAVE_LAB" = "0" ]; then
  i=0; for t in $LIVE_CHECKS; do
    skip "$t" "${LIVE_CLAIMS[$i]}" "lab credentials absent (.secrets/ is gitignored)"; i=$((i+1))
  done
else
  liveChecks
fi

# ---- neon: needs the Neon lab's credentials -------------------------------
#
# Its own phase rather than part of the live block above, for the reason
# PocketBase has one: that block is gated on the SUPABASE exploit lab and wraps
# itself in `make lab-reset`, neither of which means anything here. Folding
# this in would make a Neon result depend on a Supabase project being reachable.
echo >&2; echo "neon (needs the Neon lab: a project with the Data API enabled)" >&2
NEON_CLAIM="an independent implementation of the Neon Auth sequence reads rows the scan reports, \
and both agree on the tables that must stay silent -- including the one the vendor console \
falsely flags"
if [ "$OFFLINE_ONLY" = "1" ]; then
  skip "eval-neon-live" "$NEON_CLAIM" "--offline requested"
elif [ ! -f .secrets/neon.env ]; then
  skip "eval-neon-live" "$NEON_CLAIM" "Neon lab credentials absent (.secrets/ is gitignored)"
else
  run eval-neon-live "$NEON_CLAIM" make eval-neon-live
  run eval-neon-binary "the BINARY, run as an operator would run it, reports the escalation and exits 2 -- the check that four reachability defects got past, because every other Neon eval grades a stage rather than the program" make eval-neon-binary
  # Both evals sign in, and Neon Auth keeps a session row for each. Nobody
  # removed them until somebody counted 102. The Supabase block above brackets
  # itself with lab-reset for the same reason; this is the Neon equivalent,
  # after rather than before because a prune mid-run would invalidate the
  # tokens the evals are holding.
  if ! make neon-prune >"$LOGDIR/neon-prune.log" 2>&1; then
    printf '  %-22s %s\n' "neon-prune" "FAILED -- probe sessions are still in the lab" >&2
    emit "| \`neon-prune\` | **FAIL** | the probe sessions the live evals create are removed afterwards — **they were not, so they accumulate**; full log: \`$LOGDIR/neon-prune.log\` |"
    FAILED=$((FAILED+1))
  fi
fi

# ---- report --------------------------------------------------------------
VERDICT="all checks ran and passed"
CODE=0
if [ "$FAILED" -gt 0 ]; then
  VERDICT="$FAILED check(s) FAILED"
  CODE=1
elif [ "$SKIPPED" -gt 0 ]; then
  VERDICT="everything that ran passed, but $SKIPPED check(s) COULD NOT RUN — this is not a clean bill of health"
  CODE=3
fi

REPORT="# unruly audit

commit: \`$GIT_COMMIT\` ($GIT_DIRTY)
go: \`$GO_VERSION\`
docker: \`$DOCKER_VERSION\`
pocketbase: \`$PB_VERSION\`
fixture images: \`$IMAGES\`

**$PASSED passed, $FAILED failed, $SKIPPED not run.** $VERDICT.

$( [ "$RETRIED" -gt 0 ] && echo "$RETRIED check(s) hit an environment failure and were retried once after restarting the fixtures. That is recorded rather than hidden: an audit that quietly retries until it is green is not an audit." )

| check | result | what it establishes |
|---|---|---|
$ROWS
## Reading this report

A row marked _not run_ is not a pass. The distinction is the whole point of
this project: absence of a finding is only evidence when the scan could see.
The same rule is applied here to the scan's own test suite.

To reproduce, see \`docs/auditing.md\`, which lists what each check proves and
what would falsify it.
"

# The README states how many checks this gate runs, and that number drifts:
# it said 23 while this script ran 24. Nothing guarded it -- the Go count
# guards read the README against docs/ and the fixtures, never against
# audit.sh.
#
# Checked HERE rather than by a test parsing this file, because the names live
# in `run` lines, in FIXTURE_CHECKS and in `skip` calls inside branches, so an
# extractor would have to follow the control flow and would go blind the next
# time a phase is added -- which is exactly what just happened. This script
# already knows the number it ran, so there is no pattern to stop matching.
TOTAL=$((PASSED+FAILED+SKIPPED))
CLAIMED="$(grep -oE 'the whole gate: [0-9]+ checks' README.md | grep -oE '[0-9]+' || echo '')"
if [ -n "$CLAIMED" ] && [ "$CLAIMED" != "$TOTAL" ]; then
  echo >&2
  echo "the README says this gate runs $CLAIMED checks; it ran $TOTAL." >&2
  echo "One of the two is wrong, and a reader trusting the README cannot tell which." >&2
  CODE=1
fi

if [ -n "$OUT" ]; then
  printf '%s' "$REPORT" > "$OUT"
  echo >&2; echo "report written to $OUT" >&2
fi
printf '%s' "$REPORT"

echo >&2
echo "$PASSED passed, $FAILED failed, $SKIPPED not run (exit $CODE)" >&2
exit $CODE
