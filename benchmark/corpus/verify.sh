#!/usr/bin/env bash
# Bring a corpus project up, check its answer key against the RUNNING stack,
# and report every claim that did not hold.
#
# This script is the thing that keeps the corpus honest. An answer key is a
# hypothesis until something has gone and looked; without this, fourteen
# projects of confident YAML would measure nothing but the author's memory of
# what he meant to write.
#
#   ./verify.sh                      every project, brought up and torn down
#   ./verify.sh 01-rls-off-crud      one project
#   ./verify.sh --keep 03-...        leave the stack running afterwards
#   ./verify.sh --no-up 03-...       assume it is already up
#
# Exit status: 0 when every claim in every project held, 1 otherwise.
set -uo pipefail

CORPUS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$CORPUS/../.." && pwd)"

KEEP=0
NO_UP=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --keep)   KEEP=1 ;;
    --no-up)  NO_UP=1; KEEP=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *)        ARGS+=("$arg") ;;
  esac
done

# Tokens are MINTED, never committed. A JWT-shaped string in the tree trips
# this repository's own secret scan, and a benchmark is not a reason to keep a
# credential around. The minter is shared with fixtures/ so the corpus cannot
# drift onto a different signing secret than the stacks it talks to.
MINT="$REPO/fixtures/mint-jwt.py"
if [[ ! -f "$MINT" ]]; then
  echo "missing $MINT — the corpus signs its tokens with the same minter as fixtures/" >&2
  exit 2
fi
UNRULY_BENCH_ANON_KEY="$(python3 "$MINT" --role anon)"
UNRULY_BENCH_AUTH_KEY="$(python3 "$MINT" --role authenticated --sub 22222222-2222-2222-2222-222222222222)"
UNRULY_BENCH_AUTH_KEY_B="$(python3 "$MINT" --role authenticated --sub 33333333-3333-3333-3333-333333333333)"
UNRULY_BENCH_SERVICE_KEY="$(python3 "$MINT" --role service_role)"
export UNRULY_BENCH_ANON_KEY UNRULY_BENCH_AUTH_KEY UNRULY_BENCH_AUTH_KEY_B UNRULY_BENCH_SERVICE_KEY

# No mapfile and no `${arr[@]}` on an empty array: macOS ships bash 3.2, where
# mapfile does not exist and `set -u` treats an empty array expansion as
# unbound. Running the whole corpus failed with two lines of shell error and no
# indication that it had checked nothing -- which is exactly the silent
# false-clean this corpus is about.
PROJECTS=()
if [[ ${#ARGS[@]} -eq 0 ]]; then
  for d in "$CORPUS"/[0-9][0-9]-*; do
    [[ -d "$d" ]] && PROJECTS+=("$(basename "$d")")
  done
else
  for a in "${ARGS[@]}"; do PROJECTS+=("$a"); done
fi
if [[ ${#PROJECTS[@]} -eq 0 ]]; then
  echo "no projects found in $CORPUS" >&2
  exit 2
fi

FAILED=()
PASSED=()
SKIPPED=()

for proj in "${PROJECTS[@]}"; do
  dir="$CORPUS/${proj%/}"
  [[ -d "$dir" ]] || { echo "no such project: $proj" >&2; FAILED+=("$proj"); continue; }
  if [[ ! -f "$dir/answer-key.yaml" ]]; then
    echo "== $proj: no answer-key.yaml, skipping"; SKIPPED+=("$proj"); continue
  fi

  echo
  echo "=============================================================="
  echo "== $proj"
  echo "=============================================================="

  # A project may carry a setup hook for anything compose cannot express —
  # seeding an emulator, waiting on a migration, minting a per-project key.
  if [[ $NO_UP -eq 0 && -f "$dir/docker-compose.yml" ]]; then
    ( cd "$dir" && docker compose up -d --wait --wait-timeout 180 ) >/dev/null 2>&1 || {
      # --wait fails loudly for a stack that has no healthcheck on every
      # service; fall back and let the checks decide whether it is really up.
      ( cd "$dir" && docker compose up -d ) >/dev/null 2>&1
      sleep 10
    }
  fi
  if [[ -x "$dir/setup.sh" ]]; then
    ( cd "$dir" && ./setup.sh ) || { echo "setup.sh failed"; FAILED+=("$proj"); continue; }
  fi

  if python3 "$CORPUS/lib/check.py" "$dir"; then
    PASSED+=("$proj")
  else
    FAILED+=("$proj")
  fi

  if [[ $KEEP -eq 0 && -f "$dir/docker-compose.yml" ]]; then
    ( cd "$dir" && docker compose down -v --remove-orphans ) >/dev/null 2>&1
  fi
done

echo
echo "=============================================================="
echo "passed:  ${#PASSED[@]}  ${PASSED[*]:-}"
echo "failed:  ${#FAILED[@]}  ${FAILED[*]:-}"
[[ ${#SKIPPED[@]} -gt 0 ]] && echo "skipped: ${#SKIPPED[@]}  ${SKIPPED[*]}"
[[ ${#FAILED[@]} -eq 0 ]]
