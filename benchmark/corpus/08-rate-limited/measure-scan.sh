#!/usr/bin/env bash
# Probe every relation name once, as fast as the shell can, and print which
# ones actually answered. Not run by verify.sh; this is the tool that produced
# the two transcripts in README.md.
#
# The output is a LOWER BOUND on the relation list, and running it twice shows
# that the bound moves. That is the whole point of this project: on a target
# like this, "the relations found" is not a property of the target, it is a
# property of the run.
#
#   ./measure-scan.sh          probe all 30 in parallel
#   ./measure-scan.sh 0.25     pace them 250ms apart instead
set -u
PACE="${1:-0}"
BASE="http://127.0.0.1:54471/rest/v1"

NAMES=(
  customers user_credentials payment_cards audit_events support_tickets
  feature_flags api_tokens employee_records webhook_secrets session_store
  inventory shipments warehouses suppliers categories reviews coupons refunds
  taxes currencies regions locales templates campaigns segments exports
  imports jobs queues metrics
)

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

probe() {
  local n="$1"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$n?select=*&limit=1")"
  echo "$code $n" >> "$TMP/out"
}

for n in "${NAMES[@]}"; do
  if [[ "$PACE" == "0" ]]; then
    probe "$n" &
  else
    probe "$n"
    sleep "$PACE"
  fi
done
wait

answered=$(grep -cv '^429' "$TMP/out")
refused=$(grep -c '^429' "$TMP/out")
echo "probed ${#NAMES[@]}  answered $answered  refused-429 $refused  (pace=${PACE}s)"
echo "  resolved:   $(awk '$1!=429{printf "%s ", $2}' "$TMP/out" | tr ' ' '\n' | sort | tr '\n' ' ')"
echo "  unresolved: $(awk '$1==429{printf "%s ", $2}' "$TMP/out" | tr ' ' '\n' | sort | tr '\n' ' ')"
