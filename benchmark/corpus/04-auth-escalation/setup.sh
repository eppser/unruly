#!/usr/bin/env bash
# Reset the auth store, then REPLAY the end-to-end escalation and fail loudly
# if it stops working.
#
# Two jobs, both of which have to happen outside answer-key.yaml.
#
# 1. Reset. This project's checks CREATE ACCOUNTS -- that is the finding. A
#    second run of the same answer key would get 422 user_already_exists for
#    the signup that returned 200 the first time, and the anonymous sign-in
#    check leaves a fresh row behind every single run. So auth.users is
#    truncated before the checks and the answer key can then assert, as an
#    ordinary single-statement SELECT, that the project starts with zero
#    accounts and that a stranger can still make one.
#
# 2. Replay the escalation. lib/check.py cannot chain a token between two
#    requests: expect.checks binds either the anon key or the one authenticated
#    key from the environment, and there is no way to say "take access_token
#    from the previous response and send it as Authorization on the next one".
#    That is the ONE claim this whole project exists to make, so it is
#    performed here as three real HTTP requests and this script exits nonzero
#    if it does not hold -- which verify.sh reports as a failed project. The
#    same transcript, with its outputs, is pasted into the README, and the
#    claim is recorded under expect.unverified so that nobody reading the
#    answer key alone believes lib/check.py measured it.
set -uo pipefail
cd "$(dirname "$0")"

GATEWAY=http://127.0.0.1:54431
ESCALATION_EMAIL="bench04-escalation-proof@example.invalid"
ESCALATION_PASSWORD="hunter"   # six characters, which is this project's floor

psql() { docker compose exec -T db psql -U postgres -d fixture -tAc "$1" >/dev/null 2>&1; }

psql "TRUNCATE auth.users CASCADE"

# --- 1. a stranger creates an account -------------------------------------
signup=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ESCALATION_EMAIL\",\"password\":\"$ESCALATION_PASSWORD\"}" \
  "$GATEWAY/auth/v1/signup")

token=$(printf '%s' "$signup" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
if [[ -z "$token" ]]; then
  echo "setup.sh: signup returned no access_token: ${signup:0:300}" >&2
  exit 1
fi

# --- 2. the token it was handed carries role=authenticated ----------------
role=$(printf '%s' "$token" | python3 -c "
import base64, json, sys
p = sys.stdin.read().strip().split('.')[1]
p += '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p)).get('role', ''))
")
if [[ "$role" != "authenticated" ]]; then
  echo "setup.sh: signup token claims role=$role, expected authenticated" >&2
  exit 1
fi

# --- 3. that token reads a table anon cannot see --------------------------
salaries=$(curl -s -H "apikey: $token" -H "Authorization: Bearer $token" \
  "$GATEWAY/rest/v1/employee_salaries?select=full_name,annual_salary_cents")
if [[ "$salaries" != *"Priya Raghunathan"* ]]; then
  echo "setup.sh: the freshly created account did NOT read employee_salaries: ${salaries:0:300}" >&2
  exit 1
fi

# ...and gains nothing on the correctly scoped table.
payslips=$(curl -s -H "apikey: $token" -H "Authorization: Bearer $token" \
  "$GATEWAY/rest/v1/my_payslips?select=period")
if [[ "$payslips" != "[]" ]]; then
  echo "setup.sh: my_payslips is meant to gain a fresh account nothing, got: ${payslips:0:300}" >&2
  exit 1
fi

# Leave the auth store empty, so the answer key's "zero accounts exist" claim
# describes the state a scanner actually meets.
psql "TRUNCATE auth.users CASCADE"
