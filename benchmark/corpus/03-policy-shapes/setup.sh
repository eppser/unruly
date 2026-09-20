#!/usr/bin/env bash
# Put the database into a DETERMINISTIC starting state, then perform the one
# anonymous write whose residue the answer key asserts with a plain SELECT.
#
# Two things make this hook necessary rather than decorative.
#
# 1. Verification is destructive. `policy_delete_only` is verified by having a
#    stranger empty it over HTTP, and `policy_insert_only` is verified by
#    having a stranger append to it. Both leave the table at a different row
#    count than the DDL seeded, so a second run of verify.sh would fail on the
#    row-count claim of a project that is behaving exactly as documented.
#
# 2. lib/check.py reads only the FIRST line of psql's output, which is the
#    command tag for anything other than a bare SELECT. So an answer-key psql
#    claim cannot say "SET ROLE anon; INSERT ...; SELECT ..." -- it would
#    compare the expected value against the string "SET". Anything requiring
#    more than one statement has to happen here, and be ASSERTED there with a
#    single SELECT.
#
# The POST below is a real anonymous HTTP request against the real gateway,
# carrying the anon key and nothing else. What it leaves in the table is what
# answer-key.yaml checks.
set -uo pipefail
cd "$(dirname "$0")"

REST=http://127.0.0.1:54421
EVIDENCE_ID=990001

psql() { docker compose exec -T db psql -U postgres -d fixture -tAc "$1" >/dev/null; }

# --- reset write residue from any previous run ------------------------------
psql "DELETE FROM public.policy_insert_only WHERE submitted_by IS NULL OR submitted_by NOT LIKE 'seed%'"
psql "DELETE FROM public.policy_for_all_true WHERE email LIKE '%unruly%' OR full_name LIKE 'unruly%' OR email IN ('post@example.invalid','marker@example.invalid')"
psql "DELETE FROM public.policy_select_true_only WHERE email IN ('post@example.invalid','marker@example.invalid')"
psql "DELETE FROM public.policy_authenticated_true WHERE full_name LIKE 'unruly%'"
psql "DELETE FROM public.policy_owner_scoped WHERE note LIKE 'unruly%'"
psql "DELETE FROM public.policy_restrictive_mix WHERE customer IN ('post@example.invalid','marker@example.invalid')"
psql "DELETE FROM public.rls_no_policy WHERE account_email IN ('post@example.invalid','marker@example.invalid')"
# policy_delete_only is emptied by its own probe, so it is rebuilt rather than
# trimmed.
psql "DELETE FROM public.policy_delete_only"
psql "INSERT INTO public.policy_delete_only (invoice_no, amount_cents) SELECT 'INV-2026-'||lpad(i::text,4,'0'), i*1000 FROM generate_series(1,6) i"

# --- the anonymous write whose residue answer-key.yaml asserts ---------------
#
# Prefer: return=minimal is PostgREST's DEFAULT for POST. It matters here: the
# same request asking for the row back (return=representation) is REFUSED with
# 42501, because RETURNING is a read and this table has no SELECT policy. The
# insert-only shape is therefore invisible to a write probe that asks for a
# representation, which is what lib/check.py's insert probe does. See README.
ANON="${UNRULY_BENCH_ANON_KEY:-}"
if [[ -z "$ANON" ]]; then
  echo "setup.sh: UNRULY_BENCH_ANON_KEY is not set; run through verify.sh" >&2
  exit 1
fi

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON" \
  -H 'Content-Type: application/json' -H 'Prefer: return=minimal' \
  -d "{\"id\":$EVIDENCE_ID,\"submitted_by\":\"anon-http-probe@example.invalid\",\"message\":\"anonymous submission over HTTP\",\"is_admin\":true}" \
  "$REST/policy_insert_only")

if [[ "$code" != "201" ]]; then
  echo "setup.sh: anonymous POST to policy_insert_only returned $code, expected 201" >&2
  exit 1
fi
