#!/usr/bin/env python3
"""Emit 01_schema.sql for corpus project 09: 120 relations in three name families.

Why a generator and not 120 hand-written CREATE TABLEs: the point of this
target is a DENOMINATOR. Recall is only measurable as a percentage if the
total is exact and stays exact, and 120 hand-maintained tables drift the first
time somebody edits one. The generator is the source of truth for the counts
the answer key asserts, and the SQL it writes is committed so the target is
reproducible without running Python.

Determinism is not decorative here either. The unguessable names are derived
from md5("unruly-bench-09:<n>"), not from random.random(), so the same file
comes out on every machine and a scan run last month is comparable with one
run today. Regenerate with:

    python3 benchmark/corpus/09-huge-schema/schema/gen.py

and diff the result; a non-empty diff means somebody changed the rules.

THE THREE FAMILIES

  guessable   (20)  conventional English nouns any wordlist holds
  generic     (20)  t1..t12, data, payload, tmp_*, staging_*  -- contentless
  unguessable (80)  md5-derived hex names plus invented domain words

Recall on the unguessable family is the measurement. A scanner can score 40/120
by owning a wordlist; it cannot score above that without enumerating for real.

EXPOSURE IS DELIBERATELY ANTI-CORRELATED WITH GUESSABILITY

If every easy name were also exposed, a wordlist would be a fine enumerator and
the target would measure nothing. So most of the guessable family is protected
(reporting one of those as exposed is a false positive) while half the
unguessable family is anonymously readable, and the credential- and PII-shaped
columns live in the unguessable half.

THREE EXPOSURE STATES, TWO OF WHICH LOOK THE SAME FROM A DISTANCE

  open         GRANT SELECT to anon; rows come back
  norights     no GRANT at all; PostgREST answers 401 42501 and NAMES the table
  rls_silent   GRANT SELECT, then ENABLE ROW LEVEL SECURITY and write no
               policy; the request succeeds and returns [] forever

`rls_silent` is the one that punishes a scanner that equates "HTTP 200" with
"exposed". It is also the one that punishes a scanner that equates "empty
array" with "table does not exist".
"""
from __future__ import annotations

import hashlib
import pathlib

HERE = pathlib.Path(__file__).parent

# --------------------------------------------------------------------------
# Name families.
# --------------------------------------------------------------------------

GUESSABLE = [
    "users", "profiles", "orders", "sessions", "payments", "messages",
    "accounts", "customers", "products", "invoices", "subscriptions",
    "notifications", "comments", "posts", "files", "teams", "projects",
    "tickets", "addresses", "events",
]

GENERIC = (
    [f"t{n}" for n in range(1, 13)]
    + ["data", "payload", "tmp_1", "tmp_2", "staging_a", "staging_b", "misc", "tbl"]
)

# Invented for this fixture. Real English words, but not words anybody puts in
# a table-name wordlist, which is the interesting middle ground between
# "orders" and "tbl_9f2ab41c".
COINED = [
    "sporule_ledger", "quenchless_intake", "halidom_registry", "farrago_queue",
    "welkin_vault", "pettifog_archive", "tarnation_shard", "obelus_index",
    "susurrus_cache", "gallimaufry_store",
]


def digest(n: int, width: int) -> str:
    """Stable hex slice. Seeded by a literal string so the names never move."""
    return hashlib.md5(f"unruly-bench-09:{n}".encode()).hexdigest()[:width]


def unguessable_names() -> list[str]:
    names = [f"tbl_{digest(i, 8)}" for i in range(30)]
    names += [f"kv_{digest(100 + i, 6)}" for i in range(25)]
    names += COINED
    names += [f"zx{digest(200 + i, 10)}" for i in range(15)]
    return names


# --------------------------------------------------------------------------
# Column shapes. The "kind" decides what a scanner that reads CONTENT should
# be able to say about the relation, independently of whether it found it.
# --------------------------------------------------------------------------

SHAPES = {
    "plain": [
        "id bigserial PRIMARY KEY",
        "label text NOT NULL",
        "value text",
        "created_at timestamptz NOT NULL DEFAULT now()",
    ],
    "credential": [
        "id bigserial PRIMARY KEY",
        "email text NOT NULL",
        "password_hash text NOT NULL",
        "api_key text NOT NULL",
        "totp_secret text",
    ],
    "pii": [
        "id bigserial PRIMARY KEY",
        "full_name text NOT NULL",
        "email text NOT NULL",
        "phone_number text",
        "national_id text",
    ],
    "card": [
        "id bigserial PRIMARY KEY",
        "card_number text NOT NULL",
        "card_expiry text",
        "iban text",
        "billing_email text",
    ],
}


def seed_sql(table: str, kind: str, rows: int) -> str:
    q = f'public."{table}"'
    if kind == "plain":
        return (
            f"INSERT INTO {q} (label, value)\n"
            f"SELECT '{table}-' || i, 'value-' || i FROM generate_series(1, {rows}) i;"
        )
    if kind == "credential":
        # Hashes are bcrypt-SHAPED and hash nothing; the api_key prefix is the
        # Stripe test prefix. Nothing here authenticates to anything.
        return (
            f"INSERT INTO {q} (email, password_hash, api_key, totp_secret)\n"
            f"SELECT 'user' || i || '@example.invalid',\n"
            f"       '$2b$12$' || lpad(i::text, 53, '0'),\n"
            f"       'sk_test_' || md5('{table}' || i),\n"
            f"       'JBSWY3DPEHPK3PX' || i\n"
            f"FROM generate_series(1, {rows}) i;"
        )
    if kind == "pii":
        return (
            f"INSERT INTO {q} (full_name, email, phone_number, national_id)\n"
            f"SELECT (ARRAY['Dana Whitfield','Marcus Oyelaran','Priya Raghunathan',"
            f"'Tomas Berg','Elena Marchetti'])[1 + (i %% 5)] || ' ' || i,\n"
            f"       'person' || i || '@example.invalid',\n"
            f"       '+1-555-02' || lpad(i::text, 2, '0'),\n"
            f"       '000-00-' || lpad(i::text, 4, '0')\n"
            f"FROM generate_series(1, {rows}) i;"
        ).replace("%%", "%")
    if kind == "card":
        # The published network test PANs and the ECBS test IBANs.
        return (
            f"INSERT INTO {q} (card_number, card_expiry, iban, billing_email)\n"
            f"SELECT (ARRAY['4111111111111111','5555555555554444','378282246310005',"
            f"'6011111111111117'])[1 + (i %% 4)],\n"
            f"       '0' || (1 + (i %% 9)) || '/29',\n"
            f"       (ARRAY['DE89370400440532013000','GB82WEST12345698765432',"
            f"'NL91ABNA0417164300'])[1 + (i %% 3)],\n"
            f"       'billing' || i || '@example.invalid'\n"
            f"FROM generate_series(1, {rows}) i;"
        ).replace("%%", "%")
    raise ValueError(kind)


# --------------------------------------------------------------------------
# The plan: one row per relation, decided by fixed rules rather than by hand.
# --------------------------------------------------------------------------

def plan() -> list[dict]:
    out: list[dict] = []

    # Guessable: 20 names, only 6 open. A scanner that reports the other 14 as
    # exposed because they are "users"-shaped is producing false positives, and
    # 14 of them.
    open_guessable = {"users", "posts", "comments", "events", "products", "files"}
    rls_guessable = {"orders", "sessions", "payments", "messages"}
    for i, name in enumerate(GUESSABLE):
        if name in open_guessable:
            exposure = "open"
        elif name in rls_guessable:
            exposure = "rls_silent"
        else:
            exposure = "norights"
        out.append(dict(name=name, family="guessable", exposure=exposure,
                        kind="plain", rows=4 + (i % 5)))

    # Generic: half open, and their content is genuinely boring. They exist so
    # that "found 20 relations" cannot be reported as 20 findings.
    for i, name in enumerate(GENERIC):
        exposure = "open" if i % 2 == 0 else ("rls_silent" if i % 4 == 1 else "norights")
        out.append(dict(name=name, family="generic", exposure=exposure,
                        kind="plain", rows=2 + (i % 4)))

    # Unguessable: 40 of 80 open, and the interesting content lives here.
    ung = unguessable_names()
    for i, name in enumerate(ung):
        exposure = "open" if i % 2 == 0 else ("rls_silent" if i % 4 == 1 else "norights")
        # Every 10th open relation carries credentials, cards or PII. i%20==0
        # gives 4 credential tables; the offsets give 4 card and 4 PII tables,
        # all of them in the open half (i even).
        if i % 20 == 0:
            kind = "credential"
        elif i % 20 == 6:
            kind = "card"
        elif i % 20 == 12:
            kind = "pii"
        else:
            kind = "plain"
        out.append(dict(name=name, family="unguessable", exposure=exposure,
                        kind=kind, rows=3 + (i % 7)))
    return out


BANNER = '''-- Project 09: 120 relations, three name families, OpenAPI turned off.
--
-- GENERATED BY schema/gen.py. Do not edit by hand; edit the generator and
-- regenerate, or the counts the answer key asserts stop meaning anything.
--
-- The one property this target measures: discovery RECALL as a percentage.
-- Twenty of these names are in every wordlist, twenty are contentless
-- placeholders, and eighty cannot be guessed at all. A scanner that enumerates
-- by dictionary has a hard ceiling here and the ceiling is visible in the
-- score.
--
-- Exposure is anti-correlated with guessability on purpose: 14 of the 20
-- guessable names are protected, and half the unguessable ones are open and
-- hold credential-, card- and PII-shaped columns.
'''


def render() -> str:
    rows = plan()
    parts = [BANNER, "", "GRANT USAGE ON SCHEMA public TO anon, authenticated;", ""]
    grants, rls = [], []
    for spec in rows:
        name, kind = spec["name"], spec["kind"]
        cols = ",\n  ".join(SHAPES[kind])
        parts.append(
            f'-- {spec["family"]} / {spec["exposure"]} / {kind} / {spec["rows"]} rows\n'
            f'CREATE TABLE public."{name}" (\n  {cols}\n);\n'
            f'{seed_sql(name, kind, spec["rows"])}'
        )
        if spec["exposure"] == "open":
            grants.append(f'GRANT SELECT ON public."{name}" TO anon, authenticated;')
        elif spec["exposure"] == "rls_silent":
            grants.append(f'GRANT SELECT ON public."{name}" TO anon, authenticated;')
            rls.append(f'ALTER TABLE public."{name}" ENABLE ROW LEVEL SECURITY;')
        # norights: nothing. The absence is the configuration.

    parts.append("\n-- ---------------------------------------------------------------------------\n"
                 "-- Privileges. SELECT only, everywhere: this project measures DISCOVERY, and\n"
                 "-- write verbs are project 01's axis. Keeping writes out means a failure here\n"
                 "-- can only be a failure to find or to classify.\n"
                 "-- ---------------------------------------------------------------------------")
    parts.extend(grants)
    parts.append("\n-- ---------------------------------------------------------------------------\n"
                 "-- RLS with no policy attached. These hold a SELECT grant, so the request\n"
                 "-- succeeds; the policy set is empty, so the result is [] forever. They are\n"
                 "-- NOT exposed, and they are NOT absent.\n"
                 "-- ---------------------------------------------------------------------------")
    parts.extend(rls)

    # A handful of writable relations would muddy the measurement; instead
    # state plainly in the file that there are none.
    parts.append("\n-- No INSERT/UPDATE/DELETE is granted anywhere in this project.")
    return "\n".join(parts) + "\n"


def main() -> None:
    rows = plan()
    (HERE / "01_schema.sql").write_text(render(), encoding="utf-8")
    by_family: dict[str, int] = {}
    open_by_family: dict[str, int] = {}
    for r in rows:
        by_family[r["family"]] = by_family.get(r["family"], 0) + 1
        if r["exposure"] == "open":
            open_by_family[r["family"]] = open_by_family.get(r["family"], 0) + 1
    print(f"relations: {len(rows)}")
    for fam in ("guessable", "generic", "unguessable"):
        print(f"  {fam:12s} {by_family[fam]:3d}  open {open_by_family.get(fam, 0):3d}")
    print(f"  total open        {sum(open_by_family.values())}")
    print(f"  total rows        {sum(r['rows'] for r in rows)}")
    for kind in ("credential", "card", "pii"):
        hits = [r["name"] for r in rows if r["kind"] == kind]
        print(f"  {kind:12s} {len(hits)}  {hits}")


if __name__ == "__main__":
    main()
