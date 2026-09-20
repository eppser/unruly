# 03 — RLS enabled on everything, only the policy shape differs

## What this target is for

**The one property it measures that no other project does: RLS policy SHAPE.
All eight relations report `relrowsecurity = true` and hold identical
privileges, and the outcomes still range from wide open on all four verbs to
deny-all.**

Project 01 runs the mirror-image experiment: RLS off everywhere, `GRANT`s
varied. This one is the other half of the pair.

## The experimental design

Privileges are the control, not a variable. The schema issues one statement:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
  TO anon, authenticated;
```

so every table carries the same eight grants — 8 tables × 4 verbs × 2 roles =
64 grant tuples, which the answer key asserts against
`information_schema.role_table_grants` so that the claim cannot quietly stop
being true. Every table then gets `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`,
which the answer key also asserts (0 tables in `public` without it).

Because privileges and the RLS bit are held constant, any difference in
outcome between two relations below is attributable to the policy and to
nothing else. There is no privilege confound to argue about.

| relation | policy | anon read | account read | INSERT | UPDATE | DELETE |
|---|---|---|---|---|---|---|
| `rls_no_policy` | none | no (200 `[]`) | no | no | no | no |
| `policy_for_all_true` | `FOR ALL USING (true) WITH CHECK (true)` | **yes, 7 rows** | yes | **yes** | **yes** | **yes** |
| `policy_select_true_only` | `FOR SELECT USING (true)` | **yes, 5 rows** | yes | no | no | no |
| `policy_insert_only` | `FOR INSERT WITH CHECK (true)` | no (200 `[]`) | no | **yes** | no | no |
| `policy_delete_only` | `FOR DELETE USING (true)` | no (200 `[]`) | no | no | no | **yes, unfiltered only** |
| `policy_authenticated_true` | `FOR SELECT TO authenticated USING (true)` | no (200 `[]`) | **yes, all 4 rows** | no | no | no |
| `policy_owner_scoped` | `FOR SELECT TO authenticated USING (owner_id = sub)` | no (200 `[]`) | **own rows only** | no | no | no |
| `policy_restrictive_mix` | permissive `USING (true)` **AND** restrictive tenant check | no (200 `[]`) | no | no | no | no |

## What a correct scanner must report

- `policy_for_all_true` — anonymously readable (7 rows) and anonymously
  INSERT-, UPDATE- and DELETE-able. One policy line produced all four. `FOR
  ALL` reads in English as "for all rows" and means "for all four commands".
- `policy_select_true_only` — anonymously readable (5 rows, with IBANs), every
  write refused. Together with the row above this is the pair that proves a
  scanner is reading more than `relrowsecurity`: same bit, same grants,
  opposite write outcome, one keyword of difference.
- `policy_insert_only` — anonymous INSERT accepted, and the caller chooses the
  column values. Measured: `POST` with the default preference answers `201`,
  and the row lands with `is_admin` set to whatever the body said:

  ```
  990001|anon-http-probe@example.invalid|true
  ```

  `WITH CHECK (true)` is a check on nothing. A read probe sees `200 []` here
  and records the table as safe.
- `policy_delete_only` — a stranger can empty it. Measured: 6 rows before,
  `DELETE /policy_delete_only` answers `204`, 0 rows after. See the surprise
  below for the filter caveat, which is the interesting part.
- `policy_authenticated_true` — invisible to `anon`, and every one of its 4
  rows (names, home addresses, phone numbers, dates of birth) is returned to
  *any* token carrying `role=authenticated`. Whether that is public depends on
  a GoTrue setting, not on Postgres; project 04 supplies that half.

## What a correct scanner must NOT report

- `rls_no_policy` — RLS on, zero policies, which in Postgres is deny-all. It
  answers `200` with `[]`, and it holds `sk_live_…`-shaped strings, so a
  scanner ranking by content will want to report it. Nothing is reachable.
- `policy_restrictive_mix` — the one relation where reading each policy in
  isolation gives the wrong answer. It has `AS PERMISSIVE FOR SELECT USING
  (true)`, which alone says world-readable. Beside it sits `AS RESTRICTIVE FOR
  SELECT USING (tenant_id::text = <tenant claim>)`. Permissive policies are
  OR-ed; restrictive policies are AND-ed over the result. No token in this
  corpus carries a `tenant` claim, so the restrictive predicate is NULL, the
  conjunction denies, and both `anon` and an account get `[]`.
- `policy_owner_scoped` — a correct per-user policy, and the control that keeps
  the `policy_authenticated_true` finding from being vacuous. Same RLS bit,
  same grants, same `TO authenticated`. Reporting every authenticated-visible
  relation as an escalation is wrong about this one.

  Verified by hand, three tokens, one request:

  ```
  $ curl -s -H "Authorization: Bearer $A" \
      'http://127.0.0.1:54421/policy_owner_scoped?select=note'
  [{"note":"identity A note 1"},
   {"note":"identity A note 2"},
   {"note":"identity A note 3"}]

  $ curl -s -H "Authorization: Bearer $B" \
      'http://127.0.0.1:54421/policy_owner_scoped?select=note'
  [{"note":"identity B note 1"}]

  $ curl -s -H "Authorization: Bearer $ANON" \
      'http://127.0.0.1:54421/policy_owner_scoped?select=note'
  []
  ```

  where `$A` is sub `2222…`, `$B` is sub `3333…`. The A-side of that is
  automated in the answer key (`expect_body_contains: identity A note 1` plus
  `expect_body_missing` for B's and C's rows). The B-side is under
  `expect.unverified`: `lib/check.py` binds only one authenticated token, and
  an answer key cannot carry a literal JWT without committing a credential.

## The thing that surprised us

Two things, and both change what a write probe means.

### 1. `FOR DELETE USING (true)` does not make a FILTERED delete work

The obvious probe — `DELETE ?id=eq.<a row that provably exists>` — answers
`204` and the row is **still there**. The unfiltered request empties the table.

```
$ psql -tAc 'SELECT count(*) FROM public.policy_delete_only'
6
$ curl -X DELETE .../policy_delete_only?id=eq.7      -> 204
$ psql -tAc 'SELECT count(*) FROM public.policy_delete_only'
6
$ curl -X DELETE .../policy_delete_only              -> 204
$ psql -tAc 'SELECT count(*) FROM public.policy_delete_only'
0
```

The mechanism is a Postgres rule that is easy to read past: `UPDATE` and
`DELETE` statements that **reference existing table columns** also require
`SELECT`, and the `SELECT` **policies** are applied to that reference. This
table has a `DELETE` policy and no `SELECT` policy, so `WHERE id = 7` resolves
against an empty view of the table, zero rows match, and Postgres has nothing
to refuse. `DELETE` with no `WHERE` references no column, so only the `DELETE`
policy applies and all six rows go.

Both requests answer `204`. So does an unfiltered `DELETE` against
`rls_no_policy` and against `policy_select_true_only`, neither of which loses a
row. `204` carries no information at all here; only the row count does. The
answer key therefore gives this relation an **empty** `row_filter`, and
`cleanup_sql` rebuilds the table instead of trimming it.

### 2. The insert-only shape is invisible to a probe that asks for the row back

`POST /policy_insert_only` behaves differently depending on one request header
that has nothing to do with authorisation:

```
Prefer: return=minimal          -> 201 Created, row committed   (PostgREST's DEFAULT)
Prefer: return=representation   -> 401, {"code":"42501",
                                  "message":"new row violates row-level
                                             security policy for table
                                             \"policy_insert_only\""}
Prefer: return=headers-only     -> 401, 42501
```

`RETURNING` is a read. With `FOR INSERT WITH CHECK (true)` and no `SELECT`
policy, the `INSERT` is permitted and the `RETURNING` is not, and Postgres
reports the composite failure with a message that names the *wrong half* — it
says the new row violated a policy, which is exactly what a scanner would
record as "INSERT denied". It was not denied. Confirmed at the SQL level:

```
SET ROLE anon; INSERT INTO policy_insert_only (message) VALUES ('x');
  -> INSERT 0 1
SET ROLE anon; INSERT INTO policy_insert_only (message) VALUES ('x') RETURNING id;
  -> ERROR: new row violates row-level security policy for table "policy_insert_only"
```

This had a consequence for the corpus itself, and it is the clearest thing this
project has produced. `lib/check.py`'s insert probe used to hardcode
`Prefer: return=representation`, so it measured `insert_reachable: false` for
this shape — a wrong answer about a real exposure, produced by the harness that
exists to prevent wrong answers. The relation therefore carried **no
`insert_reachable` claim at all** rather than a claim tuned to make the probe
pass, and the exposure was proved three other ways instead.

The probe now sends `return=minimal`, which is PostgREST's own default, and the
claim is measured directly: `HTTP 201, row count 4->5`. The three indirect
proofs are still in the key — an HTTP `201`, an HTTP `409 23505` on re-posting
the same primary key (which can only conflict if the first row committed), and
two `psql` claims reading the row that `setup.sh`'s anonymous POST left behind
— because a claim with four independent witnesses is cheap to keep and the
failure it guards against has already happened once.

The general lesson is worth stating: **a write probe that asks for the row back
is testing two privileges and reporting one.** Any scanner using
`return=representation` to confirm an insert will systematically under-report
public submission forms, which is the exact shape most likely to be found in
the wild.

## Layout

Bare PostgREST at the **root**, no gateway and no GoTrue. This project varies
one thing; a gateway would add a second axis and make a failure ambiguous.

- REST: `http://127.0.0.1:54421/`
- Postgres: `127.0.0.1:54422`, database `fixture`, user `postgres`

## Running it

```sh
cd benchmark/corpus/03-policy-shapes && docker compose up -d --wait
../verify.sh --no-up 03-policy-shapes
```

`setup.sh` runs first and does two things: it resets the write residue from the
previous run (this project is verified by emptying one table and appending to
another, so the row counts do not survive a run untouched), and it performs the
one anonymous `POST` whose residue the answer key asserts with a plain
`SELECT`. It is a separate hook because `lib/check.py` reads only the **first
line** of `psql` output, which for anything other than a bare `SELECT` is the
command tag — so a `psql` claim cannot be `SET ROLE anon; INSERT …; SELECT …`,
it would compare the expected value against the string `SET`.

Verification is destructive-and-restoring. Run twice; both runs report
`all 103 claims held`.
