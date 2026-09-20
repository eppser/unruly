# 01 — RLS never enabled, exposure decided by GRANT

## What this target is for

**The one property it measures that no other project does: the four SQL write
verbs are independent, and a scanner carrying one "writable" bit cannot be
right about all of them.**

RLS is off on every table here. No policy exists anywhere in the database
(`pg_policies` is empty — the answer key asserts it). So every difference
between these five relations comes from `GRANT` alone, which isolates the
privilege axis from the policy axis that project 03 measures.

| relation | SELECT | INSERT | UPDATE | DELETE | why it is here |
|---|---|---|---|---|---|
| `customers` | yes | yes | yes | yes | the full-CRUD baseline |
| `user_credentials` | yes | yes | yes | yes | same privileges, worse content |
| `audit_log` | yes | **no** | **no** | **yes** | the whole point of the project |
| `payment_methods` | yes | no | no | no | read-only, but card numbers and IBANs |
| `internal_settings` | **no** | no | no | no | the precision control |

## What a correct scanner must report

- `customers`, `user_credentials`, `audit_log`, `payment_methods` are all
  anonymously **readable**. 25, 6, 10 and 4 rows respectively.
- `customers` and `user_credentials` accept anonymous INSERT, UPDATE **and**
  DELETE.
- `user_credentials` and `payment_methods` should rank above `customers` and
  `audit_log`: password hashes, API keys, TOTP secrets, PANs and IBANs.
  `payment_methods` is read-only and still the worst thing in the project,
  which is the case for keeping exposure and impact on separate axes.
- `audit_log` is **DELETE-reachable and INSERT-refused**. Measured: `POST`
  answers `401` `42501`; `DELETE ?id=eq.<existing row>` answers `204` and the
  row is gone from the database afterwards. A scanner that probes writability
  with an INSERT calls this table safe, and a stranger can empty it.

## What a correct scanner must NOT report

- `internal_settings` is **not** exposed, in any verb. RLS is off on it and it
  holds a Stripe-shaped secret and an SMTP password, so a scanner reasoning
  "RLS disabled means exposed" will report it. `anon` holds no privilege, so
  every verb answers `401` `42501`.
- It must still be **discovered**. The 401 body names the table
  (`permission denied for table internal_settings`).

## The thing that surprised us

PostgREST's OpenAPI document at `/` lists only the relations the requesting
role can touch. `internal_settings` is **absent** from it while a direct
`GET /internal_settings` answers 401 and names the table in the error body.

So the cheap discovery path — read the OpenAPI document — systematically
misses exactly the relations that `REVOKE` protects. Both facts are asserted
in the answer key (`expect_body_contains: customers`,
`expect_body_missing: internal_settings`) so that a scanner cannot pass this
project by reading the schema document alone.

## Layout

Bare PostgREST at the **root**, no gateway. This is the self-hosted shape; the
managed product puts the same service behind Kong at `/rest/v1`, which
projects 02, 04 and 07 use.

- REST: `http://127.0.0.1:54401/`
- Postgres: `127.0.0.1:54402`, database `fixture`, user `postgres`

## Running it

```sh
cd benchmark/corpus/01-rls-off-crud && docker compose up -d --wait
../verify.sh --no-up 01-rls-off-crud
```

Verification is destructive-and-restoring: it inserts a marker row with `psql`,
performs the real write over HTTP, reads the result back out of the database,
then deletes the marker. Row counts return to 25 / 6 / 10 / 4 / 3, and the
verifier is run twice during development precisely to confirm they do.
