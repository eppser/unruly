# 13 — the tables are locked, the functions are the way in

## What this target is for

**The one property it measures that no other project does: every relation here
is correctly protected, so a scanner that enumerates relations and stops
reports this project as clean. Its relations ARE clean. Its posture is not.**

`SECURITY DEFINER` means "run this function as its owner". The owner is
`postgres`, who owns every table in the project, and row-level security does
not apply to a table's owner. A `SECURITY DEFINER` routine is therefore not a
wrapper around a protected table — it is a hole through it, and the size of the
hole is whatever the function body selects.

## The relations, all of them clean

| relation | rows | anonymous GET | why |
|---|---|---|---|
| `customers` | 20 | `200` `[]` | RLS on, policy scoped to the JWT `email` claim |
| `api_keys` | 5 | `401` `42501` | no privilege for `anon` |
| `audit_events` | 5 | `401` `42501` | no privilege for `anon` |

No relation accepts `INSERT`, `UPDATE` or `DELETE`; each verb was measured
against a marker row inserted by `psql`, and each answered `401` `42501`. The
`customers` policy is satisfiable rather than a deny-all — a token carrying the
matching `email` claim would see its own row — which makes it a plausible
configuration rather than a fixture that is obviously broken.

## The routines, three of which are the finding

| routine | security | anon may call | verdict |
|---|---|---|---|
| `zephyr_customer_export_v2()` | DEFINER | yes | **returns all 20 customer rows** |
| `search_customers(term)` | DEFINER | yes | **SQL injectable, reads any table** |
| `record_contact_request(email, note)` | DEFINER | yes | **anonymous write into `audit_events`** |
| `customers_for_current_user()` | INVOKER | yes | control — returns `[]` |
| `public_status_counts()` | DEFINER | yes | control — aggregates only |
| `mnemosyne_key_rotation_audit()` | DEFINER | **no** | discoverable, `401` `42501` |

Two of the names — `zephyr_customer_export_v2` and
`mnemosyne_key_rotation_audit` — are in no wordlist. Routine discovery on this
target has to be more than dictionary guessing, or the routine that dumps the
customer table is never found.

### The injection, and why it is read-only on purpose

`search_customers` interpolates its argument with `format(... %s ...)` instead
of `%L`. `%L` quotes and escapes; `%s` pastes. The difference is one character
in the source and it is the whole vulnerability.

```
POST /rpc/search_customers
{"term":"' UNION SELECT id, label, key_hash FROM public.api_keys --"}
-> 200, and the body contains sk_live_meridian_0000000000000003
```

`api_keys` answers `401` to a direct `GET`. The injection reads it anyway, and
reads `audit_events` the same way.

The routine is declared `STABLE` **deliberately**. PL/pgSQL refuses to execute
`INSERT`, `UPDATE`, `DELETE` or DDL from a non-`VOLATILE` function, so the same
injection that reads any table in the database cannot change or destroy one.
That is asserted, not assumed — the answer key sends an injected `DELETE` and
an injected `UPDATE` and records the exact refusal. We kept it read-only
because a fixture that anyone who reads its own README can empty is a fixture
that gets emptied, and because the shape of the vulnerability is what the
benchmark measures, not the shape of the damage.

### The write

`record_contact_request` is `VOLATILE` `SECURITY DEFINER` and inserts into
`audit_events`, on which `anon` holds no privilege of any kind. It returns the
row it wrote, read back out of the table:

```
{"inserted_id": 11, "stored_detail": "unruly wrote this"}
```

The row is asserted to have landed by the `psql` statement at the top of the
**next** run, which deletes it and requires that it was there. From run two
onwards that check is a database-side proof that an anonymous HTTP request
wrote a durable row into a table it cannot read.

### The two controls

`customers_for_current_user()` is the same body over the same table with
`SECURITY INVOKER`. It runs as `anon`, RLS applies, and it returns `[]`. It is
a callable routine that is **not** a way in.

`public_status_counts()` is `SECURITY DEFINER` and reads all three locked
tables — and returns only `{"customers": 20, "active_keys": 5,
"events_today": 6}`. That is what `SECURITY DEFINER` is *for*. "Definer" is not
a synonym for "finding", and a scanner that reports every definer routine is
wrong about this one.

## The thing that surprised us

**`REVOKE` hides a routine from the OpenAPI document and does not hide it from
PostgREST's 404 hint.** Drop the last character of the unguessable name and the
server completes it for you:

```
POST /rpc/mnemosyne_key_rotation_audi
404 PGRST202
hint: "Perhaps you meant to call the function public.mnemosyne_key_rotation_audit"
```

`mnemosyne_key_rotation_audit` is absent from the OpenAPI document — PostgREST
lists only what the requesting role may execute — while the hint oracle names
it happily, because the hint is computed from the schema cache and not from
privileges. Discovery and privilege disagree, in the direction that favours the
scanner. (`POST /rpc/qqqqqqqq` gets `hint: null`, so there is a similarity
floor and it is not a full dump.)

Three smaller ones, all measured:

- **`EXECUTE` on a new function is granted to `PUBLIC` by default.** Without
  the `REVOKE EXECUTE ON ALL FUNCTIONS ... FROM PUBLIC` in
  `schema/02_routines.sql`, every routine here would be callable by `anon`
  whatever the explicit `GRANT`s said, and the "not callable" control would not
  exist. This is the most common way a routine becomes reachable by a stranger
  without anyone having granted anything.
- **A `STABLE` routine is served over `GET` as well as `POST`.**
  `GET /rpc/zephyr_customer_export_v2` returns the same 20 rows. A scanner that
  only `POST`s to `/rpc/` finds it; so does one that only crawls `GET`s.
- **The same refusal is `401` to `anon` and `403` to an authenticated caller**,
  with SQLSTATE `42501` in both. Keying on the HTTP status rather than the
  SQLSTATE gets two different stories about one routine — and this holds for
  the tables too (`api_keys` is `401` anonymously, `403` authenticated).

## The correct verdict, stated plainly

This project's **relations are clean and its posture is not**. A report that
says "3 relations, none exposed, no findings" is a failing report. The correct
report names `zephyr_customer_export_v2` (20 customer records with phone
numbers), `search_customers` (SQL injection reaching every table in the
database), and `record_contact_request` (anonymous durable write into a table
with no grants), and does **not** name `customers_for_current_user` or
`public_status_counts`.

## Layout

Bare PostgREST at the **root**, no gateway.

- REST: `http://127.0.0.1:54521/`
- Postgres: `127.0.0.1:54522`, database `fixture`, user `postgres`

## Running it

```sh
cd benchmark/corpus/13-rpc-security-definer && docker compose up -d --wait
../verify.sh --no-up 13-rpc-security-definer
```

Verification is destructive-and-restoring. It inserts marker rows into all
three tables with `psql`, confirms every HTTP write against them is refused,
and removes them. It calls the write RPC once per run and removes that row at
the start of the next run, so `audit_events` is back to its five seeded rows
every time the relation checks read it — confirmed by running the verifier
cold, then twice more, with all 79 claims holding each time.
