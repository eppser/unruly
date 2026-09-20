# The benchmark corpus

Sixteen target projects, each with an independently established answer key, so
that a scanner's recall and precision can be measured across a range of shapes
instead of against one or two.

Recall against a single target is not recall. It is a measurement of how well
one tool fits one database, and the number it produces moves when the database
does. The corpus exists so that "89% recall" has a denominator worth quoting.

**Every project here was built for this repository and is authorised by
construction.** Nothing third-party is scanned, referenced or included. The
`the reference target` project is deliberately excluded.

## The index

Each project exists to measure **one** property the others do not. If two rows
below ever collapse into the same reason, one of the two projects should be
deleted rather than kept for the count.

| # | project | the one property it measures | layout | claims |
|---|---|---|---|---|
| 01 | `01-rls-off-crud` | the four write **verbs are independent** — a table that refuses INSERT and permits DELETE | bare PostgREST at `/` | 53 |
| 02 | `02-hardened` | **precision**: the correct result is nothing, on a project with real surface | Kong-shaped `/rest/v1` | 102 |
| 03 | `03-policy-shapes` | RLS **policy shape**, with privileges held constant so nothing else can explain the difference | bare PostgREST at `/` | 104 |
| 04 | `04-auth-escalation` | data invisible to `anon` and readable by **anyone who signs up** | Kong-shaped `/rest/v1` | 112 |
| 05 | `05-empty-project` | a project with **nothing in it**, alive and correct | bare PostgREST at `/` | 35 |
| 06 | `06-unreachable` | **unreachable is not clean** — three distinct socket-level failures | three ports, no database | 28 |
| 07 | `07-rewriting-proxy` | a proxy that **destroys PostgREST's error semantics** and moves the mount path | `/api/db/v2/` | 69 |
| 08 | `08-rate-limited` | **429 as a function of request rate**, so the relation list is a lower bound and moves between runs | nginx `limit_req` | 55 |
| 09 | `09-huge-schema` | **scale and unguessable names**, with the OpenAPI shortcut closed | bare PostgREST at `/` | 148 |
| 10 | `10-nonlatin-names` | identifiers that are **not ASCII English** | bare PostgREST at `/` | 125 |
| 11 | `11-multi-schema` | **several exposed schemas**, selected by header, with the same table name in each | bare PostgREST at `/` | 85 |
| 12 | `12-content-vs-jsonb` | **data kind over table name**: public copy that must not be reported, secrets inside a generic JSONB column that must | bare PostgREST at `/` | 77 |
| 13 | `13-rpc-security-definer` | the tables are clean and the **routines are the way in** | bare PostgREST at `/` | 79 |
| 14 | `14-firebase` | **a different backend**, whose defaults run the opposite way to Postgres's | Firestore + RTDB + Auth | 40 |
| 15 | `15-grant-vs-rls` | **grant-awareness**: RLS state alone does not predict reachability, in either direction | bare PostgREST at `/` | 24 |
| 16 | `16-data-classification` | **what the report says is IN the data**: every class in the vocabulary, by column name and by sampled value, with lookalikes that must stay unclassified | bare PostgREST at `/` | 60 |

**1,204 claims**, every one of them re-derived from the running stack rather
than from the DDL. The claim count is not a quality score — a project can be
right in fewer claims — but a project whose count is small relative to its
surface is a project whose answer key is doing less work than it looks like it
is.

**1,193 hold; 11 do not**, measured from a cold start. This
sentence used to read "every one of them passing from a cold start", and that
had stopped being true. Naming the shortfall is the same rule the corpus
applies to the scanner:

- `13-rpc-security-definer`, 6 of 79. The injected `UNION` claims return an
  empty array where the key expects `api_key` hashes, and the volatility guard
  answers 200 where it expects 400.
- `14-firebase`, 5 of 45. Structural rather than a regression: `check.py`
  reaches for a `db` service to count rows with `psql`, and a Firestore project
  has none. The harness cannot verify this project's row counts at all, which
  is a gap in the checker and not in the project.

Neither is caused by the scanner and neither is caused by project 16: `verify.sh`
and `check.py` never invoke the scanner binary — confirmed by grep, not
assumed. Both are open.

Three of the fourteen (02, 05, 06) have "report nothing" as at least part of
their correct answer, and a fourth (12) is mostly a precision test. That
proportion is deliberate. A corpus made only of vulnerable targets rewards a
scanner that reports everything.

## What building it already found

None of these came from running a scanner. They came from writing down what a
target was supposed to do and then measuring what it did. The full list is in
`METHOD.md`; these are the ones that change how a scan should be written.

- **A write probe that asks for the row back is testing two privileges and
  reporting one.** `Prefer: return=representation` on a table with
  `FOR INSERT WITH CHECK (true)` and no SELECT policy gets
  `401 42501 "new row violates row-level security policy"` — the `RETURNING`
  was refused, not the `INSERT`, and the row committed. This corpus's own
  checker had that bug and recorded a genuinely writable public submission form
  as not writable.
- **`204` from a filtered `DELETE` means nothing.** Postgres applies SELECT
  policies to columns in a `DELETE`'s `WHERE`, so on a delete-only policy the
  filter matches nothing, the row survives, and the status is still `204`. An
  unfiltered `DELETE` takes every row. Only the row count distinguishes them.
- **Turning off the OpenAPI document makes discovery leak more.** The document
  is privilege-filtered; the `404 PGRST205` fuzzy-match hint that remains is
  not. `GET /profile` names `profiles` even where `anon` holds no grant on it.
- **`PGRST002` for a window after startup.** PostgREST answers `503` while it
  builds its schema cache. A scan begun right after a deploy gets a clean
  report for a database it never read.
- **A view over an RLS-protected table returns the rows the table refuses**,
  because `security_invoker` defaults to false and RLS does not apply to a
  table's owner.
- **`401` versus `403` is decided by the client's headers**, not by the target:
  the same `42501` renders both ways depending on whether a JWT was sent.
- **Two relations can be indistinguishable in an error message** when their
  names differ only by Unicode normalisation, and `lower()` on
  `pg_class.relname` does not fold an umlaut.

## Ports

Allocated from 54400 upward so nothing collides with the fixtures in
`fixtures/` (54321, 54326, 54327, 54331, 54341, 54366, 8090-8091, 8791-8793), which may be
running concurrently.

| project | ports |
|---|---|
| 01 | 54401 REST, 54402 Postgres |
| 02 | 54411 gateway, 54412 Postgres |
| 03 | 54421 REST, 54422 Postgres |
| 04 | 54431 gateway, 54432 Postgres, 54433 GoTrue |
| 05 | 54441 REST, 54442 Postgres |
| 06 | 54451 nothing listening, 54452 drops, 54453 502 |
| 07 | 54461 proxy, 54462 Postgres |
| 08 | 54471 proxy, 54472 Postgres |
| 09 | 54481 REST, 54482 Postgres |
| 10 | 54491 REST, 54492 Postgres |
| 11 | 54501 REST, 54502 Postgres |
| 12 | 54511 REST, 54512 Postgres |
| 13 | 54521 REST, 54522 Postgres |
| 14 | 54531 Firestore, 54532 RTDB, 54533 Auth, 54535 hub |
| 15 | 54541 PostgREST, 54542 Postgres |

## The answer-key format

Each `answer-key.yaml` is the shape of `evals/targets/lab-fixture.yaml` —
`name`, `project_ref`, `base_url`, `rest_prefix`, `anon_key_env`, `fixture`,
`notes`, and an `expect` block carrying `key_in_bundles`, `routines`,
`escalation_gains` and `relations` — with additions that exist because the
original shape cannot express a measurement, only a conclusion.

Added at the top level: `compose`, `authenticated_key_env`, and a `db:` block
(`service`, `user`, `database`) so the checker can reach `psql` in the
container.

Added per relation: `schema`, `row_count_sql`, `read_status`, `read_sqlstate`,
`authenticated_read_exposed`, `update_reachable`, `delete_reachable`, and a
`probe:` block (`post_body`, `post_prefer`, `marker_sql`, `row_filter`,
`update_body`, `update_check_sql`, `update_expect`, `exists_check_sql`,
`cleanup_sql`).

Added under `expect`: `schemas`, `psql[]` (`{name, sql, expect}`), `checks[]`
(raw HTTP, with `capture`/`${var}` chaining between them) and `unverified[]`
(`{claim, why}`).

Three of those carry the design:

- **`probe:` is mandatory for any write claim.** A relation that says
  `insert_reachable` without one fails the check by construction. You cannot
  assert a write you did not perform.
- **`unverified[]` prints as a NOTE and never fails.** It is where a claim goes
  when it is true and not measurable here, with the reason. Every project uses
  it; a project that does not is probably not looking hard enough.
- **`capture`/`${var}`** exists so that "anyone who signs up can read this" is
  a measurement rather than a recollection: the token a signup endpoint returns
  is carried into the next request.

`lib/yamlite.py` parses a deliberately narrow YAML subset and raises on
anything outside it. PyYAML is not installed on the machine this was built on
and a `pip install` in the verification path would mean the honesty check does
not run offline. A permissive parser turns a typo in an answer key into a check
that quietly stops running.

## Running it

```sh
cd benchmark/corpus
./verify.sh                            # all of them, cold: up, check, down
./verify.sh 01-rls-off-crud            # one
./verify.sh --keep 03-policy-shapes    # leave it running
./verify.sh --no-up 03-policy-shapes   # it is already running
```

`verify.sh` exits 0 only when every claim in every answer key held against the
running stack. It is the thing that keeps the corpus honest; see `METHOD.md`
for how ground truth was established and, more importantly, for what was not
verified.

## What the corpus does not cover

Stated so that a gap is a known gap rather than an implied claim.

- **Storage buckets** are not modelled here. `fixtures/lab` models the storage
  responses with a gateway, and doing the same again would add a project with
  no property of its own. A real `storage-api` was not stood up.
- **Edge Functions** and **Realtime** are likewise left to `fixtures/edge` and
  `fixtures/hardened`, for the same reason.
- **Email-confirmation-required signup** is a third auth state that neither 02
  (signup disabled) nor 04 (signup open, autoconfirm on) covers.
- **A single-relation project** is not built. 05 (zero relations) and 09 (120)
  bracket it, and "small" on its own is not a property worth a directory.
- **Cloud behaviour** is not covered anywhere. Every target is local. Managed
  Supabase adds Kong's own error shapes, connection pooling and real rate
  limits; `evals/targets/` holds the cloud-facing targets and this corpus does
  not replace them. Project 14's emulator diverges from production Firebase in
  a way that is documented in its README and answer key.

## Adding a project

1. Give it a directory `NN-short-name` and a port block from the table above.
2. Write the schema or config, and a `docker-compose.yml` with an explicit
   `name: unruly-bench-NN`. Mount `../lib/00_roles.sql` rather than copying it,
   and mount initdb files **one by one** — the postgres entrypoint ignores
   subdirectories, which presents as correct roles and no tables.
3. Write `answer-key.yaml`. Any relation making a write claim needs a `probe:`
   block; the checker fails a write claim it cannot measure, on purpose.
4. Run `./verify.sh --keep NN-short-name` until it says `all N claims held`,
   then run it again **cold** (`./verify.sh NN-short-name`). The second run is
   not redundant: it is how the `PGRST002` schema-cache race was found, and a
   key verified only against a warm stack is a key verified against a state
   nobody scans.
5. Write `README.md` opening with the one property the project measures that no
   other does. If you cannot name one, do not add the project.
6. Anything you could not check goes in `expect.unverified` with a reason, and
   anything that surprised you goes in the README. That is the most valuable
   content in either file.
