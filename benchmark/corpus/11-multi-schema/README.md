# 11 — four exposed schemas, one relation name

## What this target is for

**The one property it measures that no other project does: "is `users`
exposed?" has no single answer here. The same name resolves to four different
relations in four exposed schemas with four different verdicts, and the schema
is selected by a request HEADER rather than by a path segment.**

There is no `/api/users` URL on this target. There is `/users`, plus
`Accept-Profile: api`. A scanner that reports one verdict per relation NAME is
wrong about three of the four whichever way it sets it, and a scanner that
never sends the header sees only the safest of the four.

| request | schema reached | result | rows behind it |
|---|---|---|---|
| `GET /users` | `public` | `200` `[]` — RLS on, no policy | 12 |
| `GET /users` + `Accept-Profile: api` | `api` | `206`, `id` and `display_name` only | 12 |
| `GET /users` + `Accept-Profile: legacy` | `legacy` | `206`, bcrypt hashes and emails, full CRUD | 6 |
| `GET /users` + `Accept-Profile: reporting` | `reporting` | `401` `42501` | 9 |

`PGRST_DB_SCHEMAS` is `public,api,legacy,reporting`. The **first** entry is the
default, measured: a header-less request comes back with the response header
`Content-Profile: public`.

## Schema enumeration versus relation enumeration

Each schema carries one relation that exists in no other schema:

| relation | schema | anon can read |
|---|---|---|
| `announcements` | `public` | yes, 3 rows |
| `service_status` | `api` | yes, 4 rows |
| `sessions` | `legacy` | yes, 3 rows (session tokens) |
| `revenue_by_month`, `churn_cohorts` | `reporting` | no, `401` |

Finding `users` four times says nothing about how many schemas were reached.
Finding these five says all four were. Under the wrong profile they answer
`404` `PGRST205` with the schema-qualified name in the message
(`Could not find the table 'reporting.announcements' in the schema cache`), so
the two axes are separable from the outside.

## What a correct scanner must report

- `legacy.users` — 6 rows, `email`, `password_hash`, `reset_token`, and
  anonymous **INSERT, UPDATE and DELETE** all measured working (`201`, `200`,
  `204`, each confirmed against a marker row read back through `psql`).
- `legacy.sessions` — 3 rows of live session tokens, readable.
- `reporting` — three tables, 47 rows, all `401`. Not readable, and **not
  absent**. Each 401 names its own table.

## What a correct scanner must NOT report

- `public.users` is not a leak. `200` with body `[]`; RLS is on and the policy
  set is empty, so the grant permits the query and no row survives it.
- `api.users` is not a leak either, and this one takes work to get right. It is
  world-readable, 12 rows, and it is the **correct** design: the view projects
  `id` and `display_name` and nothing else. The base table's email column never
  crosses the wire. Precision here requires looking at columns, not at the
  name `users`.
- `reporting.*` must be **discovered** and must **not** be reported as
  readable.

## The thing that surprised us

Three things, in ascending order of how much they change the job.

**1. `api.users` returns rows that `public.users` refuses.** The view is over
the RLS-protected base table, so the intuition is that RLS follows it. It does
not. Since PostgreSQL 15 a view carries a `security_invoker` option that
defaults to **false**, so the view executes as its owner — `postgres`, who owns
`public.users` — and RLS does not apply to a table's owner unless
`FORCE ROW LEVEL SECURITY` is set. `pg_class.reloptions` on `api.users` is
empty, which the answer key asserts. So "the base table returns an empty array"
is not a statement about the data reachable through that table.

**2. The same relation answers `401` to `anon` and `403` to a JWT-bearing
`authenticated` user.** `reporting.users` is `401` `42501` anonymously and
`403` with the authenticated token — same SQLSTATE, different HTTP status,
because PostgREST distinguishes "you sent no usable credential" from "your
credential is fine and insufficient". A scanner that keys on the status code
rather than the SQLSTATE gets two different stories about one table.

**3. An invalid profile enumerates every exposed schema, for free.** This is
the most useful thing on the target and it was not something we set up:

```
$ curl -H 'Accept-Profile: nosuchschema' .../users
HTTP/1.1 406 Not Acceptable
{"code":"PGRST106","hint":"Only the following schemas are exposed: public, api, legacy, reporting",
 "message":"Invalid schema: nosuchschema"}
```

One request with a nonsense header returns the complete schema list. No
wordlist, no guessing. Meanwhile the OpenAPI document — the path a scanner is
most likely to take — is served **per profile** and tells the opposite story:
the default document lists `/announcements` and `/users` and contains no
mention of `password_hash`, and the `reporting` document has exactly one path,
`/`, and names none of its three tables. Read the schema document and
`reporting` looks empty; send one bad header and you learn it exists; send a
`GET` and its 401 names each table in turn.

## A limitation of the harness, not of the target

`lib/check.py`'s `profile_headers()` sends no profile header when a relation's
`schema` is `public` or unset. That is correct only while `public` is the first
entry of `PGRST_DB_SCHEMAS`. It is, here, deliberately — this project changes
one variable and the default schema is not it. A target whose default schema is
something other than `public` would need that function to know the difference,
and no project in the corpus builds that shape yet.

## Layout

Bare PostgREST at the **root**, no gateway.

- REST: `http://127.0.0.1:54501/`
- Postgres: `127.0.0.1:54502`, database `fixture`, user `postgres`

## Running it

```sh
cd benchmark/corpus/11-multi-schema && docker compose up -d --wait
../verify.sh --no-up 11-multi-schema
```

Verification is destructive-and-restoring: it inserts a marker row into
`legacy.users` with `psql`, performs the real INSERT, PATCH and DELETE over
HTTP with `Content-Profile: legacy`, reads the result back out of the database,
then deletes the marker. Row counts return to 12 / 3 / 12 / 4 / 6 / 3 / 9 / 14
/ 24.
