# 05 — a project with nothing in it

## What this target is for

**The one property it measures that no other project does: the correct answer
is the EMPTY answer. Every relation reported against this target is a false
positive, and a scan that errors out instead of returning an empty result is
also a failure.**

The rest of the corpus asks whether a scanner finds the right things. This one
asks whether it can find nothing, say so, and stay up. Those are two separate
failure modes and both are cheap to hit: invent findings from a catch-all
response, or crash on a schema document with no schemas in it.

## The layout

Bare PostgREST at the root, one Postgres, nothing else. Two schemas:

| schema | in `PGRST_DB_SCHEMAS` | relations | rows |
|---|---|---|---|
| `public` | yes | **0** | — |
| `internal` | **no** | `users`, `profiles`, `payments` | 14, 9, 7 |

`anon` holds `USAGE` on `public` and nothing else, because there is nothing
else to hold. On `internal` it holds `USAGE` **and `SELECT` on all three
tables** — deliberately generous, because that makes the claim sharp: the only
thing keeping those tables off the API is one line of PostgREST
configuration (`PGRST_DB_SCHEMAS: public`). Not a `GRANT`, not a policy.

An auditor reasoning from `has_table_privilege` would report three anonymous
read exposures here. From outside there are none. The answer key asserts both
halves: `has_table_privilege('anon','internal.users','SELECT')` is `t`, and
`GET /users` is `404 PGRST205`.

## What a correct scanner must report

- Zero relations. `pg_class` for schema `public`, counting `r`, `v`, `m`, `f`
  and `p`, is `0`. So is `pg_proc` for `public`.
- The host is **alive**: `GET /` answers `200` with a valid `swagger: 2.0`
  document, `Server: postgrest/14.3`.
- Probes for `users`, `profiles`, `payments`, `todos`, `posts`, `customers`
  and a random name all answer `404` with `{"code":"PGRST205", ...}`.
- `POST` to a nonexistent relation is also `404 PGRST205`; the write probe
  finds nothing either.
- `POST /rpc/version` is `404 PGRST202`, the routine-shaped equivalent.
- An `authenticated` token changes none of it. Emptiness here is not a
  privilege artefact.

## What a correct scanner must NOT report

- **Any relation at all.** There is nothing to find.
- Any finding about `internal.users`, `internal.profiles` or
  `internal.payments`. They exist, they hold rows, `anon` may read them in the
  database, and no request can reach them.
- An error, a crash or an "unmeasured" verdict. This target answers every
  request correctly and quickly; treating it as unreachable is the mirror of
  project 06's failure and is equally wrong.

The 404/`PGRST205` shape is what makes emptiness *decidable* rather than
merely unobserved. It is a different answer from the `401`/`42501` that a
`REVOKE`-protected relation gives in project 01, and a scanner that collapses
the two cannot tell this project from that one.

## The thing that surprised us

**PostgREST omits `definitions` from the OpenAPI document entirely when there
are zero relations.** It does not emit `"definitions":{}`. The whole document
is 2,160 bytes and its `paths` object has exactly one member — `/`, the
introspection endpoint describing itself:

```json
{"swagger":"2.0","info":{...},"paths":{"/":{"get":{...,"summary":"OpenAPI description (this document)"}}},"parameters":{...}}
```

Any consumer that reaches for `doc["definitions"]` without checking raises on
this target and on no other in the corpus. That is the second failure mode
named at the top of this file, and it is why the answer key asserts
`expect_body_missing: definitions` rather than asserting an empty object.

A smaller one, measured while checking the schema boundary: the `406` that
PostgREST returns for `Accept-Profile: internal` **leaks the exposed schema
list** in its hint —

```json
{"code":"PGRST106","hint":"Only the following schemas are exposed: public","message":"Invalid schema: internal"}
```

— but it does **not** leak whether the requested schema exists.
`Accept-Profile: no_such_schema_at_all` produces the same status, the same
code and the same hint, with only the echoed name differing. So content
negotiation is a channel for enumerating the *exposed* schema list and not for
enumerating the database's. Both are asserted.

## Running it

```sh
cd benchmark/corpus/05-empty-project && docker compose up -d --wait
../verify.sh --no-up 05-empty-project
```

- REST: `http://127.0.0.1:54441/`
- Postgres: `127.0.0.1:54442`, database `fixture`, user `postgres`

Nothing in this project is destructive; it holds no writable relation and the
verifier performs no writes.
