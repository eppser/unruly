# 07 — a reverse proxy that rewrites the errors

## What this target is for

**The one property it measures that no other project does: discovery has to
work without PostgREST's error codes. The proxy replaces every upstream 401,
403 and 404 with one status and one body, so "this relation exists and you may
not read it" and "this relation does not exist" become the same 53 bytes.**

This is not a contrived shape. Put an API gateway or a Next.js rewrite in front
of Supabase — which is what most production deployments do — and two things the
scanner leans on go away at once:

1. **The path moves.** The API here is at `/api/db/v2/`. Not `/`, not
   `/rest/v1/`. No wordlist guesses it, and the origin's own root serves an app
   shell with a `200` and no hint that a database is mounted three segments
   down.
2. **The 4xx bodies are rewritten.** `proxy_intercept_errors on;` plus
   `error_page 401 403 404 = @generic;` collapses all three into `403` with
   `{"error":"request could not be completed","ref":"gw"}`. The `= @generic`
   form takes the status from the named location as well as the body, which is
   what destroys the status code and not merely the message.

`2xx` is passed through untouched. That is deliberate and load-bearing: if
`Content-Range` were dropped, row counts would stop being measurable and this
would be a different, duller target.

## The four cases behind the proxy

| relation | database state | through the proxy | exists? |
|---|---|---|---|
| `press_releases` | `GRANT SELECT`, 12 rows | `206`, `Content-Range: 0-0/12` | yes |
| `support_tickets` | `GRANT SELECT`, 18 rows | `206`, `Content-Range: 0-0/18` | yes |
| `session_tokens` | `GRANT SELECT`, **RLS on, 0 policies**, 8 rows | `200`, `[]`, `Content-Range: */0` | yes |
| `billing_accounts` | **no grant at all**, 5 rows | `403`, generic body | yes |
| `no_such_table_xyz` | nothing | `403`, generic body | **no** |

`session_tokens` is the case the proxy cannot touch, and it is why the RLS
shape is in this project at all. Postgres with RLS on and no policy does not
*refuse* — it *filters*. The query succeeds, PostgREST answers `200` with an
empty array, and a proxy configured to rewrite 4xx never sees it. So the
relation stays discoverable through the gateway while the `REVOKE`-protected
one does not. Two protections that look equivalent from the DDL behave
oppositely once a gateway is in the path.

## What a correct scanner must report

- All three readable relations, at `/api/db/v2/`, with their row counts. The
  rewriting degrades **none** of this. 18 rows of reporter email addresses,
  phone numbers and internal notes are one anonymous `GET` away, and a scanner
  that gives up on this target because the error codes are gone misses all of
  them.
- The OpenAPI document, which is a `200` and therefore passes through whole.
  It names `press_releases`, `support_tickets` and `session_tokens`, and omits
  `billing_accounts` — the same asymmetry project 01 records.
- For the non-readable names: **non-discriminating for existence on the GET
  status-and-body channel.** It must not claim `billing_accounts` is absent,
  and it must not claim it is present, from a `GET` alone. The proxy has made
  that undecidable from outside on that channel.

The answer key cannot express "undecidable" as a verdict — `lib/check.py`
observes targets, not reports. So it pins down both halves of the input
instead: `expect.psql` records the ground truth (`billing_accounts` is in
`pg_class`, `no_such_table_xyz` is not) and `expect.checks` records the wire
behaviour that makes them indistinguishable. A grader can score either
behaviour against those. This is stated in `expect.unverified` as well.

## What a correct scanner must NOT report

- Any claim, either way, that `billing_accounts` is absent — from the `GET`
  channel.
- `PGRST205`, "table not found", or "42501" anywhere. None of those strings
  reach the client on this target.
- The `basePath` from the OpenAPI document. See below.

## The thing that surprised us

**The rewriting is total in the body and the status line, and defeated by three
independent side channels.** All three were measured, and all three are
asserted in the answer key, because a benchmark that recorded the *intent* of a
configuration rather than its *behaviour* would be scoring scanners against a
target that does not exist.

**A. nginx forwards the upstream's response headers even when it replaces the
status and the body.** PostgREST's `401` carries `WWW-Authenticate: Bearer`; its
`404` does not. So:

```
GET /api/db/v2/billing_accounts   -> 403  WWW-Authenticate: Bearer
GET /api/db/v2/no_such_table_xyz  -> 403  (no WWW-Authenticate)
```

One anonymous `GET` resolves existence, from a header, while the body is
byte-identical. The channel closes for a request carrying a real JWT —
PostgREST answers `403` rather than `401` for a named role, and `403` has no
challenge header — which is measured too.

**B. `error_page` names 401, 403 and 404. It does not name 400.** Every
PostgREST `400` therefore passes through verbatim, and a `400` names the table:

```
POST /api/db/v2/billing_accounts  {"zzz_probe":1}
  -> 400 {"code":"PGRST204","message":"Could not find the 'zzz_probe' column of 'billing_accounts' in the schema cache"}
POST /api/db/v2/no_such_table_xyz {"zzz_probe":1}
  -> 403 {"error":"request could not be completed","ref":"gw"}
```

`GET ?select=zzz_probe` does the same with SQLSTATE `42703`. A gateway
configured to hide which tables exist announces it to any probe that provokes a
*validation* error rather than an *authorisation* one.

**C. `OPTIONS` on an existing relation is a `200`** and is not intercepted at
all; `OPTIONS` on a nonexistent name is the generic `403`. A one-request
existence oracle that reads no data.

Three is not a claim of completeness — `expect.unverified` says so — and the
fact that three turned up by looking is the reason to distrust the intent of
this configuration in general. The practical lesson for anyone writing one: a
uniform error page is a body-level control, and existence leaks at every other
level of the response.

A fourth, smaller surprise, in the opposite direction: **the OpenAPI document
advertises a mount point that does not exist.** It describes the upstream's
view of itself —

```json
"host":"0.0.0.0:3000","basePath":"/"
```

— so a scanner that discovers the document at `/api/db/v2/` and then follows
its `basePath` walks off the target entirely. Asserted, because getting the
relation list from the document and then requesting rows from the wrong path is
a plausible way to report three relations with zero rows each.

## Running it

```sh
cd benchmark/corpus/07-rewriting-proxy && docker compose up -d --wait
../verify.sh --no-up 07-rewriting-proxy
```

- Proxy: `http://127.0.0.1:54461/api/db/v2/`
- Postgres: `127.0.0.1:54462`, database `fixture`, user `postgres`
- PostgREST: **not published**. The proxy is the only way in; if the upstream
  were reachable directly the rewriting could be sidestepped and this project
  would measure nothing.

The verifier performs no writes here. The only `POST`s it sends carry a column
that does not exist, so they are rejected before reaching the table.
