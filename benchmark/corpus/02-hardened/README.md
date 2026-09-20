# 02 — correctly configured, and still worth scanning

## What this target is for

**The one property it measures that no other project does: PRECISION. The
correct scan result for this target is NOTHING. Every finding produced here is
a false positive.**

A precision control made of an empty database would measure nothing — any
scanner reports nothing about a target with no tables. So this one has surface:
five relations, a Kong-shaped REST mount, a real GoTrue, a storage mount, all
reachable, all answering. It is just that a competent operator configured all
of it, and the one thing that *is* anonymously readable is meant to be.

## The five relations, locked five different ways

The ways a scanner can be wrong about "protected" are not interchangeable, so
each relation is protected by a different mechanism.

| relation | mechanism | anon | account holding the corpus token |
|---|---|---|---|
| `member_notes` | RLS + correct per-user policy | `200 []` | its **own 2 of 5** rows |
| `support_tickets` | RLS + per-user policy on all four verbs | `200 []` | its **own 1 of 3** rows |
| `rls_locked` | RLS enabled, **no policy at all** | `200 []` | `200 []` |
| `billing_internal` | **REVOKE** — no grant to anyone | `401` `42501` | `403` `42501` |
| `public_pages` | none. **Public by design** | `206`, 4 rows | 4 rows |

The three RLS tables carry **full CRUD grants** on purpose, which the answer key
asserts (24 grant tuples). If they were revoked as well they would be locked
twice and this project would prove nothing about the policies — the privilege
layer would be doing the work.

## The trap: `public_pages` is readable and that is correct

`public_pages` holds `slug`, `headline`, `body_markdown`, `published_at` and
four rows of marketing copy for a site that renders it client-side straight out
of PostgREST. RLS is enabled on it and it carries an explicit
`FOR SELECT USING (true)`, so the intent is written down rather than implied,
and only `SELECT` is granted, so a stranger cannot edit the site.

```
GET /rest/v1/public_pages -> 206
[{"slug":"pricing","headline":"Simple pricing that scales with you", ...}]
```

**Reporting this relation is a false positive.** It is the most likely one in
the corpus, because the crude rule "anon received rows from a table" fires on
it and nothing about the response distinguishes it from a leak except the
content, which is deliberately, unambiguously non-sensitive.

## `escalation_gains` is empty, and that is the interesting claim

`member_notes` and `support_tickets` both return rows to an authenticated token
and no rows to `anon` — the exact signature project 04 uses for its escalation
findings. Here it is correct behaviour. Measured, one token, two requests:

```
$ curl -H "Authorization: Bearer $AUTH" .../rest/v1/member_notes?select=title
[{"title":"Renewal reminder"},
 {"title":"Shipping address"}]        # its own 2 of 5 rows

$ curl -H "Authorization: Bearer $AUTH" .../rest/v1/support_tickets?select=subject
[{"subject":"Cannot export data"}]    # its own 1 of 3
```

The other three owners' rows are absent, which the answer key asserts with
`expect_body_missing: "Card on file"` and `expect_body_missing: "Duplicate
charge"` on the same requests. A bare "the authenticated token saw rows" bit
cannot tell a correctly scoped table from a wide-open one; **a scanner that
reports every authenticated-visible relation as an escalation produces two
false positives here.**

The `WITH CHECK` half is measured too — the half people leave off:

```
POST /rest/v1/support_tickets   {"owner_id":"5555…","subject":"forged"}
  -> 403 {"code":"42501","message":"new row violates row-level security policy
          for table \"support_tickets\""}
```

## GoTrue, measured rather than trusted

Every setting is asserted over HTTP, not read back out of `docker-compose.yml`.
`GET /auth/v1/settings` returns, verbatim:

```
"anonymous_users":false … "disable_signup":true,"mailer_autoconfirm":false,
"phone_autoconfirm":false,"sms_provider":"","mfa_enabled":false,
"saml_enabled":false
```

and every route into an account is closed, each with its own error code so the
settings can be told apart from outside:

| request | status | body |
|---|---|---|
| `POST /auth/v1/signup` (email + password) | `422` | `signup_disabled`, "Signups not allowed for this instance" |
| `POST /auth/v1/signup` `{}` (anonymous sign-in) | `422` | `anonymous_provider_disabled` |
| `POST /auth/v1/otp` (magic link) | `422` | `signup_disabled` |
| `POST /auth/v1/invite` | `403` | `not_admin` |
| `GET /auth/v1/admin/users` (anon **or** authenticated) | `403` | `not_admin` |
| `POST /auth/v1/token?grant_type=password` | `400` | `invalid_grant` |

`auth.users` holds 0 rows, and with signup off none can be created.

## What a correct scanner must NOT report

Everything. Specifically:

- `rls_locked` is **not** exposed. It holds a Stripe-shaped secret and an SMTP
  password and answers `200 []`, so a scanner ranking by content will want it.
- `billing_internal` is **not** exposed. RLS is *not* enabled on it — the
  protection is `REVOKE` — so a scanner reasoning "RLS disabled means exposed"
  will report the relation with the card numbers in it. It is the least
  reachable thing in the project.
- `member_notes` / `support_tickets` are **not** escalations (above).
- `public_pages` is public **by design** (above).
- The password policy must not be reported **either way** — see below.

`billing_internal` must still be **discovered**: the 401 body names it
(`permission denied for table billing_internal`) while the OpenAPI document
omits it, the same asymmetry project 01 records.

## The thing that surprised us

### 1. The password floor is unobservable, and that is a finding

`GOTRUE_PASSWORD_MIN_LENGTH` is set to `12`. Nothing can confirm it. Measured:

```
signup, password "correct-horse-battery-staple" (28 chars) -> 422 signup_disabled
signup, password "abcde"                        (5 chars)  -> 422 signup_disabled
signup, no password field at all                           -> 422 signup_disabled
POST /auth/v1/otp                                          -> 422 signup_disabled
```

GoTrue refuses on the signup switch **before** it validates a password, so
there is no request that distinguishes a 12-character floor from a 6-character
one. `/auth/v1/settings` does not report it either. A scanner cannot report the
password policy of this target in either direction, and must not guess — which
is recorded under `expect.unverified` rather than quietly asserted.

### 2. The same `42501` is a 401 to `anon` and a 403 to an account

`billing_internal` holds no grant for either role, so both requests fail the
identical way in Postgres — `permission denied for table billing_internal`,
SQLSTATE `42501`. PostgREST maps it to two different statuses:

```
GET /rest/v1/billing_internal   anon token           -> 401
GET /rest/v1/billing_internal   authenticated token  -> 403
```

A scanner keyed on the status rather than the SQLSTATE will classify the same
refusal two different ways depending on which token it happened to send. The
answer key records the anon status (`read_status: 401`) *and* the SQLSTATE
(`read_sqlstate: "42501"`) so the distinction cannot be lost.

The same thing happens in GoTrue: `POST /auth/v1/invite` answers `401
no_authorization` when only an `apikey` header is sent, and `403 not_admin`
when the same token is also sent as `Authorization: Bearer` — which is what
`lib/check.py` does. The status is decided by the client's header habits, not
by the target. The answer key records the value the checker actually measures
and says why.

### 3. Defining `auth.uid()` yourself kills the gateway

The natural way to write a per-user policy is `USING (owner_id = auth.uid())`,
and the natural way to get `auth.uid()` into a self-hosted stack is to define
it in `initdb`. Doing that produced this:

```
auth-1    | {"level":"fatal","msg":"running db migrations: error executing
             /usr/local/etc/auth/migrations/00_init_auth_schema.up.sql …
             : ERROR: must be owner of function uid (SQLSTATE 42501)"}
gateway-1 | nginx: [emerg] host not found in upstream "auth" in
             /etc/nginx/conf.d/default.conf:23
```

GoTrue creates `auth.uid()` itself, owned by `supabase_auth_admin`. A function
of that name owned by `postgres` makes its `CREATE OR REPLACE` fail, the
container exits — **and then nginx exits too**, because nginx resolves a
literal `proxy_pass` upstream at config-load time. The visible symptom names
neither Postgres nor ownership. Two fixes, both in the tree: the policy helper
is called `auth.request_sub()` and lives beside GoTrue's function rather than
on top of it, and the gateway waits on `auth: {condition: service_healthy}`.

A related near-miss worth recording: GoTrue's *first* migration defines
`auth.uid()` reading only `current_setting('request.jwt.claim.sub')`, the
**legacy** GUC name, which PostgREST sets only under
`PGRST_DB_USE_LEGACY_GUCS=true`. A later migration replaces it with a `coalesce`
over both names, which is why it works here — asserted in the answer key so a
version that ships only the legacy branch fails a claim instead of silently
turning both owner-scoped tables into deny-all. That failure mode is *safe*, so
it would never have appeared as an exposure; it would have appeared as this
project claiming to test a per-user policy while testing nothing.

## Layout

The MANAGED shape: one origin, real services behind it.

- Gateway: `http://127.0.0.1:54411` — `/rest/v1/` → PostgREST, `/auth/v1/` →
  GoTrue, `/storage/v1/` → refusing stubs
- Postgres: `127.0.0.1:54412`, database `fixture`, user `postgres`
- PostgREST and GoTrue publish **no host port**. `docker compose port rest 3000`
  returns no mapping.

`/storage/v1` is served by the gateway, not by `storage-api`. The reason is in
`gateway.conf` and in `expect.unverified`: the real service switches database
role per request and a role-level `search_path` is applied at LOGIN rather than
on `SET ROLE`, so its own tables stop resolving in this arrangement — the same
trade `fixtures/lab/gateway.conf` records. The responses are what a scanner
reasons about and those are real; no claim in this project should be read as
evidence about `storage-api` itself.

## Running it

```sh
cd benchmark/corpus/02-hardened && docker compose up -d --wait
../verify.sh --no-up 02-hardened
```

No `setup.sh`: nothing in this project's verification creates a row that
survives it, because every write it attempts is refused. Row counts return to
5 / 3 / 3 / 3 / 4, and the verifier is run twice during development to confirm
they do. Both runs report `all 102 claims held`.
