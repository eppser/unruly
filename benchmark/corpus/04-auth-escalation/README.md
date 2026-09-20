# 04 — invisible to `anon`, public to anyone who signs up

## What this target is for

**The one property it measures that no other project does: an anon-only scan
reports this target PROTECTED and the correct answer is PUBLIC.**

Every one of the five relations answers `anon` with HTTP `200` and `[]`. Four
of the five hand every row to any token carrying `role=authenticated`, and the
GoTrue on this origin issues one of those to anybody who sends a single HTTP
request — with an email address nobody checks, or with no email at all.

**The Postgres side of this project is not misconfigured.** Read the DDL on its
own and it looks careful: RLS on every table, a policy on every table, every
policy naming a role, `anon` named by none of them. The answer key asserts all
of that. The exposure is one setting in a different service.

## The escalation, end to end

Verified by hand. `$ANON` is the project's anon key; nothing else was held at
the start.

```
### step 0 — anon, holding only the anon key
$ curl -s -H "apikey: $ANON" "$G/rest/v1/employee_salaries?select=full_name,annual_salary_cents"
[]

### step 1 — sign up. six-character password, an address nobody checks
$ curl -s -X POST -H "Content-Type: application/json" \
    -d '{"email":"stranger@example.invalid","password":"hunter"}' "$G/auth/v1/signup"
  access_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...
  expires_in:   3600
  user.email_confirmed_at: 2026-08-19T02:10:35.173727057Z
  user.is_anonymous: False

### step 2 — what the token claims
{'aud': 'authenticated', 'role': 'authenticated',
 'sub': 'eb033540-90b1-41e7-9c5a-5e5e3b9476c3',
 'email': 'stranger@example.invalid', 'is_anonymous': False}

### step 3 — the same request as step 0, with the new token
$ curl -s -H "Authorization: Bearer $TOK" \
    "$G/rest/v1/employee_salaries?select=full_name,annual_salary_cents,national_id_last4"
[{"full_name":"Dana Whitfield","annual_salary_cents":24500000,"national_id_last4":"4417"},
 {"full_name":"Marcus Oyelaran","annual_salary_cents":19800000,"national_id_last4":"8830"},
 {"full_name":"Priya Raghunathan","annual_salary_cents":21200000,"national_id_last4":"1176"},
 {"full_name":"Tomas Berg","annual_salary_cents":11400000,"national_id_last4":"5502"},
 {"full_name":"Elena Marchetti","annual_salary_cents":13900000,"national_id_last4":"6694"},
 {"full_name":"Ops Shared Account","annual_salary_cents":0,"national_id_last4":null}]

$ curl -s -H "Authorization: Bearer $TOK" "$G/rest/v1/health_notes?select=full_name,diagnosis"
[{"full_name":"Dana Whitfield","diagnosis":"Type 2 diabetes"},
 {"full_name":"Marcus Oyelaran","diagnosis":"Generalised anxiety"},
 {"full_name":"Priya Raghunathan","diagnosis":"Hypertension"},
 {"full_name":"Tomas Berg","diagnosis":"Seasonal asthma"}]

$ curl -s -H "Authorization: Bearer $TOK" \
    "$G/rest/v1/internal_directory?select=full_name,home_address,mobile_number"
[{"full_name":"Dana Whitfield","home_address":"12 Fictional Street, Nowhere NW1 1AA","mobile_number":"+1-555-0401"},
 … 5 rows …]

$ curl -s -H "Authorization: Bearer $TOK" "$G/rest/v1/my_payslips?select=period,net_cents"
[]

### step 4 — the same, with NO email at all
$ curl -s -X POST -H "Content-Type: application/json" -d '{}' "$G/auth/v1/signup"
  user.email: ''  user.is_anonymous: True
$ curl -s -H "Authorization: Bearer $ATOK" "$G/rest/v1/health_notes?select=full_name,diagnosis"
[{"full_name":"Dana Whitfield","diagnosis":"Type 2 diabetes"},
 {"full_name":"Marcus Oyelaran","diagnosis":"Generalised anxiety"},
 {"full_name":"Priya Raghunathan","diagnosis":"Hypertension"},
 {"full_name":"Tomas Berg","diagnosis":"Seasonal asthma"}]
```

Elapsed cost of the escalation: one POST. No mailbox, no password of any
quality, and in step 4 no identity at all.

This chain **is now measured on every run**, and the history of how it got
there is worth keeping. It first went into the answer key under
`expect.unverified` with `why: verified by hand, see README; the checker cannot
chain a token between requests` — `lib/check.py` bound either the anon key or
the one authenticated key from the environment, and `expect.checks` had no way
to say "take `access_token` out of the previous response". So the strongest
claim this project makes was an assertion in a file rather than a measurement,
which is precisely the state the corpus exists to prevent.

The checker now supports `capture:` and `${var}`, so the signup check pulls the
`access_token` out of GoTrue's response and four later checks send it:

```
PASS  signup with a six-character password ... [capture signupToken]   777 chars
PASS  the signup token reads every salary            'salary_cents' in body
PASS  the signup token reads the health notes        'diagnosis' in body
PASS  the signup token reads the internal directory  'home_address' in body
PASS  the same signup token reads NOTHING from the owner-scoped relation  '[]'
```

The last line is the one that makes the other three mean something. Without a
control on the *same* token in the *same* run, "a logged-in user sees more" is
true of every correctly configured project in existence.

`setup.sh` still replays the chain before every run and exits nonzero if it
breaks, which is now belt and braces rather than the only enforcement.

## The relations

| relation | policy | anon | any account | why it is here |
|---|---|---|---|---|
| `employee_salaries` | `FOR SELECT TO authenticated USING (true)` | `200 []` | **all 6** | salaries, national-ID and bank fragments |
| `health_notes` | same | `200 []` | **all 4** | clinical data — impact is a separate axis from exposure |
| `internal_directory` | same | `200 []` | **all 5** | home addresses, personal mobiles, next of kin |
| `device_inventory` | same | `200 []` | **all 5** | same exposure, **low impact**, so "authenticated-visible ⇒ critical" is falsifiable |
| `my_payslips` | `USING (owner_id = auth.request_sub())` | `200 []` | **0** | **the control** |

`my_payslips` carries the same RLS bit, the same `TO authenticated`, and the
same grants as the four above. Its rows are owned by uuids no token in this
corpus carries and no signup can produce — GoTrue assigns each new account a
fresh random uuid — so a stranger who signs up gains nothing there no matter
how many times they try. **A scanner that reports it alongside the other four
is wrong about it,** and without it the escalation finding would be vacuous.

Privileges are uniform and generous on purpose (5 tables × 4 verbs × 2 roles =
40 grant tuples, asserted). `anon` holds exactly the same grants as
`authenticated` and still sees nothing, because no policy names it. That is
precisely why an anon-only scan reports this project clean.

## GoTrue, measured over HTTP

```
"anonymous_users":true … "disable_signup":false,"mailer_autoconfirm":true
```

| request | status | body |
|---|---|---|
| signup, password `abcdef` (6) | `200` | `access_token`, `email_confirmed_at` set |
| signup, password `abcde` (5) | `422` | `weak_password`, "Password should be at least 6 characters." |
| signup, password `a` (1) | `422` | same |
| `POST /signup` `{}` | `200` | `"is_anonymous":true` |
| `POST /signup` `{"data":{}}` | `200` | `"is_anonymous":true` |
| `POST /token?grant_type=anonymous` | `400` | `unsupported_grant_type` |
| `GET /admin/users` (anon or account) | `403` | `not_admin` |

The password floor is **exactly 6**, which is where `GOTRUE_PASSWORD_MIN_LENGTH`
put it. Note that `/auth/v1/settings` does not report the password policy at
all — the refusal message is the only place a scanner can read it, so finding
the floor requires deliberately sending a bad password.

## What a correct scanner must report

- `employee_salaries`, `health_notes`, `internal_directory`, `device_inventory`
  are **effectively public**, not protected. The anon probe's `200 []` is not
  evidence of protection on this target.
- Signup is open, autoconfirm is on, anonymous sign-in is on, the password
  floor is 6 — and the four together are what make the paragraph above true.
  Any one of them alone is a weaker finding.
- Rank `health_notes` and `internal_directory` above `device_inventory`. All
  three are equally reachable.

## What a correct scanner must NOT report

- `my_payslips` is not an escalation. It is the one relation here that is
  configured the way all five should be.
- No relation accepts a write from anybody. `anon` gets `401` `42501`, and a
  freshly created account gets `403` `42501` — measured, on `employee_salaries`
  with a real signup token. There are no `INSERT`, `UPDATE` or `DELETE`
  policies anywhere in this project.

## The thing that surprised us

### 1. `{"data":{}}` is also an anonymous sign-in

The anonymous endpoint was expected to be `POST /signup` with a strictly empty
body, and `{"data":{}}` was expected to be something else — a signup missing
its required fields, refused. It is not:

```
POST /auth/v1/signup  {}            -> 200, "is_anonymous":true
POST /auth/v1/signup  {"data":{}}   -> 200, "is_anonymous":true
POST /auth/v1/token?grant_type=anonymous {} -> 400 unsupported_grant_type
```

GoTrue v2.151 branches on the **absence of `email` and `phone`**, not on the
presence of any particular field, so *any* signup body without those two is an
anonymous sign-in. There is no separate endpoint and no grant type. A scanner
probing for anonymous sign-in by looking for a dedicated route will not find
one, and a scanner that sends `POST /signup` with an incomplete body while
testing something else will create an account without meaning to.

### 2. The two halves of the finding are measured by different things, and only one is in the answer key

`authenticated_read_exposed: true` sounds like "a stranger can read this". What
`lib/check.py` measures is narrower: it sends the corpus's own authenticated
token, which `fixtures/mint-jwt.py` signs offline and which never passes
through GoTrue. That establishes the **policy** admits any `role=authenticated`
token. It says nothing about whether such a token is obtainable.

Project 02 produces the byte-identical signature — `read_exposed: false`,
`authenticated_read_exposed: true` — from two **correctly scoped** tables with
signup switched off. The two projects are indistinguishable on that field
alone. Everything that separates them lives in the GoTrue checks and in the
`setup.sh` transcript, and the answer key says so under `expect.unverified`
rather than letting one boolean carry a claim it cannot support.

### 3. A rerun of an honest answer key can fail on its own success

This project's checks **create accounts** — that is the finding. The first run
of the six-character signup check returns `200`; the second returns `422
user_already_exists`, and the anonymous sign-in check leaves a fresh row behind
every single time. An answer key that measures account creation is not
idempotent by construction, so `setup.sh` truncates `auth.users` before each
run, which also makes "no account exists before the scan" a real, single-SELECT
claim rather than a hope.

## Layout

- Gateway: `http://127.0.0.1:54431` — `/rest/v1/` → PostgREST, `/auth/v1/` →
  GoTrue. Both are real services; nothing on this origin is stubbed, because
  the whole point is that a token from one is accepted by the other.
- GoTrue also published directly on `http://127.0.0.1:54433`, so the auth
  surface can be driven by hand without reasoning about the proxy. The answer
  key checks `/settings` on both.
- Postgres: `127.0.0.1:54432`, database `fixture`, user `postgres`

## Running it

```sh
cd benchmark/corpus/04-auth-escalation && docker compose up -d --wait
../verify.sh --no-up 04-auth-escalation
```

`setup.sh` runs first: it truncates `auth.users`, replays the escalation as
three real HTTP requests and fails the project if the chain breaks, then
truncates again so the checks start from zero accounts. Both runs report
`all 103 claims held`.
