# 08 — a real rate limit in front of a real PostgREST

## What this target is for

**The one property it measures that no other project does: 429 arrives as a
function of REQUEST RATE, not of which relation was asked for. The relation
list a scan produces here is a lower bound, and a correct scanner has to say
so.**

There is already a fixture in this repository, `fixtures/lab/throttled.conf`,
that returns 429 for four hard-coded relation names in front of nothing. That
is a mock of the symptom and it is deterministic: probe `users`, get 429,
every time. This is the other thing. `nginx` `limit_req_zone` at 5r/s with a
burst queue of 12, `limit_req_status 429`, and a genuine PostgREST over a
genuine 30-relation schema behind it. The same path answers 200 or 429
depending on the previous 200 milliseconds, so **the same scan run twice
produces two different relation lists**.

## Measured throttle behaviour

All numbers from `./measure-scan.sh`, which fires one probe at each of the 30
relation names as fast as the shell can start `curl`s.

```
### two cold runs, four seconds apart, identical command
probed 30  answered 13  refused-429 17
  resolved: api_tokens audit_events coupons customers employee_records
            feature_flags inventory payment_cards session_store
            support_tickets user_credentials warehouses webhook_secrets

probed 30  answered 13  refused-429 17
  resolved: api_tokens audit_events customers employee_records feature_flags
            inventory payment_cards session_store shipments support_tickets
            user_credentials warehouses webhook_secrets
```

Same count, **different set**: `coupons` resolved in the first run and
`shipments` in the second. Across six cold runs the count held at 13 while the
membership moved — `coupons` once, `shipments` twice, `categories` once,
`taxes` once, `session_store` in five of the six.

```
### the same command again, immediately, with the bucket still empty
probed 30  answered 0  refused-429 30
```

Zero. On that run the target reads as completely unreachable — no relations, no
findings, nothing to report. It is the same host that answered thirteen probes
four seconds earlier.

```
### paced 250ms apart instead of fired in parallel
probed 30  answered 29  refused-429 1
  unresolved: customers
```

29 of 30, and the one refusal is the *first* probe, which arrived while the
bucket was still draining from the previous run. So the answer to "how many
relations does this target have" is 0, or 13, or 29, depending entirely on how
the question was asked.

`./measure-throttle.sh 60` fires 60 requests at a single path: 9 through, 51
refused at burst=8; 13 through, 47 refused at burst=12.

## How the answer key handles that

This key is written differently from every other one in the corpus:

- **Ground truth comes from `psql` on `127.0.0.1:54472`**, which talks to the
  database directly and never passes the limiter. Row counts, grant counts,
  RLS state, the total relation count — all of it is stable because none of it
  is HTTP.
- **Not one relation claims `read_exposed`.** `read_exposed` is computed from
  whether rows came back, and here rows fail to come back for two unrelated
  reasons: no privilege, or too fast. Asserting it would encode a coin flip as
  ground truth.
- **Every HTTP claim uses `expect_status_in` with 429 in the allowed set.**
  `[200, 206, 429]` for a readable relation, `[401, 429]` for a protected one,
  `[404, 429]` for one that does not exist. Those are the strongest *true*
  statements available about a path whose answer depends on timing.
- **What could not be pinned is in `expect.unverified`**, printed as a NOTE,
  never as a pass.

## The schema behind the limiter

30 relations. From `pg_class`, not from the DDL:

```
30  relations in public
17  carry a SELECT grant for anon
16  grant SELECT and have RLS off, so they return rows (153 rows in total)
13  hold no grant at all
 1  has RLS enabled (session_store), with 0 policies
 1  grants anon a write verb (support_tickets)
```

The content is arranged so that a partial scan is genuinely partial rather than
merely shorter: `user_credentials` (6 rows of bcrypt-shaped hashes and API
keys) and `payment_cards` (5 rows of test PANs and IBANs) are readable, while
`api_tokens`, `employee_records` and `webhook_secrets` hold the worst material
in the project behind a `REVOKE`. A scan that gets 429 on the readable pair
reports a much tamer target than one that does not.

## What a correct scanner must do

1. **Find at least some relations.** 13 of 30 is achievable from a single cold
   parallel pass.
2. **Not report the target as clean, or as absent.** The zero-relation run
   above is the trap: a run that resolves nothing is not evidence of nothing.
3. **Report the unresolved probes as unresolved.** This is the one that
   matters. A candidate that got no readable answer is indistinguishable in a
   report from one that was measured and found absent, unless something says
   so. A scanner that silently drops the 17 refusals produces a relation list
   that is wrong in a way nobody downstream can detect.

A scanner that backs off and retries should converge — paced at 250ms, 29 of 30
resolve. Whether any given scanner does that is a property of the scanner, and
this corpus does not run scanners; the point recorded here is that the target
makes the difference visible.

## The thing that surprised us

**The verifier was itself over the rate limit, and passed anyway.**

The first version of this project used `burst=8`. Every run of
`verify.sh 08-rate-limited` passed, five times in a row, which looked like
comfortable margin. It was not. `lib/check.py` issues **22 HTTP requests in
about 4.1 seconds** here — an average of **5.4 r/s**, above the configured
5 r/s. The runs passed only because the burst queue was absorbing a steady
overdraft, which is a fixture one faster machine away from being flaky in a way
that would look like a scanner bug.

The `burst` was raised to 12 for that reason and no other; it is documented in
`conf/throttle.conf` so nobody later "cleans it up" back to 8. Two things
generalise from it:

- A throttled target does not fail loudly when you are slightly too fast. It
  fails *occasionally*, on the requests that happen to land in a full bucket,
  and the ones it eats are chosen by timing rather than by importance.
- The measured request rate of your own tooling is a number worth knowing
  before you conclude anything about a rate-limited host. We did not know ours
  until we measured it, and we only measured it because the margin looked
  suspicious.

**The 429 body is not JSON.** nginx serves its own HTML error page:

```
HTTP/1.1 429 Too Many Requests
Server: nginx/1.31.3
Content-Type: text/html
Content-Length: 169

<html><head><title>429 Too Many Requests</title></head>...
```

Every other response on this host is `application/json`. A client that parses
each body as JSON gets a parse error on a refusal rather than a rate-limit
signal, and a parse error is very easy to report as "the endpoint returned
nothing". This is recorded in `expect.unverified` rather than asserted, because
`lib/check.py` sends one request at a time and cannot reliably force a refusal.

## Layout

```
client ──▶ nginx :54471 ──▶ postgrest :3000 ──▶ postgres :5432
              │                (not published)      │
              │ limit_req 5r/s burst=12             │
              └── /rest/v1/ throttled               └── published on :54472,
                  everything else: plain 404            NOT throttled
```

- Gateway: `http://127.0.0.1:54471/rest/v1/` (the managed-product shape)
- Postgres: `127.0.0.1:54472`, database `fixture`, user `postgres`
- PostgREST is **not** published. There is no unthrottled way in over HTTP.

Requests outside `/rest/v1/` hit an nginx location with no `limit_req` on it,
so `GET http://127.0.0.1:54471/customers` is a deterministic 404 — and it is
deliberately shaped like PostgREST's own `PGRST205`, so a scanner cannot
separate "wrong prefix" from "relation does not exist" by reading the body.
That is the only HTTP fact in the answer key asserted with a bare
`expect_status`.

## Running it

```sh
cd benchmark/corpus/08-rate-limited && docker compose up -d --wait
../verify.sh --no-up 08-rate-limited     # all 55 claims held
./measure-scan.sh                        # 30 probes in parallel
./measure-scan.sh 0.25                   # the same 30, paced
./measure-throttle.sh 60                 # 60 probes at one path
```

The two measure scripts are not run by `verify.sh`. They are the tools that
produced the numbers above, kept so a human can reproduce them — and so that
the next person to change `rate` or `burst` re-measures rather than guesses.
