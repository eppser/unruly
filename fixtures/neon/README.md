# Neon Data API lab fixture

Project `<neon-project-id>` ("unruly"), branch `production`.
Synthetic data only. Six tables: three exploitable, three protected.

Ground truth is in `answer-key.yaml`; `transcript.json` is a recording of the
live endpoint that `make eval-neon` replays offline.

## Accounts this fixture leaves behind

Declared rather than hidden. All three are stable and reused, never churned:

| account | created by | why it exists |
|---|---|---|
| `unruly-recorder@example.com` | `internal/eval/neon_record_live_test.go` | re-records `transcript.json` |
| `unruly-exploit@example.com` | `internal/exploit/neon.go` | the independent harness |
| `unruly-crosscheck@example.com` | `backend/neon/crosscheck_test.go` | the scanner side of the cross-check |

Sign-up on this project is open and unverified, which is not an oversight: it
is what makes the escalation reachable by a stranger, and therefore what the
finding is about.

## Seed row counts

Restore these after any write probe:

    anon_readable 2, open_guestbook 1, rls_disabled 3, rls_enforced 2

## Configuration that is not obvious

The Data API's `auth_provider` must be **`neon_auth`** -- an undocumented
value. It binds validation to keys held in `neon_auth.jwks` inside the
database. External JWKS URLs are accepted by the API, never reflected back,
and every token is then refused with `jwk not found`, because the compute
cannot fetch them.

Tokens come from the Neon Auth service, whose URL uses `neonauth` (not `auth`)
in the hostname and is only shown in the console. Three steps, each of which
fails quietly if got wrong:

1. `POST {auth}/sign-up/email` — **must** carry an `Origin` header, or the
   answer is `MISSING_ORIGIN` and no account is created.
2. `POST {auth}/sign-in/email` — the session comes back as a **cookie**.
3. `GET {auth}/token` — send the cookie. A bearer is refused with 401.

## Probe residue: sessions accumulate, accounts do not

Step 2 above writes a row to `neon_auth.session` on **every** run. Nothing
removed them, and by the time anybody counted there were **102**, against six
probe accounts.

The accounts themselves do not accumulate: the evals sign in as fixed
addresses, so a repeat sign-up is refused and falls through to sign-in. That
was a design choice worth keeping — six rows in `neon_auth."user"` and six in
`neon_auth.account`, stable across runs, alongside the project owner.

Sessions were the part that grew, which makes them residue: precisely what this
scanner reports as `unruly-probe-object-left-behind` when it finds it in
someone else's project. Clean them with

    make neon-prune

which deletes sessions belonging to `neonfixture.ProbeAccounts()` and nothing
else. It refuses an unscoped delete, because removing every session would sign
the owner out of their own project — a property covered by unit tests rather
than by the live run, since the owner had no session row at all (the console
authenticates separately). It verifies the fixture's seed counts before and
after, and skips rather than pruning if the lab has already drifted.

Measured: 102 sessions before, 0 after, 7 users unchanged,
`anon_readable 2, open_guestbook 1, rls_disabled 3, rls_enforced 2` unchanged.
