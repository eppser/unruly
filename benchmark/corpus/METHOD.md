# How ground truth was established

This file exists because the corpus is only worth what its answer keys are
worth, and an answer key is a hypothesis until something has gone and looked.
What follows is what was checked, how, and — the part that matters most — what
was **not** checked and why.

## The rule

**No claim in any answer key was derived from the DDL.** Every one of them is
re-derived from the running stack by `lib/check.py`, which the corpus's own
`verify.sh` runs. Specifically:

| claim | where the answer comes from |
|---|---|
| `rows` | `psql` inside the container: `SELECT count(*) FROM <rel>` |
| `sensitive_columns` | `information_schema.columns` — the column **exists**; see the limits section for what this does not establish |
| `read_exposed` | an anonymous HTTP `GET ?select=*&limit=1`; true only if at least one row comes back |
| `read_status`, `read_sqlstate` | the status line and the `code` field of the body |
| `authenticated_read_exposed` | the same GET carrying an `authenticated` JWT |
| `insert_reachable` | a real anonymous `POST`, judged by whether the row count moved or the SQLSTATE shows a data constraint was reached |
| `update_reachable` | a real anonymous `PATCH` against a marker row, judged by re-reading the column with `psql` |
| `delete_reachable` | a real anonymous `DELETE` against a marker row, judged by re-counting with `psql` |
| everything else | `expect.checks` (raw HTTP) and `expect.psql` (raw SQL), both spelled out in the key |

The scanner was never run against any of these targets, and no part of its
detection code (`internal/probe`, `internal/enumerate`, `internal/surface`,
`internal/provider`, `internal/classify`, `internal/discover`,
`internal/routes`, `internal/postgrest`) was read while designing them. A
benchmark built by reading the tool measures only whether the tool agrees with
itself.

## Why writes are performed rather than inferred

The cheap way to test DELETE without destroying data is a filter that matches
nothing, and to call `204` "reachable". That is wrong, and it is wrong in the
direction that inflates a scanner's apparent recall:

> A table with RLS enabled and **no policy** also answers `204`, because zero
> rows matched and Postgres never had to refuse anything.

The no-match probe cannot distinguish "you may delete" from "there was nothing
to delete". So every write claim in this corpus is measured against a row that
provably exists: `psql` inserts a marker as superuser, the write is performed
over HTTP exactly as a stranger would perform it, the result is read back out
of the database, and the marker is removed. Row counts return to their pinned
values, and `verify.sh` is run twice during development to confirm they do.

The same reasoning applies to INSERT. A `POST {}` that comes back `400` with
SQLSTATE `23502` (not-null violation) means the write was **permitted** and
then failed a data constraint — a check constraint is only evaluated for a
write that already passed the security layer. Treating that as "refused" would
under-report. The classification lives in `CONSTRAINT_CODES` and
`DENIED_CODES` in `lib/check.py`, and it is stated there rather than buried.

## Things the running stack said that the DDL did not

These are the reason the rule exists. Each was found by measurement, and each
is asserted in the relevant answer key so it stays found.

1. **PostgREST's OpenAPI document lists only what the requesting role can
   touch.** (project 01) A table protected by `REVOKE` is absent from the
   document while a direct `GET` answers `401` and names it in the error body.
   The cheap discovery path systematically misses exactly the relations that
   `REVOKE` protects. Enumeration and exposure are different lists.

2. **PostgREST answers `503 PGRST002` for a window after startup**, while it
   builds its schema cache. `docker compose up --wait` does not cover it: the
   container is healthy, the port is open, and every probe gets a 503 that
   names no relation and no error a scanner is looking for. A project verified
   against a warm stack passed; the identical key from a cold start failed 23
   of 35 claims. The implication is not about the harness — it is that a scan
   begun right after a deploy gets a clean report for a database it never read.
   `lib/check.py` now waits this out, keyed on the `PGRST002` body specifically.

3. **The Firebase Realtime Database emulator invents namespaces.** (project 14)
   `?ns=<anything>` creates that namespace on demand with default rules of
   `{".read": true, ".write": true}`. Probing with the wrong namespace finds a
   wide-open database that never existed. The rules file loads onto
   `<project>-default-rtdb`, not onto the project id.

4. **Realtime Database rules cascade downward and cannot be revoked deeper.**
   (project 14) `open_chat/private_dm` carries `".read": false` and is readable
   anyway, because its parent granted the subtree. Measured, not quoted.

5. **A proxy that rewrites 4xx bodies does not close the existence oracle.**
   (project 07) Three side channels survived a configuration written
   specifically to destroy the distinction between "forbidden" and "absent":
   forwarded `WWW-Authenticate` headers, a `400 PGRST204` that `error_page` did
   not name, and `OPTIONS`. The configuration was left as written rather than
   patched, because recording what a configuration *does* is worth more than
   recording what it was *for*.

6. **nginx resolves upstream hostnames at config-load time.** (project 06)
   `proxy_pass http://nosuchhost:3000;` makes the container refuse to start,
   which would have collapsed the "answers 502" mode into the "nothing
   listening" mode and quietly reduced three distinct failure shapes to two.

7. **`return 444` does not arrive as a `URLError`.** (project 06)
   `http.client.RemoteDisconnected` propagates out of `urlopen` uncaught. The
   mode built to look alive to a liveness check is also the one most likely to
   crash a client written straight from the `urllib` documentation.

8. **PostgREST omits `definitions` entirely from the OpenAPI document when a
   schema has zero relations** (project 05) — not `"definitions":{}`. Any
   consumer that indexes it raises on that one target and no other.

9. **`firebase-tools` reports a read-only working directory as "An unexpected
   error has occurred."** with no path and no permission named. (project 14)

10. **`FOR DELETE USING (true)` does not make a *filtered* delete work.**
    (project 03) `DELETE ?id=eq.<an existing row>` answers `204` and the row is
    still there; `DELETE` with no filter answers `204` and takes all six rows.
    Postgres applies SELECT **policies** to columns referenced in a
    `DELETE`'s `WHERE`, and with no SELECT policy the filter matches nothing.
    An unfiltered `DELETE` against two other relations in the same project also
    answers `204` and loses nothing, so on this shape the status code carries
    no information at all — only the row count does.

11. **`FOR INSERT WITH CHECK (true)` is invisible to a probe that asks for the
    row back.** (project 03) `Prefer: return=minimal` gets `201` and the row
    commits. `return=representation` gets
    `401 42501 "new row violates row-level security policy"` — the `RETURNING`
    is refused, not the `INSERT`, and the message names the wrong half. This
    corpus's own checker had that bug: it hardcoded `return=representation` and
    recorded a genuinely writable public submission form as not writable. Fixed
    by sending PostgREST's own default. **A write probe that asks for the row
    back is testing two privileges and reporting one.**

12. **Turning the OpenAPI document off makes discovery leak more, not less.**
    (project 09) `PGRST_OPENAPI_MODE: disabled` closes the bulk listing, but
    PostgREST's per-name `404 PGRST205` still carries a fuzzy-match hint
    (`GET /tbl_0e1eb48` → "Perhaps you meant the table
    'public.tbl_0e1eb483'"), and unlike the OpenAPI document that hint does
    **not** follow privileges. `GET /profile` names `profiles`, which holds no
    grant for `anon` and which project 01 measured as absent from the document.
    Project 12 found the same channel turning singular guesses into real names
    (`/team` → `team_members`).

13. **An invalid `Accept-Profile` enumerates every exposed schema.**
    (project 11) `406 PGRST106` carries
    `"Only the following schemas are exposed: public, api, legacy, reporting"`.
    One request with a nonsense header replaces schema discovery.

14. **A view over an RLS-protected table returns the rows the table refuses.**
    (project 11) `security_invoker` defaults to false, so the view runs as its
    owner, and RLS does not apply to a table's owner. "The table answers `[]`"
    is not a statement about the data.

15. **Two relations can be indistinguishable in an error message.**
    (project 10) An NFD-normalised table's 401 renders as
    `permission denied for table café_registro`, byte-different from and
    visually identical to a *readable* NFC table of the same displayed name.
    Deduplicating a relation list by displayed name merges two relations in
    opposite exposure states. Relatedly, `lower()` on `pg_class.relname` does
    not fold an umlaut — `relname` is type `name` with `C` collation and the
    cast carries it — so a case-folding pass silently sees one relation where
    there are two.

16. **PostgREST 14.3 double-encodes non-ASCII column names in
    `Content-Location`.** (project 10) `番号` comes back as its UTF-8 bytes read
    as Latin-1 and re-encoded; following the URL the server itself emitted
    gives `400 42703 "column 顧客.ç does not exist"`.

17. **The same `42501` is `401` to `anon` and `403` to a named role.**
    (projects 02, 11, 13) The status is decided by the client's header habits,
    not by the target. A scanner keying "protected" on `401` will read a
    project differently depending on whether it sent a JWT.

18. **`EXECUTE` on a new function defaults to `PUBLIC`.** (project 13) Without
    an explicit `REVOKE ... FROM PUBLIC`, the "routine that exists and is not
    callable" control would not have existed at all. Related: `REVOKE` hides a
    routine from OpenAPI and **not** from the 404 hint, which names routines
    from the schema cache rather than from privileges.

19. **Defining `auth.uid()` yourself kills the stack, and the error names
    neither Postgres nor ownership.** (project 04) GoTrue creates it owned by
    `supabase_auth_admin`; a `postgres`-owned one makes its migration fail with
    `must be owner of function uid`, the auth container exits, and nginx then
    exits too with `host not found in upstream "auth"`.

20. **The verifier was itself over the rate limit and passed anyway.**
    (project 08) `lib/check.py` issues 22 requests in 4.1s — 5.4 r/s against a
    5 r/s cap — and five green runs at `burst=8` were the burst queue absorbing
    a steady overdraft rather than the target being fast enough. The burst was
    raised to 12 for that reason and the nginx conf says so, so nobody reverts
    it.

## What was NOT verified

Stated plainly, because unverified claims presented as measured are the exact
failure this corpus exists to avoid.

- **"Sensitive" is a human judgement.** The checker verifies that every column
  named in `sensitive_columns` *exists*, and that the values are present in a
  response body where the key says so. It does not and cannot verify that a
  column is sensitive. That classification is the author's, stated in each
  project's README, and a scanner disagreeing with it is a disagreement about
  taste as much as about detection.

- **Universal negatives are sampled, not proved.** "No relation is reachable
  under any name" (project 05) and "no fourth side channel exists"
  (project 07) cannot be established over HTTP. Where the same claim is
  decidable inside the database it is asserted there instead
  (`pg_class` counts via `psql`); otherwise it is recorded under
  `expect.unverified` with the sampling that *was* done.

- **Claims about a scanner's verdict are not claims about a target.** "The
  correct answer here is *unmeasured*, not *clean*" (project 06) and "this
  target is non-discriminating for existence" (project 07) describe a report,
  not a host. The engine observes hosts. Those claims live in
  `expect.unverified` and in the project READMEs, and grading them is the
  benchmark harness's job.

- **Emulator behaviour is not production behaviour.** The Firebase project's
  403 bodies name the failing rule line (`"false for 'list' @ L30"`) and
  distinguish an explicit deny from a collection with no rule
  (`"No matching allow statements"`). A live Google project returns a generic
  `PERMISSION_DENIED`. A scanner tuned to the emulator's wording would score
  well here and find nothing in production. This is the corpus's sharpest
  fixture-versus-reality divergence and it is recorded in project 14's key
  rather than glossed over. Nobody stood up a real Google project to compare,
  because the corpus authorises only targets we own.

- **Byte-level response identity** could not be asserted by the engine, which
  has no "response A equals response B" primitive. Project 07 asserts the two
  halves separately and records the by-hand comparison it did instead.

- **TCP-level behaviour** is asserted indirectly. The checker speaks HTTP, so
  "the handshake completed on 54452" is inferred from getting
  `RemoteDisconnected` rather than `Connection refused`; a direct socket test
  was run by hand during development and is recorded as such.

- **Timing-dependent targets are pinned where they are stable.** The
  rate-limited project's HTTP answers depend on request rate, so its row counts
  and relation list are pinned with `psql` (which is not rate limited) and its
  HTTP behaviour is asserted with `expect_status_in` rather than a single code.
  Any single number quoted for its throttle is a measurement of one run, and
  the README quotes more than one for that reason.

- **`GOTRUE_PASSWORD_MIN_LENGTH=12` on the hardened project is unobservable
  from outside.** A 5-character password, an absent password field and
  `POST /otp` all return an identical `422 signup_disabled`: GoTrue refuses on
  the signup switch before it validates a password, and `/settings` does not
  report the policy at all. So the hardened project's password floor is set and
  cannot be measured, and a scanner cannot report it either way. The only place
  the floor is readable anywhere is the `weak_password` refusal on project 04,
  which requires deliberately sending a bad password.

- **"PostgREST is unreachable except through the gateway"** (project 02) is
  established only as an absence — no port mapping in the compose file. The
  checker cannot express negative reachability.

- **The rate-limited project's refused SET is not asserted**, only its size
  distribution. A per-claim harness cannot say "the membership of the resolved
  set varies between runs"; that was measured by hand with a committed script
  and the numbers are in the project README.

- **The injectable routine's behaviour if declared `VOLATILE`** (project 13) is
  not known, because it was deliberately not built that way. The routine is
  `STABLE`, and PL/pgSQL refuses writes from a non-volatile function — measured
  as `400 0A000 "DELETE is not allowed in a non-volatile function"`, not
  assumed. A fixture a README reader can drop is a fixture that gets dropped.

- **Nothing here was scanned that we do not own.** No third-party project was
  touched. `~/supabase-prospects/final_10000.csv` is a prospect list and is not
  authorisation; it was not read. The `the reference target` project
  (`examplerefexampleref`) is excluded from the corpus entirely and was not
  scanned.

21. **`verify.sh` with no arguments checked nothing and said so in two lines of
    shell error.** macOS ships bash 3.2, which has no `mapfile`, and `set -u`
    then tripped on the empty array. Every project had been verified
    individually, so the whole-corpus run was the last thing tried, and it is
    the same failure the corpus is about: a tool that did not look, reporting
    something other than "I did not look". Now written portably, with an
    explicit exit 2 when the project list comes out empty.

## The run this file describes

Whole corpus, cold: each project brought up from nothing, checked, and torn
down with `docker compose down -v` before the next.

```
$ ./verify.sh
01-rls-off-crud            all  53 claims held
02-hardened                all 102 claims held
03-policy-shapes           all 104 claims held
04-auth-escalation         all 112 claims held
05-empty-project           all  35 claims held
06-unreachable             all  28 claims held
07-rewriting-proxy         all  69 claims held
08-rate-limited            all  55 claims held
09-huge-schema             all 148 claims held
10-nonlatin-names          all 125 claims held
11-multi-schema            all  85 claims held
12-content-vs-jsonb        all  77 claims held
13-rpc-security-definer    all  79 claims held
14-firebase                all  40 claims held
passed: 14   failed: 0
```

1,112 claims at the time of that run; 1,204 across sixteen projects as of
2026-08-23, of which 1,193 hold — see README.md for the eleven that do not and
why. Every project was also verified at least twice — once while it
was being built and once cold afterwards — because the second run is where the
`PGRST002` race, the bash 3.2 breakage and the `return=representation` probe
bug all turned up.

## What project 16 found, including about this method

`16-data-classification` was added on 2026-08-23 to measure a property nothing
else did: not whether a relation is reachable, but what the report says is IN
it. Two things came out of building it.

**The rule that answer keys are written without running the scanner earned its
keep, by being wrong.** The key expected `gehaltsdaten` — the German-named
table whose column names match no English pattern — to be classified
`[contact, financial]`, reasoning that its `notiz` column holds an email
address. The scan reported `financial` only, and the scan was right, for two
independent and deliberate reasons: the value classifier's email pattern is
anchored `^...$`, because an address that IS a field's value is a record about
a person while one mentioned inside a sentence is prose; and `.invalid` is on
the reserved-domain list precisely so that seed and demo data are not reported
as somebody's contact details.

The key moved, not the code. The point is that the disagreement was visible at
all — an answer key derived from the scanner's own output would have recorded
`[financial]` and called it agreement.

**And it exposed a limit of the corpus method itself.** `contact`-by-VALUE
cannot be exercised anywhere in this corpus and cannot be added. Testing it
needs an email address as a field's whole value at a domain that is NOT
reserved — and every domain safe to commit to a public repository is a reserved
domain. The alternative is committing an address at a domain that could belong
to somebody. So that one cell is untested, deliberately, and this paragraph is
the record of it rather than an absence nobody notices.

## Reproducing any of it

```sh
cd benchmark/corpus
./verify.sh                  # every project, cold: up, check, down
./verify.sh 01-rls-off-crud  # one
./verify.sh --keep 03-policy-shapes   # leave it running to poke at
./verify.sh --no-up 03-policy-shapes  # it is already running
```

Each run writes `evidence.jsonl` into the project directory: the status codes,
SQLSTATEs and before/after row counts behind every verdict. It is gitignored,
because a stale copy in the tree would read as evidence for claims nobody
re-ran.

Answer keys are parsed by `lib/yamlite.py`, a deliberately narrow YAML subset
reader that raises on anything it does not understand. PyYAML is not installed
on the machine this was built on and a `pip install` in the verification path
would mean the honesty check does not run offline. A parser that silently skips
what it cannot parse turns a typo in an answer key into a check that quietly
stops running.
