# unruly

**Point it at a URL. It tells you what a stranger can read out of your database — and proves it with the rows.**

```bash
unruly -u https://your-app.com
```

No credentials. No dashboard access. No agent to install. unruly finds the
public key your app already ships to every browser, then asks your backend the
only question that matters: *what does this hand to someone who isn't logged
in?*

```
[supabase-anon-read-exposed] [postgrest] [critical] https://your-app.com/rest/v1/user_credentials [6 rows]
  └─ proof {"api_key":"sk_live_4f8a2b1c9d0e7f6a5b4c3d2e","email":"dana@example.invalid",
            "password_hash":"$2b$12$K8h5vQZ...","totp_secret":"JBSWY3DPEHPK3PXP"}
[supabase-anon-read-exposed] [postgrest] [critical] https://your-app.com/rest/v1/payment_methods [4 rows]
  └─ proof {"card_number":"4111111111111111","iban":"DE89370400440532013000",
            "billing_email":"customer1@example.invalid","card_expiry":"11/29"}
```

*(Real output against `benchmark/corpus/01-rls-off-crud`, a fixture with
fabricated data. Reproduce: `make benchmark`.)*

Every finding carries the rows that prove it and the `curl` line that retrieved
them. If you can't reproduce a finding by pasting its command, it isn't a
finding.

**Supabase · Firebase · Neon · PocketBase.** 72 checks. One binary, no config.

---

## Why not just use the platform's security advisor?

**Because the advisor is documented not to flag the most common real leak.**

Supabase's advisor is [`supabase/splinter`](https://github.com/supabase/splinter).
Its `0024_rls_policy_always_true` lint checks only `UPDATE` and `DELETE`:

```sql
-- Note: SELECT with (true) is often intentional and documented,
-- so we only flag UPDATE/DELETE
```

A regression test pins it, asserting **zero** findings for a policy letting
every signed-in user read every row. Neon's advisor is a fork and states the
same exclusion. Lovable's scanner uses splinter, so the largest AI app builder
inherits the blind spot.

So this passes the advisor:

```sql
CREATE POLICY "read notes" ON notes FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL);     -- every signed-in user reads every note
```

Where signup is open, "every signed-in user" is "anyone". unruly catches it by
signing in as two people and comparing what each receives:

```
[supabase-authenticated-escalation] [postgrest] [high] .../rest/v1/notes [2 rows]
  "notes" returned 2 rows to the authenticated role but none to anon.
  The policy grants access to the ROLE rather than to the owning user.
```

**Three things no database advisor can see**, because they aren't facts a
database knows about itself: a `service_role` key in a JavaScript bundle, a
reverse proxy honouring `X-Original-URL`, and an Edge Function reaching the
database with no JWT check. That's 16 of the 72 checks here.

An advisor also runs **as the project owner**. It cannot be pointed at an app
you are assessing, acquiring, or triaging. unruly needs only the URL.

## Why not just use an agent benchmark?

[Supabase Evals](https://github.com/supabase/evals) grades *agents* — which
agent writes better Supabase code. **It never sees your app.**

We ran its own cross-user-leak scenario against a frontier coding agent:

```
resolve-security-001-rls-cross-user-leak · FAIL, 3 of 5 checks
  PASS  RLS still enabled              FAIL  user A reads only own note
  PASS  user A can update own note     FAIL  user B cannot read user A note  ← leak not fixed
  PASS  WITH CHECK prevents reassignment
```

The agent fixed one bug, left the read leak, and shipped something that *looks*
secure. Pointed at the database it left behind, unruly returned the finding
above. **Upstream measurement improves the odds. It cannot tell you what
shipped.**

---

## What we found in the wild

1,000 websites from a Shodan-derived, authorization-approved sample, scanned
read-only (25 August 2026, 12.96 hours, 46.6s per site):

| | |
|---|---:|
| Sites with a high or critical finding | **331 (33.1%)** |
| Sites returning database rows to an unauthenticated caller | **306 (30.6%)** |
| Distinct exposed relations, across 294 backend hosts | **1,848** |
| Rows reachable without logging in | **≥ 9,728,627** |
| Largest single backend | **~1.75M rows** across 13 critical relations |

**What was actually exposed**, by data class, among critical findings:

| Class | Findings | Sites |
|---|---:|---:|
| Contact details | 214 | 113 |
| Location data | 130 | 76 |
| Credential-like fields | 79 | 59 |
| Other PII | 45 | 33 |
| Financial data | 17 | 14 |
| Government identifiers | 3 | 3 |
| Health data | 2 | 2 |

**Which backends, and how they failed:**

| Exposure | Findings | Sites |
|---|---:|---:|
| Supabase — anonymous relation read | 1,894 | 306 |
| Firebase — Realtime Database anonymous read | 18 | 16 |
| Firebase — Firestore anonymous read | 18 | 5 |
| Firebase — Storage anonymous read | 1 | 1 |
| Supabase — `service_role` key in public JavaScript | **2** | **2** |
| Application — auth bypass | 48 | 11 |
| Application — inconsistent route authorisation | 46 | 4 |
| Public storage bucket | 169 | 151 |
| Public signup enabled | 367 | 367 |
| Discoverable RPC routine names | 8,910 | 254 |

Two sites published a `service_role` key — the key that **bypasses row-level
security entirely**, making every policy irrelevant. That is a rotate-now
finding, and no amount of correct RLS protects against it.

**Two caveats that belong with these numbers.** The sample is Shodan-derived and
enriched for sites exposing detectable backend configuration; it characterises
the sample, not the web. And the run was read-only — anonymous `INSERT`,
`UPDATE` and `DELETE` were never tested, so write exposure there means *not
assessed*, not *safe*.

### Names are findings too

8,910 of those results are disclosed **routine and relation names** — deliberate,
not noise. unruly reports the inventory it recovers, at `info`, separately from
access:

```
[supabase-rpc-discoverable] [postgrest] [info] .../rpc/admin_reset_password   [disclosed via PostgREST hint]
[app-openapi-schema-exposed] [http]      [info] https://api.example.com/openapi.json  [41 operations named]
```

Knowing that `admin_reset_password` and `internal_billing_export` exist is how
an attacker stops guessing — and how you find the endpoints your own inventory
forgot. Every name recovered is added to the probe list, where its actual
authorisation is then tested. Rated `info` because a name is not an exposure;
kept because it is the step that makes everything after it cheap.

## Where coding agents still fail

Six agents, one Supabase app, ground truth read from `pg_class.relrowsecurity`
on the running database.

**They secure what the prompt names.** Tell an agent the schema will be reached
by a browser holding a public key and five of five write policies unasked.
Remove that one clause — same tables, same task — and **four of six emit zero
`ENABLE ROW LEVEL SECURITY` and zero policies**, leaving `api_tokens` and
`profiles` readable and writable by anyone.

Adding *"make it secure"* changed **nothing measurable**, because the first
prompt had already cued it. And an agent asked to *fix* a known leak can close
one bug, miss the other, and still look correct — the eval above is one doing
exactly that.

The failure is conditional on phrasing, not universal. Which is the argument for
verifying the deployed result instead of trusting the instruction.

---

## Use it with a coding agent

```bash
# in CI after deploy — exit 2 if anything is exposed
unruly -u https://staging.your-app.com -proven -fix

# machine-readable, for an agent to read back and act on
unruly -u https://staging.your-app.com -agent
```

`-agent` emits a versioned envelope (`unruly.agent/v1`,
[schema](docs/schema/unruly-agent-v1.schema.json)) with stable finding
fingerprints, so an agent can diff two runs and see what its own change broke.
`-fix` prints the SQL that closes each finding.

Put the cue where it cannot be forgotten:

```markdown
<!-- CLAUDE.md / AGENTS.md -->
This project uses Supabase. The anon key ships in the browser, so RLS is the
only authorization boundary. Every table in `public` gets RLS enabled plus
policies scoped to the owning user — never `USING (true)`, never
`USING (auth.uid() IS NOT NULL)`. `anon` holds no write grant anywhere.
```

Then verify, because an agent can satisfy that instruction and still leak.

### Where it is *not* the right tool

- **Not a code reviewer.** It reads a running system. For "is this migration
  correct before I apply it", use `supabase db advisors` or a static linter.
- **Not a replacement for your platform's advisor.** Run both; they overlap on
  one check and disagree on the rest.
- **Not for targets you do not own or are not authorised to test.** It sends
  real requests.
- **Not a pentest.** One class of failure: what an anonymous or
  freshly-signed-up caller reaches through the backend's own API.
- **Weakest on an empty project.** Tables with no rows have nothing to leak; use
  `-write -yes-i-own-this` on a project you own so the write probe establishes
  exposure anyway.

---

## What it checks

| Class | Checks | Example |
|---|---:|---|
| Anonymous reachability | 11 | table readable/writable with only the public key; open bucket; realtime subscription |
| Signed-in escalation | 3 | policy scoped to the role instead of the owner |
| Exposed credentials | 7 | `service_role` key in a bundle, a preview deploy, or a web archive |
| Application layer | 6 | auth bypass via rewrite header, cross-identity read, published OpenAPI spec |
| Bypass paths | 3 | GraphQL more permissive than REST; Edge Function with no JWT check |
| Auth configuration | 5 | open signup, anonymous sign-in, weak password policy |
| Inventory | 7 | relation, routine and schema names recovered |
| Coverage | 20 | what the scan could **not** measure |

**Supabase** 27 · **Firebase** 14 · **Neon** 3 · **PocketBase** 2 · **any
application** 6. Full list: [`docs/checks.md`](docs/checks.md).

## It tells you what it could not measure

A scanner reporting nothing is ambiguous: it may have found nothing, or failed
to look. unruly separates those, and exit code `3` means *something could not be
assessed* — which is not a clean result.

Where existence is undecidable it claims nothing. Firestore answers `403`
identically for a protected collection and one that never existed, so
"protected" is not a claim this tool makes about Firestore. Measured against a
competing tool's own top-50 wordlist, that tool reports 50 protected collections
on our lab, of which **zero exist**.

## The accuracy claim, and how it is checked

**100% precision on every graded dimension.** In words, so the claim and the
measurement stay in step: relation discovery 91.1%, read exposure 89.5%, write
exposure 100.0% — each at 100% precision.

| dimension | recall | precision | n |
|---|---:|---:|---:|
| relation discovery | 91.1% | 100% | 101 |
| read exposure | 89.5% | 100% | 57 |
| protected, not flagged | 100% | 100% | 43 |
| escalation gains | 100% | 100% | 8 |
| write exposure | 100.0% | 100% | 6 |
| routine discovery | 83.3% | 100% | 6 |

A corpus of sixteen projects in [`benchmark/corpus/`](benchmark/corpus/), each
with an answer key established by direct measurement against the running stack
rather than by reading the schema. Fifteen are scored end to end by the binary
exactly as an operator runs it; the sixteenth is a Firebase target this runner
does not grade, and it is listed as unscored rather than quietly dropped.
Reproduce it all: `make benchmark`.

**Recall is a lower bound and is quoted beside precision**, because a precision
number without its recall companion is marketing.

Precision is held down by controls, not by luck. Five negative controls run in every batch —
hosts that are *not* Supabase, including one answering `200` to any path and one
merely flaky — where the correct result is silence. `protected-not-flagged`
above is the same idea inside the corpus: 43 relations that must stay unreported.

Discovery is bounded and explicit. With nothing to harvest, a scan asks about 884
conventional names. `-emit-vocab` and `-vocab-only` let an operator who already
knows their schema hand over the real ones, so you stop paying
for 884 guesses against their own metered project.

Beyond the corpus:

- **214 hand-written mutations** (`scripts/mutate.py`), each a deliberate defect
  with a written justification. `make mutation` requires every one to be caught
  by a test.
- **`make audit` executes the remediation command every finding publishes** and
  requires it to reproduce that finding — a sweep across all 72 IDs. It has
  caught five drifts in this project's own output.
- **Byte-identical output** between two scans of an unchanged target, so a diff
  in CI means the target changed.
- **Graded against real backends, not mocks**: local Postgres + PostgREST +
  GoTrue, a Firebase lab, a PocketBase lab, a Neon Data API project.

## Install

```bash
go install github.com/eppser/unruly/cmd/unruly@latest
```

```bash
git clone https://github.com/eppser/unruly && cd unruly && make build
```

Static binaries for linux/darwin/windows, amd64 and arm64: `make release`.

## Usage

```bash
unruly -u https://your-app.com              # scan
unruly -u https://your-app.com -proven      # only findings something was retrieved for
unruly -u https://app.example.com -fix         # with SQL remediation
unruly -u https://your-app.com -redact      # keep the verdict, drop the rows
unruly -u https://your-app.com -measure     # prove exposure without retrieving a row
unruly -l targets.txt -json -o report.jsonl # an estate, machine-readable

unruly -u https://your-app.com -principal a=<jwt> -principal b=<jwt>   # cross-identity
unruly -u https://your-app.com -write -yes-i-own-this                  # write probes
```

**Exit codes:** `0` clean and fully measured · `2` findings at high or above ·
`3` something could not be assessed.

`-measure` is the flag for a project you do not own: it establishes that a
relation is readable from row counts and never retrieves a row.

## Documentation

| | |
|---|---|
| [`docs/checks.md`](docs/checks.md) | every finding id, severity, remediation |
| [`docs/architecture.md`](docs/architecture.md) | how a scan is planned and executed |
| [`docs/providers.md`](docs/providers.md) | adding a backend |
| [`docs/auditing.md`](docs/auditing.md) | how the claims here are verified |
| [`docs/threat-model.md`](docs/threat-model.md) | what each check assumes about an attacker |
| [`docs/exploitability.md`](docs/exploitability.md) | which findings have a demonstrated exploit |

## Responsible use

unruly sends real requests. Run it against systems you own or are explicitly
authorised to test. Write probes are gated behind `-write -yes-i-own-this` and
are never on by default; `-measure` exists so exposure can be established
without retrieving anyone's data.

A false negative is a vulnerability in this project — see
[`SECURITY.md`](SECURITY.md).

## Licence

MIT. See [`LICENSE`](LICENSE).
