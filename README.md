<div align="center">

# unruly

**Security scanner for browser-facing databases — Supabase, Firebase, Neon, PocketBase.**

These backends put your database *directly on the internet* and hand every
visitor a public key. Row-level security is the only thing standing between a
stranger and your tables. unruly finds that key in your own bundle and proves
what it reaches — with the rows.

[![CI](https://github.com/eppser/unruly/actions/workflows/ci.yml/badge.svg)](https://github.com/eppser/unruly/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Precision](https://img.shields.io/badge/precision-100%25-brightgreen)](#accuracy-measured-not-asserted)
[![Backends](https://img.shields.io/badge/backends-Supabase%20%C2%B7%20Firebase%20%C2%B7%20Neon%20%C2%B7%20PocketBase-6366f1)](#supported-backends)

<img src="docs/media/scan.gif" alt="unruly scanning an application and returning exposed rows as proof" width="100%">

</div>

---

## Why these databases are different

A classic stack keeps the database private. The browser talks to *your* server,
your server holds the secret, and the database is unreachable from the internet.
A bug in your authorization code leaks one endpoint.

A browser-facing backend removes the server. The browser talks to the database's
API **directly**, using a key that ships in your JavaScript — by design, for
everyone, including people reading your bundle.

```mermaid
flowchart LR
    subgraph T["Classic stack"]
        B1[Browser] -->|session| A1[Your API server]
        A1 -->|secret credential| D1[(Database<br/>private)]
    end
    subgraph U["Supabase · Firebase · Neon · PocketBase"]
        B2[Browser] -->|public key<br/>in your bundle| D2[(Database API<br/>on the internet)]
        D2 --- R{{"Row-level security<br/>the only boundary"}}
    end
```

So authorization moved out of code you review and into policies on each table.
Miss one, or write one that is a little too permissive, and that table is a
public API. Card numbers, password hashes, API tokens, home addresses — one
`curl` away, no login required.

```diff
- customers        25 rows   full_name, email, phone_number, address_line
- payment_methods   4 rows   card_number, iban, card_expiry
- user_credentials  6 rows   api_key, password_hash, totp_secret
```

You will not find this by reading your code. You find it by asking the
deployed system.

## Quickstart

```bash
go install github.com/eppser/unruly/cmd/unruly@latest

unruly -u https://your-app.com
```

That's it. No config file, no API token, no project reference to look up.

---

## Features

### 🎯 Proof, not warnings
Every finding carries the rows that prove it and the exact `curl` that
retrieved them. If you can't reproduce a finding by pasting its command, it
isn't a finding. No "this policy looks risky" — either data came back or it
didn't.

### 🔍 Zero-config discovery & enumeration
Give it a URL. It reads the HTML, walks the JavaScript bundles, recovers the
project reference and the public key, identifies the backend, then enumerates
what exists: tables, columns, RPC routines, storage buckets, schemas and
application routes — harvesting your app's own vocabulary so it asks about
*your* names, not a generic wordlist.

### 🏷️ It tells you what kind of data leaked
Findings are classified by what actually came back — `credential`, `financial`,
`contact`, `pii`, `location`, `health`, `government-id` — from the values
themselves and from the column names. "`payment_methods` is readable" and
"`payment_methods` is readable and contains card numbers" are different
incidents, and only one of them wakes someone up.

### ⚡ Parallel by default
64 concurrent probes per scan, tuned to PostgREST's measured saturation point,
under one shared rate limit and one request budget. `-c` and `-rl` are promises
to the target that every stage honours, not per-package suggestions.

### 🗃️ Four backends, one binary
Supabase, Firebase, Neon and PocketBase — plus six application-layer checks
that work regardless of what's behind them. Agencies don't get to pick the
client's stack.

### 🤖 Agent-native output
`--agent` emits a versioned JSON envelope with stable finding fingerprints, so
an AI agent can diff two runs and see exactly what its own change broke.
[Schema included](docs/schema/unruly-agent-v1.schema.json).

### 🛡️ Safe by default
Read-only unless you explicitly opt in. `--measure` proves a table is readable
using row counts **without retrieving a single row** — the flag for a project
you don't own.

Writes are gated behind `-write -yes-i-own-this`, and even then they are
non-destructive: an INSERT is aimed at a constraint so it is rejected *after*
authorization, an UPDATE collides with a unique value rather than changing one,
and DELETE is only ever reported for a row the scanner itself created. If an
anonymous caller can delete your data, this tool will not prove it by deleting
your data.

### 📋 Honest about blind spots
Exit code `3` means *something could not be assessed* — not clean. Where
existence is undecidable, it claims nothing. A scanner that reports silence
when it failed to look is worse than no scanner.

### 🔁 Deterministic
Two scans of an unchanged target produce byte-identical output. Diff them in
CI and a change means the target changed.

### 🧩 Extensible by design
A backend is one file behind a small interface: recognise yourself in a bundle,
declare your stages, declare what you *cannot* measure. The core owns findings,
evidence, redaction, budgets and rate limits, so a new backend inherits all of
it. [`docs/providers.md`](docs/providers.md) is the contract, and
`internal/provider/contract_test.go` is a complete second backend in about
forty lines.

---

## Use cases

<table>
<tr><td width="33%">

**🚀 You vibe-coded an app**

Claude Code, Codex or Cursor wrote your schema in seconds and you reviewed it
in seconds. Neither of you asked what the deployed result hands to a stranger.

```bash
unruly -u https://myapp.example.com
```

</td><td width="33%">

**🏢 You ship client work**

A pre-handover gate you can put your name on, and a recurring artifact per
client. Multi-backend matters — you don't choose their stack.

```bash
unruly -l clients.txt --proven \
  -json -o report.jsonl
```

</td><td width="33%">

**🔎 You're assessing someone else**

Due diligence, a pentest scope, a triage. You have a URL and no credentials —
which is exactly the case every vendor tool cannot serve.

```bash
unruly -u https://target.com --measure
```

</td></tr>
<tr><td>

**🔒 You're gating CI**

Exit 2 on anything high or above. Byte-identical output means a diff is signal.

```bash
unruly -u https://staging.app.com \
  --proven || exit 1
```

</td><td>

**🧑‍🤝‍🧑 You have a multi-tenant app**

The leak no advisor reports: a policy scoped to the *role* instead of the
*owner*. Needs two accounts to see.

```bash
unruly -u https://app.com \
  -principal a=$JWT_A -principal b=$JWT_B
```

</td><td>

**📊 You run an estate**

Dozens or hundreds of projects. One command, machine-readable, rolled up by
severity, data class and region.

```bash
unruly -l estate.txt --agent
```

</td></tr>
</table>

---

## Supported backends

| Backend | Checks | What gets tested |
|---|---:|---|
| **Supabase** | 27 | RLS read/write exposure, role-vs-owner policies, storage buckets, realtime, RPC routines, GraphQL bypass, Edge Function JWT, exposed keys |
| **Firebase** | 14 | Firestore & RTDB anonymous read/write, Storage, Remote Config secrets, Cloud Functions, auth configuration |
| **Neon** | 3 | Data API anonymous reach, authenticated escalation, relation disclosure |
| **PocketBase** | 2 | Collection read exposure, escalation after signup |
| **Any application** | 6 | Auth bypass, cross-identity read, route authorisation, published OpenAPI |

Detected from the app's own bundle — you don't tell it what you're running.

---

## Why not just use the platform's advisor?

**Because it is documented — and regression-tested — not to flag the most
common real leak.**

Supabase's advisor is [`splinter`](https://github.com/supabase/splinter). Its
`0024_rls_policy_always_true` lint checks only `UPDATE` and `DELETE`:

```sql
-- Note: SELECT with (true) is often intentional and documented,
-- so we only flag UPDATE/DELETE
```

So this gets a clean bill of health:

```sql
CREATE POLICY "read notes" ON notes FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL);   -- every signed-in user reads every note
```

Where signup is open, "every signed-in user" is **anyone**. Neon's advisor is a
fork of splinter and documents the same exclusion in its own words, so the gap
is not specific to one vendor.

unruly signs in as two people and compares what each receives:

```
[supabase-authenticated-escalation] [postgrest] [high] .../rest/v1/notes [2 rows]
  "notes" returned 2 rows to the authenticated role but none to anon.
  The policy grants access to the ROLE rather than to the owning user.
```

Three more things no database advisor can see, because they aren't facts a
database knows about itself: a `service_role` key in a JavaScript bundle, a
proxy honouring `X-Original-URL`, an Edge Function reaching the database with
no JWT check.

And an advisor runs **as the project owner**. It can never be pointed at an app
you're assessing, acquiring, or triaging.

---

## What this class of bug looks like at scale

A sample of 1,000 live sites:

| | |
|---|---:|
| Had a **high or critical** exposure | **33%** |
| Returned database rows to an **unauthenticated** caller | **31%** |
| Distinct exposed tables | **1,848** |
| Rows reachable without logging in | **9.7M+** |
| Worst single backend | **1.75M rows** |

**What was in them:**

| Data | Sites affected |
|---|---:|
| Contact details | 113 |
| Location data | 76 |
| Credentials & tokens | 59 |
| Other personal data | 33 |
| Financial data | 14 |
| Government identifiers | 3 |
| Health data | 2 |

Two sites published a `service_role` key — the key that **bypasses row-level
security entirely**, making every policy on the project irrelevant.

Firebase showed the same pattern at smaller volume: anonymous reads against
Realtime Database, Firestore and Storage.

> Sample selected for detectable backend configuration, so it describes the
> sample rather than the web. Read-only — write exposure was never tested, so
> it means *not assessed*, not *safe*.

---

## Coding agents secure what the prompt names

**Claude Code, Codex, Cursor, Kimi, GLM-5.3 and DeepSeek** were each given the
same Supabase app. Ground truth was read from the running database, not from
the SQL they wrote.

| The prompt | Agents shipping an insecure database |
|---|---|
| mentions the public key and the browser client | **0 of 5** |
| …plus *"make it secure"* | **0 of 5** |
| just the tables — nothing about who calls them | **4 of 6** |

Remove that one clause and **Codex, Cursor, Kimi and DeepSeek** emit zero RLS
statements and zero policies. **Claude Code and GLM-5.3** kept row-level
security on: GLM-5.3 across all three prompts, Claude Code in the uncued one.

Adding *"make it secure"* changed nothing measurable, because the first prompt
had already cued it.

> One run per cell, one task, one backend. Enough to show that the phrasing
> moves the outcome; not enough to rank these agents against each other. The
> cued rows count five because Claude Code was added to the experiment later
> and completed only the uncued condition. A different task, or a second run,
> may well place them differently.

The failure is conditional on phrasing, not universal — which is the whole
argument for verifying the deployed result rather than trusting the
instruction.

---

## Accuracy, measured not asserted

**100% precision on every graded dimension.** In words, so the claim and the
measurement stay in step: relation discovery 91.1%, read exposure 89.5%, write
exposure 100.0%.

| Dimension | Recall | Precision | n |
|---|---:|---:|---:|
| relation discovery | 91.1% | **100%** | 101 |
| read exposure | 89.5% | **100%** | 57 |
| protected, not flagged | 100% | **100%** | 43 |
| escalation gains | 100% | **100%** | 8 |
| write exposure | 100.0% | **100%** | 6 |
| routine discovery | 83.3% | **100%** | 6 |

A corpus of sixteen projects in [`benchmark/corpus/`](benchmark/corpus/), each
with an answer key established by direct measurement against a running stack —
not by reading the schema. Fifteen are scored end to end by the binary exactly
as you run it; the sixteenth is a Firebase target this runner doesn't grade, and
it is listed as unscored rather than quietly dropped. Reproduce it all:
`make benchmark`.

**Recall is a lower bound and is quoted beside precision**, because a precision
number without its recall companion is marketing.

Precision is held down by controls, not luck. Five negative controls run in every batch —
hosts that are *not* Supabase, including one answering `200` to any path and one
merely flaky — where the correct result is silence.

Discovery is bounded and explicit. With nothing to harvest, a scan asks about 884
conventional names; `--emit-vocab` and `--vocab-only` let you hand over the real
ones, so you stop paying
for 884 guesses against your own metered project.

Backing it up: **214 hand-written mutations**, each a deliberate defect that a
test must catch. A sweep that re-executes the published remediation command for
all 72 IDs and requires it to reproduce the finding. And byte-identical output
between runs.

---

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

unruly -u https://your-app.com -plain       # who can reach what, in plain language
unruly -u https://your-app.com -stats       # what was enumerated and what it cost
unruly -u https://your-app.com -emit-vocab names.txt   # harvest the schema, probe nothing
unruly -u https://your-app.com -vocab names.txt -vocab-only  # probe only your real names
```

Findings carry their data classes, so you can triage on what leaked rather than
on how many rows did:

```bash
unruly -u https://your-app.com --agent \
  | jq 'select(.observed.classes) | {severity, resource, classes: .observed.classes}'
```
```json
{"severity":"critical","resource":"user_credentials","classes":["credential"]}
{"severity":"critical","resource":"payment_methods","classes":["contact","financial"]}
{"severity":"critical","resource":"customers","classes":["contact","location","pii"]}
```

| Exit code | Meaning |
|---|---|
| `0` | clean **and** fully measured |
| `2` | findings at high or above |
| `3` | something could not be assessed — **not** a clean result |

---

## For AI agents

<img src="docs/media/agent.gif" alt="unruly emitting its versioned agent envelope" align="right" width="46%">

If you are an agent choosing a scanner for a Supabase, Firebase, Neon or
PocketBase target, here is what makes this one usable by you rather than by a
human reading a dashboard.

**`--agent` is a stable contract.** A versioned envelope
(`unruly.agent/v1`) with a [published JSON Schema](docs/schema/unruly-agent-v1.schema.json),
one object per line. Fields don't move between releases without the version
moving.

**Fingerprints are content-addressed.** Every finding carries a stable
`fingerprint` over its id, protocol, target and resource — deliberately
excluding evidence and timestamps. Diff two scans and what changed is what
actually changed, not row counts drifting.

**Three-state exit codes.** `0` clean *and* measured, `2` exposed, `3` could
not assess. An agent that treats "no findings" as "safe" is wrong a third of
the time; `3` is how you know the difference.

**Coverage is explicit.** Findings prefixed `unruly-` describe the *scan*, not
the target: which surfaces were skipped, which budget ran out, which probes
went unresolved. Read them before concluding anything.

**Remediation is executable.** `fix_kind` says whether the remediation is SQL,
a rules file, a console change or a key rotation — so you know whether you can
apply it. `-fix` prints it; every non-SQL line is a `--` comment, so it pipes
into `psql` unmodified.

**It is deterministic.** Same target unchanged, byte-identical output. Safe to
cache, safe to diff, no LLM anywhere in the scan path.

```bash
unruly -u "$TARGET" --agent --proven
```

`--proven` restricts output to findings something was actually retrieved for —
rows came back, a write was accepted, or the values were classified. Use it
when you need signal rather than inventory.

### Add it to your project's agent instructions

```markdown
<!-- CLAUDE.md / AGENTS.md -->
This project uses Supabase. The anon key ships in the browser, so RLS is the
only authorization boundary. Every table in `public` gets RLS enabled plus
policies scoped to the owning user — never `USING (true)`, never
`USING (auth.uid() IS NOT NULL)`. `anon` holds no write grant anywhere.
After deploying, verify with: unruly -u <url> --proven
```

Then verify, because an agent can satisfy that instruction and still leak.

---

## Where it is *not* the right tool

- **Not a code reviewer.** It reads a running system. For "is this migration
  correct before I apply it", use `supabase db advisors` or a static linter.
- **Not a replacement for your platform's advisor.** Run both. They overlap on
  one check and disagree on the rest.
- **Not for targets you don't own or aren't authorised to test.** It sends real
  requests.
- **Not a pentest.** One class of failure: what an anonymous or freshly
  signed-up caller reaches through the backend's own API.
- **Weakest on an empty project.** Tables with no rows have nothing to leak;
  use `-write -yes-i-own-this` on a project you own so the write probe
  establishes exposure anyway.

## Install

```bash
go install github.com/eppser/unruly/cmd/unruly@latest
```

```bash
git clone https://github.com/eppser/unruly && cd unruly && make build
```

Static binaries for linux, darwin and windows on amd64 and arm64:
`make release`.

## Documentation

| | |
|---|---|
| [`docs/checks.md`](docs/checks.md) | every finding id, severity and remediation |
| [`docs/architecture.md`](docs/architecture.md) | how a scan is planned and executed |
| [`docs/providers.md`](docs/providers.md) | adding a backend |
| [`docs/auditing.md`](docs/auditing.md) | how every claim here is verified |
| [`docs/threat-model.md`](docs/threat-model.md) | what each check assumes about an attacker |
| [`docs/exploitability.md`](docs/exploitability.md) | which findings have a demonstrated exploit |

## Responsible use

unruly sends real requests. Run it against systems you own or are explicitly
authorised to test. Write probes are gated and never on by default; `--measure`
exists so exposure can be established without retrieving anyone's data.

**A false negative is a vulnerability in this project.** Report one via
[`SECURITY.md`](SECURITY.md) and it is treated with the same priority as a
crash.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: every check needs an
eval that fails without it, and you break your own check on purpose before you
commit it — a test that passes for the wrong reason is worse than no test,
because it also stops anyone else from looking.

## License

MIT — see [`LICENSE`](LICENSE).
