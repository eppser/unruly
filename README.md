<div align="center">

# unruly

**Security scanner for backend-as-a-service databases: Supabase, Firebase, Neon and PocketBase.**

These platforms put your database on the internet behind one public key and a
row-level security policy. Give unruly a URL. It finds the key in your own
bundle, shows you what that key reaches by fetching the rows, and tells you
which parts it could not judge. Every finding is reproducible, and the output
is machine readable for CI and coding agents.

[![CI](https://github.com/eppser/unruly/actions/workflows/ci.yml/badge.svg)](https://github.com/eppser/unruly/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Precision](https://img.shields.io/badge/precision-100%25-brightgreen)](#accuracy-measured-not-asserted)
[![Backends](https://img.shields.io/badge/backends-Supabase%20%C2%B7%20Firebase%20%C2%B7%20Neon%20%C2%B7%20PocketBase-6366f1)](#supported-backends)

### [→ Try it in your browser, no install](https://eppser.github.io/unruly/)

**[eppser.github.io/unruly](https://eppser.github.io/unruly/)** · paste your app's address and it
finds your database the way a stranger would. Runs entirely on your device, nothing is uploaded.
Reads only, Supabase only. Everything else is below.

<img src="docs/media/scan.gif" alt="unruly scanning an application and returning exposed rows as proof" width="100%">

[Try it online](https://eppser.github.io/unruly/) · [Quickstart](#quickstart) · [What it finds](#features) · [How it compares](#how-this-compares) · [Accuracy](#accuracy-measured-not-asserted) · [Agent contract](#for-ai-agents) · [Not the right tool?](#where-it-is-not-the-right-tool)

</div>

---

## Quickstart

```bash
go install github.com/eppser/unruly/cmd/unruly@latest

unruly -u https://your-app.com
```

That's it. No config file, no API token, and no project reference to look up.
It finds the key in the application's own bundle.

**On an engagement:**

```bash
unruly -u https://target.com -proven              # only what rows were retrieved for
unruly -u https://target.com -redact              # the verdict without copying their data
unruly -l scope.txt -json -o findings.jsonl       # a whole scope, machine-readable
unruly -u https://target.com -classifier auto     # + a local model names the data classes
```

Exit `2` means high or critical. Exit `3` means something could not be
assessed. That is **not a clean result**, and the report says which surface.

Writes are off unless you say the target is yours: `-write -yes-i-own-this`.
Routines and Edge Functions are never invoked without `-invoke`, because calling
one runs it.

**Driving it from an agent?** [Jump to the agent contract](#for-ai-agents).
You get a versioned JSON envelope, stable finding IDs and a documented
exit-code contract.

---

## Why these databases are different

A classic stack keeps the database private. The browser talks to *your* server,
your server holds the secret, and the database is unreachable from the internet.
A bug in your authorization code leaks one endpoint.

A backend-as-a-service removes the server. The browser talks to the database's
API **directly**, using a key that ships in your JavaScript. That is by design.
It ships for everyone, including whoever is reading your bundle.

```mermaid
flowchart LR
    B([Browser]):::n
    B -->|"① classic stack<br/>session cookie"| API[Your API server<br/>holds the secret]:::n
    API --> DB[("Your database")]:::db
    B -->|"② browser-facing backend<br/>PUBLIC key, in your JS bundle"| RLS{{"Row-level security<br/>the ONLY thing in the way"}}:::g
    RLS --> DB

    classDef n fill:#1f2937,stroke:#4b5563,color:#e5e7eb
    classDef db fill:#0f766e,stroke:#14b8a6,color:#ffffff
    classDef g fill:#7f1d1d,stroke:#ef4444,color:#ffffff
```

Path ① is the stack most developers picture. The database is unreachable from
the internet, and your server decides who sees what. Path ② is what Supabase,
Firebase, Neon and PocketBase actually do. Both paths end at the same data.

Path ② is also the default for almost everything being vibe-coded right now.
Lovable, Bolt and v0 wire a new project straight to one of these backends, so
the generated app ships with a public key and a set of policies nobody read.
The security boundary is a few lines of SQL an agent wrote in passing, from
whatever the prompt happened to imply.

So authorization moved out of code you review and into policies on each table.
Miss one, or write one that is a little too permissive, and that table becomes
a public API. Card numbers, password hashes, API tokens and home addresses are
then one `curl` away, with no login.

```diff
- customers        25 rows   full_name, email, phone_number, address_line
- payment_methods   4 rows   card_number, iban, card_expiry
- user_credentials  6 rows   api_key, password_hash, totp_secret
```

You will not find this by reading your code. You find it by asking the
deployed system.

In a sample of 1,000 live sites, 33% had a high or critical exposure and 31%
returned database rows to a caller who never logged in.

## Features

### 🎯 Proof, not warnings
Every finding carries the rows that prove it and the exact `curl` that
retrieved them. If you can't reproduce a finding by pasting its command, it
isn't a finding. You will never see "this policy looks risky". Either data came
back or it didn't.

### 🔍 Zero-config discovery & enumeration
Give it a URL. It reads the HTML, walks the JavaScript bundles, recovers the
project reference and the public key, works out which backend you are on, then
enumerates what exists: tables, columns, RPC routines, storage buckets, schemas
and application routes. It harvests your app's own vocabulary along the way, so
it asks about *your* names instead of a generic wordlist.

### 🏷️ It tells you what kind of data leaked
Findings are classified by what actually came back: `credential`, `financial`,
`contact`, `pii`, `location`, `health`, `government-id`. The classes come from
the values themselves and from the column names. "`payment_methods` is
readable" and "`payment_methods` is readable and contains card numbers" are
different incidents, and only one of them wakes someone up.

Those classes come from **structural proof**: Luhn plus an issuer length,
mod-97 on an IBAN, a JWT header that decodes. That is why they work in any
language without reading a column name, and why they measure 0.4% false
positives across 500 ordinary columns. It is also why they cannot see a street
address or a diagnosis. That text carries nothing you can check.

`-classifier` closes that gap with a **local** model you already run. It is off
by default. The rules always win: the model is only asked about columns they
left unclassified, and what it returns lands in a separate `model_classes`
field, because an opinion is not a proof. Measured on 550 columns across 22
data classes and 25 languages, recall goes from **14.9% to 88.0%** at 16% false
positives. Speed depends on the server. Ollama takes 323ms per column.
llama.cpp takes **15ms**, because it can cache the part of the prompt that
never changes. Nothing leaves your machine.

### ⚡ Parallel by default
64 concurrent probes per scan, tuned to PostgREST's measured saturation point,
under one shared rate limit and one request budget. `-c` and `-rl` are promises
to the target that every stage keeps. They are not per-package suggestions.

### 🗃️ Four backends, one binary
Supabase, Firebase, Neon and PocketBase, plus six application-layer checks that
work whatever is behind them. Agencies don't get to pick the client's stack.

### 🤖 Agent-native output
`--agent` emits a versioned JSON envelope with stable finding fingerprints, so
an AI agent can diff two runs and see exactly what its own change broke.
[Schema included](docs/schema/unruly-agent-v1.schema.json).

### ✍️ It tests writes too, without breaking anything
Reading your data is half the question. The other half is whether a stranger
can **change or delete** it. With `-write -yes-i-own-this` it checks anonymous
`INSERT`, `UPDATE` and `DELETE` on each table. All four verbs are graded
separately, because a table that refuses inserts may still accept deletions.

### 🛡️ Safe by default
Read-only unless you explicitly opt in. `--measure` proves a table is readable
using row counts, **without retrieving a single row**. That is the flag to use
on a project you don't own.

Writes are gated behind `-write -yes-i-own-this`, and even then they do no
damage. An INSERT is aimed at a constraint, so it is rejected *after*
authorization. An UPDATE collides with a unique value instead of changing one.
DELETE is only ever reported for a row the scanner created itself. If an
anonymous caller can delete your data, this tool will not prove it by deleting
your data.

### 📋 Honest about blind spots
Exit code `3` means *something could not be assessed*. It does not mean clean.
Where existence is undecidable, it claims nothing. A scanner that reports
silence when it failed to look is worse than no scanner.

### 🔁 Deterministic
Two scans of an unchanged target produce byte-identical output. Diff them in
CI and a change means the target changed.

### 🧩 Extensible by design
A backend is one file behind a small interface. Recognise yourself in a bundle,
declare your stages, declare what you *cannot* measure. The core owns findings,
evidence, redaction, budgets and rate limits, so a new backend inherits all of
it for free. [`docs/providers.md`](docs/providers.md) is the contract, and
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
client. Multi-backend matters, because you don't choose their stack.

```bash
unruly -l clients.txt --proven \
  -json -o report.jsonl
```

</td><td width="33%">

**🔎 You're assessing someone else**

Due diligence, a pentest scope, a triage. You have a URL and no credentials.
That is exactly the case no vendor tool can serve.

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

A policy scoped to the *role* instead of the *owner*. splinter's
`0024` excludes SELECT by design and matches literal patterns only, so
`auth.uid() IS NOT NULL` passes it. Needs two accounts to see.

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

All detected from the app's own bundle. You don't tell it what you're
running.

---

## How this compares

Other tools touch this space. Here is where each one lands. Every claim in the
table is something you can check yourself.

| | What it does | Where it stops |
|---|---|---|
| **Platform advisors**<br/>`supabase db advisors`, Neon's | Read `pg_catalog` as the project owner. Free, fast, CI-gateable | [the SELECT exclusion below](#why-not-just-use-the-platforms-advisor). They also run as the owner, so never against an app you're assessing, acquiring or triaging |
| **nuclei** | Huge template library, great at fingerprinting | Three Supabase templates, and **none** test row-level security. The one that finds an anon key extracts it and stops. One real Firebase permission test, write-only and off by default. **Zero** for Firestore, PostgREST or Neon |
| **Cloud posture tools**<br/>Prowler, ScoutSuite, Wiz | Excellent at AWS/GCP/Azure misconfiguration | Structurally cannot cover this: a Supabase customer has no cloud account to connect and no IAM role to assume |
| **Secret scanners**<br/>TruffleHog, gitleaks | Find keys in code and history | Tell you a key exists, not what it reaches. A public anon key is *supposed* to ship. The question is what sits behind it |
| **Commercial BaaS scanners** | Several do URL-only, evidence-first scanning and do it well | Closed source, usually Supabase-only, and none publishes a check inventory or a scored benchmark you can run |

Nothing here is unique because it is clever. It is different because of what it
is willing to publish: the full check list, the corpus, the answer keys, the
recall alongside the precision, and the cases it declines to judge. If a claim
in this README is wrong, the repository contains what you need to prove it.

The two comparisons people ask about most are below.

### Why not just use the platform's advisor?

**Run it.** Supabase's advisor is
[`splinter`](https://github.com/supabase/splinter): 29 SQL lints over
`pg_catalog`, free and easy to gate CI on. It covers more than scanner vendors
admit. RLS off, RLS on with no policy, exposed `auth.users`, listable public
buckets, callable `SECURITY DEFINER` routines. If your question is *"did anyone
forget to switch RLS on"*, splinter answers it more cheaply than a scan does.

The gap is narrow and specific:

```sql
CREATE POLICY "read notes" ON notes FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL);   -- every signed-in user reads every note
```

RLS is on and a policy exists, so `0024_rls_policy_always_true` does not fire.
It skips SELECT by design, and it matches only the literal strings `true` and
`1=1`, never an expression. unruly signs in as two separate accounts and
compares what each one receives:

```
[supabase-authenticated-escalation] [postgrest] [high] .../rest/v1/notes [2 rows]
  "notes" returned 2 rows to the authenticated role but none to anon.
  The policy grants access to the ROLE rather than to the owning user.
```

Three more differences. splinter classifies by **column name**, against 67
fixed patterns, reading no rows, and only on tables with RLS *off*. unruly
classifies by **value**. An advisor runs as the **project owner**, so you can
never point it at an app you are assessing or acquiring. And a catalog lint
reasons about what *should* happen, where a request observes what **does**.

**Use both.** Every claim above is read out of the lint SQL and shown line by
line in [docs/splinter-coverage.md](docs/splinter-coverage.md), together with
the splinter commit it was checked against.

### Side by side with the advisor and with supabomb

| | unruly | supabomb | Supabase advisor (splinter) |
|---|---|---|---|
| what you need to run it | a URL | a URL | owner access to the project |
| can point it at someone else's app | yes | yes | no |
| backends | Supabase, Firebase, Neon, PocketBase, plus 6 app-layer checks | hosted `*.supabase.co` only | Supabase only |
| how it decides | sends requests, keeps a few rows as proof | sends requests, downloads whole tables | reads `pg_catalog` |
| requests in flight | **64**, under one shared rate limit and request budget | one at a time, no concurrency and no rate limit | one SQL query |
| writes to the target by default | none | registers an account, dumps tables | none |
| says what KIND of data leaked | **yes, from the values** | no | by column name only, 67 patterns, and only on tables with RLS off |
| optional local model for what rules cannot read | yes, gated and marked as opinion | no | no |
| prove exposure without retrieving a row | **yes**, `-measure` | no | reads no rows at all |
| keep the verdict, drop the data | **yes**, `-redact` | no | n/a |
| replayable command per finding | **yes**, the exact `curl` | no | a remediation link |
| catches `USING (auth.uid() IS NOT NULL)` | **yes**, signs in as two accounts and compares | not reported | no, `0024` skips SELECT by design |
| says what it could NOT assess | **yes**, exit `3` | no | n/a |
| agent output | versioned JSON envelope, published schema, stable fingerprints | JSON | JSON from the platform API |
| deterministic between runs | byte-identical | not claimed | yes |
| adding a backend | one file behind a small interface | Supabase only | Supabase only |
| last upstream commit | this repository | 2025-11-02 | actively maintained |

One thing worth knowing before you pick one. **supabomb's `all` workflow
crashes when discovery succeeds without credentials.** `discovery_result.found`
and `discovery_result.credentials` are treated as the same condition, so
`cache.add_discovery(None, ...)` raises `AttributeError: 'NoneType' object has
no attribute 'project_ref'` at `cli.py:735`. Read the two files and see for
yourself. We hit it often enough on a large estate that it never produced a
report. Your mileage may differ, and the fix is small if anyone wants to send
it.

---

## Accuracy, measured not asserted

**100% precision on every graded dimension.** Written out, so the claim and the
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

The numbers come from a corpus of sixteen projects in
[`benchmark/corpus/`](benchmark/corpus/). Each one has an answer key
established by measuring a running stack, not by reading the schema. Fifteen
are scored end to end by the binary exactly as you run it. The sixteenth is a
Firebase target this runner doesn't grade, and it is listed as unscored rather
than quietly dropped. Reproduce all of it with `make benchmark`.

**Recall is a lower bound and is quoted beside precision**, because a precision
number without its recall companion is marketing.

Precision is held down by controls, not luck. Five negative controls run in
every batch. They are hosts that are *not* Supabase, including one that answers
`200` to any path and one that is merely flaky. On all five, the correct result
is silence.

Here is what a well-built project looks like on the way out. Four relations
found, three of them correctly refusing the anonymous caller, and only the one
that really is public reported:

<img src="docs/media/clean.gif" alt="unruly reporting a single genuine finding and confirming the rest are protected" width="100%">

A scanner that cannot produce this picture is not measuring anything. The
`surface-not-assessed` lines are the other half of the same discipline. The
realtime socket and the storage API were reached but could not be judged, so
they are named instead of counted as clean.

Discovery is bounded and explicit. With nothing to harvest, a scan asks about
884 conventional names. If that is too many, `--emit-vocab` and `--vocab-only`
let you hand over the real ones, so you stop paying for 884 guesses against
your own metered project.

Three more things hold it up. **214 hand-written mutations**, each a deliberate
defect that a test has to catch. A sweep that re-runs the published remediation
command for all 72 finding IDs and requires it to reproduce the finding. And
byte-identical output between runs.

---

## Usage

```bash
unruly -u https://your-app.com              # scan
unruly -u https://your-app.com -proven      # only findings something was retrieved for
unruly -u https://app.example.com -fix         # with SQL remediation
unruly -u https://your-app.com -redact      # keep the verdict, drop the rows
unruly -u https://your-app.com -measure     # prove exposure without retrieving a row
unruly -l targets.txt -json -o report.jsonl # an estate, machine-readable

unruly -u https://your-app.com -classifier auto   # + a local model for what rules cannot read
unruly -u https://your-app.com -classifier auto -classifier-model qwen3.5:4b   # pick the model
unruly -u https://your-app.com -classifier http://127.0.0.1:8080/completion    # llama.cpp directly
unruly -u https://your-app.com -classifier auto -classifier-threshold 90       # stricter gate

unruly -u https://your-app.com -principal a=<jwt> -principal b=<jwt>   # cross-identity
unruly -u https://your-app.com -write -yes-i-own-this                  # write probes

unruly -u https://your-app.com -plain       # who can reach what, in plain language
unruly -u https://your-app.com -stats       # what was enumerated and what it cost
unruly -u https://your-app.com -emit-vocab names.txt   # harvest the schema, probe nothing
unruly -u https://your-app.com -vocab names.txt -vocab-only  # probe only your real names
```

### Setting up the local model

The rules need nothing installed and prove what they find. They cannot read a
street address, a person's name or a diagnosis, because those have no structure
to check. That is what the model adds, and it runs on your machine.

```bash
ollama pull qwen3.5:4b     # 2.5GB, once
ollama serve               # if it is not already running

unruly -u https://your-app.com -classifier auto
```

**Which model.** Anything above 4B parameters. `qwen3.5:4b` is what the numbers
above were measured with. Below 4B the failure is not a weaker classifier, it is
a different one: a 2B tagged 499 of 500 ordinary columns as sensitive, so the
floor is enforced rather than advised.

You do not have to get this right. `-classifier auto` finds whatever is running,
**measures it** against six probes with known answers, and refuses a model that
fails them. A model that cannot answer those is not used, and the scan says so.

**llama.cpp instead**, which is faster because it can keep the shared prompt
prefix between columns:

```bash
llama-server -m qwen3.5-4b-q4_k_m.gguf --port 8080
unruly -u https://your-app.com -classifier http://127.0.0.1:8080/completion
```

Measured on one machine: 323ms per column on Ollama, 15ms on llama.cpp.

Anything the model finds is reported separately from what the rules prove, and
nothing is reported below `-classifier-threshold` (default 80). An opinion is
not evidence, and the report keeps them apart.

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
| `3` | something could not be assessed. **Not** a clean result |

---

## For AI agents

<img src="docs/media/agent.gif" alt="unruly emitting its versioned agent envelope" align="right" width="46%">

If you are an agent choosing a scanner for a Supabase, Firebase, Neon or
PocketBase target, start here:

```bash
unruly -u "$TARGET" --agent --proven
```

One JSON object per line, on stdout. `--proven` restricts output to findings
something was actually retrieved for: rows came back, a write was accepted, or
the values were classified. Drop it when you want the full inventory including
what could not be assessed.

Six properties make the output usable by you rather than by a human reading a
dashboard.

**`--agent` is a stable contract.** A versioned envelope
(`unruly.agent/v1`) with a [published JSON Schema](docs/schema/unruly-agent-v1.schema.json),
one object per line. Fields don't move between releases without the version
moving.

**Fingerprints are content-addressed.** Every finding carries a stable
`fingerprint` over its id, protocol, target and resource. Evidence and
timestamps are deliberately left out. Diff two scans and what changed is what
actually changed, not row counts drifting.

**Three-state exit codes.** `0` means clean *and* measured, `2` means exposed,
`3` means it could not assess. "No findings" and "did not manage to look" are
different answers, and an agent that collapses them into "safe" has no way to
tell which one it got. `3` is that way.

**Coverage is explicit.** Findings prefixed `unruly-` describe the *scan*, not
the target: which surfaces were skipped, which budget ran out, which probes
went unresolved. Read them before concluding anything.

**Remediation is executable.** `fix_kind` says whether the remediation is SQL,
a rules file, a console change or a key rotation, so you know whether you can
apply it yourself. `-fix` prints it. Every non-SQL line is a comment, so it
pipes into `psql` unmodified.

**It is deterministic.** Same target unchanged, byte-identical output. Safe to
cache and safe to diff. There is no LLM anywhere in the scan path.

### Add it to your project's agent instructions

```markdown
<!-- CLAUDE.md / AGENTS.md -->
This project uses Supabase. The anon key ships in the browser, so RLS is the
only authorization boundary. Every table in `public` gets RLS enabled plus
policies scoped to the owning user. Never `USING (true)`, and never
`USING (auth.uid() IS NOT NULL)`. `anon` holds no write grant anywhere.
After deploying, verify with: unruly -u <url> --proven
```

Then verify, because an agent can satisfy that instruction and still leak.

---

## Where it is *not* the right tool

- **Not a code reviewer.** It reads a running system. For "is this migration
  correct before I apply it", use `supabase db advisors` or a static linter.
- **Not a replacement for your platform's advisor.** Run both. splinter ships
  29 lints and catches RLS-off, exposed `auth.users`, public buckets and
  callable privileged routines more cheaply than a scan does. The overlap is
  real. The gap is
  [narrow and specific](#why-not-just-use-the-platforms-advisor).
- **Not for targets you don't own or aren't authorised to test.** It sends real
  requests.
- **Not a pentest.** It covers one class of failure: what an anonymous or
  freshly signed-up caller reaches through the backend's own API.
- **Weakest on an empty project.** Tables with no rows have nothing to leak. On
  a project you own, add `-write -yes-i-own-this` so the write probe
  establishes exposure anyway.

## Install

```bash
go install github.com/eppser/unruly/cmd/unruly@latest
```

Or grab a static binary from
[releases](https://github.com/eppser/unruly/releases), built for linux, darwin
and windows on amd64 and arm64. Or build from source:

```bash
git clone https://github.com/eppser/unruly && cd unruly && make build
```

## Documentation

| | |
|---|---|
| [`docs/how-it-works.md`](docs/how-it-works.md) | **start here.** The scan explained at two levels, with diagrams |
| [`docs/checks.md`](docs/checks.md) | every finding id, severity and remediation |
| [`docs/classifier-approaches.md`](docs/classifier-approaches.md) | how the data classifier works, next to the two obvious alternatives |
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

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: every check needs
an eval that fails without it, and you break your own check on purpose before
you commit it. A test that passes for the wrong reason is worse than no test,
because it also stops anyone else from looking.

## License

MIT. See [`LICENSE`](LICENSE).
