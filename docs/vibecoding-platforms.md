# Vibe-coding platforms and the backends they ship

Which AI app builders are popular, what database each one puts behind the apps it
generates, and why that determines where this scanner's addressable surface is.

Compiled 2026-08-17. Adoption figures for the backends are hard numbers pulled from
the npm registry and GitHub APIs on that date. Figures for the vibe-coding platforms
themselves are **press-reported and self-reported** — private companies, no filings —
so treat them as order-of-magnitude, not audited.

---

## 1. The market

Vibe coding — describing an application in natural language and having a model write
and deploy it — went from a curiosity to a category in about eighteen months.

- **$4.7B** market in 2026, forecast **$12.3B** in 2027 (~38% growth)
- **98%** of vibe-coded applications carry at least one security flaw
  (Symbiotic Security, n=1,072 scanned apps — only 26 were clean)
- On Supabase specifically: database launches grew **600%** year-over-year to June 2026,
  and **more than 60% of new databases are created by AI tools**, with Claude Code the
  single largest contributor

That last figure is the one that matters here. The population of exposed backends is
not growing at the rate the platforms grow — it is growing at the rate the *newest and
least experienced cohort* grows, and that cohort is now the majority.

---

## 2. Platform popularity

| Platform | ARR | Users | Milestone |
|---|---:|---:|---|
| **Lovable** | **$400M** (Mar 2026) | 8M | Fastest SaaS ever to $200M ARR — 12 months — then doubled to $400M in 4 more |
| **Replit** | $150M ARR | — | Revenue $24M → $240M after the AI Agent launch (Sept 2024) |
| **v0** (Vercel) | ~$42M | 6M+ devs, 80k teams | Became a full-stack agentic platform Feb 2026 |
| **Bolt.new** (StackBlitz) | $40M | 5M+ | Reached $40M ARR in 4.5 months |
| **Base44** (Wix) | — | — | Acquired by Wix for **$80M** in June 2025, six months after launch |
| **Cursor / Windsurf** | — | — | IDEs rather than app builders; no backend of their own |
| **Firebase Studio** (Google) | — | — | Google's entry, formerly Project IDX |

Lovable is the outlier by a wide margin — roughly as much ARR as Replit, v0 and Bolt
combined.

---

## 3. Which backend each platform ships

This is the mapping that decides scanner coverage.

| Platform | Backend it generates against | Nature of the coupling |
|---|---|---|
| **Lovable** | **Supabase** | Official database partner. Lovable Cloud *is* Supabase underneath and is **on by default**, so most projects never create a separate account. The AI generates the schema, the auth flows **and the RLS policies** from prompts. |
| **Bolt.new** | **Supabase** | Built-in database layer in Bolt v2; claimable to your own Supabase account for external control. |
| **v0** (Vercel) | **Neon / Supabase / Upstash** | One-click from the Vercel Marketplace. No single default — the user picks. |
| **Replit** | **Postgres (first-party)** | Was Neon-backed serverless Postgres; migrating to Replit's own managed "Helium" Postgres. Plus a first-party key-value store. Self-contained — no third-party BaaS. |
| **Base44** (Wix) | **Proprietary** | The founder deliberately built the whole infrastructure rather than lean on Firebase or Supabase. |
| **Firebase Studio** | **Firebase** | Firestore, Realtime Database, Firebase Auth. |
| **Cursor / Windsurf / Claude Code** | **Whatever the agent picks** | Editors and agents, not platforms. In practice they generate against Supabase often enough that Supabase names Claude Code its largest single source of new databases in 2026. |

### The concentration

- **Supabase is the default for the two largest app builders by user count** — Lovable
  (8M users) and Bolt (5M+). It is also one of three options in v0.
- **Firebase is the default for exactly one platform**: Google's own Firebase Studio.
- **Replit and Base44 are closed systems.** Their apps are not reachable by a
  third-party BaaS scanner at all, because there is no public client API of the kind
  this tool probes. They are out of scope by architecture, not by choice.

---

## 4. Backend adoption, measured

Pulled live from the npm registry and GitHub APIs, 2026-08-17.

| Backend | npm weekly downloads | GitHub stars | Notes |
|---|---:|---:|---|
| Supabase | 21,127,352 | 108,077 | $10.5B valuation |
| Firebase | 6,349,645 | 5,136 ⚠️ | Not open source — stars meaningless |
| AWS Amplify | 1,548,660 | 9,557 | AWS repos don't accumulate stars |
| Convex | 1,144,001 | 12,388 | Backend only open-sourced 2024 |
| InstantDB | 172,122 | — | |
| Parse | 145,382 | 21,410 | Since 2016, still alive |
| PocketBase | 137,135 | 60,702 | Go binary — npm undercounts badly |
| Directus | 135,386 | 37,432 | |
| Appwrite | 28,752 | 57,032 | Many non-JS SDKs — undercounted |
| Hasura | n/a | 32,091 | No client SDK to measure |
| Nhost | 12,355 | 9,279 | |

Supabase and Firebase together are ~89% of measured SDK traffic. Everything else
combined is ~11%.

Two caveats worth carrying: npm counts include CI, mirrors and bots, so read them as a
*relative* signal between packages rather than a user count; and stars understate
Firebase, Amplify and Convex for structural reasons — vendor-owned, AWS-owned, and
recently-opened respectively.

---

## 5. Why this compounds into a security problem

The chain is short and each link is documented above:

1. **The security control is itself AI-generated.** Lovable advertises that its model
   writes your Row Level Security policies from a plain-English prompt. RLS is not a
   thing the user forgot to configure — it is a thing a model configured on their
   behalf, and they have no way to check it.
2. **The default is invisible.** Lovable Cloud is on by default and is Supabase
   underneath. A large share of users have a live Postgres database with a public API
   and do not know the word "Supabase", let alone "RLS".
3. **The cohort is the majority.** Over 60% of new Supabase databases now come from AI
   tools, and launches grew 600% year-over-year.
4. **The failure rate is measured.** 98% of vibe-coded apps carry at least one security
   flaw. One competitor scanning 96 AI-built apps found 2.37 million exposed records.

### What that implies for coverage priority

| Priority | Rationale |
|---|---|
| **Supabase** | Default backend for the two largest builders; the AI writes the RLS itself; 21M weekly downloads |
| **Firebase** | Second-largest installed base, but only one builder defaults to it; web-only scanning is tractable, mobile needs APK/IPA work |
| **Neon** via v0 | **Reclassified 2026-08-20 — see section 6.** Neon's Data API is PostgREST, on the same `/rest/v1/` mount Supabase uses. The claim that Neon has no public client API was true when this file was written and is not true now. |
| Upstash via v0 | User-selected rather than default; a Redis/Kafka HTTP API, not a relational one, so it is a different threat model |
| Replit, Base44 | **Out of scope** — closed backends, no public client API to probe |

The conclusion the data supports: Supabase-first was correct, and the reason is not
that Supabase is the biggest BaaS. It is that Supabase is where the *AI-generated*
applications land, and those are the ones whose access control was written by a model
for a user who cannot review it.

---

## 6. Which of them speak PostgREST

Added 2026-08-20. The section this file was missing, and the axis that decides how much
of this scanner transfers.

Product categories are the wrong unit here. What decides whether unruly works against a
target is not whether it is a "BaaS" — it is **which client data API it exposes**, because
that is what the scan talks to. On that axis the market is far more concentrated than the
adoption table suggests.

| Product | Client data API | Does the PostgREST machinery apply? |
|---|---|---|
| **Supabase** (hosted and self-hosted) | PostgREST at `/rest/v1/`, behind Kong | **Entirely.** This is what the tool was built against. |
| **Neon Data API** | **PostgREST at `/rest/v1/`** | **Yes — verified from Neon's own documentation:** the same mount path, PostgREST filter syntax (`?is_published=eq.true&order=created_at.desc`), and "a REST endpoint secured by JWT authentication and Row-Level Security". |
| **PostgREST, self-hosted** | PostgREST at whatever path it is mounted on | Yes. Corpus projects 01, 06 and 07 already model the bare-root, unreachable and reverse-proxied layouts. |
| Firebase | Firestore REST + RTDB REST | No. Different semantics end to end, which is why it is implemented separately. |
| Hasura, Nhost | GraphQL | No. |
| Appwrite, PocketBase, Directus, Convex, InstantDB, Parse, Amplify | Proprietary REST or RPC | No. |
| Replit, Base44 | None published | Out of scope by architecture — there is no client API to probe. |

### What this changes

The addressable surface for the PostgREST work is **Supabase plus Neon plus every
self-hosted PostgREST deployment**, not Supabase alone. Nothing in `internal/postgrest`,
`internal/enumerate` or the `-fix` SQL is Supabase-specific: the hint oracle, the
status-code semantics, the RLS reasoning and the remediation are properties of PostgREST
and Postgres.

### The load-bearing question, now settled by measurement

This section previously said Neon's documentation "does not say what happens to a request
carrying no `Authorization` header at all", set out two threat models depending on the
answer, and said it was an hour's work to settle on a project you own. It was settled on
2026-08-21 against a Neon project owned by this author (`still-wildflower-86993864`), and
the answer is the second branch.

**A request with no `Authorization` header does not reach an anonymous role. It is refused
before any table is consulted:**

```
GET /rest/v1/<any table>          (no Authorization header)
400  {"message":"missing authentication credentials: required authorization
      bearer token in JWT format"}
```

Identical for every table — including tables the `anonymous` role holds a `GRANT` on, and
tables no role holds a grant on. That identity is the important part: because the refusal
does not vary with the target, it carries **no information about any table's posture**. A
scanner that read it as "protected" would report a project as secure having measured
nothing. unruly reports it as `unruly-target-not-discriminating` and declines to grade the
target on that evidence.

This inverts the emphasis relative to Supabase. There, the anonymous key is the usual
culprit. On Neon as configured by default, the anonymous role is unreachable over HTTP and
**escalation is the headline**: Neon Auth signup is open, so a stranger can create an
account unaided, and the `authenticated` role receives whatever GRANTs a table carries.
Measured on the same project: a table with RLS never enabled returned **every row to an
account that had signed itself up seconds earlier**, including other users' card data.

Two consequences worth stating plainly, because both cut against vendor documentation:

- **PostgREST's anonymous role is not a given.** It exists by construction in PostgREST and
  is what Supabase exposes; Neon's deployment does not expose it publicly. Reasoning from
  "PostgREST has an anonymous role" to "Neon projects have an anonymous role" is wrong.
- **A grant is not RLS.** Neon's own console warns that a table with RLS disabled lets all
  authenticated users read every row. For `owner_only` that is false — no role holds a
  GRANT, so the answer is `403`/`42501`. The console is RLS-aware but not grant-aware, and
  a scanner that copies its reasoning inherits the false positive.

One thing remains **unmeasured, and is recorded as unmeasured rather than as passing**: the
anonymous role's `SELECT` grant on `anon_readable` is real in the database and cannot be
exercised through the Data API, because no HTTP caller can assume that role. It is proven
at the database level by the grant and by nothing this scanner sent.

---

## Sources

Backend adoption: npm registry API, GitHub REST API (2026-08-17).
PostgREST classification (section 6): Neon's own Data API documentation, fetched
2026-08-20 — neon.com/docs/data-api. The headerless-request behaviour above is NOT from
that documentation, which does not describe it: it was measured on 2026-08-21 against a
project owned by this author, and the measurement is committed at
fixtures/neon/answer-key.yaml with the exchanges recorded in fixtures/neon/transcript.json. Supabase's PostgREST layer is documented at
supabase.com/docs/guides/api. Comparison articles were read and NOT relied on: several
state that Neon has no auto-generated API, which the vendor documentation contradicts.
Platform figures: CNBC and TechCrunch on the Supabase Series F; Lovable, Vercel,
Replit and StackBlitz public statements and press coverage; Wix acquisition
announcement for Base44; Symbiotic Security's 1,072-app study; LaunchGuard's published
scan statistics; Lovable and Supabase integration documentation.

Private-company revenue and user figures are self-reported or press-reported and
cannot be independently verified.
