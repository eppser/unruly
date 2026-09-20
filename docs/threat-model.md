# Threat model

*Checked, not asserted: `TestThreatModelCoversEveryCheck` fails the build if a
check exists with no row here, or if this document names a check that does not
exist.*

What this scanner assumes an attacker has, what they want, and which of this
tool's checks answers each question. It exists so the report can be ordered by
consequence rather than by which subsystem happened to produce a finding, and so
a check that fits nowhere in it can be recognised as noise.

## The attacker

One assumption, and it is not pessimistic: **they have the public key.**

Both backends ship a credential to every visitor's browser by design — the
Supabase anon key, the Firebase web API key — and neither is a secret. Google
documents its key as public; Supabase's anon key is meant to be paired with
row-level security. So the attacker is not privileged, not lucky, and not
positioned: they are anyone who opened the site and pressed F12.

Three capability tiers follow, and the tool reports which one applies because
they cost an attacker very different amounts:

| tier | what it costs | how they get it |
|---|---|---|
| anonymous | nothing | the key in the bundle |
| signed-up | one HTTP request | `accounts:signUp` / GoTrue signup, where open |
| privileged | a mistake | a `service_role` key or a connection string in a bundle or an archive |

The middle tier is the one that gets missed. A rule or policy that admits "any
authenticated user" reads as secured, and where signup is open the set it admits
is everyone. A scan that never signs up cannot tell those apart, and reports the
project as protected.

## What they want, in the order it hurts

1. **Read what should be private.** Credentials, tokens, personal data,
   financial data. The most common outcome by a wide margin.
2. **Change or destroy what the business relies on.** Editing orders, deleting
   records, defacing content. Rarer, worse, and usually unmeasured because the
   naive probe for it is unsound.
3. **Execute.** Arbitrary SQL through a `SECURITY DEFINER` routine, or an Edge
   Function that runs with elevated credentials. Rare, and total when present.
4. **Pivot.** A `service_role` key or a Postgres URI turns every control above
   into a formality; an archived key does the same for a rotation that never
   happened.

## Which check answers which question

| question | checks |
|---|---|
| Can anyone read data they should not? | `app-cross-identity-read`, `app-auth-bypass`, `app-public-record-exposure`, `supabase-anon-read-exposed`, `firebase-firestore-anon-read`, `firebase-rtdb-anon-read`, `firebase-storage-anon-read`, `supabase-rpc-returns-data`, `supabase-graphql-rls-bypass`, `supabase-graphql-anon-read`, `supabase-public-storage-bucket`, `supabase-realtime-anon-subscription` |
| Does signing up change the answer? | `supabase-authenticated-escalation`, `firebase-firestore-authenticated-read`, `supabase-open-signup`, `firebase-auth-open-signup`, `firebase-auth-anonymous-signin`, `firebase-auth-weak-password`, `supabase-anonymous-signin-enabled`, `supabase-weak-password-policy` |
| Can anyone change or destroy data? | `supabase-anon-insert-allowed`, `supabase-anon-update-allowed`, `supabase-anon-delete-allowed`, `supabase-storage-anon-write`, `supabase-realtime-anon-delivery`, `firebase-firestore-anon-write`, `firebase-rtdb-anon-write` |
| Can anyone execute? | `supabase-anon-arbitrary-sql`, `supabase-edge-function-no-jwt`, `firebase-function-public` |
| Is a privileged credential loose? | `supabase-service-key-exposed`, `supabase-management-token-exposed`, `supabase-db-connection-string-exposed`, `supabase-historic-service-key-exposed`, `supabase-historic-key-not-rotated`, `supabase-historic-key-rotated`, `supabase-preview-deployment-key`, `firebase-remote-config-secret` |
| Is the application inconsistent with its own database? | `app-route-auth-inconsistency` |
| Does deployed access match the operator's declared policy? | `unruly-intent-violation`, `unruly-intent-summary` |
| What else might be worth looking at? | `unruly-subdomains-found` |
| What does the project disclose about itself? | `app-openapi-schema-exposed`, `app-docs-exposed`, `supabase-project-ref-disclosure`, `supabase-extra-schema-exposed`, `supabase-rpc-discoverable`, `unruly-relations-protected`, `firebase-storage-protected`, `firebase-storage-absent`, `firebase-function-private` |
| What did this scan NOT do, because nobody asked? | `unruly-stage-skipped` |
| What could this scan not see? | `unruly-surface-not-assessed`, `unruly-capability-degraded`, `unruly-probes-unresolved`, `unruly-probe-budget-exhausted`, `unruly-checks-skipped`, `unruly-target-not-discriminating`, `unruly-target-refused`, `unruly-credential-rejected`, `unruly-rest-prefix-corrected`, `unruly-rest-prefix-unresolved`, `unruly-scan-summary` |
| What did this scan leave behind? | `unruly-probe-row-left-behind`, `unruly-probe-object-left-behind`, `unruly-probe-account-left-behind`, `unruly-probe-document-left-behind` |

Two of those rows are not about the target at all.

**Disclosure** is not exposure. A leaked routine name, a schema name, a project
reference, a list of relations that answered correctly — none of it is data
anybody can read, and rating it as though it were is how a report fills with
things nobody can act on. It is reported because it is what the next attacker
starts from, and at `info` or `low` accordingly.

**Residue** is this scanner's own doing. A probe row it created and could not
delete is not a property of the project; it is a mess the operator now has to
clean up, and hiding it would be the least defensible silence in the tool.

The "could not see" row is not a courtesy either. Every row above it is a claim
about the target; that one is a claim about the scan, and without it a short
report is indistinguishable from a clean one.

## What is deliberately NOT in scope

- **The application's own logic.** Broken access control above the database is a
  different tool's job. `app-route-auth-inconsistency` is the one exception, and
  it exists because a route answering anonymously beside siblings that demand
  credentials is usually a database problem wearing an HTTP hat.
- **Denial of service.** Never probed. A scanner that measures whether it can
  exhaust somebody's quota has already done the damage.
- **Anything requiring a credential the operator does not hold.** The tool
  scans as the public, plus an account it created with permission.
- **Guessing.** Where existence is undecidable — a Firestore 403, an RTDB 401 —
  nothing is claimed. Recall is reported as a lower bound instead.

## How severity follows from the model

Severity answers *how bad*, and the model says that is a function of two things:
what an attacker can DO, and to WHICH data.

- Reading credentials or financial or personal data: **critical**.
- Reading data with nothing recognised in it: **high** — unless it earns the
  content demotion, which requires positive evidence of being the site's own
  copy, no write access, and a write probe that actually ran.
- Writing anything: **high**, and **critical** where it is also readable,
  because an attacker who can see the effect can iterate.
- Executing arbitrary SQL, or a loose privileged credential: **critical**
  regardless of what else is true, because both make the rest of the report
  moot.
- Statements about the scan itself: **info**, always. A reader filtering for
  things to fix must never be handed a scanner diagnostic.

## What would falsify this model

If a real incident against one of these backends arrived by a path with no row
in the table above, the model is incomplete and the check list with it. The
shapes most likely to do that, and currently unmeasured:

- A Storage bucket policy that allows listing but not reading, or the reverse.
- An Edge Function that trusts a header the caller controls.
- A Realtime channel carrying rows the REST API refuses.
- Firestore rules that differ per document rather than per collection, which no
  collection-level probe can see.
