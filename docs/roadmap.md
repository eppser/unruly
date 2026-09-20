# Roadmap

Work that is decided but not built. Each entry says what is missing, why it
matters, and what it is blocked on — so an item that cannot move is
distinguishable from one nobody has started.

## What is already done, verified 2026-08-19

A stale to-do list costs more than it looks: it sends the next session to
rebuild something finished, and the second implementation is rarely as good as
the first. Each line below was checked by running the code, not by reading it.

| Claim | State | How it was checked |
|---|---|---|
| Plain-language mode | done | `-plain`, graded by `plain_coverage_test.go` |
| CSV, terminal tables, HTML report | done | `-csv`, `-html`, `finding.Table` |
| Write-coverage summary contradicts itself | **fixed** | `WriteCoverage` computes the sentence from the findings; with UPDATE and DELETE findings present it prints "INSERT on 1, UPDATE on 1, DELETE on 1" |
| Fixture breadth beyond PostgREST | largely done | auth, storage, realtime, edge-runtime, matrix, throttled and flaky fixtures, plus 15 corpus projects |
| Data classifier by kind and capability | done | `internal/classify` by name AND value, on both backends and both roles |
| Anonymous sign-in and weak password checks | done | `internal/surface/anonymous.go`, `firebase_auth.go`, `escalate/acquire.go` |
| Remediation for RLS-off, UPDATE/DELETE, FOR ALL | done | present in 8, 5 and 2 files respectively; executed verbatim by `eval-remediation` |
| Explicit threat model driving severity | done | `docs/threat-model.md`, 17 rows, held by `threatmodel_test.go` |
| Evals and benchmarks out of the shipped binary | done | `go list -deps ./cmd/unruly` links neither `internal/eval` nor `internal/exploit` |
| Supabase behind the provider seam | done | 10 stages in `backend/supabase/`, 12 `runStage` call sites; `scanTarget` 717 code lines, from 1,330 |

## What landed since, verified 2026-08-22

Same rule as the table above: each line was checked by running something, and
the check is named. The dates are kept apart rather than merged, because a
reader deciding whether to trust a row wants to know when it was last asked.

| Claim | State | How it was checked |
|---|---|---|
| Neon as a second backend | done | 4 stages in `internal/provider/neon.go` reusing `internal/probe` and `internal/enumerate`; `CapEscalate`, `CapWrite` and `CapListing` dropped from `Cannot()` one at a time, each with an eval watched red |
| Neon covered end to end | done | `eval-neon` (offline transcript replay), `eval-neon-live` (independent implementation, must agree), `eval-neon-binary` (the built binary, as an operator runs it) |
| Firebase Cloud Functions | done | see the section below: deployed and measured, 200/403/404 in one run |
| Firebase Storage anonymous read | done | `firebase-storage-anon-read` proven with sampled evidence and a replayable request |
| Vendor-console benchmark datapoint | done | `benchmark/corpus/15-grant-vs-rls` and `benchmark/README.md`: Neon's console is wrong in BOTH directions, flagging a table nobody can read and clearing one anybody can |
| Lab residue cleaned and checked | done | `neonfixture.PruneProbeSessions` (102 accumulated sessions found and removed, wired into the audit); Firebase probes record what they could not delete; the Supabase lab reset is now verified either side rather than assumed |
| A drifted lab is not a failed exploit | done | five branches across three backends set `Outcome.Unmeasured`; three consumers act on it; `cmd/exploitcheck` exits 3 and `scripts/audit.sh` renders that as _not run_ |
| Pending exploits | 3 -> 2 | `maxPendingExploits` tightened; `supabase-realtime-anon-subscription` reclassified with a live tripwire that fails if the platform makes it reachable |
| Audit | 27/27, six runs running | `docs/audit-report.md`, nothing skipped, every live eval executed |

**Not done, and now fully diagnosed:** `14-firebase` is still the one corpus
project that is not scored. Three layers of Supabase assumption came off to get
this far -- `Validate` demanding an anon key every backend has, `AnonKey`
demanding the variable be set, and the grader reading Supabase finding ids only
-- and the ground truth is measured and committed. What remains is not
bookkeeping.

The scanner cannot address a Firebase EMULATOR on either surface.

- Firestore is `firestoreHost`, a package variable fixed at
  `https://firestore.googleapis.com`. A test in the same package may point it
  elsewhere; nothing outside can.
- The Realtime Database looked reachable, because `rtdbFindings` takes its host
  from the application's own `databaseURL` rather than a constant -- so a site
  serving a `firebaseConfig` would seem to be enough. It is not.
  `rtdbReadable` builds `host + "/" + path + ".json?shallow=true"`, and the
  emulator selects a namespace with `?ns=`, which that expression cannot
  express. A bare host loses the namespace and the emulator answers `200 null`
  for every path, which the probe correctly reads as nothing; a host carrying
  `?ns=` produces a malformed URL. Measured: unauthenticated GETs without `ns`
  returned `200 null` even for `admin_tokens`, which is denied.

So scoring this project means making the scanner pointable at an emulator on
both surfaces -- an override reachable from outside the package, in the request
path of a security scanner. That is a decision about attack surface, not an
edit, and it is deliberately left open here rather than taken quietly.

The alternative, worth weighing: the Firebase accuracy claim is already carried
by `benchmark/firebase.md`, measured against the real lab. Corpus scoring would
add repeatability without credentials, not a new claim.

What genuinely remains, in the order it is worth doing:

**On the seam, and what the pause cost.** This sat listed as deliberately
paused, reasoning that extracting the stages "means reordering requests, which
changes the ledger", that the backend stages "are NOT contiguous", and that it
"has no user-visible benefit".

The first two were right. Escalation's port did change the ledger: it put
escalation into the spend breakdown for the first time, which turned out to be
a fix, because a pass that re-probes every relation with an elevated key could
previously be the largest spender in a scan and never appear in the
largest-first list an operator reads to decide what to cap. And the stages are
still not contiguous -- discovery and the blindness-disclosure block remain
interleaved with target-level work.

The third was wrong, and the correction matters more than the line counts.
Extracting these decisions found three defects that were shipping:

- a supplied key belonging to another project was withheld, and the credential
  discovery had ALREADY recovered from the target was discarded with it, so the
  scan reported "backend not assessed" on a project it could have read
- that withholding was never disclosed in the report, only logged
- `-no-residue` was not inherited by the per-schema probe, so a scan promising
  to create nothing would leave rows behind in every schema but the default --
  and the mutation meant to catch it had been reporting "caught" for as long as
  it existed, because the harness's own bookkeeping check answered first

Two of those are silent false negatives. None was found by reading the code;
each surfaced once the decision was small enough to test on its own. The
benefit was never tidiness.

1. **Crawling** to widen discovery. Subdomain enumeration exists
   (`internal/subdomain`); following links inside an application does not.
2. **Platform detection** (Lovable, Bolt, Base44). Blocked on evidence, not on
   effort — see below.

## Firebase Cloud Functions: CLOSED, the public path is measured

`firebase-function-public` reports a function whose invoker binding includes
allUsers. This entry recorded it as never seen on real infrastructure, because
deploying needed a Blaze plan the lab did not have.

Resolved. Billing was linked, firebase-tools deployed `publicEcho` and
`privateControl` to firebase-lab-000000, and three shapes were measured in one
run against the live project: the public function RAN and returned its own
output, which a reachable endpoint that refuses cannot produce; the private one
answered 403, so "public" means invocable rather than resolvable; and a name
that cannot exist answered 404. The interactive login turned out not to be
needed — the lab's service account authenticates the CLI through
GOOGLE_APPLICATION_CREDENTIALS.

The same billing change gave the lab bucket `unruly-lab-fixture-505809`, so the
Storage 403 column in benchmark/firebase.md is measured too rather than quoted
from Google's documentation.

Left here rather than deleted, because a roadmap that only ever grows records
what was hard and never what it cost to settle. Two functions remain deployed
on the owner's billing account; `publicEcho` is deliberately world-callable and
returns a constant synthetic string.

## Authenticated scanning against confirm-required projects

**What exists.** The scanner already becomes a logged-in user without help. It
derives an address from the project reference, signs up, stores the credential
in `~/.config/unruly/identities.json`, and reuses it on later scans rather than
registering again. That covers every project with `mailer_autoconfirm` on, which
is the default and the common case, and it is what makes
`supabase-authenticated-escalation` fire — the tier this tool's own threat model
calls the most-missed.

**What is missing.** A project with email confirmation ON issues no session at
signup. The scan says so and stops:

> signup succeeded but the project requires email confirmation, so no session
> was issued; supply -user-jwt for a confirmed account to measure what a
> logged-in user can reach

Honest, and a gap: on those projects the authenticated tier goes unmeasured
unless an operator makes an account by hand. Receiving one message would close
it.

**OpenFirebase is not a reference for this.** It was suggested as one, and it
does not do it: its authenticated scan takes `--email` and a password from the
operator (`required with --check-with-auth unless --google-id-token is used`)
and falls back to anonymous sign-in or a supplied Google ID token. There is no
mail integration in it at all. Our identity handling is already further along.

**Approaches, in the order they are worth trying.**

1. *A domain we control, routed to a Worker.* Cloudflare Email Routing accepts
   a catch-all for a registered domain and forwards each message to a Worker,
   which stores it in KV; the scanner reads the confirmation link back over an
   authenticated endpoint. No third party sees the mail, there is no per-message
   cost, and the addresses are ours — which matters because the address a
   scanner registers ends up in somebody's user table with our name on it.
   Needs: a registered domain (we currently own none — `unruly-lab.dev` in the
   exploit harness is deliberately unregistered), plus a Worker and a KV
   namespace. Cloudflare is already in use for the exploit lab.

2. *A mailbox API built for test automation* (MailSlurp, Mailosaur). Fastest to
   integrate and the least to operate. Costs a subscription, puts a third party
   in the path of confirmation links, and adds a network dependency to a tool
   whose scan path is deliberately free of them — so if it is used at all it
   belongs behind an explicit flag, never in the default path.

3. *A free disposable-mail API* (mail.tm and similar). No key and no cost, and
   no guarantee of being there next month. Acceptable for a lab, not for
   something an operator runs against a client's project.

**Constraints any of them must respect.**

- Deterministic scan path: no third-party call unless the operator asked for it
  by flag. Confirmation is opt-in, like `-write`.
- One account per project, still. The identity store and the derived address do
  not change; only the way a session is obtained does.
- The account is residue and stays reported. `unruly-probe-account-left-behind`
  already names it and gives the SQL to remove it.
- `-no-residue` must keep refusing to register at all.

**Is a domain required?** Only for the first approach. A mailbox API hands out
an address on its own domain and needs nothing but a key.

The reason to want one anyway is not the mailbox, it is the ADDRESS this
scanner leaves in somebody's user table:

- Disposable-mail domains are widely blocklisted by signup forms, and the
  projects that block them are disproportionately the ones with confirmation
  turned on — which is the exact case this work exists to reach. A third-party
  address risks being refused by the targets it was added for.
- The account is residue. `unruly-probe-<hash>@example.invalid` is
  unmistakably a scanner's and unmistakably non-routable; `a7f3@mailslurp.net`
  tells the operator who finds it nothing and gives them nobody to contact. A
  domain we own keeps it identifiable, and reachable if someone wants to ask
  about it.
- A confirmation link is a credential-bearing URL for an account on someone
  else's project. Keeping it off a third party's servers is the more
  defensible default for a tool that is run against clients.

None of that blocks shipping. A key behind an opt-in flag works today.

**Blocked on:** a decision about which approach. Only the first one needs a
domain; the others need an API key and nothing else.

**Decided 2026-08-19: AgentMail (agentmail.to), measured rather than chosen on
its description.** It is approach 2 — a mailbox API — and it removes what made
approach 1 attractive, since the only reason to prefer a Worker was that we own
no domain and a mailbox API cost a subscription per project.

Every capability the confirm-required flow needs was exercised against the live
API before this was written down:

| what the flow needs | result |
|---|---|
| authenticate | 200 |
| create an inbox on demand | 200, immediate |
| deliver a message | arrived on the FIRST poll, under 2s |
| read the body and recover a link | `https://…/confirm?token=…` recovered from a real round-trip |
| DELETE the inbox afterwards | 202, account returned to its prior state |

The last row is the one that decided it. This scanner reports its own leftovers
-- `unruly-probe-row-left-behind`, `unruly-probe-account-left-behind` -- because
residue is the tool's mess rather than a property of the target. A provider
whose inboxes cannot be removed would have added a permanent artefact to every
confirm-required scan, and there would have been nowhere honest to put that in
the report.

The latency figure is why a bounded poll is safe: at under two seconds, a 30s
ceiling is roughly fifteen times the observed cost, so a scan can wait for a
confirmation without becoming a scan that hangs.

**What is still unverified, and it is the risk that could sink this.** Whether a
real Supabase project's confirmation mail actually reaches an agentmail.to
address. It is a shared throwaway domain, and some SMTP configurations reject or
filter exactly those. The measurement above used AgentMail's own send path, so
it establishes that the mailbox side is fast and readable -- not that a given
project's mail will arrive. That can only be settled against a project with
confirmation enabled, and it should be settled before the flag is documented as
working.

The constraints below are unchanged by this choice: the call is opt-in, one
account per project still, the account stays reported as residue, and
`-no-residue` still refuses to register at all.


## Platform detection: blocked on a sample, not on effort

A large share of the projects this tool exists for are built by a platform
rather than by hand, and the platform is what the owner knows. Lovable Cloud
projects ARE Supabase instances that Lovable manages — the owner never sees
them in a Supabase dashboard and cannot inspect them from that side. Telling
such an operator "Supabase" answers a question they did not ask and points them
at a console they cannot open.

CVE-2025-48757 is the reason this is worth doing: 303 endpoints across 170
Lovable projects, 10.3% of 1,645 analysed, were readable by unauthenticated
requests with the public anon key.

**What blocks it.** Neither Lovable's documentation nor Supabase's own
troubleshooting guide publishes a fingerprint. Supabase's guide says the
reliable way to tell Lovable Cloud from a connected Supabase project is to
click the Cloud icon inside Lovable's editor — which a scan cannot do. No URL
pattern, domain, or bundle marker is documented.

The only way to derive one is to read a real Lovable-published application, and
this project scans owned or authorised targets only. One page of HTML from an
application whose owner consents would settle it; harvesting fingerprints from
strangers' sites would not, whatever the intent.
