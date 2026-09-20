# Prior art, and what was taken from it

Architecture and eval-harness design only. No tool listed here contributes code
or runs in the scan path, and nothing about this project's detection logic is
derived from reading theirs.

## nuclei — output conventions, and a validation discipline

The terminal format follows nuclei's, deliberately: an id in brackets, then
protocol, severity and the matched URL. Operators already parse that shape, and
a scanner that invents its own line format makes itself harder to pipe into
whatever they have. The `-json` schema is NOT nuclei's, and README.md says so;
the field names are a contract pinned by tests.

The more useful borrowing is a rule, not a format. nuclei's
TEMPLATE-CREATION-GUIDE prescribes validating a template against three targets:
one known-vulnerable, one patched, and one similar-but-different application.
A template validated only against a vulnerable instance cannot distinguish a
detection from a coincidence.

This project's fixtures implement the same three-way discipline, arrived at
independently and worth stating in these terms because the parallel is exact:

| nuclei                     | here                                              |
|----------------------------|---------------------------------------------------|
| known-vulnerable target    | the `exploits` half of each answer key            |
| patched target             | the `protected` half -- precision controls that must stay silent |
| similar-but-different      | a control name that cannot exist, so "not found" is distinguishable from "refused" |

The third row is the one most often skipped. Firestore answers 403 identically
for a protected collection and one that never existed, which is why this scanner
never claims a Firestore collection is protected; the Cloud Function check
probes a name that cannot exist for the same reason.

## Prowler and ScoutSuite — a different question, not a better answer

Both are configuration scanners: they authenticate AS THE ACCOUNT OWNER, read
configuration through the cloud provider's APIs, and evaluate rules against it.
Prowler maps findings to compliance controls with pass/fail status. That is a
useful question and it is not this one.

An owner-authenticated configuration read cannot tell you what an anonymous
caller on the internet actually reaches, because it never makes that call. The
distinction is not academic: Neon's own console -- which reads configuration --
warns that a table with RLS disabled lets all authenticated users read every
row, and for `owner_only` that is false, because no role holds a GRANT. The
console is RLS-aware and not grant-aware. A scanner that asks the database what
it would do, rather than asking the API what it does, inherits that error.
benchmark/corpus/15-grant-vs-rls encodes exactly this case.

So the comparison to draw is not "more checks" but "a different epistemology":
they read posture, this measures reachability, and the two disagree in the cases
that matter most.

## What appears not to exist elsewhere, stated carefully

Every finding here publishes a command, and `make audit` executes those commands
and requires them to reproduce the finding that published them. On
2026-08-22 that check found five drifts in this project's own output, including
a Firestore command that omitted the projection keeping it from retrieving field
values, and a Remote Config command whose payload sat in single quotes so the
placeholder never expanded.

A web search did not surface evidence that nuclei, Prowler or ScoutSuite verify
their own published evidence this way. That is an absence in a search, not a
proven absence in those tools, and it is recorded as such: if one of them does,
this section is wrong and should be corrected rather than defended.

## Sources

- Matchers and extractors, template structure: deepwiki.com/projectdiscovery/nuclei
- Template validation discipline: nuclei-templates TEMPLATE-CREATION-GUIDE.md
- CSPM comparison and maintenance status: kloudle.com CSPM comparison, 2026
- Prowler compliance-control reporting: jonathansblog.co.uk/prowler-cloud-security-auditing

Read 2026-08-22. Comparison articles were read and not relied on for claims
about behaviour; where this document states what a tool does, it states what its
own documentation says it does.
