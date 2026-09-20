# Security policy

## Reporting a vulnerability in unruly

Open a private security advisory on the repository, or email the maintainers.
Please do not open a public issue for anything exploitable.

A false negative is a vulnerability in this project. A scanner that misses an
exposure is worse than no scanner, because it produces confidence that was not
earned. Reports of missed findings are treated with the same priority as
crashes, and are expected to arrive with a reproducer — ideally a fixture in
`fixtures/` whose posture is known by construction.

## Platform behaviour this tool depends on

Two of unruly's techniques rest on behaviour of the upstream platform
rather than on any misconfiguration by the operator. Both were measured during
development and both are documented here rather than left implicit, because a
technique nobody has disclosed is a technique whose disappearance will silently
break the tool.

### PostgREST discloses relation and routine names to any key holder

Requesting a near-miss name returns the real one:

```
GET  /rest/v1/signator      → hint: "Perhaps you meant the table 'public.signatory_submissions'"
POST /rest/v1/rpc/admin_lis → hint: "Perhaps you meant to call the function public.admin_list_submissions"
```

This is an information disclosure: it reveals schema structure — including
`SECURITY DEFINER` routines that appear in no client bundle — to anyone holding
the public anon key, regardless of row-level security. RLS protects rows, not
names, so the disclosure is not a policy failure by the operator.

It is arguably intended developer ergonomics rather than a defect. unruly
uses it because attackers can, and because a scanner that ignores an available
channel gives its user a falsely reassuring picture. **Maintainers should
report this to Supabase and PostgREST before publishing any writeup of the
technique**, and treat the enumeration behaviour as liable to change.

### Realtime subscription acknowledgements do not reflect authorisation

Supabase Realtime acknowledges a `postgres_changes` subscription for a relation
that does not exist, identically to one that does:

```
zzz_definitely_not_a_table  {"status":"ok","response":{"postgres_changes":[{"id":21942019,...}]}}
cves (RLS-protected)        {"status":"ok","response":{"postgres_changes":[{"id":46914639,...}]}}
```

RLS is applied at delivery time, not subscription time. This is not a
vulnerability, but it is a trap for tool authors: **any scanner reporting
"Realtime exposure" from a subscription acknowledgement is emitting false
positives.** unruly reports nothing from this signal and runs a control
probe each scan to detect if the behaviour ever changes.

## Using this tool

**Do not give it a service_role key.** It refuses one, and the reason is worth
stating: every finding here is a claim about what an ANONYMOUS caller can
reach, and service_role bypasses row-level security by design. Scanned with
one, the reference target reported 14 read-exposed relations where the truth is
7 — describing seven correctly protected relations as readable by anonymous
callers. A missed finding hides one problem; that invents seven and discredits
the real ones alongside them.



Enumeration and write probing against systems you do not control is
unauthorised access in most jurisdictions, regardless of intent. `-write` is
refused unless `-yes-i-own-this` is also passed; that flag is a statement about
authorisation, not a formality.

### Two levels of consent

`-write` permits writes that create data: an `INSERT` the probe cleans up after
itself, and a `POST` to an application route.

`-invoke` additionally permits CALLING discovered database routines and Edge
Functions, which RUNS code the operator did not write. A routine named purge or
a function named send-email does what it says.

They are separate because the risks are not comparable, and because a single
flag meant a user authorising a test INSERT was also authorising arbitrary
function execution. `-invoke` requires `-write`.

### Every request this tool makes that is not a read

Audited exhaustively, because three separate default behaviours turned out to
contradict the safety model this file describes. The write gate existed the
whole time; nobody had checked which writes went through it.

| Request | When |
|---|---|
| `INSERT {}` into a relation | `-write` |
| `DELETE` of a probe row it created | `-write` (cleanup only) |
| `POST` to an application route | `-write` |
| `POST` to a discovered routine (invokes it) | `-write -invoke` |
| `POST` to an Edge Function name (invokes it) | `-write -invoke` |
| `INSERT` into a writable relation to trigger a Realtime payload | `-write` |
| `POST` to a name that cannot exist (self-check, enumeration) | always |

The last row is the residual risk and it is not fully eliminable. Routine
enumeration works by POSTing deliberate near-misses — truncations of real words
— to make PostgREST volunteer names. A truncation is chosen precisely because
it should NOT be a real routine, but nothing guarantees that: if `admin_purg`
happens to be a real zero-argument function on some project, discovering the
schema calls it.

Removing that would remove the enumeration capability entirely, which is the
one thing this scanner does that others do not. It is stated here instead so
the trade-off is the reader's to accept rather than one made silently on their
behalf.

### Routines are not invoked by default

There is no way to ask a database "may I call this function" without calling
it: PostgREST checks EXECUTE when the statement runs, so the probe invokes the
routine and reads what comes back. A routine that is callable therefore RUNS.

Verified on a fixture with a zero-argument `SECURITY DEFINER` function that
deletes rows: a `-write` scan invoked it and the table was emptied. That is
what an admin routine named purge, reset or delete does for a living, and
SECURITY DEFINER ones run with the owner's rights regardless of what the caller
is allowed to touch.

So invocation needs `-write`. Without it, routine DISCLOSURE is still reported
— that is a read — and callability is reported as unknown, which is true.

### Edge Functions are not probed by default

Detecting one requires a POST. The platform answers 404 for absent, 401 when
`verify_jwt` rejects the caller, and anything else means the request reached
the function — which is to say the function ran. A function deployed with
`verify_jwt` off is invoked by the act of detecting it, and Edge Functions send
email, charge cards and write to queues.

`-write` includes them. Without it no Edge Function is detected at all, and the
scan says so rather than leaving an apparently clean result.

### Route probing uses GET by default

Comparing route families needs to know which siblings demand credentials, and
many API routes are POST-only. Sending `POST {}` to discover that is a write to
somebody's application — `/api/subscribe`, `/api/send-email`, `/api/orders` —
and it used to run by default while a single database INSERT was gated behind
two flags. It now needs `-write`.

Without it, a family whose siblings are POST-only answers 405 to GET, which is
not an authorisation signal, and a real inconsistency can be missed. On the
reference target the open admin route is only detected with `-write`. The scan
logs which mode it used.

### One probe can leave a row it cannot remove

`-write` normally cleans up after itself. There is exactly one state where it
cannot, and it is inherent rather than a shortcoming: a relation that accepts
anonymous `INSERT`, refuses anonymous `SELECT`, and has no `NOT NULL` column.
PostgREST answers `201 Created` with no `Location` header and an empty body,
and recovering the new row's primary key would require the very `SELECT` the
relation forbids.

The scanner reports this as a `high` finding naming the relation, so the row is
never left behind silently. `-no-residue` skips the probe entirely, trading
write recall on that one state for a guarantee that the scan changes nothing.

This was found by the generated state-space fixture (`fixtures/matrix`), not by
review — three hand-written fixtures had never produced that exact combination.

Findings quote real rows from the target database as proof. Treat scan output
as containing production data.

`-redact` suppresses every sampled value while keeping counts, column names and
verdicts, so a redacted report still evidences each exposure without carrying
the data. It covers sampled rows, response excerpts from application routes,
and recovered key prefixes.

That coverage is asserted by test rather than assumed. An earlier version
threaded the flag into the relation probe but not the route probe, so a
redacted report still carried the body an unauthenticated caller received —
which on the reference target is internal pipeline records. It was found by
grepping a real redacted scan for values known to be in the database, not by
reading the code, and that check is now a test.

## The scanner's own exposure

This tool points at hosts nobody controls -- that is its purpose -- and it
carries the operator's credentials on every request to the target. Two
consequences are worth stating plainly.

**It does not follow redirects.** Go strips `Authorization` when a redirect
crosses domains but never strips a custom header, and Supabase's `apikey` is
one. A host that answers 302 would otherwise harvest the project key from any
scanner that follows. Measured against a local pair of servers before this was
fixed: the second origin received both the apikey and the bearer token. A 3xx
is now returned to the caller as the answer, which is also more informative --
PostgREST, GoTrue, Storage and Realtime do not redirect in normal operation.

**Names recovered from a target are validated before use.** The hint oracle
returns strings chosen by the host being scanned, and those names reach both a
URL and the `-fix` remediation, which exists to be pasted into a SQL console.
Measured before this was fixed: a hint reading

    Perhaps you meant the table 'public.users; DROP TABLE audit_log; --'

was accepted verbatim and would have been emitted as

    ALTER TABLE users; DROP TABLE audit_log; -- ENABLE ROW LEVEL SECURITY;

so a hostile host could get arbitrary SQL run by whoever scanned it. Two others
got through: a name carrying `?select=*&limit=999999`, and one using `../` to
reach other endpoints. Names must now match `[A-Za-z0-9_$]{1,63}`. That is
narrower than Postgres allows -- a quoted identifier may contain spaces, so a
table called `"my table"` is skipped -- and the false negative is taken
knowingly, because the alternative is executing what a scanned host asks for.

**Target text cannot drive the terminal.** Findings carry strings the scanned
host chose -- error codes and messages, object names, response snippets, row
identifiers -- and the renderer emits ANSI escapes of its own, so its output is
a terminal control stream. Measured before this was fixed: a hostile evidence
value rendered verbatim, clearing the screen and printing a green
`scan complete: 0 findings`. Control characters are now shown inert (`\x1b`)
at the render boundary, so an operator sees what the target sent rather than
obeying it. Sampled rows and `-json` output were already safe: `json.Marshal`
escapes control characters.

**The report never carries a whole credential.** The scan holds the operator's
key and recovers others -- from the page, from a web archive, from a preview
host -- and every finding quotes at most a sixteen-character prefix: enough to
say WHICH key, not enough to use. Credential-shaped strings inside an Edge
Function's response body are masked too, and that one is unconditional rather
than tied to `-redact`, because declining to republish somebody's key is not a
preference. Sampled ROWS are deliberately left alone: there the data is the
exposure being reported, and `-redact` exists for readers who need it gone.
Asserted end to end against fixtures that serve four different credentials.

**Responses are bounded.** A reply is read up to 1MB and drained up to 8MB, so
a hostile host cannot exhaust memory, and a host that accepts a connection then
says nothing hits the request timeout rather than stalling every probe behind
it. Both are tested in internal/client/hostile_test.go.
