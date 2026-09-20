# PocketBase: the measured truth table

Every line here was MEASURED against a running instance before any of it
reached code. None of it was carried over by analogy from Supabase, and the
places where the analogy would have been wrong are marked, because those are
the ones that matter.

Reproduce with `make fixtures-pocketbase`, grade with `make eval-pocketbase`.
Measured on PocketBase v0.39.11.

## The boundary is one character

A collection rule is one of three things, and telling them apart is the job:

    null          superuser only
    ""            open to the world
    expression    e.g. @request.auth.id != "" -- behaves as a FILTER

`null` and `""` are one character apart and are the whole boundary.

## Anonymous behaviour, measured

| probe                                   | result                                   |
|-----------------------------------------|------------------------------------------|
| `GET /api/collections` unauthenticated  | **401** -- enumeration is privileged      |
| LIST, `listRule: ""`                    | **200** with items -- data leaks          |
| LIST, `listRule: null`                  | **403** "Only superusers can perform..."  |
| LIST, collection absent                 | **404** "Missing collection context."     |
| LIST, expression rule                   | **200 with ZERO ROWS**                    |
| CREATE, `createRule: ""`                | **200** -- anonymous insert succeeds      |
| PATCH/DELETE fake id, rule null         | **403**                                   |
| PATCH/DELETE fake id, rule `""`         | **404**                                   |

## Three traps, each of which would have shipped

**A 200 is not a read exposure.** An expression rule filters every row away and
still answers 200 with an empty items array -- which the DEFAULT `users`
collection does on every install. A scanner keying on status reports that
collection as leaking on every PocketBase target in the world. The read signal
is ROWS RETURNED.

**A 404 on a fake id does not prove permission.** It means "not denied by a
null rule". An expression rule that matches nothing returns the byte-identical
404, so 404 cannot separate "you may" from "you were filtered out". Only 403 is
conclusive, and it is conclusive in the NEGATIVE. Proving update or delete
permission needs a real write, so it stays behind `-write -yes-i-own-this`
exactly as on Supabase.

**Realtime subscription acceptance is not exposure.** `POST /api/realtime`
returns 204 for ANY collection name. Measured end to end: an anonymous client
subscribed to a locked and a public collection, then a record was created in
each -- 1 event delivered for the public one, 0 for the locked one. Rules are
enforced at DELIVERY. Reporting exposure on a 204 would be wrong on every
locked collection on every target.

## Registration is open by default

A fresh instance creates `users` with owner-scoped data rules and
`createRule: ""`. Measured: an anonymous POST creates a real account. So
registration is open on essentially every deployment that has not closed it,
and it is the PocketBase counterpart of Supabase open signup: register, then
re-probe, because rules of the form `@request.auth.id != ""` open only for a
logged-in caller.

The gain is the DIFFERENCE. A collection returning the same rows to both
callers was already reported by the anonymous pass.

## Files bypass the collection rules

File fields carry a `protected` option defaulting to **false**, and
`/api/files/{collectionId}/{recordId}/{filename}` does not consult the
collection's viewRule.

| field `protected` | collection viewRule | anonymous fetch |
|-------------------|---------------------|-----------------|
| false (default)   | `""`                | 200, contents   |
| false (default)   | **null (locked)**   | **200, contents** |
| true              | null                | 404             |

So a collection whose record API is entirely closed still serves every uploaded
file to anyone holding the URL. Remediation verified in both directions: set
`protected: true`.

The fixtures model this as `open_files` and `locked_files`, present on BOTH
instances: `protected: false` on the vulnerable one, `true` on the hardened
one, and every record rule null on `locked_files` either way. Same names in
both, because a hardened instance that simply lacked the collection would 404
and score clean for the wrong reason.

Until e42aeab neither collection existed here. The file surface was the one
shape these fixtures never reproduced, which is how a graded suite passed
against a stale lab while the repo's own fixtures were incomplete: the table
above was measured, and nothing in this repository could reproduce it.

HONEST LIMIT: the URL needs collectionId, recordId and filename. Those are not
secret -- they appear in exports, logs and referrer headers, and come back in
full from any readable collection -- but they are not enumerable from nothing.
This is "anyone holding a URL bypasses your rules", not "anyone can list your
files".

## Cleanup is possible, so -no-residue means something here

The escalation probe must create an account. Measured: it can delete itself
with its own token (the default deleteRule is `id = @request.auth.id`), and
re-authenticating afterwards fails. No superuser credential is needed, which
matters because a scanner never has one.

A 204 on the delete proves one request succeeded. Only the failed re-auth
proves the account is gone.

## What is NOT covered

    weak or default superuser credentials  The admin API answers 401 by default
        on /api/settings, /api/backups, /api/logs and /api/collections, so a
        reachable login page is not itself an exposure. Guessable credentials
        would be, and nothing here tests them.
    JS hook misuse   Hooks can bypass collection rules entirely. Nothing here
        examines them, and from outside a deployment there may be no sound way
        to.
