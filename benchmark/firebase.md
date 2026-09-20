# Firebase benchmark

Measured against `firebase-lab-000000`, whose posture is known by construction:
the rules and seed data are in `FirebaseMap/lab/`, and every expectation below
comes from that file rather than from either tool's output.

Reproduce with `benchmark/firebase-protected-precision.sh`.

The platform behaviour this rests on is itself checked:
`TestFirestoreStillCannotDistinguishAbsentFromProtected` and its Realtime
Database counterpart fail if Google ever separates absent from protected. That
would make existence decidable, turn "protected" into something this tool could
honestly report, and make the comparison below obsolete — which is worth
learning from a failing test rather than from a report that has quietly become
less useful than it could be.

## The comparison that matters

Both tools find a world-readable collection by asking for it and getting `200`.
That part is not where they differ.

They differ on what a `403` means. Measured against this project:

| collection | exists? | anonymous |
|---|---|---|
| `public_notes` | yes, readable | `200` |
| `locked_secrets` | yes, protected | `403` |
| `collection_that_does_not_exist_xyz` | **no** | `403` |

A protected collection and one that was never created are indistinguishable,
and `listCollectionIds` is admin-only, so there is no second opinion available.

OpenFirebase (v1.3.1) classifies `403` as existence. Its summary label is
`"protected": "Protected Firestore collections (403)"`, and its status line for
that branch reads `PERMISSION DENIED - Database is protected`. It then guesses
names from a bundled wordlist of 50 or 500 entries.

Running its own top-50 wordlist against this project:

| | |
|---|---|
| entries tried | 50 |
| answered `403` | **50** |
| of those that exist here | **0** |

Every one would be reported as a protected collection. None of them are
collections; they are names from a list. On a project with five collections and
the 500-entry wordlist, the same rule produces roughly 500 claims of which
approximately five could be true.

unruly reports **no** protected collections, ever, on either database. The
finding it emits instead says recall is a lower bound, names how many candidates
were tried, and states that a refusal does not distinguish protected from
absent. `TestFirebaseFindsTheOpenAndIgnoresTheRest` includes a collection name
that has never existed and requires silence about it.

## The same rule, applied the other way, on the surfaces that permit it

The section above is a claim about Firestore, not about Firebase. Two other
surfaces answer differently, and this tool reports them differently as a
result — which is the point: the rule is "claim what the API can distinguish",
not "never say protected".

Measured against this project on 2026-08-18:

| surface | absent | denied | Can "protected" be claimed? |
|---|---|---|---|
| Firestore collection | `403` | `403` | **no** — indistinguishable |
| Realtime Database path | `401` | `401` | **no** |
| Cloud Storage bucket | `404` | `403` | **yes** |
| Cloud Function (v1) | `404` | `403` | **yes** |

The Storage measurement, on a project with no bucket provisioned:

```
GET /v0/b/firebase-lab-000000.firebasestorage.app/o   404
GET /v0/b/firebase-lab-000000.appspot.com/o           404
```

And Cloud Functions, for a name that is not deployed, in two regions:

```
GET https://us-central1-firebase-lab-000000.cloudfunctions.net/definitely-not-a-function-xyz   404
GET https://europe-west1-firebase-lab-000000.cloudfunctions.net/definitely-not-a-function-xyz  404
```

So `firebase-storage-protected` and `firebase-function-private` exist and are
positive results, while no equivalent exists for Firestore or the Realtime
Database. A scanner that reported "protected" uniformly across all four would
be right on two of them by accident.

**One thing NOT measured here, said plainly.** OpenFirebase's handling of
Storage and Functions has not been run against this project, so nothing above
is a comparison on those surfaces — only a statement of what the platform
allows and what this tool does with it.

The `403` column used to be unobserved too, and that sentence outlived the
fact. Billing was linked afterwards, so this project now has both: bucket
`unruly-lab-fixture-505809` with a world-readable object and a private control,
and two deployed functions — `publicEcho`, whose invoker binding includes
allUsers, and `privateControl`, identical except that it does not. The denied
caller's `403` is measured on both surfaces now, alongside the `404` for a name
that cannot exist.

## Recall, and the honest limit of this measurement

Zero of OpenFirebase's 50 wordlist entries exist in this project, so its recall
here is 0 of 2 readable collections. unruly finds both, because it harvests
vocabulary from the application's own bundle.

That number flatters us and should be read carefully. This lab's collections are
domain-specific (`public_notes`, `public_writable`), which is what a generic
wordlist is worst at. A project whose collections really are called `users` and
`posts` would be found by both. The defensible claim is narrower than "better
recall": a wordlist finds conventional names and nothing else, and the
application's own bundle is where the rest of them are — the same result this
project measured on the Supabase side, where a 90-entry list matched 1 relation
of 21 and harvested vocabulary recovered 21 of 21.

## What is NOT claimed

- Nothing about OpenFirebase's Android/APK extraction, which unruly does not
  do at all and which is the larger part of that tool.
- Nothing about OpenFirebase on Storage, Cloud Functions or Remote Config. The
  lab has a bucket and two deployed functions now, and unruly is graded on
  both — but OpenFirebase has not been run against them, so there is no
  comparison to report. What is missing here is the other tool's numbers, not
  the surface.
- Nothing measured by running OpenFirebase end to end. Its classification was
  read from its source at the lines quoted above, and the request behaviour it
  keys on was measured directly. Installing it pulls a git fork of androguard,
  which is a heavier dependency than this comparison needs.
