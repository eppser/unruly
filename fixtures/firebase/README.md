# Firebase Storage lab fixture

Bucket `unruly-lab-fixture-505809` on project `firebase-lab-000000`.
Synthetic data only.

| anonymous request | answer | why it is there |
|---|---|---|
| `GET /v0/b/<bucket>/o` | 200, object names | the exposure `firebase-storage-anon-read` reports |
| `GET /v0/b/<bucket>/o/public%2Fcustomers.json?alt=media` | 200, body | contents open too |
| `GET /v0/b/<bucket>/o/private%2Fcontrol.json?alt=media` | 403 | the precision control |

`private/control.json` appears in the listing and its CONTENT is refused. A
scanner that reports reading it is producing a false positive; one that reports
nothing at all has missed the listing.

## Two things that cost hours, recorded so they do not again

**The bucket needs the Firebase Storage service agent to hold IAM on it.** A
bucket created through the GCS API and then imported with `buckets:addFirebase`
is registered but not usable: every listing answers 403 no matter what the
rules say, and the giveaway is a 412 elsewhere reading *"A required service
account is missing necessary permissions"*. Granting
`roles/storage.admin` to `service-<projectNumber>@gcp-sa-firebasestorage.iam.gserviceaccount.com`
on the bucket is what fixes it. Until then the rules are not being consulted
at all, so no amount of rewriting them changes anything.

**`allow list` must sit inside a nested match.** Declared on the parent
`match /b/{bucket}/o` it compiles, releases successfully, and grants nothing.
Listing stays 403 while `allow get` on a sibling path works fine -- which makes
it look like a rules-evaluation quirk rather than a placement mistake.

Rules are deployed through the Rules API rather than the console:
create a ruleset, then PATCH the release with `?updateMask=rulesetName`.
