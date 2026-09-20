# 14 — Firebase (Firestore + Realtime Database + Auth)

## What this target is for

**The one property it measures that no other project does: a different backend
entirely, whose security model defaults in the OPPOSITE direction to
Postgres's — and whose two halves default in opposite directions to each
other.**

Everything else in this corpus is PostgREST over Postgres. The scanner also
supports Firebase, and until this project existed that support was measurable
only against a live Google project. The emulator suite serves the same REST
surface a real project does, so probes written for the cloud work unchanged:

- Firestore: `GET /v1/projects/<id>/databases/(default)/documents/<collection>`
- Realtime Database: `GET /<path>.json?ns=<namespace>`

The defaults are the point:

| | default when no rule matches | can a deeper rule tighten a looser one? |
|---|---|---|
| Postgres + RLS | **open** if RLS is off and a GRANT exists | n/a |
| Firestore | **denied** | yes, each `match` is independent |
| Realtime Database | denied at the root here | **no** — see below |

A scanner that ports its Supabase reasoning across gets Firestore backwards.

## What a correct scanner must report

**Firestore**

- `user_profiles` — `allow read, write: if true`. The "test mode" rule the
  Firebase console generates and people keep. 5 documents with emails, phone
  numbers and bcrypt hashes. Anonymously **readable, creatable and deletable**;
  all three measured, and the create/delete pair restores the collection.
- `employee_records` — `if request.auth != null`. Invisible without a token,
  fully readable with one. Salaries and home addresses. Measured end to end:
  `POST accounts:signUp` with an empty body returns a 439-character ID token to
  a stranger, and that token reads every record. The verifier chains the token
  between requests, so this is a measured claim, not a remembered one.

**Realtime Database** (namespace `unruly-bench-14-default-rtdb`)

- `open_chat` — `.read: true, .write: true`. Readable and writable
  anonymously.
- `open_chat/private_dm` — carries `".read": false` **and is readable anyway**,
  including a message containing a shared password. RTDB rules cascade
  downward: a grant at an ancestor covers the whole subtree and a descendant
  cannot revoke it. This is the most commonly misread thing about the language.
  Measured, not quoted from the docs.

## What a correct scanner must NOT report

- `public_announcements` — world-readable **by design**. It is a marketing
  feed. Reporting it is noise. Writes are refused, and that is asserted too.
- `billing_secrets` — denied to anonymous and to signed-in callers alike.
- `private_notes` — correctly owner-scoped. The **same** anonymous token that
  opens `employee_records` gains nothing here, which is what stops "readable by
  authenticated" from being a blanket finding.
- `rtdb public_config` — app configuration meant to be public.
- Any collection with no matching rule (`ghost_collection`) — denied, and it
  does not exist either.

## The things that surprised us

**1. The Realtime Database namespace is not the project id, and asking for the
wrong one invents a wide-open database.**

The configured rules load onto `unruly-bench-14-default-rtdb`. A request with
`?ns=unruly-bench-14` does not 404 — the emulator **creates** that namespace on
demand with default rules of `{".read": true, ".write": true}`. So for the
first hour this target appeared to ignore its rules file entirely: every path
answered 200, including ones the rules deny. It was a namespace that had never
existed, brought into being by the request that asked for it.

Verified directly:

```
$ curl -s -H 'Authorization: Bearer owner' \
    'http://127.0.0.1:54532/.settings/rules.json?ns=totally-made-up-ns'
{    "rules": {        ".read": true,        ".write": true    }}
```

For a benchmark this is a trap worth knowing about: a Firebase result from a
misconfigured namespace is an artefact of the tool's guess, not a property of
the target. The answer key asserts that an invented namespace answers 200 and
is empty, so the distinction stays visible.

**2. Firestore's emulator names the failing rule line in its 403 body.**

```
{"error":{"code":403,"message":"\nfalse for 'list' @ L30","status":"PERMISSION_DENIED"}}
```

and a collection with no rule at all gets a different message,
`"No matching allow statements"`. That difference is an existence oracle. It is
also an **emulator artefact** — a live Google project returns a generic
`PERMISSION_DENIED`. Recorded under `expect.unverified` for exactly that
reason: a scanner tuned to the line numbers would score well here and find
nothing in production. This is the sharpest fixture-versus-reality divergence
in the whole corpus, and it is stated rather than hidden.

**3. `"//": "a note"` breaks `database.rules.json`.**

Any key that is not `.read`, `.write`, `.validate` or `.indexOn` is treated as
a child path and its value must be an object, so a string-valued `"//"` key
fails with `Expected '{'` and the emulator refuses to start. Leading `//`
line comments before the opening brace fail the same way. The file therefore
carries no comments at all and the explanation lives here.

**4. The container must run as root, and the error message for not doing so is
"An unexpected error has occurred."**

The image's default user is `node` (uid 1000); the working directory is created
by Docker as `root:root` because every file in it is a read-only bind mount;
`firebase-tools` then cannot write `firestore-debug.log` and gives up with one
line naming neither a path nor a permission. Forty-five seconds of a
healthy-looking container to find that out.

**5. Owner-scoped rules fail a LIST query for a reason worth reading.**

`private_notes` denies the signed-in token with
`"Property owner_uid is undefined on object. for 'list' @ L43"` — not "false".
A collection-level list cannot evaluate `resource.data.owner_uid` per document,
so the rule errors rather than filtering. That is the correct outcome, but it
means owner-scoped Firestore collections are not "readable-but-filtered" the
way an owner-scoped Postgres table with RLS is; they are simply refused.

## Layout and versions

- Firestore: `http://127.0.0.1:54531`
- Realtime Database: `http://127.0.0.1:54532` (namespace
  `unruly-bench-14-default-rtdb`)
- Auth / Identity Toolkit: `http://127.0.0.1:54533`
- Emulator hub: `http://127.0.0.1:54535`
- Image `andreysenov/firebase-tools:latest`, measured as firebase-tools
  **15.27.0** with OpenJDK 25.0.4 on 2026-08-19. Pinned by tag rather than
  digest, so a future run that behaves differently should check this first.

## Running it

```sh
cd benchmark/corpus/14-firebase && docker compose up -d
./setup.sh                       # seeds via the admin bypass; idempotent
../verify.sh --no-up 14-firebase
```

`verify.sh` runs `setup.sh` automatically when it brings the stack up. Seeding
uses `Authorization: Bearer owner`, the emulator's documented admin bypass,
because the rules deny most of what has to be written.
