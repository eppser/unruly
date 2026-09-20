# 12 — nine readable relations, two findings

## What this target is for

**The one property it measures that no other project does: precision on data
KIND. Exposure carries zero information here — all nine relations are
anonymously readable, RLS is off everywhere, nothing accepts a write — so the
entire score is which relations a scanner reports.**

Seven of the nine are a public marketing site's own content: the same words
already served as HTML to anyone who loads the page. A publicly readable CMS
table is not a misconfiguration, and a finding whose correct remediation is
"do nothing" is noise. Two of the nine hold secrets inside a generic `jsonb`
column that no column-name heuristic can see.

A scanner that flags every readable table scores **2 true positives and 7 false
positives** on this target.

## What a correct scanner must report

| relation | rows | why |
|---|---|---|
| `events` | 200 | 6 payloads carry `card_number`, `password_hash` or `ssn` |
| `settings` | 14 | one `value` holds `sk_live_…` and `AKIAIOSFODNN7EXAMPLE` |

`events` is `id`, `kind`, `created_at`, `payload jsonb`. `settings` is `key
text`, `value jsonb`. Nothing in either name and nothing in any column name
says anything at all. The only way to find these is to read the values.

Measured, precisely:

- 6 of 200 event payloads are sensitive: ids **47, 63, 88, 119, 150, 191**.
  Two carry `card_number`, two `password_hash`, two `ssn`.
- **46 rows can be read in `id` order without seeing anything.** The 47th is a
  card number. `GET /events?order=id.asc&limit=46` and `limit=47` are both in
  the answer key, and they are the measurement.
- In `settings`, the secret row is `integrations.credentials`, the **9th of 14**
  in key order. `?order=key.asc&limit=8` shows nothing; `limit=9` shows a
  Stripe-shaped live key and an AWS access key id.

A probe that samples one row — `?limit=1`, the shape this corpus's own checker
uses and the shape almost every scanner uses — reads a page-view event and a
sample-rate setting, and reports the target clean.

## What a correct scanner must NOT report

The seven CMS tables, and two of them are baited:

- **`team_members` has a column literally called `email`**, holding
  `press@example.invalid` and `security@example.invalid`. Those are the
  addresses on the contact page. They are meant to be read.
- **`blog_posts` has `author_email`**, holding the byline addresses printed
  under every post.

That is seven readable email addresses across two tables, all of them public by
design. **A column name is not a data classification.** Neither column appears
in any `sensitive_columns` list in the answer key, deliberately, and the key
instead asserts that both are genuinely readable — so a run that misses the
trap did not miss it by accident of configuration.

`site_sections`, `faq_entries`, `pricing_tiers`, `press_releases` and
`changelog` are the same case without the bait.

## The thing that surprised us

**PostgREST 14.3 turns a 404 into a relation-name oracle.** A missing relation
answers `PGRST205`, which we expected. What we did not expect is the `hint`:

```
GET /event    -> hint: "Perhaps you meant the table 'public.events'"
GET /setting  -> hint: "Perhaps you meant the table 'public.settings'"
GET /team     -> hint: "Perhaps you meant the table 'public.team_members'"
GET /blog     -> hint: "Perhaps you meant the table 'public.blog_posts'"
GET /zzzzzz   -> hint: null
```

The server fuzzy-matches the requested name against its schema cache and names
a real relation back. Guessing the singular hands you the plural; guessing
`team` hands you `team_members`, a name no wordlist would carry. There is a
similarity floor — `zzzzzz` gets `hint: null` — so it is not a full dump, but
relation discovery on this target is closer to a spelling correction than to a
dictionary attack. Both the near-miss and the far-miss are asserted in the
answer key.

The second, smaller surprise: with no `PGRST_DB_MAX_ROWS` configured, a bare
`GET /events` with no query string at all returns **all 200 rows**, secrets
included, in 34KB. The sampling probe is what hides this finding, not the
server. That is asserted too, because the honest statement of severity here is
"one unauthenticated request with no parameters".

## Layout

Bare PostgREST at the **root**, no gateway. No `PGRST_DB_MAX_ROWS`.

- REST: `http://127.0.0.1:54511/`
- Postgres: `127.0.0.1:54512`, database `fixture`, user `postgres`

All fake data uses `@example.invalid`. `4111111111111111` and
`5555555555554444` are the published Visa and Mastercard test PANs,
`AKIAIOSFODNN7EXAMPLE` and `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY` are AWS's
own documentation examples, `000-00-0000` is not a valid SSN, and the bcrypt
hashes hash the string `not-a-real-password`.

## Running it

```sh
cd benchmark/corpus/12-content-vs-jsonb && docker compose up -d --wait
../verify.sh --no-up 12-content-vs-jsonb
```

Verification here is non-destructive: no relation accepts a write, so the key
makes no write claims and inserts no marker rows. The one `POST` it sends is
asserted to fail with `42501`.
