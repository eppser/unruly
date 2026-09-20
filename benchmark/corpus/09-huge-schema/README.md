# 09 — 120 relations, three name families, OpenAPI off

## What this target is for

**The one property it measures that no other project does: discovery recall as
a PERCENTAGE. 120 relations with an exactly known denominator, 80 of them named
so that no wordlist can hold them, and the cheap schema-listing path closed.**

Every other project in the corpus has five or six relations, so a scan is
scored by reading a list of table names. Here a scan is scored as a fraction.
"Found 41 of 120, 12 of 80 unguessable, 6 of 6 guessable-and-open" is a
sentence you can only write about a target whose totals are pinned
independently — and they are, by `expect.psql`, straight out of `pg_class`.

## The three name families

| family | count | open | how they are named |
|---|---|---|---|
| guessable | 20 | 6 | `users`, `profiles`, `orders`, `sessions`, `payments`, `messages`, `accounts`, `customers`, `products`, `invoices`, `subscriptions`, `notifications`, `comments`, `posts`, `files`, `teams`, `projects`, `tickets`, `addresses`, `events` |
| generic | 20 | 10 | `t1`..`t12`, `data`, `payload`, `tmp_1`, `tmp_2`, `staging_a`, `staging_b`, `misc`, `tbl` |
| unguessable | 80 | 40 | 30 × `tbl_<8 hex>`, 25 × `kv_<6 hex>`, 15 × `zx<10 hex>`, 10 invented compounds (`sporule_ledger`, `quenchless_intake`, `halidom_registry`, `farrago_queue`, `welkin_vault`, `pettifog_archive`, `tarnation_shard`, `obelus_index`, `susurrus_cache`, `gallimaufry_store`) |

The hex names come from `md5("unruly-bench-09:<n>")` in `schema/gen.py`, sliced
to width. They are deterministic — regenerate and diff, and a non-empty diff
means somebody changed the rules — and no list can contain them because this
file invented them. Recall on that family is recall of real enumeration.

**Exposure is anti-correlated with guessability on purpose.** Only 6 of the 20
guessable names are readable; 14 are protected, and reporting one of those as
exposed is a false positive. Half the unguessable family is open, and all 12
relations carrying credential-, card- or PII-shaped columns are in it. A
dictionary enumerator therefore scores badly *and* misses everything that
matters, which is the point.

## Three exposure states, two of which look alike from outside

| state | count | configuration | what anon sees |
|---|---|---|---|
| open | 56 | `GRANT SELECT`, RLS off | `206` and rows |
| RLS-silent | 29 | `GRANT SELECT`, RLS on, **no policy** | `200` and `[]`, forever |
| no rights | 35 | no grant at all | `401` `42501`, body names the table |

Measured, not inferred: `GET /orders` answers `200` with `Content-Range: */0`
and a body of exactly `[]`. A scanner keying on the status code calls those 29
relations open; one keying on an empty body calls them nonexistent. Both are
wrong, and 29 of 120 is 24% of the project.

Note the two different answers to "how many can anon read": **85** relations
carry a SELECT grant, **56** actually return a row. The answer key asserts
both, because the gap between them is exactly the RLS-silent family.

## The scoring denominator

All of these come from `psql` against `127.0.0.1:54482`, never from HTTP:

```
120  relations in public, all base tables, no views
 85  carry a SELECT grant for anon
 56  grant SELECT and have RLS off, so they return rows
 35  hold no grant at all
 29  have RLS enabled
  0  policies exist
  0  relations grant anon any write verb
664  rows in total
```

No write verb is granted anywhere. Any write finding on this target is a false
positive by construction; that keeps the whole project on the discovery axis.

## What a correct scanner must report

- Some fraction of 120, reported **as** a fraction, with the denominator it
  believes in stated. A scan that says "found 41 relations" without saying
  "of an unknown total" has not answered the question this target asks.
- The 12 sensitive relations, all with unguessable names:
  4 × credentials (`tbl_0e1eb483`, `tbl_465c6bd5`, `kv_7da565`,
  `pettifog_archive`), 4 × cards (`tbl_1c6d981c`, `tbl_554a6bbb`, `kv_089941`,
  `zx74a4150338`), 4 × PII (`tbl_beef7050`, `kv_b9d403`, `kv_3dc18d`,
  `zx9ec4126434`).
- `t1`, `data`, `tmp_1` and friends as **low-value** open relations. Two rows of
  `value-1` is not an incident, and a report that ranks 10 of those alongside
  4 tables of password hashes has failed at triage even though it found
  everything.

## What a correct scanner must NOT report

- Any of the 14 protected guessable names as exposed.
- Any of the 29 RLS-silent relations as exposed, despite their `200`.
- Any write anywhere.

## The thing that surprised us

**Turning the OpenAPI document off closes the bulk listing and leaves a
per-guess oracle that leaks strictly more than the document did.**

`PGRST_OPENAPI_MODE: disabled` behaves as advertised on the surface —
`GET /` answers `404`:

```json
{"code":"PGRST126","details":null,"hint":null,"message":"Root endpoint metadata is disabled"}
```

Two things about that are worth writing down. First, the code is a *dedicated*
one, `PGRST126`, not the generic `PGRST205` a missing route gets. Switching the
schema document off does not stop the host looking like PostgREST; it trades a
schema listing for a distinctive fingerprint.

Second, and much worse: PostgREST's `404` for an unknown relation carries a
fuzzy-match **hint** naming the closest relation it does know about. Measured:

```
GET /tbl_0e1eb48  -> hint: Perhaps you meant the table 'public.tbl_0e1eb483'
GET /sporule      -> hint: Perhaps you meant the table 'public.sporule_ledger'
GET /welkin       -> hint: Perhaps you meant the table 'public.welkin_vault'
GET /kv_          -> hint: Perhaps you meant the table 'public.kv_e8c133'
GET /aaaaaaaa     -> hint: Perhaps you meant the table 'public.kv_9aaa45'
GET /xyzzy        -> hint: null
```

So a near miss is a partial hit, and an eight-character hex suffix can be
recovered from a seven-character prefix. That alone would be an interesting
channel. The part that inverts project 01's finding is this:

```
GET /profile      -> hint: Perhaps you meant the table 'public.profiles'
GET /invoice      -> hint: Perhaps you meant the table 'public.invoices'
GET /subscription -> hint: Perhaps you meant the table 'public.subscriptions'
```

`profiles`, `invoices` and `subscriptions` hold **no grant for anon**. Project
01 measured that PostgREST's OpenAPI document follows privileges and omits
exactly such relations. The 404 hint does not follow privileges and names them
anyway. An operator who disables OpenAPI to make enumeration harder has
removed the privilege-filtered listing and kept an unfiltered one.

We did not characterise how far the channel goes — whether all 120 names can be
recovered from it, and at what request cost. That is recorded honestly under
`expect.unverified`; the two hint assertions in the answer key are an existence
proof, not a bound.

## Layout

- REST: `http://127.0.0.1:54481/` (bare PostgREST at the root, no gateway —
  identical to project 01 so the only differences are schema size, naming and
  the OpenAPI switch)
- Postgres: `127.0.0.1:54482`, database `fixture`, user `postgres`

## Running it

```sh
cd benchmark/corpus/09-huge-schema && docker compose up -d --wait
../verify.sh --no-up 09-huge-schema      # all 148 claims held
```

To regenerate the schema after editing the rules:

```sh
python3 benchmark/corpus/09-huge-schema/schema/gen.py
```

It rewrites `schema/01_schema.sql` and prints the family counts. The generated
SQL is committed so the target is reproducible without running Python, and so
that a change to the denominators shows up as a diff rather than as a quietly
different benchmark.
