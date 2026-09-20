# 10 — identifiers that are not ASCII English

## What this target is for

**The one property it measures that no other project does: relation and column
names in German, Japanese, Spanish and Cyrillic — including a name that mixes
three scripts, a name outside the Basic Multilingual Plane, a pair that differs
only by letter case, and a pair that differs only by Unicode normalisation
form.**

Fifteen of the sixteen relation names contain bytes outside ASCII. The
sixteenth, `benutzer_zugangsdaten`, is ASCII but German — which is the point of
including it: it is the credential store, and there is no column in it called
`password`.

## Why every identifier is double-quoted

Postgres folds an **unquoted** identifier to lower case. It does accept letters
with diacritics and non-Latin letters unquoted — `CREATE TABLE 顧客` is legal,
and folding is a no-op for a script with no case — but `CREATE TABLE Ünïcödé`
and `CREATE TABLE ünïcödé` would then be the same table. This project needs
both, so `schema/01_schema.sql` quotes every identifier it creates.

That is also the honest shape for such a schema. An ORM or migration tool that
quotes gives you case-sensitive relation names, and once the name is in a URL
the difference is invisible: `%C3%9Cn%C3%AFc%C3%B6d%C3%A9` and
`%C3%BCn%C3%AFc%C3%B6d%C3%A9` are two paths that a human reads as one word.

The normalisation pair and the non-BMP name are written with the SQL-standard
`U&"..."` escape rather than as literal bytes, so no editor, `git` filter or
normalising clipboard can silently collapse them. If they ever do collapse the
schema fails to load with a duplicate-table error, rather than quietly becoming
a fifteen-table fixture that still passes fourteen of its checks.

## The sixteen relations

| relation | script | rows | anon sees | content |
|---|---|---|---|---|
| `benutzer_zugangsdaten` | German (ASCII) | 5 | `206` rows | `passwort_hash`, `api_schlüssel` |
| `zahlungsempfänger` | German | 4 | `206` rows | `iban_nummer`, `kontoinhaber` |
| `bestellübersicht` | German | 7 | `200` `[]` (RLS, no policy) | order totals |
| `顧客` | Japanese | 9 | `206` rows, **full CRUD** | `氏名`, `メールアドレス`, `電話番号` |
| `注文履歴` | Japanese | 6 | `401` `42501` | order history |
| `パスワード保管` | Japanese | 4 | `206` rows | `パスワードハッシュ`, `復旧コード` |
| `contraseñas` | Spanish | 3 | `206` rows | `contraseña_hash`, `clave_api` |
| `información_personal` | Spanish | 4 | `401` `42501` | `número_de_tarjeta`, `número_de_documento` |
| `пользователи` | Cyrillic | 8 | `206` rows | `хеш_пароля`, `электронная_почта` |
| `платежи` | Cyrillic | 5 | `200` `[]` (RLS, no policy) | `номер_карты` |
| `benutzer_顧客_данные` | three scripts | 4 | `206` rows | `passwort_hash`, `почта` |
| `𝕂𝕒𝕣𝕥𝕖` | non-BMP | 3 | `206` rows | `número_de_tarjeta`, `kartenprüfnummer` |
| `Ünïcödé` | German, upper | 2 | `206` rows | `clave_api` |
| `ünïcödé` | German, lower | 3 | `200` `[]` (RLS, no policy) | `clave_api` |
| `café_registro` (NFC) | Spanish | 2 | `206` rows | a note |
| `café_registro` (NFD) | Spanish | 3 | `401` `42501` | a note |

Totals, asserted from `pg_class`: 13 relations carry a SELECT grant, 10 of
those have RLS off and actually return rows, 3 hold no grant, 3 have RLS
enabled with no policy, 0 policies exist, and exactly 1 relation (`顧客`)
grants a write verb.

## Reproducing a read by hand

The harness percent-encodes for you. This is the literal command, and its
literal measured output:

```console
$ curl -s -i 'http://127.0.0.1:54491/%E9%A1%A7%E5%AE%A2?select=*&%E7%95%AA%E5%8F%B7=eq.1'
HTTP/1.1 200 OK
Server: postgrest/14.3
Content-Range: 0-0/*
Content-Location: /顧客?select=%2A&%C3%A7%C2%95%C2%AA%C3%A5%C2%8F%C2%B7=eq.1
Content-Type: application/json; charset=utf-8

[{"番号":1,"氏名":"鈴木 花子","メールアドレス":"kokyaku1@example.invalid","電話番号":"+81-3-5555-0001"}]
```

`%E9%A1%A7%E5%AE%A2` is `顧客` and `%E7%95%AA%E5%8F%B7` is the primary key
column `番号`. Non-ASCII column names are addressable exactly like non-ASCII
relation names, in filters and in `select=`.

The `eq.1` filter is not decoration. An earlier version of this check asked for
`limit=1` with no ordering and passed until a write probe rewrote a row and
moved it in the heap. PostgREST returns rows in whatever order the scan
produces; "the first row" is not a fact about a target.

## What a correct scanner must report

- All sixteen relations, or a defensible subset with the misses stated. A
  wordlist in ASCII finds at most one of these names.
- Credential material in `benutzer_zugangsdaten`, `パスワード保管`,
  `contraseñas`, `пользователи`, `benutzer_顧客_данные` and both `Ünïcödé`
  rows; card data in `𝕂𝕒𝕣𝕥𝕖`. **A classifier keyed on English column names
  reports none of it**, and that is the measurement.
- `顧客` as anonymously INSERT-, UPDATE- **and** DELETE-reachable. Measured:
  `POST` → `201` and the row count went 9→10; `PATCH` → `200` and the column
  read back as the new value; `DELETE` → `204` and the marker row was gone.

## What a correct scanner must NOT report

- `注文履歴`, `información_personal` and the NFD `café_registro` as readable.
  They hold no grant; `información_personal` holds the card numbers, so this is
  the precision half of the project.
- `bestellübersicht`, `платежи` and `ünïcödé` as exposed. They answer `200`
  with `[]` because RLS is on and no policy exists.
- One relation where there are two, in either pair.

## The thing that surprised us

Three things, in ascending order of how much they would cost a real scan.

**1. `lower()` on a catalogue name does not fold the umlaut.** The obvious way
to ask Postgres "are there two relations here differing only by case" is

```sql
SELECT count(*) FROM pg_class c ... WHERE lower(c.relname::text) = 'ünïcödé'
```

and it returns **1**, not 2. `pg_class.relname` is of type `name`, whose
collation is `C`; the cast to `text` carries that collation, so `lower()` takes
the C-locale path and touches ASCII only. Add `COLLATE "default"` and the same
query returns 2. Both results are asserted in the answer key. Anything that
case-folds identifiers read out of the catalogue inherits this, silently, and
gets a smaller relation list than the database has.

**2. Two relations can be indistinguishable in an error message.** The NFD
`café_registro` holds no grant, so it answers:

```json
{"code":"42501","message":"permission denied for table café_registro"}
```

That rendered name is byte-for-byte different from the NFC relation's name and
visually identical to it. So the discovery signal for the protected table is a
string that collides with the name of a *different, readable* table. Any
relation list deduplicated by displayed name merges the two, and the merged
entry is right about one of them and wrong about the other. Postgres does not
normalise identifiers; nothing in the stack does; the collision only happens in
the reader's eye, which is exactly where a report is consumed.

**3. PostgREST 14.3 double-encodes non-ASCII column names in
`Content-Location`.** Look again at the header in the transcript above:

```
Content-Location: /顧客?select=%2A&%C3%A7%C2%95%C2%AA%C3%A5%C2%8F%C2%B7=eq.1
```

The relation name comes back raw and correct. The column name comes back as
`%C3%A7%C2%95%C2%AA%C3%A5%C2%8F%C2%B7`, which is the six UTF-8 bytes of `番号`
read as Latin-1 and re-encoded. Following the URL the server itself just
emitted:

```console
$ curl -s 'http://127.0.0.1:54491/%E9%A1%A7%E5%AE%A2?select=%2A&%C3%A7%C2%95%C2%AA%C3%A5%C2%8F%C2%B7=eq.1'
{"code":"42703","details":null,"hint":null,"message":"column 顧客.ç does not exist"}
```

`400`, and the column has been renamed to `ç` in transit. Canonicalising a
request against `Content-Location` is an ordinary crawler behaviour, and on
this target it converts a working probe into an error that reads as "that
column is not there". The answer key asserts the `400` and the `42703` so the
behaviour is pinned rather than remembered.

## Layout

- REST: `http://127.0.0.1:54491/` (bare PostgREST at the root, OpenAPI left ON
  — project 09 is the one that turns it off)
- Postgres: `127.0.0.1:54492`, database `fixture`, user `postgres`

`PGCLIENTENCODING: UTF8` is set on the `db` service. The database is UTF-8
regardless, but `psql` takes its *client* encoding from the locale and
`docker compose exec` brings none, so without it every non-ASCII name comes
back from the checker's `psql` mangled and the answer key looks wrong for a
reason that has nothing to do with the target.

## Running it

```sh
cd benchmark/corpus/10-nonlatin-names && docker compose up -d --wait
../verify.sh --no-up 10-nonlatin-names    # all 125 claims held
```

Verification is destructive-and-restoring on `顧客` only: a marker row is
inserted with `psql`, the real write is performed over the percent-encoded
path, the result is read back out of the database, and the marker is deleted.
The row count returns to 9.

## Known gap

No identifier here exceeds the 63-**byte** limit. That limit bites at 21
Japanese characters and at 63 ASCII ones, so a truncation fixture would be a
genuinely different target; it is named in `expect.unverified` rather than
quietly omitted.
