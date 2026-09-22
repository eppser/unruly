# What Supabase's advisor already covers, and where the gap is

Supabase's Database Advisor is [`splinter`](https://github.com/supabase/splinter):
a set of SQL views over `pg_catalog`, run by the project owner. Neon and the
other Postgres-backed platforms ship something similar in spirit.

**Run it.** It is free, fast, CI-gateable, and it covers more than the people
selling scanners tend to admit. This page says exactly what it covers and
exactly where it stops, so you can check both claims rather than take them.

> **Verified against splinter at commit
> [`e74a9e3`](https://github.com/supabase/splinter/commit/e74a9e36cb12258cb67d1464bc1cb196e9cd8446)**
> (29 lints).
> Everything below was read out of the lint SQL, not out of the documentation.
> If splinter changes, this page goes stale — re-check it against a newer
> commit before quoting it.

## What it catches

| splinter lint | catches |
|---|---|
| `0013_rls_disabled_in_public` | a table in a PostgREST-exposed schema with RLS off |
| `0008_rls_enabled_no_policy` | RLS on, no policy — the deny-everything case |
| `0002_auth_users_exposed` | `auth.users` reachable through the API via a view |
| `0023_sensitive_columns_exposed` | a column *named* `password`, `ssn`, `api_key`… on a table with RLS off |
| `0025_public_bucket_allows_listing` | a public storage bucket with a broad SELECT policy, so anyone can list it |
| `0028/0029_*_security_definer_function_executable` | a `SECURITY DEFINER` routine `anon` or `authenticated` can execute |
| `0026/0027_pg_graphql_*_table_exposed` | a relation whose name and columns are visible through GraphQL introspection |

If your question is *"did anyone forget to switch RLS on"*, splinter answers
it, and a network scan is not the cheaper way to ask.

## Where it stops

### 1. A permissive policy is not an always-true policy

```sql
CREATE POLICY "read notes" ON notes FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL);   -- every signed-in user reads every note
```

RLS is on. A policy exists. The policy is scoped to the *role* rather than to
the owning user, so it grants every signed-in caller every row — and where
signup is open, "every signed-in caller" is anyone with an email address.

This policy is clean under `0024_rls_policy_always_true`, for two independent
reasons, both readable in the lint:

1. **SELECT is excluded from the `USING` check by design.** The `has_permissive_using`
   branch is gated on `command in ('UPDATE', 'DELETE', 'ALL')`, and the lint's
   own description says why: *"SELECT policies with `USING (true)` are
   intentionally excluded as this pattern is often used deliberately for public
   read access."* A SELECT policy has no `WITH CHECK` clause, so the other
   branch cannot reach it either.
2. **It matches literal patterns only.** The comparison is
   `normalized_qual in ('true', '(true)', '1=1', '(1=1)')`, after lowercasing
   and stripping whitespace. `auth.uid() IS NOT NULL` is a function call, so it
   never matches — and that exclusion applies to `UPDATE` and `DELETE` too. A
   permissive *expression* escapes the lint even on the commands it does check.

`0027_pg_graphql_authenticated_table_exposed` is the nearest thing splinter has,
and it answers a different question. It reports that a relation's *name and
columns* are visible through GraphQL introspection; it requires the
`pg_graphql` extension; and it fires whenever `authenticated` can select any
column — which a **correctly scoped** policy also allows. It cannot separate a
good policy from the one above.

unruly signs in as two separate accounts and compares what each receives:

```
[supabase-authenticated-escalation] [postgrest] [high] .../rest/v1/notes [2 rows]
  "notes" returned 2 rows to the authenticated role but none to anon.
  The policy grants access to the ROLE rather than to the owning user.
```

### 2. Classification by column name, not by value

`0023_sensitive_columns_exposed` compares column names against a fixed list of
67 patterns, by exact equality after lowercasing and folding `-` to `_`. It
reads no rows, by design — a catalog lint cannot.

Two consequences:

- It cannot see a card number in a column called `notes`, a JSONB field holding
  `{"card": "4111…"}`, or a sensitive column in a schema that is not in
  English. The name is the whole signal.
- It only fires on tables **with RLS off** (`and not c.relrowsecurity`). A
  table holding `ssn` behind the permissive policy in §1 is exposed and
  unflagged, because as far as the catalog is concerned it is protected.

unruly classifies what actually came back over the wire: Luhn plus an issuer
length for card numbers, IBAN mod-97, a JWT header that base64-decodes to
`{"alg":…}`, bcrypt's `$2b$` prefix and 53-character length. Optionally a local
model adds a second opinion, always marked as an opinion.

### 3. An advisor runs as the project owner

It reads your catalog with your credentials. It can never be pointed at an app
you are assessing, acquiring, or triaging. unruly needs a URL.

### 4. Configuration is not behaviour

An advisor reads `pg_catalog` and reasons about what *should* happen. Neon's
console — which does exactly that — warns that a table with RLS disabled lets
all authenticated users read every row; for a table holding no `GRANT` that is
false, because no role can reach it at all. Asking the API what it *does*
inherits none of that class of error.

## Use both

They answer different questions. splinter is cheaper for everything it covers,
and it covers a lot. The gap is narrow and specific — permissive policies that
are not literally `true`, values that do not match their column names, and
anything you do not own.
