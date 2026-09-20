# 15 — grant-vs-rls

**The one property this project measures:** grant-awareness. RLS state alone
does not predict reachability, and it fails in **both** directions.

Project 03 holds the GRANTs constant and varies the policy. This one puts the
privilege back in play, because a scanner can pass 03 and still get this wrong.

| table | RLS | GRANT | anonymous read | why it is here |
|---|---|---|---|---|
| `rls_off_granted` | off | yes | **206, 3 rows** | genuinely open |
| `rls_off_ungranted` | off | **none** | **401 / 42501** | the false positive |
| `rls_on_nopolicy` | on | yes | 200, empty | deny-all, unreadable from one look |
| `rls_on_permissive` | on | yes | **206, 2 rows** | RLS on is not protection |

The first two rows have identical `relrowsecurity`. One hands over every row;
the other is unreachable by anybody, because PostgreSQL answers 42501 before
RLS is ever consulted. A tool that reads `relrowsecurity` and stops gets both
ends wrong at once: it reports `rls_off_ungranted`, which nobody can read, and
clears `rls_on_permissive`, which anybody can.

## Where this came from

Observed on a live Neon Data API. Neon's console warns that four
tables "have RLS disabled — all authenticated users can view all rows in these
table(s)". One of the four holds no GRANT and answers 403/42501 to every
caller. The console reads RLS state and stops.

Reproduced here as ordinary PostgreSQL, with nothing Neon-specific in it,
because the mistake is not Neon's to own — it is available to any tool on any
PostgREST target, and a corpus project that only reproduced one vendor's bug
would measure that vendor rather than the scanner.

## No write claims

This project measures read reachability. `verify.sh` refuses to grade a write
outcome that no probe measured, which is correct — an unprobed `false` is a
guess wearing the same syntax as a measurement. Writes are project 01's
variable.
