# Benchmark: unruly against the corpus

commit: `58b7f09` (clean)
go: `go1.26.0`

Every number here is the END-TO-END scanner run as an operator runs
it, graded against an answer key that was verified against the running
stack rather than read off the DDL. Discovery is included: a relation
the scan never recovered is a false negative here, which is the
difference between this and the fixture evals.

| project | dimension | recall | precision | missed | false alarms |
|---|---|---|---|---|---|
| `01-rls-off-crud` | relation-discovery | 100% | 100% | — | — |
| `01-rls-off-crud` | read-exposure | 100% | 100% | — | — |
| `01-rls-off-crud` | write-exposure | 100% | 100% | — | — |
| `01-rls-off-crud` | protected-not-flagged | 100% | 100% | — | — |
| `02-hardened` | relation-discovery | 100% | 100% | — | — |
| `02-hardened` | read-exposure | 100% | 100% | — | — |
| `02-hardened` | write-exposure | 100% | 100% | — | — |
| `02-hardened` | protected-not-flagged | 100% | 100% | — | — |
| `02-hardened` | escalation-gains | 100% | 100% | — | — |
| `03-policy-shapes` | relation-discovery | 100% | 100% | — | — |
| `03-policy-shapes` | read-exposure | 100% | 100% | — | — |
| `03-policy-shapes` | write-exposure | 100% | 100% | — | — |
| `03-policy-shapes` | protected-not-flagged | 100% | 100% | — | — |
| `03-policy-shapes` | escalation-gains | 100% | 100% | — | — |
| `04-auth-escalation` | relation-discovery | 100% | 100% | — | — |
| `04-auth-escalation` | read-exposure | 100% | 100% | — | — |
| `04-auth-escalation` | write-exposure | 100% | 100% | — | — |
| `04-auth-escalation` | protected-not-flagged | 100% | 100% | — | — |
| `04-auth-escalation` | escalation-gains | 100% | 100% | — | — |
| `05-empty-project` | relation-discovery | 100% | 100% | — | — |
| `05-empty-project` | read-exposure | 100% | 100% | — | — |
| `05-empty-project` | write-exposure | 100% | 100% | — | — |
| `05-empty-project` | protected-not-flagged | 100% | 100% | — | — |
| `06-unreachable` | relation-discovery | 100% | 100% | — | — |
| `06-unreachable` | read-exposure | 100% | 100% | — | — |
| `06-unreachable` | write-exposure | 100% | 100% | — | — |
| `06-unreachable` | protected-not-flagged | 100% | 100% | — | — |
| `06-unreachable` | exit-code | 100% | 100% | — | — |
| `07-rewriting-proxy` | relation-discovery | 75% | 100% | `billing_accounts` | — |
| `07-rewriting-proxy` | read-exposure | 100% | 100% | — | — |
| `07-rewriting-proxy` | write-exposure | 100% | 100% | — | — |
| `07-rewriting-proxy` | protected-not-flagged | 100% | 100% | — | — |
| `08-rate-limited` | relation-discovery | n/a | n/a | `audit_events`, `customers`, `employee_records`, `feature_flags` +8 more | — |
| `08-rate-limited` | read-exposure | n/a | n/a | — | — |
| `08-rate-limited` | write-exposure | n/a | n/a | `support_tickets` | — |
| `08-rate-limited` | protected-not-flagged | n/a | n/a | — | — |
| `09-huge-schema` | relation-discovery | 69% | n/a (sample) | `kv_089941`, `kv_7da565`, `kv_b9d403`, `t1` +4 more | — |
| `09-huge-schema` | read-exposure | 60% | n/a (sample) | `kv_089941`, `kv_7da565`, `kv_b9d403`, `t1` +2 more | — |
| `09-huge-schema` | write-exposure | 100% | 100% | — | — |
| `09-huge-schema` | protected-not-flagged | 100% | 100% | — | — |
| `10-nonlatin-names` | relation-discovery | 100% | 100% | — | — |
| `10-nonlatin-names` | read-exposure | 100% | 100% | — | — |
| `10-nonlatin-names` | write-exposure | 100% | 100% | — | — |
| `10-nonlatin-names` | protected-not-flagged | 100% | 100% | — | — |
| `11-multi-schema` | relation-discovery | 100% | 100% | — | — |
| `11-multi-schema` | read-exposure | 100% | 100% | — | — |
| `11-multi-schema` | write-exposure | 100% | 100% | — | — |
| `11-multi-schema` | protected-not-flagged | 100% | 100% | — | — |
| `12-content-vs-jsonb` | relation-discovery | 100% | 100% | — | — |
| `12-content-vs-jsonb` | read-exposure | 100% | 100% | — | — |
| `12-content-vs-jsonb` | write-exposure | 100% | 100% | — | — |
| `12-content-vs-jsonb` | protected-not-flagged | 100% | 100% | — | — |
| `13-rpc-security-definer` | relation-discovery | 100% | 100% | — | — |
| `13-rpc-security-definer` | read-exposure | 100% | 100% | — | — |
| `13-rpc-security-definer` | write-exposure | 100% | 100% | — | — |
| `13-rpc-security-definer` | protected-not-flagged | 100% | 100% | — | — |
| `13-rpc-security-definer` | routine-discovery | 83% | 100% | `mnemosyne_key_rotation_audit` | — |
| `15-grant-vs-rls` | relation-discovery | 100% | 100% | — | — |
| `15-grant-vs-rls` | read-exposure | 100% | 100% | — | — |
| `15-grant-vs-rls` | write-exposure | 100% | 100% | — | — |
| `15-grant-vs-rls` | protected-not-flagged | 100% | 100% | — | — |
| `16-data-classification` | relation-discovery | 100% | 100% | — | — |
| `16-data-classification` | read-exposure | 100% | 100% | — | — |
| `16-data-classification` | write-exposure | 100% | 100% | — | — |
| `16-data-classification` | data-classification | 100% | 100% | — | — |
| `16-data-classification` | protected-not-flagged | 100% | 100% | — | — |

## Totals across the corpus

| dimension | recall | precision | denominator |
|---|---|---|---|
| data-classification | 100.0% | 100.0% | 9 |
| escalation-gains | 100.0% | 100.0% | 8 |
| exit-code | 100.0% | 100.0% | 1 |
| protected-not-flagged | 100.0% | 100.0% | 43 |
| read-exposure | 89.5% | 100.0% | 57 |
| relation-discovery | 91.1% | 100.0% | 101 |
| routine-discovery | 83.3% | 100.0% | 6 |
| write-exposure | 100.0% | 100.0% | 6 |

## Not scored

A project that did not come up is not a project that scored zero.

- 14-firebase (this runner grades supabase findings and the target is firebase; scoring it would report 100% of nothing)
