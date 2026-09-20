# unruly audit

commit: `4692816` (clean)
go: `go version go1.26.0 darwin/arm64`
docker: `29.5.2`
pocketbase: `0.39.11`
fixture images: `jmalloc/echo-server:latest@sha256:86f2c45aa7e7ebe1be30b21f8cfff25a7ed6e3b059751822d4b35bf244a688d5 nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752 postgres:16-alpine public.ecr.aws/supabase/gotrue:v2.151.0 public.ecr.aws/supabase/postgrest:v14.3 supabase/edge-runtime:v1.67.4 `

**27 passed, 0 failed, 0 not run.** all checks ran and passed.



| check | result | what it establishes |
|---|---|---|
| `build` | **pass** | the tree compiles |
| `vet` | **pass** | no vet diagnostics |
| `lint` | **pass** | gofmt-clean; checks without rewriting |
| `unit` | **pass** | every package's tests pass |
| `race` | **pass** | no data races under the detector |
| `mutation` | **pass** | each decision the scanner makes is checked by a test; a mutation that survives is a claim nothing verifies |
| `coverage` | **pass** | every finding id has an emit site the OFFLINE suite executes |
| `eval-neon` | **pass** | the Neon backend agrees with its answer key: the escalation is reported, the three protected tables are not, and a key that parses to nothing fails loudly |
| `release` | **pass** | the cross-compiled binaries build and the Linux ones are statically linked |
| `eval-pocketbase` | **pass** | recall and precision against a deliberately vulnerable PocketBase and a hardened one, including the two answers that look like findings and are not, and a cross-check that an independent implementation can actually retrieve what the scanner reports |
| `eval-fixtures` | **pass** | recall and precision against a vulnerable fixture and a hardened one |
| `eval-exitcode` | **pass** | the exit-code contract CI depends on: 0 clean, 2 findings, 3 could-not-measure |
| `eval-notsupabase` | **pass** | near-silence against hosts that are not Supabase |
| `eval-edge` | **pass** | Edge Function classification against the real edge-runtime |
| `eval-redaction` | **pass** | -redact removes sampled data and keeps the finding usable |
| `eval-templates` | **pass** | the worked examples inside every -fix actually execute |
| `eval-determinism` | **pass** | repeated identical scans produce byte-identical reports |
| `eval-coverage` | **pass** | every finding's emit site is executed with the fixtures up |
| `eval-exploit-local` | **pass** | an independent implementation exploits the local fixture, and the scan agrees with what it could and could not do |
| `eval-remediation` | **pass** | applying the tool's own -fix output closes the findings it reported |
| `exploitcheck` | **pass** | every vulnerability in the answer key is actually exploitable, with retrieved data as proof |
| `eval-exploitability` | **pass** | cross-check: everything the scanner reports at high or above is exploitable, and everything exploitable is reported |
| `eval-graphql` | **pass** | pg_graphql is not more permissive than PostgREST, which is why the bypass finding has never fired |
| `eval-noresidue` | **pass** | -no-residue writes NOTHING to a real project: rows and objects counted with the service key before and after, while write exposure is still reported |
| `eval-exploit-firebase` | **pass** | an independent implementation reads the Firebase lab, the scan agrees, and the rules that are already correct are not reported |
| `eval-neon-live` | **pass** | an independent implementation of the Neon Auth sequence reads rows the scan reports, and both agree on the tables that must stay silent -- including the one the vendor console falsely flags |
| `eval-neon-binary` | **pass** | the BINARY, run as an operator would run it, reports the escalation and exits 2 -- the check that four reachability defects got past, because every other Neon eval grades a stage rather than the program |

## Reading this report

A row marked _not run_ is not a pass. The distinction is the whole point of
this project: absence of a finding is only evidence when the scan could see.
The same rule is applied here to the scan's own test suite.

To reproduce, see `docs/auditing.md`, which lists what each check proves and
what would falsify it.
