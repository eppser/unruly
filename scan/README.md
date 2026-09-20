# Batch scanning owned targets

Pipeline for scanning a list of sites you own with unruly, collecting
findings and performance data for analysis. Only scan targets you own or hold
written permission to test — enumeration and write probing against systems you
do not control is unauthorised access in most jurisdictions.

## 1. Add targets

Edit `scan/targets-owned.csv` — one row per site, same column layout as
`supabase-prospects/mixed_10000.csv`. Only the `url` column is read; the rest
is metadata for the dataset. `#` lines are comments.

## 2. Run

```
python3 scripts/scan-batch.py --targets scan/targets-owned.csv
```

Useful options:

- `--rate-limit N` — cap requests/second (`-rl`); set it when the
  infrastructure is shared, and only to a number the target actually receives
- `--write` — enables INSERT probing (`-write -yes-i-own-this`); owned
  targets only, it writes to the database
- `--measure` — establish exposure without retrieving rows (use whenever the
  report will leave your machine)
- `--timeout SECONDS` — per-target timeout (default 900)
- `--spotcheck N` — after the run, re-scan N random targets and byte-diff the
  JSONL (determinism validation; two scans of an unchanged target must be
  byte-identical)
- `-- -k KEY ...` — extra flags passed through to unruly

Scans run sequentially on purpose: the scanner already runs at the measured
PostgREST saturation point, so overlapping runs would push both past the knee
where throughput collapses.

## 3. Monitor progress

The runner prints one line per target and maintains
`<run>/progress.json` (done/total, failures, ETA) atomically, so it can be
polled from another shell:

```
watch cat scan/runs/<timestamp>/progress.json
```

## 4. What a run produces

`scan/runs/<timestamp>/` (gitignored — findings quote real rows, so a run
directory is a copy of the target's data):

| file | contents |
|---|---|
| `run.json` | binary, targets file, options, start time |
| `progress.json` | live progress, rewritten atomically per target |
| `manifest.jsonl` | one line per target: exit code, duration, retries, error, finding counts |
| `findings/<slug>.jsonl` | the scanner's report for that target |
| `logs/<slug>.log` | stdout/stderr of that scan |
| `spotcheck.json` | determinism re-scan results, if `--spotcheck` was used |
| `summary.json` | run-level aggregate, written at the end |

## 5. Error handling

Exit codes 0/2/3 from unruly are scan *outcomes* (clean / findings /
partially unmeasured) and are recorded, not treated as runner failures. An
unreachable target yields exit 3 from the tool itself and the batch moves on.
Anything else — crash, signal, timeout — is retried once, then recorded in the
manifest with `error` set, and the batch continues. Exit 1 (usage error)
aborts the whole batch: it means the invocation is wrong, and continuing would
record the same mistake once per target.

## 6. Analyse

```
python3 scripts/scan-summary.py scan/runs/<timestamp>
```

Writes `summary.csv` (one row per target — the per-target dataset) and
`analysis.json` (severity distribution, finding-id frequency, duration stats,
failure breakdown, determinism result), and prints a digest.

## 7. Validate

- **Ground truth (recall/precision):** `make eval-fixtures` grades the scanner
  against `evals/targets/*.yaml` — a vulnerable fixture, a hardened one, and
  the RLS state-space matrix. Run this before trusting any batch number.
- **Determinism:** `--spotcheck N` on the batch; differing re-scans mean the
  target changed or the tool is unstable — investigate before using the data.
- **Manual spot-checks:** pick a sample of targets, re-run them by hand with
  `-fix` and compare against the batch output; verify at least one
  `critical`/`high` finding per finding-id by replaying its `evidence.request`.
- **Negative controls:** `make eval-notsupabase` must stay quiet against hosts
  that are not Supabase.

Lessons from each run go in `docs/lessons-learned.md`.
