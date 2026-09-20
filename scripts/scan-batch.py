#!/usr/bin/env python3
"""Batch-scan owned targets with unruly.

Reads a CSV of targets (same layout as supabase-prospects/mixed_10000.csv; only
the `url` column is used), scans each target SEQUENTIALLY — the scanner already
runs at PostgREST saturation, so parallelism would only distort the numbers —
and records per-target outcomes for later analysis.

Output layout under --out (default: scan/runs/<timestamp>/):

  progress.json          updated after every target: done/total, ETA, failures
  manifest.jsonl         one line per target: timing, exit code, finding counts
  findings/<slug>.jsonl  the scanner's own JSONL report for that target
  logs/<slug>.log        stdout+stderr of that scan
  summary.json           aggregate, written at the end
  spotcheck.json         present if --spotcheck N re-scans were run

Exit-code contract of unruly: 0 clean+fully measured, 2 findings >= high,
3 partially unmeasured, 1 usage error. 0/2/3 are scan OUTCOMES and are recorded,
not treated as runner failures. Exit 1 means the invocation was wrong, so the
batch aborts — continuing would record one identical mistake per target.
Anything else (crash, timeout, signal) is retried once, then recorded as an
error and the batch moves on, because one unreachable target must not abandon
the rest of the list (same rule the scanner applies internally).

Only scan targets you own or hold written permission to test.
"""

import argparse
import csv
import json
import os
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.environ.get("UNRULY_BIN", os.path.join(REPO, "unruly"))
SEVERITIES = ("critical", "high", "medium", "low", "info")


def load_targets(path):
    """Return ordered, de-duplicated list of URLs from the CSV's url column.

    Every row is required to carry an http(s) URL, and rows that do not are
    counted and reported rather than scanned.

    That is not defensive tidiness. A run scanned a target literally named
    "url": DictReader consumed line 2 as the header correctly, but the file had
    a SECOND header at line 9, where a 10,000-row prospect list had been
    appended complete with its own header. The repeat is an ordinary data row
    whose url column contains the string "url", so the batch dutifully resolved
    it, failed, and wrote a findings file for it.

    Skipping line 1 would not have caught it -- line 1 was already the header,
    and was already handled. Validating every row does catch it, and also
    catches the other junk that reaches a hand-maintained targets file.
    """
    urls, seen = [], set()
    skipped = []
    with open(path, newline="", encoding="utf-8") as fh:
        # Strip comment lines first: csv module has no comment concept. Keep
        # each kept line's ORIGINAL number: reporting a position in the
        # filtered list sends the reader to the wrong line of their file, and
        # "line 2" for a problem on line 9 is worse than no line number.
        kept = [(n, ln) for n, ln in enumerate(fh, start=1)
                if ln.strip() and not ln.lstrip().startswith("#")]
    rows = [ln for _, ln in kept]
    if not rows:
        print(f"{path}: no rows after stripping blanks and comments", file=sys.stderr)
        return []
    reader = csv.DictReader(rows)
    if not reader.fieldnames or "url" not in reader.fieldnames:
        print(f"{path}: no 'url' column in header {reader.fieldnames!r}; "
              f"expected a CSV, not a plain URL list", file=sys.stderr)
        return []
    # kept[0] is the header, so data row i corresponds to kept[i].
    for i, row in enumerate(reader, start=1):
        lineno = kept[i][0] if i < len(kept) else -1
        url = (row.get("url") or "").strip()
        if not url:
            continue
        if not re.match(r"^https?://", url):
            skipped.append((lineno, url))
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    if skipped:
        # Loudly, and with the line number: a silently dropped target is the
        # same class of failure as a silently scanned non-target.
        print(f"{path}: skipped {len(skipped)} row(s) with no http(s) URL "
              f"(a repeated header row is the usual cause):", file=sys.stderr)
        for lineno, bad in skipped[:5]:
            print(f"  line {lineno}: {bad!r}", file=sys.stderr)
        if len(skipped) > 5:
            print(f"  ... and {len(skipped) - 5} more", file=sys.stderr)
    return urls


def slug(url, index):
    host = re.sub(r"^https?://", "", url).split("/")[0]
    host = re.sub(r"[^A-Za-z0-9.-]", "_", host) or "target"
    return f"{index:04d}-{host}"


def count_findings(jsonl_path):
    counts = {s: 0 for s in SEVERITIES}
    total = 0
    if not os.path.exists(jsonl_path):
        return counts, total
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                sev = json.loads(line).get("severity", "")
            except json.JSONDecodeError:
                continue  # a truncated last line after a kill must not crash the runner
            if sev in counts:
                counts[sev] += 1
                total += 1
    return counts, total


def scan_one(url, out_jsonl, log_path, args):
    """Run one scan. Returns (exit_code_or_None, duration_s, error_or_None)."""
    cmd = [BINARY, "-u", url, "-json", "-o", out_jsonl]
    if args.rate_limit:
        cmd += ["-rl", str(args.rate_limit)]
    if args.write:
        cmd += ["-write", "-yes-i-own-this"]
    if args.measure:
        cmd += ["-measure"]
    extra = args.extra
    # argparse.REMAINDER keeps a literal leading "--"; Go's flag package would
    # read it as end-of-flags and silently ignore every flag after it.
    if extra and extra[0] == "--":
        extra = extra[1:]
    cmd += extra
    started = time.monotonic()
    try:
        with open(log_path, "w", encoding="utf-8") as log:
            proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=args.timeout, cwd=REPO)
        return proc.returncode, time.monotonic() - started, None
    except subprocess.TimeoutExpired:
        return None, time.monotonic() - started, f"timeout after {args.timeout}s"
    except OSError as exc:
        return None, time.monotonic() - started, f"failed to launch: {exc}"


def write_progress(out_dir, total, done, started_at, failures, current=None):
    elapsed = time.monotonic() - started_at
    eta = (elapsed / done) * (total - done) if done else None
    payload = {
        "total": total,
        "done": done,
        "remaining": total - done,
        "failures": failures,
        "current": current,
        "elapsed_s": round(elapsed, 1),
        "eta_s": round(eta, 1) if eta is not None else None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    tmp = os.path.join(out_dir, "progress.json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, os.path.join(out_dir, "progress.json"))  # atomic: readers never see half a file


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--targets", required=True, help="CSV with a url column")
    ap.add_argument("--out", help="run directory (default scan/runs/<timestamp>)")
    ap.add_argument("--rate-limit", type=int, metavar="N",
                    help="requests per second, passed to -rl (courtesy control)")
    ap.add_argument("--write", action="store_true",
                    help="enable write probing (-write -yes-i-own-this); owned targets only")
    ap.add_argument("--measure", action="store_true",
                    help="establish exposure without retrieving rows")
    ap.add_argument("--timeout", type=int, default=900, help="per-target timeout, seconds")
    ap.add_argument("--spotcheck", type=int, default=0, metavar="N",
                    help="re-scan N random targets afterwards and byte-diff the JSONL (determinism check)")
    ap.add_argument("extra", nargs=argparse.REMAINDER,
                    help="extra flags passed through to unruly, after --")
    args = ap.parse_args()

    if not os.path.isfile(BINARY):
        sys.exit(f"binary not found: {BINARY} (run `make build` first)")
    urls = load_targets(args.targets)
    if not urls:
        sys.exit(f"no targets in {args.targets} — add URLs you own to the file first")

    out_dir = args.out or os.path.join(
        REPO, "scan", "runs", datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    findings_dir = os.path.join(out_dir, "findings")
    logs_dir = os.path.join(out_dir, "logs")
    os.makedirs(findings_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    run_meta = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "binary": BINARY,
        "targets_file": os.path.abspath(args.targets),
        "n_targets": len(urls),
        "options": {"rate_limit": args.rate_limit, "write": args.write,
                    "measure": args.measure, "timeout": args.timeout,
                    "extra": args.extra},
    }
    with open(os.path.join(out_dir, "run.json"), "w", encoding="utf-8") as fh:
        json.dump(run_meta, fh, indent=2)

    manifest_path = os.path.join(out_dir, "manifest.jsonl")
    manifest = open(manifest_path, "a", encoding="utf-8")
    batch_start = time.monotonic()
    failures = 0

    for i, url in enumerate(urls, 1):
        s = slug(url, i)
        out_jsonl = os.path.join(findings_dir, f"{s}.jsonl")
        log_path = os.path.join(logs_dir, f"{s}.log")
        print(f"[{i}/{len(urls)}] {url}", flush=True)

        code, dur, err = scan_one(url, out_jsonl, log_path, args)
        retried = False
        if code not in (0, 2, 3) and code != 1:
            # Unexpected exit or crash: one retry, then record. Same discipline
            # as scripts/audit.sh — a transient environment failure is not data.
            retried = True
            code, dur, err = scan_one(url, out_jsonl, log_path, args)

        if code == 1:
            manifest.close()
            sys.exit(f"unruly reported a usage error on {url}; aborting the "
                     f"batch so the mistake is recorded once, not {len(urls)} times. "
                     f"See {log_path}")

        counts, total_findings = count_findings(out_jsonl)
        ok = err is None and code in (0, 2, 3)
        if not ok:
            failures += 1
        record = {
            "index": i, "url": url, "slug": s,
            "exit_code": code, "duration_s": round(dur, 1),
            "error": err, "retried": retried,
            "findings_total": total_findings,
            "findings_by_severity": counts,
            "findings_file": os.path.relpath(out_jsonl, out_dir) if os.path.exists(out_jsonl) else None,
            "log_file": os.path.relpath(log_path, out_dir),
        }
        manifest.write(json.dumps(record) + "\n")
        manifest.flush()

        status = f"exit {code}" if ok else f"ERROR ({err or 'exit ' + str(code)})"
        sev = " ".join(f"{k}={v}" for k, v in counts.items() if v)
        print(f"    {status}, {dur:.0f}s, findings: {total_findings} ({sev or 'none'})",
              flush=True)
        write_progress(out_dir, len(urls), i, batch_start, failures,
                       current=url if i < len(urls) else None)

    # ---- optional determinism spot-check ------------------------------------
    spotcheck = None
    if args.spotcheck > 0:
        sample = random.sample(urls, min(args.spotcheck, len(urls)))
        results = []
        for url in sample:
            s = slug(url, urls.index(url) + 1)
            orig = os.path.join(findings_dir, f"{s}.jsonl")
            redo = os.path.join(findings_dir, f"{s}.spotcheck.jsonl")
            code, _, err = scan_one(url, redo, os.path.join(logs_dir, f"{s}.spotcheck.log"), args)
            identical = (err is None and code in (0, 2, 3) and os.path.exists(orig)
                         and os.path.exists(redo)
                         and open(orig, "rb").read() == open(redo, "rb").read())
            results.append({"url": url, "identical": identical, "exit_code": code, "error": err})
            print(f"    spotcheck {url}: {'identical' if identical else 'DIFFERS'}", flush=True)
        spotcheck = {"n": len(results), "all_identical": all(r["identical"] for r in results),
                     "results": results}
        with open(os.path.join(out_dir, "spotcheck.json"), "w", encoding="utf-8") as fh:
            json.dump(spotcheck, fh, indent=2)

    # ---- summary -------------------------------------------------------------
    manifest.close()
    totals = {s: 0 for s in SEVERITIES}
    scanned = 0
    with open(manifest_path, encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec["error"] is None and rec["exit_code"] in (0, 2, 3):
                scanned += 1
                for k, v in rec["findings_by_severity"].items():
                    totals[k] += v
    summary = {
        "targets": len(urls), "scanned_ok": scanned, "failed": failures,
        "findings_by_severity": totals,
        "findings_total": sum(totals.values()),
        "wall_clock_s": round(time.monotonic() - batch_start, 1),
        "spotcheck": spotcheck,
    }
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(f"\ndone: {scanned}/{len(urls)} scanned, {failures} failed, "
          f"{sum(totals.values())} findings "
          f"({', '.join(f'{k}={v}' for k, v in totals.items() if v) or 'none'})")
    print(f"run directory: {out_dir}")
    return 0 if failures == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
