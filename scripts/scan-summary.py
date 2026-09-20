#!/usr/bin/env python3
"""Summarise a scan-batch run for analysis.

Reads a run directory produced by scripts/scan-batch.py and prints/writes:

  summary.csv        one row per target: outcome, timing, finding counts —
                     the per-target dataset for the paper
  analysis.json      run-level aggregates: severity distribution, top finding
                     ids, duration stats, failure breakdown, determinism result

Usage: python3 scripts/scan-summary.py scan/runs/<timestamp>
"""

import json
import os
import statistics
import sys
from collections import Counter

SEVERITIES = ("critical", "high", "medium", "low", "info")


def main():
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        sys.exit("usage: scan-summary.py <run-directory>")
    run_dir = sys.argv[1]
    manifest_path = os.path.join(run_dir, "manifest.jsonl")
    if not os.path.isfile(manifest_path):
        sys.exit(f"no manifest.jsonl in {run_dir} — is that a scan-batch run directory?")

    records = [json.loads(ln) for ln in open(manifest_path, encoding="utf-8") if ln.strip()]

    # Per-target CSV -----------------------------------------------------------
    csv_path = os.path.join(run_dir, "summary.csv")
    with open(csv_path, "w", encoding="utf-8") as fh:
        fh.write("url,exit_code,duration_s,error,retried,findings_total,"
                 + ",".join(SEVERITIES) + "\n")
        for r in records:
            fh.write(",".join([
                r["url"], str(r["exit_code"]), str(r["duration_s"]),
                json.dumps(r["error"] or ""), str(r["retried"]).lower(),
                str(r["findings_total"]),
            ] + [str(r["findings_by_severity"].get(s, 0)) for s in SEVERITIES]) + "\n")

    # Finding-id frequency across all per-target JSONL, plus per-target flags
    # for the scan's own blind-spot reports: a target whose scan could not see
    # is not data about the target and must be excluded from recall statistics.
    BLIND_IDS = ("unruly-capability-degraded", "unruly-probe-budget-exhausted")
    id_counts = Counter()
    id_severity = {}
    blind_targets = []
    for r in records:
        f = r.get("findings_file")
        if not f:
            continue
        path = os.path.join(run_dir, f)
        if not os.path.isfile(path):
            continue
        target_ids = set()
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                finding = json.loads(ln)
            except json.JSONDecodeError:
                continue
            fid = finding.get("id")
            if fid:
                id_counts[fid] += 1
                id_severity.setdefault(fid, finding.get("severity", ""))
                target_ids.add(fid)
        if target_ids & set(BLIND_IDS):
            blind_targets.append({"url": r["url"],
                                  "flags": sorted(target_ids & set(BLIND_IDS))})

    ok = [r for r in records if r["error"] is None and r["exit_code"] in (0, 2, 3)]
    failed = [r for r in records if r not in ok]
    durations = [r["duration_s"] for r in ok]
    sev_totals = {s: sum(r["findings_by_severity"].get(s, 0) for r in ok) for s in SEVERITIES}

    spotcheck_path = os.path.join(run_dir, "spotcheck.json")
    spotcheck = None
    if os.path.isfile(spotcheck_path):
        sp = json.load(open(spotcheck_path, encoding="utf-8"))
        spotcheck = {"n": sp["n"], "all_identical": sp["all_identical"],
                     "differing": [r["url"] for r in sp["results"] if not r["identical"]]}

    analysis = {
        "run_directory": run_dir,
        "targets": len(records),
        "scanned_ok": len(ok),
        "failed": len(failed),
        "failures": [{"url": r["url"], "exit_code": r["exit_code"], "error": r["error"]}
                     for r in failed],
        "exit_code_distribution": dict(Counter(str(r["exit_code"]) for r in records)),
        "partially_blind_targets": blind_targets,
        "findings_by_severity": sev_totals,
        "findings_total": sum(sev_totals.values()),
        "finding_id_frequency": [
            {"id": fid, "severity": id_severity[fid], "targets": n}
            for fid, n in id_counts.most_common()
        ],
        "duration_s": {
            "min": min(durations) if durations else None,
            "median": statistics.median(durations) if durations else None,
            "max": max(durations) if durations else None,
            "total": round(sum(durations), 1),
        },
        "spotcheck": spotcheck,
    }
    with open(os.path.join(run_dir, "analysis.json"), "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, indent=2)

    # Console digest -------------------------------------------------------------
    print(f"run: {run_dir}")
    print(f"targets: {len(records)}  scanned: {len(ok)}  failed: {len(failed)}")
    print(f"exit codes: {analysis['exit_code_distribution']}")
    print(f"findings: {analysis['findings_total']} "
          f"({', '.join(f'{k}={v}' for k, v in sev_totals.items() if v) or 'none'})")
    if durations:
        print(f"duration s: min={min(durations):.0f} median={statistics.median(durations):.0f} "
              f"max={max(durations):.0f} total={sum(durations):.0f}")
    if spotcheck:
        print(f"determinism spotcheck: {spotcheck['n']} re-scans, "
              f"{'all byte-identical' if spotcheck['all_identical'] else 'DIFFERS: ' + str(spotcheck['differing'])}")
    if blind_targets:
        print(f"PARTIALLY BLIND: {len(blind_targets)} target(s) reported capability-degraded or "
              f"probe-budget-exhausted — exclude them from recall statistics:")
        for t in blind_targets:
            print(f"  {t['url']}: {', '.join(t['flags'])}")
    if id_counts:
        print("top finding ids:")
        for fid, n in id_counts.most_common(10):
            print(f"  {n:4d}  [{id_severity[fid]:8s}] {fid}")
    if failed:
        print("failures:")
        for r in failed:
            print(f"  {r['url']}: exit={r['exit_code']} error={r['error']}")
    print(f"wrote {csv_path} and {os.path.join(run_dir, 'analysis.json')}")


if __name__ == "__main__":
    main()
