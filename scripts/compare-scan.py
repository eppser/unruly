#!/usr/bin/env python3
"""Run unruly and a competing scanner over the same target list, and compare.

    ./scripts/compare-scan.py targets.txt --i-own-these

targets.txt holds one URL per line; blank lines and # comments are ignored.

The competitor is supabomb, which needs a checkout and `uv`:

    git clone https://github.com/ModernPentest/supabomb.git ~/tools/supabomb
    cd ~/tools/supabomb && uv run supabomb --version

~/tools/supabomb is the default; override with --supabomb or SUPABOMB_REPO.

WHAT THIS SENDS. Both tools probe the targets for real. unruly reads the
application, recovers the project reference and anon key, and probes relations,
routines, storage and realtime. supabomb does the same and then goes further by
default: it REGISTERS A USER ACCOUNT on the target and DUMPS table contents.
That is a write to somebody's project, which is why --i-own-these is required
and why the flag names ownership rather than permission -- a scan you are
allowed to run against a host you do not own still writes to it.

THE COMPARISON RULES, stated because a comparison whose rules are implicit is
a marketing document:

1.  The tools run SEQUENTIALLY, never at once, so neither pays for the other's
    bandwidth. Order alternates per target so a warm DNS cache does not always
    favour the same tool.

2.  unruly's coverage records -- scan summary, skipped stage, surface not
    assessed, budget exhausted -- are NOT counted as findings. They are how it
    reports what it could not measure, and counting them would inflate its
    number against a tool that stays silent about the same gaps. They are
    reported separately, under coverage, because "did not look" is a result.

3.  supabomb needs two invocations to produce findings: `all` discovers and
    enumerates, `test` grades. Both are timed and the times are summed, because
    that is the work required to reach a finding.

4.  A target that is not a hosted *.supabase.co project is recorded as n/a for
    supabomb rather than as zero findings. It resolves every project to
    https://<ref>.supabase.co and structurally cannot address a self-hosted
    PostgREST. Scoring that as a miss would be scoring the wrong thing.

5.  Severity vocabularies differ. They are mapped onto one scale and the
    mapping is printed in the report, so a reader can disagree with it.

Nothing here is written to the target by this script itself; it only starts
the tools and reads their output.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone

# unruly emits these to describe the SCAN rather than the target. They are
# coverage, not findings, and rule 2 above keeps them out of the count.
COVERAGE_IDS = {
    "unruly-scan-summary",
    "unruly-stage-skipped",
    "unruly-surface-not-assessed",
    "unruly-checks-skipped",
    "unruly-probe-budget-exhausted",
    "unruly-probes-unresolved",
    "unruly-capability-degraded",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# The verbs that mean "somebody can put data there". For these the accepted
# write IS the retrieval, so they are proven without sampled rows.
WRITE_VERBS = {"createRows", "changeRows", "deleteRows", "runAnything"}


def load_capability(repo_root):
    """Read unruly's own capability table instead of keeping a second copy.

    internal/finding/plain.go maps each finding id onto who can do what, and
    the binary's -proven filter uses exactly that table to decide which
    findings reach data at all. Re-typing the list here would be a check
    grading its own copy of a rule -- the defect this repository has shipped
    twice -- so the harness parses the source. If the file moves, the caller
    is told rather than silently scoring against an empty list.
    """
    path = os.path.join(repo_root, "internal", "finding", "plain.go")
    try:
        with open(path) as fh:
            src = fh.read()
    except OSError:
        return None
    rows = re.findall(r'"([a-z][a-z0-9-]+)":\s*\{\s*\w+\s*,\s*(\w+)\s*\}', src)
    return {fid: verb for fid, verb in rows} or None

# supabomb grades high/medium/info. Nothing is invented: an unrecognised label
# lands in "unknown" and is shown as such rather than being rounded into a
# bucket that flatters either tool.
SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "moderate": "medium", "low": "low", "info": "info",
    "informational": "info", "none": "info",
}

PROJECT_REF = re.compile(r"\b([a-z]{20})\.supabase\.co\b")
REGION_HEADERS = ["x-sb-region", "sb-region", "x-region", "fly-region",
                  "x-served-by", "x-amz-cf-pop"]


def norm_severity(raw):
    return SEVERITY_MAP.get(str(raw or "").strip().lower(), "unknown")


def read_targets(path):
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line if "://" in line else "https://" + line)
    return out


# Credentials in the operator's shell must not reach either tool.
#
# unruly reads SUPABASE_ANON_KEY from the environment by design, and this
# machine has one exported. The first run of this script against a real target
# therefore handed unruly a working key for that exact project while supabomb
# had to find its own -- a comparison that measures whose shell was configured,
# not whose discovery works. The corpus runner already scrubs these for the
# same reason (cmd/benchmark/main.go), and this is that lesson arriving a
# second time.
SCRUB = ["SUPABASE_ANON_KEY", "SUPABASE_URL", "SUPABASE_SERVICE_KEY",
         "SUPABASE_ACCESS_TOKEN", "SUPABASE_KEY", "SUPABASE_PROJECT_REF"]


def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k not in SCRUB}
    env.update(extra or {})
    return env


def run(cmd, cwd=None, timeout=1800, env=None):
    """Run a command, return (seconds, exit code, tail of output)."""
    if env is None:
        env = clean_env()
    started = time.monotonic()
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        elapsed = time.monotonic() - started
        tail = p.stdout.decode("utf-8", "replace")[-4000:]
        return elapsed, p.returncode, tail
    except subprocess.TimeoutExpired:
        return time.monotonic() - started, None, "TIMEOUT after %ds" % timeout
    except FileNotFoundError as e:
        return 0.0, -1, str(e)


# ---------------------------------------------------------------- unruly ----

def scan_unruly(binary, target, outdir, name, timeout, extra):
    report = os.path.join(outdir, name + ".unruly.jsonl")
    cmd = [binary, "-u", target, "-json", "-o", report, "-silent", "-nc",
           "-stats"] + list(extra)
    elapsed, code, tail = run(cmd, timeout=timeout)

    findings, coverage = [], []
    if os.path.exists(report):
        with open(report) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev = d.get("evidence") or {}
                rec = {
                    "id": d.get("id", ""),
                    "title": d.get("name", ""),
                    "severity": norm_severity(d.get("severity")),
                    "resource": d.get("resource", ""),
                    "matched": d.get("matched", ""),
                    "rows": ev.get("rows"),
                    "columns": ev.get("columns") or [],
                    "classes": ev.get("classes") or [],
                    "replay": ev.get("request", ""),
                    "sampled": bool(ev.get("sample")),
                }
                (coverage if rec["id"] in COVERAGE_IDS else findings).append(rec)

    # -stats prints the request total; it is the honest denominator for "how
    # much did this cost the target", which wall clock alone does not give.
    requests = None
    m = re.search(r"(\d[\d,]*)\s+requests?", tail)
    if m:
        requests = int(m.group(1).replace(",", ""))

    return {
        "tool": "unruly", "seconds": round(elapsed, 2), "exit": code,
        "findings": findings, "coverage": coverage, "requests": requests,
        "report": report, "tail": tail[-1500:],
    }


# -------------------------------------------------------------- supabomb ----

def scan_supabomb(repo, target, outdir, name, timeout):
    """`all` to discover and enumerate, then `test` to grade. Times are summed."""
    all_out = os.path.abspath(os.path.join(outdir, name + ".supabomb.all.json"))
    test_out = os.path.abspath(os.path.join(outdir, name + ".supabomb.test.json"))

    # ONE WORKING DIRECTORY PER TARGET, and this is not tidiness.
    #
    # supabomb caches discovered credentials in `.supabomb.json` in the CURRENT
    # DIRECTORY, and `test` falls back to that cache when it is given no
    # project. Run every target from the same directory and a target whose
    # discovery failed silently inherits the previous target's credentials --
    # so target two gets scanned, graded, and reported as target three. The
    # comparison would look complete and be attributing findings to the wrong
    # host, which is worse than a crash.
    #
    # `uv run --project` keeps the tool's environment while letting the cwd be
    # somewhere disposable.
    cwd = os.path.abspath(os.path.join(outdir, "sbcwd-" + name))
    os.makedirs(cwd, exist_ok=True)
    base = ["uv", "run", "--project", os.path.abspath(repo), "supabomb"]

    t1, c1, tail1 = run(base + ["all", "--url", target, "-o", all_out],
                        cwd=cwd, timeout=timeout)
    t2, c2, tail2 = 0.0, None, ""
    if c1 == 0:
        t2, c2, tail2 = run(base + ["test", "-o", test_out],
                            cwd=cwd, timeout=timeout)

    findings = []
    if os.path.exists(test_out):
        try:
            with open(test_out) as fh:
                doc = json.load(fh)
            for f in doc.get("findings", []):
                findings.append({
                    "id": f.get("title", ""),
                    "title": f.get("title", ""),
                    "severity": norm_severity(f.get("severity")),
                    "resource": f.get("affected_resource", ""),
                    "matched": doc.get("url", ""),
                    "rows": None, "columns": [], "classes": [],
                    "replay": "",
                })
        except (json.JSONDecodeError, OSError):
            pass

    enumerated, credentials, dumped = {}, {}, {}
    if os.path.exists(all_out):
        try:
            with open(all_out) as fh:
                doc = json.load(fh)
            enumerated = doc.get("summary", {}) or {}
            credentials = doc.get("credentials", {}) or {}
            # What IT retrieved, per table. This is how its findings get the
            # same proof test unruly's do.
            for tname, t in ((doc.get("dump") or {}).get("tables") or {}).items():
                if isinstance(t, dict) and t.get("row_count"):
                    dumped[tname] = t["row_count"]
        except (json.JSONDecodeError, OSError):
            pass

    # Applicable means it got as far as holding credentials. Anything short of
    # that is "this tool cannot address this target", which rule 4 keeps
    # separate from "this tool found nothing here".
    applicable = bool(credentials.get("project_ref")) or bool(findings)
    return {
        "tool": "supabomb", "seconds": round(t1 + t2, 2),
        "exit": c1 if c1 != 0 else c2,
        "findings": findings, "coverage": [], "requests": None,
        "enumerated": enumerated, "credentials": credentials, "dumped": dumped,
        "applicable": applicable,
        "report": test_out, "tail": (tail1 + tail2)[-1500:],
    }


# ---------------------------------------------------------------- estate ----

def project_region(findings):
    """Ask the project's own origin where it answers from.

    One HEAD request per distinct project. The header is reported by NAME, and
    a Cloudflare colo is labelled an edge PoP rather than a data region --
    those are different facts and conflating them would put a project in the
    wrong jurisdiction on a compliance slide.
    """
    refs = set()
    for f in findings:
        m = PROJECT_REF.search(f.get("matched", "") or "")
        if m:
            refs.add(m.group(1))
    out = {}
    for ref in sorted(refs):
        url = "https://%s.supabase.co/rest/v1/" % ref
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=15) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except (urllib.error.URLError, OSError, ValueError):
            out[ref] = {"region": "unreachable", "source": "-"}
            continue
        found = None
        for h in REGION_HEADERS:
            if headers.get(h):
                found = (headers[h], h)
                break
        if found:
            out[ref] = {"region": found[0], "source": found[1]}
        elif headers.get("cf-ray"):
            out[ref] = {"region": headers["cf-ray"].split("-")[-1],
                        "source": "cf-ray (edge PoP, NOT the data region)"}
        else:
            out[ref] = {"region": "unknown", "source": "no region header"}
    return out


def estate_summary(results):
    """The global view of the hosts, from unruly's output only.

    supabomb reports no row counts, no column names and no data classes, so a
    combined estate view would silently be unruly's view wearing both names.
    """
    sev = Counter()
    classes = Counter()
    columns = Counter()
    rows_exposed = 0
    relations = set()
    per_target = []

    for r in results:
        u = r["unruly"]
        t_sev = Counter()
        t_rows = 0
        for f in u["findings"]:
            sev[f["severity"]] += 1
            t_sev[f["severity"]] += 1
            for c in f["classes"]:
                classes[c] += 1
            for c in f["columns"]:
                columns[c] += 1
            if isinstance(f["rows"], int):
                rows_exposed += f["rows"]
                t_rows += f["rows"]
            if f["resource"]:
                relations.add((r["target"], f["resource"]))
        worst = next((s for s in SEVERITY_ORDER if t_sev.get(s)), "none")
        per_target.append({
            "target": r["target"], "worst": worst,
            "findings": len(u["findings"]),
            "proven": sum(1 for f in u["findings"] if f.get("proven")),
            "rows": t_rows,
            "coverage_gaps": len(u["coverage"]),
            "seconds": u["seconds"], "requests": u["requests"],
        })

    return {
        "severity": dict(sev), "classes": dict(classes),
        "top_columns": dict(columns.most_common(15)),
        "rows_exposed": rows_exposed, "relations_exposed": len(relations),
        "per_target": per_target,
    }


# ---------------------------------------------------------------- report ----

def proven_unruly(f, cap):
    """unruly's own bar: high or above, reaches data, and something came back."""
    if f["severity"] not in ("critical", "high"):
        return False
    verb = cap.get(f["id"]) if cap else None
    if verb is None:
        return False
    if verb in WRITE_VERBS:
        return True
    return bool(f["rows"]) or f.get("sampled") or bool(f["classes"])


def proven_supabomb(f, dumped):
    """The SAME bar, answered from supabomb's own output.

    It reports no row counts on its findings, but `all` dumps every accessible
    table and records row_count per table -- so the question "did anything come
    back for this resource" is answerable from what the tool itself retrieved.
    Scoring its findings as unproven merely because the finding object lacks a
    row count would be measuring its report format rather than its result.
    """
    if f["severity"] not in ("critical", "high"):
        return False
    return dumped.get(f["resource"], 0) > 0


def bar(n, most, width=28):
    return "█" * max(1, round(width * n / most)) if n else ""


def summary_table(meta, results, estate):
    """The one table to paste into a README, an issue or a slide.

    Capability rows are answered from THIS RUN's output, not from either
    tool's documentation: a column is "yes" because the field arrived in the
    report, which is the only claim a comparison is entitled to make.
    """
    applicable = [r for r in results if r["supabomb"].get("applicable", True)]
    tu = sum(r["unruly"]["seconds"] for r in results)
    ts = sum(r["supabomb"]["seconds"] for r in applicable)
    fu = sum(len(r["unruly"]["findings"]) for r in results)
    fs = sum(len(r["supabomb"]["findings"]) for r in applicable)
    pu = sum(1 for r in results for f in r["unruly"]["findings"] if f.get("proven"))
    ps = sum(1 for r in applicable for f in r["supabomb"]["findings"] if f.get("proven"))

    def sev_line(which, rows):
        c = Counter()
        for r in rows:
            for f in r[which]["findings"]:
                c[f["severity"]] += 1
        return " / ".join(str(c.get(s, 0)) for s in
                          ["critical", "high", "medium", "low", "info"])

    u_rows = sum(f["rows"] for r in results for f in r["unruly"]["findings"]
                 if isinstance(f["rows"], int))
    u_classes = bool(estate["classes"])
    u_replay = any(f["replay"] for r in results for f in r["unruly"]["findings"])
    s_replay = any(f["replay"] for r in results for f in r["supabomb"]["findings"])
    n_selfhosted = len(results) - len(applicable)

    def pace(total, rows):
        return "%.1fs" % (total / len(rows)) if rows else "—"

    L = []
    A = L.append
    A("| | unruly | supabomb |")
    A("|---|---|---|")
    A("| targets scanned | %d | %d%s |" % (
        len(results), len(applicable),
        "" if not n_selfhosted else " (%d not addressable)" % n_selfhosted))
    A("| total wall clock | %.1fs | %s |" % (
        tu, "%.1fs" % ts if applicable else "n/a"))
    A("| average per target | %s | %s |" % (pace(tu, results), pace(ts, applicable)))
    A("| findings reported | %d | %d |" % (fu, fs))
    A("| **proven** — rows retrieved, write accepted, or data classified | **%d** | **%d** |"
      % (pu, ps))
    A("| critical / high / medium / low / info | %s | %s |" % (
        sev_line("unruly", results), sev_line("supabomb", applicable)))
    A("| rows proven reachable | %s | not reported |" % f"{u_rows:,}")
    A("| exposed relations named | %d | %d |" % (
        estate["relations_exposed"],
        len({(r["target"], f["resource"]) for r in applicable
             for f in r["supabomb"]["findings"] if f["resource"]})))
    A("| data classified (what the rows hold) | %s | no |" % ("yes" if u_classes else "none seen"))
    A("| replayable command per finding | %s | %s |" % (
        "yes" if u_replay else "no", "yes" if s_replay else "no"))
    A("| coverage gaps declared | %d | not reported |" %
      sum(len(r["unruly"]["coverage"]) for r in results))
    A("| remediation supplied | yes | yes |")
    A("| writes to the target | none | registers an account, dumps tables |")
    A("| self-hosted PostgREST | yes | no, hosted projects only |")
    return "\n".join(L)


def write_report(path, meta, results, estate, regions):
    L = []
    A = L.append
    A("# unruly vs supabomb")
    A("")
    A("## Summary")
    A("")
    A(summary_table(meta, results, estate))
    A("")
    A("- run: `%s`" % meta["when"])
    A("- targets: **%d**" % len(results))
    A("- unruly: `%s`" % meta["unruly_version"])
    A("- supabomb: `%s`" % meta["supabomb_version"])
    A("")
    A("Both tools probe for real. supabomb additionally registers a user "
      "account and dumps table contents by default; unruly refuses any write "
      "unless `-write -yes-i-own-this` is passed. That difference is in the "
      "timings below, and it is a difference in what was DONE to the target, "
      "not only in what was measured.")
    A("")

    A("## Time and cost")
    A("")
    A("| target | unruly | supabomb | unruly requests | faster |")
    A("|---|---:|---:|---:|---|")
    for r in results:
        u, s = r["unruly"], r["supabomb"]
        if not s.get("applicable", True):
            faster = "n/a — not a hosted project"
            sb = "n/a"
        else:
            sb = "%.1fs" % s["seconds"]
            faster = "unruly" if u["seconds"] < s["seconds"] else "supabomb"
            ratio = (max(u["seconds"], s["seconds"]) /
                     max(0.01, min(u["seconds"], s["seconds"])))
            faster += " (%.1f×)" % ratio
        A("| `%s` | %.1fs | %s | %s | %s |" % (
            r["target"], u["seconds"], sb,
            u["requests"] if u["requests"] is not None else "—", faster))
    A("")

    A("## What each tool found")
    A("")
    A("| target | unruly | of which proven | supabomb | of which proven | unruly coverage gaps |")
    A("|---|---:|---:|---:|---:|---:|")
    for r in results:
        u, s = r["unruly"], r["supabomb"]
        na = not s.get("applicable", True)
        up = sum(1 for f in u["findings"] if f.get("proven"))
        sp = sum(1 for f in s["findings"] if f.get("proven"))
        A("| `%s` | %d | **%d** | %s | %s | %d |" % (
            r["target"], len(u["findings"]), up,
            "n/a" if na else len(s["findings"]), "n/a" if na else "**%d**" % sp,
            len(u["coverage"])))
    A("")

    A("### Agreement, per target")
    A("")
    A("Matched on the RESOURCE each tool names, which is the only field both "
      "populate. A resource one tool reports and the other does not is listed "
      "under the tool that found it -- without a third source neither column "
      "is proof, and this table is a starting point for adjudication rather "
      "than a score.")
    A("")
    for r in results:
        u, s = r["unruly"], r["supabomb"]
        if not s.get("applicable", True):
            continue
        ur = {f["resource"] for f in u["findings"] if f["resource"]}
        sr = {f["resource"] for f in s["findings"] if f["resource"]}
        A("**`%s`**" % r["target"])
        A("")
        A("- both: %s" % (", ".join("`%s`" % x for x in sorted(ur & sr)) or "—"))
        A("- unruly only: %s" % (", ".join("`%s`" % x for x in sorted(ur - sr)) or "—"))
        A("- supabomb only: %s" % (", ".join("`%s`" % x for x in sorted(sr - ur)) or "—"))
        A("")

    A("## The estate")
    A("")
    A("Everything below is unruly's output. supabomb reports no row counts, "
      "no column names and no data classification, so a combined view would "
      "be unruly's numbers under both names.")
    A("")
    A("### By severity")
    A("")
    sev = estate["severity"]
    most = max(sev.values()) if sev else 1
    A("| severity | findings | |")
    A("|---|---:|---|")
    for s in SEVERITY_ORDER + ["unknown"]:
        if sev.get(s):
            A("| %s | %d | `%s` |" % (s, sev[s], bar(sev[s], most)))
    A("")
    A("- relations exposed: **%d**" % estate["relations_exposed"])
    A("- rows reachable across the estate: **%s**" % f"{estate['rows_exposed']:,}")
    A("")

    if estate["classes"]:
        A("### Data classes reached")
        A("")
        A("| class | occurrences |")
        A("|---|---:|")
        for c, n in sorted(estate["classes"].items(), key=lambda kv: -kv[1]):
            A("| %s | %d |" % (c, n))
        A("")

    if estate["top_columns"]:
        A("### Most frequently exposed column names")
        A("")
        A(", ".join("`%s` (%d)" % (c, n) for c, n in estate["top_columns"].items()))
        A("")

    if regions:
        A("### Where the projects answer from")
        A("")
        A("| project | region | reported by |")
        A("|---|---|---|")
        for ref, info in sorted(regions.items()):
            A("| `%s` | %s | %s |" % (ref, info["region"], info["source"]))
        A("")

    A("### Per target")
    A("")
    A("| target | worst | findings | proven | rows | coverage gaps | time |")
    A("|---|---|---:|---:|---:|---:|---:|")
    for t in sorted(estate["per_target"],
                    key=lambda t: SEVERITY_ORDER.index(t["worst"])
                    if t["worst"] in SEVERITY_ORDER else 99):
        A("| `%s` | %s | %d | **%d** | %s | %d | %.1fs |" % (
            t["target"], t["worst"], t["findings"], t.get("proven", 0),
            f"{t['rows']:,}", t["coverage_gaps"], t["seconds"]))
    A("")

    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", help="file of target URLs, one per line")
    ap.add_argument("--i-own-these", action="store_true",
                    help="confirm every target is yours; both tools probe for "
                         "real and supabomb registers an account and dumps data")
    ap.add_argument("--unruly", default="./unruly")
    ap.add_argument("--supabomb",
                    default=os.environ.get("SUPABOMB_REPO",
                                           os.path.expanduser("~/tools/supabomb")),
                    help="path to a supabomb checkout (uses `uv run`); "
                         "defaults to ~/tools/supabomb")
    ap.add_argument("--out", default="compare-out")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--unruly-flag", action="append", default=[],
                    help="extra flag passed to unruly, repeatable")
    ap.add_argument("--skip-regions", action="store_true",
                    help="do not ask each project where it answers from")
    args = ap.parse_args()

    if not args.i_own_these:
        sys.exit("refusing to run without --i-own-these.\n"
                 "Both tools send real probes, and supabomb registers a user "
                 "account and dumps table contents on every target by default. "
                 "That is a write to a live project. Confirm they are yours.")

    targets = read_targets(args.targets)
    if not targets:
        sys.exit("no targets in %s" % args.targets)

    if not (os.path.exists(args.unruly) or shutil.which(args.unruly)):
        sys.exit("unruly binary not found at %s (build it: make build)" % args.unruly)
    have_sb = bool(args.supabomb) and os.path.isdir(args.supabomb)
    if not have_sb:
        print("! no supabomb checkout given (--supabomb or SUPABOMB_REPO); "
              "running unruly alone", file=sys.stderr)

    # unruly's own capability table decides which findings reach data at all.
    # If it cannot be read, say so instead of scoring every finding unproven.
    cap = load_capability(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if cap is None:
        print("! internal/finding/plain.go not readable; the proven column would "
              "score every finding as unproven, so it is omitted", file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    _, _, uv_out = run([args.unruly, "-version"], timeout=60)
    sb_ver = "not run"
    if have_sb:
        _, _, sb_ver = run(["uv", "run", "supabomb", "--version"],
                           cwd=args.supabomb, timeout=600)

    results = []
    for i, target in enumerate(targets, 1):
        name = re.sub(r"[^A-Za-z0-9]+", "-", target).strip("-")[:60]
        print("[%d/%d] %s" % (i, len(targets), target), file=sys.stderr)

        # Alternate the order so a warm cache does not always help the same one.
        if i % 2:
            u = scan_unruly(args.unruly, target, args.out, name, args.timeout,
                            args.unruly_flag)
            s = scan_supabomb(args.supabomb, target, args.out, name, args.timeout) \
                if have_sb else {"tool": "supabomb", "seconds": 0.0, "exit": None,
                                 "findings": [], "coverage": [], "requests": None,
                                 "applicable": False, "tail": "not run"}
        else:
            s = scan_supabomb(args.supabomb, target, args.out, name, args.timeout) \
                if have_sb else {"tool": "supabomb", "seconds": 0.0, "exit": None,
                                 "findings": [], "coverage": [], "requests": None,
                                 "applicable": False, "tail": "not run"}
            u = scan_unruly(args.unruly, target, args.out, name, args.timeout,
                            args.unruly_flag)

        print("      unruly %.1fs / %d findings   supabomb %.1fs / %s" % (
            u["seconds"], len(u["findings"]), s["seconds"],
            "n/a" if not s.get("applicable", True) else len(s["findings"])),
            file=sys.stderr)
        for f in u["findings"]:
            f["proven"] = proven_unruly(f, cap)
        for f in s["findings"]:
            f["proven"] = proven_supabomb(f, s.get("dumped") or {})
        results.append({"target": target, "unruly": u, "supabomb": s})

    estate = estate_summary(results)
    regions = {}
    if not args.skip_regions:
        allf = [f for r in results for f in r["unruly"]["findings"]]
        regions = project_region(allf)

    meta = {"when": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "unruly_version": uv_out.strip().splitlines()[-1] if uv_out.strip() else "?",
            "supabomb_version": sb_ver.strip().splitlines()[-1] if sb_ver.strip() else "?"}

    md = os.path.join(args.out, "comparison.md")
    write_report(md, meta, results, estate, regions)
    # The pasteable one, on its own, so it can go into a README without
    # carrying the whole report with it.
    with open(os.path.join(args.out, "summary.md"), "w") as fh:
        fh.write("## unruly vs supabomb — %d targets, %s\n\n%s\n" % (
            len(results), meta["when"][:10], summary_table(meta, results, estate)))
    with open(os.path.join(args.out, "comparison.json"), "w") as fh:
        json.dump({"meta": meta, "results": results, "estate": estate,
                   "regions": regions}, fh, indent=2)

    tu = sum(r["unruly"]["seconds"] for r in results)
    ts = sum(r["supabomb"]["seconds"] for r in results)
    fu = sum(len(r["unruly"]["findings"]) for r in results)
    fs = sum(len(r["supabomb"]["findings"]) for r in results)
    print("\n%-10s %8s %10s" % ("", "seconds", "findings"), file=sys.stderr)
    print("%-10s %8.1f %10d" % ("unruly", tu, fu), file=sys.stderr)
    print("%-10s %8.1f %10d" % ("supabomb", ts, fs), file=sys.stderr)
    print("\nreport: %s" % md, file=sys.stderr)


if __name__ == "__main__":
    main()
