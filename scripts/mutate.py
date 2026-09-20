#!/usr/bin/env python3
"""Mutation testing for the parts of unruly that decide what is true.

Coverage says a line ran. It does not say a test would notice if the line were
wrong, and this project has now found four tests that ran the code under test
and asserted nothing about it -- most recently one that called surface.Run with
no seeds and concluded no routine was disclosed.

So each mutation below breaks one specific decision, deliberately, and the
suite must fail. A mutation that SURVIVES is a claim nothing is checking.

Two rules the harness holds itself to:

  * A pattern that does not match exactly once is a hard error, not a skip. A
    mutation that silently fails to apply tests nothing while reporting a pass,
    which is the exact failure being hunted.
  * The tree is restored even when the run is interrupted, so a crashed harness
    cannot leave a sabotaged classifier behind.

Usage:  python3 scripts/mutate.py [-k substring]
"""

import argparse
import os
import atexit
import pathlib
import shutil
import signal
import subprocess
import tempfile
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Files this process has sabotaged and must put back. A try/finally is not
# enough on its own: the first run of this harness exceeded a caller's timeout,
# was killed outright, and left a mutated classifier on disk -- which then
# failed the NEXT run's baseline and would have been committed if the baseline
# check did not exist. Restoration is registered before any write and repeated
# on SIGINT and SIGTERM.
_PENDING: dict = {}


def _restore_all(*_):
    for path, text in list(_PENDING.items()):
        pathlib.Path(path).write_text(text)
        _PENDING.pop(path, None)


atexit.register(_restore_all)
for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(_sig, lambda s, f: (_restore_all(), sys.exit(128 + s)))


# Only one mutation run at a time, per checkout.
#
# Restoration on signal covers this process being killed. It does not cover
# being ORPHANED: killing `make audit` does not kill the mutate.py it started,
# and the orphan keeps applying and reverting mutations. Start a second audit
# while that is happening and its baseline runs against a tree with a mutation
# applied -- so the run reports "the suite is already red", having measured the
# previous run's sabotage rather than the code.
#
# Measured exactly that way: an audit killed at its unit stage left this harness
# running, the next audit's baseline failed, and the tree was left holding
# `NoResidue: s.NoResidue` deleted from SchemasStage.probeOptions. Neither run
# said anything about the real cause.
#
# A lock turns that into a refusal that names the holder.
_LOCK_PATH = ROOT / ".mutate.lock"
_LOCK_FH = None


def _isolated_copy():
    """Copy every tracked file into a temp dir and return its path.

    --buildcheck is spawned from a Go test, so it runs inside `go test ./...`
    alongside every other package's compilation. Applying mutations to THIS
    tree means another package can be compiled from a mutated dependency and
    fail for a reason that has nothing to do with it, then pass on the next
    run. Measured before this was fixed: 53 source files were modified during
    a single test run. Killing the parent `go test` does not kill this child,
    so an orphan went on cycling mutations through the tree long enough for
    cmd/unruly's TestChooseKey to fail against a mutated vocabsources.go. The
    SIGTERM handler above restores correctly -- the hazard is not a failed
    cleanup, it is that the file is mutated at all while others read it.

    Taken from the WORKING TREE rather than from HEAD, so uncommitted edits are
    checked and .gitignored material -- including .secrets/ -- is never copied.

    Untracked-but-not-ignored files are copied TOO, and that is not a nicety.
    With `git ls-files` alone, a new file that had not been `git add`ed was
    absent from the copy while the edits CALLING it were present, so the
    package could not compile and all 25 of its mutations were reported
    "killed by the compiler" -- a red result whose cause was in neither the
    mutations nor the code. That is this project's recurring defect wearing a
    new hat: a check that cannot see part of its domain reporting a confident
    verdict about it.
    """
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                             capture_output=True, check=True)
    untracked = subprocess.run(
        ["git", "ls-files", "-z", "--others", "--exclude-standard"], cwd=ROOT,
        capture_output=True, check=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="unruly-buildcheck-"))
    for raw in tracked.stdout.split(b"\0") + untracked.stdout.split(b"\0"):
        if not raw:
            continue
        rel = raw.decode()
        src = ROOT / rel
        if not src.is_file():
            continue  # a deleted-but-tracked path, or a submodule
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return work


def _take_lock() -> None:
    global _LOCK_FH
    import fcntl

    # "a+" and not "w": opening for write TRUNCATES, which would erase the
    # holder's pid before flock even fails and leave the refusal unable to say
    # who to kill. The whole value of this message is naming the process.
    _LOCK_FH = open(_LOCK_PATH, "a+")
    try:
        fcntl.flock(_LOCK_FH, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        _LOCK_FH.seek(0)
        holder = ""
        try:
            holder = _LOCK_FH.read().strip()
        except OSError:
            pass
        print(
            "another mutation run holds " + str(_LOCK_PATH)
            + (" (pid " + holder + ")" if holder else "")
            + ".\nIt rewrites source in place, so a second run would measure its "
            "sabotage rather than the code.\nKill it -- `pkill -f scripts/mutate.py` "
            "-- and check `git status` before starting again.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    _LOCK_FH.seek(0)
    _LOCK_FH.truncate()
    _LOCK_FH.write(str(os.getpid()))
    _LOCK_FH.flush()

# (id, file, find, replace, what it breaks, packages that should catch it)
#
# Packages are named per mutation rather than running everything: a full
# ./internal/... run takes over a minute, and ten of them exceeded the time
# budget entirely. Naming them also makes a survivor sharper -- it says which
# package's tests are silent, not merely that some test somewhere is.
MUTATIONS = [
    # cmd/estate, the fleet-scale summary.
    #
    # Its failure modes are all quiet ones: a number that reads plausibly and
    # is wrong about somebody's whole estate, or a report that leaks the data
    # it exists to count.
    (
        "estate-counts-coverage-as-exposure",
        "cmd/estate/estate.go",
        "\t\t\tif coverageID[f.ID] {\n\t\t\t\te.CoverageGaps++\n\t\t\t\tcontinue\n\t\t\t}",
        "\t\t\tif coverageID[f.ID] {\n\t\t\t\te.CoverageGaps++\n\t\t\t}",
        "the estate summary counts \"this surface was not assessed\" as an exposure, so "
        "every total in a thousand-target report is inflated by the scanner's own "
        "honesty about what it could not reach",
        ["./cmd/estate/"],
    ),
    (
        "estate-drops-projects-with-no-known-region",
        "cmd/estate/estate.go",
        '\tif strings.TrimSpace(name) == "" {\n\t\tname = "unknown"\n\t}',
        '\tif strings.TrimSpace(name) == "" {\n\t\tname = ""\n\t}',
        "projects whose region could not be resolved vanish from the region table "
        "instead of being reported as unknown, so a jurisdiction report silently "
        "describes only the subset that happened to resolve",
        ["./cmd/estate/"],
    ),
    (
        "estate-publishes-the-data-it-counts",
        "cmd/estate/estate.go",
        "\t\t\t\tcolNames = append(colNames, c)\n\t\t\t\te.Columns[c]++",
        "\t\t\t\tcolNames = append(colNames, c)\n\t\t\t\tfor _, r := range rows {\n\t\t\t\t\te.Columns[fmt.Sprint(r[c])]++\n\t\t\t\t}",
        "the summary keys its column table on VALUES rather than column names, so a "
        "report an operator forwards becomes a second copy of the leak it was written "
        "to describe",
        ["./cmd/estate/"],
    ),
    # -proven, the filter that answers "what can somebody actually do".
    #
    # Its failure mode is silence: a filter that drops too much makes a report
    # look clean, and the operator who asked for a quieter report is exactly
    # the one who will not notice the difference.
    (
        "proven-reports-what-was-never-retrieved",
        "internal/finding/finding.go",
        "\tcap, reaches := capability[f.ID]\n\tif !reaches {\n\t\treturn false\n\t}",
        "\tcap, reaches := capability[f.ID]\n\tif !reaches {\n\t\treturn true\n\t}",
        "-proven keeps findings that reach no data at all -- a routine that merely "
        "exists, a backend named in a header -- so the flag an operator uses to cut "
        "noise returns the noise it was meant to remove",
        ["./internal/finding/"],
    ),
    (
        "proven-drops-every-write-finding",
        "internal/finding/finding.go",
        "\tcase createRows, changeRows, deleteRows, runAnything:",
        "\tcase runAnything:",
        "-proven demands sampled rows from write findings, which have none: an "
        "accepted INSERT, UPDATE or DELETE is the retrieval. The most serious thing "
        "the scanner can find disappears from the filtered report",
        ["./internal/finding/"],
    ),
    (
        "proven-filters-when-nobody-asked",
        "internal/finding/finding.go",
        "\tif w.Proven && !f.proven() {",
        "\tif !f.proven() {",
        "the proven filter applies to every scan whether or not it was requested, so "
        "an ordinary run silently stops reporting discoverable routines, open signup "
        "and disclosed project references",
        ["./internal/finding/"],
    ),
    # The demonstrator's four discriminators.
    #
    # internal/exploit is not the scanner -- it is the second implementation
    # that discharges the application rows in docs/exploitability.md -- and
    # that is exactly why these belong here. A demonstrator whose checks have
    # rotted still prints "demonstrated", and the ledger goes on citing it.
    #
    # Three of these four SURVIVED when they were first broken by hand: the
    # sound application refuses the paths the techniques ask for, so each
    # declined at an earlier guard and the discriminator was never reached.
    # The controls that reach them were written in the same commit.
    (
        "exploit-claims-an-open-endpoint-that-holds-nothing",
        "internal/exploit/application.go",
        '\tcase !strings.Contains(body, "@"):',
        "\tcase false:",
        "the public-record demonstration stops requiring anything IN the record, so a "
        "status page returning a build number proves the finding and the ledger cites "
        "it as evidence that personal data was retrieved",
        ["./internal/exploit/"],
    ),
    (
        "exploit-claims-a-specification-that-adds-no-name",
        "internal/exploit/application.go",
        "\t\tif !strings.Contains(body, want) {",
        "\t\tif false && !strings.Contains(body, want) {",
        "the published-specification demonstration stops requiring the document to name "
        "an endpoint no bundle calls, so a spec describing only what the front end "
        "already calls counts as reach an attacker did not have",
        ["./internal/exploit/"],
    ),
    (
        "exploit-claims-a-header-that-changed-nothing",
        "internal/exploit/application.go",
        "\tcase strings.TrimSpace(body) == strings.TrimSpace(ctrlBody) && withHdr == control:",
        "\tcase false && strings.TrimSpace(body) == strings.TrimSpace(ctrlBody) && withHdr == control:",
        "the bypass demonstration drops its third request, the one asking whether the "
        "URL answers identically WITHOUT the header, so any application whose root "
        "serves anonymous callers is reported as bypassed",
        ["./internal/exploit/"],
    ),
    (
        "exploit-claims-two-identities-that-were-served-different-rows",
        "internal/exploit/application.go",
        "\tcase strings.TrimSpace(ba) != strings.TrimSpace(bb):",
        "\tcase false && strings.TrimSpace(ba) != strings.TrimSpace(bb):",
        "the cross-identity demonstration stops comparing the two bodies, so an "
        "endpoint that correctly returns each caller their OWN row -- the shape a "
        "well-built API has -- is reported as one account reading another's data",
        ["./internal/exploit/"],
    ),
    (
        "provider-guide-stops-naming-the-artifact-store",
        "docs/providers.md",
        "scan.Put(st, Relations{Names: names})       // keyed by its Go type",
        "// values move between stages somehow",
        "the document a backend author reads stops naming how stages hand values to "
        "each other, so the next backend is written against a contract two "
        "architectures out of date -- which is what the document already was before "
        "anything checked it",
        ["./internal/eval/"],
    ),
    (
        "silent-about-not-testing-writes",
        "cmd/unruly/main.go",
        "\t\tif !o.write {",
        "\t\tif false {",
        "a default scan stops saying that write exposure was never tested, so a reader "
        "seeing three criticals assumes the scan covered whether their data can be "
        "modified, when it only ever asked whether it can be read",
        ["./internal/eval/"],
    ),
    (
        "ci-invokes-a-target-that-does-not-exist",
        ".github/workflows/ci.yml",
        "make lint-check",
        "make lint-checks",
        "the CI workflow invokes a make target that does not exist, so the first pull "
        "request anybody sends fails for a reason that has nothing to do with their change",
        ["./internal/eval/"],
    ),
    (
        "response-read-is-unbounded",
        "internal/client/client.go",
        "\t\tpayload, _ := io.ReadAll(io.LimitReader(resp.Body, c.bodyLimit()))",
        "\t\tpayload, _ := io.ReadAll(resp.Body)",
        "responses are read without a bound, so a target sending 261 KB of gzip that "
        "expands to 256 MB decides how much memory the scan uses",
        ["./internal/client/"],
    ),
    (
        "report-omits-what-was-examined",
        "cmd/unruly/main.go",
        "\t\tall = append(all, finding.ScanSummary(target(o), cov.Relations, cov.Schemas,\n\t\t\trequests, cov.SeedOrigins))",
        # `_ = cov` since the whole summary now reads one neutral artifact:
        # deleting the summary leaves that read unused, and a mutation killed by
        # the compiler reads as a guarded decision while guarding nothing.
        "\t\t_ = finding.ScanSummary\n\t\t_ = cov",
        "the stored report stops saying how many relations were discovered, so a saved scan "
        "with no exposures cannot be told apart from one that discovered nothing -- and a "
        "reader diffing two scans cannot tell a fixed project from a smaller scan",
        ["./internal/eval/"],
    ),
    (
        "every-public-bucket-is-medium",
        "internal/surface/surface.go",
        "\tsev, why := bucketSeverity(b.Name)",
        "\tsev, why := finding.Medium, \"\"",
        "every public storage bucket is reported at medium again, including the ones named "
        "images and avatars that Supabase documents as the way to serve assets -- so the "
        "one bucket called invoices scrolls past with the noise",
        ["./internal/surface/"],
    ),
    (
        "column-probing-is-unbounded",
        "internal/probe/probe.go",
        "\t\t\tif budget.take(len(sensitiveCandidates)) {",
        "\t\t\tif true {",
        "sensitive-column probing loses its budget, so a project with 500 exposed relations "
        "receives 16,500 requests it never agreed to and nothing in the report says the "
        "scan was that expensive",
        ["./internal/probe/"],
    ),
    (
        "repeated-stage-loses-a-control",
        "backend/supabase/schemas_stage.go",
        "\t\tNoResidue:       s.NoResidue,\n\t\tSchema:          schema,",
        "\t\tSchema:          schema,",
        "the per-schema probe stops inheriting -no-residue, so a write test promising to "
        "create nothing leaves rows behind in every schema but the default -- the same "
        "shape of defect that let -measure retrieve a stranger's data",
        # Was ./internal/eval/ only, where the eval that would notice needs the
        # live lab and skips offline -- so this was scored caught by the
        # harness's own bookkeeping check and never by a test. It now has an
        # offline grader.
        ["./backend/supabase/", "./internal/eval/"],
    ),
    (
        "schema-probe-ignores-measure",
        "backend/supabase/schemas_stage.go",
        "\t\tSchema:          schema,\n\t\tMeasure:         s.Measure,",
        "\t\tSchema:          schema,",
        "-measure is not inherited by the probe that runs for additional exposed schemas, "
        "so a scan promising to retrieve no data pulls real rows out of somebody else's "
        "database -- which it did, against a third-party site, before the harness caught it",
        ["./backend/supabase/", "./internal/eval/"],
    ),
    (
        "retry-after-ignored",
        "internal/client/client.go",
        "\t\t\tif !sleepCtx(ctx, retryDelay(attempt, resp.Header)) {\n\t\t\t\treturn out\n\t\t\t}",
        "\t\t\t_ = retryDelay",
        "a target answering 429 is retried immediately, so an explicit slow-down request "
        "from somebody else's infrastructure is ignored and the retry budget is spent on "
        "responses that were never going to succeed",
        ["./internal/client/"],
    ),
    (
        "measure-mode-cannot-tell-tokens-from-blog-posts",
        "internal/probe/probe.go",
        "\t\t\trel.Columns, rel.requests = probeSensitiveColumns(ctx, c, name, rel.requests)",
        "\t\t\t_ = probeSensitiveColumns",
        "a measurement scan stops learning column names, so a publicly readable table of "
        "session tokens is reported at the same severity as a table of blog posts -- the "
        "distinction severity exists to make",
        ["./internal/probe/"],
    ),
    (
        "site-url-query-mangled",
        "internal/discover/discover.go",
        "\tbody, hdr, ok := get(site)",
        "\tbody, hdr, ok := get(strings.TrimRight(o.Site, \"/\") + \"/\")",
        "a target URL carrying a query has \"/\" appended to the query itself, so the "
        "document fetched is not the one asked for -- which is 218 of the 10,000 URLs in a "
        "real prospect list, and 716 more carry a path",
        ["./internal/discover/"],
    ),
    (
        "script-discovery-requires-a-leading-slash",
        "internal/assets/assets.go",
        "\t\tif !ok || seen[ref] {",
        "\t\tif !ok || seen[ref] || !strings.HasPrefix(m[1], \"/\") {",
        "script discovery ignores relative references again, so a page serving "
        "<script src=\"script.js\"> has its credentials missed entirely and is reported as "
        "not being a Supabase application at all -- measured on a real site whose script.js "
        "held both the project URL and the anon key",
        ["./internal/assets/", "./internal/enumerate/"],
    ),
    (
        "measure-mode-still-retrieves-rows",
        "internal/probe/probe.go",
        "\tlimit := o.SampleRows\n\tif o.Measure {\n\t\tlimit = 0\n\t}",
        "\tlimit := o.SampleRows",
        "-measure retrieves rows after all, so a study of projects nobody owns downloads "
        "strangers' personal data while claiming not to -- the one promise that makes such "
        "a scan defensible",
        ["./internal/probe/"],
    ),
    (
        "role-claim-read-by-substring",
        "internal/creds/creds.go",
        "\tif !decodeClaims(tok, &claims) {\n\t\treturn \"\"\n\t}\n\treturn claims.Role",
        "\tif !decodeClaims(tok, &claims) {\n\t\treturn \"\"\n\t}\n\tif !strings.Contains(tok, \"cGF5bG9hZA\") {\n\t\treturn \"\"\n\t}\n\treturn claims.Role",
        "the role claim stops being read for ordinary tokens, which is what the old "
        "substring matcher did to any key whose payload contained a space: a leaked "
        "service_role key reported as nothing at all",
        ["./internal/creds/", "./internal/discover/"],
    ),
    (
        "archives-not-scanned-for-the-worst-credentials",
        "internal/history/history.go",
        "\tout = append(out, creds.MgmtToken.FindAllString(body, -1)...)",
        "\t_ = creds.MgmtToken",
        "public archives are not searched for Management API tokens, so the one channel "
        "where a secret that was 'removed' still works is unchecked for the credential "
        "that compromises every project in the account",
        ["./internal/history/"],
    ),
    (
        "management-token-not-detected",
        "internal/discover/discover.go",
        "\tif m := creds.MgmtToken.FindString(content); m != \"\" {",
        "\tif m := creds.MgmtToken.FindString(content); false {",
        "a Supabase Management API token served to browsers is not reported, so the one "
        "credential that compromises every project in the account -- their keys, their "
        "database passwords, their existence -- is the one the scanner walks past",
        ["./internal/discover/"],
    ),
    (
        "connection-string-template-reported-as-a-leak",
        "internal/discover/discover.go",
        "\t\tif creds.PlaceholderPassword(m[1]) {\n\t\t\tcontinue\n\t\t}",
        "\t\tif false {\n\t\t\tcontinue\n\t\t}",
        "the [YOUR-PASSWORD] connection string Supabase's own dashboard hands out is "
        "reported as a leaked credential at CRITICAL, which is how a scanner teaches "
        "people to ignore its most serious severity",
        ["./internal/discover/"],
    ),
    (
        "readme-shows-a-flag-that-does-not-exist",
        "README.md",
        "unruly -u https://app.example.com -fix         # with SQL remediation",
        "unruly -u https://app.example.com -emit-fixes  # with SQL remediation",
        "the README's worked examples name a flag the tool does not define, so a reader "
        "copying the project's own front-page command gets \"unknown flag\" and no scan",
        ["./internal/eval/"],
    ),
    (
        "edge-control-failure-treated-as-a-pass",
        "internal/surface/surface.go",
        "\tif ctrl.Err != nil {\n\t\tres.Findings = append(res.Findings, uncheckedFinding(c, \"edge-functions\", base,\n\t\t\t\"Edge Functions were not assessed. The control probe for a function name that \"+\n\t\t\t\t\"cannot exist never completed (\"+ctrl.Err.Error()+\"), so this scan could \"+\n\t\t\t\t\"not establish that the host tells a deployed function apart from an \"+\n\t\t\t\t\"absent one. Without that, every candidate name would look deployed. \"+\n\t\t\t\t\"Absence of Edge Function findings below is not evidence that none are \"+\n\t\t\t\t\"exposed.\"))\n\t\treturn nil\n\t}\n\tif classifyFunction(ctrl.Status) != functionAbsent {",
        "\tif ctrl.Err == nil && classifyFunction(ctrl.Status) != functionAbsent {",
        "restores the short-circuit this guard was split out of: a control probe that "
        "never completed is skipped rather than reported, so the scan proceeds against "
        "a host whose answers it cannot interpret -- which is how a catch-all turns the "
        "pinned function wordlist into findings and privileged-looking names into HIGHs",
        ["./internal/surface/"],
    ),
    (
        "failed-target-vanishes-from-the-report",
        "cmd/unruly/main.go",
        "\t\t\tif _, _, _, werr := emitAll(w, []finding.Finding{\n\t\t\t\tfinding.TargetFailed(target, err, to.keyWithheldRef)}); werr != nil {\n\t\t\t\treturn werr\n\t\t\t}",
        "\t\t\t_ = finding.TargetFailed",
        "a target the scan could not start on produces no finding at all, so a list of "
        "fifty projects where ten errored writes a report covering forty with nothing "
        "naming the ten that are missing",
        ["./internal/eval/"],
    ),
    (
        "project-url-plus-key-is-refused",
        "cmd/unruly/discovery.go",
        '\treturn o.projectRef != "" || o.baseURL != "" ||\n\t\t(o.anonKey != "" && strings.HasPrefix(o.target, "http"))',
        # keeps strings referenced: a mutation the compiler kills grades nothing
        '\t_ = strings.HasPrefix\n\treturn o.projectRef != "" || o.baseURL != ""',
        "the tool's most basic invocation -- a project URL and an anon key -- is refused "
        "with a message naming the flag the operator just supplied, and produces an empty "
        "report against a project with seven anonymously readable tables",
        ["./cmd/unruly/", "./internal/eval/"],
    ),
    (
        "vocabulary-outage-looks-like-an-empty-result",
        "backend/supabase/vocabulary_shortfall.go",
        '\t\tf := finding.NotAssessedApplication(site,\n\t\t\tfmt.Sprintf("%d source(s) read, no usable vocabulary in them", sources))',
        # keeps sources referenced: a mutation the compiler kills grades nothing
        '\t\t_ = sources\n\t\tf := finding.NotAssessedApplication(site, "no response from the application")',
        "an application that answered but held no usable vocabulary is reported as an "
        "unreachable one, so the operator is sent to debug a network problem they do not "
        "have while the real finding -- that enumeration recall is a lower bound -- reads "
        "as an outage",
        ["./backend/supabase/"],
    ),
    (
        "declared-api-origin-loses-to-the-guess",
        "cmd/unruly/discovery.go",
        '\tif declared != "" {',
        '\tif declared == "" && false {',
        "a self-hosted deployment that declares its API origin is scanned at its website "
        "instead: measured at 16,558 requests, 0 relations, and a report reading clean on "
        "a project the same scan finds 21 relations in once it is aimed correctly -- a "
        "clean bill of health for a host nobody asked about",
        ["./cmd/unruly/"],
    ),
    (
        "rejected-key-reported-as-a-refusing-host",
        "cmd/unruly/gaveup.go",
        "\tif keyRejected {",
        "\tif keyRejected && false {",
        "a scan blinded by a key the project rejected is reported as a host that refused "
        "every request, so the operator is told to back off a target that was answering "
        "fine and never learns the credential is the problem",
        ["./cmd/unruly/"],
    ),
    (
        "created-probe-account-is-not-reported",
        "cmd/unruly/account.go",
        "\tif acct.Created {",
        "\tif acct.Created && false {",
        "an account the scan created on someone else's project under -write is never "
        "reported, so the one lasting change this tool can make to a target is left out "
        "of the only record its owner gets -- residue the tool promises not to leave",
        ["./cmd/unruly/"],
    ),
    (
        "non-supabase-target-reaches-postgrest-prefix-probe",
        "cmd/unruly/main.go",
        "\tif !supabaseOK {\n\t\tgologger.Info().Msgf(\"no Supabase pipeline: %s\", whyNot)",
        "\tif false && !supabaseOK {\n\t\tgologger.Info().Msgf(\"no Supabase pipeline: %s\", whyNot)",
        "a plain application with an ambient key falls through to PostgREST prefix "
        "resolution, sending provider-specific traffic to a backend the target never "
        "identified and turning the absence of Supabase into degraded findings",
        ["./cmd/unruly/"],
    ),
    (
        "neon-detector-fires-on-any-neon-host",
        "internal/provider/neon.go",
        '\t`https://([a-z0-9-]+\\.apirest\\.[a-z0-9.-]+\\.neon\\.tech)/([A-Za-z0-9_-]+)/rest/v1/`)',
        '\t`https://([a-z0-9-]+\\.[a-z0-9.-]*neon\\.tech)/([A-Za-z0-9_-]*)`)',
        "any neon.tech URL in a bundle is reported as a Data API endpoint -- a docs "
        "link, the vendor console, or a Postgres connection host -- so the scan names a "
        "backend on a host nobody owns, which is the worst false positive this tool can "
        "produce",
        ["./internal/provider/"],
    ),
    (
        "malformed-answer-key-is-sent-anyway",
        "internal/exploit/techniques.go",
        '\tif strings.TrimSpace(value) != "" {\n\t\treturn o, false\n\t}',
        '\t_ = strings.TrimSpace\n\tif true {\n\t\treturn o, false\n\t}',
        "an answer key entry that names no relation is attempted anyway, so the harness "
        "sends a POST to /rest/v1/ -- a write aimed at nothing, against whatever base_url "
        "names, on a harness that runs against real projects",
        ["./internal/exploit/"],
    ),
    (
        "bundle-budget-ignores-chunk-signal",
        "internal/assets/assets.go",
        "\t\tif runtimeChunk.MatchString(m[1]) {",
        "\t\tif false {",
        "the JS bundle budget stops preferring application code, so a framework runtime "
        "chunk is read in preference to a page chunk -- the budget goes to the one file "
        "guaranteed not to mention the data model",
        ["./internal/enumerate/"],
    ),
    (
        "critical-finding-cannot-be-reproduced",
        "internal/discover/discover.go",
        '\t\t\tRequest: "curl -sS \'" + where + "\' | grep -oE " +\n\t\t\t\t"\'(eyJ[A-Za-z0-9_-]+[.]){2}[A-Za-z0-9_-]+|sb_secret_[A-Za-z0-9]+\'",',
        '\t\t\tRequest: "",',
        "the critical service_role finding ships without the request that produced it, so a "
        "reader who does not trust the scanner cannot reproduce its most serious claim",
        ["./internal/discover/"],
    ),
    (
        "truncated-vocabulary-is-not-disclosed",
        "internal/enumerate/vocab.go",
        "\t\tSeeds: seeds, Sources: dedupSorted(sources), Harvested: harvested,",
        "\t\tSeeds: seeds, Sources: dedupSorted(sources), Harvested: len(seeds) + harvested*0,",
        "a truncated vocabulary reports itself as complete, so the most upstream bound in "
        "the scan -- 2,000 of 4,112 tokens on the reference project, feeding both relation "
        "and routine discovery -- is silent and the relation list looks exhaustive",
        ["./internal/enumerate/"],
    ),
    (
        "seed-cap-keeps-the-front-of-the-alphabet",
        "internal/enumerate/vocab.go",
        "\tseeds = sample.Take(seeds, o.MaxSeeds)",
        "\tif len(seeds) > o.MaxSeeds {\n\t\tseeds = seeds[:o.MaxSeeds]\n\t}",
        "the harvested vocabulary is cut at the front, so on any site yielding more tokens "
        "than the cap (4,112 against 2,000 on the reference project) half the application's "
        "own words are discarded alphabetically before a single probe is sent",
        ["./internal/enumerate/"],
    ),
    (
        "rpc-budget-truncates-alphabetically",
        "internal/surface/surface.go",
        "\tadd(sample.Strided(snake, seedBudget))\n\tadd(sample.Strided(plain, seedBudget))",
        "\t_ = seedBudget\n\t_ = sample.Strided\n\tadd(snake)\n\tadd(plain)",
        "the RPC probe budget spends itself on the alphabetically first seeds, so routines "
        "named update_*, verify_* or write_* are unreachable on every project where the "
        "budget binds -- which is every real scan",
        ["./internal/surface/"],
    ),
    (
        "service-key-finding-republishes-the-key",
        "internal/discover/discover.go",
        'Response: safePrefix(key) + "\u2026",',
        "Response: key,",
        "the critical finding that says a service_role key is exposed carries the whole key, "
        "so pasting the report into a ticket discloses the credential again",
        ["./internal/discover/"],
    ),
    (
        "remediation-names-a-flag-that-does-not-exist",
        "internal/finding/scan.go",
        "-severity or -no-routes",
        "-severity or -skip-routes",
        "the tool tells an operator to pass a flag it does not have, so following its own "
        "advice produces \"unknown flag\" and no scan at all",
        ["./internal/eval/"],
    ),
    (
        "interrupted-scan-blames-the-target",
		"internal/engine/engine.go",
		"\t\tfinding.AttributeBlindnessToInterruption(out.Findings)",
		"\t\t_ = out.Findings // mutated: leave the blind verdicts unattributed",
        "an interrupted scan describes its own cancelled requests as properties of "
        "the target, advising the operator to fix a configuration problem they do not have",
        ["./internal/eval/"],
    ),
    (
        "read-counted-rows-ignored",
        "internal/postgrest/classify.go",
        "\t\tif n > 0 {\n\t\t\treturn ReadExposed, n\n\t\t}\n\t\treturn ReadEmpty, 0",
        "\t\tif n > 0 {\n\t\t\treturn ReadEmpty, 0\n\t\t}\n\t\treturn ReadEmpty, 0",
        "a counted read of N>0 rows stops being read exposure: the central false negative",
        ["./internal/postgrest/", "./internal/probe/"],
    ),
    (
        "read-rls-filtered-empty-is-exposure",
        "internal/postgrest/classify.go",
        "\t\tif n > 0 {\n\t\t\treturn ReadExposed, n\n\t\t}\n\t\treturn ReadEmpty, 0\n\tcase http.StatusUnauthorized",
        "\t\tif n > 0 {\n\t\t\treturn ReadExposed, n\n\t\t}\n\t\treturn ReadExposed, 0\n\tcase http.StatusUnauthorized",
        "200 with Content-Range */0 -- an RLS-filtered empty result -- reported as exposed",
        ["./internal/postgrest/", "./internal/probe/"],
    ),
    (
        "write-rls-denial-is-reachable",
        "internal/postgrest/classify.go",
        "\tif reason, ok := blockedCodes[b.Code]; ok {\n\t\treturn WriteBlockedRLS, reason, true\n\t}",
        "\tif reason, ok := blockedCodes[b.Code]; ok {\n\t\treturn WriteReached, reason, true\n\t}",
        "42501 read as a reachable write: every protected relation becomes a finding",
        ["./internal/postgrest/", "./internal/probe/"],
    ),
    (
        "write-preflight-error-is-reachable",
        "internal/postgrest/classify.go",
        "\tif reason, ok := preFlightCodes[b.Code]; ok {\n\t\treturn WriteInconclusive, reason, true\n\t}",
        "\tif reason, ok := preFlightCodes[b.Code]; ok {\n\t\treturn WriteReached, reason, true\n\t}",
        "PGRST204 treated as proof the table was reached, though PostgREST raises it "
        "from its own cache before any SQL runs",
        ["./internal/postgrest/", "./internal/probe/"],
    ),
    (
        "hint-oracle-blinded",
        "internal/postgrest/classify.go",
        "func HintedRelation(hint string) (string, bool) {\n\ti := strings.Index(hint, hintPrefix)",
        "func HintedRelation(hint string) (string, bool) {\n\tif true {\n\t\treturn \"\", false\n\t}\n\ti := strings.Index(hint, hintPrefix)",
        "the relation hint oracle returns nothing: enumeration goes silently blind",
        ["./internal/postgrest/", "./internal/enumerate/"],
    ),
    (
        "probe-row-not-cleaned-up",
        "internal/probe/probe.go",
        "\t\t\tdel.state, del.why, cleanupErr = deleteRow(ctx, c, name, rows[0])",
        "\t\t\tdel.state, del.why, cleanupErr = postgrest.WriteReached, \"\", \"\"",
        "a probe-created row is left behind and reported as removed",
        ["./internal/probe/"],
    ),
    (
        "no-residue-sends-empty-insert",
        "internal/probe/probe.go",
        "\t\tif body, ok = collidingBody(sample); !ok {",
        "\t\tif body, ok = []byte(`{}`), true; !ok {",
        "-no-residue goes back to an INSERT that can create a row",
        ["./internal/probe/"],
    ),
    (
        "routine-discovery-invokes",
        "internal/surface/surface.go",
        "\t\tresp := c.Get(ctx, c.RPCURL(name), nil)",
        "\t\tresp := c.Do(ctx, \"POST\", c.RPCURL(name), []byte(`{}`), nil)",
        "routine discovery calls every candidate instead of asking whether it exists",
        ["./internal/surface/"],
    ),
    (
        "direct-hit-control-ignored",
        "internal/surface/surface.go",
        "\t\tdirectHitsDiscriminate = ctrl.Status == 404 && ccode == \"PGRST202\"",
        "\t\tdirectHitsDiscriminate = true\n\t\t_ = ccode",
        "a host that answers 200 to everything yields one phantom routine per candidate",
        ["./internal/surface/"],
    ),
    (
        "unknown-callability-rated-as-proven",
        "internal/surface/surface.go",
        "\t\t\tsev = finding.Low\n\t\t}\n\t\treturn buildRoutineFinding(c, name, sev, note, schema)",
        "\t\t\tsev = finding.Medium\n\t\t}\n\t\treturn buildRoutineFinding(c, name, sev, note, schema)",
        "a routine whose callability was never established is rated like one proven callable",
        ["./internal/surface/", "./internal/finding/"],
    ),
    (
        "redaction-leaks-samples",
        "internal/probe/probe.go",
        "\tsample := rel.Sample\n\tif redact {\n\t\tsample = nil\n\t}",
        "\tsample := rel.Sample\n\tif false {\n\t\tsample = nil\n\t}",
        "-redact stops removing sampled rows: real customer data in a shareable report",
        ["./internal/probe/"],
    ),
    (
        "rate-limit-ignored",
        "internal/client/limiter.go",
        "\t_ = lim.l.Wait(ctx)",
        "\t_ = ctx",
        "-rate-limit becomes advisory: the target receives full-speed traffic regardless",
        ["./internal/client/"],
    ),
    (
        "bucket-unknown-counted-as-present",
        "internal/surface/storage.go",
        "\t\tif resp.Status != 400 && resp.Status != 404 {\n\t\t\treturn bucketUnknown\n\t\t}",
        "\t\tif resp.Status != 400 && resp.Status != 404 {\n\t\t\treturn bucketExists\n\t\t}",
        "an audit-found CRITICAL replayed: throttling or a gateway error invents a bucket, "
        "so every candidate name is reported as real",
        ["./internal/surface/"],
    ),
    (
        "enumerate-control-ignored",
        "internal/enumerate/oracle.go",
        "\tcase postgrest.ReadExposed, postgrest.ReadEmpty:\n\t\tres.Discriminating = false",
        "\tcase postgrest.ReadExposed, postgrest.ReadEmpty:\n\t\tres.Discriminating = true",
        "a host answering every relation name is treated as discriminating, so every "
        "candidate becomes a discovered relation",
        ["./internal/enumerate/"],
    ),
    (
        "enumerate-merge-discards",
        "internal/enumerate/oracle.go",
        "func (r Result) Merge(other Result) Result {\n\tseen := make(map[string]bool, len(r.Relations))",
        "func (r Result) Merge(other Result) Result {\n\tif true {\n\t\treturn other\n\t}\n\tseen := make(map[string]bool, len(r.Relations))",
        "the expansion pass REPLACES earlier results instead of merging, silently losing "
        "relations already found -- a bug this project shipped once",
        ["./internal/enumerate/"],
    ),
    (
        "blindness-never-reported",
        "internal/finding/coverage.go",
        "var blindIDs = map[string]bool{\n\t\"unruly-target-not-discriminating\": true,",
        "var blindIDs = map[string]bool{\n\t\"disabled-by-mutation\": true,\n\t\"x-unruly-target-not-discriminating\": true,",
        "a scan that could not see stops exiting 3, so unmeasured reads as clean",
        ["./internal/finding/"],
    ),
    (
        "preview-findings-discarded",
        "internal/preview/preview.go",
        "\t\tif len(d.Findings) > 0 {",
        "\t\tif false {",
        "a CRITICAL replayed: the preview sweep keeps the anon key and throws away the "
        "findings, including any service_role key it found",
        ["./internal/preview/"],
    ),
    (
        "escalation-replaces-the-apikey",
        "internal/escalate/escalate.go",
        "\televated := base.WithBearer(o.ElevatedKey)",
        "\televated := base.WithKey(o.ElevatedKey)",
        "the shipped -user-jwt bug replayed: the user token replaces the project apikey, "
        "a managed project answers \"Invalid API key\" to everything, and the pass reports "
        "zero gains built entirely from refusals",
        ["./internal/escalate/"],
    ),
    (
        "escalation-counts-already-public",
        "internal/escalate/escalate.go",
        "\t\tif rel.Read != postgrest.ReadExposed || baseReadable[rel.Name] {",
        "\t\tif rel.Read != postgrest.ReadExposed {",
        "every relation anon could already read is re-reported as an escalation gain",
        ["./internal/escalate/"],
    ),
    (
        "edge-protected-counted-as-reached",
        "internal/surface/surface.go",
        "\tcase status == 401 || status == 403:\n\t\treturn functionProtected",
        "\tcase status == 401 || status == 403:\n\t\treturn functionReached",
        "a function that verify_jwt correctly refused is reported as anonymously invokable",
        ["./internal/surface/"],
    ),
    (
        "edge-control-probe-ignored",
        "internal/surface/surface.go",
        "\tif classifyFunction(ctrl.Status) != functionAbsent {",
        "\tif false {",
        "the 392-findings bug replayed: a host answering every path yields an Edge "
        "Function finding per candidate name",
        ["./internal/surface/"],
    ),
    (
        "graphql-bypass-not-reported",
        "internal/graphql/graphql.go",
        "\t\tif !o.RESTReadable[name] {\n\t\t\tbypass = append(bypass, name)\n\t\t}",
        "\t\tif false {\n\t\t\tbypass = append(bypass, name)\n\t\t}",
        "a relation serving rows over GraphQL that REST refused stops being reported, "
        "which is the only reason this check exists",
        ["./internal/graphql/"],
    ),
    (
        "graphql-control-ignored",
        "internal/graphql/graphql.go",
        "\tres.Discriminating = ctrlState.state == Absent",
        "\tres.Discriminating = ctrlState.state == Absent || true",
        "an endpoint that answers every relation name is believed, so every candidate "
        "looks like a real relation",
        ["./internal/graphql/"],
    ),
    (
        "graphql-filtered-read-as-readable",
        "internal/graphql/graphql.go",
        "\tif len(conn.Edges) == 0 {\n\t\t// The relation exists and this role saw none of it.\n\t\treturn queryResult{state: Filtered}, nil\n\t}",
        "\tif len(conn.Edges) == 0 {\n\t\treturn queryResult{state: Readable}, nil\n\t}",
        "an empty edge list -- RLS working correctly -- is read as exposure, putting a "
        "finding on every protected relation",
        ["./internal/graphql/"],
    ),
    (
        "privilege-denied-relation-dropped",
        "internal/enumerate/oracle.go",
        "\t\tif p.privilegeDenied {",
        "\t\tif false {",
        "a relation Postgres refused with 42501 is discarded, so a schema protected with "
        "REVOKE rather than RLS reports as empty",
        ["./internal/enumerate/"],
    ),
    (
        "bare-401-counted-as-a-relation",
        "internal/enumerate/oracle.go",
        "\t\t\tif code, _, _ := resp.DecodeError(); code == \"42501\" {\n\t\t\t\tout.privilegeDenied = true\n\t\t\t}",
        "\t\t\tout.privilegeDenied = true",
        "any 401 counts as proof a relation exists, which with a wrong key once reported "
        "2684 relations against a database with 21",
        ["./internal/enumerate/"],
    ),
    (
        "extra-schemas-not-reported",
        "internal/schemas/schemas.go",
        "\tif len(res.Extra) > 0 {\n\t\tres.Findings = append(res.Findings, extraSchemaFinding(c, res.Exposed, res.Extra, resp.Status))\n\t}",
        "\tif false {\n\t\tres.Findings = append(res.Findings, extraSchemaFinding(c, res.Exposed, res.Extra, resp.Status))\n\t}",
        "a project exposing a schema beyond the defaults is not reported, so an entire "
        "surface stays invisible",
        ["./internal/schemas/"],
    ),
    (
        "per-schema-routines-skipped",
        "backend/supabase/schemas_stage.go",
        "\t\tsrt := surface.Routines(ctx, sc, surface.Options{\n\t\t\tRoutineSeeds:   vocab.RoutineSeeds,\n\t\t\tRoutineGuesses: vocab.Composed,\n\t\t\tConcurrency:    s.Concurrency,\n\t\t\tMaxCandidates:  before,\n\t\t\tAllowInvoke:    s.Invoke,\n\t\t\tRedact:         s.Redact,\n\t\t\tSchema:         schema,\n\t\t})\n",
        "\t\tsrt := surface.Result{}\n\t\t_ = sc\n\t\t_ = vocab\n",
        "routine discovery in a non-default schema is disabled, hiding a SECURITY DEFINER "
        "routine that returns data the direct read refuses",
        ["./internal/eval/"],
    ),
    (
        "escalation-skips-other-schemas",
        # Moved with the code: the elevated pass now lives in
        # backend/supabase.EscalationStage. --check caught this the moment the
        # port landed, which is the whole reason it exists -- a mutation whose
        # pattern no longer matches applies to nothing and is reported as
        # caught, which is the false assurance this project argues against.
        "backend/supabase/escalation_stage.go",
        "\tfor _, ss := range schemas.Scans {",
        # `_ = schemas` since the artifact read is the only other use.
        "\t_ = schemas\n\tfor _, ss := range []SchemaScan(nil) {",
        "the elevated pass covers only the default schema, so a relation granted to "
        "authenticated in a reporting schema reads as protected",
        ["./internal/eval/", "./backend/supabase/"],
    ),
    (
        "realtime-only-default-schema",
        "internal/realtime/realtime.go",
        "\tif o.Schema == \"\" {\n\t\treturn \"public\"\n\t}\n\treturn o.Schema",
        "\treturn \"public\"",
        "Realtime subscribes to the default schema whatever it was asked for, so a table "
        "in another exposed schema streams every change to anonymous listeners unseen",
        ["./internal/realtime/"],
    ),
    (
        "remediation-not-schema-qualified",
        "internal/probe/probe.go",
        "func (r Relation) Qualified() string {\n\tif r.Schema == \"\" {\n\t\treturn r.Name\n\t}\n\treturn r.Schema + \".\" + r.Name\n}",
        "func (r Relation) Qualified() string {\n\treturn r.Name\n}",
        "remediation SQL loses the schema, so ALTER TABLE resolves against search_path and "
        "either errors or alters a different table while the exposure stays open",
        ["./internal/probe/"],
    ),
    (
        "token-rule-narrowed-again",
        "internal/classify/classify.go",
        "\t{regexp.MustCompile(`(?i)(^|_)token$`), \"credential\"},",
        "\t{regexp.MustCompile(`(?i)(access|refresh|api|auth|bearer|session|csrf)[_-]?token`), \"credential\"},",
        "the token rule goes back to a fixed prefix list, missing every token Supabase's "
        "own auth schema uses, so a table of reset credentials reports high not critical",
        ["./internal/probe/", "./internal/classify/"],
    ),
    (
        "token-rule-widened-to-counts",
        "internal/classify/classify.go",
        "\t{regexp.MustCompile(`(?i)(^|_)token$`), \"credential\"},",
        "\t{regexp.MustCompile(`(?i)token`), \"credential\"},",
        "the token rule matches any column containing 'token', so max_tokens and "
        "token_count make every LLM usage table a critical",
        ["./internal/probe/", "./internal/classify/"],
    ),
    (
        "explicit-site-discarded",
        "cmd/unruly/main.go",
        "\t\t\tif !explicitSite {",
        "\t\t\tif explicitSite || true {",
        "an explicit -site is thrown away when -target is given, so the application is "
        "never fetched and a service_role key served to browsers goes unreported",
        ["./internal/eval/"],
    ),
    (
        "route-family-threshold-loosened",
        "internal/routes/routes.go",
        "\treturn len(f.Protected) >= 2 && len(f.Open) >= 1",
        "\treturn len(f.Open) >= 1",
        "any open route is reported as an inconsistency, so an entirely public API "
        "family becomes a page of high findings",
        ["./internal/routes/"],
    ),
    (
        "route-family-never-inconsistent",
        "internal/routes/routes.go",
        "\treturn len(f.Protected) >= 2 && len(f.Open) >= 1",
        "\treturn false",
        "a route answering anonymously beside siblings that demand credentials is never "
        "reported, which is the whole check",
        ["./internal/routes/"],
    ),
    (
        "object-residue-only-when-not-writable",
        "internal/surface/surface.go",
        "\t\t\t\tif residue != \"\" {\n\t\t\t\t\tres.Findings = append(res.Findings, residueFinding(c, b.Name, residue))",
        "\t\t\t\tif residue != \"\" && !writable {\n\t\t\t\t\tres.Findings = append(res.Findings, residueFinding(c, b.Name, residue))",
        "the object-residue finding fires only when the bucket is NOT writable, which is "
        "the opposite of the common case: a bucket granting INSERT and refusing DELETE "
        "keeps the object and the canonical id never appears",
        ["./internal/surface/"],
    ),
    (
        "unresolved-probes-not-counted",
        "internal/enumerate/oracle.go",
        "\t\t\tres.Unresolved++",
        "\t\t\t_ = p",
        "a probe that got no readable answer -- a 429 that survived retries, a 5xx, a "
        "dropped connection -- is silently treated as measured-and-absent, so a "
        "rate-limited scan reports a partial relation list as if it were complete",
        ["./internal/enumerate/"],
    ),
    (
        "preview-key-severity-collapsed",
        "internal/preview/preview.go",
        "\tsame := current != \"\" && d.AnonKey == current",
        "\tsame := true\n\t_ = current",
        "every preview credential is rated as merely another copy of the production key, "
        "so a branch build serving a DIFFERENT live key -- the one a production rotation "
        "would not touch -- is reported as low",
        ["./internal/preview/"],
    ),
    (
        "historic-service-key-downgraded",
        "internal/history/history.go",
        "\tcase s.Role == \"service_role\" || strings.HasPrefix(s.KeyPrefix, \"sb_secret_\"):\n\t\tsev, id = finding.Critical, \"supabase-historic-service-key-exposed\"",
        "\tcase s.Role == \"service_role\" || strings.HasPrefix(s.KeyPrefix, \"sb_secret_\"):\n\t\tsev, id = finding.Info, \"supabase-historic-service-key-exposed\"",
        "a service_role key preserved in a public archive is reported at info; it bypasses "
        "row-level security entirely and cannot be un-published",
        ["./internal/history/"],
    ),
    (
        "historic-key-rotation-not-checked",
        "internal/history/history.go",
        "\tcase s.StillCurrent:",
        "\tcase false:",
        "an archived key that is byte-identical to the one in use is filed as rotated, so "
        "an unremediated exposure reads as history",
        ["./internal/history/"],
    ),
    (
        "credential-bearing-client-follows-redirects",
        "internal/client/client.go",
        "\t\t\tCheckRedirect: func(*http.Request, []*http.Request) error {\n\t\t\t\treturn http.ErrUseLastResponse\n\t\t\t},",
        "",
        "the scanner follows redirects again, so a host that answers 302 harvests the "
        "project apikey -- Go strips Authorization across domains but never a custom header",
        ["./internal/client/"],
    ),
    (
        "hostile-relation-name-accepted",
        "internal/postgrest/classify.go",
        "\tif !safeIdentifier.MatchString(name) || len(name) > maxIdentifierBytes {\n\t\treturn \"\", false\n\t}\n\treturn name, true\n}\n\n// HintedFunction",
        "\tif name == \"\" {\n\t\treturn \"\", false\n\t}\n\treturn name, true\n}\n\n// HintedFunction",
        "a relation name from a hostile host is accepted verbatim, so it reaches the -fix "
        "SQL an operator pastes into their database: 'users; DROP TABLE audit_log; --'",
        ["./internal/postgrest/"],
    ),
    (
        "terminal-escapes-not-stripped",
        "internal/finding/finding.go",
        "\tlocator := safeText(f.Matched)",
        "\tlocator := f.Matched",
        "target-controlled text reaches the terminal unfiltered, so a scanned host can "
        "clear the screen and print its own 'scan complete: 0 findings'",
        ["./internal/finding/"],
    ),
    (
        "enumeration-rounds-unbounded",
        "internal/enumerate/oracle.go",
        "\tfor round := 0; round < o.MaxRounds && len(frontier) > 0; round++ {",
        "\tfor round := 0; len(frontier) > 0; round++ {",
        "the hint BFS runs until the frontier empties, so a host that volunteers a new "
        "name in every hint decides how much work the scan does -- the queue belongs to "
        "the target",
        ["./internal/enumerate/"],
    ),
    (
        "critical-routine-fix-unqualified",
        "internal/surface/surface.go",
        "REVOKE EXECUTE ON FUNCTION %[2]s.%[1]s FROM PUBLIC, anon, authenticated;",
        "REVOKE EXECUTE ON FUNCTION public.%[1]s FROM PUBLIC, anon, authenticated;",
        "the CRITICAL routine finding emits SQL naming the wrong schema, so the fix an "
        "operator pastes errors instead of revoking anything",
        ["./internal/surface/"],
    ),
    (
        "write-evidence-loses-content-type",
        "internal/probe/probe.go",
        "\t\t\t\t\"-H 'Content-Type: application/json'%s -d '{}'\",",
        "\t\t\t\t\"%s -d '{}'\",",
        "the write finding's own reproduction command omits Content-Type, so curl sends "
        "form-encoded and PostgREST answers PGRST204: the proof denies the finding",
        ["./internal/probe/"],
    ),
    (
        "snippet-republishes-credentials",
        "internal/surface/surface.go",
        "\treturn maskCredentials(snippet)",
        "\treturn snippet",
        "an Edge Function's response body is quoted verbatim, so a function holding the "
        "service_role key puts it in a report people paste into tickets",
        ["./internal/surface/"],
    ),
    (
        "readme-count-drifts",
        "README.md",
        "Five negative",
        "Six negative",
        "a number the README states about this repository stops matching the repository; "
        "this document has drifted seven times and prose cannot be pinned, but counts can",
        ["./internal/eval/"],
    ),
    (
        "probe-issues-an-extra-request",
        "internal/probe/probe.go",
        "\tresp := c.Get(ctx, url, map[string]string{\"Prefer\": \"count=exact\"})\n\trel.requests++",
        "\tresp := c.Get(ctx, url, map[string]string{\"Prefer\": \"count=exact\"})\n\t_ = c.Get(ctx, url, nil)\n\trel.requests++",
        "read probing sends two requests per relation instead of one, which is invisible "
        "on a ten-table fixture and doubles the traffic on a real project",
        ["./internal/probe/"],
    ),
    # --- the rebuilt tree -------------------------------------------------
    #
    # backend/ and scan/ carry decisions now, and nothing here was breaking
    # them. Coverage says those lines RUN; only a mutation says a test would
    # object if they were wrong. The first two below break exactly the two
    # claims this project got wrong about PocketBase and had to retract, so if
    # they survive, the guards written after those retractions are decoration.
    (
        "pocketbase-status-counts-as-exposure",
        "backend/pocketbase/probe.go",
        "\tr.Exposed = len(body.Items) > 0",
        "\tr.Exposed = true",
        "a 200 counts as a read exposure whether or not rows came back, so the DEFAULT "
        "users collection -- which carries the expression rule id = @request.auth.id and "
        "filters every row away while still answering 200 -- is reported as leaking on "
        "every PocketBase install in the world",
        ["./backend/pocketbase/"],
    ),
    (
        "pocketbase-404-counts-as-denial",
        "backend/pocketbase/probe.go",
        "\tv.Denied = resp.Status == http.StatusForbidden",
        "\tv.Denied = resp.Status == http.StatusNotFound",
        "denial is read from the wrong status, inverting the only conclusion this probe "
        "is entitled to draw: an OPEN rule is called denied and a superuser-only one is "
        "not, so a locked collection reads as reachable and an exposed one reads as safe",
        ["./backend/pocketbase/"],
    ),
    (
        "neon-any-200-is-an-escalation",
        "backend/neon/escalation.go",
        "\t\tif len(authed.rows) == 0 {",
        "\t\tif authed.status != 200 {",
        "escalation is read from the status instead of from rows actually returned, so a "
        "table whose RLS denies every row -- answering 200 with an empty array -- is "
        "reported as handing its contents to any account. That is the vendor console's "
        "own mistake: reasoning about a table without checking what came back",
        ["./backend/neon/"],
    ),
    (
        "neon-400-means-absent",
        "backend/neon/reach.go",
        "\tif controlStatus == http.StatusNotFound {",
        "\tif controlStatus == http.StatusBadRequest {",
        "the refusal a Neon endpoint gives an unauthenticated caller is read as proof the "
        "control relation is absent, so a surface that answers every name identically is "
        "called discriminating and an anonymous scan reports a clean project having "
        "measured nothing",
        ["./backend/neon/"],
    ),
    (
        "neon-blind-outranks-real-findings",
        "backend/neon/reach.go",
        "\t\tSeverity: finding.Info,",
        "\t\tSeverity: finding.High,",
        "an unassessed surface is ranked as though something were known to be wrong with "
        "it, so a scanner-configuration problem sorts above the real findings other "
        "stages produced and buries them",
        ["./backend/neon/"],
    ),
    (
        "a-backend-is-assessed-once-per-sighting",
        "cmd/unruly/discovery.go",
        "\t\tif seen[key] {",
        "\t\tif false {",
        "a backend named BOTH by the target URL and by the application's own bundle -- "
        "the ordinary case -- is assessed once per sighting, so every stage behind the "
        "seam runs twice. Measured against a live lab: 1770 requests where one pass "
        "costs 885, sent to somebody else's server to repeat work already done, with "
        "nothing in the report saying so",
        ["./cmd/unruly/"],
    ),
    (
        "probe-sweeps-a-target-that-answers-everything-alike",
        "internal/probe/probe.go",
        "\tif !res.Discriminating {",
        "\tif false {",
        "the full candidate list is swept even when a name that cannot exist answered "
        "exactly as the real ones did, so a scan spends a request per candidate against "
        "an endpoint whose replies carry no information. The cost is proportional to the "
        "candidate list, which on a target with no enumeration oracle is the whole pinned "
        "wordlist",
        ["./internal/probe/"],
    ),
    (
        "probe-control-404-is-not-taken-as-absence",
        "internal/probe/probe.go",
        "\tif control.Read == postgrest.ReadNotFound {",
        "\tif false {",
        "a clean 404 for a relation that cannot exist stops counting as proof the "
        "endpoint can report absence, so a schema where every candidate is genuinely "
        "missing -- an informative result -- is called blind and nothing is probed",
        ["./internal/probe/"],
    ),
    (
		"neon-seam-grants-write-without-consent",
		"internal/provider/neon.go",
		"\t\tconsent := in.Write && !in.Controls.NoResidue",
		"\t\tconsent := true",
		"the seam grants write consent even when the operator did not, or when "
		"-no-residue forbids a probe that can leave an inserted row behind",
        ["./internal/provider/"],
    ),
    (
        "neon-write-ignores-consent",
        "backend/neon/write.go",
        "\tif !s.Consent {",
        "\tif false {",
        "the write probe is performed whether or not the operator passed -write "
        "-yes-i-own-this, so a plain scan adds a row to every table it can reach. The "
        "consent is checked before the request is BUILT precisely because a probe whose "
        "result is discarded has still changed somebody's data",
        ["./backend/neon/"],
    ),
    (
        "neon-write-any-status-is-acceptance",
        "backend/neon/write.go",
        "\t\t\tcase resp.Status == http.StatusCreated:",
        "\t\t\tcase resp.Status >= 200:",
        "every write attempt is reported as accepted, including the 403/42501 a table "
        "with no INSERT grant returns, so a refusal becomes an exposure -- the same "
        "error as reporting a table whose RLS returned no rows",
        ["./backend/neon/"],
    ),
    (
        "a-failed-stage-is-swallowed",
        "scan/stage.go",
        "\t\t\tst.Add(finding.NotAssessedStage(st.Target, s.Name(), err.Error()))",
        "\t\t\t_ = err",
        "a stage that fails is silently skipped, so a surface that refused the connection "
        "reports as clean rather than unexamined -- the exact false negative the pipeline "
        "exists to prevent, and the only reason it is allowed to continue past an error",
        ["./scan/"],
    ),
    # --- provenance counting and -vocab-only ------------------------------
    # Both landed this session with their own tests. A test says the code was
    # RUN; a mutation says the test would object if it were wrong.
    (
        "contributions-does-not-fold",
        "internal/wordlist/wordlist.go",
        "\t\t\ts = fold(strings.TrimSpace(s))\n\t\t\tif s == \"\" {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tif _, ok := seen[s]; ok {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tseen[s] = struct{}{}\n\t\t\tcounts[i]++",
        "\t\t\ts = strings.TrimSpace(s)\n\t\t\tif s == \"\" {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tif _, ok := seen[s]; ok {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tseen[s] = struct{}{}\n\t\t\tcounts[i]++",
        "provenance counting stops folding while Merge keeps folding, so the summary "
        "describes a different set than the one probed: Users and users are counted as "
        "two candidates and the parts no longer sum to what was probed",
        ["./internal/wordlist/", "./backend/supabase/"],
    ),
    (
        "contributions-counts-duplicates",
        "internal/wordlist/wordlist.go",
        "\t\t\tif _, ok := seen[s]; ok {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tseen[s] = struct{}{}\n\t\t\tcounts[i]++",
        "\t\t\tif _, ok := seen[s]; ok {\n\t\t\t\tcounts[i]++\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tseen[s] = struct{}{}\n\t\t\tcounts[i]++",
        "a name contributed by two sources is counted twice -- exactly the bug the "
        "post-merge attribution replaced, where the summary claimed 5 candidates on a "
        "scan that probed 3",
        ["./internal/wordlist/", "./backend/supabase/"],
    ),
    (
        "vocab-only-still-probes-the-pinned-list",
        "cmd/unruly/vocabsources.go",
		"\t\treturn scan.SeedSet{Supplied: supplied}",
		"\t\treturn scan.SeedSet{Supplied: supplied, Pinned: wordlist.Relations()}",
        "-vocab-only silently keeps the pinned list, so an operator who asked to pay for "
        "four metered guesses is billed for 884 -- the flag's entire promise, broken "
        "invisibly",
        ["./cmd/unruly/"],
    ),
    (
        "vocab-only-accepts-an-empty-vocabulary",
        "cmd/unruly/main.go",
        "\t\tif len(suppliedVocabulary(o)) == 0 {",
        "\t\tif false {",
        "-vocab-only with an unreadable handoff file is accepted, so the scan probes "
        "NOTHING and reports the project clean without ever asking a question",
        ["./cmd/unruly/"],
    ),
    (
        "failed-cleanup-believed",
        "internal/exploit/firebase.go",
        "\treturn status == 200 || status == 204 || status == 404\n}",
        "\treturn true\n}",
        "a probe that created a document and could NOT delete it reports that it removed "
        "it, so the lab quietly keeps the object and every later run grades against a "
        "project this one changed -- the exact shape the scanner reports against other "
        "people's projects as unruly-probe-object-left-behind",
        ["./internal/exploit/"],
    ),
    (
        "lab-drift-reported-as-a-failed-exploit",
        "internal/exploit/firebase.go",
        "\t\to.Unmeasured = true\n\t\to.Detail = fmt.Sprintf(\"retrieved %d documents where the key says %d: the lab \"+",
        "\t\to.Detail = fmt.Sprintf(\"retrieved %d documents where the key says %d: the lab \"+",
        "a Firebase lab that has drifted from its answer key is graded as a documented "
        "exploit that did not work, so a change in the LABORATORY is reported as a "
        "regression in the scanner and someone hunts a defect that is not there",
        ["./internal/exploit/"],
    ),
    (
        "every-public-endpoint-becomes-an-ownership-failure",
        "internal/routes/idor.go",
        "\tif anon.code == 200 && strings.TrimSpace(anon.body) == strings.TrimSpace(a.res.body) {\n\t\treturn finding.Finding{}, false\n\t}",
        "\t_ = anon",
        "the anonymous leg of the three-way comparison is dropped, so every endpoint two "
        "signed-in callers can both read is reported as a broken ownership check -- "
        "including a product catalogue, which serves every id to everyone, correctly. "
        "The finding needs three answers and this removes one of them",
        ["./internal/routes/"],
    ),
    (
        "every-correctly-scoped-endpoint-becomes-an-ownership-failure",
        "internal/routes/idor.go",
        "\tif b.res.code != 200 || strings.TrimSpace(b.res.body) != strings.TrimSpace(a.res.body) {",
        "\tif b.res.code != 200 {",
        "the same-body test is dropped, so an endpoint that returns each caller THEIR OWN "
        "row from one URL is reported as one account reading another's record. That is "
        "the correct design, and a check that flags it flags every correctly built "
        "endpoint in the application -- which is how a check comes to be switched off",
        ["./internal/routes/"],
    ),
    (
        "a-template-is-filled-with-somebody-elses-identifier",
        "internal/routes/params.go",
        "\tif missing {\n\t\treturn \"\", false\n\t}",
        "\t_ = missing",
        "a path template is probed even when the operator supplied no value for one of "
        "its placeholders, so /customers/{customer_id} is filled with whatever was given "
        "for a DIFFERENT parameter. That sends a request for a record belonging to "
        "somebody the operator never mentioned, and reports the answer as coverage. The "
        "distinction between an identifier that was given and one that was invented is "
        "the whole of this check",
        ["./internal/routes/"],
    ),
    (
        "a-guessed-identifier-reads-as-a-demonstration",
        "internal/routes/params.go",
        "\tswitch src {\n\tcase SourceSupplied:",
        "\tswitch SourceSupplied {\n\tcase SourceSupplied:",
        "every probed identifier is described as one the operator supplied, including the "
        "ones this scan derived. A finding on /invoices/42 means \"your own record is "
        "readable\" when 42 was given and \"a record we picked is readable, and we do not "
        "know whose\" when it was guessed. Reporting them identically lets a guess be "
        "read as a demonstration",
        ["./internal/routes/"],
    ),
    (
        "every-site-with-a-homepage-reports-a-bypass",
        "internal/routes/bypass.go",
        "\t\tif ctrl, ok := variants[name+\" (control)\"]; ok {\n\t\t\tif ctrl.code == got.code && strings.TrimSpace(ctrl.body) == body {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t}",
        "\t\t_ = name",
        "a header variant is no longer compared against the identical request WITHOUT the "
        "header. The rewrite variants ask for \"/\" and name the protected path in a "
        "header, and \"/\" returns the homepage on every ordinary site -- so every site "
        "with a homepage reports a bypass on every refused endpoint. Caught by the "
        "testbed's protected-endpoint controls the first time this ran, on all five at "
        "once",
        ["./backend/application/"],
    ),
    (
        "a-catch-all-host-manufactures-bypasses",
        "internal/routes/bypass.go",
        "\tpathVariantsSound := !haveControl || discriminates(control)",
        "\tpathVariantsSound := true\n\t_ = haveControl",
        "path variants are trusted on a host that answers 200 for a path which cannot "
        "exist. A single-page application does exactly that, and one that echoes the "
        "requested path back defeats the body comparison too, so every refused endpoint "
        "collects a bypass finding for every path variant. Reporting one bypass per "
        "endpoint per variant is how an operator learns to ignore the check",
        ["./internal/routes/"],
    ),
    (
        "a-published-api-specification-is-read-and-not-used",
        "internal/routes/routes.go",
		"\t\t\trefs = appendUniqueRef(refs, endpointRef{Base: base, Path: p, Source: sourceSpec})",
		"\t\t\t_ = p",
        "the API's own published specification is fetched and its operations never reach "
        "the probe list, so the document is read and not used. Its whole value is naming "
        "endpoints the front end does not call: on a real target it named CRM, "
        "candidate, invoice, document, credential, financial, user and internal-log "
        "endpoints, most of which no bundle on the entry page referenced",
        ["./backend/application/"],
    ),
    (
        "a-specification-is-parsed-from-a-300-byte-snippet",
        "internal/routes/spec_findings.go",
        "\t\tcode, body, _ := rr.probeFull(ctx, base+p)\n\t\tif code != 200 || !looksLikeSpec(body) {",
		"\t\tcode, body, _, _ := rr.probe(ctx, \"GET\", base+p)\n\t\tif code != 200 || !looksLikeSpec(body) {",
        "specification discovery reads probe()'s 300-byte evidence snippet instead of the "
        "document, so JSON never parses and no specification is ever recognised. Silent: "
        "the request is made, the 200 comes back, and the scan concludes the API "
        "publishes nothing. A real one was 291 KB",
        ["./internal/routes/", "./backend/application/"],
    ),
    (
        "an-endpoint-alone-in-its-family-can-leak-silently",
        "internal/routes/routes.go",
        "\t\tif f, ok := standaloneExposure(r, o.Redact); ok {\n\t\t\tres.Findings = append(res.Findings, f)\n\t\t}",
        "\t\t_ = r",
        "an endpoint is reported only when its SIBLINGS disagree about authorisation, so "
        "a lone route serving a live record to anyone produces nothing. Inconsistency is "
        "a proxy for a missing auth check and it assumes an open endpoint is fine if its "
        "siblings are open too -- meaning an API where EVERYTHING is open scores "
        "perfectly consistent and the worst case is the blind spot. Measured on a real "
        "target: one endpoint returned a database-backed record with an employee address "
        "to anyone, alone in its family, discovered and probed and silent",
        ["./internal/routes/", "./backend/application/"],
    ),
    (
        "an-endpoint-that-refuses-is-reported-as-one-that-leaks",
        "internal/routes/exposed.go",
        "\tif r.GET != 200 || strings.TrimSpace(r.Snippet) == \"\" {",
        "\tif r.GET == 0 || strings.TrimSpace(r.Snippet) == \"\" {",
        "the status is no longer checked, so an endpoint answering 401 with a refusal "
        "message that happens to contain an address is reported as an exposure. A scan "
        "that flags correctly protected endpoints is worse than one that misses the real "
        "finding: it sends somebody to fix things that are already right and discredits "
        "the finding that is not",
        ["./internal/routes/"],
    ),
    (
        "a-hosting-platform-is-mistaken-for-an-api-vendor",
        "internal/routes/origins.go",
        "\t\"launchdarkly.com\", \"posthog.com\", \"openai.com\", \"anthropic.com\",",
        "\t\"launchdarkly.com\", \"posthog.com\", \"openai.com\", \"anthropic.com\", \"run.app\", \"fly.dev\",",
        "hosting platforms are added to the vendor denylist, so a customer's own backend "
        "on Cloud Run or Fly is skipped as though it belonged to somebody else. That "
        "restores the exact false negative this work exists to close -- a real "
        "application's entire endpoint inventory lived on run.app -- while LOOKING like "
        "caution, which is the worst kind of wrong: it reads as a deliberate safety "
        "decision and is a blind spot",
        ["./internal/routes/"],
    ),
    (
        "the-applications-backend-is-never-probed",
        "internal/routes/routes.go",
        "\t\tif or.Probed {\n\t\t\tbases = append(bases, or.URL)\n\t\t}",
        "\t\t_ = or",
        "endpoints are probed only against the page origin, never against the backend "
        "the application's own bundle declares. Measured on a real target: every "
        "endpoint lived on a separate API host, so the scan asked the wrong server for "
        "all of them and reported zero application routes",
        ["./internal/routes/", "./backend/application/"],
    ),
    (
        "endpoints-outside-six-prefixes-are-invisible",
        "internal/routes/endpoints.go",
        "var reAnyPath = regexp.MustCompile(`[\"\'\\x60](/[a-zA-Z0-9_\\-/\\[\\]{}.:]{1,120})[\"\'\\x60]`)",
        "var reAnyPath = regexp.MustCompile(`[\"\'\\x60](/(?:api|rest|graphql|internal|admin|_api)/[a-zA-Z0-9_\\-/\\[\\]{}.]{1,120})[\"\'\\x60]`)",
        "route discovery accepts only six URL prefixes, so an endpoint outside them is "
        "never seen. Measured on a real target: /system/mode returned a live "
        "database-backed record to anonymous callers, containing an employee address, "
        "and scored zero matches. A prefix allowlist is a guess about another team's URL "
        "design and this one was wrong in the case that mattered",
        ["./internal/routes/"],
    ),
    (
        "a-third-party-cdn-is-probed-as-the-applications-api",
        "internal/routes/endpoints.go",
        "\tfor _, m := range reScriptImport.FindAllStringSubmatch(body, -1) {\n\t\tskip[m[1]] = true\n\t}",
        "\t_ = reScriptImport",
        "every origin a bundle mentions is treated as the application's API, so a CDN "
        "serving a copy of React is probed as though it were the customer's backend. "
        "That sends traffic to a host the operator never nominated and tells them "
        "nothing about their own application -- the distinction between where code came "
        "FROM and where the application sends its users' DATA",
        ["./internal/routes/"],
    ),
    (
        "an-ambient-key-selects-the-supabase-pipeline-for-any-site",
        "cmd/unruly/select.go",
        "\tcase o.apiLocated:",
        "\tcase o.apiLocated || o.anonKey != \"\":",
        "a SUPABASE_ANON_KEY exported for one project selects the whole PostgREST "
        "pipeline for whatever is scanned next. Measured against a plain website: 2,725 "
        "requests -- 1,200 relation probes and a routine sweep -- at a host with no "
        "database, concluding that enumeration 'cannot be distinguished from a target "
        "with nothing to find'. The traffic is real, the conclusion is noise, and the "
        "cause is an environment variable somebody forgot was set",
        ["./cmd/unruly/"],
    ),
    (
        "bundles-outside-four-directories-are-never-read",
        "internal/routes/routes.go",
        "\treAsset := regexp.MustCompile(`[\"\'](/[^\"\'\\s]*\\.m?js)(?:\\?[^\"\']*)?[\"\']`)",
        "\treAsset := regexp.MustCompile(`[\"\']((?:/_next/static|/assets|/static|/js)/[^\"\']+\\.js)[\"\']`)",
        "route discovery reads only scripts under four hard-coded directories, so an "
        "application serving its bundle anywhere else -- Vite's /index-<hash>.js at the "
        "root, Create React App's /build/, a plain /app.js -- has EVERY route it names "
        "missed. The failure is silent and reads exactly like an application with no "
        "API. Measured: 0 routes probed against a fixture serving three",
        ["./internal/routes/"],
    ),
    (
        "an-untested-access-expectation-counts-as-satisfied",
        "internal/intent/intent.go",
        "\t\tif !ok {\n\t\t\tout = append(out, Outcome{Expectation: e, State: Unverified,",
        "\t\tif !ok {\n\t\t\tout = append(out, Outcome{Expectation: e, State: Matched,",
        "an access expectation the scan never tested is reported as satisfied, so a "
        "manifest full of intentions produces a clean verdict from a scan that measured "
        "none of them. This is the tool's own central claim applied to its newest "
        "feature: not looking is not the same as looking and finding nothing",
        ["./internal/intent/"],
    ),
    (
        "the-plan-level-consent-check-stops-seeing-mutation",
        "scan/plan.go",
        "\t\tif desc.MutatesTarget && !c.Write {\n\t\t\twrites = append(writes, desc.ID)\n\t\t}",
        "\t\t_ = desc.MutatesTarget",
        "the plan-level consent check no longer notices a stage that writes, so the only "
        "guard left is the per-stage one it was added to back up -- and the case it "
        "exists for is exactly the stage that forgets to ask. An irreversible action "
        "against somebody else's project deserves two independent guards, and this is "
        "the one that costs the target nothing because it runs first",
        ["./scan/"],
    ),
    (
        "a-stage-declares-its-type-rather-than-its-configuration",
        "backend/supabase/descriptors.go",
        "\t\tMutatesTarget: s.Write}",
        "\t\tMutatesTarget: true}",
        "the schemas stage declares itself a mutator whether or not writes are enabled, "
        "so every read-only scan is refused for exceeding a permission it never needed. "
        "That is how a safety check comes to be switched off: not by argument, but by "
        "being wrong often enough to be in the way",
        ["./backend/supabase/"],
    ),
    (
        "a-deliberate-skip-is-reported-as-a-blind-scan",
        "scan/stage.go",
        "\t\t\tif nr, ok := err.(notRun); ok {\n\t\t\t\tst.Add(finding.SkippedStage(st.Target, s.Name(), nr.reason))\n\t\t\t\tcontinue\n\t\t\t}",
        "\t\t\t_ = notRun{}",
        "a stage the OPERATOR turned off is reported as a surface that could not be "
        "assessed, which drives exit 3 and tells the reader to re-run once the cause is "
        "resolved -- the cause being their own flag. The coverage set already states the "
        "rule in its own comment: a skip that fires on almost every scan makes the "
        "incomplete-coverage signal mean nothing",
        ["./scan/"],
    ),
    (
        "a-minted-credential-never-reaches-the-escalation-pass",
        "backend/supabase/escalation_stage.go",
        "\t\tif c, ok := scan.Get[Credential](st); ok {\n\t\t\tkey = c.Token\n\t\t}",
        "\t\t_ = st",
        "an account the scan MINTED mid-run never reaches the escalation pass, which then "
        "declines for want of a credential the scan is holding. That silently removes the "
        "middle tier of the threat model -- what anybody who registers can reach -- from "
        "every scan that mints its own account, which is every -write scan without "
        "-user-jwt. The corpus cannot catch it: every benchmark run supplies a token",
        ["./backend/supabase/"],
    ),
    (
        "an-unproven-realtime-probe-reads-as-a-quiet-surface",
        "backend/supabase/realtime_stage.go",
        "\tcase len(d.DeliveryTested) > 0:",
        "\tcase false && len(d.DeliveryTested) > 0:",
        "a realtime pass that CAUSED a change and received no payload falls through to "
        "\"N of M relations stream to anon\", reporting an unproven probe as a measured "
        "quiet surface. With no delivery anywhere the instrument itself is unverified, "
        "which is inconclusive rather than clean -- the distinction this whole tool "
        "exists to hold",
        ["./backend/supabase/"],
    ),
    (
        "an-untrustworthy-relation-list-is-reported-as-a-clean-one",
        "backend/supabase/enumerate_stage.go",
        "\tif !res.Discriminating {",
        "\tif false && !res.Discriminating {",
        "the control probe failed -- the target cannot tell an absent relation from a "
        "present one -- and the scan says nothing. Read and write classification both "
        "start from the discovered set, so NOTHING downstream can be trusted, and an "
        "empty relation list reads as a clean project. This is the exact lie the tool "
        "exists to refuse",
        ["./backend/supabase/"],
    ),
    (
        "graphql-reports-every-readable-relation-as-an-rls-bypass",
        "backend/supabase/graphql_stage.go",
        "\tfor _, name := range pr.ReadExposed() {\n\t\trestReadable[name] = true\n\t}",
        "\t_ = pr",
        "RESTReadable is left empty, so every relation GraphQL can read is reported as an "
        "RLS BYPASS -- the most serious thing this check finds -- including the ones REST "
        "already read perfectly openly. A false positive on every readable relation. "
        "Nothing caught this until 2026-08-23: the stage's parity fixture serves no "
        "GraphQL at all, so deleting the derivation changed no test result",
        ["./backend/supabase/"],
    ),
    (
        "the-request-total-counts-every-earlier-stage-again",
        "internal/engine/engine.go",
        "\t\tout.Requests += st.Attributed()",
        "\t\tout.Requests += st.Attributed() * 2",
        "the request total counts each workload's attributed traffic twice. This "
        "project's own words are that a scan is not free for the person being scanned, "
        "so a total that overstates it by an order of magnitude is a claim about "
        "somebody else's server that happens to be wrong",
        ["./internal/engine/"],
    ),
    (
        "a-stage-that-never-ran-reads-as-a-stage-that-found-nothing",
        "scan/artifact.go",
        "\tv, ok := st.artifacts[typ]\n\tif !ok {\n\t\treturn zero, false\n\t}",
        "\tv, ok := st.artifacts[typ]\n\tif !ok {\n\t\treturn zero, true\n\t}",
        "Get reports every artifact as present, so a stage that was skipped is "
        "indistinguishable from one that ran and found nothing -- the distinction this "
        "whole tool is built on, in the one place stages hand each other results. The "
        "fresh-State case does NOT exercise this: a nil map short-circuits earlier, "
        "which is why the first version of the test passed against this mutation",
        ["./scan/"],
    ),
    (
        "classification-is-graded-on-projects-that-claim-nothing",
        "internal/eval/score.go",
        "\tif t.ClaimsClasses() && o.Classes != nil {",
        "\tif true || (t.ClaimsClasses() && o.Classes != nil) {",
        "every corpus project is scored on data classification, including the fifteen "
        "that make no claim about it -- so every correct class those scans report "
        "becomes a false positive against an empty expectation, and the corpus-wide "
        "precision for the one dimension that grades the classifier collapses for a "
        "reason that has nothing to do with the classifier. Absent is not zero",
        ["./internal/eval/"],
    ),
    (
        "an-empty-class-list-stops-meaning-report-nothing",
        "internal/eval/spec.go",
        "\t\tif r.Classes != nil {",
        "\t\tif len(r.Classes) > 0 {",
        "a relation whose answer key says `classes: []` -- the lookalike tables, whose "
        "columns end in address and token and name and hold none of those things -- "
        "stops being graded at all, so a scanner that labels ip_address as personal "
        "data is no longer marked down for it. That half of the project is the only "
        "thing stopping \"comprehensive\" from being satisfied by labelling everything",
        ["./internal/eval/"],
    ),
    (
        "machine-addresses-classified-as-personal-data",
        "internal/classify/classify.go",
        '\t\tif notPersonal.MatchString(leaf) &&',
        '\t\tif false && notPersonal.MatchString(leaf) &&',
        "ip_address, mac_address, wallet_address and contract_address are reported as "
        "personal data. A false class in the column an operator reads to decide what to "
        "worry about first is how a severity column stops being trusted, and precision "
        "is the whole design of this classifier",
        ["./internal/classify/"],
    ),
    (
        "a-bare-name-column-is-personal-data",
        "internal/classify/classify.go",
        "(first|last|full|sur|given|family|middle|maiden)[_-]?name$",
        "(first|last|full|sur|given|family|middle|maiden)?[_-]?name$",
        "the qualified-name anchor goes, so every column called name, file_name, "
        "display_name, table_name or branch_name is reported as personal data. That is "
        "very nearly every schema in existence, and a classifier that fires everywhere "
        "says nothing",
        ["./internal/classify/"],
    ),
    (
        "value-classes-dropped-when-a-column-name-matched",
        "internal/probe/probe.go",
        "\t\tseen[k] = true",
        "\t\t_ = k",
        "everything the VALUE classifier found is discarded whenever any column "
        "NAME also matched, so a table with an `email` column and a service_role key "
        "in a `notes` column reports pii and stays silent about the credential. The "
        "value classifier is the only one of the two that works on a schema not "
        "written in English, which is the case this project promises to handle",
        ["./internal/probe/"],
    ),
    (
        "an-unmeasured-row-count-reads-as-zero",
        "internal/finding/table.go",
        '\t\treturn "?"',
        '\t\treturn "0"',
        "a relation whose row count the server never reported is printed as holding 0 "
        "rows, which states a measurement nobody made and reads as the reassuring "
        "answer. Evidence.Rows is 0 both for \"no rows\" and for \"no count came "
        "back\", and collapsing the two is the exact defect this project is built to "
        "avoid, in a column an operator scans first",
        ["./internal/finding/"],
    ),
    (
        "explicit-scheme-is-second-guessed",
        "cmd/unruly/scheme.go",
        '\tif trimmed == "" || hasScheme.MatchString(trimmed) {',
        '\tif trimmed == "" {',
        "a scheme the operator WROTE stops being respected, so http://127.0.0.1:54401 "
        "becomes https://http://127.0.0.1:54401 -- an empty host that can never be "
        "fetched. benchmark/README.md criticises another scanner in print for exactly "
        "this, and names it as the reason that tool cannot address a self-hosted or "
        "proxied deployment at all. It would also send a request the operator did not "
        "ask for, to a protocol they did not name",
        ["./cmd/unruly/"],
    ),
    (
        "cleartext-is-tried-before-tls",
        "cmd/unruly/scheme.go",
        "\treturn []string{https, http}",
        "\treturn []string{http, https}",
        "a bare domain is tried over cleartext FIRST, so a public host that answers on "
        "both -- which is most of them, port 80 usually redirecting -- is scanned over "
        "HTTP, and the anon key travels unencrypted for the whole scan because plaintext "
        "happened to be first in a list rather than because TLS failed",
        ["./cmd/unruly/"],
    ),
    (
        "the-sql-probe-sends-ddl",
        "internal/surface/sqlexec.go",
        'const sqlProbeStatement = "SELECT 6*7 AS unruly_probe"',
        'const sqlProbeStatement = "DROP TABLE IF EXISTS unruly_probe"',
        "the statement this scanner hands to routines that run arbitrary SQL as the "
        "database owner stops being a read. \"Never send DDL\" is a standing constraint "
        "and docs/exploitability.md states it outright; the whole of that guarantee is "
        "this constant, and the read-only transaction PostgREST wraps a GET in is "
        "somebody else's server behaving well, not this tool behaving safely",
        ["./internal/surface/"],
    ),
    (
        "write-runs-without-the-ownership-confirmation",
        "cmd/unruly/main.go",
        "\tif o.write && !o.confirmOwn {",
        "\tif o.write && !o.confirmOwn && false {",
        "-write no longer requires -yes-i-own-this, so a single flag issues INSERT "
        "requests against somebody's project. probe.Options carries `Write: o.write` with "
        "no consent term of its own and is safe only because this refusal runs first, so "
        "removing it is the whole consent model gone",
        ["./cmd/unruly/"],
    ),
    (
        "no-site-silently-skips-route-consistency",
        "cmd/unruly/skipped.go",
        "\tif o.site == \"\" {\n\t\tskipped = append(skipped, finding.SkippedCheck{\n\t\t\tName: \"application-routes\", Enable: \"-site <url>\",",
        "\tif false {\n\t\tskipped = append(skipped, finding.SkippedCheck{\n\t\t\tName: \"application-routes\", Enable: \"-site <url>\",",
        "a scan given no -site stops disclosing that route authorisation consistency was "
        "never examined, so a report with no route findings reads as a surface that came "
        "back clean rather than one nobody looked at",
        ["./cmd/unruly/"],
    ),
    (
        "subdomain-enumeration-skipped-in-silence",
        "cmd/unruly/skipped.go",
        "\tif !o.subdomains || o.site == \"\" {",
        "\tif false {",
        "sibling hostnames under the application's domain stop being disclosed as "
        "unenumerated, so a staging or admin host serving the same project looks like "
        "something the scan looked for and did not find",
        ["./cmd/unruly/"],
    ),
    (
        "ambient-key-wins-on-self-hosted",
        "cmd/unruly/vocabsources.go",
        "\tcase fromEnv && discovered != \"\" && discovered != current:",
        "\tcase fromEnv && discovered != \"\" && discovered != current && currentRef != \"\" && discoveredRef != \"\":",
        "the exact bug this function was extracted to pin: preferring the target's own key "
        "again requires BOTH project references, which quietly means managed projects only. "
        "A self-hosted deployment has no reference, so an exported SUPABASE_ANON_KEY for an "
        "unrelated project is kept, every request is answered 401, and the scan reports 0 "
        "relations on a target where the discovered key finds 21 -- a report that looks clean",
        ["./cmd/unruly/"],
    ),
    (
        "withheld-key-discards-the-discovered-one",
        "cmd/unruly/credential.go",
        "\t\tKey:         discovered,",
        "\t\tKey:         \"\",",
        "withholding a foreign key throws away the credential discovery already "
        "recovered from THIS target, so a scan that could read the project reports "
        "'backend not assessed' instead -- silence presented as a result, on a target "
        "whose own key was in hand",
        ["./cmd/unruly/"],
    ),
    # The report's account of its own blindness had NO mutation coverage: the
    # only disclosure mutation targeted the terminal stats line, not the
    # SkippedCheck block that reaches the stored artifact. These break it in
    # both directions, because either lie is a lie.
    (
        "withheld-key-not-disclosed",
        "cmd/unruly/skipped.go",
        "\tif o.keyWithheldRef != \"\" {",
        "\tif false {",
        "the report stops saying that a supplied -key was withheld, so a reader of a thin "
        "result has no way to know the credential they passed was deliberately not sent -- "
        "the decision goes back to existing only as a log line, which is what this "
        "disclosure was added to fix",
        ["./cmd/unruly/"],
    ),
    (
        "routine-callability-always-reported-skipped",
        "cmd/unruly/skipped.go",
        "\tif !o.invoke {",
        "\tif true {",
        "a check that DID run is reported as skipped, so the report understates its own "
        "coverage. The opposite of the usual failure and easy to wave through, but a "
        "disclosure that fires unconditionally tells the reader nothing, and a reader who "
        "learns to skip one line skips the ones that matter",
        ["./cmd/unruly/"],
    ),
    (
        "retry-cost-folded-into-the-first-pass",
        "backend/supabase/enumerate_stage.go",
        "\t\tst.Attribute(\"relations-retry\", retry.Requests)",
        "\t\tst.Attribute(\"relations\", retry.Requests)",
        "the near-miss retry stops being attributed separately, so the spend breakdown "
        "cannot distinguish one enumeration sweep from two -- and the retry only runs "
        "when the first pass found nothing, which is exactly when an operator looking at "
        "a large relations figure needs to know it was spent twice",
        ["./backend/supabase/"],
    ),
    (
        "pocketbase-hook-limit-filed-under-the-wrong-capability",
        "internal/provider/pocketbase.go",
        "\t\tCapExecute: \"JS hooks are not examined.",
        "\t\tCapRead: \"JS hooks are not examined.",
        "the one limit saying every rule in the report can be correct while a hook hands "
        "the same data to anyone is filed under anonymous reads, so a reader asking what was "
        "established about CALLABLE CODE is told nothing. Misfiled rather than deleted, "
        "because deletion is the mutation anyone would expect and misfiling is what "
        "actually happens: the text is still there and the diff still reads well",
        ["./internal/provider/"],
    ),
    (
        "quota-exhaustion-graded-as-a-refusal",
        "internal/exploit/firebase.go",
        "\tif status == 429 {",
        "\tif false {",
        "a 429 from Firestore is read as the collection refusing a signed-up caller, so "
        "the free tier running out mid-run reports the lab as MORE SECURE than it is. "
        "That is the false negative this project refuses, arriving as a FAILING check -- "
        "and it cost an audit reporting '1 of 8 documented exploits did not work' when "
        "the collection had refused nothing",
        ["./internal/exploit/"],
    ),
    (
        "abort-names-the-wrong-missing-thing",
        "cmd/unruly/cannot.go",
        "\tif strings.HasPrefix(target, \"http\") {",
        "\tif !strings.HasPrefix(target, \"http\") {",
        "a target given as a URL is told to supply -site, which is the flag that would "
        "NOT have helped -- the origin is already known and the credential is what is "
        "missing. That is the bug this function was extracted to pin, and the message is "
        "the entire output of a failed invocation",
        ["./cmd/unruly/"],
    ),
    (
        "login-wall-diagnosis-collapsed",
        "cmd/unruly/cannot.go",
        "\tif loginWall {",
        "\tif false {",
        "a site serving a sign-in screen gets the same sentence as one that simply ships "
        "no key, so the operator is never told the key arrives in the bundle loaded AFTER "
        "authenticating and is sent to re-check a -site that was already correct. "
        "Collapsing two branches into one string looks like simplification and reads fine "
        "in review",
        ["./cmd/unruly/"],
    ),
    (
        "exploit-neon-write-ignores-consent",
        "internal/exploit/neonwrite.go",
        "\tif !e.IOwnThis {",
        "\tif false {",
        "the harness inserts a row into somebody's table without the caller having "
        "consented. The scanner's write stage has its own gate and so does the seam; "
        "this is the third, and it is the one an operator running an answer key by hand "
        "is relying on",
        ["./internal/exploit/"],
    ),
    (
        "exploit-neon-write-drops-the-prefer-header",
        "internal/exploit/neonwrite.go",
        '\treq.Header.Set("Prefer", "return=representation")',
        "",
        "PostgREST then answers 201 with an EMPTY body, so the demonstration retrieves "
        "nothing and the exploit is graded on a status code -- the boolean this project "
        "refuses to call evidence. The recorded transcript held exactly that empty 201 "
        "for months",
        ["./internal/exploit/"],
    ),
    (
        "exploit-neon-write-believes-a-row-it-did-not-send",
        "internal/exploit/neonwrite.go",
        "\tif got, _ := rows[0][e.Column].(string); got != e.Marker {",
        "\tif got, _ := rows[0][e.Column].(string); got != e.Marker && false {",
        "a 201 returning some OTHER row counts as the write landing. Cleanup keys on the "
        "marker, so the row this run cannot account for is left behind in a fixture whose "
        "contents are the ground truth every other Neon eval rests on",
        ["./internal/exploit/"],
    ),
    (
        "exploit-function-invoke-ignores-consent",
        "internal/exploit/firebase.go",
        "\tif !r.Invoke {",
        "\tif false {",
        "the harness RUNS somebody's deployed code without being asked to. Every other "
        "technique here reads; this one executes, and what it executes is unknowable from "
        "the outside -- which is the whole reason the finding matters",
        ["./internal/exploit/"],
    ),
    (
        "exploit-function-invoke-reports-a-refusal",
        "internal/exploit/firebase.go",
        "\tcase status == 401 || status == 403:",
        "\tcase status == 401:",
        "a function whose invoker binding excludes allUsers stops being recognised as "
        "refusing. Every project has functions and most are correctly closed, so this is "
        "the false positive that would matter most",
        ["./internal/exploit/"],
    ),
    (
        "exploit-function-invoke-accepts-an-empty-body",
        "internal/exploit/firebase.go",
        "\tif len(bytes.TrimSpace(body)) == 0 {",
        "\tif false {",
        "a 200 with nothing in it is reported as a function that ran. Reaching a host is "
        "not running its code, and the payload is the only thing that distinguishes them",
        ["./internal/exploit/"],
    ),
    (
        "neonfixture-counts-an-estimate",
        "internal/neonfixture/neonfixture.go",
        '`select count(*) as n from "`+t+`"',
        '`select n_live_tup as n from pg_stat_user_tables where relname = \'`+t+`\'',
        "the fixture is verified against the statistics view, which the collector updates "
        "after the fact. A probe row still in the table reads as restored, and every Neon "
        "eval afterwards rests on counts that were never checked",
        ["./internal/neonfixture/"],
    ),
    (
        "harvested-function-names-are-folded",
        "cmd/unruly/main.go",
        "\treturn wordlist.MergeKeepingCase(v.Seeds, supplied)",
        "\treturn wordlist.Merge(v.Seeds, supplied)",
        "function names reach the probe lower-cased. A Cloud Function name is a path "
        "segment compared byte for byte, so publicEcho becomes publicecho, every probe "
        "answers 404, and 404 is reported as nothing -- the check goes silent on exactly "
        "the camelCase names Firebase convention produces. It was dead this way, with "
        "unit tests and a mutation passing, until an independent implementation "
        "succeeded where the scan said nothing",
        ["./cmd/unruly/"],
    ),
    (
        "supplied-function-names-lose-to-harvested-noise",
        "internal/provider/firebase_functions.go",
        "\tfirst, rest := keep(supplied), keep(harvested)",
        "\tfirst, rest := keep(nil), keep(append(append([]string{}, supplied...), harvested...))",
        "names the operator asserted are merged into the harvested pile and sorted with "
        "it, so config-key noise can fill the call budget ahead of them. Measured against "
        "the lab: privateControl survived at position 25 and publicEcho was cut at 28, "
        "and a dropped name looks exactly like a function that is not deployed",
        ["./internal/provider/"],
    ),
    (
        "function-call-budget-says-nothing",
        "internal/provider/firebase_functions.go",
        "\tif dropped > 0 {",
        "\tif false {",
        "the call budget trims candidates without a word, so a bounded search reads as a "
        "complete one. Absence of a finding is only evidence when the scan could look, "
        "and here it could not look at the names it never called",
        ["./internal/provider/"],
    ),
    (
        "function-silence-names-no-region",
        "internal/provider/firebase_functions.go",
        "\tif reached == 0 {",
        "\tif false {",
        "the scan calls every name, none answers, and it reports nothing. Functions are "
        "addressed per REGION and this check tries us-central1 plus one guessed from the "
        "RTDB URL, so a project whose functions live anywhere else produces output "
        "identical to a project that has none -- absence of a finding read as evidence, "
        "which is the confusion this scanner refuses everywhere else",
        ["./internal/provider/"],
    ),
    (
        "remote-config-silence-on-a-refusal",
        "internal/provider/firebase_remoteconfig.go",
        "\t\treturn []finding.Finding{remoteConfigNotAssessed(u,\n\t\t\tfmt.Sprintf(",
        "\t\treturn nil\n\t}\n\tif false {\n\t\t_ = []finding.Finding{remoteConfigNotAssessed(u,\n\t\t\tfmt.Sprintf(",
        "a Remote Config fetch that answered 429 or 403 is reported as nothing, which "
        "reads exactly like a template holding no credentials. Remote Config is where a "
        "project's secrets go when somebody wants to change them without shipping a "
        "release, so silence about an unread template is the expensive kind",
        ["./internal/provider/"],
    ),
    (
        "escalation-silence-on-a-refused-token",
        "backend/neon/escalation.go",
        "\tif reported == 0 && len(names) > 0 && refusals == len(names) {",
        "\tif false {",
        "every table refuses the authenticated read -- expired token, wrong project, or "
        "rate limiting -- and the stage reports nothing, which is byte-identical to a "
        "project where every table is correctly protected. Escalation is the headline "
        "finding on Neon, so this turns the check that matters most into a clean bill of "
        "health issued by a credential nobody accepted",
        ["./backend/neon/"],
    ),
    (
        "neon-write-invents-a-column",
        "backend/neon/write.go",
        "const writeProbePayload = `{}`",
        'const writeProbePayload = `{"body":"x"}`',
        "the probe names a column it cannot know exists. Any table without it answers "
        "400 PGRST204 rather than 201, so the write tier reports nothing and reads as a "
        "clean result -- which is what it did on five of the reference lab's six tables "
        "until 2026-08-22, and would do on every table of a project with no such column",
        ["./backend/neon/"],
    ),
    (
        "neon-write-ignores-a-constraint-violation",
        "backend/neon/write.go",
        "\t\t\tcase isConstraintViolation(resp.Body):",
        "\t\t\tcase false:",
        "23502 and 23505 are raised by the table AFTER the security layer admitted the "
        "insert, so they prove the write is permitted while leaving no row. Dropping them "
        "discards the only evidence this probe can obtain without residue, and reports a "
        "writable table as nothing",
        ["./backend/neon/"],
    ),
    (
        "transcript-forgets-the-request",
        "internal/transcript/transcript.go",
        "\t\ttr.AddWithRequest(q.Method, q.Path, q.Auth, q.Body, resp.StatusCode,",
        "\t\ttr.AddWithRequest(q.Method, q.Path, q.Auth, \"\", resp.StatusCode,",
        "the recording keeps the response and forgets what provoked it, so nothing can "
        "tell whether it still answers the request the code makes. That is how the Neon "
        "write recording went on serving 400 PGRST204 after the probe stopped naming a "
        "column and started getting 403/42501 -- every offline eval passed while the "
        "stage was graded against answers the live API would never give again",
        ["./internal/transcript/", "./backend/neon/"],
    ),
    (
        "preview-sweep-skips-in-silence",
        "cmd/unruly/skipped.go",
        '\tif o.site == "" && o.previewHosts == "" {',
        "\tif false {",
        "a scan given no site sweeps no preview deployments and says nothing about it, so "
        "the report reads exactly like a sweep that ran and found none. Preview and "
        "staging hosts routinely ship production credentials behind weaker access "
        "control, and historical-credentials -- skipped for the identical reason -- has "
        "always been disclosed",
        ["./cmd/unruly/"],
    ),
    (
        "accepted-write-cannot-name-its-row",
        "backend/neon/write.go",
        '\t\t\t\t\t"Prefer": "return=representation",',
        '\t\t\t\t\t"Prefer": "return=minimal",',
        "PostgREST answers 201 with an empty body, so the finding reports that a row "
        "exists and cannot say which one. The remediation then offers no usable DELETE "
        "and the operator is left with residue they believe they have removed -- worse "
        "than the hardcoded marker it replaced, because it misinforms rather than misses",
        ["./backend/neon/"],
    ),
    (
        "firestore-evidence-drops-the-projection",
        "internal/provider/firebase_scan.go",
        '\t\t\t"select": map[string]any{"fields": []map[string]string{{"fieldPath": "__name__"}}},',
        "",
        "the probe stops projecting __name__ and starts retrieving whole documents, and "
        "so does the curl printed as evidence. The finding says field values were never "
        "retrieved while handing the reader a command that retrieves them, from somebody "
        "else's database, in a report they may paste to a colleague",
        ["./internal/provider/"],
    ),
    (
        "graphql-evidence-hardcodes-the-limit",
        "internal/graphql/findings.go",
        "\t\t\t\tendpoint, relation, limit),",
        "\t\t\t\tendpoint, relation, 3),",
        "the published GraphQL query says first: 3 whatever -sample was set to, so "
        "replaying the report's own command returns a different number of rows than the "
        "report claims -- which reads as the tool miscounting rather than as the tool "
        "printing a command it never ran",
        ["./internal/graphql/"],
    ),
    (
        "neon-enumeration-ignores-the-hint",
        "backend/neon/enumerate.go",
        '\t\tif r.Source == "hint" {',
        "\t\tif false {",
        "names the SERVER volunteered are discarded, so a Neon scan reports only what the "
        "operator already knew to ask for. Measured against the lab: three near-miss "
        "seeds recover all six tables, three of which were never guessed at",
        ["./backend/neon/"],
    ),
    (
        "neon-enumeration-probes-the-wrong-base",
        "backend/neon/enumerate.go",
        "\tc := s.Client.WithBase(s.Base).WithRestPrefix(\"/\").WithBearer(s.Token)",
        "\tc := s.Client.WithBearer(s.Token)",
        "internal/enumerate probes c.RestURL(name), so the scan-wide client sends every "
        "probe to a path that does not exist. The stage then reports that the API "
        "volunteered nothing -- true of the URL it asked and false of the API, which is "
        "exactly what it did on the first live run",
        ["./backend/neon/"],
    ),
    (
        "a-discovered-origin-widens-scope-without-consent",
        "internal/routes/origins.go",
        "\t\tif inScope[o] {",
        "\t\tif inScope[o] || !isThirdPartyAPI(o) {",
        "a same-party-looking backend named by a bundle is probed without the operator "
        "placing that exact origin in scope. Discovery proves relationship, not "
        "authority, and a frontend can name any host on the internet",
        ["./internal/routes/"],
    ),
    (
        "route-families-combine-get-and-post",
        "internal/routes/routes.go",
        "\t\t\tkey := r.Base + \"\\x00\" + method + \"\\x00\" + prefix",
        "\t\t\tkey := r.Base + \"\\x00\" + prefix",
        "a protected POST and an open GET are folded into one route decision, so one "
        "method can hide or manufacture an authorisation inconsistency in another",
        ["./internal/routes/"],
    ),
    (
        "post-route-finding-replays-get-evidence",
        "internal/routes/routes.go",
        "\t\t\tsnippet, size = r.response(method)",
        "\t\t\tsnippet, size = r.response(http.MethodGet)",
        "a POST inconsistency carries the GET response as proof, so the report's replay "
        "and captured evidence describe different requests",
        ["./internal/routes/"],
    ),
    (
        "truncated-application-inventory-looks-complete",
        "internal/routes/routes.go",
        "\tif len(targets) < len(refs) {\n\t\tres.Findings = append(res.Findings,\n\t\t\trouteBudgetFinding(entry, \"application-routes\", \"-max-routes\", len(targets), len(refs)))\n\t}",
        "\t_ = refs",
        "the route budget drops eligible paths without reporting a lower bound, so no "
        "finding is indistinguishable from every route having been assessed",
        ["./internal/routes/"],
    ),
    (
        "bypass-controls-are-repeated-for-every-route",
        "internal/routes/routes.go",
        "\t\t\tcontrols[r.Base] = ctrl",
        "\t\t\t_ = ctrl",
        "the origin-wide catch-all and root controls are sent again for every refused "
        "path, multiplying traffic without adding evidence",
        ["./internal/routes/"],
    ),
    (
        "intent-manifest-silently-ignores-unknown-fields",
        "internal/intent/intent.go",
        "\tdec.KnownFields(true)",
        "\tdec.KnownFields(false)",
        "a misspelt or future policy field is discarded while the rest of the manifest "
        "is reported as verified, turning an expectation nobody read into assurance",
        ["./internal/intent/"],
    ),
    (
        "firestore-repeats-a-project-wide-terminal-error",
        "internal/provider/firebase_scan.go",
        "\t\tif probe.Terminal != \"\" {\n\t\t\tterminal = probe.Terminal\n\t\t\tbreak\n\t\t}",
        "\t\tif probe.Terminal != \"\" {\n\t\t\tterminal = probe.Terminal\n\t\t\tcontinue\n\t\t}",
        "SERVICE_DISABLED, invalid-key, billing and quota responses apply to the whole "
        "project; repeating them for every guessed collection burns traffic and quota "
        "without measuring another rule",
        ["./internal/provider/"],
    ),
    (
        "anonymous-firebase-probe-account-is-left-behind",
        "internal/provider/firebase_auth.go",
        "\tif deleteAccount(ctx, o.Client, d.Credential, st) {\n\t\treturn true, \"\"\n\t}",
        "\tif false && deleteAccount(ctx, o.Client, d.Credential, st) {\n\t\treturn true, \"\"\n\t}",
        "the anonymous-auth capability probe creates a user and never deletes it, leaving "
        "one new account on every scan",
        ["./internal/provider/"],
    ),
    (
        "agent-record-copies-the-response-body",
        "internal/finding/agent.go",
        "Reason: truncate(f.Evidence.Reason, 320)",
        "Reason: truncate(f.Evidence.Response, 320)",
        "the token-saving agent stream copies sampled target data into its compact reason "
        "field, defeating redaction-by-construction and increasing context cost",
        ["./internal/finding/"],
    ),
    (
        "application-requests-overwrite-provider-requests",
        "internal/engine/engine.go",
        "\t\tout.Requests += st.Attributed()",
        "\t\tout.Requests = st.Attributed()",
        "application traffic replaces the provider total instead of adding to it, so the "
        "same requests disappear from the scan summary depending on stage order",
        ["./internal/engine/"],
    ),
    (
        "application-route-denominator-is-discarded",
        "internal/engine/engine.go",
        "\t\t\tout.Application.Routes += coverage.Routes",
        "\t\t\tout.Application.Routes = 0",
        "the agent summary reports zero application routes and origins after the route "
        "stage measured them, so a complete live inventory looks like an empty scan",
        ["./internal/engine/"],
    ),
    (
        "application-denominator-counts-circuit-refused-routes",
        "internal/engine/engine.go",
        "\t\t\tout.Application.Routes += coverage.Routes",
        "\t\t\tout.Application.Routes += coverage.Routes + 1",
        "route candidates the shared circuit breaker refused to send are called probed "
        "in the agent denominator, overstating both coverage and traffic",
        ["./internal/engine/"],
    ),
    (
        "application-origin-denominator-counts-unprobed-hosts",
        "internal/engine/engine.go",
        "\t\t\tout.Application.Origins += coverage.Origins",
        "\t\t\tout.Application.Origins += coverage.Origins + 1",
        "a host merely mentioned by a bundle is counted as a scoped, probed origin in "
        "the agent denominator, overstating application coverage",
        ["./internal/engine/"],
    ),
    (
        "circuit-refused-route-is-marked-attempted",
        "internal/routes/routes.go",
        "\tattempted := !errors.Is(r.Err, client.ErrRefused)",
        "\tattempted := !errors.Is(nil, client.ErrRefused)",
        "a route the circuit breaker deliberately did not send is counted as a probe, "
        "making planned work indistinguishable from traffic that reached the target",
        ["./internal/routes/"],
    ),
    (
        "route-stage-request-count-includes-prior-shared-traffic",
        "internal/routes/routes.go",
        "\tres.Requests = sentEnd - sentStart",
        "\tres.Requests = sentEnd - sentStart*0",
        "the route stage attributes every request the shared application client sent "
        "before it started, double-counting discovery traffic in the spend ledger",
        ["./internal/routes/"],
    ),
    (
        "non-supabase-agent-artifact-omits-the-scan-summary",
        "cmd/unruly/main.go",
        "\t\tall = append(all, finding.SkippedStage(target(o), \"supabase\", whyNot))\n\t\trunUnified()\n\t\tsentApplication, _ := webClient.Stats()\n\t\trequests = int(sentApplication) + externalProviderRequests\n\t\tall = append(all, finding.ScanSummarySurfaces(target(o), applicationRoutes,\n\t\t\tapplicationOrigins, providerNames, requests))",
        "\t\tall = append(all, finding.SkippedStage(target(o), \"supabase\", whyNot))\n\t\trunUnified()\n\t\tsentApplication, _ := webClient.Stats()\n\t\trequests = int(sentApplication) + externalProviderRequests\n\t\t_ = finding.ScanSummarySurfaces(target(o), applicationRoutes,\n\t\t\tapplicationOrigins, providerNames, requests)",
        "a non-Supabase agent stream ends without the denominator that distinguishes an "
        "empty assessment from an application whose routes were checked and found sound",
        ["./cmd/unruly/"],
    ),
    (
        "provider-summary-ignores-the-probe-budget",
        "cmd/unruly/main.go",
        "\tif limit > 0 && total > limit {",
        "\tif false && limit > 0 && total > limit {",
        "a one-name provider budget is reported as thousands of names probed, overstating "
        "recall and hiding the exact lower bound the operator selected",
        ["./cmd/unruly/"],
    ),
    (
        "early-report-paths-drop-request-statistics",
        "cmd/unruly/main.go",
        "\tprintReportStats(o, all, start, stats)",
        "\t_ = stats",
        "statistics are emitted only by the relational tail again, so -silent -stats "
        "prints nothing for application-only and early-termination scans",
        ["./internal/eval/"],
    ),
    (
        "provider-capability-manifest-allows-silent-gaps",
        "internal/provider/capability.go",
        "\t\tif !seen[c] {\n\t\t\treturn fmt.Errorf(\"provider %q does not declare capability %q as measured or limited\", d.Name(), c)\n\t\t}",
        "\t\tif false && !seen[c] {\n\t\t\treturn fmt.Errorf(\"provider %q does not declare capability %q as measured or limited\", d.Name(), c)\n\t\t}",
        "a provider can omit an attacker outcome from both measured and limited, making "
        "a surface nobody implemented read exactly like one assessed and found clean",
        ["./internal/provider/"],
    ),
    (
        "intent-observation-drops-row-scope",
        "internal/intent/findings.go",
        "Subject: Subject(f.Subject), Scope: Scope(f.Scope), Allowed: f.Allowed",
        "Subject: Subject(f.Subject), Scope: \"\", Allowed: f.Allowed",
        "an owner-only measurement becomes unscoped at the neutral boundary, so intent "
        "cannot distinguish access to one's own row from access to every tenant's row",
        ["./internal/intent/"],
    ),
    (
        "application-access-never-reaches-intent-verification",
		"internal/engine/engine.go",
		"\t\t\tout.Access = scan.MergeAccess(out.Access, access)",
		"\t\t\t_ = access",
        "route access is measured and then discarded at the stage boundary, leaving an "
        "intent manifest about application endpoints permanently unverified",
		["./internal/engine/", "./internal/intent/"],
    ),
    (
        "later-access-observation-hides-a-more-permissive-path",
        "internal/intent/intent.go",
        "\t\t\tseen[k] = combineObservation(previous, o)",
        "\t\t\tseen[k] = o\n\t\t\t_ = previous",
        "two interfaces disagree and the later denial overwrites an observed allow, so "
        "intent verification reports a policy matched while an access path remains open",
        ["./internal/intent/"],
    ),
    (
        "health-and-docs-routes-manufacture-auth-bugs",
        "internal/routes/routes.go",
        "\t\t\t\tif conventionalPublicPath(r.Path) {",
        "\t\t\t\tif false && conventionalPublicPath(r.Path) {",
        "a conventional public health, metrics or documentation leaf is treated as a "
        "missing authorization check merely because data routes beside it are private",
        ["./internal/routes/"],
    ),
    (
        "entry-path-is-mistaken-for-the-application-origin",
        "internal/routes/routes.go",
        "\thome, ok := rr.fetch(ctx, entry)",
        "\thome, ok := rr.fetch(ctx, site+\"/\")",
        "a path-based entry URL is discarded, so the page and its root-relative bundle "
        "are never read and a live route inventory becomes zero routes",
        ["./internal/routes/"],
    ),
    (
        "explicit-route-origin-still-depends-on-bundle-extraction",
        "internal/routes/routes.go",
        "\torigins = append(origins, o.AllowedOrigins...)",
        "\t_ = o.AllowedOrigins",
        "an exact origin supplied by the operator authorizes traffic but never becomes a "
        "scan base unless the extractor rediscovers it, defeating the override when "
        "extraction is the broken component",
        ["./internal/routes/"],
    ),
    (
        "public-api-inventory-is-rated-as-a-vulnerability",
        "internal/routes/spec_findings.go",
        "\t\tID:       \"app-openapi-schema-exposed\",\n\t\tName:     \"The API publishes its own specification to anonymous callers\",\n\t\tSeverity: finding.Info,",
        "\t\tID:       \"app-openapi-schema-exposed\",\n\t\tName:     \"The API publishes its own specification to anonymous callers\",\n\t\tSeverity: finding.Medium,",
        "an intentionally public OpenAPI inventory is elevated to vulnerability severity "
        "despite proving no authorization failure, teaching users to distrust Medium",
        ["./internal/routes/"],
    ),
    (
        "coverage-stage-hides-the-probe-artifact-it-reads",
        "backend/supabase/descriptors.go",
        "\t\t\tArtRelations, ArtVocabulary, ArtSchemas, ArtSurface, ArtProbe, ArtEscalation,",
        "\t\t\tArtRelations, ArtVocabulary, ArtSchemas, ArtSurface, ArtEscalation,",
        "the coverage stage reads probe results without declaring that dependency, so "
        "runtime artifact validation fails only after a real scan reaches finalization",
        ["./backend/supabase/"],
    ),
    (
        "escalation-stage-hides-the-surface-artifact-it-reads",
        "backend/supabase/descriptors.go",
        "Optional: []scan.ArtifactType{ArtSchemas, ArtCredential, ArtSurface},",
        "Optional: []scan.ArtifactType{ArtSchemas, ArtCredential},",
        "escalation reads signup state from the surface result without declaring it, "
        "breaking the typed stage contract on hardened targets",
        ["./backend/supabase/"],
    ),
    (
        "standalone-route-finding-drops-the-observed-status",
        "internal/routes/exposed.go",
        "Status:  r.GET,",
        "Status:  0,",
        "the finding cannot replay or prove which response justified a standalone "
        "application exposure because its observed HTTP status was discarded",
        ["./internal/routes/"],
    ),
    (
        "route-inconsistency-finding-drops-the-observed-status",
        "internal/routes/routes.go",
        "Status:   status,",
        "Status:   status * 0,",
        "the authorization inconsistency names a route but omits the response status "
        "that established anonymous access",
        ["./internal/routes/"],
    ),
]


def run_suite(pkgs) -> bool:
    """True when the named packages pass."""
    # The meta-tests -- TestEveryMutationStillApplies and
    # TestEveryMutationCompiles -- check THIS FILE's bookkeeping against the
    # tree. Under a mutation the tree is deliberately wrong: the outer mutation
    # has already replaced its own old_text, so --check counts zero occurrences
    # of it, reports "its pattern no longer appears", and exits 1. The suite
    # goes red for a reason that has nothing to do with the behaviour on trial,
    # and the mutation is scored CAUGHT by bookkeeping.
    #
    # Measured: of the mutations scoped to ./internal/eval/, all but one lose
    # their pattern this way (the exception's new_text still contains its
    # old_text, so the count stays 1). Their verdicts were being produced by a
    # check that knows nothing about what they broke -- the same false
    # assurance as a mutation killed by the compiler, one level up.
    #
    # Nothing is lost by skipping them here: the audit runs both in its `unit`
    # stage against an unmutated tree, which is the only state in which a
    # bookkeeping check means anything.
    env = dict(os.environ, UNRULY_MUTATION_ACTIVE="1")
    r = subprocess.run(
        ["go", "test", *pkgs, "-count=1"],
        cwd=ROOT, capture_output=True, text=True, timeout=600, env=env,
    )
    return r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="", help="only run mutations whose id contains this")
    ap.add_argument("--check", action="store_true",
                    help="verify every mutation still applies exactly once, and exit")
    ap.add_argument("--buildcheck", action="store_true",
                    help="verify every mutation still COMPILES, and exit")
    args = ap.parse_args()

    # --check only reads; every other mode writes mutations to disk.
    if not args.check:
        _take_lock()

    if args.buildcheck:
        # A mutation that does not compile is scored as CAUGHT.
        #
        # run_suite returns True only when `go test` exits 0, and a build
        # failure exits non-zero, so a mutation with a syntax error is
        # indistinguishable from one a test objected to. It then reports as
        # caught forever while testing nothing -- the exact false assurance
        # this project argues against, aimed at itself.
        #
        # Found the hard way: escalation-skips-other-schemas left an unmatched
        # closing paren and had never been killed by a test in its life.
        # Build the mutations in a COPY of the tree, never in the tree itself.
        # See _isolated_copy for what this is protecting against.
        work = _isolated_copy()
        bad = 0
        try:
          for mid, path, old_text, new_text, _why, _pkgs in MUTATIONS:
            f = work / path
            original = f.read_text()
            if original.count(old_text) != 1:
                continue  # --check reports that separately
            if f.suffix != ".go":
                # Mutations that target CI yaml, the README or the docs are
                # graded by tests that read those files, not by the compiler.
                continue
            pkg = "./" + str(pathlib.Path(path).parent) + "/"
            try:
                f.write_text(original.replace(old_text, new_text, 1))
                r = subprocess.run(["go", "build", pkg], cwd=work,
                                   capture_output=True, text=True, timeout=300)
            finally:
                # Restore so the next mutation starts from a clean copy. If
                # this process is killed the whole copy is abandoned, which is
                # the point: nothing a killed run leaves behind is a source
                # file anyone else is reading.
                f.write_text(original)
            if r.returncode != 0:
                bad += 1
                first = (r.stderr.strip().split("\n") or [""])[0]
                print(f"  {mid}: does not compile, so it is killed by the compiler "
                      f"rather than by a test: {first}")
        finally:
            shutil.rmtree(work, ignore_errors=True)
        print(f"{len(MUTATIONS)} mutations build-checked, {bad} killed by the compiler")
        return 1 if bad else 0

    if args.check:
        # Cheap drift check. A mutation is a patch: find this exact text,
        # replace it, expect the suite to go red. Refactor the code it names
        # and the text stops matching -- the mutation then applies to nothing
        # and is reported as caught, which is the false assurance this whole
        # project argues against, aimed at itself.
        #
        # The full run already enforces this, but stops at the first breakage
        # and costs a mutation pass to reach it. Two broke in a single commit
        # (extracting classifyCode, widening deleteRow's return) and each cost
        # an audit cycle. This finds all of them in milliseconds.
        broken = 0
        for mid, path, old_text, _new, _why, _pkgs in MUTATIONS:
            try:
                src = pathlib.Path(path).read_text()
            except OSError as exc:
                print(f"  {mid}: names {path}, which cannot be read: {exc}")
                broken += 1
                continue
            n = src.count(old_text)
            if n == 1:
                continue
            broken += 1
            if n == 0:
                print(f"  {mid}: its pattern no longer appears in {path}. The code "
                      f"moved; move the mutation with it, or it tests nothing.")
            else:
                print(f"  {mid}: its pattern appears {n} times in {path}. Mutating one "
                      f"copy leaves the other, so the tests can pass for the wrong "
                      f"reason -- and a decision made twice is checked in neither.")
        print(f"{len(MUTATIONS)} mutations checked, {broken} broken")
        return 1 if broken else 0

    selected = [m for m in MUTATIONS if args.k in m[0]]
    if not selected:
        print(f"no mutation matches {args.k!r}", file=sys.stderr)
        return 1

    baseline_pkgs = sorted({p for m in selected for p in m[5]})
    print("Baseline: these packages must pass before anything is mutated.")
    if not run_suite(baseline_pkgs):
        print("  FAIL -- the suite is already red, so no mutation result would mean")
        print("  anything. If a previous run was killed, check `git status` for a")
        print("  file this harness left mutated.")
        return 1
    print("  ok\n")

    survivors = []
    for mid, relpath, find, replace, why, pkgs in selected:
        path = ROOT / relpath
        original = path.read_text()

        count = original.count(find)
        if count != 1:
            print(f"  {mid}: PATTERN MATCHED {count} TIMES in {relpath}, expected exactly 1.")
            print("    The code moved. Fix the mutation rather than letting it silently")
            print("    test nothing -- a mutation that does not apply always 'passes'.")
            return 1

        _PENDING[str(path)] = original
        try:
            path.write_text(original.replace(find, replace))
            caught = not run_suite(pkgs)
        finally:
            path.write_text(original)
            _PENDING.pop(str(path), None)

        status = "caught" if caught else "SURVIVED"
        print(f"  {status:8}  {mid}  [{' '.join(p.replace('./internal/', '').strip('/') for p in pkgs)}]")
        print(f"            {why}")
        if not caught:
            survivors.append((mid, why))

    print()
    if survivors:
        print(f"{len(survivors)} mutation(s) survived. Each is a decision no test is checking:")
        for mid, why in survivors:
            print(f"  - {mid}: {why}")
        return 1
    print(f"All {len(selected)} mutations were caught by the offline suite.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
