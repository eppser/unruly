#!/usr/bin/env python3
"""Verify one corpus project's answer key against its RUNNING stack.

The rule this file enforces is the corpus's only real rule: no claim in an
answer key is allowed to come from the DDL. Row counts come from `psql` in the
container. Read exposure comes from an anonymous HTTP GET. Write exposure comes
from actually performing the write against a marker row and reading the result
back out of the database, then undoing it.

The reason for the marker row is worth stating, because it was the first thing
that went wrong here. The cheap way to test DELETE without destroying data is
to send a filter that matches nothing and call 204 "reachable". That is wrong:
a table with RLS enabled and NO policy also answers 204, because zero rows
matched and Postgres never had to refuse anything. The no-match probe cannot
tell "you may delete" from "there was nothing to delete". So every write is
performed against a row that provably exists, inserted by psql as superuser
immediately beforehand and removed afterwards, and the verdict comes from
whether the row actually changed.

Usage:
    python3 check.py <project-dir> [--evidence]

Exit status is 0 when every claim held and 1 when any did not.

Runs on the stock macOS interpreter, measured as Python 3.9.6, with no
third-party packages. The `dict | None` and `list[tuple[...]]` annotations
below are only legal there because of the `from __future__ import annotations`
on the next line, which defers them to strings -- removing it breaks the
harness on 3.9 with a TypeError at import, well before any claim is checked.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yamlite  # noqa: E402

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YELLOW = DIM = RESET = ""

# SQLSTATEs that mean "the security layer let this write through, and it then
# failed on a data constraint". Reaching a constraint is proof of reachability:
# a check constraint is evaluated only for a write that was already permitted.
CONSTRAINT_CODES = {
    "23502",  # not_null_violation
    "23503",  # foreign_key_violation
    "23505",  # unique_violation
    "23514",  # check_violation
    "22P02",  # invalid_text_representation
    "22001",  # string_data_right_truncation
    "PGRST102",  # PostgREST could not parse the body — never reached the DB
}
DENIED_CODES = {"42501"}  # insufficient_privilege, and RLS refusals


class Result:
    def __init__(self):
        self.rows: list[tuple[str, str, str]] = []  # status, label, detail
        self.failed = 0
        self.evidence: list[dict] = []

    def ok(self, label, detail=""):
        self.rows.append(("PASS", label, detail))

    def bad(self, label, detail=""):
        self.rows.append(("FAIL", label, detail))
        self.failed += 1

    def note(self, label, detail=""):
        self.rows.append(("NOTE", label, detail))

    def check(self, label, want, got, detail=""):
        if want == got:
            self.ok(label, detail or f"= {got!r}")
        else:
            self.bad(label, f"want {want!r}, got {got!r}" + (f" ({detail})" if detail else ""))

    def render(self):
        for status, label, detail in self.rows:
            colour = {"PASS": GREEN, "FAIL": RED, "NOTE": YELLOW}[status]
            print(f"  {colour}{status}{RESET}  {label}  {DIM}{detail}{RESET}")


class Stack:
    """Everything the checker needs to talk to one running project."""

    def __init__(self, project_dir: str, key: dict):
        self.dir = project_dir
        self.key = key
        self.base = key["base_url"].rstrip("/")
        self.prefix = key.get("rest_prefix", "/")
        db = key.get("db") or {}
        self.db_service = db.get("service", "db")
        self.db_user = db.get("user", "postgres")
        self.db_name = db.get("database", "fixture")
        self.anon = os.environ.get(key.get("anon_key_env", ""), "")
        self.authed = os.environ.get(key.get("authenticated_key_env", ""), "")

    # -- database -----------------------------------------------------------
    def psql(self, sql: str) -> str:
        proc = subprocess.run(
            # -q suppresses psql's command tags. Without it `INSERT ...
            # RETURNING id` prints the id AND "INSERT 0 1" on the next line,
            # and a multi-statement claim like "SET ROLE anon; SELECT count(*)"
            # comes back as "SET". The first workaround was to take the first
            # line, which fixed the RETURNING case and left the multi-statement
            # one silently comparing an expected value against "SET" -- a wrong
            # answer rather than an error, which is worse. -q fixes both at the
            # source, so the full output is returned and an accidental
            # multi-row result fails loudly instead of being truncated.
            ["docker", "compose", "exec", "-T", self.db_service,
             "psql", "-U", self.db_user, "-d", self.db_name, "-tAqc", sql],
            cwd=self.dir, capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"psql failed for {sql!r}: {proc.stderr.strip()}")
        return proc.stdout.strip()

    # -- http ---------------------------------------------------------------
    def url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        prefix = self.prefix if self.prefix.startswith("/") else "/" + self.prefix
        if not prefix.endswith("/"):
            prefix += "/"
        return self.base + prefix + path.lstrip("/")

    def http(self, method: str, path: str, body=None, headers=None, role="anon", timeout=15):
        url = self.url(path)
        hdrs = {}
        token = self.authed if role == "authenticated" else self.anon
        if token:
            hdrs["apikey"] = token
            hdrs["Authorization"] = "Bearer " + token
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return resp.status, dict(resp.headers), raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            return e.code, dict(e.headers), raw
        except urllib.error.URLError as e:
            return 0, {}, f"URLError: {e.reason}"
        except Exception as e:  # socket timeouts, resets
            return 0, {}, f"{type(e).__name__}: {e}"

    @staticmethod
    def sqlstate(body: str) -> str:
        try:
            return (json.loads(body) or {}).get("code", "") or ""
        except Exception:
            return ""


def relation_path(rel: dict) -> str:
    return urllib.parse.quote(rel["name"], safe="")


def profile_headers(rel: dict, write: bool = False) -> dict:
    """Non-default schemas are addressed by CONTENT NEGOTIATION in PostgREST,
    not by a path segment: Accept-Profile for reads, Content-Profile for
    writes. Getting this wrong reads as "the relation does not exist".

    The header is sent for EVERY relation that names a schema, `public`
    included. Skipping it for `public` was correct only while `public` happened
    to be the first entry of PGRST_DB_SCHEMAS -- PostgREST's default schema is
    the first entry, not the one called public -- so on a target that exposes
    `api,public` every `public` relation would have been addressed against
    `api` and reported absent. Sending it always costs one header and removes
    the dependency on a coincidence.
    """
    schema = rel.get("schema")
    if not schema:
        return {}
    return {"Content-Profile" if write else "Accept-Profile": schema}


def verify_relation(stack: Stack, rel: dict, res: Result):
    name = rel["name"]
    schema = rel.get("schema", "public")
    qualified = f'"{schema}"."{name}"'
    path = relation_path(rel)
    label = f"{schema}.{name}"

    # --- row count, from the database ------------------------------------
    if "rows" in rel:
        got = int(stack.psql(rel.get("row_count_sql") or f"SELECT count(*) FROM {qualified}"))
        res.check(f"{label} rows", rel["rows"], got)

    # --- claimed sensitive columns must actually exist --------------------
    for col in rel.get("sensitive_columns") or []:
        got = stack.psql(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema="
            f"'{schema}' AND table_name='{name}' AND column_name='{col}'")
        if got == "1":
            res.ok(f"{label}.{col} exists")
        else:
            res.bad(f"{label}.{col} exists", "column named in sensitive_columns is not in the table")

    # --- read exposure, from an anonymous GET -----------------------------
    status, hdrs, body = stack.http(
        "GET", f"{path}?select=*&limit=1",
        headers={**profile_headers(rel), "Prefer": "count=exact", "Range": "0-0"})
    res.evidence.append({"relation": label, "op": "GET", "status": status,
                         "body": body[:300], "range": hdrs.get("Content-Range", "")})
    returned_rows = 0
    if status in (200, 206):
        try:
            returned_rows = len(json.loads(body))
        except Exception:
            returned_rows = 0
    read_exposed = status in (200, 206) and returned_rows > 0
    if "read_exposed" in rel:
        res.check(f"{label} read_exposed", rel["read_exposed"], read_exposed,
                  f"HTTP {status} range={hdrs.get('Content-Range','-')} code={stack.sqlstate(body)}")
    if "read_status" in rel:
        res.check(f"{label} read_status", rel["read_status"], status)
    if "read_sqlstate" in rel:
        res.check(f"{label} read_sqlstate", rel["read_sqlstate"], stack.sqlstate(body))

    # --- reads as an authenticated user (the escalation axis) -------------
    if "authenticated_read_exposed" in rel:
        st2, h2, b2 = stack.http("GET", f"{path}?select=*&limit=1",
                                 headers=profile_headers(rel), role="authenticated")
        got = st2 in (200, 206) and len(json.loads(b2) if st2 in (200, 206) else []) > 0
        res.check(f"{label} authenticated_read_exposed", rel["authenticated_read_exposed"], got,
                  f"HTTP {st2} range={h2.get('Content-Range','-')}")
        res.evidence.append({"relation": label, "op": "GET(authenticated)", "status": st2,
                             "body": b2[:300], "range": h2.get("Content-Range", "")})

    wants_write = any(k in rel for k in ("insert_reachable", "update_reachable", "delete_reachable"))
    if not wants_write:
        return
    probe = rel.get("probe")
    if not probe:
        res.bad(f"{label} write claims", "claims a write outcome with no probe: block, so it cannot be measured")
        return

    try:
        verify_writes(stack, rel, probe, res, label, path)
    finally:
        if probe.get("cleanup_sql"):
            stack.psql(probe["cleanup_sql"])


def verify_writes(stack: Stack, rel: dict, probe: dict, res: Result, label: str, path: str):
    schema = rel.get("schema", "public")
    qualified = f'"{schema}"."{rel["name"]}"'

    # --- INSERT ------------------------------------------------------------
    if "insert_reachable" in rel:
        before = int(stack.psql(f"SELECT count(*) FROM {qualified}"))
        body = probe.get("post_body", "{}")
        # Prefer: return=minimal, which is PostgREST's own default.
        #
        # This used to ask for return=representation, and that made the probe
        # blind to the single most interesting write shape in the corpus. A
        # table with FOR INSERT WITH CHECK (true) and NO select policy commits
        # the row and then refuses the RETURNING, so the response is
        # 401 42501 "new row violates row-level security policy" -- naming the
        # wrong half of what happened -- and the probe recorded a genuinely
        # writable public submission form as not writable. The row count check
        # below sees the truth either way, but the SQLSTATE branch did not.
        prefer = probe.get("post_prefer", "return=minimal")
        status, _, resp = stack.http("POST", path, body=body,
                                     headers={**profile_headers(rel, write=True),
                                              "Prefer": prefer})
        code = stack.sqlstate(resp)
        after = int(stack.psql(f"SELECT count(*) FROM {qualified}"))
        landed = after > before
        if landed:
            got, why = True, f"HTTP {status}, row count {before}->{after}"
        elif code in CONSTRAINT_CODES:
            got, why = True, f"HTTP {status} {code}: write was permitted, then failed a data constraint"
        elif code in DENIED_CODES or status in (401, 403):
            got, why = False, f"HTTP {status} {code}"
        else:
            got, why = False, f"HTTP {status} {code} (unclassified)"
        res.check(f"{label} insert_reachable", rel["insert_reachable"], got, why)
        res.evidence.append({"relation": label, "op": "POST", "status": status,
                             "sqlstate": code, "count_before": before, "count_after": after})

    needs_marker = "update_reachable" in rel or "delete_reachable" in rel
    if not needs_marker:
        return
    if not probe.get("marker_sql"):
        res.bad(f"{label} update/delete", "no marker_sql: UPDATE and DELETE cannot be measured "
                                          "without a row that provably exists")
        return

    # --- UPDATE, against a row that exists ---------------------------------
    if "update_reachable" in rel:
        # Cleanup runs BEFORE each marker insert as well as after the relation.
        # Tables with a text primary key collide on the second marker
        # otherwise: the UPDATE probe's row is still present when the DELETE
        # probe inserts its own, and the duplicate-key error was being read as
        # a failure of the check rather than of the harness.
        if probe.get("cleanup_sql"):
            stack.psql(probe["cleanup_sql"])
        marker_id = stack.psql(probe["marker_sql"])
        flt = probe["row_filter"].replace("{id}", marker_id)
        status, _, resp = stack.http("PATCH", f"{path}?{flt}", body=probe["update_body"],
                                     headers={**profile_headers(rel, write=True),
                                              "Prefer": "return=representation"})
        code = stack.sqlstate(resp)
        observed = stack.psql(probe["update_check_sql"].replace("{id}", marker_id))
        changed = observed == probe["update_expect"]
        res.check(f"{label} update_reachable", rel["update_reachable"], changed,
                  f"HTTP {status} {code}; column now {observed!r}")
        res.evidence.append({"relation": label, "op": "PATCH", "status": status,
                             "sqlstate": code, "column_after": observed})

    # --- DELETE, against a row that exists ---------------------------------
    if "delete_reachable" in rel:
        if probe.get("cleanup_sql"):
            stack.psql(probe["cleanup_sql"])
        marker_id = stack.psql(probe["marker_sql"])
        flt = probe["row_filter"].replace("{id}", marker_id)
        status, _, resp = stack.http("DELETE", f"{path}?{flt}",
                                     headers=profile_headers(rel, write=True))
        code = stack.sqlstate(resp)
        still = stack.psql(probe["exists_check_sql"].replace("{id}", marker_id)) \
            if probe.get("exists_check_sql") else \
            stack.psql(f"SELECT count(*) FROM {qualified} WHERE {probe['row_filter'].replace('=eq.', '=').replace('{id}', marker_id)}")
        gone = still == "0"
        res.check(f"{label} delete_reachable", rel["delete_reachable"], gone,
                  f"HTTP {status} {code}; rows matching marker after: {still}")
        res.evidence.append({"relation": label, "op": "DELETE", "status": status,
                             "sqlstate": code, "rows_left": still})


def _interpolate(value, vars: dict):
    """Substitute ${name} from earlier checks' `capture:` blocks.

    Added for the escalation cases, which cannot be measured any other way: the
    claim "anyone who signs up can read this" requires taking the token a
    signup endpoint just returned and using it on the next request. Without
    chaining, that claim can only be verified by hand and then asserted from
    memory in an answer key, which is the failure mode this corpus exists to
    avoid. A missing variable is left as the literal ${name} so the resulting
    check fails loudly rather than silently sending an empty credential.
    """
    if isinstance(value, str):
        for k, v in vars.items():
            value = value.replace("${" + k + "}", v)
        return value
    if isinstance(value, dict):
        return {k: _interpolate(v, vars) for k, v in value.items()}
    return value


def verify_http_check(stack: Stack, chk: dict, res: Result, vars: dict | None = None):
    vars = vars if vars is not None else {}
    label = chk.get("name") or f"{chk['method']} {chk['path']}"
    status, hdrs, body = stack.http(
        chk.get("method", "GET"), _interpolate(chk["path"], vars),
        body=_interpolate(chk.get("body"), vars),
        headers=_interpolate(chk.get("headers") or {}, vars),
        role=chk.get("role", "anon"),
        timeout=chk.get("timeout", 15))
    cap = chk.get("capture")
    if cap:
        try:
            vars[cap["name"]] = str(json.loads(body)[cap["json_key"]])
            res.ok(f"{label} [capture {cap['name']}]", f"{len(vars[cap['name']])} chars")
        except Exception as e:
            res.bad(f"{label} [capture {cap['name']}]", f"{type(e).__name__} reading {cap['json_key']!r} from {body[:160]!r}")
    res.evidence.append({"check": label, "status": status, "body": body[:400]})
    if "expect_status" in chk:
        res.check(label + " [status]", chk["expect_status"], status, body[:120])
    if "expect_status_in" in chk:
        want = chk["expect_status_in"]
        (res.ok if status in want else res.bad)(
            label + " [status]", f"got {status}, allowed {want}")
    if "expect_body_contains" in chk:
        want = chk["expect_body_contains"]
        (res.ok if want in body else res.bad)(
            label + " [contains]", f"{want!r} in body" if want in body else f"{want!r} NOT in {body[:160]!r}")
    if "expect_body_missing" in chk:
        want = chk["expect_body_missing"]
        (res.ok if want not in body else res.bad)(
            label + " [absent]", f"{want!r} absent" if want not in body else f"{want!r} PRESENT in {body[:160]!r}")
    if "expect_header" in chk:
        for hk, hv in (chk["expect_header"] or {}).items():
            res.check(f"{label} [{hk}]", hv, hdrs.get(hk, ""))


def verify_psql_check(stack: Stack, chk: dict, res: Result):
    got = stack.psql(chk["sql"])
    res.check(chk.get("name") or chk["sql"][:60], str(chk["expect"]), got)


def await_schema_cache(stack: Stack, res: Result, seconds: int = 90):
    """Wait out PostgREST's schema cache load before judging anything.

    Found by re-running a project that had passed. PostgREST answers

        503 {"code":"PGRST002", "message":"Could not query the database for
             the schema cache. Retrying."}

    for a window after startup, and `docker compose up --wait` does not cover
    it: the container is healthy, the port is open, and every probe gets a 503.
    A key verified against an already-warm stack passed; the same key from a
    cold start failed 23 of 35 claims.

    That is worth more than the fix. It means a scan begun immediately after a
    deploy sees a project with no relations and no errors it recognises, and
    every corpus project would have inherited the race silently.

    The wait is keyed on the PGRST002 body specifically, so a target that is
    unreachable (project 06) or is not PostgREST at all (project 14) does not
    pay for it -- those fail the probe differently and fall through at once.
    """
    import time
    deadline = time.time() + seconds
    waited = 0.0
    while time.time() < deadline:
        status, _, body = stack.http("GET", "", timeout=5)
        if not (status == 503 and "PGRST002" in body):
            if waited:
                res.note("schema cache warm-up", f"waited {waited:.0f}s for PGRST002 to clear")
            return
        time.sleep(1.0)
        waited += 1.0
    res.bad("schema cache warm-up", f"still 503 PGRST002 after {seconds}s")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check.py <project-dir>", file=sys.stderr)
        return 2
    project_dir = os.path.abspath(sys.argv[1])
    key_path = os.path.join(project_dir, "answer-key.yaml")
    key = yamlite.load_path(key_path)
    stack = Stack(project_dir, key)
    res = Result()

    print(f"{key['name']}  {key['base_url']}{key.get('rest_prefix','/')}")
    await_schema_cache(stack, res)

    for chk in key.get("expect", {}).get("psql") or []:
        try:
            verify_psql_check(stack, chk, res)
        except Exception as e:
            res.bad(chk.get("name", "psql"), f"{type(e).__name__}: {e}")

    for rel in key.get("expect", {}).get("relations") or []:
        try:
            verify_relation(stack, rel, res)
        except Exception as e:
            res.bad(f"{rel.get('schema','public')}.{rel.get('name','?')}", f"{type(e).__name__}: {e}")

    # Checks run in file order and share one variable scope, so a check may use
    # a token an earlier one captured.
    chain_vars: dict[str, str] = {}
    for chk in key.get("expect", {}).get("checks") or []:
        try:
            verify_http_check(stack, chk, res, chain_vars)
        except Exception as e:
            res.bad(chk.get("name", "check"), f"{type(e).__name__}: {e}")

    for item in key.get("expect", {}).get("unverified") or []:
        res.note("UNVERIFIED: " + item.get("claim", "?"), item.get("why", ""))

    res.render()
    with open(os.path.join(project_dir, "evidence.jsonl"), "w") as fh:
        for line in res.evidence:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")

    checked = sum(1 for s, _, _ in res.rows if s != "NOTE")
    if res.failed:
        print(f"{RED}{res.failed} of {checked} claims did not hold{RESET}")
        return 1
    print(f"{GREEN}all {checked} claims held{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
