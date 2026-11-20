"""
Visual Expert Code Inspection MCP server.

Wraps the JSON endpoints used by the Visual Expert web UI:
  GET  /api/codeinspection/{project}/{analysis}/GetDefects          (DevExtreme load options)
  GET  /api/codeinspection/{project}/{analysis}/ai-defect-export/{id}
  POST /api/codeinspection/{project}/{analysis}/update-status       {defectIds, statusEnum, comment}
  POST /api/codeinspection/{project}/{analysis}/update-severity     {defectIds, severityEnum, comment}

Configuration (environment variables):
  VE_BASE_URL      e.g. https://demo.visual-expert.com         (required)
  VE_PROJECT       default project, id (1027) or name ("PFCApps-Git")  (optional; VE_PROJECT_ID also accepted)
  VE_ANALYSIS_ID   pin an analysis id; empty or "latest" (default) follows the newest analysis
  VE_AUTH          windows | form | cookie                      (default: windows if no VE_EMAIL, else form)
  VE_EMAIL         login email      (form auth)
  VE_PASSWORD      login password   (form auth)
  VE_COOKIE        raw Cookie header copied from a signed-in browser (cookie auth)
  VE_VERIFY_TLS    "false" to skip TLS verification (self-signed on-prem servers)
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
import functools

# --------------------------------------------------------------------------- enums

SEVERITY = {"critical": 0, "major": 1, "minor": 2, "low": 3, "information": 4}
TYPE = {"bug": 0, "maintainability": 1, "vulnerability": 2, "security warning": 3, "metric": 4}
STATUS = {
    "open": 0,
    "risk accepted": 1,
    "false positive": 2,
    "on hold": 3,
    "pending validation": 4,
    "resolved": 5,  # set by the analyzer, not settable from the UI
}
SETTABLE_STATUS = {k: v for k, v in STATUS.items() if k != "resolved"}
# Grid "scope" filters used by the UI (Active = Open + Pending Validation)
ACTIVE_STATUSES = ["open", "pending validation"]


def _norm(s: str) -> str:
    return re.sub(r"[\s_\-]+", " ", s.strip().lower())


def _enum(mapping: dict[str, int], value: str | int, what: str) -> int:
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        v = int(value)
        if v in mapping.values():
            return v
    else:
        key = _norm(value)
        if key in mapping:
            return mapping[key]
        # allow prefixes like "crit", "risk", "false"
        hits = [k for k in mapping if k.startswith(key)]
        if len(hits) == 1:
            return mapping[hits[0]]
    raise ValueError(f"Unknown {what} {value!r}. Valid: {', '.join(mapping)}")


def _defect_num(defect_id: str | int) -> int:
    """'VE-2745' / 've2745' / '2745' / 2745 -> 2745"""
    m = re.search(r"(\d+)\s*$", str(defect_id))
    if not m:
        raise ValueError(f"Can't parse defect id {defect_id!r}")
    return int(m.group(1))


# --------------------------------------------------------------------------- HTML form parsing


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._cur: dict[str, Any] | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append(
                {"name": a.get("name"), "type": (a.get("type") or "text").lower(), "value": a.get("value") or ""}
            )

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _forms(html: str) -> list[dict[str, Any]]:
    p = _FormParser()
    p.feed(html)
    return p.forms


# --------------------------------------------------------------------------- client


class AuthError(RuntimeError):
    pass


def _env(name: str) -> str | None:
    """Env var, treating empty strings and unexpanded ${...} placeholders as unset."""
    v = os.environ.get(name, "").strip()
    return None if not v or v.startswith("${") else v


class VEClient:
    def __init__(self) -> None:
        base = os.environ.get("VE_BASE_URL", "").rstrip("/")
        if not base:
            raise RuntimeError("VE_BASE_URL is not set")
        self.base = base
        # Project may be an id (1027) or a project name ("PFCApps-Git"); resolved lazily.
        self.project = _env("VE_PROJECT") or _env("VE_PROJECT_ID")
        self.project_id: str | None = None
        # Analysis: a fixed id pins it; empty or "latest" follows the newest analysis automatically.
        a = (_env("VE_ANALYSIS_ID") or "latest").strip().lower()
        self.analysis_id: str | None = None if a == "latest" else a
        self._latest: dict[int, tuple[float, int]] = {}
        self.auth_mode = _env("VE_AUTH") or ("form" if _env("VE_EMAIL") else "windows")
        self.s = requests.Session()
        self.s.verify = os.environ.get("VE_VERIFY_TLS", "true").lower() != "false"
        self.s.headers["User-Agent"] = "visual-expert-mcp/0.2"
        self.s.headers["X-Requested-With"] = "XMLHttpRequest"
        self._logged_in = False

    # ---- auth

    def login(self) -> None:
        mode = self.auth_mode.lower()
        if mode == "cookie":
            cookie = os.environ.get("VE_COOKIE")
            if not cookie:
                raise AuthError("VE_AUTH=cookie but VE_COOKIE is empty")
            self.s.headers["Cookie"] = cookie
        elif mode == "windows":
            try:
                from requests_negotiate_sspi import HttpNegotiateAuth
            except ImportError as e:  # non-Windows
                raise AuthError("Windows auth needs requests-negotiate-sspi (Windows only)") from e
            r = self.s.post(f"{self.base}/account/quick-login", auth=HttpNegotiateAuth(), allow_redirects=True)
            if r.status_code >= 400:
                raise AuthError(f"Windows authentication failed: HTTP {r.status_code}")
        elif mode == "form":
            self._form_login()
        else:
            raise AuthError(f"Unknown VE_AUTH {mode!r}")
        if not self._is_authenticated():
            raise AuthError(f"Login ({mode}) did not produce an authenticated session")
        self._logged_in = True

    def _form_login(self) -> None:
        email, password = os.environ.get("VE_EMAIL"), os.environ.get("VE_PASSWORD")
        if not email or not password:
            raise AuthError("Form auth needs VE_EMAIL and VE_PASSWORD")
        r = self.s.get(f"{self.base}/account/login")
        # The login is multi-step (email, then password). Fill whatever form the server returns.
        for _ in range(4):
            forms = [f for f in _forms(r.text) if f["method"] == "post" and "login" in f["action"].lower()] or [
                f for f in _forms(r.text) if f["method"] == "post"
            ]
            if not forms:
                break
            form = forms[0]
            data: dict[str, str] = {}
            for inp in form["inputs"]:
                if not inp["name"]:
                    continue
                t, n = inp["type"], inp["name"].lower()
                if t == "password":
                    data[inp["name"]] = password
                elif t == "email" or "email" in n or n in ("username", "user", "login"):
                    data[inp["name"]] = email
                elif t in ("hidden", "text"):
                    data[inp["name"]] = inp["value"]
                elif t == "checkbox" and "remember" in n:
                    data[inp["name"]] = "true"
            r = self.s.post(urljoin(r.url, form["action"] or r.url), data=data, allow_redirects=True)
            if "/account/login" not in urlparse(r.url).path.lower():
                return
        if "/account/login" in urlparse(r.url).path.lower():
            raise AuthError("Form login failed (still on the login page) - check VE_EMAIL / VE_PASSWORD")

    def _is_authenticated(self) -> bool:
        r = self.s.get(f"{self.base}/api/notification/unseen-count", allow_redirects=False)
        return r.status_code == 200 and r.headers.get("X-Unauthorized") != "true"

    @staticmethod
    def _unauth(r: requests.Response) -> bool:
        return (
            r.status_code in (401, 403)
            or r.headers.get("X-Unauthorized") == "true"
            or (300 <= r.status_code < 400 and "login" in r.headers.get("Location", "").lower())
            or "/account/login" in urlparse(r.url).path.lower()
        )

    def request(self, method: str, path: str, **kw) -> requests.Response:
        if not self._logged_in:
            self.login()
        kw.setdefault("allow_redirects", False)
        r = self.s.request(method, f"{self.base}{path}", **kw)
        if self._unauth(r) and self.auth_mode != "cookie":
            self._logged_in = False
            self.login()
            r = self.s.request(method, f"{self.base}{path}", **kw)
        if self._unauth(r):
            raise AuthError("Not authenticated (session expired or credentials invalid)")
        if r.status_code >= 400:
            detail = r.text[:500]
            try:
                detail = r.json().get("ErrorMessage") or detail
            except Exception:
                pass
            raise RuntimeError(f"HTTP {r.status_code} from {path}: {detail}")
        return r

    # ---- context

    def list_projects(self) -> list[dict]:
        html = self.request("GET", "/projects").text
        out, seen = [], set()
        for m in re.finditer(r'\{"Id":(\d+),"Name":"((?:[^"\\]|\\.)*)"', html):
            pid = int(m.group(1))
            if pid not in seen:
                seen.add(pid)
                out.append({"id": pid, "name": json.loads(f'"{m.group(2)}"')})
        return out

    def resolve_project(self, project: str | int) -> int:
        s = str(project).strip()
        if s.isdigit():
            return int(s)
        projects = self.list_projects()
        exact = [p for p in projects if p["name"].lower() == s.lower()]
        hits = exact or [p for p in projects if s.lower() in p["name"].lower()]
        if len(hits) != 1:
            names = ", ".join(f"{p['name']} ({p['id']})" for p in (hits or projects))
            raise ValueError(f"{'Ambiguous' if hits else 'Unknown'} project {s!r}. Projects: {names}")
        return hits[0]["id"]

    def latest_analysis(self, p: int, max_age: float = 300) -> int:
        """Newest analysis of project p. The web app redirects /codeinspection/{p} to the analysis
        it would open; then we probe forward in case a newer one exists."""
        cached = self._latest.get(p)
        if cached and time.time() - cached[0] < max_age:
            return cached[1]
        r = self.request("GET", f"/codeinspection/{p}", allow_redirects=True)
        m = re.search(rf"/codeinspection/{p}/(\d+)", r.url)
        if not m:
            raise ValueError(f"Project {p} not found or has no analysis (redirected to {urlparse(r.url).path})")
        a = int(m.group(1))
        for _ in range(50):
            probe = self.s.get(f"{self.base}/api/codeinspection/{p}/{a + 1}/GetDefects",
                               params={"skip": 0, "take": 1}, allow_redirects=False)
            if probe.status_code != 200:
                break
            a += 1
        self._latest[p] = (time.time(), a)
        return a

    def ctx(self, project_id: int | str | None, analysis_id: int | None) -> tuple[int, int]:
        if project_id:
            p = self.resolve_project(project_id)
        else:
            if not self.project_id and self.project:
                self.project_id = str(self.resolve_project(self.project))
            if not self.project_id:
                raise ValueError("No project set. Call list_projects, then set_context with a project name/id "
                                 "or a Visual Expert URL.")
            p = int(self.project_id)
        a = analysis_id or self.analysis_id
        return p, int(a) if a else self.latest_analysis(p)

    # ---- API

    def get_defects(self, p: int, a: int, filt: list | None, scope: str | None, sort: list | None,
                    skip: int, take: int, search: str | None) -> list[dict]:
        params: dict[str, Any] = {"skip": skip, "take": take, "requireTotalCount": "false"}
        if sort:
            params["sort"] = json.dumps(sort)
        if filt:
            params["filter"] = json.dumps(filt)
        if scope:
            params["filterScope"] = scope
        if search:
            params["searchValue"] = search
            params["searchExpr"] = json.dumps(["defectDisplayId", "codeRuleName", "containerName"])
            params["searchOperation"] = "contains"
        return self.request("GET", f"/api/codeinspection/{p}/{a}/GetDefects", params=params).json().get("data", [])

    def export(self, p: int, a: int, num: int) -> dict:
        r = self.request("GET", f"/api/codeinspection/{p}/{a}/ai-defect-export/{num}")
        return json.loads(r.text)

    def update_status(self, p: int, a: int, ids: list[int], status: int, comment: str | None) -> None:
        self.request("POST", f"/api/codeinspection/{p}/{a}/update-status",
                     json={"defectIds": ids, "statusEnum": status, "comment": comment})

    def update_severity(self, p: int, a: int, ids: list[int], severity: int, comment: str | None) -> None:
        self.request("POST", f"/api/codeinspection/{p}/{a}/update-severity",
                     json={"defectIds": ids, "severityEnum": severity, "comment": comment})


# --------------------------------------------------------------------------- filters


def _any_of(field: str, values: list[int]) -> list:
    if len(values) == 1:
        return [field, "=", values[0]]
    out: list = []
    for i, v in enumerate(values):
        if i:
            out.append("or")
        out.append([field, "=", v])
    return out


def _and(parts: list[list]) -> list | None:
    parts = [p for p in parts if p]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    out: list = []
    for i, p in enumerate(parts):
        if i:
            out.append("and")
        out.append(p)
    return out


def _row(d: dict) -> dict:
    return {
        "id": d.get("defectDisplayId"),
        "rule": d.get("codeRuleName"),
        "ruleId": d.get("codeRuleId"),
        "container": d.get("containerFullName") or d.get("containerName"),
        "severity": d.get("severity"),
        "type": d.get("type"),
        "status": d.get("status"),
        "occurrences": d.get("occurrences"),
        "score": d.get("score"),
        "assignee": d.get("assigneeName"),
        "task": d.get("taskDisplayId"),
        "lastDetected": (d.get("lastDetectedDate") or "")[:10],
    }


def _as_list(v: list[str] | str | None) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [x for x in re.split(r"\s*,\s*", v) if x]
    return list(v)


# --------------------------------------------------------------------------- MCP tools

mcp = MCPServer(
    "visual-expert",
    instructions=(
        "Tools for Visual Expert Code Inspection defects (findings). Defect ids look like 'VE-2745'. "
        "Severities: Critical, Major, Minor, Low, Information. Types: Bug, Maintainability, Vulnerability, "
        "Security warning, Metric. Statuses: Open, Risk Accepted, False Positive, On Hold, Pending Validation, "
        "Resolved (Resolved is set by re-analysis only). 'Active' means Open or Pending Validation. "
        "Changing status or severity is visible to the whole team - confirm with the user before doing it "
        "unless they explicitly asked for that exact change."
    ),
)
_client: VEClient | None = None


def tool(fn):
    """Register an MCP tool; expected failures reach Claude as readable messages."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (AuthError, ValueError, RuntimeError, requests.RequestException) as e:
            raise ToolError(str(e)) from e
    return mcp.tool()(wrapper)


def client() -> VEClient:
    global _client
    if _client is None:
        _client = VEClient()
    return _client


@tool
def list_projects() -> str:
    """List the Visual Expert projects this account can see (id and name), marking the current one."""
    c = client()
    cur = c.project_id
    rows = c.list_projects()
    return json.dumps([{**p, "current": str(p["id"]) == str(cur)} for p in rows], indent=1)


@tool
def set_context(project: str | None = None, analysis: str | None = None, url: str | None = None) -> str:
    """Choose the project (name or id, or any Visual Expert URL containing /codeinspection/{project}/...).
    analysis: "latest" (default - always follows the newest analysis) or a specific analysis id to pin
    an older one."""
    c = client()
    if url:
        m = re.search(r"/codeinspection/(\d+)", url)
        if not m:
            raise ValueError("URL doesn't contain /codeinspection/{project}")
        project = m.group(1)
    if project:
        c.project_id = str(c.resolve_project(project))
    if analysis is not None:
        c.analysis_id = None if str(analysis).strip().lower() in ("", "latest") else str(int(analysis))
    p, a = c.ctx(None, None)
    mode = "pinned" if c.analysis_id else "latest"
    return f"Context: project {p}, analysis {a} ({mode}) on {c.base}"


@tool
def list_defects(
    severity: list[str] | str | None = None,
    status: list[str] | str | None = "active",
    type: list[str] | str | None = None,
    rule: str | None = None,
    container: str | None = None,
    search: str | None = None,
    limit: int = 200,
    project_id: int | None = None,
    analysis_id: int | None = None,
) -> str:
    """List defects (findings).

    severity: e.g. ["Critical"] or "Critical,Major". status: "active" (Open + Pending Validation, default),
    "all", or names like ["Risk Accepted"]. type: e.g. "Vulnerability". rule: rule id (e.g. VEPBRULE7) or substring of rule name.
    container: substring of the object/script name. search: free text. limit: max rows (default 200).
    Returns JSON {count, truncated, defects:[...]}, sorted by severity."""
    c = client()
    p, a = c.ctx(project_id, analysis_id)
    statuses = _as_list(status)
    if any(_norm(s) == "all" for s in statuses):
        statuses = []
    elif any(_norm(s) == "active" for s in statuses):
        statuses = [s for s in statuses if _norm(s) != "active"] + ACTIVE_STATUSES
    parts = [
        _any_of("severityEnum", sorted({_enum(SEVERITY, s, "severity") for s in _as_list(severity)})) if severity else None,
        _any_of("statusEnum", sorted({_enum(STATUS, s, "status") for s in statuses})) if statuses else None,
        _any_of("typeEnum", sorted({_enum(TYPE, t, "type") for t in _as_list(type)})) if type else None,
        ["containerName", "contains", container] if container else None,
    ]
    # The server can filter on codeRuleId but not on the (computed) rule name, and ignores
    # free-text search, so those two are applied client-side.
    rule_text = None
    if rule:
        if re.fullmatch(r"[A-Za-z]+RULE\d+", rule.strip()):
            parts.append(["codeRuleId", "=", rule.strip().upper()])
        else:
            rule_text = rule.lower()
    needle = search.lower() if search else None

    def keep(d: dict) -> bool:
        if rule_text and rule_text not in (d.get("codeRuleName") or "").lower():
            return False
        if needle and not any(needle in (d.get(k) or "").lower()
                              for k in ("defectDisplayId", "codeRuleName", "containerName", "containerFullName")):
            return False
        return True

    filt = _and(parts)
    rows: list[dict] = []
    page = 100
    skip = 0
    while len(rows) <= limit:
        batch = c.get_defects(p, a, filt, None, [{"selector": "severityEnum", "desc": False}],
                              skip, page, None)
        skip += len(batch)
        rows.extend(d for d in batch if keep(d))
        if len(batch) < page:
            break
    truncated = len(rows) > limit
    rows = rows[:limit]
    return json.dumps({"project": p, "analysis": a, "count": len(rows), "truncated": truncated, "defects": [_row(d) for d in rows]}, indent=1)


@tool
def summarize_defects(status: list[str] | str | None = "active", project_id: int | None = None,
                      analysis_id: int | None = None) -> str:
    """Counts of defects by severity, type and rule (top 15) for the given status filter (default active)."""
    data = json.loads(list_defects(status=status, limit=100000, project_id=project_id, analysis_id=analysis_id))
    from collections import Counter
    d = data["defects"]
    return json.dumps({
        "total": len(d),
        "bySeverity": Counter(x["severity"] for x in d),
        "byType": Counter(x["type"] for x in d),
        "byStatus": Counter(x["status"] for x in d),
        "topRules": Counter(x["rule"] for x in d).most_common(15),
    }, indent=1)


def _source_excerpt(src: str, lines: list[int], context: int) -> str:
    all_lines = src.splitlines()
    if not lines:
        return "\n".join(f"{i+1:5}: {l}" for i, l in enumerate(all_lines[: 2 * context]))
    keep: set[int] = set()
    for ln in lines:
        keep.update(range(max(1, ln - context), min(len(all_lines), ln + context) + 1))
    out, prev = [], 0
    for n in sorted(keep):
        if prev and n != prev + 1:
            out.append("  ...")
        mark = ">>" if n in lines else "  "
        out.append(f"{mark}{n:5}: {all_lines[n-1]}")
        prev = n
    return "\n".join(out)


@tool
def get_defect(defect_id: str, full_source: bool = False, context_lines: int = 25,
               project_id: int | None = None, analysis_id: int | None = None) -> str:
    """Details for one defect (e.g. 'VE-2745'): rule description and benefit, severity, object location
    (container path like 'F:\\src\\app.pbl>w_main'), occurrence line numbers, and the source code.
    By default returns only the lines around each occurrence (marked '>>'); set full_source=True for all of it.
    Line numbers are relative to the exported object source shown here."""
    c = client()
    p, a = c.ctx(project_id, analysis_id)
    num = _defect_num(defect_id)
    ex = c.export(p, a, num)
    sc = ex.get("sourceCode") or {}
    src = sc.get("sourceCode") or ""
    lines = ex.get("occurrenceLines") or []
    meta = [d for d in c.get_defects(p, a, ["defectDisplayId", "=", f"VE-{num}"], None, None, 0, 1, None)]
    out = {
        "id": ex.get("defectId"),
        "project": p,
        "analysis": a,
        "status": meta[0]["status"] if meta else None,
        "type": meta[0]["type"] if meta else None,
        "severity": ex.get("severity"),
        "container": ex.get("containerName"),
        "location": ex.get("containerLocation"),
        "rule": ex.get("codeRule"),
        "occurrenceLines": lines,
        "language": sc.get("sourceCodeLanguage"),
        "assignee": meta[0].get("assigneeName") if meta else None,
    }
    body = src if full_source else _source_excerpt(src, lines, context_lines)
    return json.dumps(out, indent=1) + "\n\n--- source " + ("(full)" if full_source else "(excerpt)") + " ---\n" + body


@tool
def set_defect_status(defect_ids: list[str] | str, status: str, comment: str | None = None,
                      project_id: int | None = None, analysis_id: int | None = None) -> str:
    """Change status of one or more defects. status: Open, Risk Accepted, False Positive, On Hold,
    Pending Validation. A comment is strongly recommended (required by most teams for Risk Accepted /
    False Positive). Use 'Pending Validation' after fixing code, until the next analysis marks it Resolved."""
    c = client()
    p, a = c.ctx(project_id, analysis_id)
    ids = [_defect_num(x) for x in _as_list(defect_ids)]
    s = _enum(SETTABLE_STATUS, status, "status")
    c.update_status(p, a, ids, s, comment)
    name = next(k for k, v in STATUS.items() if v == s).title()
    return f"Set {', '.join(f'VE-{i}' for i in ids)} to {name}" + (f" with comment: {comment}" if comment else "")


@tool
def set_defect_severity(defect_ids: list[str] | str, severity: str, comment: str | None = None,
                        project_id: int | None = None, analysis_id: int | None = None) -> str:
    """Change severity of one or more defects (Critical, Major, Minor, Low, Information), with optional comment."""
    c = client()
    p, a = c.ctx(project_id, analysis_id)
    ids = [_defect_num(x) for x in _as_list(defect_ids)]
    s = _enum(SEVERITY, severity, "severity")
    c.update_severity(p, a, ids, s, comment)
    name = next(k for k, v in SEVERITY.items() if v == s).title()
    return f"Set {', '.join(f'VE-{i}' for i in ids)} severity to {name}" + (f" with comment: {comment}" if comment else "")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        c = client()
        c.login()
        print(f"Authenticated to {c.base} via {c.auth_mode}")
        sys.exit(0)
    mcp.run()
