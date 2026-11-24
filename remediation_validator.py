"""Independent validation of a candidate workspace. Deterministic; no LLM involved.

It never trusts what the remediation agent says it did. Every run:
  1. regenerates the SBOM from the workspace files,
  2. re-runs OSV (scanner or API) + threat intel, and the static anomaly inspector,
  3. rebuilds the attack tree, so every finding is re-scored by the risk engine,
  4. compares findings with the pristine baseline and the previous iteration (resolved / still present / new),
  5. checks dependency-graph consistency (manifest vs lockfile vs overrides),
  6. verifies that each recorded change is really present in the files and the resolved tree,
  7. optionally runs the project's tests in a Docker sandbox.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

import threat_intel
from attack_tree import AttackTree
from models import Finding, Sbom, StaticAnomaly
from scanners import run_cdxgen, run_osv_scanner, run_static_supply_chain_inspector
from versions import satisfies
from workspace import LOCKFILES, Change, Workspace, run_tests_sandboxed, sha256

LogFn = Callable[[str, str, str], None]


class FindingState(BaseModel):
    key: str
    title: str
    kind: str
    package: Optional[str] = None
    version: Optional[str] = None
    advisory: Optional[str] = None
    severity: str
    score: int


class ChangeCheck(BaseModel):
    change_id: str
    ok: bool
    detail: str


class ValidationResult(BaseModel):
    iteration: int
    ran_at: float = Field(default_factory=time.time)
    seconds: float = 0.0
    sbom_source: str = ""
    components: int = 0
    vuln_source: str = ""
    findings: List[FindingState] = Field(default_factory=list)
    resolved_vs_baseline: List[str] = Field(default_factory=list)       # keys
    resolved_this_iteration: List[str] = Field(default_factory=list)
    still_present: List[str] = Field(default_factory=list)
    new_vs_baseline: List[FindingState] = Field(default_factory=list)
    risk: Dict[str, Any] = Field(default_factory=dict)
    graph_consistency: Dict[str, Any] = Field(default_factory=dict)
    changes_verified: List[ChangeCheck] = Field(default_factory=list)
    tests: Dict[str, Any] = Field(default_factory=dict)
    verdict: str = "baseline"            # baseline | improved | no_change | regressed | error
    notes: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


def finding_key(f: Finding, anomalies: List[StaticAnomaly]) -> str:
    """Version-independent identity: an upgraded package keeps its key, so the finding shows as resolved."""
    if f.kind == "vulnerability":
        return f"vuln|{f.package}|{f.advisory_ids[0] if f.advisory_ids else ''}"
    a = next((x for x in anomalies if f.advisory_ids and x.id == f.advisory_ids[0]), None)
    if a is not None:
        return f"anomaly|{a.kind.value}|{a.file}|{a.id}"
    return f"{f.kind}|{f.package}|{f.title[:60]}"


def scan_tree(path: Path, log: LogFn, resolve_lockfile: bool = True) -> Dict[str, Any]:
    """The full deterministic pipeline on a directory (no LLM, no cards)."""
    sbom, imports = run_cdxgen(path, log, use_cache=False, resolve_lockfile=resolve_lockfile)
    vulns, src = run_osv_scanner(sbom, log)
    threat_intel.enrich(vulns, log)
    anomalies = run_static_supply_chain_inspector(path, None, "HEAD~1", log)
    tree = AttackTree(path, sbom, imports, vulns, anomalies, log).build()
    return {"sbom": sbom, "imports": imports, "vulns": vulns, "vuln_source": src, "anomalies": anomalies, "tree": tree}


def states_of(scan: Dict[str, Any]) -> List[FindingState]:
    out = []
    for f in scan["tree"].findings.values():
        out.append(FindingState(key=finding_key(f, scan["anomalies"]), title=f.title[:140], kind=f.kind, package=f.package,
                                version=f.version, advisory=f.advisory_ids[0] if f.advisory_ids else None,
                                severity=f.risk.severity.value, score=f.risk.total))
    return out


def risk_summary(states: List[FindingState]) -> Dict[str, Any]:
    by: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in states:
        by[s.severity] = by.get(s.severity, 0) + 1
    return {"max": max((s.score for s in states), default=0), "total": sum(s.score for s in states),
            "count": len(states), "by_severity": by}


def check_graph_consistency(ws: Workspace, sbom: Sbom) -> Dict[str, Any]:
    problems: List[str] = []
    manifest = json.loads(ws.read("package.json") or "{}")
    declared: Dict[str, str] = {}
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        declared.update({k: str(v) for k, v in (manifest.get(sec) or {}).items()})
    lock_text = ws.read("package-lock.json", 60_000_000)
    if lock_text:
        try:
            lock = json.loads(lock_text)
        except ValueError:
            return {"ok": False, "problems": ["package-lock.json is not valid JSON"]}
        pk = lock.get("packages") or {}
        root = pk.get("", {})
        root_decl = {**(root.get("dependencies") or {}), **(root.get("devDependencies") or {}), **(root.get("optionalDependencies") or {})}
        for name, spec in declared.items():
            if root_decl.get(name) != spec:
                problems.append(f"lockfile root does not match package.json for {name} ({root_decl.get(name)!r} vs {spec!r})")
            entry = pk.get(f"node_modules/{name}")
            if entry is None:
                if not spec.startswith(("file:", "link:", "git", "http", "github:")):
                    problems.append(f"{name} is declared but missing from the lockfile")
            elif satisfies("npm", str(entry.get("version", "")), spec) is False:
                problems.append(f"{name}@{entry.get('version')} in the lockfile does not satisfy {spec}")
        for name, ver in (manifest.get("overrides") or {}).items():
            if not isinstance(ver, str):
                continue
            bad = [k for k, v in pk.items() if k.endswith(f"node_modules/{name}") and v.get("version") != ver.lstrip("=")]
            if bad:
                problems.append(f"override {name}={ver} not honoured at {', '.join(bad[:3])}")
    else:
        comps = {c.name for c in sbom.components if c.is_direct}
        missing = [n for n in declared if n not in comps]
        if missing:
            problems.append(f"declared but not in the SBOM: {', '.join(missing[:5])}")
    return {"ok": not problems, "problems": problems[:20], "checked": "lockfile" if lock_text else "manifest/SBOM"}


def verify_changes(ws: Workspace, changes: List[Change], sbom: Sbom) -> List[ChangeCheck]:
    manifest = json.loads(ws.read("package.json") or "{}")
    lock = {}
    try:
        lock = json.loads(ws.read("package-lock.json", 60_000_000) or "{}")
    except ValueError:
        pass
    pk = lock.get("packages") or {}
    by_name: Dict[str, List[str]] = {}
    for c in sbom.components:
        by_name.setdefault(c.name, []).append(c.version)
    out: List[ChangeCheck] = []
    applied = [c for c in changes if c.status == "applied"]
    # the last change that sets the same thing wins; earlier ones are superseded, not ineffective
    last_setter: Dict[tuple, str] = {}
    for ch in applied:
        for op in ch.ops:
            last_setter[(op["op"], op.get("name") or op.get("path"))] = ch.change_id
    for ch in applied:
        problems: List[str] = []
        superseded = []
        for op in ch.ops:
            k = op["op"]
            owner = last_setter.get((k, op.get("name") or op.get("path")))
            if owner and owner != ch.change_id and k in ("set_dependency", "set_override"):
                superseded.append(f"{op.get('name')} superseded by {owner}")
                continue
            if k == "set_dependency":
                sec = op.get("section") or next((s for s in ("dependencies", "devDependencies", "optionalDependencies")
                                                 if op["name"] in (manifest.get(s) or {})), "dependencies")
                if (manifest.get(sec) or {}).get(op["name"]) != op["version"]:
                    problems.append(f"package.json does not declare {op['name']}@{op['version']}")
                got = by_name.get(op["name"], [])
                if got and not any(satisfies("npm", v, op["version"]) for v in got):
                    problems.append(f"resolved tree has {op['name']}@{', '.join(sorted(set(got)))}, not {op['version']}")
            elif k == "set_override":
                if (manifest.get("overrides") or {}).get(op["name"]) != op["version"]:
                    problems.append(f"override {op['name']} missing from package.json")
                got = by_name.get(op["name"], [])
                stale = sorted({v for v in got if satisfies("npm", v, op["version"]) is False})
                if stale:
                    problems.append(f"{op['name']} still resolves to {', '.join(stale)} despite the override")
            elif k == "remove_dependency":
                if any(op["name"] in (manifest.get(s) or {}) for s in ("dependencies", "devDependencies", "optionalDependencies")):
                    problems.append(f"{op['name']} is still declared")
                if pk.get(f"node_modules/{op['name']}"):
                    problems.append(f"{op['name']} is still in the lockfile")
            elif k == "delete_script":
                if op["name"] in (manifest.get("scripts") or {}):
                    problems.append(f"script {op['name']} still present")
            elif k == "replace_text":
                text = ws.read(op["path"]) or ""
                if op["new"] not in text:
                    problems.append(f"new text not found in {op['path']}")
            elif k == "restore_from_git":
                cur = ws.read(op["path"], 60_000_000)
                if cur is None:
                    problems.append(f"{op['path']} missing")
        out.append(ChangeCheck(change_id=ch.change_id, ok=not problems,
                               detail="; ".join(problems) if problems else
                               ("; ".join(superseded) if superseded else "present in files and resolved tree")))
    return out


def validate(ws: Workspace, iteration: int, log: LogFn, baseline: Optional[ValidationResult] = None,
             previous: Optional[ValidationResult] = None, changes: Optional[List[Change]] = None,
             run_tests: bool = False, out: Optional[Dict[str, Any]] = None) -> ValidationResult:
    t0 = time.time()
    res = ValidationResult(iteration=iteration)
    log("validator-agent", f"iteration {iteration}: independent re-scan of the candidate workspace", "tool")
    try:
        scan = scan_tree(ws.path, log)
    except Exception as exc:  # noqa: BLE001 - report, never crash the session
        res.verdict, res.errors = "error", [f"scan failed: {type(exc).__name__}: {str(exc)[:300]}"]
        res.seconds = round(time.time() - t0, 1)
        return res
    if out is not None:
        out["scan"] = scan
    res.sbom_source, res.components, res.vuln_source = scan["sbom"].source, len(scan["sbom"].components), scan["vuln_source"]
    res.findings = states_of(scan)
    res.risk = risk_summary(res.findings)
    res.graph_consistency = check_graph_consistency(ws, scan["sbom"])
    res.changes_verified = verify_changes(ws, changes or [], scan["sbom"])
    if run_tests:
        log("validator-agent", "running tests in the Docker sandbox (network off for the test step)", "tool")
        res.tests = run_tests_sandboxed(ws)
    else:
        res.tests = {"status": "skipped", "reason": "sandboxed tests not enabled for this session"}
    keys = {s.key for s in res.findings}
    if baseline is not None:
        base_keys = {s.key for s in baseline.findings}
        res.resolved_vs_baseline = sorted(base_keys - keys)
        res.still_present = sorted(base_keys & keys)
        res.new_vs_baseline = [s for s in res.findings if s.key not in base_keys]
    if previous is not None:
        res.resolved_this_iteration = sorted({s.key for s in previous.findings} - keys)
    if res.vuln_source == "demo":
        res.notes.append("advisories are built-in demo data (offline)")
    if not res.graph_consistency.get("ok", True):
        res.notes.append("graph inconsistency: " + "; ".join(res.graph_consistency["problems"][:3]))
    bad = [c.change_id for c in res.changes_verified if not c.ok]
    if bad:
        res.notes.append(f"changes not effective: {', '.join(bad)}")
    if res.tests.get("status") == "failed":
        res.notes.append("tests failed in the sandbox")
    if baseline is None:
        res.verdict = "baseline"
    else:
        prev = previous or baseline
        worse = [s for s in res.new_vs_baseline if s.severity in ("CRITICAL", "HIGH")]
        if worse or res.risk["max"] > prev.risk.get("max", 0) or res.tests.get("status") == "failed":
            res.verdict = "regressed"
        elif res.resolved_this_iteration or res.risk["total"] < prev.risk.get("total", 0):
            res.verdict = "improved"
        else:
            res.verdict = "no_change"
    res.seconds = round(time.time() - t0, 1)
    log("validator-agent", f"iteration {iteration}: {len(res.findings)} findings, max risk {res.risk['max']}, "
                           f"resolved {len(res.resolved_vs_baseline)} vs baseline, {len(res.new_vs_baseline)} new, "
                           f"graph {'ok' if res.graph_consistency.get('ok') else 'INCONSISTENT'}, "
                           f"tests {res.tests.get('status')}, verdict {res.verdict}",
        "success" if res.verdict in ("improved", "baseline") else "warn")
    return res
