"""Multi-source mitigation candidates + deterministic Human Validation Gate (Day 2, objective 3).

Candidates are aggregated from:
  OSV_SCANNER      fixed versions from the OSV record (osv-scanner or the OSV.dev API)
  GHSA             GitHub Security Advisory: first patched version + upstream fix commit
  CSV_FEED         organisation-curated overrides (advisory_overrides.csv in the Guardian's own folder;
                   never read from the scanned repository, which could plant "trusted" versions)
  CHANGELOG_DIFF   release notes / changelog: security fixes and BREAKING / REMOVED / DEPRECATED entries
  CONTEXTUAL_RULE  attack-tree context: move test-only deps, restore a tampered lockfile, pin images
                   and actions, block malicious or typosquatted packages

Every number here is computed in Python. The LLM may only write `ai_tradeoff_summary`, and
`validate_tradeoff_summary` rejects any version, candidate id or gate decision it did not get from us.

The Human Validation Gate is mandatory when:
  1. no automated fix exists (ESCALATE_FOR_REVIEW),
  2. the top candidate is a MAJOR SemVer bump (a 0.x minor bump counts as major, as npm's caret does),
  3. release notes flag breaking changes that mention symbols the app actually calls,
  4. the fix means applying a raw upstream patch commit,
  5. the two best candidates are within 10 fit points of each other.
Otherwise the top candidate is auto-approved by the Python policy. Approval records intent only:
the Guardian is read-only and never applies a fix itself.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime, timezone
from enum import Enum
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from remediation import cmd_override, cmd_refresh, cmd_remove, cmd_upgrade
from versions import V, cmp as vcmp, satisfies


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class MitigationAction(str, Enum):
    UPGRADE_TO_SAFER = "UPGRADE_TO_SAFER"
    APPLY_UPSTREAM_PATCH = "APPLY_UPSTREAM_PATCH"
    MOVE_DEPENDENCY = "MOVE_DEPENDENCY"
    POINT_TO_TRUSTED_VERSION = "POINT_TO_TRUSTED_VERSION"
    UPDATE_BASE_IMAGE = "UPDATE_BASE_IMAGE"
    BLOCK_UNSAFE_COMPONENT = "BLOCK_UNSAFE_COMPONENT"
    ESCALATE_FOR_REVIEW = "ESCALATE_FOR_REVIEW"


class CompatibilityRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class HumanDecisionType(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED_ESCALATED = "REJECTED_ESCALATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


CandidateSource = Literal["OSV_SCANNER", "GHSA", "CSV_FEED", "CHANGELOG_DIFF", "CONTEXTUAL_RULE"]
SemverJump = Literal["PATCH", "MINOR", "MAJOR", "PATCH_COMMIT", "CONFIG_ONLY"]


class CandidateMitigation(BaseModel):
    candidate_id: str
    source: CandidateSource
    also_reported_by: List[str] = Field(default_factory=list)
    action_type: MitigationAction
    target_version_or_ref: str
    semver_jump: SemverJump
    breaking_changes: List[str] = Field(default_factory=list)
    affects_called_symbols: List[str] = Field(default_factory=list)
    version_diff_notes: str = ""
    compatibility_risk: CompatibilityRisk
    fixes_all_advisories: bool = True
    fit_score: int = Field(ge=0, le=100)
    fit_breakdown: List[str] = Field(default_factory=list)
    apply_command: str
    rollback_command: str


class HumanValidationRecord(BaseModel):
    decision: HumanDecisionType = HumanDecisionType.PENDING
    chosen_candidate_id: Optional[str] = None
    reviewer: Optional[str] = None
    justification: Optional[str] = None
    decided_at: Optional[str] = None


class MitigationDecisionPackage(BaseModel):
    finding_id: str
    stable_key: str = ""                 # survives re-scans (finding ids are renumbered)
    package_name: str
    current_version: str
    risk_score: int                      # from risk_engine (0-100)
    is_production: bool
    requires_human_validation: bool
    escalation_reasons: List[str] = Field(default_factory=list)
    recommended_candidate_id: Optional[str] = None
    candidates: List[CandidateMitigation] = Field(default_factory=list)
    ai_tradeoff_summary: str = ""
    summary_author: Literal["llm", "deterministic"] = "deterministic"
    summary_validation_errors: List[str] = Field(default_factory=list)
    context_sources: List[str] = Field(default_factory=list)   # what was consulted, for the audit trail
    human_validation: HumanValidationRecord = Field(default_factory=HumanValidationRecord)


class ValidationRequest(BaseModel):
    finding_id: str = Field(max_length=32)
    decision: HumanDecisionType
    chosen_candidate_id: Optional[str] = Field(default=None, max_length=64)
    reviewer: str = Field(max_length=80)
    justification: str = Field(default="", max_length=2000)


# --------------------------------------------------------------------------- #
# Deterministic helpers
# --------------------------------------------------------------------------- #
SAFE_COMMAND_PREFIXES = ("npm install --ignore-scripts", "npm uninstall --ignore-scripts", "npm ci --ignore-scripts",
                         "npm update --ignore-scripts ", "npm pkg set overrides.", 'npm pkg set "overrides[',
                         "git checkout ", "git ls-remote ", "docker buildx imagetools inspect ", "pip install --no-deps ",
                         "pip uninstall -y ", "uv lock --upgrade-package ", "# ")
SAFE_CHAINS = (" && npm ci --ignore-scripts", " && npm install --ignore-scripts")
VERSION_OK = re.compile(r"^v?\d+(\.\d+){0,3}([-+][0-9A-Za-z.-]{1,40})?$")
NAME_OK = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$|^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def is_safe_command(cmd: str) -> bool:
    """Same policy as the Post-Check Validator: allow-listed prefix, scripts off, no shell metacharacters."""
    cmd = cmd.strip()
    head = cmd
    for s in SAFE_CHAINS:
        if head.endswith(s):
            head = head[: -len(s)]
            break
    if not cmd.startswith(SAFE_COMMAND_PREFIXES):
        return False
    if cmd.startswith("# "):
        return not re.search(r"[`]|\$\(", cmd)
    return not re.search(r"[;|`&<>]|\$\(", head)


def _vkey(v: str) -> Any:
    return cmp_to_key(vcmp)(v)


def semver_jump(current: str, target: str) -> SemverJump:
    a = (V(current).nums + (0, 0, 0))[:3]
    b = (V(target).nums + (0, 0, 0))[:3]
    if a[0] != b[0]:
        return "MAJOR"
    if a[0] == 0 and a[1] != b[1]:
        return "MAJOR"                    # 0.x: npm's ^0.y range treats a minor bump as breaking
    if a[1] != b[1]:
        return "MINOR"
    return "PATCH"


_HEADING = re.compile(r"^\s{0,3}#{1,4}\s*\[?v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)\]?", re.M)
_BREAKING = re.compile(r"BREAKING[ _-]?CHANGES?|\bREMOVED\b|\bDEPRECATED\b|\bremoved\b|\bdeprecated\b|\bno longer\b", re.I)
_SECURITY = re.compile(r"\bsecurity\b|\bCVE-\d{4}-\d+|\bGHSA-[\w-]+|\bvulnerab", re.I)


def changelog_sections(text: str) -> List[Tuple[str, str]]:
    """[(version, section text)] from markdown changelogs / composed release notes."""
    marks = [(m.start(), m.group(1)) for m in _HEADING.finditer(text or "")]
    out = []
    for i, (pos, ver) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append((ver, text[pos:end]))
    return out


def scan_version_diff(text: str, current: str, target: str, called_symbols: Iterable[str]) -> Tuple[List[str], List[str], str]:
    """Breaking-change lines between current (exclusive) and target (inclusive), and which called symbols they name."""
    called = sorted({s for s in called_symbols if s and s != "<default>" and re.fullmatch(r"[A-Za-z_$][\w$]{1,60}", s)})
    breaking: List[str] = []
    hits: List[str] = []
    versions_seen: List[str] = []
    for ver, body in changelog_sections(text):
        try:
            if not (vcmp(ver, current) > 0 and vcmp(ver, target) <= 0):
                continue
        except (ValueError, TypeError):
            continue
        versions_seen.append(ver)
        for line in body.splitlines():
            if _BREAKING.search(line):
                entry = f"{ver}: {line.strip().lstrip('-*# ').strip()[:180]}"
                if entry not in breaking:
                    breaking.append(entry)
                for sym in called:
                    if re.search(rf"(?<![\w$]){re.escape(sym)}(?![\w$])", line) and sym not in hits:
                        hits.append(sym)
    if not text:
        notes = "no release notes / changelog available: compatibility judged from SemVer only"
    elif not versions_seen:
        notes = f"release notes found, but no entries between {current} and {target}"
    else:
        notes = (f"read release notes for {len(versions_seen)} version(s) between {current} and {target}: "
                 f"{len(breaking)} breaking/removal/deprecation line(s)"
                 + (f", naming symbols this app calls: {', '.join(hits)}" if hits else ""))
    return breaking[:12], hits, notes


def compatibility_for(jump: SemverJump, breaking: Sequence[str], hits: Sequence[str]) -> CompatibilityRisk:
    if jump == "MAJOR" or hits:
        return CompatibilityRisk.HIGH
    if jump == "PATCH_COMMIT" or breaking:
        return CompatibilityRisk.MEDIUM
    return CompatibilityRisk.LOW


MAX_CANDIDATES = 5
JUMP_PENALTY = {"CONFIG_ONLY": 5, "PATCH": 0, "MINOR": 10, "MAJOR": 35, "PATCH_COMMIT": 25}
COMPAT_PENALTY = {CompatibilityRisk.LOW: 0, CompatibilityRisk.MEDIUM: 10, CompatibilityRisk.HIGH: 20}


def fit_score_for(c: CandidateMitigation) -> Tuple[int, List[str]]:
    """0-100: how well this candidate removes the risk with the least disruption. Pure arithmetic."""
    if c.action_type == MitigationAction.ESCALATE_FOR_REVIEW:
        return 20, ["fixed 20: no automated remediation; a person has to decide"]
    score, why = 100, ["start 100"]

    def add(points: int, reason: str) -> None:
        nonlocal score
        if points:
            score += points
            why.append(f"{points:+d} {reason}")

    add(-JUMP_PENALTY[c.semver_jump], f"{c.semver_jump} change")
    add(-COMPAT_PENALTY[c.compatibility_risk], f"{c.compatibility_risk.value} compatibility risk")
    add(-min(15, 5 * len(c.breaking_changes)), f"{len(c.breaking_changes)} breaking/removal note(s) in the release notes")
    add(-min(30, 15 * len(c.affects_called_symbols)), "breaking change names a symbol the app calls")
    if not c.fixes_all_advisories:
        add(-30, "does not clear every advisory on this package version")
    if c.source == "CSV_FEED":
        add(5, "organisation-approved override (CSV feed)")
    if len({c.source, *c.also_reported_by}) >= 2:
        add(5, "corroborated by more than one source")
    return max(0, min(100, score)), why


def load_csv_overrides(path: Optional[str], package: str, current: str) -> List[Dict[str, str]]:
    """Rows: package,current_version,target_version,action,notes. current_version may be '*' or an npm range."""
    if not path or not Path(path).is_file():
        return []
    rows: List[Dict[str, str]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if (row.get("package") or "").strip() != package:
                continue
            cur = (row.get("current_version") or "*").strip()
            if cur not in ("*", "") and cur != current and satisfies("npm", current, cur) is not True:
                continue
            target = (row.get("target_version") or "").strip()
            action = (row.get("action") or "UPGRADE_TO_SAFER").strip().upper()
            if action not in MitigationAction.__members__:
                continue
            if action == "UPGRADE_TO_SAFER" and not VERSION_OK.match(target):
                continue
            if action == "POINT_TO_TRUSTED_VERSION" and target and not (VERSION_OK.match(target) or NAME_OK.match(target)):
                continue
            rows.append({"target": target, "action": action, "notes": (row.get("notes") or "").strip()[:200]})
    return rows


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def _upgrade_commands(eco: str, name: str, current: str, target: str, is_direct: bool, declared_spec: Optional[str],
                      parent_specs: Sequence[Optional[str]], has_lockfile: bool) -> Tuple[str, str, str]:
    """(apply, rollback, how) for moving `name` to `target` given the declared ranges in the graph."""
    restore = "git checkout -- package.json" + (" package-lock.json" if has_lockfile else "")
    if is_direct:
        if declared_spec and satisfies(eco, target, declared_spec) is True and has_lockfile:
            return cmd_refresh(eco, [name]), restore, f"declared range {declared_spec} already allows {target}: refresh the lockfile"
        return cmd_upgrade(eco, name, target), cmd_upgrade(eco, name, current), "upgrade the direct dependency"
    specs = [s for s in parent_specs if s]
    if specs and len(specs) == len(parent_specs) and all(satisfies(eco, target, s) is True for s in specs) and has_lockfile:
        return cmd_refresh(eco, [name]), restore, "every parent range already allows it: refresh the lockfile"
    return cmd_override(eco, [(name, target)]), restore, "a parent range blocks it: force it with an override"


def build_mitigation_options(
    *,
    finding_id: str,
    package_name: str,
    current_version: str,
    risk_score: int,
    is_production: bool,
    ecosystem: str = "npm",
    osv_fixed_versions: Sequence[str] = (),
    required_fixed_version: Optional[str] = None,
    ghsa_data: Optional[Dict[str, Any]] = None,
    csv_override_path: Optional[str] = None,
    changelog_text: str = "",
    called_symbols: Iterable[str] = (),
    anomaly_type: Optional[str] = None,
    is_direct: bool = True,
    declared_spec: Optional[str] = None,
    parent_specs: Sequence[Optional[str]] = (),
    has_lockfile: bool = True,
    test_only_usage: bool = False,
    artifact_file: Optional[str] = None,
    artifact_ref: Optional[str] = None,
    trusted_alternative: Optional[str] = None,
    stable_key: str = "",
    context_sources: Sequence[str] = (),
    advisory_count: int = 1,
) -> MitigationDecisionPackage:
    called = sorted(set(called_symbols))
    raw: List[Dict[str, Any]] = []      # pre-candidates; ids, compat and scores assigned below

    def add(source: str, action: MitigationAction, target: str, jump: SemverJump, apply: str, rollback: str,
            notes: str = "", breaking: Optional[List[str]] = None, hits: Optional[List[str]] = None,
            fixes_all: bool = True) -> None:
        for r in raw:   # dedupe by (action, target): keep the first source, record the rest
            if r["action"] == action and r["target"] == target:
                if source != r["source"] and source not in r["also"]:
                    r["also"].append(source)
                have = [x.strip() for x in r["notes"].split(";") if x.strip()]
                for part in (x.strip() for x in notes.split(";")):
                    if part and part not in have:
                        have.append(part)
                r["notes"] = "; ".join(have)
                return
        raw.append({"source": source, "also": [], "action": action, "target": target, "jump": jump, "apply": apply,
                    "rollback": rollback, "notes": notes, "breaking": breaking or [], "hits": hits or [],
                    "fixes_all": fixes_all})

    def add_upgrade(source: str, target: str, extra_note: str = "") -> None:
        if not VERSION_OK.match(target) or vcmp(target, current_version) <= 0:
            return
        jump = semver_jump(current_version, target)
        breaking, hits, diff_notes = scan_version_diff(changelog_text, current_version, target, called)
        apply, rollback, how = _upgrade_commands(ecosystem, package_name, current_version, target, is_direct,
                                                 declared_spec, parent_specs, has_lockfile)
        fixes_all = required_fixed_version is None or vcmp(target, required_fixed_version) >= 0
        note = f"{how}; {diff_notes}" + (f"; {extra_note}" if extra_note else "")
        if not fixes_all:
            note += f"; still below {required_fixed_version}, which another advisory requires"
        add(source, MitigationAction.UPGRADE_TO_SAFER, target, jump, apply, rollback, note, breaking, hits, fixes_all)

    # ---- known-vulnerability sources ------------------------------------------------- #
    if anomaly_type is None:
        for v in sorted(set(osv_fixed_versions), key=_vkey):
            add_upgrade("OSV_SCANNER", v)
        if required_fixed_version:
            add_upgrade("OSV_SCANNER", required_fixed_version, "lowest version that clears every advisory on this package")
        g = ghsa_data or {}
        if g.get("patched_version"):
            add_upgrade("GHSA", str(g["patched_version"]), f"GitHub advisory {g.get('id') or ''} ({g.get('source') or 'osv'})".strip())
        commit, url = g.get("upstream_patch_commit"), g.get("commit_url")
        if commit and url and re.fullmatch(r"[0-9a-f]{7,40}", str(commit)):
            add("GHSA", MitigationAction.APPLY_UPSTREAM_PATCH, f"commit {str(commit)[:12]}", "PATCH_COMMIT",
                f"# review first: apply {url}.patch to {package_name}@{current_version} with patch-package",
                f"# delete patches/{package_name.replace('/', '+')}+{current_version}.patch and reinstall",
                "backport of the upstream fix commit; keeps the current version but needs a code review"
                + (f"; fixes only this advisory, not the other {advisory_count - 1} on {package_name}@{current_version}"
                   if advisory_count > 1 else ""),
                fixes_all=advisory_count <= 1)
        # release notes that announce a security fix in a version OSV did not list
        for ver, body in changelog_sections(changelog_text):
            if _SECURITY.search(body) and VERSION_OK.match(ver) and vcmp(ver, current_version) > 0:
                add_upgrade("CHANGELOG_DIFF", ver, "release notes for this version mention a security fix")
                break
    for row in load_csv_overrides(csv_override_path, package_name, current_version):
        if row["action"] == "UPGRADE_TO_SAFER":
            add_upgrade("CSV_FEED", row["target"], row["notes"])
        elif row["action"] == "BLOCK_UNSAFE_COMPONENT":
            add("CSV_FEED", MitigationAction.BLOCK_UNSAFE_COMPONENT, f"remove {package_name}", "CONFIG_ONLY",
                cmd_remove(ecosystem, package_name), cmd_upgrade(ecosystem, package_name, current_version), row["notes"])
        elif row["action"] == "ESCALATE_FOR_REVIEW":
            add("CSV_FEED", MitigationAction.ESCALATE_FOR_REVIEW, "security review", "CONFIG_ONLY",
                f"# escalate {package_name}@{current_version}: {row['notes'] or 'organisation policy'}", "# no change made",
                row["notes"])

    # ---- attack-tree contextual rules ------------------------------------------------- #
    restore = "git checkout -- package.json" + (" package-lock.json" if has_lockfile else "")
    if anomaly_type is None and test_only_usage and is_production:
        add("CONTEXTUAL_RULE", MitigationAction.MOVE_DEPENDENCY, f"devDependencies ({package_name}@{current_version})",
            "CONFIG_ONLY", f"npm install --ignore-scripts --save-dev --save-exact {package_name}@{current_version}", restore,
            "only test code imports it: move it out of production installs (reduces exposure, does not remove the flaw)",
            fixes_all=False)
    imported_break = [f"removing {package_name} breaks code that calls: {', '.join(called[:6])}"] if called else []
    if anomaly_type in ("malicious", "nonexistent"):
        add("CONTEXTUAL_RULE", MitigationAction.BLOCK_UNSAFE_COMPONENT, f"remove {package_name}", "CONFIG_ONLY",
            cmd_remove(ecosystem, package_name), "# do not reinstall a malicious package; restore only after review",
            "known malicious or non-existent package: remove it and rotate any secrets it could read",
            breaking=imported_break, hits=called[:6])
    elif anomaly_type == "typosquat":
        add("CONTEXTUAL_RULE", MitigationAction.BLOCK_UNSAFE_COMPONENT, f"do not install {package_name}", "CONFIG_ONLY",
            f"# blocked: do not install {package_name}@{current_version}", "# nothing to roll back (never installed)",
            "the pre-install gate blocks it")
        if trusted_alternative and NAME_OK.match(trusted_alternative):
            add("CONTEXTUAL_RULE", MitigationAction.POINT_TO_TRUSTED_VERSION, trusted_alternative, "CONFIG_ONLY",
                f"npm install --ignore-scripts {trusted_alternative}", f"npm uninstall --ignore-scripts {trusted_alternative}",
                f"the popular package this name imitates; confirm it is the one you meant")
    elif anomaly_type == "tamper":
        lock = artifact_file or "package-lock.json"
        add("CONTEXTUAL_RULE", MitigationAction.POINT_TO_TRUSTED_VERSION, f"{lock} @ HEAD~1", "CONFIG_ONLY",
            f"git checkout HEAD~1 -- {lock} && npm ci --ignore-scripts", f"git checkout HEAD -- {lock}",
            "restore the last trusted lockfile and verify the registry tarball out of band")
    elif anomaly_type in ("docker_latest_tag", "docker_untrusted_registry") and artifact_ref:
        add("CONTEXTUAL_RULE", MitigationAction.UPDATE_BASE_IMAGE, f"{artifact_ref}@sha256:<digest>", "CONFIG_ONLY",
            f"docker buildx imagetools inspect {artifact_ref} --format '{{{{json .Manifest.Digest}}}}'",
            f"git checkout -- {artifact_file or 'Dockerfile'}",
            "resolve the digest, then pin FROM to it" + (" and move to a trusted registry" if anomaly_type == "docker_untrusted_registry" else ""))
    elif anomaly_type == "workflow_unpinned_action" and artifact_ref:
        repo = "/".join(artifact_ref.split("@")[0].split("/")[:2])
        add("CONTEXTUAL_RULE", MitigationAction.POINT_TO_TRUSTED_VERSION, f"{repo}@<40-char SHA>", "CONFIG_ONLY",
            f"git ls-remote https://github.com/{repo} {artifact_ref.split('@')[-1]}",
            f"git checkout -- {artifact_file or '.github/workflows'}", "pin the action to the commit SHA the tag points to")
    elif anomaly_type in ("suspicious_hook", "docker_pipe_to_shell", "admission_signals"):
        add("CONTEXTUAL_RULE", MitigationAction.ESCALATE_FOR_REVIEW, "security review", "CONFIG_ONLY",
            f"# escalate: review {artifact_file or package_name} before the next install/build", "# no change made",
            "behaviour-level risk: a person has to judge intent")

    if not raw:
        add("CONTEXTUAL_RULE", MitigationAction.ESCALATE_FOR_REVIEW, "security review", "CONFIG_ONLY",
            f"# escalate: no published fix for {package_name}@{current_version}; replace, isolate or accept with review",
            "# no change made", "no fixed version or patch is available from any source")

    # ---- score, rank, gate ------------------------------------------------------------ #
    cands: List[CandidateMitigation] = []
    for i, r in enumerate(raw, 1):
        c = CandidateMitigation(
            candidate_id=f"{finding_id}-C{i}", source=r["source"], also_reported_by=r["also"], action_type=r["action"],
            target_version_or_ref=r["target"], semver_jump=r["jump"], breaking_changes=r["breaking"],
            affects_called_symbols=r["hits"], version_diff_notes=r["notes"],
            compatibility_risk=compatibility_for(r["jump"], r["breaking"], r["hits"]), fixes_all_advisories=r["fixes_all"],
            fit_score=0, apply_command=r["apply"], rollback_command=r["rollback"])
        c.fit_score, c.fit_breakdown = fit_score_for(c)
        if not (is_safe_command(c.apply_command) and is_safe_command(c.rollback_command)):
            continue        # never surface a command outside the allow-list
        cands.append(c)
    order = {"PATCH": 0, "CONFIG_ONLY": 1, "MINOR": 2, "PATCH_COMMIT": 3, "MAJOR": 4}
    cands.sort(key=lambda c: (-c.fit_score, order[c.semver_jump], c.candidate_id))
    if len(cands) > MAX_CANDIDATES:
        # keep the best few, and always the best one that clears every advisory
        keep = cands[:MAX_CANDIDATES]
        full = next((c for c in cands if c.fixes_all_advisories and c.action_type == MitigationAction.UPGRADE_TO_SAFER), None)
        if full and full not in keep:
            keep = keep[:-1] + [full]
        dropped = len(cands) - len(keep)
        cands = sorted(keep, key=lambda c: (-c.fit_score, order[c.semver_jump], c.candidate_id))
        context_sources = [*context_sources, f"{dropped} lower-fit candidate(s) not shown (partial fixes)"]

    top = cands[0] if cands else None
    reasons: List[str] = []
    automated = [c for c in cands if c.action_type != MitigationAction.ESCALATE_FOR_REVIEW]
    if not automated:
        reasons.append("no automated fix exists: escalation for review")
    if top and top.semver_jump == "MAJOR":
        reasons.append(f"recommended fix is a MAJOR version change ({current_version} -> {top.target_version_or_ref})")
    if top and top.affects_called_symbols:
        reasons.append("release notes flag breaking changes in symbols this app calls: " + ", ".join(top.affects_called_symbols))
    if top and top.action_type == MitigationAction.APPLY_UPSTREAM_PATCH:
        reasons.append("fix requires applying a raw upstream patch commit")
    if len(automated) >= 2 and automated[0].fit_score - automated[1].fit_score < 10:
        reasons.append(f"two close candidates ({automated[0].candidate_id} fit {automated[0].fit_score}, "
                       f"{automated[1].candidate_id} fit {automated[1].fit_score}): a person should choose")
    needs_human = bool(reasons)

    pkg = MitigationDecisionPackage(
        finding_id=finding_id, stable_key=stable_key, package_name=package_name, current_version=current_version,
        risk_score=risk_score, is_production=is_production, requires_human_validation=needs_human,
        escalation_reasons=reasons, recommended_candidate_id=top.candidate_id if top else None, candidates=cands,
        context_sources=list(context_sources))
    if not needs_human and top:
        pkg.human_validation = HumanValidationRecord(
            decision=HumanDecisionType.APPROVED, chosen_candidate_id=top.candidate_id, reviewer="python-policy (auto)",
            justification=f"auto-approved: {top.semver_jump} change, {top.compatibility_risk.value} compatibility risk, "
                          f"no breaking changes on called symbols, fit {top.fit_score}/100 with no close alternative",
            decided_at=_now())
    pkg.ai_tradeoff_summary = deterministic_tradeoff_summary(pkg)
    return pkg


# --------------------------------------------------------------------------- #
# Summaries and the LLM guard
# --------------------------------------------------------------------------- #
def deterministic_tradeoff_summary(pkg: MitigationDecisionPackage) -> str:
    if not pkg.candidates:
        return f"No mitigation candidates for {pkg.package_name}@{pkg.current_version}."
    top = next(c for c in pkg.candidates if c.candidate_id == pkg.recommended_candidate_id)
    alt = next((c for c in pkg.candidates if c is not top and c.action_type != MitigationAction.ESCALATE_FOR_REVIEW), None)
    s = (f"{top.candidate_id} ({top.action_type.value.lower().replace('_', ' ')} to {top.target_version_or_ref}) "
         f"is the best fit at {top.fit_score}/100: a {top.semver_jump} change with {top.compatibility_risk.value} compatibility risk.")
    if alt:
        s += (f" The alternative {alt.candidate_id} ({alt.target_version_or_ref}) scores {alt.fit_score}/100"
              + (" because it does not clear every advisory." if not alt.fixes_all_advisories else
                 f" as a {alt.semver_jump} change with {alt.compatibility_risk.value} compatibility risk."))
    s += (" Human validation is required: " + "; ".join(pkg.escalation_reasons) + "."
          if pkg.requires_human_validation else " The Python policy auto-approved it as a safe change.")
    return s


_VERSION_TOKEN = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)(?![\w])")
_CAND_TOKEN = re.compile(r"\b[A-Z]+-\d{3}-C\d+\b")
_NO_REVIEW = re.compile(r"(?i)auto[- ]?approv|no (?:human )?(?:review|validation|approval) (?:is )?(?:needed|required)|"
                        r"safe to (?:apply|merge|deploy) (?:automatically|without review)|does not (?:need|require) (?:human )?review")
_NEEDS_REVIEW = re.compile(r"(?i)(?:human|manual) (?:review|validation|approval) (?:is )?(?:required|needed|mandatory)")


def validate_tradeoff_summary(text: str, pkg: MitigationDecisionPackage,
                              llm_gate_claim: Optional[bool] = None) -> List[str]:
    """Deterministic post-check of an LLM trade-off summary. Empty list = accepted."""
    errs: List[str] = []
    t = (text or "").strip()
    if not t:
        return ["summary is empty"]
    if len(t) > 900:
        errs.append("summary is longer than 900 characters")
    sentences = [x for x in re.split(r"(?<=[.!?])\s+", t) if x.strip()]
    if len(sentences) > 4:
        errs.append(f"summary has {len(sentences)} sentences (max 4)")
    allowed = {pkg.current_version.lstrip("v")}
    for c in pkg.candidates:
        allowed |= {m.group(1) for m in _VERSION_TOKEN.finditer(c.target_version_or_ref)}
    for m in _VERSION_TOKEN.finditer(t):
        if m.group(1) not in allowed:
            errs.append(f"cites version {m.group(1)}, which is not a candidate target or the current version")
    ids = {c.candidate_id for c in pkg.candidates}
    for m in _CAND_TOKEN.finditer(t):
        if m.group(0) not in ids:
            errs.append(f"cites unknown candidate {m.group(0)}")
    if llm_gate_claim is not None and llm_gate_claim != pkg.requires_human_validation:
        errs.append("tried to change requires_human_validation")
    if pkg.requires_human_validation and _NO_REVIEW.search(t):
        errs.append("claims no human review is needed, but the Python gate requires it")
    if not pkg.requires_human_validation and _NEEDS_REVIEW.search(t):
        errs.append("claims human review is required, but the Python gate auto-approved")
    return errs[:5]


# --------------------------------------------------------------------------- #
# Human decisions
# --------------------------------------------------------------------------- #
def record_human_decision(pkg: MitigationDecisionPackage, decision: HumanDecisionType | str, reviewer: str,
                          justification: str, chosen_candidate_id: Optional[str] = None) -> MitigationDecisionPackage:
    """Return a copy of `pkg` with a validated human decision. Raises ValueError on invalid input."""
    try:
        d = HumanDecisionType(decision)
    except ValueError as exc:
        raise ValueError(f"unknown decision {decision!r}") from exc
    if d == HumanDecisionType.PENDING:
        raise ValueError("a decision must be APPROVED, ACCEPTED_RISK or REJECTED_ESCALATED")
    who = (reviewer or "").strip()
    if len(who) < 2:
        raise ValueError("reviewer name is required")
    why = (justification or "").strip()
    chosen: Optional[str] = None
    if d == HumanDecisionType.APPROVED:
        cand = next((c for c in pkg.candidates if c.candidate_id == chosen_candidate_id), None)
        if cand is None:
            raise ValueError(f"chosen_candidate_id {chosen_candidate_id!r} is not one of this finding's candidates")
        if cand.action_type == MitigationAction.ESCALATE_FOR_REVIEW:
            raise ValueError("an escalation is not a fix: use REJECTED_ESCALATED instead")
        chosen = cand.candidate_id
    elif d == HumanDecisionType.ACCEPTED_RISK:
        if len(why) < 8:
            raise ValueError("accepting a risk needs a written justification of at least 8 characters")
    out = pkg.model_copy(deep=True)
    out.human_validation = HumanValidationRecord(decision=d, chosen_candidate_id=chosen, reviewer=who,
                                                 justification=why or None, decided_at=_now())
    return out
