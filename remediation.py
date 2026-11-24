"""Root-cause fix recommendations for OSV findings (ported from the Day-1 Guardian).

For every vulnerability finding we answer "why is this version installed and what
single change removes it?", using only verified data:

  * the fixed version of the affected range that contains the installed version
    (`Vulnerability.fixed_in`, computed from the OSV record's introduced/fixed events),
  * the dependency graph (`DependencyIndex`: parents, shortest path, introducing
    direct dependencies),
  * declared version ranges per edge (`Sbom.edge_specs`, from package.json and the lockfile).

Root causes:
  direct             direct dependency whose declared range excludes the fix  -> upgrade it
  direct-stale-lock  direct dependency whose range already allows the fix     -> refresh the lockfile
  stale-lock         transitive; every parent's range already allows the fix  -> refresh the lockfile
  blocked-by-parent  transitive; a parent's range excludes the fix            -> upgrade parent / override
  transitive         transitive; parent ranges not recorded (e.g. cdxgen)     -> upgrade parent / override
  parent-unknown     no recorded parent                                       -> pin via override
  no-fix             advisory lists no patched version                        -> replace / mitigate

Every command produced here starts with a prefix on the Post-Check Validator's
allow-list and never runs lifecycle scripts.
"""
from __future__ import annotations

from functools import cmp_to_key
from typing import Dict, Iterable, List, Optional, Tuple

from models import Finding, FixBlocker, FixGroup, FixRecommendation, Sbom, Severity, Vulnerability
from dep_graph import ROOT, DependencyIndex
from versions import cmp as version_cmp, satisfies

_SEV_RANK = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.LOW: 0}
OVERRIDE_HINT = {"npm": 'an "overrides" entry in package.json', "pypi": "a constraint (constraints.txt)"}


# --------------------------------------------------------------------------- #
# Commands (allow-listed prefixes only)
# --------------------------------------------------------------------------- #
def _override_key(name: str) -> str:
    # `npm pkg set` uses dot paths; names containing dots need the quoted bracket form.
    return f'"overrides[{name}]' if "." in name else f"overrides.{name}"


def _override_arg(name: str, to: str) -> str:
    key = _override_key(name)
    return f'{key}={to}"' if key.startswith('"') else f"{key}={to}"


def cmd_upgrade(eco: str, name: str, to: str) -> str:
    if eco == "pypi":
        return f"pip install --no-deps {name}=={to}"
    return f"npm install --ignore-scripts --save-exact {name}@{to}"


def cmd_refresh(eco: str, names: Iterable[str]) -> str:
    names = sorted(set(names))
    if eco == "pypi":
        return f"uv lock --upgrade-package {names[0]}"
    return "npm update --ignore-scripts " + " ".join(names)


def cmd_override(eco: str, pins: Iterable[Tuple[str, str]]) -> str:
    pins = sorted(set(pins))
    if eco == "pypi":
        name, to = pins[0]
        return f"pip install --no-deps {name}=={to}"
    return "npm pkg set " + " ".join(_override_arg(n, t) for n, t in pins) + " && npm install --ignore-scripts"


def cmd_remove(eco: str, name: str) -> str:
    return f"pip uninstall -y {name}" if eco == "pypi" else f"npm uninstall --ignore-scripts {name}"


def _vmax(versions: Iterable[Optional[str]]) -> Optional[str]:
    vs = [v for v in versions if v]
    return max(vs, key=cmp_to_key(version_cmp)) if vs else None


# --------------------------------------------------------------------------- #
# Per-finding root cause
# --------------------------------------------------------------------------- #
def recommend_fix(v: Vulnerability, sbom: Sbom, idx: DependencyIndex,
                  all_vulns: Iterable[Vulnerability] = ()) -> Optional[FixRecommendation]:
    comp = idx.comp.get(v.purl)
    if comp is None:
        return None
    eco, name = comp.ecosystem, comp.name
    path, intro = idx.path(v.purl), sorted(idx.introduced_by.get(v.purl, set()))
    base = {"path": path, "introduced_by": intro}

    if not v.fixed_in:
        return FixRecommendation(
            root_cause_kind="no-fix", kind="no-fix", target=name,
            explanation=f"{v.id} lists no patched version of {name} for {comp.version}.",
            action=f"No fixed version of {name} is published: replace it, isolate the vulnerable call, "
                   f"or accept the risk with a documented review.",
            command=cmd_remove(eco, name), **base)

    # Upgrading should clear every advisory on this exact package version at once.
    to = _vmax([v.fixed_in] + [x.fixed_in for x in all_vulns if x.purl == v.purl]) or v.fixed_in

    if idx.is_direct(v.purl) and v.purl not in idx.inferred:
        spec = sbom.edge_specs.get(ROOT, {}).get(v.purl)
        allows = satisfies(eco, to, spec)
        if allows:
            floor = comp.version_source in ("manifest-range-floor", "manifest-unresolvable")
            expl = (f"{name} is declared as `{spec}`, which already allows {to}, but "
                    + ("no lockfile is committed, so the scanned version is only the range floor; a fresh "
                       "resolve picks up the fix (re-scan with --resolve-lockfile to confirm)."
                       if floor else f"the lockfile pins {comp.version}."))
            return FixRecommendation(
                root_cause_kind="direct-stale-lock", kind="refresh-lockfile", target=name, to=to,
                declared_spec=spec, explanation=expl,
                action=f"Refresh the lockfile so {name} resolves to {to}+ (no package.json change needed).",
                command=cmd_refresh(eco, [name]), **base)
        why = (f"declared as `{spec}`, which does not allow {to}" if allows is False
               else f"declared directly{f' as `{spec}`' if spec else ''}")
        return FixRecommendation(
            root_cause_kind="direct", kind="upgrade-direct", target=name, to=to, declared_spec=spec,
            explanation=f"{name}@{comp.version} is a direct dependency ({why}).",
            action=f"Upgrade {name} from {comp.version} to {to} or later in package.json.",
            command=cmd_upgrade(eco, name, to), **base)

    parents = idx.parents(v.purl)
    if not parents:
        return FixRecommendation(
            root_cause_kind="parent-unknown", kind="pin", target=name, to=to,
            explanation=f"{name}@{comp.version} is in the SBOM but no package records depending on it.",
            action=f"Pin {name} to {to}+ with {OVERRIDE_HINT.get(eco, 'an explicit pin')}.",
            command=cmd_override(eco, [(name, to)]), **base)

    checks = []
    for p in parents:
        spec = sbom.edge_specs.get(p, {}).get(v.purl)
        checks.append(FixBlocker(parent=p, parent_label=idx.label(p), spec=spec, allows_fix=satisfies(eco, to, spec)))
    blockers = [c for c in checks if c.allows_fix is False]
    unknown = [c for c in checks if c.allows_fix is None]
    intro_names = [idx.comp[d].name for d in intro if d in idx.comp]

    if not blockers and not unknown:
        reqs = "; ".join(f"{c.parent_label} requires `{c.spec}`" for c in checks[:3])
        return FixRecommendation(
            root_cause_kind="stale-lock", kind="refresh-lockfile", target=name, to=to, parents=checks,
            explanation=f"Every parent already allows {name} {to}+ ({reqs}); the old version is only "
                        f"pinned by the lockfile.",
            action=f"Refresh the lockfile so {name} resolves to {to}+ (no package.json change needed).",
            command=cmd_refresh(eco, [name]), **base)

    if blockers:
        b = blockers[0]
        via: List[str] = []
        for x in blockers:
            via += [x.parent] if idx.is_direct(x.parent) else sorted(idx.introduced_by.get(x.parent, set()))
        target = ", ".join(sorted({idx.comp[d].name for d in via if d in idx.comp})) or b.parent_label.rsplit("@", 1)[0]
        bname = b.parent_label.rsplit("@", 1)[0]
        return FixRecommendation(
            root_cause_kind="blocked-by-parent", kind="upgrade-parent", target=target, to=to,
            parents=checks, blockers=blockers,
            explanation=f"{b.parent_label} requires {name} `{b.spec}`, which excludes the fixed version {to}. "
                        f"The fix has to come from upgrading {bname}"
                        f"{' (brought in by ' + target + ')' if target != bname else ''} or an override.",
            action=f"Upgrade {target} to a release whose dependency tree allows {name} {to}+, or force it with "
                   f"{OVERRIDE_HINT.get(eco, 'an explicit pin')} ({name}@{to}).",
            command=cmd_override(eco, [(name, to)]), **base)

    target = ", ".join(intro_names) or checks[0].parent_label.rsplit("@", 1)[0]
    par = ", ".join(c.parent_label for c in checks[:3])
    return FixRecommendation(
        root_cause_kind="transitive", kind="upgrade-parent", target=target, to=to, parents=checks,
        explanation=f"{name} is pulled in by {par}{' (via direct dependency ' + target + ')' if intro_names else ''}. "
                    f"The declared range is not recorded for this SBOM source, so check whether a newer "
                    f"{target} brings {to}+.",
        action=f"Upgrade {target} so that {name} resolves to {to}+, or force it with "
               f"{OVERRIDE_HINT.get(eco, 'an explicit pin')} ({name}@{to}).",
        command=cmd_override(eco, [(name, to)]), **base)


# --------------------------------------------------------------------------- #
# Attach to findings + group by the change that resolves them
# --------------------------------------------------------------------------- #
def attach_fix_recommendations(findings: Iterable[Finding], sbom: Sbom, vulns: List[Vulnerability],
                               idx: DependencyIndex) -> List[FixGroup]:
    by_key: Dict[Tuple[str, str], Vulnerability] = {(v.id, v.purl): v for v in vulns}
    vuln_findings: List[Finding] = []
    for f in findings:
        if f.kind != "vulnerability" or not f.purl or not f.advisory_ids:
            continue
        v = by_key.get((f.advisory_ids[0], f.purl))
        if v is None:
            continue
        f.fix = recommend_fix(v, sbom, idx, vulns)
        if f.fix:
            vuln_findings.append(f)
    return group_fixes(vuln_findings, idx)


def group_fixes(findings: List[Finding], idx: DependencyIndex) -> List[FixGroup]:
    buckets: Dict[Tuple[str, str], List[Finding]] = {}
    for f in findings:
        assert f.fix is not None
        buckets.setdefault((f.fix.kind, f.fix.target), []).append(f)
    groups: List[FixGroup] = []
    for (kind, target), fs in buckets.items():
        eco = idx.comp[fs[0].purl].ecosystem if fs[0].purl in idx.comp else "npm"
        pkgs = sorted({f"{f.package}@{f.version}" for f in fs})
        pins: Dict[str, str] = {}
        for f in fs:
            if f.fix and f.fix.to and f.package:
                pins[f.package] = _vmax([pins.get(f.package), f.fix.to]) or f.fix.to
        to = _vmax(pins.values())
        if kind == "upgrade-direct" and to:
            command, action = cmd_upgrade(eco, target, to), f"Upgrade {target} to {to} or later"
        elif kind == "refresh-lockfile":
            command = cmd_refresh(eco, pins or [target])
            action = f"Refresh the lockfile so {', '.join(sorted(pins)) or target} resolve to fixed versions"
        elif kind in ("upgrade-parent", "pin") and pins:
            command = cmd_override(eco, pins.items())
            action = (f"Upgrade {target} (fixes {len(pkgs)} vulnerable package{'s' if len(pkgs) > 1 else ''}), "
                      f"or add override{'s' if len(pins) > 1 else ''} for {', '.join(f'{n}@{t}' for n, t in sorted(pins.items()))}")
        else:
            command, action = fs[0].fix.command, fs[0].fix.action
        if len(fs) > 1 and kind in ("upgrade-direct", "refresh-lockfile"):
            action += f" (fixes {len(fs)} findings)"
        worst = max(fs, key=lambda f: (f.elo.total, _SEV_RANK[f.elo.severity]))
        groups.append(FixGroup(
            id="", kind=kind, target=target, to=to, action=action, command=command,
            findings=sorted(f.id for f in fs), packages=pkgs, max_severity=worst.elo.severity,
            max_elo=worst.elo.total,
            runtime=any(not f.elo.factors.dev_or_test_only for f in fs)))
    groups.sort(key=lambda g: (-g.max_elo, -len(g.findings), g.target))
    by_finding = {f.id: f for f in findings}
    for i, g in enumerate(groups, 1):
        g.id = f"G-{i:02d}"
        for fid in g.findings:
            fx = by_finding[fid].fix
            if fx:
                fx.group_id = g.id
    return groups
