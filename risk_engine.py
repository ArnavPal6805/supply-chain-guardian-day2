"""Deterministic risk-scoring engine (0-100). The only place a risk score is produced.

The LLM never decides a score. It explains this function's output, and the
Post-Check Validator recomputes `compute_risk(card.factors)` for every card.

Known vulnerabilities (weights proposed for Day 2):
    CVSS severity              35   linear in the CVSS base score
    EPSS exploit probability   25   log-scaled (EPSS is extremely skewed: most CVEs < 0.05)
    CISA KEV listing           20   listed = 20, checked and absent = 0
    Reachability               10   confirmed 10 | imported/unknown 5 | not imported 2 | symbol never called 0
    Exposure                   10   public route 10 | network service 6 | unknown 5 | internal/CLI 2
Adjustments (applied in this order, each one listed on the card):
    MAL- advisory               = 100   (malicious package, not a bug)
    KEV floor                   >= 80 if reachable or unknown, >= 60 if proven unused
    dev/test-only scope         x 0.6   (not shipped to production)
Missing data is never "zero risk": unknown CVSS -> 5.0 prior, unknown EPSS -> 0.01 prior,
unknown reachability/exposure -> middle points; every assumption lowers *confidence* instead.
Dependency depth is context only: a transitive dependency is not automatically safer.

Non-CVE findings (tampering, typosquats, hooks, CI/container hygiene) have no CVSS/EPSS and
start from a fixed threat-class base instead.

Bands: Critical 80-100, High 60-79, Medium 30-59, Low 0-29.
"""
from __future__ import annotations

import math
from typing import List, Tuple

from models import RiskAdjustment, RiskBreakdown, RiskComponent, RiskFactors, Severity

FORMULA_VERSION = "risk-v2"

W_CVSS, W_EPSS, W_KEV, W_REACH, W_EXPOSURE = 35, 25, 20, 10, 10
CVSS_PRIOR, EPSS_PRIOR = 5.0, 0.01
KEV_FLOOR_REACHABLE, KEV_FLOOR_UNUSED = 80, 60
DEV_MULTIPLIER = 0.6

REACH_POINTS = {"confirmed": 10.0, "imported": 5.0, "unknown": 5.0, "not_imported": 2.0, "not_called": 0.0}
REACH_TEXT = {
    "confirmed": "vulnerable code is called on a path from an entrypoint",
    "imported": "package is imported, but whether the vulnerable function is called is unknown",
    "unknown": "reachability could not be determined statically (scored neutrally)",
    "not_imported": "package is never imported by first-party code",
    "not_called": "package is imported but the vulnerable function is never called",
}
EXPOSURE_POINTS = {"public_route": 10.0, "network_service": 6.0, "unknown": 5.0, "internal": 2.0}
EXPOSURE_TEXT = {
    "public_route": "reachable from an unauthenticated route of an internet-facing service",
    "network_service": "the application is a network service, but no public route to this code was found",
    "unknown": "exposure could not be determined (scored neutrally)",
    "internal": "no network entrypoint found (library / CLI / internal tool)",
}

# Non-CVE threat classes: (base score, label)
THREAT_BASE = {
    "malicious": (100, "known malicious package"),
    "tamper": (90, "lockfile integrity changed without a version bump"),
    "typosquat": (85, "typosquat of a popular package"),
    "nonexistent": (85, "package does not exist on the registry (hallucinated / dependency confusion)"),
    "suspicious_hook": (80, "install hook with network/exec/secret-reading behaviour"),
    "docker_pipe_to_shell": (55, "remote script piped to a shell during image build"),
    "docker_untrusted_registry": (50, "base image from an untrusted registry"),
    "docker_latest_tag": (40, "base image floats on :latest"),
    "workflow_unpinned_action": (35, "CI action pinned to a mutable ref"),
    "admission_signals": (40, "pre-install warning signals (no hard block)"),
    "clean": (10, "no risk signals"),
}


def severity_for(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    return Severity.LOW


def priority_for(score: int, kev: bool) -> str:
    if score >= 80 or kev:
        return "P1 act now"
    if score >= 60:
        return "P2 fix soon"
    if score >= 30:
        return "P3 plan"
    return "P4 monitor"


def epss_points(epss: float) -> float:
    """0.001 -> 2.5, 0.01 -> 8.7, 0.1 -> 16.7, 0.5 -> 22.5, 0.92 -> 24.7 (of 25)."""
    e = min(max(epss, 0.0), 1.0)
    return W_EPSS * min(1.0, math.log10(1 + 999 * e) / 3)


def _confidence(f: RiskFactors, cve: bool) -> Tuple[float, List[str]]:
    c, why = 1.0, []

    def dock(amount: float, reason: str) -> None:
        nonlocal c
        c -= amount
        why.append(f"-{amount:.2f} {reason}")

    if f.demo_data:
        dock(0.40, "built-in demo advisory data")
    if cve:
        if f.cvss is None:
            dock(0.25, "no CVSS score available (5.0 prior used)")
        elif f.cvss_source == "label-estimate":
            dock(0.15, "CVSS estimated from the advisory's severity label (no vector)")
        if f.epss is None:
            dock(0.10, "no EPSS score (no CVE alias, or EPSS not reachable)")
        if f.kev is None:
            dock(0.10, "CISA KEV catalogue not checked")
        if f.reachability == "unknown":
            dock(0.20, "reachability unknown")
        elif f.reachability == "imported":
            dock(0.10, "imported, but no vulnerable-symbol data to confirm a call")
        elif f.reachability_source == "agent-verified":
            dock(0.05, "call site found by the agent (verified verbatim, not a full call graph)")
        if f.version_uncertain:
            dock(0.20, "installed version approximated from a semver range (no lockfile)")
    if f.exposure == "unknown":
        dock(0.10, "deployment exposure unknown")
    elif f.exposure_source == "static" and f.exposure in ("public_route", "network_service"):
        dock(0.05, "exposure inferred from source (routes / server entrypoint), not deployment config")
    c = round(max(0.05, c), 2)
    return c, why


def compute_risk(f: RiskFactors) -> RiskBreakdown:
    """Pure and deterministic: same factors -> same breakdown."""
    comps: List[RiskComponent] = []
    adj: List[RiskAdjustment] = []
    is_cve = f.threat_class is None

    if is_cve:
        cvss = f.cvss if f.cvss is not None else CVSS_PRIOR
        comps.append(RiskComponent(
            factor="CVSS severity", points=round(W_CVSS * min(max(cvss, 0), 10) / 10, 1), max_points=W_CVSS,
            detail=(f"CVSS {cvss:.1f}" + (f" ({f.cvss_source})" if f.cvss_source else "")) if f.cvss is not None
            else f"unknown, prior {CVSS_PRIOR}"))
        epss = f.epss if f.epss is not None else EPSS_PRIOR
        comps.append(RiskComponent(
            factor="EPSS exploit probability", points=round(epss_points(epss), 1), max_points=W_EPSS,
            detail=(f"EPSS {f.epss:.4f}" + (f" (percentile {f.epss_percentile:.2f})" if f.epss_percentile is not None else ""))
            if f.epss is not None else f"unknown, prior {EPSS_PRIOR}"))
        comps.append(RiskComponent(
            factor="CISA KEV", points=float(W_KEV if f.kev else 0), max_points=W_KEV,
            detail="listed as known exploited" if f.kev else ("not listed" if f.kev is False else "not checked")))
        comps.append(RiskComponent(
            factor="Reachability", points=REACH_POINTS[f.reachability], max_points=W_REACH,
            detail=REACH_TEXT[f.reachability] + (" [agent-verified call site]" if f.reachability_source == "agent-verified" else "")))
    else:
        base, label = THREAT_BASE.get(f.threat_class or "clean", THREAT_BASE["clean"])
        comps.append(RiskComponent(factor="Threat class", points=float(base), max_points=100, detail=label))
    comps.append(RiskComponent(factor="Exposure", points=EXPOSURE_POINTS[f.exposure] if is_cve else 0.0,
                               max_points=W_EXPOSURE if is_cve else 0,
                               detail=EXPOSURE_TEXT[f.exposure] + (" (override)" if f.exposure_source == "override" else "")
                               + ("" if is_cve else " (context only for non-CVE findings)")))

    score = sum(c.points for c in comps)
    if not is_cve:
        if f.auto_exec_hook:
            score += 10
            adj.append(RiskAdjustment(label="auto-executes at install time", effect="+10"))
        if f.provenance_flags:
            score += 10
            adj.append(RiskAdjustment(label="provenance: " + "; ".join(sorted(set(f.provenance_flags))), effect="+10"))
    if f.threat_class == "malicious":
        score = 100
    if is_cve and f.kev:
        floor = KEV_FLOOR_UNUSED if f.reachability in ("not_called", "not_imported") else KEV_FLOOR_REACHABLE
        if score < floor:
            adj.append(RiskAdjustment(label="listed in CISA KEV (actively exploited)", effect=f"floor {floor}"))
            score = floor
    if f.dev_or_test_only and f.threat_class not in ("malicious", "tamper", "typosquat", "nonexistent", "suspicious_hook"):
        # install-time attacks hit developer machines and CI too, so they are not discounted
        score *= DEV_MULTIPLIER
        adj.append(RiskAdjustment(label="dev/test-only dependency (not shipped to production)", effect=f"x{DEV_MULTIPLIER}"))
    total = int(round(min(max(score, 0), 100)))
    conf, why = _confidence(f, is_cve)
    return RiskBreakdown(
        factors=f, components=comps, adjustments=adj, total=total, severity=severity_for(total),
        priority=priority_for(total, bool(f.kev)), confidence=conf,
        confidence_level="high" if conf >= 0.8 else ("medium" if conf >= 0.5 else "low"),
        confidence_reasons=why, formula_version=FORMULA_VERSION)


def explain_deterministic(r: RiskBreakdown) -> str:
    """Plain-language explanation built only from the breakdown (fallback when no LLM)."""
    f = r.factors
    parts = [f"Risk score {r.total}/100 ({r.severity.value.title()}, {r.priority})"]
    top = sorted((c for c in r.components if c.max_points), key=lambda c: -c.points)
    parts.append("driven by " + ", ".join(f"{c.factor.lower()} {c.points:g} of {c.max_points:g} pts ({c.detail})"
                                          for c in top[:3]))
    if r.adjustments:
        parts.append("adjusted for " + "; ".join(f"{a.label} [{a.effect}]" for a in r.adjustments))
    if f.dependency_depth:
        parts.append("direct dependency" if f.dependency_depth == 1 else
                     f"transitive dependency at depth {f.dependency_depth} (depth is context, not a discount)")
    parts.append(f"confidence {r.confidence_level} ({r.confidence:.2f})")
    return "; ".join(parts) + "."
