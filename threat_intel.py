"""Threat intelligence for the risk engine: FIRST EPSS, CISA KEV, NVD (CVSS fallback).

* Read-only HTTPS GETs of public JSON feeds; nothing from a scanned repository is sent
  except CVE identifiers.
* Every value is recorded with its source and the dataset's own last-updated date
  (`IntelSource`), so a card shows exactly how fresh each input was.
* Cached under .scg_cache/intel (KEV and EPSS 24 h, NVD 7 days) so re-scans and the
  drift daemon do not hammer the APIs. With SCG_OFFLINE=1 nothing is fetched and the
  fields stay None ("not checked"), which the engine scores neutrally and reports as
  lower confidence.
* NVD is only queried when OSV gave no CVSS v3 vector (it is heavily rate-limited:
  5 requests / 30 s without an API key). Set NVD_API_KEY to raise the per-scan budget.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx

from models import IntelSource, Vulnerability
from scanners import CACHE_ROOT, LogFn, _noop_log, cvss3_base_score, offline_mode

INTEL_DIR = CACHE_ROOT / "intel"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DAY = 86400
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
UA = {"User-Agent": "supply-chain-guardian/2.0", "Accept": "application/json"}


def _load(name: str) -> Dict[str, Any]:
    p = INTEL_DIR / name
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        return {}


def _save(name: str, data: Dict[str, Any]) -> None:
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    (INTEL_DIR / name).write_text(json.dumps(data), encoding="utf-8")


def cve_of(v: Vulnerability) -> Optional[str]:
    return next((a for a in [v.id, *v.aliases] if CVE_RE.match(a or "")), None)


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #
def load_kev(log: LogFn = _noop_log) -> Optional[Dict[str, Any]]:
    """{"version", "released", "fetched_at", "entries": {cve: {...}}} or None if unavailable."""
    cached = _load("kev.json")
    if cached and time.time() - cached.get("fetched_at", 0) < DAY:
        return cached
    if offline_mode():
        return cached or None
    try:
        with httpx.Client(timeout=30, headers=UA, follow_redirects=True) as c:
            r = c.get(KEV_FEED)
            r.raise_for_status()
            doc = r.json()
        entries = {e["cveID"]: {"dateAdded": e.get("dateAdded"), "ransomware": e.get("knownRansomwareCampaignUse"),
                                "name": e.get("vulnerabilityName"), "due": e.get("dueDate")}
                   for e in doc.get("vulnerabilities", []) if e.get("cveID")}
        data = {"version": doc.get("catalogVersion"), "released": doc.get("dateReleased"),
                "fetched_at": time.time(), "entries": entries}
        _save("kev.json", data)
        log("threat-intel", f"CISA KEV catalogue {data['version']} ({len(entries)} CVEs, released {data['released']})", "tool")
        return data
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        log("threat-intel", f"CISA KEV unavailable ({exc}); {'using cached copy' if cached else 'KEV not checked'}", "warn")
        return cached or None


# --------------------------------------------------------------------------- #
# FIRST EPSS
# --------------------------------------------------------------------------- #
def load_epss(cves: Iterable[str], log: LogFn = _noop_log) -> Dict[str, Dict[str, Any]]:
    """cve -> {"epss", "percentile", "date"}; CVEs EPSS does not know map to {"missing": True}."""
    cache = _load("epss.json")
    now = time.time()
    want = sorted({c for c in cves if CVE_RE.match(c)})
    stale = [c for c in want if now - cache.get(c, {}).get("fetched_at", 0) >= DAY]
    if stale and not offline_mode():
        try:
            with httpx.Client(timeout=30, headers=UA) as c:
                for i in range(0, len(stale), 80):
                    chunk = stale[i:i + 80]
                    r = c.get(EPSS_API, params={"cve": ",".join(chunk)})
                    r.raise_for_status()
                    got = {d["cve"]: d for d in r.json().get("data", [])}
                    for cve in chunk:
                        d = got.get(cve)
                        cache[cve] = ({"epss": float(d["epss"]), "percentile": float(d["percentile"]), "date": d.get("date"),
                                       "fetched_at": now} if d else {"missing": True, "fetched_at": now})
            _save("epss.json", cache)
            log("threat-intel", f"FIRST EPSS: scored {sum(1 for c in stale if not cache[c].get('missing'))}/{len(stale)} CVEs "
                                f"({len(want) - len(stale)} cached)", "tool")
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log("threat-intel", f"FIRST EPSS unavailable ({exc}); EPSS not checked for {len(stale)} CVE(s)", "warn")
    return {c: cache[c] for c in want if c in cache}


# --------------------------------------------------------------------------- #
# NVD (CVSS fallback only)
# --------------------------------------------------------------------------- #
def load_nvd(cves: List[str], log: LogFn = _noop_log) -> Dict[str, Dict[str, Any]]:
    cache = _load("nvd.json")
    now = time.time()
    key = os.environ.get("NVD_API_KEY")
    budget = int(os.environ.get("SCG_NVD_MAX", "40" if key else "5"))
    todo = [c for c in dict.fromkeys(cves) if now - cache.get(c, {}).get("fetched_at", 0) >= 7 * DAY][:budget]
    if todo and not offline_mode():
        headers = dict(UA, **({"apiKey": key} if key else {}))
        fetched = 0
        try:
            with httpx.Client(timeout=30, headers=headers) as c:
                for cve in todo:
                    r = c.get(NVD_API, params={"cveId": cve})
                    if r.status_code in (403, 429):
                        log("threat-intel", "NVD rate limit reached; remaining CVSS lookups skipped", "warn")
                        break
                    r.raise_for_status()
                    items = r.json().get("vulnerabilities", [])
                    entry: Dict[str, Any] = {"fetched_at": now}
                    if items:
                        cv = items[0].get("cve", {})
                        metrics = cv.get("metrics", {})
                        for k in ("cvssMetricV31", "cvssMetricV30"):
                            m = next((x for x in metrics.get(k, []) if x.get("type") == "Primary"), None) or \
                                (metrics.get(k) or [None])[0]
                            if m:
                                entry.update({"vector": m["cvssData"].get("vectorString"),
                                              "score": m["cvssData"].get("baseScore")})
                                break
                        entry["last_modified"] = cv.get("lastModified")
                    cache[cve] = entry
                    fetched += 1
                    if not key:
                        time.sleep(0.7)
            log("threat-intel", f"NVD: CVSS fallback for {fetched} CVE(s) without an OSV vector", "tool")
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log("threat-intel", f"NVD unavailable ({exc}); keeping OSV severity", "warn")
        _save("nvd.json", cache)
    return {c: cache[c] for c in cves if c in cache}


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def _iso(ts: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%MZ") if ts else None


def enrich(vulns: List[Vulnerability], log: LogFn = _noop_log) -> Dict[str, Any]:
    """Fill CVE, EPSS, KEV (and NVD CVSS when OSV had no vector) on every vulnerability in place."""
    for v in vulns:
        v.cve = v.cve or cve_of(v)
    cves = [v.cve for v in vulns if v.cve]
    status: Dict[str, Any] = {"offline": offline_mode(), "kev_checked": False, "epss_checked": False,
                              "kev_version": None, "epss_date": None}
    if not vulns:
        return status
    kev = load_kev(log)
    epss = load_epss(cves, log)
    need_nvd = [v.cve for v in vulns if v.cve and v.cvss_source in (None, "label-estimate", "scanner-group")]
    nvd = load_nvd(need_nvd, log) if need_nvd else {}
    status["kev_checked"] = kev is not None
    status["kev_version"] = kev.get("version") if kev else None
    status["epss_checked"] = bool(epss) or (not cves and not offline_mode())
    status["epss_date"] = next((e.get("date") for e in epss.values() if e.get("date")), None)

    for v in vulns:
        src = [IntelSource(name="OSV", value=f"{v.id} ({v.source})", as_of=v.modified or v.published,
                           url=f"https://osv.dev/vulnerability/{v.id}" if v.source != "demo" else None)]
        if v.cve and v.cve in nvd and nvd[v.cve].get("vector"):
            n = nvd[v.cve]
            score = cvss3_base_score(n["vector"]) or n.get("score")
            if score is not None:
                v.cvss_score, v.cvss_vector, v.cvss_source = float(score), n["vector"], "nvd"
                src.append(IntelSource(name="NVD", value=f"CVSS {score} {n['vector']}", as_of=n.get("last_modified"),
                                       url=f"https://nvd.nist.gov/vuln/detail/{v.cve}"))
        if v.cvss_score is not None and v.cvss_source != "nvd":
            src[0].value += f"; CVSS {v.cvss_score} ({v.cvss_source or 'osv'})"
        if v.cve:
            e = epss.get(v.cve)
            if e and not e.get("missing"):
                v.epss, v.epss_percentile = e["epss"], e["percentile"]
                src.append(IntelSource(name="FIRST EPSS", value=f"{e['epss']:.4f} (percentile {e['percentile']:.2f})",
                                       as_of=e.get("date"), url=f"https://api.first.org/data/v1/epss?cve={v.cve}"))
            elif e and e.get("missing"):
                src.append(IntelSource(name="FIRST EPSS", value="no score published for this CVE", as_of=_iso(e.get("fetched_at"))))
            if kev is not None:
                k = kev["entries"].get(v.cve)
                v.kev = k is not None
                if k:
                    v.kev_date_added, v.kev_ransomware = k.get("dateAdded"), k.get("ransomware") == "Known"
                src.append(IntelSource(
                    name="CISA KEV", value=(f"listed (added {k.get('dateAdded')}"
                                            f"{', ransomware use known' if v.kev_ransomware else ''})") if k else "not listed",
                    as_of=f"catalog {kev.get('version')} released {kev.get('released')}",
                    url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
        else:
            # Without a CVE id neither EPSS nor KEV can say anything: leave as "not checked".
            src.append(IntelSource(name="FIRST EPSS / CISA KEV", value="advisory has no CVE alias; not applicable"))
        v.intel_sources = src
    n_kev = sum(1 for v in vulns if v.kev)
    log("threat-intel", f"enriched {len(vulns)} advisories: {len(set(cves))} CVEs, {n_kev} in CISA KEV, "
                        f"{sum(1 for v in vulns if v.epss is not None)} with EPSS", "success" if status["kev_checked"] else "warn")
    return status
