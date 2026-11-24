# Supply-Chain Guardian Team 6

# Contributions:
  | Member | Day 1 Contribution | Day 2 Contribution |
|---|---|---|
| **Arnav Pal** | SBOM generation, OSV scanning, vulnerability identification, fixed-version extraction, and remediation recommendations. | Improved vulnerability remediation logic, integration of findings with the agent, and dependency-aware fix recommendations. |
| **Aditya Santosh** | Rule-based anomaly detection, typosquatting detection, suspicious package scripts, integrity checks, and package source analysis. | Extended anomaly detection with metadata and provenance checks, configuration analysis, baseline comparison, and LLM-assisted anomaly investigation. |
| **Souri** | Dependency graph analysis, direct and transitive dependency tracing, root-cause identification, and risk scoring. | Attack-tree generation, Risk Elo prioritisation, dependency reachability analysis, and evidence-based remediation decisions. |
| **M KAVYA** | Integration of scanning and analysis components, initial remediation workflow, and coordination of security findings. | Agentic remediation workflow, tool calling, autonomous planning, dependency modification, adaptive remediation, and iterative fix generation. |
| **Saran J Palani ** | Scan result presentation, baseline comparison, reporting, and overall system integration. | Isolated remediation workspaces, post-fix validation, human approval, before-and-after comparison, and final reporting. |

Continuous, **read-only** software supply-chain security: a pre-install admission gate, an
evidence-backed attack tree, a deterministic 0-100 risk engine fed by OSV/NVD/EPSS/KEV, a constrained LLM triage agent
whose every answer passes a deterministic Post-Check Validator, plus a CLI and a web dashboard.

## Quick start

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # (bin/ on Linux/macOS)
git clone --depth 40 https://github.com/juice-shop/juice-shop.git targets/juice-shop

python main.py --mode scan                                  # defaults to ./targets/juice-shop
python main.py --mode check-pkg --pkg reqeusts@1.0.0        # exit code 3 when BLOCKED (CI-friendly)
python main.py --mode replay --commits 5
python main.py --mode daemon --interval 30 --max-polls 3 --demo-drift
python main.py --mode simulate-attack                       # exit code 4 if NOT blocked
python main.py --mode serve --port 8000                     # http://127.0.0.1:8000
python -m unittest discover -s tests -v
```

Flags: `--no-llm`, `--offline`, `--resolve-lockfile`, `--json-out out.json`, `--keep-sandbox`.
`cdxgen` and `osv-scanner` are used when on `PATH`; otherwise a built-in lockfile/manifest parser
and the OSV.dev API are used, and as a last resort clearly-labelled demo data.

## Day 2 merge: dependency graph + OSV fix recommendations

This folder is SUPPLY-CHAIN-GUARDIAN (pipeline, attack tree, LLM triage, Post-Check Validator, dashboard)
with two capabilities ported from the Day-1 `supply-chain-guardian` and rewritten to fit this design:

| Capability | Where | Notes |
|---|---|---|
| Dependency graph analysis | `dep_graph.py` | `DependencyIndex`: depth (1 = direct), shortest path from the project, parents/children, `introduced_by` (which direct deps pull a package in), orphans attached as *inferred direct*, `DependencyStats` (depth histogram, heaviest direct deps, most depended-on, multi-version packages). Every edge in `dependency_graph` still carries `Evidence` (package.json line, lockfile entry with declared range, or an explicit "inferred" note). |
| Graph explorer (UI) | `static/index.html`, *Dependencies* view | Collapsible SVG tree (no layout library): click a dot to expand, click a label to inspect and filter evidence cards, "only paths to critical & high", "▸ N below" counts on collapsed branches, D/T-depth tags, cycle and dev markers. *Attack paths* stays on cytoscape. |
| Fixed version per OSV advisory | `scanners.fixed_version_for` | Picks the fix of the affected range that contains the installed version (not just the first `fixed` event). osv-scanner runs `scan source -L bom.cdx.json` on the same inventory as the graph; alias groups (GHSA + CVE) are counted once. Also applied to OSV.dev API results. |
| Root-cause fix recommendation | `remediation.py` | Uses declared ranges per edge (`Sbom.edge_specs`, from package.json + lockfile): `direct`, `direct-stale-lock`, `stale-lock`, `blocked-by-parent` (names the blocking parent and its range), `transitive`, `parent-unknown`, `no-fix`. Stored on `Finding.fix`, shown in evidence-card field 5, and grouped in `ScanResult.fix_groups` ("Fix first", ordered by risk score). |

Fix commands only use allow-listed prefixes, which the Post-Check Validator checks: `npm install --ignore-scripts`,
`npm update --ignore-scripts`, `npm pkg set overrides.<pkg>=<ver> && npm install --ignore-scripts`,
`npm uninstall --ignore-scripts`. The validator also enforces a new `fix_targets_root_cause` check: an LLM-edited
command has to act on the vulnerable package or its root-cause target.

**GitHub URLs**: `--repo` and the dashboard's repo box accept a local path or a public GitHub URL
(`https://github.com/owner/repo`, optionally `/tree/<branch>`). A URL is shallow-cloned (`--depth 40`, enough for
commit replay) into `.scg_cache/clones/` with hooks, LFS smudge, symlinks, submodules and non-https transports
disabled, then scanned read-only like any local repo. Every full scan clones it again. Set `SCG_ALLOW_CLONE=0`
to accept local paths only.

Extra env vars: `SCG_OSV_SCANNER` (path to the binary), `SCG_OSV_OFFLINE_DB=1` (run osv-scanner with its
local database while `SCG_OFFLINE=1`).

## Day 2, objective 1: prioritize risks (`risk_engine.py`, `threat_intel.py`)

**The LLM never decides risk.** `risk_engine.compute_risk(factors)` is a pure function. The Post-Check Validator
recomputes it for every card and rejects any explanation that claims a different level, score or priority.

| Factor | Max | Mapping | Source (cached, with dataset date on every card) |
|---|---|---|---|
| CVSS severity | 35 | linear in base score; unknown -> 5.0 prior | OSV vector, NVD fallback when OSV has none |
| EPSS exploit probability | 25 | **log-scaled** (0.01 -> 8.7, 0.1 -> 16.7, 0.92 -> 24.7); unknown -> 0.01 prior | FIRST EPSS API |
| CISA KEV | 20 | listed 20 / not listed 0 / not checked -> confidence penalty | CISA KEV JSON feed |
| Reachability | 10 | confirmed 10, imported/unknown 5, not imported 2, symbol never called 0 | static analysis, or an agent call site that passed verification |
| Exposure | 10 | public route 10, network service 6, unknown 5, internal/CLI 2 | routes / `listen()` / `EXPOSE`, or the `SCG_EXPOSURE=internet\|internal` override |

Adjustments (each one shown on the card): MAL- advisory = 100. A KEV listing sets a floor of 80 (60 if the code
is proven unused). Dev/test-only dependencies are scored x0.6. Install-time attacks (typosquat, tamper,
malicious hooks) are never discounted. **Dependency depth is context only.**
Non-CVE findings start from a fixed threat-class base (malicious 100, lockfile tamper 90, typosquat 85, ...).
Bands: Critical >= 80, High 60-79, Medium 30-59, Low < 30. Priority: P1 act now, P2 fix soon, P3 plan, P4 monitor.

**Confidence** (0-1, high/medium/low) starts at 1.0 and is lowered for every assumption: CVSS estimated from a
label, no EPSS, KEV not checked, reachability unknown, version taken from a semver range floor, exposure inferred
from source rather than deployment config, demo data. Each deduction is listed on the card.

**Agentic part (needs `GEMINI_API_KEY`):** the agent explains the breakdown (tool `get_risk_breakdown`). When
reachability is unknown, it may search the code and propose a call site. `verify_agent_call_site` accepts it only
if the file imports the package, the line matches verbatim, the call uses the import binding, and the function is
named in the advisory. A verified site changes the engine's *input* (reachability -> confirmed); the engine then
re-scores. The agent can raise a score with proof but never lower it.

**Drift daemon:** besides new advisories, it now flags *exploitation drift*: a known CVE that has since been added
to KEV, or whose EPSS crossed 0.1, triggers a re-score and a new LLM explanation.

Env: `GEMINI_API_KEY` (preferred when set), `SCG_GEMINI_MODEL`, `NVD_API_KEY` (raises the NVD budget from 5 to 40
lookups per scan), `SCG_NVD_MAX`, `SCG_EXPOSURE=auto|internet|internal`.

## Day 2, objective 3: mitigation candidates + Human Validation Gate (`mitigation_engine.py`)

For every finding the Guardian builds a `MitigationDecisionPackage` of candidate fixes from five sources:

| Source | What it contributes |
|---|---|
| `OSV_SCANNER` | the fix for the range that contains the installed version, plus the lowest version that clears every advisory on the package |
| `GHSA` | GitHub's first patched version (advisory API, cached) and the upstream fix commit (offered as a reviewed patch) |
| `CSV_FEED` | organisation-approved overrides from `advisory_overrides.csv` in the **Guardian's own folder** (or `SCG_ADVISORY_CSV`), never from the scanned repo. See `advisory_overrides.example.csv`. |
| `CHANGELOG_DIFF` | `node_modules/<pkg>/CHANGELOG.md` if present, plus GitHub release notes newer than the installed version: BREAKING / REMOVED / DEPRECATED lines, and whether they name symbols the app actually calls |
| `CONTEXTUAL_RULE` | move test-only deps to devDependencies, restore a tampered lockfile, pin images to a digest and actions to a SHA, block malicious or typosquatted packages |

Python scores each candidate (`fit_score`, 0-100: SemVer jump, compatibility risk, breaking notes, partial-fix
penalty, corroboration) and keeps the best five. **The gate requires a human** when: no automated fix exists,
the top fix is a MAJOR bump (a 0.x minor bump counts as major), breaking changes hit called symbols, the fix is a
raw upstream patch, or the top two candidates are within 10 points. Otherwise the Python policy auto-approves.
Approval records intent only: the Guardian never runs the command.

Gemini (when enabled) writes only `ai_tradeoff_summary`. `validate_tradeoff_summary` rejects any version or
candidate id that is not in the package, any attempt to change `requires_human_validation`, and any "no review
needed" claim on a gated finding. It gets one retry, then the deterministic summary is used.

Decisions: dashboard panel (section 6 of each card, "to review" filter on the Evidence Cards tab),
`POST /api/mitigations/validate`, or `python main.py --repo … --mode scan --validate` (interactive). Every decision
is appended to `.scg_cache/<repo>/decisions.jsonl`, and it is re-applied after re-scans (matched by package,
advisory and chosen fix).

Env: `GITHUB_TOKEN` (raises the GitHub budget from 20 to 60 calls per scan), `SCG_GITHUB_MAX`, `SCG_ADVISORY_CSV`,
`SCG_MAX_LLM_MITIGATIONS` (default 8).

## Day 2, objective 4: agentic remediation (`remediation_agent.py`, `workspace.py`, `remediation_validator.py`)

**One Lead Remediation Agent** runs investigate → plan → act → observe → adapt → validate in iterations
(default 5, up to 10). Gemini chooses tools in a JSON tool-calling loop. Without a key, or when the provider
fails mid-run, a deterministic policy drives the same tools, so a session always completes.

| Tool group | Tools |
|---|---|
| Investigate | `inspect_file`, `search_codebase`, `inspect_dependency`, `inspect_dependency_graph`, `inspect_osv_advisory`, `inspect_package_metadata`, `analyze_lifecycle_script` |
| Plan | `generate_remediation_plan` (strategy, rationale, alternatives considered) |
| Change (workspace only) | `update_dependency` (direct pin or override; the version must be a known fix or exist on the registry), `remove_dependency` / `replace_dependency` (refused if first-party code imports it), `move_dependency_to_dev`, `disable_lifecycle_script`, `pin_github_action` (tag → SHA via `git ls-remote`), `restore_file_from_git`, `edit_file` (package.json, Dockerfile, compose, workflows only), `rollback_change` |
| Observe | `regenerate_sbom`, `run_osv_scan`, `run_anomaly_scan`, `run_tests`, `compare_scan_results`, `calculate_risk` |
| Control | `request_validation`, `request_human_review`, `dismiss_finding` (LOW only), `finish` |

**Permissions (enforced in code):** reads come from an isolated copy, where `.env`, `.npmrc`, keys and symlinks are
never copied. Writes go only to allow-listed config files in that copy, and lockfiles are only regenerated by
`npm install --package-lock-only --ignore-scripts`. There is no shell tool, and every argument is validated by a
strict schema (extra fields rejected). Network use: npm registry metadata, `git ls-remote`, and the sandbox
install step. Tests (opt-in) run in Docker: install with scripts disabled, then `npm test` with `--network none`,
`--cap-drop ALL`, a non-root user, and memory/CPU/PID limits.

**Independent validator (deterministic, no LLM)** after every iteration: fresh SBOM, OSV + intel, anomaly scan, full
re-scoring, findings compared with the baseline and the previous iteration (by stable key, so an upgraded package
counts as resolved), graph consistency (manifest vs lockfile vs overrides), checks that each change is really in
the files and the resolved tree (superseded changes are recognised), and optional tests. A regression rolls back
the changes that touched the packages behind the new findings.

**Stopping (Python decides):** every target settled, no safe strategy left, regression, iteration limit, repeated
failures, no progress in two iterations, time budget, or user stop. A failed attempt is fingerprinted and never
repeated. Final statuses: `resolved`, `unresolved`, `accepted_risk`, `dismissed`, `requires_human_review` (this
includes findings fixed in the candidate by a high-impact change, e.g. a MAJOR upgrade).

**Human approval boundary:** the dashboard's **Remediation Agent** tab (or `--mode remediate` for a patch file)
shows line-level diffs per change. Tick the ones you approve, then **Prepare**: only those are replayed on a
fresh copy of the original and the lockfile is re-resolved. You see the exact final diff and its digest, and it's
flagged when it differs from what you reviewed. **Confirm** writes only that diff (refused if the original changed
since review), then runs one final independent validation. Every step is in
`.scg_cache/<repo>/remediation-<session>.jsonl`.

Env: `SCG_REMEDIATE_MAX` (finding units per session, default 8), `SCG_AGENT_MAX_STEPS` (LLM tool calls per
iteration, 14), `SCG_AGENT_BUDGET_S` (1200), `SCG_SANDBOX_IMAGE` (`node:20-bookworm-slim`), `SCG_SANDBOX_DNS`.

## Safety model

| Risk | Control |
|---|---|
| Executing untrusted code | Never runs `npm/pip install`, `docker build` or project scripts. All subprocesses: arg lists, `shell=False`, timeouts, `NPM_CONFIG_IGNORE_SCRIPTS=true`. `cdxgen` runs with `--no-install-deps` (its default is to install!). |
| Malicious `.git/config` / `.gitattributes` | Git runs with hooks, fsmonitor, external diff and textconv disabled; the working tree is never diffed (clean filters), history is read via `git show <ref>:<path>`. |
| Commit replay / simulation side effects | No worktree checkouts, no commits, no branches. Simulation uses a temp sandbox (only `package.json` + lockfile) with an `.npmrc` that disables scripts and points at an unroutable registry; deleted afterwards. Payload host uses the reserved `.invalid` TLD. |
| Registry checks | Metadata JSON only; tarballs never downloaded. Package names validated by regex before URL construction. |
| `--resolve-lockfile` (opt-in) | `npm install --package-lock-only --ignore-scripts` on a *copy* of `package.json` in a temp dir; the repo's `.npmrc` is not copied. |
| LLM hallucination | 5 read-only tools only; risk computed in Python (`risk_engine.py`), explanation checked for contradictions; validator checks file, verbatim snippet (+/-5 lines), purl, graph edges, formula, and an allow-listed fix command; 1 retry then deterministic fallback. |
| Prompt injection via scanned code | Observations fenced as untrusted data; LLM cannot write or execute anything; validator is the actual guarantee. |
| Secret leakage to the LLM | `.env`, keys, `.npmrc`, `encryptionkeys/` etc. unreadable by tools; tokens/private keys redacted from all tool output. |
| Dashboard / API abuse | Binds to 127.0.0.1 (non-loopback needs `--allow-remote`), Host allow-list (DNS rebinding), Origin check + JSON-only POSTs (CSRF), all rendered data HTML-escaped. |

## Known limitations (read before trusting a score)

* **Juice Shop ships no lockfile** (`.npmrc: package-lock=false`). Without `--resolve-lockfile`, only
  direct dependencies are known and semver ranges are approximated by their floor version
  (flagged on each card). Lockfile-hash-mutation checks then only apply to the simulation.
* Reachability is regex/import-based, not a real call graph. It handles direct imports, one
  re-export hop and a curated list of "parent always calls child" pairs (e.g. express -> qs.parse).
  The `-600` "never called" downgrade is the riskiest rule: dynamic dispatch can hide real calls.
  Unknown reachability is scored neutral (0), never downgraded.
* Function-level advisory data is rare for npm, so vulnerable symbols come from a small curated table.
* CVSS is computed from v3 vectors; v4-only advisories fall back to the GHSA severity label (flagged).
* The typosquat list is a curated ~300 names, not a live top-N download ranking.
