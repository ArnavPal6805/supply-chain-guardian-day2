# Supply-Chain Guardian Team 6

Continuous, **read-only** software supply-chain security: a pre-install admission gate, an
evidence-backed attack tree with a locked Risk Elo formula, a constrained LLM triage agent
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

This folder is SUPPLY-CHAIN-GUARDIAN (pipeline, Risk Elo, LLM triage, Post-Check Validator, dashboard)
with two capabilities ported from the Day-1 `supply-chain-guardian` and rewritten to fit this design:

| Capability | Where | Notes |
|---|---|---|
| Dependency graph analysis | `dep_graph.py` | `DependencyIndex`: depth (1 = direct), shortest path from the project, parents/children, `introduced_by` (which direct deps pull a package in), orphans attached as *inferred direct*, `DependencyStats` (depth histogram, heaviest direct deps, most depended-on, multi-version packages). Every edge in `dependency_graph` still carries `Evidence` (package.json line, lockfile entry with declared range, or an explicit "inferred" note). |
| Graph explorer (UI) | `static/index.html`, *Dependencies* view | Collapsible SVG tree (no layout library): click a dot to expand, click a label to inspect and filter evidence cards, "only paths to critical & high", "▸ N below" counts on collapsed branches, D/T-depth tags, cycle and dev markers. *Attack paths* stays on cytoscape. |
| Fixed version per OSV advisory | `scanners.fixed_version_for` | Picks the fix of the affected range that contains the installed version (not just the first `fixed` event). osv-scanner runs `scan source -L bom.cdx.json` on the same inventory as the graph; alias groups (GHSA + CVE) are counted once. Also applied to OSV.dev API results. |
| Root-cause fix recommendation | `remediation.py` | Uses declared ranges per edge (`Sbom.edge_specs`, from package.json + lockfile): `direct`, `direct-stale-lock`, `stale-lock`, `blocked-by-parent` (names the blocking parent and its range), `transitive`, `parent-unknown`, `no-fix`. Stored on `Finding.fix`, shown in evidence-card field 5, and grouped in `ScanResult.fix_groups` ("Fix first", ordered by Risk Elo). |

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

## Safety model

| Risk | Control |
|---|---|
| Executing untrusted code | Never runs `npm/pip install`, `docker build` or project scripts. All subprocesses: arg lists, `shell=False`, timeouts, `NPM_CONFIG_IGNORE_SCRIPTS=true`. `cdxgen` runs with `--no-install-deps` (its default is to install!). |
| Malicious `.git/config` / `.gitattributes` | Git runs with hooks, fsmonitor, external diff and textconv disabled; the working tree is never diffed (clean filters), history is read via `git show <ref>:<path>`. |
| Commit replay / simulation side effects | No worktree checkouts, no commits, no branches. Simulation uses a temp sandbox (only `package.json` + lockfile) with an `.npmrc` that disables scripts and points at an unroutable registry; deleted afterwards. Payload host uses the reserved `.invalid` TLD. |
| Registry checks | Metadata JSON only; tarballs never downloaded. Package names validated by regex before URL construction. |
| `--resolve-lockfile` (opt-in) | `npm install --package-lock-only --ignore-scripts` on a *copy* of `package.json` in a temp dir; the repo's `.npmrc` is not copied. |
| LLM hallucination | 4 read-only tools only; Elo computed in Python; validator checks file, verbatim snippet (+/-5 lines), purl, graph edges, formula, and an allow-listed fix command; 1 retry then deterministic fallback. |
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
