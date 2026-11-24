"""Supply-Chain Guardian - dual-mode entrypoint.

CLI:
  python main.py --repo ./targets/juice-shop --mode scan
  python main.py --repo ./targets/juice-shop --mode check-pkg --pkg reqeusts@1.0.0
  python main.py --repo ./targets/juice-shop --mode replay --commits 5
  python main.py --repo ./targets/juice-shop --mode daemon --interval 30 [--max-polls 3 --demo-drift]
  python main.py --repo ./targets/juice-shop --mode simulate-attack
Web dashboard (binds to 127.0.0.1 only unless --allow-remote):
  python main.py --mode serve --port 8000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse  # noqa: E402
from starlette.middleware.trustedhost import TrustedHostMiddleware  # noqa: E402

from continuous_monitor import Engine  # noqa: E402
from models import (  # noqa: E402
    ChatRequest,
    CheckPkgRequest,
    DaemonToggleRequest,
    ReplayRequest,
    ScanRequest,
    SimulateRequest,
)
from orchestrator import LogBus  # noqa: E402
from mitigation_engine import HumanDecisionType, MitigationAction, ValidationRequest  # noqa: E402
from remediation_agent import ConfirmApply, PrepareApply, StartRemediation  # noqa: E402


def default_repo() -> str:
    env = os.environ.get("SCG_DEFAULT_REPO")
    if env:
        return env
    local = PROJECT_ROOT / "targets" / "juice-shop"
    return str(local) if local.is_dir() else "/tmp/juice-shop"


# --------------------------------------------------------------------------- #
# FastAPI
# --------------------------------------------------------------------------- #
LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]", "::1"]


def create_app(engine: Engine, bus: LogBus, allowed_hosts: Optional[list] = None) -> FastAPI:
    app = FastAPI(title="Supply-Chain Guardian", version="1.0.0", docs_url="/api/docs", redoc_url=None)
    hosts = allowed_hosts or LOOPBACK_HOSTS
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)   # blocks DNS-rebinding

    @app.middleware("http")
    async def same_origin_and_headers(request: Request, call_next: Any) -> Any:
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin:
                host = origin.split("://", 1)[-1].split("/")[0].rsplit(":", 1)[0].strip("[]")
                if host not in [h.strip("[]") for h in hosts] and "*" not in hosts:
                    return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
            if not request.headers.get("content-type", "").startswith("application/json"):
                return JSONResponse({"detail": "application/json required"}, status_code=415)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    async def run(fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=f"not found: {exc}") from exc

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(PROJECT_ROOT / "static" / "index.html", media_type="text/html",
                            headers={"Cache-Control": "no-store"})   # always serve the current dashboard

    @app.get("/api/config")
    async def config() -> dict:
        from orchestrator import LLMClient
        llm = LLMClient()
        active = llm.enabled and engine.use_llm and LLMClient.sdk_available(llm.provider)
        missing = llm.enabled and engine.use_llm and not LLMClient.sdk_available(llm.provider)
        return {"default_repo": default_repo(), "llm_provider": llm.provider if active else "none",
                "llm_model": llm.model if active else None, "offline": os.environ.get("SCG_OFFLINE") == "1",
                "llm_error": (f"{llm.provider} key found but its SDK is not installed for {sys.executable}; "
                              f"start the server with .venv/bin/python") if missing else None}

    @app.get("/api/result")
    async def result() -> Any:
        res = engine.refresh_result()
        return res.model_dump(mode="json") if res else {}

    @app.post("/api/scan")
    async def scan(req: ScanRequest) -> Any:
        res = await run(engine.scan, req.repo, req.use_llm, req.resolve_lockfile)
        return res.model_dump(mode="json")

    @app.post("/api/check-pkg")
    async def check_pkg(req: CheckPkgRequest) -> Any:
        res = await run(engine.check_pkg, req.repo, req.pkg)
        return {"admission": res.model_dump(mode="json"), "result": engine.refresh_result().model_dump(mode="json")}

    @app.post("/api/replay")
    async def replay(req: ReplayRequest) -> Any:
        res = await run(engine.replay, req.repo, req.commits)
        return {"replay": res.model_dump(mode="json"), "result": engine.refresh_result().model_dump(mode="json")}

    @app.post("/api/simulate-attack")
    async def simulate(req: SimulateRequest) -> Any:
        res = await run(engine.simulate_attack, req.repo)
        return res.model_dump(mode="json")

    @app.get("/api/daemon/status")
    async def daemon_status() -> Any:
        return engine.daemon.status.model_dump(mode="json")

    @app.post("/api/daemon/toggle")
    async def daemon_toggle(req: DaemonToggleRequest) -> Any:
        if engine.daemon.status.running:
            return engine.daemon.stop().model_dump(mode="json")
        try:
            await asyncio.to_thread(engine.resolve, req.repo)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return engine.daemon.start(req.repo, req.interval, req.demo_drift).model_dump(mode="json")

    STATE = engine.state   # STATE["mitigations"][finding_id], STATE["decision_log"] (shared with the engine)

    @app.get("/api/mitigations")
    async def mitigations() -> Any:
        return {"mitigations": {k: v.model_dump(mode="json") for k, v in STATE["mitigations"].items()},
                "decision_log": STATE["decision_log"][-200:]}

    @app.post("/api/mitigations/validate")
    async def validate_mitigation(req: ValidationRequest) -> Any:
        if req.finding_id not in STATE["mitigations"]:
            raise HTTPException(status_code=404, detail=f"no mitigation package for finding {req.finding_id}")
        pkg = await run(engine.validate_mitigation, req.finding_id, req.decision, req.reviewer, req.justification,
                        req.chosen_candidate_id)
        return pkg.model_dump(mode="json")

    # ---- agentic remediation -------------------------------------------------- #
    @app.post("/api/remediation/start")
    async def remediation_start(req: StartRemediation) -> Any:
        return await run(engine.start_remediation, req.finding_ids, req.max_iterations, req.run_tests, req.use_llm)

    @app.get("/api/remediation/session")
    async def remediation_session() -> Any:
        return engine.remediation_state()

    @app.post("/api/remediation/stop")
    async def remediation_stop() -> Any:
        return engine.stop_remediation()

    @app.post("/api/remediation/prepare-apply")
    async def remediation_prepare(req: PrepareApply) -> Any:
        if engine.remediation is None:
            raise HTTPException(status_code=409, detail="no remediation session")
        return await run(engine.remediation.prepare_apply, req.accepted_change_ids)

    @app.post("/api/remediation/apply")
    async def remediation_apply(req: ConfirmApply) -> Any:
        if engine.remediation is None:
            raise HTTPException(status_code=409, detail="no remediation session")
        if not req.confirm:
            raise HTTPException(status_code=400, detail="explicit confirmation required (confirm: true)")
        return await run(engine.remediation.confirm_apply, req.digest)

    @app.post("/api/chat")
    async def chat(req: ChatRequest) -> Any:
        if engine.orch is None:
            raise HTTPException(status_code=409, detail="run a scan first")
        res = await run(engine.orch.answer, req.message, req.session_id)
        return res.model_dump(mode="json")

    @app.get("/api/stream")
    async def stream(request: Request) -> StreamingResponse:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        def push(ev: Any) -> None:
            def put() -> None:
                if not queue.full():
                    queue.put_nowait(ev)
            loop.call_soon_threadsafe(put)

        unsubscribe = bus.subscribe(push)

        async def gen() -> AsyncIterator[str]:
            try:
                for ev in bus.history()[-150:]:
                    yield f"data: {ev.model_dump_json()}\n\n"
                while not await request.is_disconnected():
                    try:
                        ev = await asyncio.wait_for(queue.get(), timeout=15)
                        yield f"data: {ev.model_dump_json()}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                unsubscribe()

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


# --------------------------------------------------------------------------- #
# CLI rendering
# --------------------------------------------------------------------------- #
def _console() -> Any:
    from rich.console import Console
    return Console()


def print_cards(cards: list, limit: int = 8) -> None:
    from rich.panel import Panel
    from rich.markup import escape
    con = _console()
    colour = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green"}
    for c in cards[:limit]:
        sev = c.finding.severity.value
        math = " + ".join(f"{x.points:g}" for x in c.risk.components if x.max_points) + \
            "".join(f" [{a.effect}]" for a in c.risk.adjustments) + f" = {c.risk.total}/100"
        v = c.validation
        body = (f"[bold]1. Finding[/] {escape(c.finding.title)}\n   purl: {escape(str(c.finding.purl))}  "
                f"ids: {escape(', '.join(c.finding.advisory_ids[:3]))}\n"
                f"[bold]2. Location[/] {escape(c.location.local_file)}:{c.location.local_line}\n"
                f"[dim]{escape(c.location.code_snippet[:500])}[/]\n"
                f"[bold]3. Attack path[/] (depth {c.attack_path.call_chain_depth})\n   " +
                "\n   ".join(escape(h) for h in c.attack_path.hops[:6]) +
                f"\n[bold]4. Risk[/] {math} -> {sev} · {c.risk.priority} · confidence {c.risk.confidence_level} "
                f"({c.risk.confidence:.2f})\n   " +
                "\n   ".join(escape(f"{x.points:g}/{x.max_points:g} {x.factor}: {x.detail}") for x in c.risk.components) +
                "".join("\n   " + escape(f"{a.effect} {a.label}") for a in c.risk.adjustments) +
                "".join("\n   [dim]" + escape(f"{x.name}: {x.value}" + (f" (as of {x.as_of})" if x.as_of else "")) + "[/]"
                        for x in c.risk.factors.sources[:6]) +
                f"\n[bold]5. Remediation[/] {escape(c.remediation.summary)}\n   $ {escape(c.remediation.fix_command)}\n" +
                (f"   root cause ({escape(c.remediation.root_cause_kind or '')}): {escape(c.remediation.root_cause)}\n"
                 if c.remediation.root_cause else "") +
                f"[dim]{escape(c.narrative[:400])}[/]\n"
                f"Validator: {'[green]PASSED[/]' if v and v.passed else '[red]FAILED[/]'} (author={c.author}"
                f"{', fallback' if v and v.fell_back_to_deterministic else ''})")
        con.print(Panel(body, title=f"[{colour[sev]}]{c.finding.finding_id}  {sev}  {c.risk.total}/100  {c.risk.priority}[/]",
                        border_style=colour[sev]))


def print_scan(res: Any) -> None:
    from rich.table import Table
    from rich.markup import escape
    con = _console()
    k = res.kpis
    con.print(f"\n[bold]Components[/] {k.total_components}   [bold]Raw alerts[/] {k.raw_scanner_alerts}   "
              f"[bold red]Actionable critical[/] {k.actionable_critical}   [bold green]Downgraded noise[/] {k.downgraded_noise}"
              f"   (sbom={res.sbom_source}, advisories={res.vuln_source})")
    for n in res.notes:
        con.print(f"[yellow]note:[/] {escape(n)}")
    intel = res.intel or {}
    if intel:
        con.print(f"[bold]Threat intel[/] CISA KEV {'catalog ' + str(intel.get('kev_version')) if intel.get('kev_checked') else 'not checked'}"
                  f" · FIRST EPSS {('data ' + str(intel.get('epss_date'))) if intel.get('epss_checked') else 'not checked'}")
    t = Table(title="Findings (risk score 0-100, highest first)", show_lines=False)
    for col in ("ID", "Score", "Level", "Priority", "Conf.", "EPSS", "KEV", "Reach", "Exposure", "Title"):
        t.add_column(col)
    for f in res.findings[:40]:
        x = f.risk.factors
        t.add_row(f.id, str(f.risk.total), f.risk.severity.value, f.risk.priority.split()[0], f.risk.confidence_level,
                  f"{x.epss:.3f}" if x.epss is not None else "-", {True: "YES", False: "no", None: "-"}[x.kev],
                  x.reachability if x.threat_class is None else "-", x.exposure if x.threat_class is None else "-",
                  escape(f.title[:70]))
    con.print(t)
    st = res.dependency_stats
    if st.packages:
        heavy = ", ".join(f"{escape(h['label'])} (+{h['pulls_in']})" for h in st.heaviest_direct[:3])
        con.print(f"[bold]Dependency graph[/] {st.packages} packages: {st.direct} direct"
                  f"{f' ({st.direct_inferred} inferred)' if st.direct_inferred else ''}, {st.transitive} transitive, "
                  f"max depth {st.max_depth}, {st.edges} edges" + (f"; heaviest: {heavy}" if heavy else ""))
    if res.fix_groups:
        g = Table(title="Fix first: vulnerabilities grouped by root cause", show_lines=False)
        for col in ("Group", "Worst", "Findings", "Action", "Command"):
            g.add_column(col)
        for grp in res.fix_groups[:10]:
            g.add_row(grp.id, f"{grp.max_severity.value} {grp.max_score}", str(len(grp.findings)),
                      escape(grp.action[:90]), escape(grp.command))
        con.print(g)
    info = [a for a in res.anomalies if not a.scored]
    if info:
        con.print("[dim]Informational (not scored): " + "; ".join(escape(f"{a.file}:{a.line} {a.title}") for a in info[:8]) + "[/]")
    print_cards(res.cards, limit=5)


def print_remediation(engine: Any) -> None:
    from rich.markup import escape
    from rich.table import Table
    con = _console()
    a = engine.remediation
    m = a.mem
    con.print(f"\n[bold]Remediation session {m.session_id}[/] driver={m.driver} status={m.status}\n{escape(m.summary)}")
    t = Table(title="Target findings (status decided by the independent validator)")
    for col in ("Finding", "Severity", "Score", "Status", "Reason"):
        t.add_column(col)
    for x in m.targets:
        t.add_row(escape(x.key[:70]), x.severity, str(x.score), x.status, escape(x.reason[:80]))
    con.print(t)
    for v in m.validations:
        con.print(f"  iteration {v.iteration}: verdict {v.verdict}, max risk {v.risk.get('max')}, resolved {len(v.resolved_vs_baseline)}, "
                  f"new {len(v.new_vs_baseline)}, graph {'ok' if v.graph_consistency.get('ok') else 'INCONSISTENT'}, tests {v.tests.get('status')}")
    for c in m.changes:
        con.print(f"[bold]{c.change_id}[/] {c.tool} ({c.status}, impact {c.impact}) {escape(c.reason[:100])}")
        for f in c.files:
            con.print(f"[dim]{escape(f.diff[:1500])}[/]")
    patch = a.audit_path.with_suffix(".patch")
    patch.write_text("".join(a.candidate_diff().values()), encoding="utf-8")
    con.print(f"\nCandidate patch: {patch}\nAudit log: {a.audit_path}\n"
              "Nothing was written to the repository. Review and approve individual changes in the dashboard "
              "(Remediation tab) to apply them.")


def validate_interactively(engine: Any, only_gated: bool = True) -> None:
    """--validate: candidate comparison per finding, then approve / accept risk / reject & escalate."""
    from rich.markup import escape
    from rich.table import Table
    con = _console()
    pkgs = sorted(engine.state["mitigations"].values(), key=lambda p: (not p.requires_human_validation, -p.risk_score))
    if only_gated:
        pkgs = [p for p in pkgs if p.requires_human_validation and p.human_validation.decision == HumanDecisionType.PENDING]
    if not pkgs:
        con.print("[green]No findings are waiting for human validation.[/]")
        return
    interactive = sys.stdin.isatty()
    reviewer = os.environ.get("USER") or "reviewer"
    if interactive:
        reviewer = input(f"Reviewer name [{reviewer}]: ").strip() or reviewer
    con.print(f"\n[bold]{len(pkgs)} finding(s) need a human decision[/] (Python never applies a fix; this records the decision)")
    for p in pkgs:
        t = Table(title=f"{p.finding_id}  {escape(p.package_name)}@{escape(p.current_version)}  risk {p.risk_score}/100"
                        f"{'  production' if p.is_production else '  dev/test'}", show_lines=False)
        for col in ("#", "Candidate", "Source", "Action", "Target", "SemVer", "Compat Risk", "Fit Score", "Risk (expected)"):
            t.add_column(col)
        for i, c in enumerate(p.candidates, 1):
            rec = " *" if c.candidate_id == p.recommended_candidate_id else ""
            t.add_row(str(i), c.candidate_id + rec, c.source + (f" +{','.join(c.also_reported_by)}" if c.also_reported_by else ""),
                      c.action_type.value, escape(c.target_version_or_ref), c.semver_jump, c.compatibility_risk.value, str(c.fit_score),
                      f"{c.expected_risk_before} -> {c.expected_risk_after}" if c.expected_risk_before is not None else "-")
        con.print(t)
        for r in p.escalation_reasons:
            con.print(f"  [yellow]gate:[/] {escape(r)}")
        con.print(f"  [dim]{escape(p.ai_tradeoff_summary)} ({p.summary_author})[/]")
        for c in p.candidates:
            if c.breaking_changes:
                con.print(f"  [red]{c.candidate_id} breaking:[/] " + escape("; ".join(c.breaking_changes[:3])))
        if not interactive:
            continue
        while True:
            ans = input("  [number]=approve candidate, a=accept risk, r=reject & escalate, s=skip, q=quit > ").strip().lower()
            try:
                if ans == "q":
                    return
                if ans in ("", "s"):
                    break
                if ans == "a":
                    why = input("  justification (min 8 chars): ")
                    engine.validate_mitigation(p.finding_id, HumanDecisionType.ACCEPTED_RISK, reviewer, why)
                elif ans == "r":
                    why = input("  reason (optional): ")
                    engine.validate_mitigation(p.finding_id, HumanDecisionType.REJECTED_ESCALATED, reviewer, why)
                elif ans.isdigit() and 1 <= int(ans) <= len(p.candidates):
                    cand = p.candidates[int(ans) - 1]
                    why = input("  note (optional): ")
                    engine.validate_mitigation(p.finding_id, HumanDecisionType.APPROVED, reviewer, why, cand.candidate_id)
                    con.print(f"  approved. Apply it yourself when ready:\n  $ {escape(cand.apply_command)}\n"
                              f"  rollback: $ {escape(cand.rollback_command)}")
                else:
                    con.print("  [yellow]unknown choice[/]")
                    continue
                break
            except ValueError as exc:
                con.print(f"  [red]{escape(str(exc))}[/]")
    con.print(f"[green]Decisions are logged in {engine._decision_file(engine.ctx.repo)}[/]")


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Continuous agentic software supply-chain security (read-only).")
    p.add_argument("--repo", default=default_repo(),
                   help="local path or public GitHub URL (https://github.com/owner/repo[/tree/<branch>]) of the target repository")
    p.add_argument("--mode", default="scan", choices=["scan", "check-pkg", "replay", "daemon", "simulate-attack", "serve", "remediate"])
    p.add_argument("--iterations", type=int, default=5, help="remediate: iteration limit (1-10)")
    p.add_argument("--findings", default="", help="remediate: comma-separated finding ids (default: top findings)")
    p.add_argument("--sandbox-tests", action="store_true", help="remediate: run the project's tests in a Docker sandbox")
    p.add_argument("--pkg", help="candidate package for check-pkg, e.g. reqeusts@1.0.0 or pypi:requests==2.31.0")
    p.add_argument("--commits", type=int, default=5)
    p.add_argument("--interval", type=int, default=30)
    p.add_argument("--max-polls", type=int, default=None, help="daemon: stop after N polls")
    p.add_argument("--demo-drift", action="store_true", help="daemon: inject one clearly-labelled synthetic advisory on poll 2")
    p.add_argument("--no-llm", action="store_true", help="deterministic triage only; nothing is sent to an LLM provider")
    p.add_argument("--offline", action="store_true", help="no network: no OSV / registry lookups (demo advisories)")
    p.add_argument("--resolve-lockfile", action="store_true",
                   help="opt-in: resolve a lockfile from registry metadata (npm --package-lock-only --ignore-scripts in a temp dir)")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--keep-sandbox", action="store_true", help="simulate-attack: keep the temp sandbox for inspection")
    p.add_argument("--json-out", help="write the result as JSON to this path")
    p.add_argument("--validate", action="store_true",
                   help="scan: show mitigation candidates and record human decisions for gated findings")
    p.add_argument("--validate-all", action="store_true", help="with --validate: also review auto-approved findings")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--allow-remote", action="store_true",
                   help="allow binding to a non-loopback interface (the API can read repository files: think twice)")
    args = p.parse_args(argv)
    if args.offline:
        os.environ["SCG_OFFLINE"] = "1"

    bus = LogBus(console=True)
    engine = Engine(bus)
    engine.use_llm = not args.no_llm

    if args.mode == "serve":
        import uvicorn
        os.environ["SCG_DEFAULT_REPO"] = args.repo   # pre-fills the dashboard's repo box
        if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
            print("Refusing to bind to a non-loopback address without --allow-remote.", file=sys.stderr)
            return 2
        hosts = LOOPBACK_HOSTS + ([args.host] if args.allow_remote else [])
        app = create_app(engine, bus, hosts)
        print(f"Dashboard: http://127.0.0.1:{args.port}/   (default repo: {args.repo})")
        from orchestrator import LLMClient
        _llm = LLMClient()
        if _llm.enabled and not args.no_llm:
            ok = LLMClient.sdk_available(_llm.provider)
            print(f"LLM: {_llm.provider} ({_llm.model}) via {sys.executable}" if ok else
                  f"WARNING: {_llm.provider} key found but its SDK is missing for {sys.executable}. "
                  f"Use .venv/bin/python main.py ... (LLM features are off until then).")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
        return 0

    result: Any
    try:
        if args.mode == "scan":
            result = engine.scan(args.repo, use_llm=not args.no_llm, resolve_lockfile=args.resolve_lockfile,
                                 use_cache=not args.no_cache)
            print_scan(result)
            if args.validate or args.validate_all:
                validate_interactively(engine, only_gated=not args.validate_all)
                result = engine.refresh_result()
        elif args.mode == "check-pkg":
            if not args.pkg:
                p.error("--pkg is required for check-pkg")
            engine.scan(args.repo, use_llm=not args.no_llm, resolve_lockfile=args.resolve_lockfile)
            result = engine.check_pkg(args.repo, args.pkg)
            con = _console()
            colour = "red" if result.decision.value == "BLOCKED" else "green"
            con.print(f"\n[bold {colour}]{result.decision.value}[/] {result.package}@{result.version} "
                      f"(metadata: {result.metadata_source})")
            for s in result.signals:
                con.print(f"  {'[red]x[/]' if s.triggered and s.hard_block else ('[yellow]![/]' if s.triggered else '[green]ok[/]')} "
                          f"{s.name}: {s.detail}")
            for e in result.errors:
                con.print(f"  [dim]{e}[/]")
            if result.card:
                print_cards([result.card])
        elif args.mode == "replay":
            result = engine.replay(args.repo, args.commits)
            con = _console()
            for c in result.commits:
                con.print(f"[bold]{c.sha}[/] {c.subject[:70]}  +{len(c.added)} -{len(c.removed)} ~{len(c.changed)}  "
                          f"anomalies={len(c.anomalies)}  gate={[a.decision.value for a in c.admissions]}  triaged={c.triaged}")
            for n in result.notes:
                con.print(f"[yellow]{n}[/]")
        elif args.mode == "daemon":
            engine.scan(args.repo, use_llm=not args.no_llm, resolve_lockfile=args.resolve_lockfile)
            try:
                asyncio.run(engine.daemon.run_foreground(args.repo, args.interval, args.max_polls, args.demo_drift))
            except KeyboardInterrupt:
                pass
            result = engine.daemon.status
            print(result.model_dump_json(indent=2))
        elif args.mode == "remediate":
            engine.scan(args.repo, use_llm=not args.no_llm, resolve_lockfile=args.resolve_lockfile)
            ids = [x.strip() for x in args.findings.split(",") if x.strip()]
            engine.start_remediation(ids, args.iterations, args.sandbox_tests, use_llm=not args.no_llm, background=False)
            print_remediation(engine)
            result = engine.remediation.mem
        else:  # simulate-attack
            result = engine.simulate_attack(args.repo, keep_sandbox=args.keep_sandbox)
            con = _console()
            print_cards(result.cards)
            con.print(f"\n[bold {'green' if result.blocked else 'red'}]"
                      f"{'ATTACK INTERCEPTED AND BLOCKED' if result.blocked else 'ATTACK NOT FULLY BLOCKED'}[/] "
                      f"max risk {result.max_score}/100; sandbox removed={result.sandbox_removed}")
            for n in result.safety_notes:
                con.print(f"[dim]safety: {n}[/]")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
    if args.mode == "check-pkg" and result.decision.value == "BLOCKED":
        return 3   # non-zero so CI / pre-commit hooks can gate on it
    if args.mode == "simulate-attack" and not result.blocked:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
