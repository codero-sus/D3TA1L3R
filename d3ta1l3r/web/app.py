"""FastAPI dashboard.

Endpoints
---------
``GET  /``                        dashboard: start a scan, browse past runs
``POST /api/scans``               start a scan (JSON body)
``GET  /api/scans``               list stored scans
``GET  /api/scans/{id}``          full report JSON
``GET  /api/scans/{id}/events``   Server-Sent Events progress stream
``GET  /api/scans/{id}/report.{json,md,html}``  downloads
``GET  /api/sources``             source inventory (what gets checked, and why not)
``POST /api/calibrate``           run a false-positive calibration pass
``GET  /api/health``              liveness + effective settings
``DELETE /api/scans/{id}``        delete a stored scan

The frontend uses only relative URLs, so it works unchanged behind a reverse
proxy (including the sandbox preview host) and never calls localhost directly.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .. import __version__
from ..config import RateLimitConfig, ScanConfig
from ..core.engine import ScanEngine
from ..core.report import render_html, render_json, render_markdown
from ..core.storage import ScanStore
from ..errors import D3ta1l3rError, UsageError
from ..models import Confidence, ScanEvent, ScanReport, ScanTarget
from ..sources.probe import load_site_specs

_HERE = Path(__file__).resolve().parent
_MAX_EVENTS = 500
_SSE_HEARTBEAT_SECONDS = 15.0
_MAX_TARGETS = 8
"""Upper bound on how many identifier combinations one dashboard scan may expand to."""


@dataclass(slots=True)
class AppSettings:
    output_dir: Path = Path("scans")
    demo: bool = False
    config: ScanConfig = field(default_factory=ScanConfig)
    title: str = "D3TA1L3R"

    def base_config(self) -> ScanConfig:
        return self.config


class ScanRequest(BaseModel):
    """Body of ``POST /api/scans``. Everything is optional except an identifier."""

    username: str | None = None
    email: str | None = None
    name: str | None = None
    domain: str | None = None
    location: str | None = None
    demo: bool | None = None
    sources: list[str] | None = None
    exclude_sources: list[str] | None = None
    categories: list[str] | None = None
    kinds: list[str] | None = None
    max_sites: int | None = Field(default=None, ge=1, le=1000)
    min_confidence: Confidence | None = None
    respect_robots: bool | None = None
    concurrency: int | None = Field(default=None, ge=1, le=64)

    def targets(self) -> list[ScanTarget]:
        """Expand the supplied identifiers into validated scan targets.

        Each field accepts a comma-separated list (``alice, alice_dev``), and the
        combination of fields is capped so one request cannot fan out into a
        long-running batch nobody is watching.
        """
        fields = {
            key: _split_list(getattr(self, key))
            for key in ("username", "email", "name", "domain")
        }
        combos: list[dict[str, Any]] = [{}]
        for key, values in fields.items():
            if values:
                combos = [{**combo, key: value} for combo in combos for value in values]
        if combos == [{}]:
            return []
        if len(combos) > _MAX_TARGETS:
            raise UsageError(
                f"that would expand to {len(combos)} separate scans; the dashboard runs at "
                f"most {_MAX_TARGETS} per request — split it up"
            )
        return [
            ScanTarget.create(location=self.location, **combo) for combo in combos
        ]


@dataclass
class RunState:
    """In-memory state for one dashboard-initiated scan."""

    run_id: str
    targets: list[ScanTarget]
    demo: bool
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "queued"  # queued | running | done | error
    events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=_MAX_EVENTS))
    reports: list[ScanReport] = field(default_factory=list)
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    task: asyncio.Task | None = None
    error: str | None = None
    finished_at: datetime | None = None

    @property
    def primary(self) -> ScanReport | None:
        return self.reports[-1] if self.reports else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "demo": self.demo,
            "created_at": self.created_at.isoformat(),
            "targets": [t.display() for t in self.targets],
            "scan_ids": [r.scan_id for r in self.reports],
            "findings": sum(r.stats.findings_total for r in self.reports),
            "error": self.error,
            "events": list(self.events)[-25:],
        }


def create_app(settings: AppSettings | None = None) -> FastAPI:
    settings = settings or AppSettings()
    store = ScanStore(settings.output_dir)
    runs: dict[str, RunState] = {}

    app = FastAPI(
        title="D3TA1L3R dashboard",
        version=__version__,
        description="Self-audit dashboard for your own public footprint.",
    )
    app.state.settings = settings
    app.state.store = store
    app.state.runs = runs
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(_HERE / "templates"))

    def _context(request: Request, **extra: Any) -> dict[str, Any]:
        return {
            "request": request,
            "version": __version__,
            "title": settings.title,
            "demo_default": settings.demo,
            **extra,
        }

    def _render(request: Request, name: str, **extra: Any) -> HTMLResponse:
        """Render a template across Starlette versions.

        Starlette >= 0.29 wants ``TemplateResponse(request, name, context)``;
        older releases want ``TemplateResponse(name, context)``. The context
        always carries ``request``, so both paths work.
        """
        context = _context(request, **extra)
        try:
            return templates.TemplateResponse(request, name, context)
        except TypeError:  # pragma: no cover - Starlette < 0.29
            return templates.TemplateResponse(name, context)

    # -- pages -----------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return _render(
            request,
            "index.html",
            scans=[meta.to_dict() for meta in store.list(limit=25)],
            categories=sorted({spec.category for spec in load_site_specs()}),
            sources_count=len([s for s in load_site_specs() if s.enabled_by_default]),
        )

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_page(request: Request, scan_id: str) -> HTMLResponse:
        run = runs.get(scan_id)
        if run is not None:
            return _render(request, "run.html", run=run.to_dict(), scan_id=scan_id)
        report = store.load(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"no such scan: {scan_id}")
        return _render(
            request,
            "scan.html",
            report=report,
            report_json=report.to_dict(),
            grouped=report.findings_by_category(),
        )

    @app.get("/sources", response_class=HTMLResponse)
    async def sources_page(request: Request) -> HTMLResponse:
        engine = ScanEngine(settings.base_config())
        return _render(request, "sources.html", sources=engine.describe_sources())

    # -- api -------------------------------------------------------------
    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        config = settings.base_config()
        return {
            "status": "ok",
            "version": __version__,
            "demo_default": settings.demo,
            "output_dir": str(store.directory),
            "respect_robots": config.respect_robots,
            "concurrency": config.rate.global_concurrency,
            "timeout": config.timeout,
            "stored_scans": len(store.list()),
        }

    @app.get("/api/sources")
    async def api_sources() -> dict[str, Any]:
        engine = ScanEngine(settings.base_config())
        rows = engine.describe_sources()
        return {"count": len(rows), "sources": rows}

    @app.get("/api/scans")
    async def api_scans() -> dict[str, Any]:
        stored = [meta.to_dict() for meta in store.list()]
        active = [run.to_dict() for run in runs.values()]
        return {"stored": stored, "active": active}

    @app.get("/api/scans/{scan_id}")
    async def api_scan(scan_id: str) -> JSONResponse:
        run = runs.get(scan_id)
        if run is not None:
            return JSONResponse(run.to_dict())
        report = store.load(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"no such scan: {scan_id}")
        return JSONResponse(report.to_dict())

    @app.post("/api/scans")
    async def api_start_scan(payload: ScanRequest) -> JSONResponse:
        try:
            targets = payload.targets()
        except UsageError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not targets:
            raise HTTPException(status_code=400, detail="supply at least one identifier")

        config = _scan_config(settings, payload)
        run = RunState(run_id=_new_run_id(), targets=targets, demo=config.demo)
        runs[run.run_id] = run
        run.task = asyncio.create_task(_execute_run(run, config, store))
        return JSONResponse(_run_payload(run), status_code=202)

    @app.get("/api/scans/{scan_id}/events")
    async def api_events(scan_id: str, request: Request) -> StreamingResponse:
        run = runs.get(scan_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"no live run named {scan_id}")
        queue: asyncio.Queue = asyncio.Queue()
        run.subscribers.add(queue)

        async def stream():
            try:
                for event in list(run.events):
                    yield _sse(event)
                if run.status in {"done", "error"}:
                    yield _sse({"type": "run_finished", "status": run.status})
                    return
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=_SSE_HEARTBEAT_SECONDS)
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
                        continue
                    yield _sse(event)
                    if event.get("type") in {"run_finished", "run_error"}:
                        break
            finally:
                run.subscribers.discard(queue)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",  # ask proxies not to buffer SSE
            },
        )

    @app.get("/api/scans/{scan_id}/report.{suffix}")
    async def api_report(scan_id: str, suffix: str) -> Any:
        report = store.load(scan_id) or _run_report(runs.get(scan_id))
        if report is None:
            raise HTTPException(status_code=404, detail=f"no such scan: {scan_id}")
        if suffix == "json":
            return PlainTextResponse(render_json(report), media_type="application/json")
        if suffix in {"md", "markdown"}:
            return PlainTextResponse(render_markdown(report), media_type="text/markdown")
        if suffix == "html":
            return HTMLResponse(render_html(report))
        raise HTTPException(status_code=400, detail="suffix must be json, md or html")

    @app.delete("/api/scans/{scan_id}")
    async def api_delete_scan(scan_id: str) -> dict[str, Any]:
        run = runs.pop(scan_id, None)
        if run and run.task and not run.task.done():
            run.task.cancel()
        removed = store.delete(scan_id)
        if removed == 0 and run is None:
            raise HTTPException(status_code=404, detail=f"no such scan: {scan_id}")
        return {"deleted_files": removed, "scan_id": scan_id}

    @app.post("/api/calibrate")
    async def api_calibrate(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the bogus-handle false-positive check on the HTML probes."""
        from ..cli import _calibration_row  # reuse the CLI's verdict logic

        site_ids = set((payload or {}).get("sites") or [])
        samples = int((payload or {}).get("absent_samples") or 1)
        specs = [spec for spec in load_site_specs() if not site_ids or spec.id in site_ids]
        if not specs:
            raise HTTPException(status_code=400, detail="no matching site ids")

        from ..sources.probe import UsernameProbeSource

        engine = ScanEngine(settings.base_config(), sources=[UsernameProbeSource(s) for s in specs])
        results = {spec.id: {"id": spec.id, "name": spec.name, "absent_probes": [],
                             "present_probe": None} for spec in specs}
        for _ in range(max(1, samples)):
            bogus = "zzq" + _random_token(12)
            report = await engine.scan(ScanTarget.create(username=bogus))
            for outcome in report.outcomes:
                entry = results.get(outcome.source_id)
                if entry is None:
                    continue
                entry["absent_probes"].append(
                    {
                        "handle": bogus,
                        "status": outcome.status.value,
                        "http_status": outcome.http_status,
                        "evidence": outcome.findings[0].evidence if outcome.findings else outcome.error,
                    }
                )
        rows = [_calibration_row(entry) for entry in results.values()]
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sites": rows,
            "false_positive_sites": [r["id"] for r in rows if r["counts"]["false_positive"]],
        }

    return app


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _scan_config(settings: AppSettings, payload: ScanRequest) -> ScanConfig:
    base = settings.base_config()
    rate = base.rate
    if payload.concurrency:
        rate = RateLimitConfig(
            per_host_rps=rate.per_host_rps,
            per_host_burst=rate.per_host_burst,
            global_concurrency=payload.concurrency,
            max_retries=rate.max_retries,
            backoff_base=rate.backoff_base,
            backoff_max=rate.backoff_max,
            honor_retry_after=rate.honor_retry_after,
        )
    return base.replaced(
        rate=rate,
        demo=settings.demo if payload.demo is None else bool(payload.demo),
        respect_robots=base.respect_robots if payload.respect_robots is None
        else bool(payload.respect_robots),
        enabled_sources=frozenset(payload.sources or ()),
        disabled_sources=frozenset(payload.exclude_sources or ()),
        categories=frozenset(payload.categories or ()),
        kinds=frozenset(payload.kinds or ()),
        max_sites=payload.max_sites,
        use_cache=True,
        cache_dir=base.cache_dir or (_cache_dir(settings.output_dir)),
    )


def _cache_dir(output_dir: Path) -> Path:
    path = Path(output_dir) / ".cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


async def _execute_run(run: RunState, config: ScanConfig, store: ScanStore) -> None:
    run.status = "running"
    _publish(run, {"type": "run_started", "run_id": run.run_id, "demo": config.demo})
    try:
        for target in run.targets:
            engine = ScanEngine(config, on_event=lambda event: _on_event(run, event))
            report = await engine.scan(target)
            report.demo = config.demo
            store.save(report)
            run.reports.append(report)
            _publish(
                run,
                {
                    "type": "scan_completed",
                    "scan_id": report.scan_id,
                    "findings": report.stats.findings_total,
                    "sources": report.stats.sources_total,
                },
            )
        run.status = "done"
    except asyncio.CancelledError:  # pragma: no cover - user deleted the run
        run.status = "error"
        run.error = "cancelled"
        _publish(run, {"type": "run_error", "error": "cancelled"})
        raise
    except D3ta1l3rError as exc:
        run.status = "error"
        run.error = str(exc)
        _publish(run, {"type": "run_error", "error": str(exc)})
    except Exception as exc:
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"
        _publish(run, {"type": "run_error", "error": run.error})
    finally:
        run.finished_at = datetime.now(timezone.utc)
        _publish(run, {"type": "run_finished", "status": run.status})


def _on_event(run: RunState, event: ScanEvent) -> None:
    payload = event.to_dict()
    payload["run_id"] = run.run_id
    _publish(run, payload)


def _publish(run: RunState, event: dict[str, Any]) -> None:
    run.events.append(event)
    for queue in list(run.subscribers):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:  # pragma: no cover - subscriber is too slow
            continue


def _sse(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(event, default=str)}\n\n"


def _run_payload(run: RunState) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "status": run.status,
        "demo": run.demo,
        "targets": [t.display() for t in run.targets],
        "events_url": f"/api/scans/{run.run_id}/events",
        "page_url": f"/scans/{run.run_id}",
    }


def _run_report(run: RunState | None) -> ScanReport | None:
    return run.primary if run else None


def _split_list(value: str | None) -> list[str]:
    """Comma-separated request fields into a clean list of identifiers."""
    if not value:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _new_run_id() -> str:
    return "run_" + _random_token(10)


def _random_token(length: int) -> str:
    import secrets

    return secrets.token_hex(length)[:length]

