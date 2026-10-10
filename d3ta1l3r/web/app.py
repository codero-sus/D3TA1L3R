"""FastAPI dashboard.

Pages
-----
``GET  /``                        dashboard: watchlist, breach watch, past scans
``GET  /login`` ``POST /login``    sign in with the vault passphrase
``POST /logout``                   end the session
``GET  /scans/{id}``               a stored scan, or live progress for a run
``GET  /sources``                  coverage: what gets checked, and what does not

API
---
``POST /api/scans``               start a scan (JSON body)
``GET  /api/scans``               list stored scans
``GET  /api/scans/{id}``          full report JSON
``GET  /api/scans/{id}/events``   Server-Sent Events progress stream
``GET  /api/scans/{id}/report.{json,md,html}``  downloads
``DELETE /api/scans/{id}``        delete a stored scan
``GET  /api/sources``             source inventory
``POST /api/calibrate``           false-positive calibration pass
``GET  /api/vault``               masked watchlist (auth required)
``POST /api/vault/entries``       add a watched identifier (auth required)
``DELETE /api/vault/entries/{id}`` remove one (auth required)
``GET  /api/breach``              last breach-watch result (auth required)
``POST /api/breach/check``        run a breach check now (auth required)
``GET  /api/health``              liveness + effective settings

Two security notes that the routes depend on:

* **When a vault is configured, every page and API needs a session.** The vault
  holds decrypted identifiers, so an authenticated dashboard is the only mode in
  which it is exposed. Mutating requests are additionally origin-checked
  (see :mod:`d3ta1l3r.web.auth`).
* **The frontend uses only relative URLs**, so it works unchanged behind a
  reverse proxy (including the sandbox preview host) and never calls localhost
  directly.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .. import __version__
from ..breach import (
    BreachConfig,
    BreachReport,
    record_outcomes,
    run_breach_check,
    save_breach_report,
    transient_password_entry,
)
from ..config import RateLimitConfig, ScanConfig
from ..core.engine import ScanEngine
from ..core.report import render_html, render_json, render_markdown
from ..core.storage import ScanStore
from ..errors import D3ta1l3rError, UsageError
from ..llm import (
    CATALOG,
    CORTEX_DEFAULT_HOST,
    ChatSession,
    build_context,
    model_doctor,
    select_backend,
    verify_findings,
)
from ..llm import models as model_catalog
from ..models import Confidence, ScanEvent, ScanReport, ScanTarget
from ..sources.probe import load_site_specs
from ..vault import Vault, VaultError, VaultKind
from .auth import (
    MUTATING_METHODS,
    AuthSettings,
    LoginThrottle,
    SessionManager,
    clear_session_cookie,
    client_key,
    default_trusted_origins,
    origin_allowed,
    set_session_cookie,
)

_HERE = Path(__file__).resolve().parent
_MAX_EVENTS = 500
_SSE_HEARTBEAT_SECONDS = 15.0
_MAX_TARGETS = 8
"""Upper bound on how many identifier combinations one dashboard scan may expand to."""
_SAFE_NEXT_PREFIX = "/"


@dataclass(slots=True)
class AppSettings:
    output_dir: Path = Path("scans")
    demo: bool = False
    config: ScanConfig = field(default_factory=ScanConfig)
    title: str = "D3TA1L3R"
    auth: AuthSettings = field(default_factory=AuthSettings)
    vault: Vault | None = None
    vault_path: Path | None = None
    """A vault to unlock at login. The passphrase is never read at startup."""
    breach_config: BreachConfig = field(default_factory=BreachConfig)
    trusted_origins: tuple[str, ...] = ()
    chat_backend: str = "auto"
    """Which local chat backend to prefer. Never remote — see d3ta1l3r.llm."""
    chat_model_path: Path | None = None
    """A GGUF file for llama-cpp-python; None falls back to Ollama, Cortex, then retrieval."""
    ollama_model: str = "auto"
    """Ollama model name; ``auto`` asks the daemon what it has."""
    ollama_host: str = "http://127.0.0.1:11434"
    cortex_model: str = "auto"
    """Cortex model id; ``auto`` asks the Cortex server what it serves."""
    cortex_host: str = "http://127.0.0.1:8624"

    def base_config(self) -> ScanConfig:
        """The config every scan inherits — including the dashboard's demo switch.

        ``demo`` is user-visible state (the banner at the top of every page), so it
        has to reach the engine through one path rather than being applied per call
        site; breach checks derive their own demo flag from this config.
        """
        if self.demo == self.config.demo:
            return self.config
        return self.config.replaced(demo=self.demo)

    @property
    def auth_enabled(self) -> bool:
        """A vault implies a login: there is nothing secret to serve otherwise.

        A configured-but-still-locked vault counts: the passphrase is entered in
        the browser, so the dashboard is already gated before it is unlocked.
        """
        return self.vault is not None or self.vault_path is not None or self.auth.enabled

    def unlock(self, passphrase: str) -> Vault:
        """Decrypt the vault in memory (raises :class:`VaultError` if it is not yours).

        Called by the login route: the same passphrase both signs you in and
        decrypts the watchlist, so there is only ever one secret to remember.
        """
        if self.vault is not None:
            if not self.vault.verify_passphrase(passphrase):
                raise VaultError("wrong passphrase")
            return self.vault
        if self.vault_path is None:
            raise VaultError("no vault is configured")
        return Vault.open(self.vault_path, passphrase)

    @property
    def vault_ready(self) -> bool:
        return self.vault is not None

    def effective_trusted_origins(self) -> tuple[str, ...]:
        return self.trusted_origins or default_trusted_origins()


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
        return [ScanTarget.create(location=self.location, **combo) for combo in combos]


class VaultEntryRequest(BaseModel):
    """Body of ``POST /api/vault/entries``.

    ``value`` carries the secret itself — a password for ``kind=password``. It is
    used in memory, checked, and dropped; only a keyed fingerprint is persisted
    (plus a SHA-1 verifier when ``store_hash`` is set, which is what makes
    automatic re-checks possible).
    """

    kind: VaultKind
    value: str = Field(min_length=1, max_length=320)
    label: str = Field(default="", max_length=80)
    notes: str = Field(default="", max_length=280)
    store_hash: bool = False
    check_now: bool = True


class AskRequest(BaseModel):
    """Body of ``POST /api/ask``.

    ``include_values`` is the operator's explicit choice to put raw identifiers
    in the prompt. The model is local either way; the default is masked because
    a dashboard field should not decide that question on the user's behalf.
    """

    question: str = Field(min_length=1, max_length=600)
    scans: list[str] = Field(default_factory=list)
    limit: int = Field(default=3, ge=1, le=25)
    include_values: bool = False
    backend: str = ""  # "" = whatever the dashboard was started with
    max_findings: int | None = Field(default=None, ge=1, le=200)
    reset: bool = False


class ModelPullRequest(BaseModel):
    """Body of ``POST /api/models/pull``.

    ``confirm`` is the "yes" the CLI asks for interactively. A 5 GB fetch that a
    stray click could start is not a feature, so the browser has to send its
    intent explicitly — the button in the panel shows the size first.
    """

    model: str = Field(min_length=1, max_length=160)
    confirm: bool = False
    force: bool = False


class VerifyRequest(BaseModel):
    """Body of ``POST /api/verify``.

    This endpoint exists so that verification happens *because someone pressed a
    button*. Nothing on the dashboard calls it during a scan, a breach run or an
    ordinary question; the same rules as the CLI apply — a local model, verdicts
    that never touch the measured confidence, and an error rather than a fake
    review when no model is installed.
    """

    scans: list[str] = Field(default_factory=list)
    limit: int = Field(default=3, ge=1, le=25)
    verify_limit: int = Field(default=12, ge=1, le=60)
    only_uncertain: bool = False
    include_values: bool = False
    facts: str = Field(default="", max_length=400)


@dataclass
class ModelPullState:
    """One in-flight ``models pull``, reported to the browser by polling."""

    model: str = ""
    status: str = "idle"  # idle | running | done | error | refused
    phase: str = ""
    done_bytes: int = 0
    total_bytes: int = 0
    path: str = ""
    error: str = ""
    task: asyncio.Task | None = None

    def to_dict(self) -> dict[str, Any]:
        percent = (
            round(self.done_bytes / self.total_bytes * 100)
            if self.total_bytes > 0
            else None
        )
        return {
            "model": self.model,
            "status": self.status,
            "phase": self.phase,
            "done_bytes": self.done_bytes,
            "total_bytes": self.total_bytes,
            "percent": percent,
            "path": self.path,
            "error": self.error,
        }


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


@dataclass
class BreachState:
    """In-memory state for the watchlist checks (the "breach watch")."""

    status: str = "idle"  # idle | running | done | error
    triggered_by: str = ""
    report: BreachReport | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    task: asyncio.Task | None = None
    events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=_MAX_EVENTS))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "triggered_by": self.triggered_by,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "error": self.error,
            "events": list(self.events)[-8:],
        }
        if self.report is not None:
            payload["report"] = self.report.to_dict()
            payload["headline"] = self.report.headline()
        else:
            payload["report"] = None
            payload["headline"] = ""
        return payload


def create_app(settings: AppSettings | None = None) -> FastAPI:
    settings = settings or AppSettings()
    settings.auth.validate()
    store = ScanStore(settings.output_dir)
    runs: dict[str, RunState] = {}
    breach = BreachState()
    sessions = SessionManager(ttl_seconds=settings.auth.session_ttl_seconds)
    throttle = LoginThrottle(
        max_attempts=settings.auth.max_attempts,
        lockout_seconds=settings.auth.lockout_seconds,
    )
    trusted = settings.effective_trusted_origins()
    guard_on = settings.auth_enabled

    app = FastAPI(
        title="D3TA1L3R dashboard",
        version=__version__,
        description="Self-audit dashboard for your own public footprint.",
    )
    app.state.settings = settings
    app.state.store = store
    app.state.runs = runs
    app.state.breach = breach
    app.state.sessions = sessions
    #: One conversation per signed-in session, in memory only. Transcripts are
    #: never written next to the reports: the vault is the encrypted home of the
    #: identifiers, and a plaintext copy of a chat about them would undo that.
    chats: dict[str, ChatSession] = {}
    app.state.chats = chats
    pull = ModelPullState()
    app.state.model_pull = pull
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(_HERE / "templates"))

    # -- auth plumbing ---------------------------------------------------
    def _token(request: Request) -> str | None:
        return request.cookies.get(settings.auth.session_cookie)

    def _signed_in(request: Request) -> bool:
        return True if not guard_on else sessions.verify(_token(request))

    def require_session(request: Request) -> None:
        """API dependency: JSON 401 instead of a redirect, so fetch() can react."""
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")

    def require_vault(request: Request) -> None:
        """Watchlist endpoints need a vault *and* a session — the vault is decrypted data."""
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        if settings.vault is None:  # pragma: no cover - a session implies an unlock
            raise HTTPException(status_code=404, detail="no vault is configured")

    def _guard_page(request: Request) -> RedirectResponse | None:
        if _signed_in(request):
            return None
        target = request.url.path or "/"
        return RedirectResponse(f"/login?next={target}", status_code=303)

    @app.middleware("http")
    async def _origin_guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Refuse cross-site state changes (defence in depth behind SameSite=Lax)."""
        if guard_on and request.method in MUTATING_METHODS and not origin_allowed(request, trusted):
            return JSONResponse(
                {
                    "detail": (
                        "cross-origin request refused. The dashboard validates the "
                        "Origin header; if you are behind a reverse proxy, add its "
                        "origin to D3TA1L3R_TRUSTED_ORIGINS."
                    )
                },
                status_code=403,
            )
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if guard_on:
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    def _context(request: Request, **extra: Any) -> dict[str, Any]:
        return {
            "request": request,
            "version": __version__,
            "title": settings.title,
            "demo_default": settings.demo,
            "auth_enabled": guard_on,
            "signed_in": _signed_in(request),
            "vault_ready": settings.vault_ready,
            **extra,
        }

    def _render(
        request: Request, name: str, *, status_code: int | None = None, **extra: Any
    ) -> HTMLResponse:
        """Render a template across Starlette versions.

        Starlette >= 0.29 wants ``TemplateResponse(request, name, context)``;
        older releases want ``TemplateResponse(name, context)``. The context
        always carries ``request``, so both paths work.
        """
        context = _context(request, **extra)
        try:
            response = templates.TemplateResponse(request, name, context)
        except TypeError:  # pragma: no cover - Starlette < 0.29
            response = templates.TemplateResponse(name, context)
        if status_code is not None:
            response.status_code = status_code
        return response

    def _vault_summary() -> dict[str, Any] | None:
        if settings.vault is None:
            return None
        summary = settings.vault.describe()
        summary["list"] = [
            {
                "entry_id": entry.entry_id,
                "kind": entry.kind.value,
                "kind_label": entry.kind.label,
                "label": entry.display,
                "masked_value": entry.masked,
                "added_at": entry.added_at,
                "recheckable": entry.recheckable,
                "last_checked": entry.last_checked,
                "last_status": entry.last_status,
                "last_count": entry.last_count,
            }
            for entry in settings.vault.watchlist()
        ]
        return summary

    # -- breach watch ----------------------------------------------------
    def _publish_breach(event: dict[str, Any]) -> None:
        breach.events.append(event)

    async def _execute_breach(entries: list[Any], reason: str) -> None:
        breach.status = "running"
        breach.triggered_by = reason
        breach.started_at = datetime.now(timezone.utc)
        breach.error = None
        breach.events.clear()
        _publish_breach(
            {
                "type": "breach_started",
                "message": f"watching {len(entries)} identifier(s) ({reason})",
                "total": len(entries),
            }
        )
        try:
            report = await run_breach_check(
                entries,
                scan_config=settings.base_config(),
                breach_config=settings.breach_config,
                on_event=_publish_breach,
            )
            breach.report = report
            record_outcomes(settings.vault, report)
            save_breach_report(report, settings.output_dir)
            breach.status = "done"
        except asyncio.CancelledError:  # pragma: no cover - server shutting down
            breach.status = "error"
            breach.error = "cancelled"
            raise
        except Exception as exc:
            breach.status = "error"
            breach.error = f"{type(exc).__name__}: {exc}"
        finally:
            breach.finished_at = datetime.now(timezone.utc)
            _publish_breach({"type": "breach_finished", "status": breach.status})

    def _start_breach_run(reason: str) -> bool:
        """Kick off a watchlist check unless one is already in flight."""
        if settings.vault is None:
            return False
        entries = settings.vault.watchlist()
        if not entries:
            breach.status = "done"
            breach.triggered_by = reason
            breach.report = None
            breach.finished_at = datetime.now(timezone.utc)
            return False
        if breach.status == "running" and breach.task and not breach.task.done():
            return False
        breach.task = asyncio.create_task(_execute_breach(entries, reason))
        return True

    app.state.start_breach_run = _start_breach_run  # used by the CLI smoke path

    # -- authentication routes -------------------------------------------
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Any:
        if not guard_on:
            return RedirectResponse("/", status_code=303)
        if _signed_in(request):
            return RedirectResponse(_safe_next(request.query_params.get("next")), status_code=303)
        return _render(
            request,
            "login.html",
            error=None,
            next_path=_safe_next(request.query_params.get("next")),
            locked_for=0,
            max_attempts=settings.auth.max_attempts,
        )

    @app.post("/login")
    async def login_submit(request: Request) -> Any:
        if not guard_on:
            return RedirectResponse("/", status_code=303)
        if settings.vault is None and settings.vault_path is None:
            return RedirectResponse("/", status_code=303)
        form = await request.form()
        passphrase = str(form.get("passphrase") or "")
        next_path = _safe_next(str(form.get("next") or "/"))
        key = client_key(request)

        remaining = throttle.locked_for(key)
        if remaining > 0:
            return _render(
                request,
                "login.html",
                error=f"too many failed attempts — try again in {int(remaining) + 1}s",
                next_path=next_path,
                locked_for=int(remaining) + 1,
                max_attempts=settings.auth.max_attempts,
                status_code=429,
            )

        # The passphrase decrypts the vault. It is verified by re-deriving the
        # scrypt key; a wrong guess costs exactly as much as a right one, and
        # nothing is written anywhere.
        unlocked: Vault | None = None
        if passphrase:
            try:
                unlocked = settings.unlock(passphrase)
            except D3ta1l3rError:
                unlocked = None
        if unlocked is None:
            locked = throttle.record_failure(key)
            message = "wrong passphrase"
            if locked:
                message = f"too many failed attempts — locked for {int(locked)}s"
            return _render(
                request,
                "login.html",
                error=message,
                next_path=next_path,
                locked_for=int(locked),
                max_attempts=settings.auth.max_attempts,
                status_code=401,
            )

        throttle.record_success(key)
        settings.vault = unlocked  # now serve the watchlist for this process
        token, _ttl = sessions.issue()
        # The requested behaviour: a fresh login re-checks the watchlist.
        _start_breach_run("login")
        response = RedirectResponse(next_path, status_code=303)
        set_session_cookie(response, token, settings.auth)
        return response

    @app.post("/logout")
    async def logout(request: Request) -> Any:
        if _token(request):
            chats.pop(hashlib.sha256((_token(request) or "").encode()).hexdigest()[:16], None)
        sessions.revoke(_token(request))
        if settings.vault is not None or settings.vault_path is not None:
            breach.report = None
            breach.status = "idle"
        settings.vault = None  # re-lock: the next login decrypts again
        response = RedirectResponse("/login", status_code=303)
        clear_session_cookie(response, settings.auth)
        return response

    # -- pages -----------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Any:
        redirect = _guard_page(request)
        if redirect is not None:
            return redirect
        return _render(
            request,
            "index.html",
            scans=[meta.to_dict() for meta in store.list(limit=25)],
            categories=sorted({spec.category for spec in load_site_specs()}),
            sources_count=len([s for s in load_site_specs() if s.enabled_by_default]),
            vault=_vault_summary(),
            breach=breach.to_dict(),
            breach_sources=[
                source.describe(settings.breach_config)
                for source in _breach_sources_for_display(settings.breach_config)
            ],
        )

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_page(request: Request, scan_id: str) -> Any:
        redirect = _guard_page(request)
        if redirect is not None:
            return redirect
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
    async def sources_page(request: Request) -> Any:
        redirect = _guard_page(request)
        if redirect is not None:
            return redirect
        engine = ScanEngine(settings.base_config())
        return _render(request, "sources.html", sources=engine.describe_sources())

    # -- api -------------------------------------------------------------
    @app.get("/api/health")
    async def health(request: Request) -> dict[str, Any]:
        """Liveness. Unauthenticated callers get the minimum useful payload."""
        if not _signed_in(request):
            return {"status": "ok", "version": __version__, "auth_required": True}
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
            "auth_required": guard_on,
            "vault": _vault_summary(),
            "breach": {"status": breach.status, "triggered_by": breach.triggered_by},
        }

    @app.get("/api/sources")
    async def api_sources(_: None = Depends(require_session)) -> dict[str, Any]:
        engine = ScanEngine(settings.base_config())
        rows = engine.describe_sources()
        return {"count": len(rows), "sources": rows}

    @app.get("/api/scans")
    async def api_scans(_: None = Depends(require_session)) -> dict[str, Any]:
        stored = [meta.to_dict() for meta in store.list()]
        active = [run.to_dict() for run in runs.values()]
        return {"stored": stored, "active": active}

    @app.get("/api/scans/{scan_id}")
    async def api_scan(scan_id: str, _: None = Depends(require_session)) -> JSONResponse:
        run = runs.get(scan_id)
        if run is not None:
            return JSONResponse(run.to_dict())
        report = store.load(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"no such scan: {scan_id}")
        return JSONResponse(report.to_dict())

    @app.post("/api/scans")
    async def api_start_scan(
        payload: ScanRequest, _: None = Depends(require_session)
    ) -> JSONResponse:
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
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
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
    async def api_report(
        scan_id: str, suffix: str, _: None = Depends(require_session)
    ) -> Any:
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
    async def api_delete_scan(
        scan_id: str, _: None = Depends(require_session)
    ) -> dict[str, Any]:
        run = runs.pop(scan_id, None)
        if run and run.task and not run.task.done():
            run.task.cancel()
        removed = store.delete(scan_id)
        if removed == 0 and run is None:
            raise HTTPException(status_code=404, detail=f"no such scan: {scan_id}")
        return {"deleted_files": removed, "scan_id": scan_id}

    @app.post("/api/calibrate")
    async def api_calibrate(
        payload: dict[str, Any] | None = None, _: None = Depends(require_session)
    ) -> dict[str, Any]:
        """Run the bogus-handle false-positive check on the HTML probes."""
        from ..cli import _calibration_row  # reuse the CLI's verdict logic

        site_ids = set((payload or {}).get("sites") or [])
        samples = int((payload or {}).get("absent_samples") or 1)
        specs = [spec for spec in load_site_specs() if not site_ids or spec.id in site_ids]
        if not specs:
            raise HTTPException(status_code=400, detail="no matching site ids")

        from ..sources.probe import UsernameProbeSource

        engine = ScanEngine(settings.base_config(), sources=[UsernameProbeSource(s) for s in specs])
        results = {
            spec.id: {
                "id": spec.id,
                "name": spec.name,
                "absent_probes": [],
                "present_probe": None,
            }
            for spec in specs
        }
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
                        "evidence": (
                            outcome.findings[0].evidence if outcome.findings else outcome.error
                        ),
                    }
                )
        rows = [_calibration_row(entry) for entry in results.values()]
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sites": rows,
            "false_positive_sites": [r["id"] for r in rows if r["counts"]["false_positive"]],
        }

    # -- chat over your own scans (local model only) ----------------------
    def _chat_context(payload: AskRequest) -> Any:
        """Build the digest the question is answered from, newest scan first."""
        wanted = payload.scans or [meta.scan_id for meta in store.list(limit=payload.limit)]
        reports = []
        for scan_id in wanted:
            report = store.load(scan_id)
            if report is not None:
                reports.append(report)
        watchlist = settings.vault.entries if settings.vault is not None else []
        return build_context(
            reports,
            watchlist=watchlist,
            breach=breach.to_dict(),
            include_values=payload.include_values,
            max_findings_per_scan=payload.max_findings,
        )

    def _chat_for(request: Request, payload: AskRequest) -> ChatSession:
        """One conversation per session cookie, discarded on logout."""
        token = _token(request) or "anonymous"
        key = hashlib.sha256(token.encode()).hexdigest()[:16]
        existing = chats.get(key)
        fresh_context = _chat_context(payload)
        if existing is not None and not payload.reset and existing.context.values_included == (
            payload.include_values
        ):
            existing.context = fresh_context  # reports may have changed since the last turn
            return existing
        backend, notes = select_backend(
            prefer=payload.backend or settings.chat_backend,
            model_path=settings.chat_model_path,
            ollama_model=settings.ollama_model,
            ollama_host=settings.ollama_host,
            cortex_model=settings.cortex_model,
            cortex_host=settings.cortex_host,
            allow_cortex_lan=settings.cortex_host != CORTEX_DEFAULT_HOST,
        )
        session = ChatSession(fresh_context, backend, notes=notes)
        chats[key] = session
        if len(chats) > 64:  # keep memory bounded on a 4 GB machine
            for stale in list(chats)[: len(chats) - 64]:
                chats.pop(stale, None)
        return session

    @app.get("/api/ask/setup")
    async def api_ask_setup(request: Request) -> dict[str, Any]:
        """What could answer a question here. Available before any model is installed."""
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        try:
            return model_doctor(
                settings.chat_model_path,
                ollama_model=settings.ollama_model,
                ollama_host=settings.ollama_host,
                cortex_model=settings.cortex_model,
                cortex_host=settings.cortex_host,
            )
        except Exception as exc:  # a broken daemon must not break the page
            return {
                "ram_budget_mb": 0,
                "selected": None,
                "backends": [],
                "recommendations": [],
                "error": f"the local model probe failed: {exc.__class__.__name__}",
            }

    @app.post("/api/ask")
    async def api_ask(payload: AskRequest, request: Request) -> JSONResponse:
        """Answer a question about the reports in this dashboard."""
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        if not (payload.question or "").strip():
            raise HTTPException(status_code=422, detail="ask a question")
        try:
            session = _chat_for(request, payload)
            answer = session.ask(payload.question)
        except (UsageError, D3ta1l3rError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        body = answer.to_dict(strip_unknown=True)
        body["session"] = {
            "backend": session.backend.name,
            "model": session.backend.model_id,
            "is_model": session.backend.is_model,
            "values_included": session.context.values_included,
            "context_items": len(session.context.items),
            "turns": len(session.history),
            "stored_to_disk": False,
        }
        body["notes"] = list(session.notes)
        return JSONResponse(body)

    @app.post("/api/ask/reset")
    async def api_ask_reset(request: Request) -> dict[str, Any]:
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        token = _token(request) or "anonymous"
        key = hashlib.sha256(token.encode()).hexdigest()[:16]
        session = chats.pop(key, None)
        return {"reset": session is not None, "turns": 0}

    # -- model catalogue (Hugging Face, fetched only on request) ----------
    def _catalogue_rows() -> list[dict[str, Any]]:
        directory = model_catalog.default_models_dir()
        downloaded = {row["id"] for row in model_catalog.list_downloaded(directory)}
        ram = model_catalog.local_ram_mb()
        rows = []
        for spec in CATALOG:
            row = spec.to_dict()
            row["downloaded"] = spec.id in downloaded
            row["fits_ram"] = ram is None or spec.ram_mb <= ram
            rows.append(row)
        return rows

    @app.get("/api/models")
    async def api_models(request: Request) -> dict[str, Any]:
        """The catalogue as the panel shows it: sizes, licences, what is here."""
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        directory = model_catalog.default_models_dir()
        return {
            "models": _catalogue_rows(),
            "directory": str(directory),
            "disk": model_catalog.describe_disk(directory),
            "pull": pull.to_dict(),
            "downloads_require_confirmation": True,
        }

    @app.post("/api/models/pull")
    async def api_model_pull(payload: ModelPullRequest, request: Request) -> JSONResponse:
        """Fetch one model, after the browser has said yes to that exact file."""
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        if not payload.confirm:
            raise HTTPException(
                status_code=400,
                detail="a download needs an explicit confirmation — nothing was fetched",
            )
        if pull.status == "running" and pull.task and not pull.task.done():
            raise HTTPException(
                status_code=409, detail=f"already downloading {pull.model} — one at a time"
            )
        directory = model_catalog.default_models_dir()
        spec = model_catalog.find_model(payload.model, specs=model_catalog.catalogue(directory))
        if spec is None:
            raise HTTPException(status_code=404, detail=f"no model called {payload.model!r}")
        if model_catalog.model_path(spec, directory).is_file() and not payload.force:
            raise HTTPException(
                status_code=409, detail=f"{spec.id} is already downloaded — nothing to fetch"
            )
        disk = model_catalog.describe_disk(directory)
        if spec.size_mb and 0 <= disk["free_mb"] < spec.size_mb:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"not enough disk: {model_catalog.format_mb(spec.size_mb)} needed, "
                    f"{model_catalog.format_mb(disk['free_mb'])} free"
                ),
            )

        pull.model = spec.id
        pull.status = "running"
        pull.phase = "starting"
        pull.done_bytes = 0
        pull.total_bytes = (spec.size_mb or 0) * 1024 * 1024
        pull.path = ""
        pull.error = ""

        def report(phase: str, done: int, total: int) -> None:
            pull.phase = phase
            pull.done_bytes = done
            if total > 0:
                pull.total_bytes = total

        async def fetch() -> None:
            try:
                path = await asyncio.to_thread(
                    model_catalog.download_model,
                    spec,
                    directory,
                    progress=report,
                    force=payload.force,
                )
            except Exception as exc:  # a failed fetch is reported, not raised at a browser
                pull.status = "error"
                pull.phase = ""
                pull.error = f"{exc.__class__.__name__}: {exc}"
            else:
                pull.status = "done"
                pull.phase = "done"
                pull.path = str(path)
                pull.done_bytes = pull.total_bytes = max(pull.done_bytes, pull.total_bytes)

        pull.task = asyncio.create_task(fetch())
        return JSONResponse(
            {
                "accepted": True,
                "model": spec.id,
                "size_mb": spec.size_mb,
                "url": spec.url,
                "note": "the download continues in the background; nothing else is fetched",
            }
        )

    @app.get("/api/models/pull")
    async def api_model_pull_status(request: Request) -> dict[str, Any]:
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        return pull.to_dict()

    @app.post("/api/verify")
    async def api_verify(payload: VerifyRequest, request: Request) -> JSONResponse:
        """Ask the local model to judge who is who — only when called explicitly."""
        if not _signed_in(request):
            raise HTTPException(status_code=401, detail="sign in to use the dashboard")
        wanted = payload.scans or [meta.scan_id for meta in store.list(limit=payload.limit)]
        reports = [report for scan_id in wanted if (report := store.load(scan_id)) is not None]
        if not reports:
            raise HTTPException(
                status_code=422, detail="there is no scan to review yet — run one first"
            )
        try:
            backend, notes = select_backend(
                prefer=settings.chat_backend,
                model_path=settings.chat_model_path,
                ollama_model=settings.ollama_model,
                ollama_host=settings.ollama_host,
                cortex_model=settings.cortex_model,
                cortex_host=settings.cortex_host,
                allow_cortex_lan=settings.cortex_host != CORTEX_DEFAULT_HOST,
            )
        except (UsageError, D3ta1l3rError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not backend.is_model:
            # A page of "cannot tell" would look like a completed review, so refuse.
            raise HTTPException(
                status_code=400,
                detail=(
                    "identity verification needs a local model and none is available here. "
                    "Install llama-cpp-python and pull a model, or run Ollama on this "
                    "machine — nothing was judged."
                ),
            )
        result = verify_findings(
            reports,
            backend,
            about=payload.facts.strip(),
            include_values=payload.include_values,
            only_uncertain=payload.only_uncertain,
            limit=payload.verify_limit,
            notes=notes,
        )
        body = result.to_dict()
        body["stored_to_disk"] = False
        return JSONResponse(body)

    # -- watchlist (vault) -----------------------------------------------
    @app.get("/api/vault")
    async def api_vault(_: None = Depends(require_vault)) -> dict[str, Any]:
        assert settings.vault is not None
        return _vault_summary() or {}

    @app.post("/api/vault/entries")
    async def api_vault_add(
        payload: VaultEntryRequest, _: None = Depends(require_vault)
    ) -> JSONResponse:
        assert settings.vault is not None
        try:
            entry, created = settings.vault.add(
                payload.kind,
                payload.value,
                label=payload.label,
                notes=payload.notes,
                store_hash=payload.store_hash,
            )
        except (UsageError, D3ta1l3rError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        settings.vault.save()

        result: dict[str, Any] = {
            "created": created,
            "entry": {
                "entry_id": entry.entry_id,
                "kind": entry.kind.value,
                "label": entry.display,
                "masked_value": entry.masked,
                "recheckable": entry.recheckable,
            },
            "check": None,
        }
        if payload.check_now:
            if payload.kind is VaultKind.PASSWORD:
                # The password is right here in memory: check it now, and keep
                # nothing but the count unless the caller asked for a verifier.
                result["check"] = await _check_password_now(payload.value, entry)
            else:
                result["check"] = await _check_entry_now(entry)
        return JSONResponse(result, status_code=201 if created else 200)

    @app.delete("/api/vault/entries/{entry_id}")
    async def api_vault_delete(
        entry_id: str, _: None = Depends(require_vault)
    ) -> dict[str, Any]:
        assert settings.vault is not None
        removed = settings.vault.remove(entry_id)
        if not removed:
            raise HTTPException(status_code=404, detail=f"no such entry: {entry_id}")
        settings.vault.save()
        return {"removed": entry_id, "entries": len(settings.vault)}

    async def _check_password_now(password: str, entry: Any) -> dict[str, Any]:
        """Check a password the moment it is typed, using k-anonymity.

        The plaintext lives only for the duration of this call. What is retained
        is the outcome — and, only when the entry was added with ``store_hash``,
        the verifier on the stored entry itself.
        """
        probe = transient_password_entry(
            password, label=entry.display, entry_id=entry.entry_id
        )
        report = await _single_entry_check(probe)
        if report.checks:
            record_outcomes(settings.vault, report)
        return report.to_dict()

    async def _check_entry_now(entry: Any) -> dict[str, Any]:
        """Immediate feedback after adding an identifier."""
        report = await _single_entry_check(entry)
        if report.checks:
            record_outcomes(settings.vault, report)
        return report.to_dict()

    async def _single_entry_check(entry: Any) -> BreachReport:
        try:
            return await run_breach_check(
                [entry],
                scan_config=settings.base_config(),
                breach_config=settings.breach_config,
            )
        except D3ta1l3rError as exc:  # pragma: no cover - surfaced as a gap
            report = BreachReport(entries=[entry])
            report.finished_at = datetime.now(timezone.utc)
            report.unavailable = [
                {"source_id": "internal", "source_name": "breach check", "reason": str(exc)}
            ]
            return report

    # -- breach watch ----------------------------------------------------
    @app.get("/api/breach")
    async def api_breach(_: None = Depends(require_vault)) -> dict[str, Any]:
        return breach.to_dict()

    @app.post("/api/breach/check")
    async def api_breach_check(_: None = Depends(require_vault)) -> dict[str, Any]:
        started = _start_breach_run("manual")
        return JSONResponse(
            {"started": started, "status": breach.status}, status_code=202 if started else 200
        )

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
        respect_robots=(
            base.respect_robots if payload.respect_robots is None
            else bool(payload.respect_robots)
        ),
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


def _breach_sources_for_display(config: BreachConfig) -> list[Any]:
    from ..breach import build_breach_sources

    return build_breach_sources(config)


def _safe_next(value: str | None) -> str:
    """Only ever redirect to a path on this host (no open redirects)."""
    if not value or not value.startswith(_SAFE_NEXT_PREFIX) or value.startswith("//"):
        return "/"
    return value


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


# Re-exported for tests and for `d3ta1l3r web` wiring.
__all__ = [
    "AppSettings",
    "BreachState",
    "RunState",
    "ScanRequest",
    "Vault",
    "VaultEntryRequest",
    "VaultError",
    "create_app",
]
