"""The scan engine: select sources, run them concurrently, contain failures.

Properties this module guarantees:

* **Bounded.** A global semaphore plus per-host token buckets cap load; nothing
  runs unbounded even with 70 sources and a long handle list.
* **Failure-contained.** A source that explodes becomes a ``SourceOutcome`` with
  ``status=error`` and a message — the scan always finishes.
* **Deterministic.** Outcomes are ordered by source weight, so two runs of the
  same scan produce diffable reports.
* **Reproducible.** The report records the tool version, transport settings and
  a hash of the signature database, so a finding can be traced back to the exact
  configuration and spec set that produced it.
* **Observable.** Progress events stream to callbacks (CLI progress bar, SSE in
  the dashboard) without the engine knowing what consumes them.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import platform
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import ScanConfig
from ..errors import UsageError
from ..models import (
    EVENT_SCAN_FINISHED,
    EVENT_SCAN_STARTED,
    EVENT_SOURCE_FINISHED,
    EVENT_SOURCE_STARTED,
    ScanEvent,
    ScanReport,
    ScanStatus,
    ScanTarget,
    SourceOutcome,
    utcnow,
)
from .cache import ResponseCache
from .http import Fetcher
from .ratelimit import HostRateLimiter
from .robots import RobotsPolicy

__all__ = ["ScanEngine", "run_scan"]

ProgressCallback = Callable[[ScanEvent], Any]  # sync or async callable

_SITES_FILE = Path(__file__).resolve().parent.parent / "data" / "sites.json"


class ScanEngine:
    """Runs one scan at a time; create a new engine for a new configuration."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        *,
        sources: Sequence[Any] | None = None,
        transport: Any | None = None,
        cache: ResponseCache | None = None,
        on_event: ProgressCallback | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.on_event = on_event
        self._prototypes = list(sources) if sources is not None else None
        self._transport = transport
        self._cache = cache
        self.last_report: ScanReport | None = None

    # -- source selection -------------------------------------------------
    def available_sources(self) -> list[Any]:
        if self._prototypes is None:
            from ..sources import all_sources

            self._prototypes = all_sources(include_disabled=True)
        return list(self._prototypes)

    def selected_sources(self) -> list[Any]:
        """Apply the config filters, then order by weight (cheap/high-signal first)."""
        selected = [
            source
            for source in self.available_sources()
            if self.config.source_enabled(source.id, source.kind.value, source.category)
            and (source.enabled_by_default or self.config.enabled_sources)
        ]
        selected.sort(key=lambda s: (s.meta.weight, s.id))
        if self.config.max_sites is not None:
            selected = selected[: self.config.max_sites]
        return selected

    def describe_sources(self) -> list[dict[str, Any]]:
        """Inventory for ``d3ta1l3r sources`` and the dashboard's coverage page."""
        return [
            {
                "id": source.id,
                "name": source.name,
                "kind": source.kind.value,
                "category": source.category,
                "description": source.meta.description,
                "docs_url": source.meta.docs_url,
                "enabled_by_default": source.enabled_by_default,
                "weight": source.meta.weight,
                "notes": source.meta.notes,
            }
            for source in sorted(self.available_sources(), key=lambda s: (s.meta.weight, s.id))
        ]

    # -- scan -------------------------------------------------------------
    async def scan(
        self, target: ScanTarget, *, on_event: ProgressCallback | None = None
    ) -> ScanReport:
        target.require_identifier()
        selected = self.selected_sources()
        # A source whose identifier kind was not supplied has nothing to ask about;
        # running it would only add "skipped" noise and inflate the source count.
        available_kinds = set(target.identifiers)
        sources = [source for source in selected if source.kind.value in available_kinds]
        if not sources:
            raise UsageError(
                "no sources matched the supplied identifier kind(s) — check the "
                "--sources/--categories/--kind filters (see `d3ta1l3r sources`)"
            )

        sink = on_event or self.on_event
        report = self._new_report(target, sources, available_kinds)
        fetcher, cache = await self._open_fetcher(target)
        try:
            await self._emit(sink, self._event(report, EVENT_SCAN_STARTED,
                                              f"scanning {len(sources)} sources"))
            outcomes = await self._run_sources(sources, target, report, fetcher, sink)
            report.outcomes = outcomes
        finally:
            await fetcher.close()

        report.finished_at = utcnow()
        report.warnings.extend(self._warnings(report))
        report.refresh_stats(
            hosts_contacted=len(fetcher.hosts_contacted),
            http_requests=fetcher.request_count,
        )
        if cache is not None:
            report.options["cache_hits"] = cache.hits
        await self._emit(
            sink,
            self._event(
                report,
                EVENT_SCAN_FINISHED,
                f"done: {report.stats.sources_hit} source(s) with results, "
                f"{report.stats.sources_failed} error(s), {report.stats.sources_skipped} skipped",
                completed=len(outcomes),
            ),
        )
        self.last_report = report
        return report

    # -- internals --------------------------------------------------------
    def _new_report(
        self, target: ScanTarget, sources: Sequence[Any], available_kinds: set[str] | None = None
    ) -> ScanReport:
        report = ScanReport.new(
            target,
            __version__,
            user_agent=self.config.user_agent,
            timeout_seconds=self.config.timeout,
            concurrency=self.config.rate.global_concurrency,
            per_host_rps=self.config.rate.per_host_rps,
            respect_robots=self.config.respect_robots,
            follow_redirects=self.config.follow_redirects,
            max_body_bytes=self.config.max_body_bytes,
            strict_ssrf=self.config.strict_ssrf,
            use_cache=self.config.use_cache,
            sources=[source.id for source in sources],
            identifier_kinds=sorted(available_kinds or ()),
            categories=sorted(self.config.categories),
            kinds=sorted(self.config.kinds),
            sources_available=len(sources),
            signature_db_sha256=_file_digest(_SITES_FILE),
            python=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            platform=platform.platform(),
        )
        report.demo = self.config.demo
        return report

    async def _open_fetcher(self, target: ScanTarget) -> tuple[Fetcher, ResponseCache | None]:
        transport = self._transport
        if self.config.demo and transport is None:
            from .demo import DemoTransport

            transport = DemoTransport(
                username=target.username or "demo_user",
                email=target.email or "demo.user@example.com",
                name=target.name or "Demo User",
                domain=(target.email or "example.com").partition("@")[2] or "example.com",
            )

        cache: ResponseCache | None = self._cache
        if cache is None and self.config.use_cache and self.config.cache_dir:
            cache = ResponseCache(self.config.cache_dir, self.config.cache_ttl)

        limiter = HostRateLimiter(
            rps=self.config.rate.per_host_rps, burst=self.config.rate.per_host_burst
        )
        fetcher = Fetcher(
            self.config, cache=cache, transport=transport, limiter=limiter
        )
        await fetcher.start()
        if self.config.respect_robots:
            fetcher.robots = RobotsPolicy(fetcher)
        return fetcher, cache

    async def _run_sources(
        self,
        sources: Sequence[Any],
        target: ScanTarget,
        report: ScanReport,
        fetcher: Fetcher,
        sink: ProgressCallback | None,
    ) -> list[SourceOutcome]:
        semaphore = asyncio.Semaphore(self.config.rate.global_concurrency)
        total = len(sources)
        results: dict[str, SourceOutcome] = {}
        completed = 0

        async def worker(source: Any) -> SourceOutcome:
            async with semaphore:
                await self._emit(
                    sink,
                    self._event(
                        report, EVENT_SOURCE_STARTED, f"checking {source.name}",
                        source=source, completed=completed, total=total,
                    ),
                )
                source.bind(fetcher)
                return await source.execute(target)

        tasks = [asyncio.ensure_future(worker(source)) for source in sources]
        try:
            for future in asyncio.as_completed(tasks):
                outcome = await future
                results[outcome.source_id] = outcome
                completed += 1
                await self._emit(
                    sink,
                    self._event(
                        report,
                        EVENT_SOURCE_FINISHED,
                        f"{outcome.source_name}: {outcome.status.value}",
                        source=outcome,
                        completed=completed,
                        total=total,
                    ),
                )
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

        # Deterministic ordering: the order the sources were selected in.
        ordered = [results[source.id] for source in sources if source.id in results]
        missing = [s for s in sources if s.id not in results]
        for source in missing:  # pragma: no cover - defensive
            ordered.append(
                SourceOutcome(
                    source_id=source.id,
                    source_name=source.name,
                    kind=source.kind,
                    status=ScanStatus.ERROR,
                    error="source produced no outcome (cancelled)",
                )
            )
        return ordered

    def _warnings(self, report: ScanReport) -> list[str]:
        warnings: list[str] = []
        if report.demo:
            from .demo import DEMO_WARNING

            warnings.append(DEMO_WARNING)
        if not self.config.respect_robots:
            warnings.append(
                "robots.txt enforcement was disabled (--ignore-robots): some sources may have "
                "been skipped by the sites themselves."
            )
        if not self.config.strict_ssrf:
            warnings.append(
                "DNS-level SSRF checks were disabled: hosts were validated syntactically only."
            )
        blocked = [o for o in report.outcomes if o.status is ScanStatus.BLOCKED]
        robots = [o for o in report.outcomes if o.status is ScanStatus.SKIPPED_ROBOTS]
        errors = [o for o in report.outcomes if not o.ok and o.status is not ScanStatus.BLOCKED]
        if blocked:
            warnings.append(
                f"{len(blocked)} source(s) could not be checked anonymously (sign-in walls or "
                "refused access): " + ", ".join(o.source_name for o in blocked[:8])
                + (" …" if len(blocked) > 8 else "")
            )
        if robots:
            warnings.append(
                f"{len(robots)} source(s) were skipped because robots.txt disallows them: "
                + ", ".join(o.source_name for o in robots[:8])
                + (" …" if len(robots) > 8 else "")
            )
        if errors:
            warnings.append(
                f"{len(errors)} source(s) failed (timeouts, layout changes or API errors) — "
                "these are coverage gaps, not 'no account' answers: "
                + ", ".join(o.source_name for o in errors[:8])
                + (" …" if len(errors) > 8 else "")
            )
        return warnings

    def _event(
        self,
        report: ScanReport,
        event_type: str,
        message: str,
        *,
        source: Any | None = None,
        completed: int = 0,
        total: int = 0,
    ) -> ScanEvent:
        event = ScanEvent(
            type=event_type,
            scan_id=report.scan_id,
            message=message,
            completed=completed,
            total=total,
        )
        if source is not None:
            if isinstance(source, SourceOutcome):
                event.source_id = source.source_id
                event.source_name = source.source_name
                event.status = source.status
                event.findings_count = len(source.findings)
            else:
                event.source_id = source.id
                event.source_name = source.name
        return event

    @staticmethod
    async def _emit(sink: ProgressCallback | None, event: ScanEvent) -> None:
        """Deliver a progress event; a broken consumer must not break a scan."""
        if sink is None:
            return
        try:
            result = sink(event)
            if inspect.isawaitable(result):
                await result
        except Exception:
            return


async def run_scan(
    target: ScanTarget,
    config: ScanConfig | None = None,
    *,
    on_event: ProgressCallback | None = None,
    **engine_kwargs: Any,
) -> ScanReport:
    """Convenience one-shot helper: ``await run_scan(ScanTarget.create(username="me"))``."""
    engine = ScanEngine(config, on_event=on_event, **engine_kwargs)
    return await engine.scan(target)


def _file_digest(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()[:16]
