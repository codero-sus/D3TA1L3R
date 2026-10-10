"""Engine behaviour: selection, concurrency, containment, determinism, reporting."""

from __future__ import annotations

import asyncio

import pytest

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.engine import ScanEngine, run_scan
from d3ta1l3r.errors import UsageError
from d3ta1l3r.models import (
    EVENT_SCAN_FINISHED,
    EVENT_SCAN_STARTED,
    EVENT_SOURCE_FINISHED,
    Confidence,
    ScanStatus,
    ScanTarget,
    SourceKind,
)
from d3ta1l3r.sources.base import BaseSource, SourceMeta
from tests.conftest import html, json_response, make_config


class StubSource(BaseSource):
    """A source whose behaviour is scripted — no HTTP at all."""

    def __init__(self, source_id: str, status: ScanStatus = ScanStatus.FOUND, **meta) -> None:
        super().__init__(None)
        self.meta = SourceMeta(
            id=source_id,
            name=meta.pop("name", source_id.title()),
            kind=meta.pop("kind", SourceKind.USERNAME),
            category=meta.pop("category", "stub"),
            description="stub source for tests",
            enabled_by_default=meta.pop("enabled_by_default", True),
            weight=meta.pop("weight", 100),
            **meta,
        )
        self.status = status
        self.calls = 0
        self.delay = 0.0
        self.raises: Exception | None = None

    async def run(self, identifier: str, target: ScanTarget):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raises is not None:
            raise self.raises
        started = self.now()
        if self.status is ScanStatus.FOUND:
            return self._outcome(
                ScanStatus.FOUND,
                started,
                findings=[
                    self.finding(
                        identifier=identifier,
                        url=f"https://example.com/{identifier}",
                        confidence=Confidence.HIGH,
                        evidence="scripted hit",
                    )
                ],
            )
        return self._outcome(self.status, started)


async def run_engine(sources, config: ScanConfig | None = None, **kwargs):
    engine = ScanEngine(config or make_config(), sources=sources, **kwargs)
    return await engine.scan(ScanTarget.create(username="alice"))


class TestSelection:
    def test_disabled_by_default_sources_are_skipped_unless_requested(self) -> None:
        on, off = StubSource("on"), StubSource("off", enabled_by_default=False)
        engine = ScanEngine(make_config(), sources=[on, off])
        assert [s.id for s in engine.selected_sources()] == ["on"]
        engine = ScanEngine(make_config(enabled_sources=frozenset({"off"})), sources=[on, off])
        assert [s.id for s in engine.selected_sources()] == ["off"]

    def test_category_kind_and_exclusion_filters(self) -> None:
        a = StubSource("a", category="developer")
        b = StubSource("b", category="social")
        c = StubSource("c", category="developer", kind=SourceKind.EMAIL)
        assert [s.id for s in ScanEngine(
            make_config(categories=frozenset({"social"})), sources=[a, b]).selected_sources()] == ["b"]
        assert [s.id for s in ScanEngine(
            make_config(disabled_sources=frozenset({"a"})), sources=[a, b]).selected_sources()] == ["b"]
        assert [s.id for s in ScanEngine(
            make_config(kinds=frozenset({"email"})), sources=[a, b, c]).selected_sources()] == ["c"]

    def test_sources_run_in_weight_order(self) -> None:
        heavy = StubSource("heavy", weight=900)
        light = StubSource("light", weight=1)
        assert [s.id for s in ScanEngine(
            make_config(), sources=[heavy, light]).selected_sources()] == ["light", "heavy"]

    def test_max_sites_caps_the_run(self) -> None:
        sources = [StubSource(f"s{i}", weight=i) for i in range(5)]
        engine = ScanEngine(make_config(max_sites=2), sources=sources)
        assert [s.id for s in engine.selected_sources()] == ["s0", "s1"]

    async def test_sources_without_the_supplied_identifier_kind_are_not_run(self) -> None:
        username = StubSource("u")
        email = StubSource("e", kind=SourceKind.EMAIL)
        report = await run_engine([username, email])
        assert [o.source_id for o in report.outcomes] == ["u"]
        assert email.calls == 0
        assert report.options["identifier_kinds"] == ["username"]

    async def test_no_source_matching_the_identifier_is_a_usage_error(self) -> None:
        engine = ScanEngine(make_config(), sources=[StubSource("e", kind=SourceKind.EMAIL)])
        with pytest.raises(UsageError):
            await engine.scan(ScanTarget.create(username="alice"))

    def test_describe_sources_powers_the_coverage_page(self) -> None:
        rows = ScanEngine(make_config(), sources=[StubSource("x")]).describe_sources()
        assert rows[0]["id"] == "x"
        assert rows[0]["enabled_by_default"] is True


class TestExecution:
    async def test_all_sources_run_and_hits_are_recorded(self) -> None:
        sources = [StubSource(f"s{i}") for i in range(4)]
        report = await run_engine(sources)
        assert all(source.calls == 1 for source in sources)
        assert report.stats.sources_total == 4
        assert report.stats.findings_total == 4
        assert all(o.status is ScanStatus.FOUND for o in report.outcomes)

    async def test_outcome_order_is_deterministic_regardless_of_completion_order(self) -> None:
        slow = StubSource("aaa_slow", weight=1)
        slow.delay = 0.05
        quick = StubSource("bbb_quick", weight=2)
        report = await run_engine([slow, quick])
        assert [o.source_id for o in report.outcomes] == ["aaa_slow", "bbb_quick"]

    async def test_one_broken_source_does_not_stop_the_scan(self) -> None:
        broken = StubSource("broken")
        broken.raises = RuntimeError("boom")
        healthy = StubSource("healthy")
        report = await run_engine([broken, healthy])
        assert report.outcome("broken").status is ScanStatus.ERROR
        assert "RuntimeError" in (report.outcome("broken").error or "")
        assert report.outcome("healthy").status is ScanStatus.FOUND

    async def test_concurrency_limit_is_respected(self) -> None:
        active = {"now": 0, "peak": 0}

        class Counting(StubSource):
            async def run(self, identifier, target):
                active["now"] += 1
                active["peak"] = max(active["peak"], active["now"])
                await asyncio.sleep(0.02)
                active["now"] -= 1
                return await super().run(identifier, target)

        sources = [Counting(f"s{i}") for i in range(6)]
        config = make_config(rate={"global_concurrency": 2})
        await run_engine(sources, config)
        assert active["peak"] <= 2

    async def test_polite_defaults_are_reflected_in_the_report(self) -> None:
        report = await run_engine([StubSource("x")])
        assert report.options["respect_robots"] is True
        assert report.options["concurrency"] == 8
        assert report.options["signature_db_sha256"]

    async def test_demo_mode_uses_fixtures_and_flags_the_report(self) -> None:
        engine = ScanEngine(make_config(demo=True))
        report = await engine.scan(ScanTarget.create(username="alice"))
        assert report.demo is True
        assert any("DEMO MODE" in warning for warning in report.warnings)
        assert report.findings, "demo fixtures should produce findings"

    async def test_run_scan_helper(self) -> None:
        report = await run_scan(
            ScanTarget.create(username="alice"), make_config(), sources=[StubSource("x")]
        )
        assert report.stats.sources_total == 1


class TestEvents:
    async def test_progress_events_are_emitted_in_order(self) -> None:
        seen: list[str] = []
        report = await run_engine(
            [StubSource("a"), StubSource("b", status=ScanStatus.NOT_FOUND)],
            on_event=lambda event: seen.append(event.type),
        )
        assert seen[0] == EVENT_SCAN_STARTED
        assert seen[-1] == EVENT_SCAN_FINISHED
        assert seen.count(EVENT_SOURCE_FINISHED) == 2
        assert report.stats.sources_hit == 1

    async def test_async_callbacks_are_awaited(self) -> None:
        seen: list[str] = []

        async def sink(event):
            await asyncio.sleep(0)
            seen.append(event.type)

        await run_engine([StubSource("a")], on_event=sink)
        assert EVENT_SCAN_FINISHED in seen

    async def test_a_broken_callback_cannot_break_a_scan(self) -> None:
        def explode(event):
            raise RuntimeError("observer is broken")

        report = await run_engine([StubSource("a")], on_event=explode)
        assert report.stats.findings_total == 1

    async def test_event_percentages_are_bounded(self) -> None:
        events: list = []
        await run_engine([StubSource(f"s{i}") for i in range(3)], on_event=events.append)
        assert all(0 <= event.percent <= 100 for event in events)


class TestRealSourcesThroughTheEngine:
    """The engine driving the actual source implementations, offline."""

    async def test_full_pipeline_against_a_fake_internet(self) -> None:
        routes = {
            "api.github.com": json_response({
                "login": "alice", "name": "Alice", "location": "Delhi",
                "public_repos": 5, "html_url": "https://github.com/alice",
                "created_at": "2015-01-01T00:00:00Z",
            }),
            "gravatar.com": json_response({"entry": [{"displayName": "Alice Doe"}]}),
            "news.ycombinator.com": html("<html>No such user.</html>"),
            "codepen.io": html("<html>Alice profile</html>"),
        }
        from tests.conftest import mock_transport

        transport, _table = mock_transport(routes)
        engine = ScanEngine(make_config(), transport=transport)
        # Only the sources we scripted a route for, to keep the test hermetic.
        engine._prototypes = [
            source for source in engine.available_sources()
            if source.id in {"github_api_user", "gravatar_api_email", "hackernews_user", "codepen_user"}
        ]
        report = await engine.scan(
            ScanTarget.create(username="alice", email="alice@example.com")
        )
        statuses = {o.source_id: o.status for o in report.outcomes}
        assert statuses["github_api_user"] is ScanStatus.FOUND
        assert statuses["gravatar_api_email"] is ScanStatus.FOUND
        assert statuses["hackernews_user"] is ScanStatus.NOT_FOUND
        assert statuses["codepen_user"] is ScanStatus.FOUND
        assert report.stats.hosts_contacted >= 3
        assert report.stats.findings_total == 3


class TestWarnings:
    async def test_gaps_are_summarised_in_warnings(self) -> None:
        sources = [
            StubSource("ok"),
            StubSource("blocked", status=ScanStatus.BLOCKED),
            StubSource("robots", status=ScanStatus.SKIPPED_ROBOTS),
            StubSource("failed", status=ScanStatus.ERROR),
        ]
        report = await run_engine(sources)
        joined = " ".join(report.warnings)
        assert "sign-in walls" in joined
        assert "robots.txt disallows" in joined
        assert "coverage gaps" in joined

    async def test_disabling_robots_is_flagged(self) -> None:
        report = await run_engine([StubSource("a")], make_config(respect_robots=False))
        assert any("robots.txt enforcement was disabled" in w for w in report.warnings)

    async def test_stats_are_internally_consistent(self) -> None:
        sources = [
            StubSource("found"),
            StubSource("absent", status=ScanStatus.NOT_FOUND),
            StubSource("skip", status=ScanStatus.SKIPPED_ROBOTS),
            StubSource("err", status=ScanStatus.ERROR),
        ]
        report = await run_engine(sources)
        stats = report.stats
        assert stats.sources_total == 4
        assert stats.sources_hit == 1
        assert stats.sources_skipped == 1
        assert stats.sources_failed == 1
        assert stats.findings_total == 1
        assert stats.sources_ok + stats.sources_failed == 4
