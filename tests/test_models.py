"""Model layer: validation, serialisation round-trips, storage layout."""

from __future__ import annotations

import json

import pytest

from d3ta1l3r.config import RateLimitConfig, ScanConfig
from d3ta1l3r.core.storage import ScanStore
from d3ta1l3r.errors import ConfigError, UsageError
from d3ta1l3r.models import (
    Confidence,
    Finding,
    ScanReport,
    ScanStatus,
    ScanTarget,
    SourceKind,
    SourceOutcome,
)


class TestScanTarget:
    def test_requires_at_least_one_identifier(self) -> None:
        with pytest.raises(UsageError):
            ScanTarget.create()

    def test_identifiers_only_include_supplied_values(self) -> None:
        target = ScanTarget.create(username="alice", name="Alice Doe")
        assert target.identifiers == {"username": "alice", "name": "Alice Doe"}
        assert "domain" not in target.identifiers

    def test_display_masks_the_email_but_keeps_context(self) -> None:
        target = ScanTarget.create(username="alice", email="alice@example.com", name="Alice Doe")
        shown = target.display()
        assert "alice@example.com" not in shown
        assert "al***@example.com" in shown
        assert "@alice" in shown

    def test_fingerprint_is_stable_and_non_reversible(self) -> None:
        first = ScanTarget.create(username="alice", email="alice@example.com").fingerprint()
        second = ScanTarget.create(username="alice", email="alice@example.com").fingerprint()
        assert first == second
        assert "alice" not in first
        assert len(first) == 12

    def test_round_trip(self) -> None:
        target = ScanTarget.create(username="alice", domain="example.com", location="Delhi, IN")
        restored = ScanTarget.from_dict(target.to_dict())
        assert restored.to_dict() == target.to_dict()


class TestConfidence:
    def test_ranking_orders_evidence_strength(self) -> None:
        assert Confidence.LOW.rank < Confidence.MEDIUM.rank < Confidence.HIGH.rank
        assert Confidence.HIGH.rank < Confidence.CONFIRMED.rank


class TestFinding:
    def test_non_string_api_values_are_coerced(self) -> None:
        finding = Finding(
            source_id="s", source_name="S", kind=SourceKind.USERNAME,
            url="https://x", identifier="alice",
            account_created_at=1600000000,  # epoch int from a real API
            bio={"nested": "dict"},
        )
        assert finding.account_created_at == "1600000000"
        assert finding.bio == "{'nested': 'dict'}"

    def test_none_stays_none(self) -> None:
        finding = Finding(
            source_id="s", source_name="S", kind=SourceKind.USERNAME,
            url="https://x", identifier="alice", title=None, bio=None,
        )
        assert finding.title is None and finding.bio is None

    def test_dedupe_key_includes_the_source(self) -> None:
        common = {"kind": SourceKind.USERNAME, "url": "https://x/alice", "identifier": "alice"}
        a = Finding(source_id="api_a", source_name="A", **common)
        b = Finding(source_id="api_b", source_name="B", **common)
        assert a.dedupe_key() != b.dedupe_key()


class TestOutcomeAndReport:
    def test_outcome_statuses_classify_correctly(self) -> None:
        def make(status: ScanStatus) -> SourceOutcome:
            return SourceOutcome("s", "S", SourceKind.USERNAME, status)

        assert make(ScanStatus.FOUND).ok
        assert make(ScanStatus.NOT_FOUND).ok
        assert not make(ScanStatus.ERROR).ok
        assert not make(ScanStatus.TIMEOUT).ok
        assert not make(ScanStatus.BLOCKED).ok
        assert ScanStatus.SKIPPED_ROBOTS.is_skip
        assert ScanStatus.SKIPPED_NO_INPUT.is_skip
        assert not ScanStatus.NOT_FOUND.is_skip
        assert ScanStatus.FOUND.is_terminal_hit

    def test_report_round_trips_through_json(self) -> None:
        report = _report()
        restored = ScanReport.from_json(report.to_json())
        assert restored.scan_id == report.scan_id
        assert restored.target.display() == report.target.display()
        assert restored.stats.to_dict() == report.stats.to_dict()
        assert [o.status for o in restored.outcomes] == [o.status for o in report.outcomes]

    def test_stats_are_derived_from_outcomes(self) -> None:
        report = _report()
        stats = report.refresh_stats()
        assert stats.sources_total == 3
        assert stats.sources_hit == 1
        assert stats.sources_skipped == 1
        assert stats.findings_total == 1

    def test_refresh_stats_keeps_transport_counters(self) -> None:
        report = _report()
        stats = report.refresh_stats(hosts_contacted=4, http_requests=9)
        assert (stats.hosts_contacted, stats.http_requests) == (4, 9)

    def test_unknown_status_in_a_stored_report_is_rejected(self) -> None:
        payload = json.loads(_report().to_json())
        payload["outcomes"][0]["status"] = "definitely_not_a_status"
        with pytest.raises(ValueError, match="definitely_not_a_status"):
            ScanReport.from_dict(payload)


class TestStorage:
    def test_save_and_reload(self, tmp_path) -> None:
        store = ScanStore(tmp_path)
        report = _report()
        written = store.save(report)
        assert {p.suffix for p in written} == {".json", ".md", ".html"}
        loaded = store.load(report.scan_id)
        assert loaded is not None and loaded.scan_id == report.scan_id

    def test_listing_is_newest_first_and_has_counts(self, tmp_path) -> None:
        store = ScanStore(tmp_path)
        older, newer = _report(), _report()
        newer.started_at = older.started_at.replace(year=older.started_at.year + 1)
        store.save(older, formats=("json",))
        store.save(newer, formats=("json",))
        metas = store.list()
        assert [meta.scan_id for meta in metas] == [newer.scan_id, older.scan_id]
        assert metas[0].findings == 1
        assert metas[0].sources_total == 3

    def test_delete_removes_every_artefact_of_one_scan_only(self, tmp_path) -> None:
        store = ScanStore(tmp_path)
        keep, drop = _report(), _report()
        store.save(keep)
        store.save(drop)
        removed = store.delete(drop.scan_id)
        assert removed == 3
        assert store.load(drop.scan_id) is None
        assert store.load(keep.scan_id) is not None

    def test_purge_clears_the_directory(self, tmp_path) -> None:
        store = ScanStore(tmp_path)
        store.save(_report())
        assert store.purge() == 3
        assert store.list() == []

    def test_corrupt_files_are_skipped_when_listing(self, tmp_path) -> None:
        store = ScanStore(tmp_path)
        (tmp_path / "20260101T000000Z-broken-abcdef.json").write_text("{not json")
        assert store.list() == []


class TestConfig:
    def test_defaults_are_polite(self) -> None:
        config = ScanConfig()
        assert config.respect_robots is True
        assert config.rate.per_host_rps <= 5
        assert config.rate.global_concurrency <= 32
        assert config.rate.max_retries >= 1
        assert config.strict_ssrf is True
        assert config.max_redirects <= 5
        assert "D3TA1L3R/" in config.user_agent

    def test_invalid_values_are_rejected(self) -> None:
        with pytest.raises(ConfigError):
            ScanConfig(timeout=0)
        with pytest.raises(ConfigError):
            ScanConfig(rate=RateLimitConfig(per_host_rps=0))
        with pytest.raises(ConfigError):
            ScanConfig(kinds=frozenset({"telepathy"}))
        with pytest.raises(ConfigError):
            ScanConfig(enabled_sources=frozenset({"a"}), disabled_sources=frozenset({"a"}))

    def test_source_enabled_logic(self) -> None:
        config = ScanConfig()
        assert config.source_enabled("anything", "username") is True
        allow = ScanConfig(enabled_sources=frozenset({"only_me"}))
        assert allow.source_enabled("only_me", "username") is True
        assert allow.source_enabled("other", "username") is False
        deny = ScanConfig(disabled_sources=frozenset({"nope"}))
        assert deny.source_enabled("nope", "username") is False
        assert deny.source_enabled("fine", "username") is True
        social = ScanConfig(categories=frozenset({"social"}))
        assert social.source_enabled("x", "username", "social") is True
        assert social.source_enabled("y", "username", "developer") is False

    def test_replaced_revalidates(self) -> None:
        config = ScanConfig()
        with pytest.raises(ConfigError):
            config.replaced(timeout=-1)

    def test_env_overrides(self, monkeypatch) -> None:
        monkeypatch.setenv("D3TA1L3R_TIMEOUT", "3.5")
        monkeypatch.setenv("D3TA1L3R_CONCURRENCY", "4")
        monkeypatch.setenv("D3TA1L3R_RPS", "1")
        monkeypatch.setenv("D3TA1L3R_ROBOTS", "0")
        config = ScanConfig.from_env()
        assert config.timeout == 3.5
        assert config.rate.global_concurrency == 4
        assert config.rate.per_host_rps == 1
        assert config.respect_robots is False

    def test_explicit_overrides_beat_env(self, monkeypatch) -> None:
        monkeypatch.setenv("D3TA1L3R_TIMEOUT", "3.5")
        assert ScanConfig.from_env(timeout=9.0).timeout == 9.0


def _report() -> ScanReport:
    target = ScanTarget.create(username="alice")
    report = ScanReport.new(target, "0.1.0")
    report.outcomes = [
        SourceOutcome(
            source_id="api_a", source_name="API A", kind=SourceKind.USERNAME,
            status=ScanStatus.FOUND, category="developer",
            findings=[
                Finding(
                    source_id="api_a", source_name="API A", kind=SourceKind.USERNAME,
                    url="https://a.example/alice", identifier="alice",
                    confidence=Confidence.CONFIRMED, evidence="record returned",
                )
            ],
            http_status=200, duration_ms=42,
        ),
        SourceOutcome(
            source_id="probe_b", source_name="Probe B", kind=SourceKind.USERNAME,
            status=ScanStatus.NOT_FOUND, category="social", http_status=404,
        ),
        SourceOutcome(
            source_id="probe_c", source_name="Probe C", kind=SourceKind.USERNAME,
            status=ScanStatus.SKIPPED_ROBOTS, category="social",
            skipped_reason="robots.txt disallows",
        ),
    ]
    report.finished_at = report.started_at
    report.refresh_stats()
    return report
