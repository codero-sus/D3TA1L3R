"""Report rendering and diffs — including the escaping that keeps them safe to open."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from d3ta1l3r.core.report import diff_reports, render_html, render_json, render_markdown
from d3ta1l3r.models import (
    Confidence,
    Finding,
    ScanReport,
    ScanStatus,
    ScanTarget,
    SourceKind,
    SourceOutcome,
    utcnow,
)


def finding(**overrides) -> Finding:
    base = {
        "source_id": "github_api_user",
        "source_name": "GitHub (REST API)",
        "kind": SourceKind.USERNAME,
        "url": "https://github.com/alice",
        "identifier": "alice",
        "confidence": Confidence.CONFIRMED,
        "category": "developer",
        "evidence": "GitHub REST API returned the account record",
        "title": "GitHub @alice",
        "display_name": "Alice Doe",
        "bio": "engineer",
        "location": "Delhi",
        "account_created_at": "2014-05-05T00:00:00Z",
        "extra": {"exposure": ["public location: Delhi", "42 public repositories"]},
    }
    base.update(overrides)
    return Finding(**base)


def outcome(source_id: str = "github_api_user", **overrides) -> SourceOutcome:
    base = {
        "source_id": source_id,
        "source_name": source_id,
        "kind": SourceKind.USERNAME,
        "status": ScanStatus.FOUND,
        "category": "developer",
        "findings": [finding()],
        "http_status": 200,
        "duration_ms": 120,
    }
    base.update(overrides)
    return SourceOutcome(**base)


def report(**overrides) -> ScanReport:
    target = ScanTarget.create(username="alice")
    base = ScanReport.new(target, "0.1.0", signature_db_sha256="deadbeef")
    base.outcomes = [
        outcome(),
        outcome("svc_a", status=ScanStatus.NOT_FOUND, findings=[], error="HTTP 404"),
        outcome("svc_b", status=ScanStatus.BLOCKED, findings=[], error="sign-in wall"),
        outcome("svc_c", status=ScanStatus.ERROR, findings=[], error="ambiguous response"),
        outcome(
            "gravatar_api_email",
            kind=SourceKind.EMAIL,
            findings=[finding(source_id="gravatar_api_email", confidence=Confidence.HIGH)],
        ),
    ]
    base.finished_at = base.started_at + timedelta(seconds=3)
    for key, value in overrides.items():
        setattr(base, key, value)
    base.refresh_stats(hosts_contacted=12, http_requests=20)
    return base


class TestMarkdown:
    def test_contains_every_essential_section(self) -> None:
        rendered = render_markdown(report())
        for expected in [
            "# D3TA1L3R self-audit",
            "## Findings",
            "## Coverage",
            "## Remaining gaps (verify by hand)",
            "## How to read confidence",
            "signature database",
        ]:
            assert expected in rendered

    def test_lists_sources_that_could_not_be_checked(self) -> None:
        rendered = render_markdown(report())
        assert "svc_b" in rendered
        assert "blocked / sign-in wall" in rendered
        assert "svc_c" in rendered

    def test_findings_carry_confidence_and_evidence(self) -> None:
        rendered = render_markdown(report())
        assert "CONFIRMED" in rendered
        assert "GitHub REST API returned the account record" in rendered
        assert "https://github.com/alice" in rendered

    def test_demo_banner_appears(self) -> None:
        assert "DEMO MODE" in render_markdown(report(demo=True))

    def test_empty_report_says_so_without_overclaiming(self) -> None:
        empty = report()
        empty.outcomes = [outcome("svc", status=ScanStatus.NOT_FOUND, findings=[])]
        empty.refresh_stats()
        rendered = render_markdown(empty)
        assert "No accounts were located" in rendered
        assert "unknown" in rendered.lower()


class TestHtml:
    def test_renders_a_complete_document(self) -> None:
        rendered = render_html(report())
        assert rendered.startswith("<!doctype html>")
        assert rendered.rstrip().endswith("</html>")
        assert "noindex" in rendered  # keep reports out of search engines

    def test_escapes_hostile_content(self) -> None:
        evil = report()
        evil.outcomes = [
            outcome(
                findings=[
                    finding(
                        title="<script>alert('xss')</script>",
                        bio="<img src=x onerror=alert(1)>",
                        url="https://evil.example/<script>",
                    )
                ]
            )
        ]
        evil.refresh_stats()
        rendered = render_html(evil)
        assert "<script>alert" not in rendered
        assert "&lt;script&gt;alert" in rendered
        assert "onerror" not in rendered or "&lt;" in rendered

    def test_includes_coverage_and_confidence_legend(self) -> None:
        rendered = render_html(report())
        assert "Coverage" in rendered
        assert "CONFIRMED" in rendered
        assert "verify by hand" in rendered.lower() or "skip" in rendered.lower()


class TestJson:
    def test_round_trips_losslessly(self) -> None:
        original = report()
        raw = render_json(original)
        restored = ScanReport.from_json(raw)
        assert restored.scan_id == original.scan_id
        assert restored.target.username == "alice"
        assert restored.stats.to_dict() == original.stats.to_dict()
        assert restored.findings[0].evidence == original.findings[0].evidence
        assert restored.findings[0].extra["exposure"] == ["public location: Delhi", "42 public repositories"]

    def test_schema_field_is_versioned(self) -> None:
        payload = json.loads(render_json(report()))
        assert payload["schema"] == "d3ta1l3r/report/1"
        assert payload["options"]["signature_db_sha256"] == "deadbeef"

    def test_records_are_json_serialisable_even_with_odd_api_values(self) -> None:
        weird = report()
        weird.outcomes = [
            outcome(findings=[finding(account_created_at=1600000000, location={"city": "Delhi"})])
        ]
        weird.refresh_stats()
        payload = json.loads(render_json(weird))
        assert payload["outcomes"][0]["findings"][0]["account_created_at"] == "1600000000"
        # A dict where a string belongs gets coerced, never left to break a renderer.
        assert payload["outcomes"][0]["findings"][0]["location"] == "{'city': 'Delhi'}"


class TestDiff:
    def test_new_findings_are_reported(self) -> None:
        before = report()
        after = report()  # same sources and results...
        after.outcomes.append(
            outcome("new_svc", findings=[finding(source_id="new_svc", url="https://new.example/alice")])
        )  # ...plus one that appeared since
        after.refresh_stats()
        difference = diff_reports(before, after)
        assert [f.source_id for f in difference.new_findings] == ["new_svc"]
        assert difference.removed_findings == []

    def test_disappeared_findings_are_reported(self) -> None:
        before = report()
        after = report()
        after.outcomes = [outcome("svc", status=ScanStatus.NOT_FOUND, findings=[])]
        after.refresh_stats()
        difference = diff_reports(before, after)
        assert {f.source_id for f in difference.removed_findings} == {
            "github_api_user", "gravatar_api_email",
        }

    def test_status_changes_are_summarised(self) -> None:
        before = report()
        after = report()
        for item in after.outcomes:
            if item.source_id == "svc_b":
                item.status = ScanStatus.FOUND
        difference = diff_reports(before, after)
        assert ("svc_b", "blocked", "found") in difference.changed_sources

    def test_no_change_is_reported_as_such(self) -> None:
        difference = diff_reports(report(), report())
        assert difference.empty is True
        assert "No changes detected" in difference.render_markdown()

    def test_diff_serialises(self) -> None:
        difference = diff_reports(report(), report())
        assert json.loads(json.dumps(difference.to_dict()))["target"] == "@alice"


class TestSanity:
    def test_report_duration_uses_finished_at(self) -> None:
        assert report().duration_ms == 3000

    def test_findings_are_sorted_by_confidence(self) -> None:
        mixed = report()
        mixed.outcomes = [
            outcome("low", findings=[finding(confidence=Confidence.LOW)]),
            outcome("confirmed", findings=[finding(confidence=Confidence.CONFIRMED)]),
        ]
        mixed.refresh_stats()
        assert mixed.findings[0].confidence is Confidence.CONFIRMED

    def test_findings_by_category_groups_and_sorts(self) -> None:
        grouped = report().findings_by_category()
        assert set(grouped) == {"developer"}
        assert len(grouped["developer"]) == 2


_ = utcnow, pytest
