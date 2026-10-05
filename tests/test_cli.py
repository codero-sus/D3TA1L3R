"""CLI behaviour, exit codes, report files and the confidence filter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d3ta1l3r.cli import (
    EXIT_NEW_FINDINGS,
    EXIT_OK,
    EXIT_USAGE,
    _calibration_row,
    _split_values,
    _write_reports,
    build_parser,
    main,
)
from d3ta1l3r.core.report import render_json
from d3ta1l3r.core.storage import ScanStore
from d3ta1l3r.models import Confidence, ScanReport, ScanStatus, ScanTarget, SourceKind


class TestValueSplitting:
    def test_repeated_flags_and_commas_both_work(self) -> None:
        assert _split_values(["a", "b,c"]) == ["a", "b", "c"]

    def test_spaces_are_not_separators(self) -> None:
        """A two-word name must survive as one identifier."""
        assert _split_values(["Demo User"]) == ["Demo User"]
        assert _split_values([" a , b "]) == ["a", "b"]


class TestParser:
    def test_parser_builds_and_documents_the_tool(self) -> None:
        parser = build_parser()
        assert parser.prog == "d3ta1l3r"
        subparsers = [action for action in parser._actions if action.dest == "command"]
        assert subparsers and set(subparsers[0].choices) == {
            "scan", "sources", "calibrate", "diff", "web"
        }


class TestScanCommand:
    def test_scan_without_an_identifier_is_a_usage_error(self, capsys) -> None:
        assert main(["scan"]) == EXIT_USAGE
        assert "at least one" in capsys.readouterr().err

    def test_bad_identifier_is_rejected_before_any_request(self, capsys, tmp_path) -> None:
        code = main(["scan", "-u", "bad handle", "-o", str(tmp_path / "out"), "--demo"])
        assert code == EXIT_USAGE
        assert "bare handle" in capsys.readouterr().err

    def test_demo_scan_writes_all_three_formats(self, tmp_path, capsys) -> None:
        out = tmp_path / "scans"
        code = main([
            "scan", "-u", "demo_user", "-e", "demo.user@example.com", "-d", "example.com",
            "--demo", "-o", str(out), "--stdout", "json", "--quiet",
        ])
        assert code == EXIT_OK
        written = sorted(p.suffix for p in out.iterdir())
        assert written == [".html", ".json", ".md"]
        payload = json.loads(next(out.glob("*.json")).read_text())
        assert payload["demo"] is True
        assert payload["stats"]["findings_total"] > 0
        captured = capsys.readouterr().out
        assert json.loads(captured)["scan_id"] == payload["scan_id"]

    def test_report_filenames_are_sortable_and_identifiable(self, tmp_path) -> None:
        main(["scan", "-u", "demo_user", "--demo", "-o", str(tmp_path), "--stdout", "none", "-q"])
        name = next(tmp_path.glob("*.json")).name
        assert name[:8].isdigit() and "demo-user" in name

    def test_min_confidence_filters_weak_findings(self, tmp_path) -> None:
        out = tmp_path / "scans"
        main([
            "scan", "-u", "demo_user", "-n", "Demo User", "--demo", "-o", str(out),
            "--stdout", "json", "--quiet", "--min-confidence", "confirmed",
        ])
        payload = json.loads(next(out.glob("*.json")).read_text())
        for outcome in payload["outcomes"]:
            for finding in outcome["findings"]:
                assert finding["confidence"] == Confidence.CONFIRMED.value
        assert any("filtered out" in w for w in payload["warnings"])

    def test_verbose_scan_streams_progress(self, tmp_path, capsys) -> None:
        main([
            "scan", "-u", "demo_user", "--demo", "-o", str(tmp_path), "--stdout", "none", "-v",
        ])
        out = capsys.readouterr().out
        assert "scanning" in out
        assert "source(s)" in out

    def test_comparison_and_fail_on_new_uses_exit_code_3(self, tmp_path, capsys) -> None:
        out = tmp_path / "scans"
        main(["scan", "-u", "demo_user", "--demo", "-o", str(out), "--stdout", "none", "-q"])
        first = next(out.glob("*.json"))
        # A previous report with no findings at all: everything found now is "new".
        empty = ScanReport.new(ScanTarget.create(username="demo_user"), "0.1.0")
        empty.outcomes = []
        empty.refresh_stats()
        baseline = out / "baseline.json"
        baseline.write_text(render_json(empty), encoding="utf-8")

        code = main([
            "scan", "-u", "demo_user", "--demo", "-o", str(out), "--stdout", "none",
            "--compare", str(baseline), "--fail-on-new", "-q",
        ])
        assert code == EXIT_NEW_FINDINGS
        assert first.exists()

    def test_scan_help_mentions_the_scope_limits(self, capsys) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])
        out = capsys.readouterr().out
        assert "public, unauthenticated endpoints" in out


class TestSourcesCommand:
    def test_lists_sources_and_their_state(self, capsys) -> None:
        assert main(["sources"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "github_api_user" in out
        assert "disabled by default" in out

    def test_kind_filter(self, capsys) -> None:
        main(["sources", "--kind", "domain"])
        out = capsys.readouterr().out
        assert "rdap_domain" in out
        assert "github_api_user" not in out

    def test_json_output_is_machine_readable(self, capsys) -> None:
        main(["sources", "--json", "--enabled-only"])
        rows = json.loads(capsys.readouterr().out)
        assert all(row["enabled_by_default"] for row in rows)
        assert {"id", "name", "kind", "category", "description"} <= set(rows[0])


class TestCalibrationHelpers:
    def test_verdict_flags_false_positives_loudly(self) -> None:
        row = _calibration_row({
            "id": "noisy_site", "name": "Noisy",
            "absent_probes": [{"handle": "zzq123", "status": "found", "http_status": 200,
                               "evidence": "matched marker"}],
            "present_probe": None,
        })
        assert "do not trust" in row["verdict"]
        assert row["counts"]["false_positive"] == 1

    def test_verdict_flags_ambiguous_specs(self) -> None:
        row = _calibration_row({
            "id": "drifted", "name": "Drifted",
            "absent_probes": [{"handle": "zzq123", "status": "error", "http_status": 200,
                               "evidence": "ambiguous"}],
            "present_probe": None,
        })
        assert "spec needs updating" in row["verdict"]

    def test_verdict_confirms_good_absent_behaviour(self) -> None:
        row = _calibration_row({
            "id": "good", "name": "Good",
            "absent_probes": [{"handle": "zzq123", "status": "not_found", "http_status": 404,
                               "evidence": "HTTP 404"}],
            "present_probe": {"handle": "mine", "status": "found", "http_status": 200},
        })
        assert row["verdict"].startswith("trustworthy")
        assert "ground-truth account" in row["verdict"]

    def test_verdict_flags_a_missed_known_account(self) -> None:
        row = _calibration_row({
            "id": "blind", "name": "Blind",
            "absent_probes": [{"handle": "zzq123", "status": "not_found", "http_status": 404,
                               "evidence": "404"}],
            "present_probe": {"handle": "mine", "status": "not_found", "http_status": 404},
        })
        assert "MISSES a known account" in row["verdict"]


class TestDiffCommand:
    def test_diff_reports_new_findings_and_exits_3(self, tmp_path, capsys) -> None:
        store = ScanStore(tmp_path)
        older = _fake_report("alice", findings=0)
        newer = _fake_report("alice", findings=1)
        store.save(older, formats=("json",))
        store.save(newer, formats=("json",))
        code = main([
            "diff", str(store.path_for(older, ".json")), str(store.path_for(newer, ".json")),
        ])
        assert code == EXIT_NEW_FINDINGS
        assert "New findings" in capsys.readouterr().out

    def test_diff_handles_identical_reports(self, tmp_path, capsys) -> None:
        store = ScanStore(tmp_path)
        older = _fake_report("alice", findings=1)
        newer = _fake_report("alice", findings=1)
        store.save(older, formats=("json",))
        store.save(newer, formats=("json",))
        assert main(["diff", str(store.path_for(older, ".json")),
                     str(store.path_for(newer, ".json"))]) == EXIT_OK
        assert "No changes detected" in capsys.readouterr().out

    def test_missing_file_is_a_usage_error(self, tmp_path, capsys) -> None:
        assert main(["diff", str(tmp_path / "nope.json"), str(tmp_path / "nope2.json")]) == EXIT_USAGE
        assert "not found" in capsys.readouterr().err


class TestReportWriter:
    def test_format_selection_is_honoured(self, tmp_path) -> None:
        report = _fake_report("alice", findings=1)
        written = _write_reports(report, tmp_path, "json")
        assert [p.suffix for p in written] == [".json"]
        assert len(list(tmp_path.iterdir())) == 1

    def test_unknown_format_writes_nothing_but_does_not_crash(self, tmp_path) -> None:
        assert _write_reports(_fake_report("alice", 1), tmp_path, "pdf") == []


def _fake_report(username: str, findings: int) -> ScanReport:
    from d3ta1l3r.models import Finding, SourceOutcome

    report = ScanReport.new(ScanTarget.create(username=username), "0.1.0")
    found = [
        Finding(
            source_id=f"svc{i}",
            source_name=f"Service {i}",
            kind=SourceKind.USERNAME,
            url=f"https://svc{i}.example/{username}",
            identifier=username,
            confidence=Confidence.HIGH,
            evidence="synthetic",
        )
        for i in range(findings)
    ]
    report.outcomes = [
        SourceOutcome(
            source_id="svc0",
            source_name="Service 0",
            kind=SourceKind.USERNAME,
            status=ScanStatus.FOUND if found else ScanStatus.NOT_FOUND,
            findings=found,
        )
    ]
    report.finished_at = report.started_at
    report.refresh_stats()
    return report


_ = Path
