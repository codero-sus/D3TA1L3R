"""CLI behaviour, exit codes, report files and the confidence filter."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from d3ta1l3r.cli import (
    EXIT_FAILURE,
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
            "scan", "sources", "calibrate", "diff", "vault", "breach", "web", "ask", "models"
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


class TestVaultCommand:
    """The vault CLI: the passphrase never comes from argv, results stay masked."""

    @pytest.fixture(autouse=True)
    def _passphrase(self, monkeypatch, tmp_path):
        # Non-interactive: the documented environment variable, not a terminal.
        monkeypatch.setenv("D3TA1L3R_VAULT_PASSPHRASE", "correct horse battery staple")
        monkeypatch.setenv("D3TA1L3R_VAULT", str(tmp_path / "watchlist.vault"))
        return "correct horse battery staple"

    def test_init_creates_a_locked_down_vault(self, tmp_path, capsys) -> None:
        assert main(["vault", "init"]) == EXIT_OK
        output = capsys.readouterr().out
        assert "created" in output
        assert "0o600" in output
        assert (tmp_path / "watchlist.vault").is_file()

    def test_init_refuses_to_clobber_and_can_be_forced(self, tmp_path, capsys) -> None:
        main(["vault", "init"])
        capsys.readouterr()
        assert main(["vault", "init"]) == EXIT_FAILURE
        assert "already exists" in capsys.readouterr().err
        assert main(["vault", "init", "--force"]) == EXIT_OK

    def test_where_needs_no_passphrase(self, tmp_path, monkeypatch, capsys) -> None:
        main(["vault", "init"])
        capsys.readouterr()
        monkeypatch.delenv("D3TA1L3R_VAULT_PASSPHRASE", raising=False)
        assert main(["vault", "where"]) == EXIT_OK
        assert "0o600" in capsys.readouterr().out

    def test_where_reports_a_missing_vault_without_failing(self, tmp_path, capsys) -> None:
        assert main(["vault", "where"]) == EXIT_OK
        assert "not created yet" in capsys.readouterr().out

    def test_add_list_and_unlock_keep_values_masked(self, tmp_path, capsys) -> None:
        main(["vault", "init"])
        assert main(["vault", "add", "--kind", "email", "alice@example.com", "--no-check"]) == EXIT_OK
        capsys.readouterr()
        assert main(["vault", "list"]) == EXIT_OK
        listed = capsys.readouterr().out
        assert "al***@example.com" in listed
        assert "alice@example.com" not in listed
        assert main(["vault", "unlock"]) == EXIT_OK
        assert "entries: 1" in capsys.readouterr().out

    def test_list_json_is_masked(self, tmp_path, capsys) -> None:
        main(["vault", "init"])
        main(["vault", "add", "--kind", "email", "alice@example.com", "--no-check"])
        capsys.readouterr()
        main(["vault", "list", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["entries"][0]["masked_value"] == "al***@example.com"
        assert "alice@example.com" not in json.dumps(payload)

    def test_adding_the_same_value_twice_says_so(self, tmp_path, capsys) -> None:
        main(["vault", "init"])
        main(["vault", "add", "--kind", "username", "alice", "--no-check"])
        capsys.readouterr()
        main(["vault", "add", "--kind", "username", "alice", "--no-check"])
        assert "already watched" in capsys.readouterr().out

    def test_a_password_is_prompted_for_and_checked_from_stdin(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        main(["vault", "init"])
        capsys.readouterr()
        monkeypatch.setattr("sys.stdin", io.StringIO("hunter2\n"))
        code = main(["vault", "add", "--kind", "password", "--store-hash", "--demo"])
        assert code == EXIT_NEW_FINDINGS  # found in the demo corpus
        output = capsys.readouterr().out
        assert "hunter2" not in output
        assert "••••••••" in output

    def test_a_password_is_never_written_to_the_vault(self, tmp_path, monkeypatch, capsys) -> None:
        main(["vault", "init"])
        monkeypatch.setattr("sys.stdin", io.StringIO("hunter2\n"))
        main(["vault", "add", "--kind", "password", "--store-hash", "--demo"])
        raw = (tmp_path / "watchlist.vault").read_text(encoding="utf-8")
        assert "hunter2" not in raw
        assert hashlib.sha1(b"hunter2").hexdigest() not in raw

    def test_remove_asks_unless_told_not_to(self, tmp_path, monkeypatch, capsys) -> None:
        main(["vault", "init"])
        main(["vault", "add", "--kind", "username", "alice", "--no-check"])
        entry_id = json.loads(
            _capture(lambda: main(["vault", "list", "--json"]))
        )["entries"][0]["entry_id"]
        capsys.readouterr()
        monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
        assert main(["vault", "remove", entry_id]) == EXIT_OK
        assert "left it alone" in capsys.readouterr().out
        assert main(["vault", "remove", entry_id, "--yes"]) == EXIT_OK

    def test_removing_something_that_is_not_there_is_a_usage_error(self, tmp_path, capsys) -> None:
        main(["vault", "init"])
        capsys.readouterr()
        assert main(["vault", "remove", "nope", "--yes"]) == EXIT_USAGE
        assert "no entry" in capsys.readouterr().err

    def test_rotate_changes_the_passphrase(self, tmp_path, monkeypatch, capsys) -> None:
        main(["vault", "init"])
        capsys.readouterr()
        new_secret = tmp_path / "new-passphrase.txt"
        new_secret.write_text("a second long passphrase\n", encoding="utf-8")
        assert main(["vault", "rotate", "--new-passphrase-file", str(new_secret)]) == EXIT_OK
        assert "re-encrypted" in capsys.readouterr().out
        monkeypatch.setenv("D3TA1L3R_VAULT_PASSPHRASE", "correct horse battery staple")
        assert main(["vault", "unlock"]) == EXIT_FAILURE  # the old one no longer works
        monkeypatch.setenv("D3TA1L3R_VAULT_PASSPHRASE", "a second long passphrase")
        assert main(["vault", "unlock"]) == EXIT_OK

    def test_init_can_be_seeded_from_a_stored_scan(self, tmp_path, capsys) -> None:
        scans = tmp_path / "scans"
        main(["scan", "-u", "demo_user", "-e", "demo.user@example.com", "--demo",
              "-o", str(scans), "--stdout", "none", "-q"])
        report = next(scans.glob("*.json"))
        assert main(["vault", "init", "--from-scan", str(report)]) == EXIT_OK
        assert "seeded 2 identifier(s)" in capsys.readouterr().out

    def test_a_bad_seed_report_leaves_no_vault_behind(self, tmp_path, capsys) -> None:
        junk = tmp_path / "not-a-report.json"
        junk.write_text("{}", encoding="utf-8")
        assert main(["vault", "init", "--from-scan", str(junk)]) == EXIT_USAGE
        assert not (tmp_path / "watchlist.vault").exists()


class TestBreachCommand:
    @pytest.fixture(autouse=True)
    def _vault(self, monkeypatch, tmp_path):
        monkeypatch.setenv("D3TA1L3R_VAULT_PASSPHRASE", "correct horse battery staple")
        monkeypatch.setenv("D3TA1L3R_VAULT", str(tmp_path / "watchlist.vault"))
        main(["vault", "init"])
        return tmp_path / "watchlist.vault"

    def test_sources_lists_what_is_usable(self, capsys) -> None:
        assert main(["breach", "sources"]) == EXIT_OK
        output = capsys.readouterr().out
        assert "pwned_passwords" in output
        assert "unavailable" in output  # no HIBP key in the test environment

    def test_sources_json_is_machine_readable(self, capsys) -> None:
        main(["breach", "sources", "--json"])
        rows = json.loads(capsys.readouterr().out)
        ids = [row["id"] for row in rows]
        assert ids[0] == "pwned_passwords"
        assert all("sends_data" in row for row in rows)

    def test_check_finds_a_breached_password_in_demo_mode(self, capsys) -> None:
        import d3ta1l3r.cli as cli_module

        original = cli_module.prompt_password
        cli_module.prompt_password = lambda what="": "hunter2"
        try:
            code = main(["breach", "check", "--kind", "password", "--demo"])
        finally:
            cli_module.prompt_password = original
        assert code == EXIT_NEW_FINDINGS
        assert "found in breach data" in capsys.readouterr().out

    def test_check_infers_the_kind_from_the_value(self, capsys) -> None:
        assert main(["breach", "check", "alice@example.com", "--demo"]) == EXIT_NEW_FINDINGS
        assert "pwned" in capsys.readouterr().out

    def test_check_does_not_need_a_vault(self, monkeypatch, capsys) -> None:
        monkeypatch.delenv("D3TA1L3R_VAULT", raising=False)
        monkeypatch.delenv("D3TA1L3R_VAULT_PASSPHRASE", raising=False)
        assert main(["breach", "check", "quiet@example.com", "--demo"]) == EXIT_OK
        assert "not found" in capsys.readouterr().out

    def test_run_on_an_empty_watchlist_explains_itself(self, capsys) -> None:
        assert main(["breach", "run", "--demo"]) == EXIT_OK
        assert "watchlist is empty" in capsys.readouterr().out

    def test_run_records_outcomes_in_the_vault(self, capsys) -> None:
        main(["vault", "add", "--kind", "password", "hunter2x", "--demo", "--store-hash"])
        main(["vault", "add", "--kind", "email", "alice@example.com", "--demo"])
        capsys.readouterr()
        assert main(["breach", "run", "--demo", "-q"]) == EXIT_NEW_FINDINGS
        main(["vault", "list"])
        listed = capsys.readouterr().out
        assert "last: pwned" in listed

    def test_run_writes_a_report_when_asked(self, tmp_path, capsys) -> None:
        main(["vault", "add", "--kind", "email", "alice@example.com", "--demo"])
        out = tmp_path / "scans"
        main(["breach", "run", "--demo", "-o", str(out), "-q"])
        saved = list((out / "breach").glob("*.json"))
        assert saved and (out / "breach" / "latest.json").is_file()
        payload = json.loads(saved[0].read_text(encoding="utf-8"))
        assert payload["schema"] == "d3ta1l3r/breach/1"
        assert "alice@example.com" not in saved[0].read_text(encoding="utf-8")

    def test_run_json_output_is_masked(self, capsys) -> None:
        main(["vault", "add", "--kind", "email", "alice@example.com", "--demo"])
        capsys.readouterr()
        main(["breach", "run", "--demo", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["entry_counts"]["pwned"] == 1
        assert "alice@example.com" not in json.dumps(payload)

    def test_a_missing_corpus_is_a_usage_error(self, capsys) -> None:
        assert main(["breach", "run", "--demo", "--corpus", "/nope/missing.txt"]) == EXIT_USAGE
        assert "corpus file not found" in capsys.readouterr().err

    def test_corpus_hash_writes_hashes_not_values(self, tmp_path, capsys) -> None:
        source = tmp_path / "plain.txt"
        source.write_text("hunter2\nalice@example.com\n", encoding="utf-8")
        out = tmp_path / "corpus"
        assert main(["breach", "corpus-hash", str(source), "--algorithm", "sha1",
                     "-o", str(out)]) == EXIT_OK
        written = out / "plain-sha1.txt"
        body = written.read_text(encoding="utf-8")
        assert "hunter2" not in body
        assert body.startswith("sha1:")

    def test_a_local_corpus_reports_a_match_without_the_network(
        self, tmp_path, capsys
    ) -> None:
        corpus = tmp_path / "corpus.txt"
        corpus.write_text(f"sha1:{hashlib.sha1(b'hunter2').hexdigest()}\n", encoding="utf-8")
        main(["vault", "add", "--kind", "password", "hunter2", "--store-hash", "--no-check"])
        capsys.readouterr()
        assert main(["breach", "run", "--corpus", str(corpus), "-q"]) == EXIT_NEW_FINDINGS
        assert "in breach data" in capsys.readouterr().out


def _capture(call) -> str:
    """Run ``call`` and return what it printed (used for --json output)."""
    import contextlib
    import io as _io

    buffer = _io.StringIO()
    with contextlib.redirect_stdout(buffer):
        call()
    return buffer.getvalue()


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
