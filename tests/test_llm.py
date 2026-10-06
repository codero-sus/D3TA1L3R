"""The local-model chat: grounding, masking, loopback-only, and the CLI.

These tests are mostly about the promises the feature makes rather than the
generation itself — this suite cannot run a 1.5B model, and should not try. What
it can pin is everything that makes the answer trustworthy when a model *is*
installed:

* the digest masks identifiers unless the operator asked for raw ones, and the
  masking survives the places values hide (finding URLs, evidence text, labels);
* citations are verified against the context, so an invented ``F9-999`` is
  reported instead of displayed;
* :class:`OllamaBackend` refuses a non-loopback host, because "local model" that
  is not local is just data exfiltration with nicer wording;
* the supervisor is told what will fit in 4 GB before a 4 GB machine finds out;
* the CLI answers without a model at all, and says which backend spoke.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest

from d3ta1l3r.cli import EXIT_OK, main
from d3ta1l3r.errors import UsageError
from d3ta1l3r.llm import (
    ChatSession,
    ExtractiveBackend,
    LlamaCppBackend,
    OllamaBackend,
    build_context,
    build_messages,
    extract_citations,
    model_doctor,
    recommend_models,
    select_backend,
    verify_citations,
)
from d3ta1l3r.llm.backends import (
    DEFAULT_RAM_BUDGET_MB,
    GGUF_MAGIC,
    estimate_model_ram_mb,
    is_loopback_host,
)
from d3ta1l3r.llm.context import scrub_text
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
from d3ta1l3r.vault import VaultEntry, VaultKind


def make_report(
    *,
    demo: bool = False,
    findings: int = 2,
    gaps: int = 1,
) -> ScanReport:
    """A small report with known ids, raw handles and a gap."""
    target = ScanTarget(
        username="demo_user", email="demo@example.com", name="Demo User", location="Delhi, IN"
    )
    report = ScanReport.new(target, "0.1.0", demo=demo)
    outcomes: list[SourceOutcome] = []
    for index in range(findings):
        outcomes.append(
            SourceOutcome(
                source_id=f"site_{index}",
                source_name=f"Site {index}",
                kind=SourceKind.USERNAME,
                status=ScanStatus.FOUND,
                category="developer" if index == 0 else "social",
                findings=[
                    Finding(
                        source_id=f"site_{index}",
                        source_name=f"Site {index}",
                        kind=SourceKind.USERNAME,
                        url=f"https://site{index}.example/demo_user",
                        identifier="demo_user",
                        confidence=Confidence.HIGH,
                        category="developer" if index == 0 else "social",
                        evidence="the handle demo_user appears in the page title",
                        display_name="Demo User",
                    )
                ],
            )
        )
    for index in range(gaps):
        outcomes.append(
            SourceOutcome(
                source_id=f"wall_{index}",
                source_name=f"Wall {index}",
                kind=SourceKind.USERNAME,
                status=ScanStatus.BLOCKED,
                category="social",
                error="HTTP 403: sign-in wall",
            )
        )
    report.outcomes = outcomes
    report.demo = demo  # ScanReport.new() carries options, not the flag itself
    report.refresh_stats()
    report.finished_at = utcnow()
    return report


class TestBackendSelection:
    def test_loopback_hosts_are_accepted_and_others_are_not(self) -> None:
        for good in ("127.0.0.1", "localhost", "http://127.0.0.1:11434", "[::1]:11434"):
            assert is_loopback_host(good), good
        for bad in ("example.com", "http://models.example.com:11434", "10.0.0.5", "8.8.8.8"):
            assert not is_loopback_host(bad), bad

    def test_ollama_refuses_a_remote_host(self) -> None:
        with pytest.raises(UsageError) as excinfo:
            OllamaBackend("llama3.2:1b", host="http://models.example.com:11434")
        assert "non-local host" in str(excinfo.value)

    def test_an_explicit_backend_that_cannot_work_raises(self) -> None:
        """--backend llama_cpp must fail loudly rather than quietly degrading."""
        with pytest.raises(UsageError) as excinfo:
            select_backend(prefer="llama_cpp", model_path=Path("/nonexistent/model.gguf"))
        assert "llama_cpp" in str(excinfo.value)

    def test_auto_falls_back_and_explains(self) -> None:
        backend, notes = select_backend(model_path=Path("/nonexistent/model.gguf"))
        assert backend.name == "extractive"
        assert notes, "the fallback must be explained, not silent"
        assert any("llama_cpp" in note for note in notes)

    def test_ollama_availability_is_probed_on_loopback_only(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.host in {"127.0.0.1", "localhost"}, request.url
            return httpx.Response(200, json={"models": [{"name": "llama3.2:1b"}]})

        with httpx.Client(
            base_url="http://127.0.0.1:11434", transport=httpx.MockTransport(handler)
        ) as _:
            backend = OllamaBackend(
                "llama3.2:1b", transport=httpx.MockTransport(handler), timeout=5
            )
            ok, reason = backend.available()
        assert ok, reason

    def test_ollama_reports_a_missing_model_precisely(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"models": [{"name": "phi3:mini"}]})

        backend = OllamaBackend(
            "llama3.2:1b", transport=httpx.MockTransport(handler), timeout=5
        )
        ok, reason = backend.available()
        assert not ok
        assert "llama3.2:1b" in reason and "phi3:mini" in reason


class TestModelSizing:
    def test_the_recommendations_fit_the_budget(self) -> None:
        for item in recommend_models(4096):
            assert item.ram_mb <= 4096, item

    def test_a_small_budget_still_recommends_something(self) -> None:
        assert recommend_models(512), "a tiny machine still needs one suggestion"

    def test_a_gguf_estimate_counts_more_than_the_file(self, tmp_path: Path) -> None:
        """Being told a model will not fit when it would is the cheap mistake."""
        model = tmp_path / "model.gguf"
        model.write_bytes(GGUF_MAGIC + b"\x00" * (4 * 1024 * 1024))
        file_mb = model.stat().st_size / (1024 * 1024)
        estimate = estimate_model_ram_mb(model, context_window=2048)
        assert estimate > file_mb, "the KV cache and runtime overhead must be counted"

    def test_llama_cpp_refuses_a_model_that_does_not_fit(self, tmp_path: Path) -> None:
        """A sparse 2 GB file keeps the test cheap and the arithmetic honest."""
        model = tmp_path / "big.gguf"
        model.write_bytes(GGUF_MAGIC)
        os.truncate(model, 2 * 1024**3)
        backend = LlamaCppBackend(model, ram_budget_mb=1024, context_window=2048)
        ok, reason = backend.available()
        assert not ok
        assert "RAM" in reason or "budget" in reason
        assert "1024" in reason, "the refusal should say what budget was exceeded"

    def test_a_non_gguf_file_is_rejected_before_loading(self, tmp_path: Path) -> None:
        model = tmp_path / "not-a-model.bin"
        model.write_bytes(b"NOPE" + b"\x00" * 1024)
        ok, reason = LlamaCppBackend(model).available()
        assert not ok
        assert "GGUF" in reason

    def test_the_doctor_reports_the_budget_and_a_choice(self) -> None:
        report = model_doctor(Path("/nonexistent/model.gguf"), ram_budget_mb=DEFAULT_RAM_BUDGET_MB)
        assert report["ram_budget_mb"] == DEFAULT_RAM_BUDGET_MB
        assert report["selected"] == "extractive"
        names = {item["name"] for item in report["backends"]}
        assert {"ollama", "llama_cpp", "extractive"} <= names
        assert any(item["fits_4gb"] for item in report["recommendations"])


class TestContext:
    def test_every_line_carries_a_citable_id(self) -> None:
        context = build_context([make_report()])
        ids = context.ids()
        assert "S1" in ids
        assert "F1-001" in ids and "F1-002" in ids
        assert "G1-01" in ids

    def test_masked_by_default_and_raw_on_request(self) -> None:
        report = make_report()
        masked = build_context([report], include_values=False).render()
        raw = build_context([report], include_values=True).render()
        assert "demo_user" not in masked
        assert "demo@example.com" not in masked
        assert "Demo User" not in masked
        assert "demo_user" in raw and "demo@example.com" in raw

    def test_masking_survives_finding_urls_and_evidence(self) -> None:
        """Handles hide inside URLs and evidence sentences; both must be scrubbed."""
        report = make_report()
        assert "https://site0.example/demo_user" in report.findings[0].url
        masked = build_context([report], include_values=False).render()
        assert "site0.example" in masked, "the site itself is not a secret"
        assert "/demo_user" not in masked
        assert "the handle d…r appears" in masked or "demo_user" not in masked

    def test_scrub_replaces_longest_first_so_a_short_handle_cannot_corrupt_an_email(self) -> None:
        pairs = sorted(
            [("alice@example.com", "al***@example.com"), ("alice", "a…e")],
            key=lambda pair: len(pair[0]),
            reverse=True,
        )
        assert scrub_text("write to alice@example.com, not alice", pairs) == (
            "write to al***@example.com, not a…e"
        )

    def test_watchlist_entries_are_numbered_and_masked(self) -> None:
        entries = [
            VaultEntry(kind=VaultKind.EMAIL, value="demo@example.com", last_status="clean"),
            VaultEntry(
                kind=VaultKind.PASSWORD,
                password_sha1="a" * 40,
                last_status="pwned",
                last_count=3,
            ),
        ]
        context = build_context([make_report()], watchlist=entries)
        assert {"E1", "E2"} <= context.ids()
        rendered = context.render()
        assert "de***@example.com" in rendered
        assert "pwned (3 record(s))" in rendered
        assert "a" * 40 not in rendered, "the verifier must never reach a prompt"

    def test_gaps_are_in_the_digest_so_they_can_be_asked_about(self) -> None:
        rendered = build_context([make_report(gaps=2)]).render()
        assert "G1-01" in rendered and "G1-02" in rendered
        assert "was not checked" in rendered

    def test_demo_reports_are_labelled_as_demo(self) -> None:
        assert "DEMO fixtures" in build_context([make_report(demo=True)]).render()
        assert "DEMO fixtures" not in build_context([make_report(demo=False)]).render()

    def test_the_digest_is_trimmed_without_cutting_a_line_in_half(self) -> None:
        context = build_context([make_report(findings=40)])
        rendered = context.render(max_chars=600)
        for line in rendered.splitlines():
            if line.startswith("…"):
                continue
            assert line.startswith("["), line
        assert len(rendered) < 900

    def test_newest_scan_gets_the_first_number(self) -> None:
        older = make_report()
        newer = make_report()
        older.started_at = older.started_at.replace(year=2020)
        context = build_context([older, newer])
        scan_lines = [item for item in context.items if item.kind == "scan"]
        assert context.reports[0].scan_id == newer.scan_id
        assert scan_lines[0].refs["scan_id"] == newer.scan_id


class TestCitations:
    def test_ids_are_extracted_in_order_without_duplicates(self) -> None:
        text = "See [F1-003] and [E2], also [f1-003] and [G1-01]."
        assert extract_citations(text) == ["F1-003", "E2", "G1-01"]

    def test_invented_ids_are_reported_not_swallowed(self) -> None:
        verdict = verify_citations("Use [F1-001] and [F9-999].", {"F1-001", "S1"})
        assert verdict.known == ["F1-001"]
        assert verdict.unknown == ["F9-999"]
        assert not verdict.ok

    def test_verification_is_case_insensitive(self) -> None:
        assert verify_citations("see [s1]", {"S1"}).ok

    def test_an_answer_with_an_invented_citation_is_flagged(self) -> None:
        context = build_context([make_report()])

        class Liar(ExtractiveBackend):
            def generate(self, messages, *, context_text: str = "") -> str:  # type: ignore[override]
                return "Everything is fine [F1-001], and also [F9-999]."

        session = ChatSession(context, Liar())
        answer = session.ask("summary?")
        assert answer.unknown_citations == ["F9-999"]
        assert "not in the context" in answer.citation_problem
        assert "[F9-999]" not in answer.clean_text(strip_unknown=True)
        assert "[F1-001]" in answer.clean_text(strip_unknown=True)

    def test_an_answer_without_citations_from_a_model_is_not_grounded(self) -> None:
        class Vague(ExtractiveBackend):
            is_model = True  # a retrieval answer is exempt from citing; a model is not

            def generate(self, messages, *, context_text: str = "") -> str:  # type: ignore[override]
                return "You should probably change your passwords."

        session = ChatSession(build_context([make_report()]), Vague())
        answer = session.ask("what now?")
        assert not answer.grounded
        assert "cites no context id" in answer.citation_problem


class TestChatSession:
    def test_the_extractive_backend_answers_with_ids_and_says_it_is_not_a_model(self) -> None:
        session = ChatSession(build_context([make_report()]))
        answer = session.ask("which sites could not be checked?")
        assert answer.is_model is False
        assert "not generation" in answer.text or "keyword retrieval" in answer.text
        assert answer.citations, "a retrieval answer must still cite what it returned"
        assert answer.grounded

    def test_an_empty_context_says_so_instead_of_inventing(self) -> None:
        session = ChatSession(build_context([]))
        answer = session.ask("what should I fix?")
        assert "no context" in answer.text.lower()
        assert not answer.citations

    def test_a_failing_backend_degrades_to_retrieval_instead_of_a_traceback(self) -> None:
        class Broken(ExtractiveBackend):
            def generate(self, messages, *, context_text: str = "") -> str:  # type: ignore[override]
                raise RuntimeError("the model crashed")

        session = ChatSession(build_context([make_report()]), Broken())
        answer = session.ask("what is exposed?")
        assert answer.text
        assert any("failed" in note for note in answer.notes)

    def test_history_is_bounded_and_resettable(self) -> None:
        session = ChatSession(build_context([make_report()]), max_history=2)
        for index in range(5):
            session.ask(f"question {index}")
        assert len(session.history) <= 4
        session.reset()
        assert session.history == []

    def test_an_empty_question_is_a_programming_error(self) -> None:
        session = ChatSession(build_context([make_report()]))
        with pytest.raises(ValueError):
            session.ask("   ")

    def test_the_session_reports_that_nothing_is_written_to_disk(self) -> None:
        session = ChatSession(build_context([make_report()]))
        assert session.describe()["stored_to_disk"] is False

    def test_question_and_context_land_in_one_user_turn(self) -> None:
        messages = build_messages("what is public?", "[F1-001] a finding")
        assert messages[0]["role"] == "system"
        assert messages[-1]["role"] == "user"
        assert "CONTEXT:" in messages[-1]["content"]
        assert "QUESTION: what is public?" in messages[-1]["content"]
        assert "cite" in messages[0]["content"].lower()


def _ask(args: list[str]) -> str:
    """Run the CLI and capture only its stdout (the JSON, for --json runs)."""
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(args)
    assert code == EXIT_OK, f"{args} exited {code}"
    return buffer.getvalue()


class TestAskCommand:
    def _scan(self, tmp_path: Path) -> Path:
        out = tmp_path / "scans"
        assert main(["scan", "-u", "demo_user", "-e", "demo@example.com", "--demo",
                     "-o", str(out), "-q"]) == EXIT_OK
        return out

    def test_ask_answers_without_any_model_installed(self, tmp_path: Path, capsys) -> None:
        out = self._scan(tmp_path)
        code = main(["ask", "what could not be checked?", "-o", str(out),
                     "--no-watchlist", "--backend", "extractive", "-y"])
        captured = capsys.readouterr()
        assert code == EXIT_OK
        assert "retrieval" in captured.out.lower() or "direct answer" in captured.out.lower()
        assert captured.err, "the backend used must be stated on stderr"

    def test_ask_json_is_machine_readable_and_keeps_the_verdict(self, tmp_path: Path,
                                                              capsys) -> None:
        out = self._scan(tmp_path)
        payload = json.loads(
            _ask(["ask", "what is exposed?", "-o", str(out), "--no-watchlist", "--json", "-y"])
        )
        assert payload["citation_problem"] == ""
        assert payload["grounded"] is True
        assert payload["backend"] == "extractive"
        assert payload["is_model"] is False

    def test_ask_masks_by_default_and_includes_values_on_request(self, tmp_path: Path,
                                                                capsys) -> None:
        out = self._scan(tmp_path)
        masked = _ask(
            ["ask", "where is my handle?", "-o", str(out), "--no-watchlist", "--json", "-y"]
        )
        assert "demo_user" not in masked
        raw = _ask(
            ["ask", "where is my handle?", "-o", str(out), "--no-watchlist", "--json", "-y",
             "--include-values"]
        )
        assert "demo_user" in raw

    def test_ask_writes_nothing_to_the_scan_directory(self, tmp_path: Path) -> None:
        out = self._scan(tmp_path)
        before = {path.name for path in out.iterdir()}
        main(["ask", "anything?", "-o", str(out), "--no-watchlist", "-y"])
        assert {path.name for path in out.iterdir()} == before

    def test_ask_without_a_question_explains_itself(self, tmp_path: Path, capsys) -> None:
        out = self._scan(tmp_path)
        assert main(["ask", "-o", str(out), "--no-watchlist"]) != EXIT_OK
        assert "ask a question" in capsys.readouterr().err

    def test_ask_with_nothing_to_ask_about_is_a_usage_error(self, tmp_path: Path, capsys) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        code = main(["ask", "anything?", "-o", str(empty), "--no-watchlist"])
        assert code != EXIT_OK
        assert "nothing to ask about" in capsys.readouterr().err

    def test_ask_can_read_a_report_file_directly(self, tmp_path: Path, capsys) -> None:
        out = self._scan(tmp_path)
        report = next(out.glob("*.json"))
        payload = json.loads(
            _ask(["ask", "what is exposed?", "--report", str(report), "--no-watchlist", "-y",
                  "--json"])
        )
        assert payload["citations"]

    def test_ask_uses_the_vault_watchlist_when_one_is_present(self, tmp_path: Path,
                                                             monkeypatch, capsys) -> None:
        out = self._scan(tmp_path)
        vault_path = tmp_path / "watchlist.vault"
        monkeypatch.setenv("D3TA1L3R_VAULT", str(vault_path))
        monkeypatch.setenv("D3TA1L3R_VAULT_PASSPHRASE", "ask-test-passphrase")
        assert main(["vault", "init"]) == EXIT_OK
        assert main(["vault", "add", "--kind", "email", "demo@example.com", "--no-check"]) == EXIT_OK
        payload = json.loads(
            _ask(["ask", "which email is in my watchlist?", "-o", str(out), "--json", "-y"])
        )
        # E1 is the watchlist entry: retrieval answers cite what they returned, so
        # an entry the question is about must be able to surface at all.
        assert "E1" in payload["citations"], payload["citations"]

    def test_list_models_needs_no_scan_and_explains_the_budget(self, capsys) -> None:
        assert main(["ask", "--list-models"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "RAM budget: 4096 MB" in out
        assert "Qwen2.5-1.5B" in out
        assert "llama-cpp-python" in out
