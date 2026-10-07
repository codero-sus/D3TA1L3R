"""Identity verification: opt-in, parseable, and never confused with evidence.

The dangerous failures for this feature are all about attribution:
* a model verdict quietly replacing the measured confidence,
* a malformed answer being read as "it's me",
* an id the model invented attaching itself to a real finding,
* verification running when the operator did not ask for it.

Each of those has a test. The model itself is stubbed — a 1.5B GGUF is not going
to run in CI, and these tests are about the contract around it, not its prose.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from d3ta1l3r.cli import EXIT_OK, main
from d3ta1l3r.llm import (
    ExtractiveBackend,
    parse_verdicts,
    verify_findings,
)
from d3ta1l3r.llm.verify import (
    Verdict,
    build_verification_messages,
    render_verification_markdown,
)
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


class StubModel(ExtractiveBackend):
    """Answers in the required shape; records the prompt so tests can inspect it."""

    is_model = True
    name = "stub"

    def __init__(self, reply: str = "", *, brain=None) -> None:
        super().__init__()
        self.reply = reply
        self.brain = brain
        self.prompts: list[str] = []

    @property
    def model_id(self) -> str:
        return "stub-1.5b-q4"

    def generate(self, messages, *, context_text: str = ""):  # type: ignore[override]
        self.prompts.append(messages[-1]["content"])
        if self.brain is not None:
            return self.brain(self.prompts[-1])
        return self.reply


def make_report(*, findings: int = 3, demo: bool = False) -> ScanReport:
    target = ScanTarget(username="demo_user", email="demo@example.com")
    report = ScanReport.new(target, "0.1.0", demo=demo)
    report.demo = demo
    report.outcomes = [
        SourceOutcome(
            source_id=f"site_{index}",
            source_name=f"Site {index}",
            kind=SourceKind.USERNAME,
            status=ScanStatus.FOUND,
            category="social",
            findings=[
                Finding(
                    source_id=f"site_{index}",
                    source_name=f"Site {index}",
                    kind=SourceKind.USERNAME,
                    url=f"https://site{index}.example/demo_user",
                    identifier="demo_user",
                    confidence=Confidence.HIGH if index % 2 else Confidence.LOW,
                    category="social",
                    evidence="HTTP 200 and no not-found phrase",
                    display_name=f"Some Name {index}",
                    location="Berlin, DE",
                )
            ],
        )
        for index in range(findings)
    ]
    report.refresh_stats()
    report.finished_at = utcnow()
    return report


class TestParsing:
    def test_a_well_formed_answer_parses(self) -> None:
        text = (
            "VERDICT F1-001 MINE — the handle matches exactly\n"
            "VERDICT F1-002 NOT_MINE — different display name\n"
            "VERDICT F1-003 UNSURE — a bare 200\n"
        )
        verdicts = parse_verdicts(text, known_ids=["F1-001", "F1-002", "F1-003"])
        assert [v.verdict for v in verdicts] == [Verdict.MINE, Verdict.NOT_MINE, Verdict.UNSURE]
        assert verdicts[1].reason == "different display name"

    @pytest.mark.parametrize(
        "line",
        [
            "VERDICT F1-001 NOT_MINE - wrong person",
            "VERDICT F1-001 NOTMINE: wrong person",
            "VERDICT F1-001 not_mine — wrong person",
            "verdict f1-001 not mine — wrong person",
            "VERDICT [F1-001] NOT-MINE — wrong person",
        ],
    )
    def test_the_wording_a_small_model_actually_emits_is_accepted(self, line: str) -> None:
        verdicts = parse_verdicts(line, known_ids=["F1-001"])
        assert verdicts and verdicts[0].verdict is Verdict.NOT_MINE

    def test_an_invented_id_is_dropped(self) -> None:
        verdicts = parse_verdicts("VERDICT F9-999 MINE — invented", known_ids=["F1-001"])
        assert verdicts == []

    def test_a_broken_line_becomes_unsure_and_says_so(self) -> None:
        """The one unacceptable outcome would be reading gibberish as "it's me"."""
        verdicts = parse_verdicts("VERDICT F1-001 probably mine!", known_ids=["F1-001"])
        assert len(verdicts) == 1
        assert verdicts[0].verdict is Verdict.UNSURE
        assert verdicts[0].parsed is False
        assert "unparseable" in verdicts[0].reason

    def test_prose_without_verdict_lines_is_ignored(self) -> None:
        assert parse_verdicts("I think this is probably you.", known_ids=["F1-001"]) == []

    def test_a_duplicate_line_does_not_double_count(self) -> None:
        text = "VERDICT F1-001 MINE — one\nVERDICT F1-001 NOT_MINE — two\n"
        verdicts = parse_verdicts(text, known_ids=["F1-001"])
        assert len(verdicts) == 1 and verdicts[0].verdict is Verdict.MINE


class TestVerificationRun:
    def test_verdicts_never_change_the_measured_confidence(self) -> None:
        report = make_report()
        before = [finding.confidence for finding in report.findings]
        backend = StubModel(brain=lambda _prompt: _answer_all("F1-001", "NOT_MINE"))
        verify_findings([report], backend)
        after = [finding.confidence for finding in report.findings]
        assert before == after, "a model opinion must not rewrite a measurement"

    def test_every_finding_gets_a_verdict_even_when_the_model_skips_one(self) -> None:
        report = make_report(findings=3)
        backend = StubModel("VERDICT F1-001 MINE — only this one")
        result = verify_findings([report], backend)
        assert len(result.verdicts) == 3
        skipped = [v for v in result.verdicts if v.finding_id != "F1-001"]
        assert all(v.verdict is Verdict.UNSURE for v in skipped)
        assert all("did not answer" in v.reason for v in skipped)

    def test_a_crashing_model_still_produces_unsure_not_a_failure(self) -> None:
        class Broken(StubModel):
            def generate(self, messages, *, context_text: str = ""):  # type: ignore[override]
                raise RuntimeError("the model died")

        result = verify_findings([make_report()], Broken())
        assert result.verdicts
        assert all(v.verdict is Verdict.UNSURE for v in result.verdicts)
        assert any("failed" in note for note in result.notes)

    def test_disagreement_with_a_strong_finding_is_flagged(self) -> None:
        report = make_report(findings=2)
        # the report decides which finding is strong; the test must not assume
        strong_index = next(
            index
            for index, finding in enumerate(report.findings)
            if finding.confidence is Confidence.HIGH
        )
        strong_source = report.findings[strong_index].source_id

        def disagree_with_the_strong_one(prompt: str) -> str:
            # verify_findings numbers the prompt in report.findings order
            return "\n".join(
                "VERDICT {} {} — stub".format(
                    finding_id,
                    "NOT_MINE" if index == strong_index else "UNSURE",
                )
                for index, finding_id in enumerate(_ids(prompt))
            )

        result = verify_findings([report], StubModel(brain=disagree_with_the_strong_one))
        flagged = [v for v in result.verdicts if v.disagrees_with_evidence]
        assert len(flagged) == 1
        assert flagged[0].measured_confidence == Confidence.HIGH.value
        assert flagged[0].source_id == strong_source

    def test_only_uncertain_skips_the_confident_ones(self) -> None:
        report = make_report(findings=4)
        result = verify_findings([report], StubModel(""), only_uncertain=True)
        assert {v.measured_confidence for v in result.verdicts} == {Confidence.LOW.value}

    def test_a_limit_caps_how_much_is_asked(self) -> None:
        result = verify_findings([make_report(findings=5)], StubModel(""), limit=2)
        assert len(result.verdicts) == 2

    def test_an_empty_selection_says_so_rather_than_inventing_work(self) -> None:
        report = make_report(findings=0)
        result = verify_findings([report], StubModel("VERDICT F1-001 MINE — nothing to judge"))
        assert result.verdicts == []
        assert "no findings to review" in result.notes

    def test_masked_by_default_and_raw_on_request(self) -> None:
        report = make_report(findings=1)
        masked = StubModel(brain=lambda prompt: prompt)
        verify_findings([report], masked, include_values=False)
        assert "demo@example.com" not in masked.prompts[0]
        raw = StubModel(brain=lambda prompt: prompt)
        verify_findings([report], raw, include_values=True)
        assert "demo@example.com" in raw.prompts[0]

    def test_the_prompt_states_the_rules_and_the_ids(self) -> None:
        report = make_report(findings=2)
        backend = StubModel("")
        verify_findings([report], backend, about="my bios mention chess")
        prompt = backend.prompts[0]
        assert "[F1-001]" in prompt and "[F1-002]" in prompt
        assert "my bios mention chess" in prompt
        assert "UNSURE" in prompt

    def test_the_system_prompt_forbids_guessing(self) -> None:
        messages = build_verification_messages([])
        system = messages[0]["content"]
        assert "UNSURE" in system
        assert "Do not invent" in system
        assert "not" in system.lower() and "guess" in system.lower()

    def test_the_summary_counts_every_verdict(self) -> None:
        report = make_report(findings=3)
        ids = None  # resolved below from the prompt
        backend = StubModel(brain=lambda prompt: _answer_all(*_first_two(prompt)))

        def _stub(prompt: str) -> str:
            nonlocal ids
            ids = _ids(prompt)
            return "\n".join(
                [
                    f"VERDICT {ids[0]} MINE — matches",
                    f"VERDICT {ids[1]} NOT_MINE — different person",
                    f"VERDICT {ids[2]} UNSURE — cannot tell",
                ]
            )

        backend.brain = _stub
        result = verify_findings([report], backend)
        tally = result.tally().to_dict()
        assert tally == {"considered": 3, "mine": 1, "not_mine": 1, "unsure": 1, "unparsed": 0}
        disclaimer = result.to_dict()["disclaimer"].lower()
        assert "opinion" in disclaimer
        assert "never replace the measured confidence" in disclaimer
        assert "check the url" in disclaimer

    def test_markdown_states_the_caveat_and_the_model(self) -> None:
        result = verify_findings(
            [make_report()], StubModel("VERDICT F1-001 MINE — matches")
        )
        rendered = render_verification_markdown(result)
        assert "Identity review (local model)" in rendered
        assert "stub-1.5b-q4" in rendered
        assert "opinions" in rendered and "not evidence" in rendered


class TestVerificationIsOptIn:
    def test_a_plain_ask_never_calls_the_verifier(self, tmp_path: Path, monkeypatch,
                                                 capsys) -> None:
        """`ask` without --verify must not judge identity, whatever the model is."""
        out = tmp_path / "scans"
        assert main(["scan", "-u", "demo_user", "--demo", "-o", str(out), "-q"]) == EXIT_OK
        called = {"verify": False}
        real = __import__("d3ta1l3r.llm.verify", fromlist=["verify_findings"]).verify_findings

        def spy(*args, **kwargs):  # pragma: no cover - only runs if the bug exists
            called["verify"] = True
            return real(*args, **kwargs)

        monkeypatch.setattr("d3ta1l3r.cli.verify_findings", spy)
        capsys.readouterr()
        assert main(["ask", "what is exposed?", "-o", str(out), "--no-watchlist", "-y"]) == EXIT_OK
        assert called["verify"] is False

    def test_verify_without_a_model_refuses_instead_of_faking_a_review(
        self, tmp_path: Path, capsys
    ) -> None:
        out = tmp_path / "scans"
        assert main(["scan", "-u", "demo_user", "--demo", "-o", str(out), "-q"]) == EXIT_OK
        capsys.readouterr()
        code = main(["ask", "--verify", "-o", str(out), "--no-watchlist",
                     "--backend", "extractive"])
        captured = capsys.readouterr()
        assert code != EXIT_OK
        assert "needs a model" in captured.err
        assert "Nothing was judged" in captured.err
        assert "VERDICT" not in captured.out

    def test_verify_json_carries_the_disclaimer_and_the_measured_confidence(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        out = tmp_path / "scans"
        assert main(["scan", "-u", "demo_user", "--demo", "-o", str(out), "-q"]) == EXIT_OK
        capsys.readouterr()

        class Fake(StubModel):
            def __init__(self) -> None:
                super().__init__("")

            def generate(self, messages, *, context_text: str = ""):  # type: ignore[override]
                return "\n".join(
                    f"VERDICT {item} UNSURE — a bare 200 proves nothing"
                    for item in _ids(messages[-1]["content"])
                )

        monkeypatch.setattr(
            "d3ta1l3r.cli.select_backend", lambda **kwargs: (Fake(), [])
        )
        code = main(["ask", "--verify", "--json", "-o", str(out), "--no-watchlist", "-y"])
        assert code == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["is_model"] is True
        assert payload["verdicts"]
        assert all("measured_confidence" in row for row in payload["verdicts"])
        assert "not a detection" in payload["verdicts"][0]["note"]
        assert "disclaimer" in payload

    def test_about_file_is_read_and_used(self, tmp_path: Path, monkeypatch, capsys) -> None:
        out = tmp_path / "scans"
        assert main(["scan", "-u", "demo_user", "--demo", "-o", str(out), "-q"]) == EXIT_OK
        capsys.readouterr()
        about = tmp_path / "about.txt"
        about.write_text("I am a chess player in Delhi.\n", encoding="utf-8")
        seen: list[str] = []

        class Fake(StubModel):
            def __init__(self) -> None:
                super().__init__("")

            def generate(self, messages, *, context_text: str = ""):  # type: ignore[override]
                seen.append(messages[-1]["content"])
                return "\n".join(
                    f"VERDICT {item} UNSURE — nothing distinguishing"
                    for item in _ids(messages[-1]["content"])
                )

        monkeypatch.setattr("d3ta1l3r.cli.select_backend", lambda **kwargs: (Fake(), []))
        code = main(["ask", "--verify", "--about-file", str(about), "-o", str(out),
                     "--no-watchlist", "-y"])
        assert code == EXIT_OK
        assert seen and "chess player in Delhi" in seen[0]


# ---------------------------------------------------------------------------
def _ids(prompt: str) -> list[str]:
    """Finding ids from the prompt the verifier built."""
    return [
        line.split("]")[0].lstrip("[")
        for line in prompt.splitlines()
        if line.startswith("[")
    ]


def _answer_all(finding_id: str, verdict: str) -> str:
    return f"VERDICT {finding_id} {verdict} — stub reason"


def _first_two(prompt: str) -> tuple[str, str]:  # pragma: no cover - helper for one test
    ids = _ids(prompt)
    return ids[0], ids[1]
