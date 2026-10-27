"""The dashboard's identity review: a button someone has to press.

The rule the user stated — verification runs *only if the user selects verify* —
is a UI rule as much as a server one, so both halves are pinned here: the panel
ships a disabled button behind an explicit checkbox, and the endpoint refuses to
judge anything without a local model rather than returning a page of "cannot
tell" that would read like a completed review.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from d3ta1l3r.core.storage import ScanStore
from d3ta1l3r.llm import ExtractiveBackend
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
from d3ta1l3r.vault import Vault, VaultKind
from d3ta1l3r.web.app import AppSettings, create_app
from d3ta1l3r.web.auth import AuthSettings

PASSPHRASE = "dashboard-verify-passphrase"
WEB_JS = Path(__file__).resolve().parent.parent / "d3ta1l3r" / "web" / "static" / "app.js"
INDEX = Path(__file__).resolve().parent.parent / "d3ta1l3r" / "web" / "templates" / "index.html"


class FakeModel(ExtractiveBackend):
    """A model in the required shape; records what it was shown."""

    is_model = True
    name = "fake"

    def __init__(self, verdict: str = "UNSURE") -> None:
        super().__init__()
        self.verdict = verdict
        self.prompts: list[str] = []

    @property
    def model_id(self) -> str:
        return "fake-1.5b-q4"

    def generate(self, messages, *, context_text: str = ""):  # type: ignore[override]
        prompt = messages[-1]["content"]
        self.prompts.append(prompt)
        return "\n".join(
            f"VERDICT {line.split(']')[0].lstrip('[')} {self.verdict} — stub reason"
            for line in prompt.splitlines()
            if line.startswith("[")
        )


def _store(directory: Path) -> str:
    target = ScanTarget(username="demo_user", email="demo@example.com")
    report = ScanReport.new(target, "0.1.0", demo=True)
    report.demo = True
    report.outcomes = [
        SourceOutcome(
            source_id="github_api_user",
            source_name="GitHub user",
            kind=SourceKind.USERNAME,
            status=ScanStatus.FOUND,
            category="developer",
            findings=[
                Finding(
                    source_id="github_api_user",
                    source_name="GitHub user",
                    kind=SourceKind.USERNAME,
                    url="https://github.com/demo_user",
                    identifier="demo_user",
                    confidence=Confidence.CONFIRMED,
                    category="developer",
                    evidence="login demo_user matches the API record",
                )
            ],
        ),
        SourceOutcome(
            source_id="probe_site",
            source_name="Probe site",
            kind=SourceKind.USERNAME,
            status=ScanStatus.FOUND,
            category="social",
            findings=[
                Finding(
                    source_id="probe_site",
                    source_name="Probe site",
                    kind=SourceKind.USERNAME,
                    url="https://probe.example/demo_user",
                    identifier="demo_user",
                    confidence=Confidence.LOW,
                    category="social",
                    evidence="HTTP 200 and no not-found phrase",
                )
            ],
        ),
    ]
    report.refresh_stats()
    report.finished_at = utcnow()
    ScanStore(directory).save(report, formats=("json",))
    return report.scan_id


def _app(tmp_path: Path, *, with_vault: bool = False) -> tuple[TestClient, Path]:
    out = tmp_path / "scans"
    _store(out)
    settings = AppSettings(demo=True, output_dir=out)
    if with_vault:
        vault_path = tmp_path / "watchlist.vault"
        vault = Vault.create(vault_path, PASSPHRASE)
        vault.add(VaultKind.EMAIL, "demo@example.com")
        vault.save()
        settings = AppSettings(
            demo=True,
            output_dir=out,
            vault_path=vault_path,
            auth=AuthSettings(max_attempts=3, lockout_seconds=60),
        )
    return TestClient(create_app(settings), follow_redirects=False), out


def _with_fake_model(monkeypatch, model: FakeModel) -> None:
    monkeypatch.setattr(
        "d3ta1l3r.web.app.select_backend", lambda **kwargs: (model, ["stub backend"])
    )


class TestVerifyApi:
    def test_without_a_model_it_refuses_instead_of_faking_a_review(
        self, tmp_path: Path
    ) -> None:
        client, _ = _app(tmp_path)
        response = client.post("/api/verify", json={})
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert "needs a local model" in detail
        assert "nothing was judged" in detail
        assert "verdicts" not in response.text

    def test_a_run_carries_the_model_the_verdicts_and_the_caveat(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client, _ = _app(tmp_path)
        _with_fake_model(monkeypatch, FakeModel("NOT_MINE"))
        body = client.post("/api/verify", json={"facts": "my bios mention chess"}).json()
        assert body["is_model"] is True
        assert body["model"] == "fake-1.5b-q4"
        assert body["about"] == "my bios mention chess"
        assert body["stored_to_disk"] is False
        assert body["tally"]["considered"] == len(body["verdicts"]) == 2
        assert body["tally"]["not_mine"] == 2
        assert "opinion" in body["disclaimer"].lower()
        for verdict in body["verdicts"]:
            assert verdict["measured_confidence"], "the measurement must travel with the verdict"
            assert verdict["reason"] == "stub reason"
            assert verdict["verdict"] == "not_mine"
        # the strong finding's disagreement is surfaced, not hidden
        assert body["verdicts"][0]["overrides_evidence"] is True

    def test_only_uncertain_skips_what_the_scan_already_settled(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client, _ = _app(tmp_path)
        _with_fake_model(monkeypatch, FakeModel("MINE"))
        body = client.post("/api/verify", json={"only_uncertain": True}).json()
        assert body["verdicts"]
        assert {v["measured_confidence"] for v in body["verdicts"]} == {"low"}

    def test_the_verify_limit_caps_the_batch(self, tmp_path: Path, monkeypatch) -> None:
        client, _ = _app(tmp_path)
        _with_fake_model(monkeypatch, FakeModel("UNSURE"))
        body = client.post("/api/verify", json={"verify_limit": 1}).json()
        assert len(body["verdicts"]) == 1

    def test_raw_identifiers_reach_the_prompt_only_when_asked(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client, _ = _app(tmp_path)
        masked = FakeModel("UNSURE")
        _with_fake_model(monkeypatch, masked)
        client.post("/api/verify", json={})
        assert "demo@example.com" not in masked.prompts[0]

        raw = FakeModel("UNSURE")
        _with_fake_model(monkeypatch, raw)
        body = client.post("/api/verify", json={"include_values": True}).json()
        assert "demo@example.com" in raw.prompts[0]
        assert body["values_included"] is True

    def test_nothing_is_written_to_disk_by_a_review(self, tmp_path: Path, monkeypatch) -> None:
        client, out = _app(tmp_path)
        _with_fake_model(monkeypatch, FakeModel("UNSURE"))
        before = {path.name for path in out.iterdir()}
        client.post("/api/verify", json={})
        assert {path.name for path in out.iterdir()} == before

    def test_a_cross_origin_post_never_reaches_the_verifier(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client, _ = _app(tmp_path, with_vault=True)
        client.post("/login", data={"passphrase": PASSPHRASE})
        model = FakeModel("MINE")
        _with_fake_model(monkeypatch, model)
        refused = client.post(
            "/api/verify", json={}, headers={"Origin": "https://evil.example"}
        )
        assert refused.status_code == 403
        assert model.prompts == [], "a refused request must not have judged anything"


class TestVerifyPanel:
    def test_the_button_is_disabled_until_the_operator_opts_in(self, tmp_path: Path) -> None:
        """The user's rule is "only if the user selects verify" — so: a checkbox first."""
        client, _ = _app(tmp_path)
        page = client.get("/").text
        assert 'id="verify-enabled"' in page
        assert 'id="verify-submit" type="button" disabled' in page
        # compare on collapsed whitespace: the template wraps its prose
        prose = " ".join(page.split())
        assert "never runs on its own" in prose
        script = WEB_JS.read_text(encoding="utf-8")
        assert "button.disabled = !enabled" in script
        assert 'status.textContent = "tick the box first' in script

    def test_the_panel_renders_verdicts_as_text_never_as_html(self, tmp_path: Path) -> None:
        """A model's reason string is untrusted input in a browser."""
        script = WEB_JS.read_text(encoding="utf-8")
        start = script.index("function renderVerification")
        end = script.index("function syncVerifyButton")
        body = script[start:end]
        assert "innerHTML" not in body
        assert "textContent" in body
        assert 'rel = "noopener noreferrer nofollow"' in body

    def test_the_endpoint_is_gated_and_the_panel_is_hidden_while_signed_out(
        self, tmp_path: Path
    ) -> None:
        client, _ = _app(tmp_path, with_vault=True)
        assert client.post("/api/verify", json={}).status_code == 401
        assert 'id="verify-submit"' not in client.get("/login").text
        redirect = client.get("/")
        assert redirect.status_code == 303 and redirect.headers["location"].startswith("/login")
        client.post("/login", data={"passphrase": PASSPHRASE})
        assert 'id="verify-submit"' in client.get("/").text

    def test_the_docs_the_panel_quotes_match_the_shipped_rules(self) -> None:
        page = INDEX.read_text(encoding="utf-8")
        assert "not proof of ownership" in page
        assert "cannot raise it" in page
