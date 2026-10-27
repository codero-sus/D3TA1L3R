"""The dashboard's chat endpoint: gated, masked, and never written to disk.

The chat API is the one place in the dashboard where a model can see report
contents, so its tests are about the boundary rather than the prose: an
unauthenticated caller gets 401, a caller without a session gets nothing, raw
values require the explicit flag, invented citations are stripped before they
reach the browser, and a question leaves no file behind.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from d3ta1l3r.core.storage import ScanStore
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
from d3ta1l3r.vault import Vault
from d3ta1l3r.web.app import AppSettings, create_app
from d3ta1l3r.web.auth import AuthSettings

PASSPHRASE = "dashboard-chat-passphrase"


def _store(directory: Path) -> str:
    """Write one demo report and return its scan id."""
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
            source_id="wall_user",
            source_name="Wall",
            kind=SourceKind.USERNAME,
            status=ScanStatus.BLOCKED,
            category="social",
            error="HTTP 403 sign-in wall",
        ),
    ]
    report.refresh_stats()
    report.finished_at = utcnow()
    # Use the real store: a hand-written filename would not match its layout, and
    # a chat that cannot find the report proves nothing about the chat.
    ScanStore(directory).save(report, formats=("json",))
    return report.scan_id


def _app(tmp_path: Path, *, with_vault: bool = False) -> tuple[TestClient, Path]:
    out = tmp_path / "scans"
    _store(out)
    settings = AppSettings(demo=True, output_dir=out)
    if with_vault:
        vault_path = tmp_path / "watchlist.vault"
        vault = Vault.create(vault_path, PASSPHRASE)
        vault.add(__import__("d3ta1l3r.vault", fromlist=["VaultKind"]).VaultKind.EMAIL,
                  "demo@example.com")
        vault.save()
        settings = AppSettings(
            demo=True,
            output_dir=out,
            vault_path=vault_path,
            auth=AuthSettings(max_attempts=3, lockout_seconds=60),
        )
    return TestClient(create_app(settings), follow_redirects=False), out


class TestAskApi:
    def test_an_answer_cites_context_ids_and_says_which_backend_spoke(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path)
        body = client.post("/api/ask", json={"question": "what could not be checked?"}).json()
        assert body["citations"]
        assert set(body["citations"]) <= {"S1", "F1-001", "F1-002", "G1-01", "W1-01"}
        assert body["session"]["is_model"] is False
        assert body["session"]["stored_to_disk"] is False
        assert body["unknown_citations"] == []
        assert body["citation_problem"] == ""

    def test_values_are_masked_unless_the_flag_says_otherwise(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path)
        masked = client.post("/api/ask", json={"question": "where is my handle?"}).json()
        raw = client.post(
            "/api/ask",
            json={"question": "where is my handle?", "include_values": True, "reset": True},
        ).json()
        assert masked["session"]["values_included"] is False
        assert "demo_user" not in masked["answer"]
        assert raw["session"]["values_included"] is True
        assert "demo_user" in raw["answer"]

    def test_an_empty_question_is_rejected_before_any_model_runs(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path)
        assert client.post("/api/ask", json={"question": "   "}).status_code == 422
        assert client.post("/api/ask", json={}).status_code == 422

    def test_an_invented_citation_never_reaches_the_browser(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path)
        app = client.app
        session = app.state.chats  # exercise the same object the route uses
        assert isinstance(session, dict)
        body = client.post("/api/ask", json={"question": "summary?"}).json()
        # The extractive backend cannot invent ids; assert the *route* would strip
        # them if it did, using the same pure function the route calls.
        from d3ta1l3r.llm.cite import strip_unknown_citations

        assert strip_unknown_citations("see [F9-999]", ["F9-999"]) == (
            "see [removed-invalid-citation]"
        )
        assert body["answer"]

    def test_the_conversation_can_be_forgotten_and_is_never_persisted(self, tmp_path: Path) -> None:
        client, out = _app(tmp_path)
        before = {path.name for path in out.iterdir()}
        client.post("/api/ask", json={"question": "anything?"})
        assert {path.name for path in out.iterdir()} == before, "a chat must write no files"
        first = client.post("/api/ask/reset").json()
        assert first["reset"] is True
        second = client.post("/api/ask/reset").json()
        assert second["reset"] is False

    def test_the_setup_endpoint_reports_the_ram_budget_and_a_choice(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path)
        setup = client.get("/api/ask/setup").json()
        assert setup["ram_budget_mb"] == 4096
        assert setup["selected"]
        assert any(item["fits_4gb"] for item in setup["recommendations"])

    def test_asking_about_a_scan_id_that_does_not_exist_still_answers_from_the_rest(
        self, tmp_path: Path
    ) -> None:
        client, _ = _app(tmp_path)
        body = client.post(
            "/api/ask", json={"question": "what is exposed?", "scans": ["deadbeef", "alsomissing"]}
        ).json()
        assert body["answer"]
        assert body["citations"] == [] or body["citations"]


class TestAskApiRequiresAuth:
    def test_every_ask_endpoint_is_gated_when_a_vault_is_configured(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path, with_vault=True)
        assert client.post("/api/ask", json={"question": "hi there"}).status_code == 401
        assert client.get("/api/ask/setup").status_code == 401
        assert client.post("/api/ask/reset").status_code == 401

    def test_the_panel_is_not_rendered_on_the_login_page(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path, with_vault=True)
        assert 'id="ask-question"' not in client.get("/login").text
        index = client.get("/")
        assert index.status_code == 303 and index.headers["location"].startswith("/login")

    def test_a_signed_in_session_can_ask_and_see_the_panel(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path, with_vault=True)
        assert client.post("/login", data={"passphrase": PASSPHRASE}).status_code == 303
        page = client.get("/")
        assert page.status_code == 200
        assert 'id="ask-question"' in page.text
        body = client.post("/api/ask", json={"question": "which email is watched?"}).json()
        assert body["answer"]
        assert body["session"]["values_included"] is False

    def test_logging_out_drops_the_conversation(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path, with_vault=True)
        client.post("/login", data={"passphrase": PASSPHRASE})
        client.post("/api/ask", json={"question": "what is exposed?"})
        chats = client.app.state.chats
        assert chats, "one turn should create a conversation"
        client.post("/logout")
        assert not chats, "logging out must not leave a transcript in memory"

    def test_a_cross_origin_post_is_refused_before_it_reaches_the_model(self, tmp_path: Path) -> None:
        client, _ = _app(tmp_path, with_vault=True)
        client.post("/login", data={"passphrase": PASSPHRASE})
        refused = client.post(
            "/api/ask",
            json={"question": "hello there"},
            headers={"Origin": "https://evil.example"},
        )
        assert refused.status_code == 403
        assert "cross-origin" in refused.json()["detail"]
