"""The dashboard's model catalogue: shown before anything is fetched.

The catalogue exists so that "use a bigger model" never means "run an unlabelled
blob". These tests pin the properties that make that true in the browser: the
list is served with sizes, licences and sources before any download, a fetch
needs an explicit confirmation, a second fetch is refused while one is running,
and the download itself is stubbed — no test in this suite touches the network.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from d3ta1l3r.llm import models as catalog
from d3ta1l3r.vault import Vault, VaultKind
from d3ta1l3r.web.app import AppSettings, create_app
from d3ta1l3r.web.auth import AuthSettings

PASSPHRASE = "dashboard-models-passphrase"


def _app(tmp_path: Path, *, with_vault: bool = False) -> TestClient:
    settings = AppSettings(demo=True, output_dir=tmp_path / "scans")
    if with_vault:
        vault_path = tmp_path / "watchlist.vault"
        vault = Vault.create(vault_path, PASSPHRASE)
        vault.add(VaultKind.EMAIL, "demo@example.com")
        vault.save()
        settings = AppSettings(
            demo=True,
            output_dir=tmp_path / "scans",
            vault_path=vault_path,
            auth=AuthSettings(max_attempts=3, lockout_seconds=60),
        )
    return TestClient(create_app(settings), follow_redirects=False)


def wait_for_pull(client: TestClient, *, timeout: float = 10.0) -> dict:
    """Poll the pull status until it stops being ``running`` (or time out)."""
    deadline = time.monotonic() + timeout
    state = client.get("/api/models/pull").json()
    while state["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        state = client.get("/api/models/pull").json()
    return state


class TestCatalogueEndpoint:
    def test_the_list_discloses_size_licence_and_source_before_any_download(
        self, tmp_path: Path
    ) -> None:
        body = _app(tmp_path).get("/api/models").json()
        assert body["models"], "an empty catalogue would make the panel useless"
        for model in body["models"]:
            assert model["size_mb"] > 0, model["id"]
            assert model["ram_mb"] > model["size_mb"], model["id"]
            assert model["license"], model["id"]
            assert model["repo"].count("/") == 1, model["id"]
            assert model["url"].startswith("https://"), model["id"]
            assert model["downloaded"] in (True, False)
        assert body["downloads_require_confirmation"] is True
        assert body["pull"]["status"] == "idle"

    def test_nothing_is_downloaded_just_by_listing(self, tmp_path: Path, monkeypatch) -> None:
        def explode(*args, **kwargs):  # pragma: no cover - only runs on a bug
            raise AssertionError("listing the catalogue must not fetch anything")

        monkeypatch.setattr(catalog, "download_model", explode)
        assert _app(tmp_path).get("/api/models").json()["models"]

    def test_the_catalogue_is_gated_behind_a_session(self, tmp_path: Path) -> None:
        client = _app(tmp_path, with_vault=True)
        assert client.get("/api/models").status_code == 401
        assert client.post("/api/models/pull", json={"model": "x", "confirm": True}).status_code == 401
        assert client.get("/api/models/pull").status_code == 401


class TestPullEndpoint:
    def test_a_download_without_confirmation_is_refused(self, tmp_path: Path) -> None:
        client = _app(tmp_path)
        response = client.post("/api/models/pull", json={"model": "tinyllama-1.1b-chat-q4_k_m"})
        assert response.status_code == 400
        assert "confirmation" in response.json()["detail"]
        assert client.get("/api/models/pull").json()["status"] == "idle"

    def test_an_unknown_model_is_a_404(self, tmp_path: Path) -> None:
        client = _app(tmp_path)
        response = client.post(
            "/api/models/pull", json={"model": "not-a-model", "confirm": True}
        )
        assert response.status_code == 404

    def test_a_second_download_is_refused_while_one_is_running(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client = _app(tmp_path)

        def slow_download(spec, directory, *, progress=None, force=False, **kwargs):
            # Bounded on purpose: a stub that waits for a flag can outlive the test
            # and hang interpreter shutdown when an assertion trips first.
            time.sleep(0.6)
            return Path(directory) / f"{spec.id}.gguf"

        monkeypatch.setattr(catalog, "download_model", slow_download)
        monkeypatch.setattr(catalog, "default_models_dir", lambda: tmp_path / "models")
        first_id, second_id = (spec.id for spec in catalog.CATALOG[:2])
        # `with client` keeps one event loop alive; a background download needs one
        with client:
            first = client.post(
                "/api/models/pull", json={"model": first_id, "confirm": True}
            )
            assert first.status_code == 200
            assert first.json()["accepted"] is True
            assert first.json()["url"].startswith("https://huggingface.co/")
            assert client.get("/api/models/pull").json()["status"] == "running"
            second = client.post(
                "/api/models/pull", json={"model": second_id, "confirm": True}
            )
            assert second.status_code == 409
            assert "one at a time" in second.json()["detail"]

    def test_progress_is_reported_and_a_finished_download_becomes_visible(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client = _app(tmp_path)
        directory = tmp_path / "models"

        def fake_download(spec, models_dir, *, progress=None, force=False, **kwargs):
            target = Path(models_dir) / f"{spec.id}.gguf"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"gguf")
            if progress is not None:
                progress("downloading", 512, 1024)
                progress("done", 1024, 1024)
            return target

        monkeypatch.setattr(catalog, "download_model", fake_download)
        monkeypatch.setattr(catalog, "default_models_dir", lambda: directory)
        with client:
            client.post(
                "/api/models/pull",
                json={"model": "tinyllama-1.1b-chat-q4_k_m", "confirm": True},
            )
            state = wait_for_pull(client)
            assert state["status"] == "done", state
            assert state["percent"] == 100
            assert state["path"].endswith(".gguf")
            listed = {model["id"]: model for model in client.get("/api/models").json()["models"]}
        assert listed["tinyllama-1.1b-chat-q4_k_m"]["downloaded"] is True
        assert sum(1 for model in listed.values() if model["downloaded"]) == 1

    def test_a_failed_download_is_reported_not_raised(self, tmp_path: Path, monkeypatch) -> None:
        client = _app(tmp_path)

        def failing_download(spec, models_dir, **kwargs):
            raise RuntimeError("the network went away")

        monkeypatch.setattr(catalog, "download_model", failing_download)
        monkeypatch.setattr(catalog, "default_models_dir", lambda: tmp_path / "models")
        with client:
            client.post(
                "/api/models/pull",
                json={"model": "tinyllama-1.1b-chat-q4_k_m", "confirm": True},
            )
            state = wait_for_pull(client)
        assert state["status"] == "error"
        assert "the network went away" in state["error"]

    def test_an_already_downloaded_model_is_not_fetched_again(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client = _app(tmp_path)
        directory = tmp_path / "models"
        monkeypatch.setattr(catalog, "default_models_dir", lambda: directory)
        spec = catalog.find_model("tinyllama-1.1b-chat-q4_k_m")
        assert spec is not None
        path = catalog.model_path(spec, directory)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"gguf")
        refused = client.post(
            "/api/models/pull", json={"model": spec.id, "confirm": True}
        )
        assert refused.status_code == 409
        assert "already downloaded" in refused.json()["detail"]

    def test_a_download_that_does_not_fit_the_disk_is_refused_before_it_starts(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client = _app(tmp_path)
        monkeypatch.setattr(catalog, "default_models_dir", lambda: tmp_path / "models")
        monkeypatch.setattr(
            catalog,
            "describe_disk",
            lambda directory=None: {
                "directory": str(tmp_path / "models"),
                "exists": True,
                "free_mb": 10,
                "total_mb": 20,
                "ram_mb": 4096,
            },
        )
        response = client.post(
            "/api/models/pull", json={"model": "qwen2.5-32b-instruct-q4_k_m", "confirm": True}
        )
        assert response.status_code == 409
        assert "not enough disk" in response.json()["detail"]


class TestModelsPanel:
    def test_the_panel_shows_the_licence_and_asks_before_downloading(self) -> None:
        root = Path(__file__).resolve().parent.parent
        page = (root / "d3ta1l3r" / "web" / "templates" / "index.html").read_text(
            encoding="utf-8"
        )
        script = (root / "d3ta1l3r" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        prose = " ".join(page.split())
        assert "nothing is fetched by itself" in prose
        assert "Nothing is downloaded until you press" in prose
        start = script.index("function renderModels")
        end = script.index("function wireModels")
        body = script[start:end]
        assert "window.confirm(" in body, "the size must be agreed to, not assumed"
        assert "Licence: " in body
        assert "innerHTML" not in body, "a repository name or licence is untrusted text"

    def test_the_update_path_never_polls_after_a_finished_download(self) -> None:
        """Polling must terminate: a stuck spinner would look like a stuck download."""
        root = Path(__file__).resolve().parent.parent
        script = (root / "d3ta1l3r" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        start = script.index("async function watchPull")
        end = script.index("function wireModels")
        body = script[start:end]
        for state in ("done", "error"):
            assert 'state.status === "' + state + '"' in body
        assert body.count("break;") >= 3
