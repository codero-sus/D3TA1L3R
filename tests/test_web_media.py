"""The dashboard's media endpoints.

The important property is that the upload path never touches the network and
never writes the file to disk: it decodes bytes, parses them, and answers.  These
tests hold that contract, including the failure modes (bad base64, oversize
upload, a format that cannot be scrubbed).
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="web extras are optional")

from fastapi.testclient import TestClient

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.web import app as app_module
from d3ta1l3r.web.app import AppSettings, create_app
from tests.test_media import full_exif, jpeg_with, mp4_with, png_with


@pytest.fixture
def client(tmp_path):
    settings = AppSettings(
        output_dir=tmp_path / "scans",
        demo=True,
        config=ScanConfig(demo=True, strict_ssrf=False, timeout=5.0),
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


def upload(client, data: bytes, *, name: str = "photo.jpg", **extra):
    """POST a file to the media endpoint as base64 JSON."""
    body = {"name": name, "data_base64": base64.b64encode(data).decode("ascii"), **extra}
    return client.post("/api/media", json=body)


class TestFormatsEndpoint:
    """The catalogue the UI builds its file picker from."""

    def test_lists_formats_and_the_upload_cap(self, client) -> None:
        response = client.get("/api/media/formats")
        assert response.status_code == 200
        payload = response.json()
        by_name = {row["format"]: row for row in payload["formats"]}
        assert by_name["jpeg"]["extensions"] == [".jpe", ".jpeg", ".jpg"]
        assert by_name["jpeg"]["scrubbable"] is True
        assert by_name["heic"]["scrubbable"] is False
        assert payload["max_upload_bytes"] == 32 * 1024 * 1024

    def test_kind_is_reported(self, client) -> None:
        payload = client.get("/api/media/formats").json()
        kinds = {row["format"]: row["kind"] for row in payload["formats"]}
        assert kinds["mp3"] == "audio"
        assert kinds["mp4"] == "video"
        assert kinds["png"] == "image"


class TestAnalyseUpload:
    """The report must be the same one the CLI produces."""

    def test_photo_with_gps(self, client) -> None:
        response = upload(client, jpeg_with(full_exif()))
        assert response.status_code == 200
        report = response.json()["report"]
        assert report["format"] == "jpeg"
        assert report["score"] == 100
        assert report["coordinates"] is not None
        assert any(row["key"] == "GPSLatitude" for row in report["exposures"])

    def test_include_fields_false_trims_the_payload(self, client) -> None:
        response = upload(client, jpeg_with(full_exif()), include_fields=False)
        report = response.json()["report"]
        assert report["fields"] == []
        assert report["exposures"]  # the verdict survives the trim

    def test_clean_file(self, client) -> None:
        report = upload(client, png_with(), name="clean.png").json()["report"]
        assert report["score"] == 0
        assert report["verdict"] == "nothing identifying found"

    def test_unknown_bytes_are_not_called_clean(self, client) -> None:
        report = upload(client, b"not a media file", name="blob.bin").json()["report"]
        assert report["format"] == "unknown"
        assert any("not a statement that the file is clean" in note for note in report["notes"])

    def test_bad_base64_is_a_400(self, client) -> None:
        response = client.post("/api/media", json={"name": "x.jpg", "data_base64": "!!!"})
        assert response.status_code == 400
        assert "base64" in response.json()["detail"]

    def test_oversize_upload_is_a_413(self, client, monkeypatch) -> None:
        monkeypatch.setattr(app_module, "MAX_MEDIA_UPLOAD", 4)
        response = upload(client, b"\x00" * 64)
        assert response.status_code == 413

    def test_missing_payload_is_rejected(self, client) -> None:
        assert client.post("/api/media", json={"name": "x.jpg"}).status_code == 422


class TestScrubEndpoint:
    """Scrubbing returns bytes the caller can save directly."""

    def test_scrub_returns_clean_bytes(self, client) -> None:
        response = upload(client, jpeg_with(full_exif(), comment=b"home"), scrub=True)
        assert response.status_code == 200
        payload = response.json()
        assert payload["scrub"]["supported"] is True
        assert payload["scrub"]["residual_score"] == 0
        cleaned = base64.b64decode(payload["scrub"]["data_base64"])
        # Round-trip: the cleaned bytes must analyse as clean.
        second = upload(client, cleaned, name="clean.jpg").json()["report"]
        assert second["score"] == 0

    def test_unsupported_format_does_not_fail_the_request(self, client) -> None:
        payload = upload(client, mp4_with(), name="clip.mp4", scrub=True).json()
        assert payload["report"]["format"] == "mp4"
        assert payload["scrub"]["supported"] is False
        assert "ffmpeg" in payload["scrub"]["error"]

    def test_scrub_is_off_by_default(self, client) -> None:
        assert "scrub" not in upload(client, jpeg_with()).json()

    def test_scrub_output_has_no_bytes_field(self, client) -> None:
        payload = upload(client, jpeg_with(full_exif()), scrub=True).json()["scrub"]
        assert "data" not in payload
        assert payload["bytes_saved"] >= 0


class TestMediaPage:
    """The page is the human half of the feature; the API is the machine half."""

    def test_page_renders(self, client) -> None:
        response = client.get("/media")
        assert response.status_code == 200
        assert "What your files say" in response.text
        assert "/static/media.js" in response.text
        assert 'id="media-file"' in response.text

    def test_dashboard_links_to_it(self, client) -> None:
        assert 'href="/media"' in client.get("/").text

    def test_the_script_never_injects_markup(self) -> None:
        """Tag values are attacker-controlled; they must only reach textContent."""
        script = Path("d3ta1l3r/web/static/media.js").read_text(encoding="utf-8")
        # The comment in the file names innerHTML; only actual use is a problem.
        assert ".innerHTML" not in script
        assert ".insertAdjacentHTML" not in script
        assert ".outerHTML" not in script
        assert "textContent" in script
