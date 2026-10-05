"""Dashboard endpoints, exercised through Starlette's TestClient in demo mode.

Demo mode is used deliberately: it proves the web layer works end-to-end without
a single outbound request, which is also how the tool is demoed.
"""

from __future__ import annotations

import json
import time

import pytest

pytest.importorskip("fastapi", reason="web extras are optional")

from fastapi.testclient import TestClient

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.storage import ScanStore
from d3ta1l3r.web.app import AppSettings, create_app


@pytest.fixture
def client(tmp_path):
    settings = AppSettings(
        output_dir=tmp_path / "scans",
        demo=True,
        config=ScanConfig(demo=True, strict_ssrf=False, timeout=5.0),
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        test_client.app_settings = settings
        yield test_client


def run_demo_scan(client, payload: dict | None = None, *, timeout: float = 25.0) -> tuple[str, str]:
    body = {"username": "cooluser", "demo": True, **(payload or {})}
    response = client.post("/api/scans", json=body)
    assert response.status_code == 202, response.text
    run_id = response.json()["run_id"]

    deadline = time.time() + timeout
    scan_id = None
    while time.time() < deadline:
        state = client.get(f"/api/scans/{run_id}").json()
        if state.get("scan_ids"):
            scan_id = state["scan_ids"][-1]
        if state["status"] in {"done", "error"}:
            break
        time.sleep(0.2)
    assert state["status"] == "done", state
    assert scan_id, "no report was stored"
    return run_id, scan_id


class TestPages:
    def test_dashboard_renders(self, client) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "What of yours is already public?" in response.text
        assert "Demo mode is on" in response.text

    def test_coverage_page_lists_sources(self, client) -> None:
        response = client.get("/sources")
        assert response.status_code == 200
        assert "github_api_user" in response.text
        assert "Calibrating signatures" in response.text

    def test_static_assets_are_served(self, client) -> None:
        css = client.get("/static/styles.css")
        js = client.get("/static/app.js")
        assert css.status_code == 200 and "--accent" in css.text
        assert js.status_code == 200 and "watchRun" in js.text

    def test_frontend_uses_relative_urls(self, client) -> None:
        """The dashboard must work behind a proxy — no absolute localhost calls."""
        js = client.get("/static/app.js").text
        assert "localhost" not in js and "127.0.0.1" not in js
        assert 'fetch("/api/scans"' in js


class TestHealthAndInventory:
    def test_health_reports_effective_settings(self, client) -> None:
        payload = client.get("/api/health").json()
        assert payload["status"] == "ok"
        assert payload["demo_default"] is True
        assert payload["respect_robots"] is True
        assert payload["version"]

    def test_sources_endpoint(self, client) -> None:
        payload = client.get("/api/sources").json()
        assert payload["count"] >= 40
        kinds = {row["kind"] for row in payload["sources"]}
        assert {"username", "email", "name", "domain"} <= kinds


class TestScanFlow:
    def test_post_scan_runs_and_stores_a_report(self, client) -> None:
        run_id, scan_id = run_demo_scan(client, {"email": "cool@example.org"})
        assert run_id.startswith("run_")

        report = client.get(f"/api/scans/{scan_id}").json()
        assert report["demo"] is True
        assert report["stats"]["findings_total"] > 0
        assert report["target"]["username"] == "cooluser"

        page = client.get(f"/scans/{scan_id}")
        assert page.status_code == 200
        assert "Coverage" in page.text
        assert "badge confirmed" in page.text

    def test_live_run_page_renders_before_results_exist(self, client) -> None:
        response = client.post("/api/scans", json={"username": "cooluser", "demo": True})
        run_id = response.json()["run_id"]
        page = client.get(f"/scans/{run_id}")
        assert page.status_code == 200
        assert "Scan in progress" in page.text
        assert "watchRun" in page.text

    def test_events_stream_replays_progress(self, client) -> None:
        run_id, _ = run_demo_scan(client)
        with client.stream("GET", f"/api/scans/{run_id}/events") as stream:
            assert stream.status_code == 200
            assert stream.headers["content-type"].startswith("text/event-stream")
            chunks = []
            for line in stream.iter_lines():
                if line.startswith("data: "):
                    chunks.append(json.loads(line[6:]))
                if len(chunks) > 3:
                    break
        assert chunks[0]["type"] in {"run_started", "scan_started"}

    def test_exports_are_offered_in_three_formats(self, client) -> None:
        _, scan_id = run_demo_scan(client)
        assert client.get(f"/api/scans/{scan_id}/report.json").json()["scan_id"] == scan_id
        assert "D3TA1L3R self-audit" in client.get(f"/api/scans/{scan_id}/report.md").text
        html = client.get(f"/api/scans/{scan_id}/report.html")
        assert html.status_code == 200 and html.text.startswith("<!doctype html>")
        assert client.get(f"/api/scans/{scan_id}/report.pdf").status_code == 400

    def test_stored_scan_appears_in_the_listing(self, client) -> None:
        _, scan_id = run_demo_scan(client)
        payload = client.get("/api/scans").json()
        assert any(row["scan_id"] == scan_id for row in payload["stored"])
        assert scan_id in client.get("/").text


class TestValidationAndErrors:
    @pytest.mark.parametrize("payload", [
        {},
        {"username": "bad handle"},
        {"username": "-nope"},
        {"email": "not-an-email"},
        {"domain": "localhost"},
    ])
    def test_invalid_input_is_rejected_with_400(self, client, payload) -> None:
        response = client.post("/api/scans", json={**payload, "demo": True})
        assert response.status_code == 400
        assert response.json()["detail"]

    def test_unknown_scan_is_404(self, client) -> None:
        assert client.get("/api/scans/nope").status_code == 404
        assert client.get("/scans/nope").status_code == 404
        assert client.get("/api/scans/nope/events").status_code == 404

    def test_delete_removes_files_and_state(self, client) -> None:
        _, scan_id = run_demo_scan(client)
        response = client.delete(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        assert response.json()["deleted_files"] >= 1
        assert client.get(f"/api/scans/{scan_id}").status_code == 404
        assert client.delete(f"/api/scans/{scan_id}").status_code == 404

    def test_excessive_identifier_expansion_is_refused(self, client) -> None:
        payload = {
            "username": ",".join(f"user{i}" for i in range(10)),
            "email": "x@example.com",
            "demo": True,
        }
        response = client.post("/api/scans", json=payload)
        assert response.status_code == 400
        assert "expand" in response.json()["detail"]


class TestConfiguration:
    def test_per_scan_overrides_are_applied(self, client) -> None:
        response = client.post("/api/scans", json={
            "username": "cooluser",
            "demo": True,
            "sources": ["github_api_user"],
            "max_sites": 5,
            "concurrency": 2,
            "respect_robots": False,
        })
        run_id = response.json()["run_id"]
        deadline = time.time() + 20
        while time.time() < deadline:
            state = client.get(f"/api/scans/{run_id}").json()
            if state["status"] in {"done", "error"}:
                break
            time.sleep(0.2)
        assert state["status"] == "done", state
        scan_id = state["scan_ids"][-1]
        report = client.get(f"/api/scans/{scan_id}").json()
        assert report["options"]["sources"] == ["github_api_user"]
        assert report["options"]["respect_robots"] is False
        assert report["options"]["concurrency"] == 2
        assert any("robots.txt enforcement was disabled" in w for w in report["warnings"])

    def test_reports_land_in_the_configured_directory(self, client) -> None:
        run_demo_scan(client)
        store = ScanStore(client.app_settings.output_dir)
        assert store.list(), "expected at least one stored report"


class TestCalibrationEndpoint:
    def test_calibration_detects_false_positives(self, client) -> None:
        response = client.post("/api/calibrate", json={"absent_samples": 1})
        assert response.status_code == 200
        payload = response.json()
        assert payload["sites"]
        noisy = [
            row for row in payload["sites"]
            if row["counts"]["false_positive"] and row["id"] == "codepen_user"
        ]
        # Demo fixtures claim hits for the fixed 'present' site list, so a bogus
        # handle landing on one of those must be reported as a false positive.
        assert noisy, "a demo site that reports hits for bogus handles must be flagged"
        assert payload["false_positive_sites"]

    def test_calibration_rejects_unknown_site_ids(self, client) -> None:
        response = client.post("/api/calibrate", json={"sites": ["not_a_site"]})
        assert response.status_code == 400
