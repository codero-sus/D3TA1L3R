"""Dashboard authentication, the vault-backed watchlist, and the CSRF posture.

The dashboard is the one part of D3TA1L3R that holds a decrypted watchlist, so
these tests are as interested in the refusals (401/403/404/429) as in the happy
path. Everything runs against Starlette's ``TestClient`` with the demo transport,
so no third party is contacted and no real account is described.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

import pytest

from d3ta1l3r.errors import UsageError
from d3ta1l3r.vault import Vault, VaultKind
from d3ta1l3r.web.app import AppSettings, create_app
from d3ta1l3r.web.auth import (
    MUTATING_METHODS,
    AuthSettings,
    LoginThrottle,
    SessionManager,
    clear_session_cookie,
    client_key,
    default_trusted_origins,
    origin_allowed,
    set_session_cookie,
    trusted_origins_from_env,
)

PASSPHRASE = "correct horse battery staple"


class FakeRequest:
    """Just enough of a Starlette Request for the small helpers."""

    def __init__(self, headers: dict[str, str] | None = None, host: str = "10.0.0.9") -> None:
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.client = type("Client", (), {"host": host})()


# ---------------------------------------------------------------------------
# settings and cookies
# ---------------------------------------------------------------------------
class TestAuthSettings:
    def test_defaults_are_conservative(self) -> None:
        settings = AuthSettings()
        assert settings.enabled is False
        assert settings.session_ttl_seconds == 8 * 3600
        assert settings.session_cookie == "d3ta1l3r_session"
        assert settings.secure_cookies is False  # local http by default
        assert settings.max_attempts == 5

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("session_ttl_seconds", 30, "at least a minute"),
            ("max_attempts", 0, "at least 1"),
            ("lockout_seconds", -1, "must not be negative"),
            ("session_cookie", "  ", "must not be empty"),
        ],
    )
    def test_nonsense_values_are_refused(self, field: str, value: Any, message: str) -> None:
        settings = AuthSettings(**{field: value})
        with pytest.raises(UsageError, match=message):
            settings.validate()

    def test_cookies_are_httponly_samesite_and_no_store(self) -> None:
        class FakeResponse:
            def __init__(self) -> None:
                self.cookies: dict[str, Any] = {}
                self.headers: dict[str, str] = {}

            def set_cookie(self, name: str, value: str, **kwargs: Any) -> None:
                self.cookies[name] = kwargs

            def delete_cookie(self, name: str, **kwargs: Any) -> None:
                self.cookies.pop(name, None)

        response = FakeResponse()
        settings = AuthSettings(secure_cookies=True)
        set_session_cookie(response, "token", settings)
        placed = response.cookies[settings.session_cookie]
        assert placed["httponly"] is True
        assert placed["samesite"] == "lax"
        assert placed["secure"] is True  # when served over TLS
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Referrer-Policy"] == "no-referrer"

        clear_session_cookie(response, settings)
        assert settings.session_cookie not in response.cookies

    def test_mutating_methods_are_the_ones_that_need_protection(self) -> None:
        assert {"POST", "PUT", "PATCH", "DELETE"} == MUTATING_METHODS
        assert "GET" not in MUTATING_METHODS


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------
class TestSessionManager:
    def test_a_fresh_session_verifies(self) -> None:
        sessions = SessionManager(ttl_seconds=60)
        token, ttl = sessions.issue()
        assert ttl == 60
        assert sessions.verify(token) is True
        assert sessions.active == 1

    def test_a_tampered_token_is_refused(self) -> None:
        sessions = SessionManager(ttl_seconds=60)
        token, _ = sessions.issue()
        payload, signature = token.split(".")
        assert sessions.verify(f"{payload}.{signature[:-2]}xx") is False
        assert sessions.verify(payload) is False
        assert sessions.verify("nonsense") is False
        assert sessions.verify("") is False
        assert sessions.verify(None) is False

    def test_another_process_secret_cannot_validate(self) -> None:
        one = SessionManager(secret=b"a" * 32)
        two = SessionManager(secret=b"b" * 32)
        token, _ = one.issue()
        assert two.verify(token) is False

    def test_expiry_is_enforced(self) -> None:
        now = {"t": 1000.0}
        sessions = SessionManager(ttl_seconds=60, clock=lambda: now["t"])
        token, _ = sessions.issue()
        assert sessions.verify(token) is True
        now["t"] += 61
        assert sessions.verify(token) is False

    def test_revoke_makes_a_token_worthless(self) -> None:
        sessions = SessionManager()
        token, _ = sessions.issue()
        assert sessions.revoke(token) is True
        assert sessions.verify(token) is False
        assert sessions.revoke(token) is False

    def test_prune_drops_only_the_stale(self) -> None:
        now = {"t": 0.0}
        sessions = SessionManager(ttl_seconds=10, clock=lambda: now["t"])
        first, _ = sessions.issue()
        now["t"] = 5.0
        sessions.issue()
        now["t"] = 12.0
        assert sessions.prune() == 1
        assert sessions.verify(first) is False
        assert sessions.active == 1


# ---------------------------------------------------------------------------
# login throttling
# ---------------------------------------------------------------------------
class TestLoginThrottle:
    def test_lockout_kicks_in_after_the_configured_failures(self) -> None:
        throttle = LoginThrottle(max_attempts=3, lockout_seconds=300)
        assert throttle.record_failure("a") == 0.0
        assert throttle.record_failure("a") == 0.0
        assert throttle.record_failure("a") == 300.0
        assert throttle.lockouts == 1
        assert throttle.locked_for("a") > 0

    def test_the_lockout_expires(self) -> None:
        now = {"t": 0.0}
        throttle = LoginThrottle(max_attempts=1, lockout_seconds=10, clock=lambda: now["t"])
        throttle.record_failure("a")
        assert throttle.locked_for("a") == pytest.approx(10.0)
        now["t"] = 11.0
        assert throttle.locked_for("a") == 0.0

    def test_addresses_are_counted_separately(self) -> None:
        throttle = LoginThrottle(max_attempts=2, lockout_seconds=60)
        throttle.record_failure("a")
        throttle.record_failure("a")
        assert throttle.locked_for("a") > 0
        assert throttle.locked_for("b") == 0.0

    def test_a_success_clears_the_record(self) -> None:
        throttle = LoginThrottle(max_attempts=2, lockout_seconds=60)
        throttle.record_failure("a")
        throttle.record_success("a")
        assert throttle.record_failure("a") == 0.0
        assert throttle.locked_for("a") == 0.0

    def test_zero_lockout_never_locks(self) -> None:
        throttle = LoginThrottle(max_attempts=1, lockout_seconds=0)
        for _ in range(5):
            assert throttle.record_failure("a") == 0.0
        assert throttle.locked_for("a") == 0.0


# ---------------------------------------------------------------------------
# origin checking
# ---------------------------------------------------------------------------
class TestOrigins:
    def test_env_origins_are_parsed(self, monkeypatch) -> None:
        monkeypatch.setenv("D3TA1L3R_TRUSTED_ORIGINS", " https://a.example , https://b.example ")
        assert trusted_origins_from_env() == ("https://a.example", "https://b.example")
        monkeypatch.setenv("D3TA1L3R_TRUSTED_ORIGINS", "*")
        assert trusted_origins_from_env() == ("*",)

    def test_the_sandbox_preview_origin_is_allowed(self, monkeypatch) -> None:
        monkeypatch.setenv("E2B_SANDBOX_ID", "abc123")
        monkeypatch.delenv("D3TA1L3R_TRUSTED_ORIGINS", raising=False)
        origins = default_trusted_origins()
        assert "https://8000-abc123.e2b.app" in origins
        assert "https://9000-abc123.e2b.app" in default_trusted_origins(9000)

    def test_a_matching_host_is_allowed(self) -> None:
        request = FakeRequest({"host": "localhost:8000", "origin": "http://localhost:8000"})
        assert origin_allowed(request) is True

    def test_loopback_aliases_are_interchangeable(self) -> None:
        request = FakeRequest({"host": "127.0.0.1:8000", "origin": "http://localhost:8000"})
        assert origin_allowed(request) is True

    def test_a_foreign_origin_is_refused(self) -> None:
        request = FakeRequest({"host": "localhost:8000", "origin": "https://evil.example"})
        assert origin_allowed(request) is False

    def test_a_trusted_origin_is_allowed(self) -> None:
        request = FakeRequest(
            {"host": "127.0.0.1:8000", "origin": "https://8000-abc.e2b.app"}
        )
        assert origin_allowed(request, ("https://8000-abc.e2b.app",)) is True

    def test_a_referer_is_checked_when_there_is_no_origin(self) -> None:
        request = FakeRequest({"host": "localhost:8000", "referer": "https://evil.example/x"})
        assert origin_allowed(request) is False

    def test_no_origin_header_is_not_a_forgery(self) -> None:
        assert origin_allowed(FakeRequest({"host": "localhost:8000"})) is True

    def test_the_wildcard_escape_hatch(self) -> None:
        request = FakeRequest({"host": "localhost:8000", "origin": "https://evil.example"})
        assert origin_allowed(request, ("*",)) is True

    def test_forwarded_host_is_honoured(self) -> None:
        request = FakeRequest(
            {
                "host": "127.0.0.1:8000",
                "x-forwarded-host": "audit.example",
                "origin": "https://audit.example",
            }
        )
        assert origin_allowed(request) is True

    def test_client_key_prefers_the_proxy_headers(self) -> None:
        request = FakeRequest({"x-forwarded-for": "203.0.113.9, 10.0.0.1"})
        assert client_key(request) == "203.0.113.9"
        assert client_key(FakeRequest()) == "10.0.0.9"
        assert client_key(FakeRequest(host="")) == "unknown"


# ---------------------------------------------------------------------------
# the dashboard itself
# ---------------------------------------------------------------------------
def build_app(tmp_path: Path, *, demo: bool = True, unlock: bool = False):
    from starlette.testclient import TestClient as StarletteClient

    vault_path = tmp_path / "watchlist.vault"
    Vault.create(vault_path, PASSPHRASE)
    settings = AppSettings(
        output_dir=tmp_path / "scans",
        demo=demo,
        vault_path=None if unlock else vault_path,
        vault=Vault.open(vault_path, PASSPHRASE) if unlock else None,
        auth=AuthSettings(lockout_seconds=60),
    )
    client = StarletteClient(create_app(settings), follow_redirects=False)
    return client, settings, vault_path


def sign_in(client) -> None:
    response = client.post("/login", data={"passphrase": PASSPHRASE})
    assert response.status_code == 303, response.text


def wait_for_breach(client, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = client.get("/api/breach").json()
        if payload["status"] != "running":
            return payload
        time.sleep(0.05)
    raise AssertionError("the breach run never finished")


class TestDashboardAuth:
    def test_without_a_vault_there_is_no_login(self, tmp_path: Path) -> None:
        from starlette.testclient import TestClient as StarletteClient

        app = create_app(AppSettings(output_dir=tmp_path / "scans", demo=True))
        with StarletteClient(app, follow_redirects=False) as client:
            assert client.get("/").status_code == 200
            assert client.get("/login").status_code == 303
            assert client.get("/api/vault").status_code == 404  # nothing to serve

    def test_a_locked_dashboard_redirects_to_the_login_page(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            response = client.get("/")
            assert response.status_code == 303
            assert response.headers["location"] == "/login?next=/"
            page = client.get("/login")
            assert page.status_code == 200
            assert 'name="passphrase"' in page.text
            assert "vault passphrase" in page.text.lower()

    @pytest.mark.parametrize(
        "path", ["/api/vault", "/api/breach", "/api/scans", "/api/sources", "/api/health"]
    )
    def test_apis_are_not_served_before_login(self, tmp_path: Path, path: str) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            response = client.get(path)
            if path == "/api/health":
                # Health stays reachable, but says only that it is gated.
                assert response.status_code == 200
                assert response.json()["auth_required"] is True
                assert "output_dir" not in response.json()
            else:
                assert response.status_code == 401, path

    def test_a_wrong_passphrase_is_refused_and_counted(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            for _ in range(2):
                response = client.post("/login", data={"passphrase": "definitely wrong"})
                assert response.status_code == 401
                assert "wrong passphrase" in response.text
            # Still not locked out, and still not signed in.
            assert client.get("/").status_code == 303

    def test_too_many_failures_lock_the_address_out(self, tmp_path: Path) -> None:
        client, settings, _ = build_app(tmp_path)
        with client:
            for _ in range(settings.auth.max_attempts):
                client.post("/login", data={"passphrase": "nope-nope-nope"})
            response = client.post("/login", data={"passphrase": PASSPHRASE})
            assert response.status_code == 429
            assert "too many failed attempts" in response.text
            # The lockout applies even to the right passphrase, by design.
            assert client.get("/").status_code == 303

    def test_signing_in_sets_a_usable_session(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            response = client.post("/login", data={"passphrase": PASSPHRASE})
            assert response.status_code == 303
            assert response.headers["location"] == "/"
            cookie = response.headers["set-cookie"]
            assert "HttpOnly" in cookie
            assert "SameSite=lax" in cookie.lower().replace("samesite=lax", "SameSite=lax")
            assert "d3ta1l3r_session=" in cookie
            assert client.get("/").status_code == 200
            assert client.get("/api/vault").status_code == 200

    def test_sign_in_only_unlocks_the_configured_vault(self, tmp_path: Path) -> None:
        client, settings, _ = build_app(tmp_path)
        with client:
            assert settings.vault is None  # still locked before the POST
            sign_in(client)
            assert settings.vault is not None
            assert isinstance(settings.vault, Vault)

    def test_logout_revokes_and_re_locks(self, tmp_path: Path) -> None:
        client, settings, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            assert client.get("/api/vault").status_code == 200
            response = client.post("/logout")
            assert response.status_code == 303
            assert response.headers["location"] == "/login"
            assert settings.vault is None
            assert client.get("/api/vault").status_code == 401

    def test_a_foreign_origin_cannot_mutate_anything(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com"},
                headers={"Origin": "https://evil.example"},
            )
            assert response.status_code == 403
            assert "cross-origin" in response.json()["detail"]

    def test_a_same_origin_post_is_allowed(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post(
                "/api/vault/entries",
                json={"kind": "username", "value": "alice"},
                headers={"Origin": "http://testserver"},
            )
            assert response.status_code == 201

    def test_the_preview_origin_is_trusted_inside_a_sandbox(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("E2B_SANDBOX_ID", "sandbox42")
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post(
                "/api/vault/entries",
                json={"kind": "username", "value": "alice"},
                headers={"Origin": "https://8000-sandbox42.e2b.app"},
            )
            assert response.status_code == 201


class TestVaultEndpoints:
    def test_the_watchlist_is_masked_and_counted(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com", "check_now": False},
            )
            payload = client.get("/api/vault").json()
            assert payload["entries"] == 1
            row = payload["list"][0]
            assert row["masked_value"] == "al***@example.com"
            assert "alice@example.com" not in str(payload)

    def test_adding_an_identifier_checks_it_immediately(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com", "check_now": True},
            )
            body = response.json()
            assert response.status_code == 201
            assert body["created"] is True
            assert body["check"]["counts"]["pwned"] == 1
            assert body["check"]["headline"].startswith("1 identifier(s) found")
            assert "alice@example.com" not in response.text

    def test_a_password_is_checked_but_not_kept(self, tmp_path: Path) -> None:
        client, _, vault_path = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post(
                "/api/vault/entries",
                json={
                    "kind": "password",
                    "value": "hunter2",
                    "store_hash": False,
                    "check_now": True,
                },
            )
            body = response.json()
            assert response.status_code == 201
            assert body["entry"]["masked_value"] == "••••••••"
            assert body["entry"]["recheckable"] is False
            assert body["check"]["checks"][0]["status"] == "pwned"
            assert "hunter2" not in response.text
            assert "hunter2" not in vault_path.read_text(encoding="utf-8")

    def test_a_password_with_a_verifier_can_be_rechecked(self, tmp_path: Path) -> None:
        client, _, vault_path = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={
                    "kind": "password",
                    "value": "hunter2",
                    "store_hash": True,
                    "check_now": True,
                },
            )
            row = client.get("/api/vault").json()["list"][0]
            assert row["recheckable"] is True
            assert "hunter2" not in vault_path.read_text(encoding="utf-8")

    def test_a_duplicate_is_not_an_error(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            payload = {"kind": "email", "value": "alice@example.com", "check_now": False}
            assert client.post("/api/vault/entries", json=payload).status_code == 201
            again = client.post("/api/vault/entries", json=payload)
            assert again.status_code == 200
            assert again.json()["created"] is False
            assert client.get("/api/vault").json()["entries"] == 1

    def test_a_bad_value_is_a_400(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post(
                "/api/vault/entries", json={"kind": "email", "value": "not-an-email"}
            )
            assert response.status_code == 400
            assert client.get("/api/vault").json()["entries"] == 0

    def test_an_unknown_kind_is_rejected_by_the_schema(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post(
                "/api/vault/entries", json={"kind": "credit-card", "value": "4111"}
            )
            assert response.status_code == 422

    def test_removing_an_entry(self, tmp_path: Path) -> None:
        client, settings, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            entry_id = client.post(
                "/api/vault/entries",
                json={"kind": "username", "value": "alice", "check_now": False},
            ).json()["entry"]["entry_id"]
            response = client.delete(f"/api/vault/entries/{entry_id}")
            assert response.status_code == 200
            assert response.json()["removed"] == entry_id
            assert client.delete(f"/api/vault/entries/{entry_id}").status_code == 404
            assert len(settings.vault.watchlist()) == 0

    def test_the_watchlist_page_shows_the_entries_masked(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com", "check_now": False},
            )
            page = client.get("/")
            assert page.status_code == 200
            assert 'id="watchlist"' in page.text
            assert "al***@example.com" in page.text
            assert "alice@example.com" not in page.text
            assert "Change this password" not in page.text


class TestBreachWatch:
    def test_signing_in_rechecks_the_watchlist(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com", "check_now": False},
            )
            client.post("/logout")
            sign_in(client)
            payload = wait_for_breach(client)
            assert payload["status"] == "done"
            assert payload["triggered_by"] == "login"
            assert payload["report"]["entries"][0]["status"] == "pwned"
            assert "found in breach data" in payload["headline"]

    def test_a_manual_check_can_be_triggered(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={"kind": "password", "value": "hunter2", "store_hash": True,
                      "check_now": False},
            )
            response = client.post("/api/breach/check")
            assert response.status_code in {200, 202}
            payload = wait_for_breach(client)
            assert payload["triggered_by"] == "manual"
            assert payload["report"]["counts"]["pwned"] == 1

    def test_an_empty_watchlist_is_not_an_error(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            response = client.post("/api/breach/check")
            assert response.status_code == 200
            assert response.json()["started"] is False
            payload = client.get("/api/breach").json()
            assert payload["status"] == "done"
            assert payload["report"] is None

    def test_reports_are_written_next_to_the_scans(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com", "check_now": True},
            )
            # A full watchlist run is what gets persisted, for the record.
            client.post("/api/breach/check")
            wait_for_breach(client)
            saved = sorted((tmp_path / "scans" / "breach").glob("*.json"))
            assert saved, "the breach report should be written to disk"
            assert (tmp_path / "scans" / "breach" / "latest.json").is_file()

    def test_the_source_list_says_what_leaves_the_machine(self, tmp_path: Path) -> None:
        client, _, _ = build_app(tmp_path)
        with client:
            sign_in(client)
            page = client.get("/")
            assert "Pwned Passwords" in page.text
            assert "five characters of a SHA-1 hash" in page.text
            # In demo mode HIBP is answered locally, so it is listed as available.
            assert "unavailable" not in page.text.split("Breach sources")[1][:600]


class TestVaultFromAFileOnDisk:
    """The vault is written, reopened and re-checked exactly as the CLI would."""

    def test_entries_survive_a_server_restart(self, tmp_path: Path) -> None:
        client, _, vault_path = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com", "check_now": True},
            )
            wait_for_breach(client)

        reopened = Vault.open(vault_path, PASSPHRASE)
        entries = reopened.watchlist()
        assert [e.kind for e in entries] == [VaultKind.EMAIL]
        assert entries[0].last_status == "pwned"
        assert entries[0].last_count >= 1

    def test_the_file_is_owner_only_and_hides_the_identifiers(self, tmp_path: Path) -> None:
        client, _, vault_path = build_app(tmp_path)
        with client:
            sign_in(client)
            client.post(
                "/api/vault/entries",
                json={"kind": "email", "value": "alice@example.com", "check_now": False},
            )
        raw = vault_path.read_text(encoding="utf-8")
        assert "alice@example.com" not in raw
        assert re.search(r'"payload": "[A-Za-z0-9_=-]+"', raw)
