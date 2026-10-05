"""Dashboard authentication: sessions, login throttling, CSRF posture.

The dashboard can hold a decrypted watchlist, so when it is opened with
``--auth`` it stops being an open local page and becomes a login-protected one.
Three mechanisms do the work, and each is deliberately boring:

**Session cookies.** The passphrase you type at the login form is *the vault
passphrase* — there is no second password to store or forget. On success the
server mints a random 256-bit session id, keeps it in memory, and hands the
browser an ``HttpOnly`` + ``SameSite=Lax`` cookie whose value is
``base64(json{sid, exp}).base64(HMAC-SHA256(...))``. The MAC key is random per
process, so restarting the server invalidates every session. Sessions expire on
their own (``--session-hours``) and are revoked on logout.

**Login throttling.** Failed attempts are counted per client address; after
``max_attempts`` the address is locked out for ``lockout_seconds``. This is what
makes an online guessing attack against a 12-character-minimum passphrase
pointless, on top of scrypt costing ~100 ms per attempt by design.

**CSRF.** ``SameSite=Lax`` already keeps the cookie off cross-site POSTs, which
is the defence that matters. On top of that, mutating requests are checked
against an origin allowlist (the ``Host`` header, ``X-Forwarded-Host``, anything
in ``D3TA1L3R_TRUSTED_ORIGINS``, and — inside an E2B-style sandbox — the preview
origin). A request whose ``Origin``/``Referer`` is some *other* site is refused
with 403.

Nothing here stores a password: :class:`~d3ta1l3r.vault.Vault.verify_passphrase`
re-derives the scrypt key and compares it in constant time against the key the
server unlocked at startup, so a failed login costs exactly as much as a
successful one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..errors import UsageError

__all__ = [
    "MUTATING_METHODS",
    "AuthSettings",
    "LoginThrottle",
    "SessionManager",
    "clear_session_cookie",
    "client_key",
    "default_trusted_origins",
    "origin_allowed",
    "set_session_cookie",
    "trusted_origins_from_env",
]

_ENV_TRUSTED_ORIGINS = "D3TA1L3R_TRUSTED_ORIGINS"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})


@dataclass(slots=True)
class AuthSettings:
    """Everything the auth layer needs, all of it non-secret."""

    enabled: bool = False
    vault_path: Path = field(default_factory=lambda: Path("vault/watchlist.vault"))
    session_ttl_seconds: int = 8 * 3600
    session_cookie: str = "d3ta1l3r_session"
    secure_cookies: bool = False
    """Set when the dashboard is served over HTTPS (or through a TLS proxy)."""
    max_attempts: int = 5
    lockout_seconds: int = 300
    trusted_origins: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.session_ttl_seconds < 60:
            raise UsageError("a session must last at least a minute")
        if self.max_attempts < 1:
            raise UsageError("max_attempts must be at least 1")
        if self.lockout_seconds < 0:
            raise UsageError("lockout_seconds must not be negative")
        if not self.session_cookie.strip():
            raise UsageError("the session cookie name must not be empty")


class SessionManager:
    """In-memory sessions behind a signed cookie."""

    def __init__(
        self,
        *,
        ttl_seconds: int = 8 * 3600,
        secret: bytes | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self.ttl_seconds = int(ttl_seconds)
        self._secret = secret or os.urandom(32)
        self._clock = clock
        self._sessions: dict[str, float] = {}
        self.issued = 0
        self.rejected = 0

    # -- issuing ---------------------------------------------------------
    def issue(self) -> tuple[str, int]:
        """Create a session. Returns ``(token, ttl_seconds)``."""
        sid = secrets.token_urlsafe(32)
        self._sessions[sid] = self._clock() + self.ttl_seconds
        self.issued += 1
        return self._encode(sid), self.ttl_seconds

    def _encode(self, sid: str) -> str:
        payload = base64.urlsafe_b64encode(
            json.dumps({"sid": sid, "exp": int(self._clock() + self.ttl_seconds)}).encode()
        ).rstrip(b"=")
        signature = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return f"{payload.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"

    # -- verifying -------------------------------------------------------
    def verify(self, token: str | None) -> bool:
        if not token:
            return False
        try:
            payload_b64, _, signature_b64 = token.partition(".")
            if not payload_b64 or not signature_b64:
                raise ValueError("malformed token")
            expected = hmac.new(
                self._secret, payload_b64.encode(), hashlib.sha256
            ).digest()
            given = _b64decode(signature_b64)
            if not hmac.compare_digest(expected, given):
                raise ValueError("bad signature")
            payload = json.loads(_b64decode(payload_b64))
            sid = str(payload["sid"])
            expiry = float(payload["exp"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self.rejected += 1
            return False

        server_expiry = self._sessions.get(sid)
        now = self._clock()
        if server_expiry is None or server_expiry <= now or expiry <= now:
            # Expired, or revoked by a restart/logout: drop it and refuse.
            self._sessions.pop(sid, None)
            self.rejected += 1
            return False
        return True

    def revoke(self, token: str | None) -> bool:
        """Log out: drop the server-side session so the cookie is worthless."""
        if not token:
            return False
        try:
            payload_b64, _, _ = token.partition(".")
            sid = str(json.loads(_b64decode(payload_b64))["sid"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return False
        return self._sessions.pop(sid, None) is not None

    def prune(self) -> int:
        now = self._clock()
        stale = [sid for sid, expiry in self._sessions.items() if expiry <= now]
        for sid in stale:
            del self._sessions[sid]
        return len(stale)

    @property
    def active(self) -> int:
        return len(self._sessions)


class LoginThrottle:
    """Per-address failure counter with a lockout window."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        lockout_seconds: int = 300,
        clock: Any = time.monotonic,
    ) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self.lockout_seconds = max(0, int(lockout_seconds))
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self.lockouts = 0

    def locked_for(self, key: str) -> float:
        """Seconds remaining on a lockout, or ``0`` when the address may try."""
        until = self._locked_until.get(key, 0.0)
        remaining = until - self._clock()
        if remaining <= 0:
            self._locked_until.pop(key, None)
            return 0.0
        return remaining

    def record_failure(self, key: str) -> float:
        """Count a failure; returns the lockout length applied (0 if none yet)."""
        now = self._clock()
        window = self._failures.setdefault(key, deque())
        window.append(now)
        while window and now - window[0] > self.lockout_seconds:
            window.popleft()
        if len(window) >= self.max_attempts and self.lockout_seconds:
            self._locked_until[key] = now + self.lockout_seconds
            window.clear()
            self.lockouts += 1
            return float(self.lockout_seconds)
        return 0.0

    def record_success(self, key: str) -> None:
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)

    def prune(self) -> None:
        now = self._clock()
        for key in list(self._failed_keys_older_than(now)):
            del self._failures[key]

    def _failed_keys_older_than(self, now: float):  # pragma: no cover - small helper
        return [
            key
            for key, window in self._failures.items()
            if not window or now - window[-1] > self.lockout_seconds
        ]


# ---------------------------------------------------------------------------
# request helpers
# ---------------------------------------------------------------------------
def client_key(request: Any) -> str:
    """Best-effort client identity for throttling: the address, not the port."""
    for header in ("cf-connecting-ip", "x-forwarded-for", "x-real-ip"):
        value = request.headers.get(header)
        if value:
            return value.split(",")[0].strip()
    client = getattr(request, "client", None)
    return getattr(client, "host", "") or "unknown"


def _hostname_of(value: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        return urlsplit(value).netloc.lower()
    return value


def trusted_origins_from_env() -> tuple[str, ...]:
    """``D3TA1L3R_TRUSTED_ORIGINS`` — comma-separated origins, or ``*`` to skip the check."""
    raw = os.environ.get(_ENV_TRUSTED_ORIGINS, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def default_trusted_origins(port: int | None = None) -> tuple[str, ...]:
    """Origins a request may legitimately carry in the usual setups.

    Includes the sandbox preview origin when ``E2B_SANDBOX_ID`` is set, because
    the preview proxy rewrites the ``Host`` header and would otherwise make every
    dashboard action look like a cross-site request.
    """
    origins = list(trusted_origins_from_env())
    sandbox = os.environ.get("E2B_SANDBOX_ID", "").strip()
    if sandbox:
        for candidate_port in ([port] if port else []) or [8000]:
            origins.append(f"https://{candidate_port}-{sandbox}.e2b.app")
    return tuple(dict.fromkeys(origins))


def origin_allowed(request: Any, trusted: tuple[str, ...] = ()) -> bool:
    """True when a mutating request's origin matches where it was sent.

    A browser always attaches ``Origin`` to a cross-site ``POST``; if that
    origin is not one of ours, the request is a forgery attempt (or a proxy
    misconfiguration we can explain). Requests with no origin header at all
    (curl, scripts, health probes) are allowed through — they cannot be CSRF.
    """
    if "*" in trusted:
        return True
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if not origin:
        return True
    candidate = _hostname_of(origin)
    if not candidate:
        return False

    allowed = {_hostname_of(request.headers.get("host", ""))}
    forwarded = request.headers.get("x-forwarded-host", "")
    if forwarded:
        allowed.add(_hostname_of(forwarded.split(",")[0]))
    allowed.update(_hostname_of(item) for item in trusted)
    allowed.discard("")
    # Loopback aliases are interchangeable: a browser on the same machine may
    # legitimately say localhost:8000 while the socket reports 127.0.0.1:8000.
    candidate_host = candidate.split(":")[0].strip("[]")
    both_loopback = candidate_host in _LOOPBACK_HOSTS and any(
        host.split(":")[0].strip("[]") in _LOOPBACK_HOSTS for host in allowed
    )
    return both_loopback or candidate in allowed


def set_session_cookie(response: Any, token: str, settings: AuthSettings) -> None:
    """Attach the session cookie: JS cannot read it, cross-site POSTs do not send it."""
    response.set_cookie(
        settings.session_cookie,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"


def clear_session_cookie(response: Any, settings: AuthSettings) -> None:
    response.delete_cookie(settings.session_cookie, path="/")
    response.headers["Cache-Control"] = "no-store"


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
