"""Scan configuration: timeouts, politeness limits, caching, source selection.

Defaults are deliberately *polite*: a fresh host is contacted at two requests
per second with a small burst, robots.txt is honoured, retries are capped, and
the whole scan is bounded by a concurrency limiter. An OSINT tool that hammers
public infrastructure is both rude and a good way to get your IP banned.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, ClassVar

from .core.browser import BrowserProfile, resolve_profile
from .errors import ConfigError

__all__ = ["DEFAULT_USER_AGENT", "RateLimitConfig", "ScanConfig"]

_CONTACT_ENV = "D3TA1L3R_UA_EMAIL"


def DEFAULT_USER_AGENT(version: str = "0.1.0") -> str:
    """Identify the tool honestly; add a contact address if the operator sets one.

    Polite crawlers advertise who they are and how to complain. Set
    ``D3TA1L3R_UA_EMAIL=you@example.com`` and the address is embedded in the
    User-Agent of every request.
    """
    contact = os.environ.get(_CONTACT_ENV, "").strip()
    suffix = f"; contact: {contact}" if contact else ""
    return f"D3TA1L3R/{version} (self-audit scanner{suffix})"


@dataclass(slots=True)
class RateLimitConfig:
    """Politeness envelope applied per host *and* globally."""

    per_host_rps: float = 2.0
    """Steady-state requests per second for a single hostname."""

    per_host_burst: int = 4
    """Burst capacity of a host's token bucket."""

    global_concurrency: int = 16
    """Maximum in-flight sources across all hosts."""

    max_retries: int = 2
    """Retries after the first attempt (0 disables retrying)."""

    backoff_base: float = 0.5
    """Exponential backoff base in seconds (attempt n sleeps base * 2**(n-1))."""

    backoff_max: float = 8.0
    """Upper bound for a single backoff sleep."""

    honor_retry_after: bool = True
    """Respect ``Retry-After`` on 429/503 responses."""

    def validate(self) -> None:
        if self.per_host_rps <= 0:
            raise ConfigError("rate.per_host_rps must be > 0")
        if self.per_host_burst < 1:
            raise ConfigError("rate.per_host_burst must be >= 1")
        if self.global_concurrency < 1:
            raise ConfigError("rate.global_concurrency must be >= 1")
        if self.max_retries < 0:
            raise ConfigError("rate.max_retries must be >= 0")
        if self.backoff_base < 0 or self.backoff_max < 0:
            raise ConfigError("rate backoff values must be >= 0")


@dataclass(slots=True)
class ScanConfig:
    """Everything the engine needs to know about *how* to scan."""

    # -- transport -------------------------------------------------------
    timeout: float = 10.0
    connect_timeout: float = 5.0
    follow_redirects: bool = True
    max_redirects: int = 4
    verify_tls: bool = True
    max_body_bytes: int = 262_144
    """Hard cap on how much of a response body is read (256 KiB default)."""

    user_agent: str = field(default_factory=DEFAULT_USER_AGENT)

    browser_profile: str = "off"
    """Send browser-shaped navigation headers (``chrome``/``firefox``/``safari``/
    ``edge``), or ``off`` for the tool's own User-Agent.

    Off by default: the tool identifying itself is the honest baseline, and a
    scan that changes its story should be a deliberate choice. See
    :mod:`d3ta1l3r.core.browser` for what this does and does not do — it is not
    a fingerprint forge, it rotates nothing, and robots.txt and the rate limiter
    apply exactly the same either way.
    """

    contact_email: str = field(default_factory=lambda: os.environ.get(_CONTACT_ENV, "").strip())
    """Ride-along contact address, sent as ``From:`` when a browser profile hides
    the tool's own User-Agent. Empty unless ``D3TA1L3R_UA_EMAIL`` is set."""

    # -- politeness ------------------------------------------------------
    rate: RateLimitConfig = field(default_factory=RateLimitConfig)
    respect_robots: bool = True
    robots_fail_open: bool = False
    """On a robots.txt fetch error: RFC 9309 says treat 5xx as "disallow all".

    ``True`` opts into the friendlier, less compliant behaviour of scanning
    anyway when robots.txt is unreachable.
    """

    robots_cache_ttl: float = 3600.0
    respect_crawl_delay: bool = True
    crawl_delay_cap: float = 10.0

    # -- safety ----------------------------------------------------------
    strict_ssrf: bool = True
    """Reject URLs that resolve to private/loopback/link-local addresses."""

    max_sites: int | None = None
    """Optional cap on how many username-probe sites run (useful for smoke tests)."""

    # -- caching ---------------------------------------------------------
    cache_dir: Path | None = None
    cache_ttl: float = 86_400.0
    use_cache: bool = False

    # -- source selection ------------------------------------------------
    enabled_sources: frozenset[str] = frozenset()
    disabled_sources: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    kinds: frozenset[str] = frozenset()

    # -- misc ------------------------------------------------------------
    demo: bool = False
    log_evidence: bool = True
    """Record the reason each source believes it has a hit."""

    SUPPORTED_KINDS: ClassVar[frozenset[str]] = frozenset(
        {"username", "email", "name", "domain"}
    )

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.timeout <= 0 or self.connect_timeout <= 0:
            raise ConfigError("timeouts must be > 0")
        if self.connect_timeout > self.timeout * 4:
            raise ConfigError("connect_timeout looks nonsensical relative to timeout")
        if self.max_body_bytes < 1024:
            raise ConfigError("max_body_bytes must be >= 1024")
        if self.max_redirects < 0:
            raise ConfigError("max_redirects must be >= 0")
        if not self.user_agent.strip():
            raise ConfigError("user_agent must not be empty")
        resolve_profile(self.browser_profile)  # raises ConfigError on an unknown name
        if self.contact_email and "@" not in self.contact_email:
            raise ConfigError("contact_email must look like an address")
        if self.max_sites is not None and self.max_sites < 1:
            raise ConfigError("max_sites must be >= 1 when set")
        if self.cache_ttl < 0:
            raise ConfigError("cache_ttl must be >= 0")
        bad_kinds = self.kinds - self.SUPPORTED_KINDS
        if bad_kinds:
            raise ConfigError(f"unknown kind(s): {', '.join(sorted(bad_kinds))}")
        if self.enabled_sources and self.disabled_sources:
            overlap = self.enabled_sources & self.disabled_sources
            if overlap:
                raise ConfigError(
                    f"source(s) both enabled and disabled: {', '.join(sorted(overlap))}"
                )
        self.rate.validate()

    # -- helpers ---------------------------------------------------------
    @property
    def profile(self) -> BrowserProfile | None:
        """The resolved browser profile, or ``None`` when the tool introduces itself."""
        return resolve_profile(self.browser_profile)

    def replaced(self, **changes: Any) -> ScanConfig:
        """Return a copy with overrides applied and re-validated."""
        return replace(self, **changes)

    def source_enabled(self, source_id: str, kind: str, category: str = "") -> bool:
        """Apply the enable/disable/category/kind filters for one source."""
        if self.enabled_sources:
            return source_id in self.enabled_sources
        if source_id in self.disabled_sources:
            return False
        if self.categories and category not in self.categories:
            return False
        return not (self.kinds and kind not in self.kinds)

    @classmethod
    def from_env(cls, **overrides: Any) -> ScanConfig:
        """Build a config from environment variables, then explicit overrides.

        Recognised variables: ``D3TA1L3R_TIMEOUT``, ``D3TA1L3R_CONCURRENCY``,
        ``D3TA1L3R_RPS``, ``D3TA1L3R_CACHE_DIR``, ``D3TA1L3R_ROBOTS`` (0/1),
        ``D3TA1L3R_UA_EMAIL`` (the contact address, in the User-Agent and as
        ``From:``), ``D3TA1L3R_BROWSER`` (a browser profile name, or ``off``).
        """
        rate = RateLimitConfig()
        if (raw := os.environ.get("D3TA1L3R_CONCURRENCY")) is not None:
            rate.global_concurrency = _int(raw, "D3TA1L3R_CONCURRENCY")
        if (raw := os.environ.get("D3TA1L3R_RPS")) is not None:
            rate.per_host_rps = _float(raw, "D3TA1L3R_RPS")

        values: dict[str, Any] = {"rate": rate}
        if (raw := os.environ.get("D3TA1L3R_TIMEOUT")) is not None:
            values["timeout"] = _float(raw, "D3TA1L3R_TIMEOUT")
        if (raw := os.environ.get("D3TA1L3R_CACHE_DIR")) is not None:
            values["cache_dir"] = Path(raw).expanduser()
            values["use_cache"] = True
        if (raw := os.environ.get("D3TA1L3R_ROBOTS")) is not None:
            values["respect_robots"] = raw.strip().lower() not in {"0", "false", "no", "off"}
        if (raw := os.environ.get("D3TA1L3R_BROWSER")) is not None:
            values["browser_profile"] = raw.strip() or "off"
        values.update(overrides)
        return cls(**values)


def _int(raw: str, name: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:  # pragma: no cover - trivial
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _float(raw: str, name: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:  # pragma: no cover - trivial
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
