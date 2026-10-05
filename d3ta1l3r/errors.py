"""Exception hierarchy.

Every error raised by D3TA1L3R derives from :class:`D3ta1l3rError` so callers can
catch one type. Errors raised *by a source* are contained by the engine and
recorded as a ``SourceOutcome`` with ``ScanStatus.ERROR`` — a single broken site
must never abort a scan.
"""

from __future__ import annotations

__all__ = [
    "ConfigError",
    "D3ta1l3rError",
    "ForbiddenTargetError",
    "HttpError",
    "RobotsDeniedError",
    "SourceError",
    "UsageError",
]


class D3ta1l3rError(Exception):
    """Base class for all D3TA1L3R errors."""


class UsageError(D3ta1l3rError):
    """Bad input from the operator (invalid identifier, unknown source id, ...)."""


class ConfigError(D3ta1l3rError):
    """Invalid or contradictory configuration."""


class ForbiddenTargetError(UsageError):
    """A target or URL violates the tool's safety policy (SSRF / private host).

    Raised when an identifier, custom site template, or redirect would send a
    request to a private, loopback, link-local, or otherwise non-public host.
    """


class RobotsDeniedError(D3ta1l3rError):
    """robots.txt forbids fetching the requested path for our user agent."""


class HttpError(D3ta1l3rError):
    """Transport-level failure (DNS, TLS, timeout) after retries were exhausted."""

    def __init__(self, message: str, *, url: str = "", status: int | None = None) -> None:
        super().__init__(message)
        self.url = url
        self.status = status


class SourceError(D3ta1l3rError):
    """A source could not complete (parse failure, unexpected payload, ...)."""
