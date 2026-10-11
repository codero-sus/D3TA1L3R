"""D3TA1L3R — automated self-audit of your own public digital footprint.

D3TA1L3R queries *public* endpoints (a curated list of no-key public APIs and
public profile pages) to answer one question: **what of mine is already out
there?**

Design boundaries (enforced in :mod:`d3ta1l3r.core.security` and documented in
``docs/SCOPE.md``):

* Only unauthenticated, publicly reachable endpoints are queried.
* Only data you supplied (your handle, your email, your name) is used as input.
* The tool never touches people-search brokers, breach corpora, phone/address
  lookups, credential dumps, or any endpoint that requires bypassing a control.
* Every heuristic hit carries a confidence label, and the tool ships a
  ``calibrate`` command that measures its own false-positive rate so you never
  mistake a heuristic for a fact.

Public API::

    from d3ta1l3r import ScanConfig, ScanTarget, ScanEngine, ScanReport

    report = await ScanEngine(ScanConfig()).scan(ScanTarget.create(username="me"))
"""

from __future__ import annotations

from .config import RateLimitConfig, ScanConfig
from .errors import (
    ConfigError,
    D3ta1l3rError,
    ForbiddenTargetError,
    HttpError,
    RobotsDeniedError,
    SourceError,
    UsageError,
)
from .models import (
    Confidence,
    Finding,
    ScanEvent,
    ScanReport,
    ScanStats,
    ScanStatus,
    ScanTarget,
    SourceKind,
    SourceOutcome,
)

__version__ = "0.1.0"

#: Who this is by. Kept here so the CLI, the dashboard footer and the packaged
#: metadata cannot disagree about it; pyproject reads them at build time and
#: the web layer passes them to every template.
__author__ = "codero-sus"
__author_url__ = "https://github.com/codero-sus"
__author_website__ = "https://the-codero.web.app/"
__repository__ = "https://github.com/codero-sus/D3TA1L3R"

__all__ = [
    "Confidence",
    "ConfigError",
    "D3ta1l3rError",
    "Finding",
    "ForbiddenTargetError",
    "HttpError",
    "RateLimitConfig",
    "RobotsDeniedError",
    "ScanConfig",
    "ScanEngine",
    "ScanEvent",
    "ScanReport",
    "ScanStats",
    "ScanStatus",
    "ScanTarget",
    "SourceError",
    "SourceKind",
    "SourceOutcome",
    "UsageError",
    "__author__",
    "__author_url__",
    "__author_website__",
    "__repository__",
    "__version__",
]


def __getattr__(name: str):  # pragma: no cover - tiny lazy-import shim
    """Expose :class:`ScanEngine` without importing the whole source tree eagerly."""
    if name == "ScanEngine":
        from .core.engine import ScanEngine

        return ScanEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
