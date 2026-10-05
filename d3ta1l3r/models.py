"""Typed, dependency-free data model for a scan and its results.

The model layer deliberately uses only the standard library: reports can be
produced, stored, loaded and re-rendered without httpx or the web stack.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

__all__ = [
    "EVENT_SCAN_FINISHED",
    "EVENT_SCAN_STARTED",
    "EVENT_SOURCE_FINISHED",
    "EVENT_SOURCE_STARTED",
    "Confidence",
    "Finding",
    "ScanEvent",
    "ScanReport",
    "ScanStats",
    "ScanStatus",
    "ScanTarget",
    "SourceKind",
    "SourceOutcome",
    "utcnow",
]


def utcnow() -> datetime:
    """Timezone-aware 'now' — never use naive datetimes in this codebase."""
    return datetime.now(timezone.utc)


def _text(value: Any) -> str | None:
    """Coerce API-shaped values into plain strings (``None`` stays ``None``)."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ", ".join(str(_text(item)) for item in value if item not in (None, ""))
    return str(value)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class _StrEnum(str, Enum):
    """``str``-mixin enum so values serialise straight into JSON."""

    def __str__(self) -> str:  # pragma: no cover - convenience
        return str(self.value)


class Confidence(_StrEnum):
    """How much weight a heuristic hit deserves.

    ``CONFIRMED`` — endpoint returned a structured record that *is* the account
    (authenticated-free JSON API describing the handle, e.g. GitHub users API).

    ``HIGH`` — strong, stable signal (dedicated 404 for unknown users + 200 for
    this handle, or an unambiguous "not found" body marker).

    ``MEDIUM`` — body marker matched, but the site may render the same marker for
    other states (rate limits, login walls).

    ``LOW`` — status-code-only heuristic on a site known to be noisy. Verify by
    hand before believing it.
    """

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "confirmed": 3}[self.value]


class SourceKind(_StrEnum):
    """Which identifier class a source consumes."""

    USERNAME = "username"
    EMAIL = "email"
    NAME = "name"
    DOMAIN = "domain"


class ScanStatus(_StrEnum):
    """Terminal state of a single source."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED_ROBOTS = "skipped_robots"
    SKIPPED_RATE_LIMITED = "skipped_rate_limited"
    SKIPPED_DISABLED = "skipped_disabled"
    SKIPPED_NO_INPUT = "skipped_no_input"
    BLOCKED = "blocked"

    @property
    def is_terminal_hit(self) -> bool:
        return self is ScanStatus.FOUND

    @property
    def is_skip(self) -> bool:
        return self.value.startswith("skipped")


# Web/CLI progress event names.
EVENT_SCAN_STARTED = "scan_started"
EVENT_SOURCE_STARTED = "source_started"
EVENT_SOURCE_FINISHED = "source_finished"
EVENT_SCAN_FINISHED = "scan_finished"


@dataclass(slots=True)
class ScanTarget:
    """The identifiers you supplied about *yourself*.

    At least one identifier is required. Everything the tool does is derived
    from these values — it never expands the search beyond them.
    """

    username: str | None = None
    email: str | None = None
    name: str | None = None
    domain: str | None = None
    location: str | None = None

    @classmethod
    def create(
        cls,
        *,
        username: str | None = None,
        email: str | None = None,
        name: str | None = None,
        domain: str | None = None,
        location: str | None = None,
    ) -> ScanTarget:
        """Validate and normalise identifiers (raises :class:`UsageError`)."""
        from .core.security import (
            validate_domain,
            validate_email,
            validate_location,
            validate_name,
            validate_username,
        )

        target = cls(
            username=validate_username(username) if username else None,
            email=validate_email(email) if email else None,
            name=validate_name(name) if name else None,
            domain=validate_domain(domain) if domain else None,
            location=validate_location(location) if location else None,
        )
        target.require_identifier()
        return target

    def require_identifier(self) -> None:
        from .errors import UsageError

        if not any((self.username, self.email, self.name, self.domain)):
            raise UsageError(
                "no identifier supplied: pass at least one of --username, --email, --name "
                "or --domain"
            )

    @property
    def identifiers(self) -> dict[str, str]:
        """Only the identifiers the operator actually supplied."""
        return {
            key: value
            for key, value in (
                (SourceKind.USERNAME.value, self.username),
                (SourceKind.EMAIL.value, self.email),
                (SourceKind.NAME.value, self.name),
                (SourceKind.DOMAIN.value, self.domain),
            )
            if value
        }

    def fingerprint(self) -> str:
        """Stable short id used for cache keys and log lines (no raw PII)."""
        material = json.dumps(self.identifiers, sort_keys=True).encode()
        return hashlib.sha256(material).hexdigest()[:12]

    def display(self) -> str:
        """Human label with the email partially redacted for screenshots/logs."""
        parts = []
        if self.username:
            parts.append(f"@{self.username}")
        if self.email:
            local, _, domain = self.email.partition("@")
            masked = (local[:2] + "***") if len(local) > 2 else "***"
            parts.append(f"{masked}@{domain}")
        if self.name:
            parts.append(self.name)
        if self.domain:
            parts.append(f"domain:{self.domain}")
        if self.location:
            parts.append(f"({self.location})")
        return " ".join(parts) or "<empty target>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "email": self.email,
            "name": self.name,
            "domain": self.domain,
            "location": self.location,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanTarget:
        return cls(
            username=data.get("username"),
            email=data.get("email"),
            name=data.get("name"),
            domain=data.get("domain"),
            location=data.get("location"),
        )


@dataclass(slots=True)
class Finding:
    """A single verified-by-heuristic hit on a public endpoint.

    ``evidence`` records *why* the source believes this is a hit — it is the
    field to look at when auditing the tool's own output.
    """

    source_id: str
    source_name: str
    kind: SourceKind
    url: str
    identifier: str
    confidence: Confidence = Confidence.MEDIUM
    category: str = "other"
    evidence: str = ""
    title: str | None = None
    display_name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None
    location: str | None = None
    account_created_at: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # APIs hand back ints, nested dicts and empty strings where a string is
        # expected. Normalise once here so every renderer can trust the types.
        for name in ("title", "display_name", "bio", "avatar_url", "location",
                     "account_created_at", "evidence", "url", "identifier"):
            object.__setattr__(self, name, _text(getattr(self, name)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "kind": self.kind.value,
            "url": self.url,
            "identifier": self.identifier,
            "confidence": self.confidence.value,
            "category": self.category,
            "evidence": self.evidence,
            "title": self.title,
            "display_name": self.display_name,
            "bio": self.bio,
            "avatar_url": self.avatar_url,
            "location": self.location,
            "account_created_at": self.account_created_at,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        return cls(
            source_id=data["source_id"],
            source_name=data["source_name"],
            kind=SourceKind(data["kind"]),
            url=data["url"],
            identifier=data["identifier"],
            confidence=Confidence(data.get("confidence", "medium")),
            category=data.get("category", "other"),
            evidence=data.get("evidence", ""),
            title=data.get("title"),
            display_name=data.get("display_name"),
            bio=data.get("bio"),
            avatar_url=data.get("avatar_url"),
            location=data.get("location"),
            account_created_at=data.get("account_created_at"),
            extra=dict(data.get("extra") or {}),
        )

    def dedupe_key(self) -> tuple[str, str, str]:
        """Identity of a finding for deduplication and report diffs.

        The source is part of the key on purpose: two sources can legitimately
        report the same URL (for example an API record and an HTML probe of the
        same profile), and collapsing those would hide one of them from a diff.
        """
        return (self.source_id, self.url, self.identifier)


@dataclass(slots=True)
class SourceOutcome:
    """Everything that happened for one source in one scan."""

    source_id: str
    source_name: str
    kind: SourceKind
    status: ScanStatus
    category: str = "other"
    findings: list[Finding] = field(default_factory=list)
    http_status: int | None = None
    error: str | None = None
    duration_ms: int = 0
    skipped_reason: str | None = None
    docs_url: str | None = None
    query_url: str | None = None
    attempts: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "error", _text(self.error))
        object.__setattr__(self, "skipped_reason", _text(self.skipped_reason))

    @property
    def ok(self) -> bool:
        return self.status not in (ScanStatus.ERROR, ScanStatus.TIMEOUT, ScanStatus.BLOCKED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "kind": self.kind.value,
            "category": self.category,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "http_status": self.http_status,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "skipped_reason": self.skipped_reason,
            "docs_url": self.docs_url,
            "query_url": self.query_url,
            "attempts": self.attempts,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SourceOutcome:
        return cls(
            source_id=data["source_id"],
            source_name=data["source_name"],
            kind=SourceKind(data["kind"]),
            category=data.get("category", "other"),
            status=ScanStatus(data["status"]),
            findings=[Finding.from_dict(f) for f in data.get("findings") or []],
            http_status=data.get("http_status"),
            error=data.get("error"),
            duration_ms=int(data.get("duration_ms") or 0),
            skipped_reason=data.get("skipped_reason"),
            docs_url=data.get("docs_url"),
            query_url=data.get("query_url"),
            attempts=int(data.get("attempts") or 0),
        )


@dataclass(slots=True)
class ScanStats:
    """Aggregate counters, computed from outcomes — never maintained by hand."""

    sources_total: int = 0
    sources_ok: int = 0
    sources_failed: int = 0
    sources_skipped: int = 0
    sources_hit: int = 0
    findings_total: int = 0
    hosts_contacted: int = 0
    http_requests: int = 0

    @classmethod
    def from_outcomes(cls, outcomes: Sequence[SourceOutcome], **extra: int) -> ScanStats:
        hits = [o for o in outcomes if o.status is ScanStatus.FOUND]
        return cls(
            sources_total=len(outcomes),
            sources_ok=sum(1 for o in outcomes if o.ok),
            sources_failed=sum(1 for o in outcomes if not o.ok),
            sources_skipped=sum(1 for o in outcomes if o.status.is_skip),
            sources_hit=len(hits),
            findings_total=sum(len(o.findings) for o in hits),
            **extra,
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "sources_total": self.sources_total,
            "sources_ok": self.sources_ok,
            "sources_failed": self.sources_failed,
            "sources_skipped": self.sources_skipped,
            "sources_hit": self.sources_hit,
            "findings_total": self.findings_total,
            "hosts_contacted": self.hosts_contacted,
            "http_requests": self.http_requests,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanStats:
        return cls(**{k: int(v or 0) for k, v in data.items() if k in cls.__slots__})


@dataclass(slots=True)
class ScanEvent:
    """Progress event streamed to the CLI/SSE consumers."""

    type: str
    scan_id: str
    message: str = ""
    source_id: str | None = None
    source_name: str | None = None
    status: ScanStatus | None = None
    findings_count: int = 0
    completed: int = 0
    total: int = 0
    ts: datetime = field(default_factory=utcnow)

    @property
    def percent(self) -> float:
        if not self.total:
            return 0.0
        return round(100.0 * self.completed / self.total, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "scan_id": self.scan_id,
            "message": self.message,
            "source_id": self.source_id,
            "source_name": self.source_name,
            "status": self.status.value if self.status else None,
            "findings_count": self.findings_count,
            "completed": self.completed,
            "total": self.total,
            "percent": self.percent,
            "ts": _iso(self.ts),
        }


@dataclass(slots=True)
class ScanReport:
    """The complete artefact: target, per-source outcomes, findings, warnings."""

    scan_id: str
    target: ScanTarget
    tool_version: str
    started_at: datetime
    finished_at: datetime | None = None
    outcomes: list[SourceOutcome] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    warnings: list[str] = field(default_factory=list)
    demo: bool = False
    options: dict[str, Any] = field(default_factory=dict)

    # -- construction ----------------------------------------------------
    @classmethod
    def new(cls, target: ScanTarget, tool_version: str, **options: Any) -> ScanReport:
        return cls(
            scan_id=uuid.uuid4().hex[:12],
            target=target,
            tool_version=tool_version,
            started_at=utcnow(),
            options=options,
        )

    @property
    def duration_ms(self) -> int:
        end = self.finished_at or utcnow()
        return int((end - self.started_at).total_seconds() * 1000)

    # -- derived views ---------------------------------------------------
    @property
    def findings(self) -> list[Finding]:
        """All findings, strongest confidence first, then by category."""
        found: Iterable[Finding] = (f for o in self.outcomes for f in o.findings)
        return sorted(
            found,
            key=lambda f: (-f.confidence.rank, f.category, f.source_name.lower()),
        )

    def findings_by_category(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return dict(sorted(grouped.items()))

    def outcome(self, source_id: str) -> SourceOutcome | None:
        return next((o for o in self.outcomes if o.source_id == source_id), None)

    def refresh_stats(self, **extra: int) -> ScanStats:
        self.stats = ScanStats.from_outcomes(self.outcomes, **extra)
        return self.stats

    # -- serialisation ---------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "d3ta1l3r/report/1",
            "scan_id": self.scan_id,
            "tool_version": self.tool_version,
            "demo": self.demo,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "duration_ms": self.duration_ms,
            "target": self.target.to_dict(),
            "target_display": self.target.display(),
            "stats": self.stats.to_dict(),
            "warnings": list(self.warnings),
            "options": self.options,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanReport:
        return cls(
            scan_id=data["scan_id"],
            target=ScanTarget.from_dict(data.get("target") or {}),
            tool_version=data.get("tool_version", "unknown"),
            started_at=_parse_dt(data.get("started_at")) or utcnow(),
            finished_at=_parse_dt(data.get("finished_at")),
            outcomes=[SourceOutcome.from_dict(o) for o in data.get("outcomes") or []],
            stats=ScanStats.from_dict(data.get("stats") or {}),
            warnings=list(data.get("warnings") or []),
            demo=bool(data.get("demo", False)),
            options=dict(data.get("options") or {}),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> ScanReport:
        return cls.from_dict(json.loads(raw))
