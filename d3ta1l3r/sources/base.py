"""Source base class and the classification helpers every source shares.

Contract for a source:

1. It answers exactly one question about exactly one identifier class
   (:class:`SourceKind`) — username, email, name or domain.
2. It never invents identifiers. If the operator did not supply the identifier
   class it needs, it reports ``skipped_no_input``.
3. It returns :class:`~d3ta1l3r.models.SourceOutcome` and lets exceptions fly —
   :meth:`BaseSource.execute` contains them and turns them into statuses, so one
   broken site can never abort a scan.
4. Every hit is explainable: it carries ``evidence`` (why the answer is yes) and
   a :class:`~d3ta1l3r.models.Confidence` level. A heuristic must never be
   presented with the same authority as an API record.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from ..errors import ForbiddenTargetError, HttpError, RobotsDeniedError, SourceError
from ..models import (
    Confidence,
    Finding,
    ScanStatus,
    ScanTarget,
    SourceKind,
    SourceOutcome,
)

if TYPE_CHECKING:  # pragma: no cover
    from ..core.http import Fetcher, HttpResponse

__all__ = ["BaseSource", "SourceMeta", "classify_status"]


@dataclass(frozen=True, slots=True)
class SourceMeta:
    """Static description of a source (shown in ``d3ta1l3r sources``)."""

    id: str
    name: str
    kind: SourceKind
    category: str
    description: str
    docs_url: str = ""
    homepage: str = ""
    enabled_by_default: bool = True
    weight: int = 100
    """Lower runs first — cheap, high-signal APIs ahead of slow HTML probes."""

    tier: int = 1
    """Breadth tier, 1..15. A scan at mode ``N`` uses sources with ``tier <= N``.

    Sources that are not site-spec probes are the curated, key-free APIs; they
    sit at tier 1, so even the narrowest mode keeps them.
    """
    notes: str = ""
    """Set when a source is disabled (or surprising): why, and what to do instead."""


class BaseSource(ABC):
    """Common machinery: identity, timing, error containment, finding helpers."""

    meta: ClassVar[SourceMeta]

    def __init__(self, fetcher: Fetcher | None = None) -> None:
        self.fetcher = fetcher

    # -- identity --------------------------------------------------------
    @property
    def id(self) -> str:
        """Stable identifier for this source."""
        return self.meta.id

    @property
    def name(self) -> str:
        """Human-readable name."""
        return self.meta.name

    @property
    def kind(self) -> SourceKind:
        """The kind of identifier this source asks about."""
        return self.meta.kind

    @property
    def category(self) -> str:
        """Grouping used in reports and in the source inventory."""
        return self.meta.category

    @property
    def enabled_by_default(self) -> bool:
        """Whether a default scan includes this source."""
        return self.meta.enabled_by_default

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.id} kind={self.kind.value}>"

    # -- lifecycle -------------------------------------------------------
    def bind(self, fetcher: Fetcher) -> BaseSource:
        """Attach a fetcher and return self, so sources can be bound in a comprehension."""
        self.fetcher = fetcher
        return self

    def identifier_for(self, target: ScanTarget) -> str | None:
        """This source's identifier from the target, or None if it was not supplied."""
        return target.identifiers.get(self.kind.value)

    def applies_to(self, target: ScanTarget) -> bool:
        """Whether the target supplies the identifier this source needs.

        A source that does not apply is skipped rather than run: it has nothing
        to ask about, and running it would pad the source count with noise."""
        return self.identifier_for(target) is not None

    def query_url(self, identifier: str) -> str | None:
        """The URL that will be requested, for display/evidence. Optional."""
        return None

    @staticmethod
    def now() -> float:
        """Monotonic clock reading, for sources that build their own outcomes."""
        return time.perf_counter()

    @property
    def http(self) -> Fetcher:
        """The bound fetcher.

        Raises:
            RuntimeError: if the source was never bound."""
        if self.fetcher is None:  # pragma: no cover - programming error
            raise RuntimeError(f"source {self.id} is not bound to a Fetcher")
        return self.fetcher

    # -- execution -------------------------------------------------------
    async def execute(self, target: ScanTarget) -> SourceOutcome:
        """Run the source, converting *any* failure into a recorded status."""
        started = time.perf_counter()
        identifier = self.identifier_for(target)
        query_url = self.query_url(identifier) if identifier else None

        if not identifier:
            return self._outcome(
                ScanStatus.SKIPPED_NO_INPUT,
                started,
                query_url=query_url,
                skipped_reason=f"no {self.kind.value} supplied",
            )

        try:
            outcome = await self.run(identifier, target)
        except RobotsDeniedError as exc:
            outcome = self._outcome(
                ScanStatus.SKIPPED_ROBOTS, started, query_url=query_url, skipped_reason=str(exc)
            )
        except ForbiddenTargetError as exc:
            outcome = self._outcome(
                ScanStatus.BLOCKED, started, query_url=query_url, error=str(exc)
            )
        except HttpError as exc:
            status = ScanStatus.TIMEOUT if "Timeout" in str(exc) else ScanStatus.ERROR
            outcome = self._outcome(
                status,
                started,
                query_url=query_url,
                error=str(exc),
                http_status=exc.status,
            )
        except SourceError as exc:
            outcome = self._outcome(ScanStatus.ERROR, started, query_url=query_url, error=str(exc))
        except Exception as exc:
            outcome = self._outcome(
                ScanStatus.ERROR,
                started,
                query_url=query_url,
                error=f"unexpected {type(exc).__name__}: {exc}",
            )

        # Backfill identity/timing that sources should not have to repeat.
        outcome.source_id = self.id
        outcome.source_name = self.name
        outcome.kind = self.kind
        outcome.category = self.category
        outcome.duration_ms = outcome.duration_ms or int((time.perf_counter() - started) * 1000)
        outcome.docs_url = outcome.docs_url or self.meta.docs_url
        outcome.query_url = outcome.query_url or query_url
        return outcome

    @abstractmethod
    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        """Do the work for one identifier. Raise on failure; return an outcome."""

    # -- helpers ---------------------------------------------------------
    def _outcome(
        self,
        status: ScanStatus,
        started: float,
        *,
        findings: list[Finding] | None = None,
        http_status: int | None = None,
        error: str | None = None,
        skipped_reason: str | None = None,
        query_url: str | None = None,
        attempts: int = 0,
        duration_ms: int | None = None,
    ) -> SourceOutcome:
        return SourceOutcome(
            source_id=self.id,
            source_name=self.name,
            kind=self.kind,
            status=status,
            category=self.category,
            findings=list(findings or []),
            http_status=http_status,
            error=error,
            skipped_reason=skipped_reason,
            query_url=query_url,
            attempts=attempts,
            duration_ms=duration_ms if duration_ms is not None else int(
                (time.perf_counter() - started) * 1000
            ),
        )

    def finding(
        self,
        *,
        identifier: str,
        url: str,
        confidence: Confidence,
        evidence: str,
        category: str | None = None,
        title: str | None = None,
        display_name: str | None = None,
        bio: str | None = None,
        avatar_url: str | None = None,
        location: str | None = None,
        account_created_at: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> Finding:
        """Build a finding attributed to this source."""
        return Finding(
            source_id=self.id,
            source_name=self.name,
            kind=self.kind,
            url=url,
            identifier=identifier,
            confidence=confidence,
            category=category or self.category,
            evidence=evidence,
            title=title,
            display_name=display_name,
            bio=bio,
            avatar_url=avatar_url,
            location=location,
            account_created_at=account_created_at,
            extra=dict(extra or {}),
        )


def classify_status(response: HttpResponse) -> ScanStatus | None:
    """Map an HTTP status onto a terminal scan status, or ``None`` when the body decides.

    Returns ``None`` for 2xx/3xx so the caller can apply its own signature logic.
    """
    status = response.status
    if status in (404, 410):
        return ScanStatus.NOT_FOUND
    if status in (401, 403, 451):
        return ScanStatus.BLOCKED
    if status == 429:
        return ScanStatus.SKIPPED_RATE_LIMITED
    if status >= 500:
        return ScanStatus.ERROR
    if 200 <= status < 400:
        return None
    return ScanStatus.ERROR
