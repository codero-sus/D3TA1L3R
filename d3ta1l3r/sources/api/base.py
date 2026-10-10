"""Machinery shared by the public-API sources.

An API source is the strongest kind of evidence D3TA1L3R can produce: the
service itself returns *the account record* for the identifier we supplied, so
the result is labelled ``CONFIRMED``. That authority comes with obligations,
and this module exists to make them mechanical:

* **No payload, no claim.** :meth:`ApiSource.outcome_for` refuses to report a
  hit unless the body parsed as JSON, and :func:`require_mapping` /
  :func:`require_sequence` refuse to read a shape the source did not expect.
  A site that answers with an HTML error page (or a captive portal) produces an
  ``error`` outcome, never a fabricated finding.
* **Status codes are translated, not ignored.** 404/410 mean "no such account",
  401/403/451 mean "blocked" (unknown), 429 means "rate limited", 5xx means
  "error" — see :func:`d3ta1l3r.sources.base.classify_status`.
* **Identifiers are never invented.** Sources only ever use the value handed to
  them by the engine; there is no "try common variations" pass anywhere.
* **Evidence is quotable.** Every helper below records *why* the answer is yes
  in words a human can re-check, including which field the value came from.

Nothing here uses an API key, a token, or a session: if a service needs one, the
source ships disabled with a note explaining the alternative, because a
self-audit should not require credentials for the service being audited.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from ...errors import SourceError
from ...models import Confidence, Finding, ScanStatus, ScanTarget, SourceOutcome
from ..base import BaseSource

__all__ = [
    "ApiSource",
    "JsonResult",
    "as_list",
    "dig",
    "first_present",
    "iso_from_epoch",
    "name_matches",
    "name_tokens",
    "require_mapping",
    "require_sequence",
    "summarise",
    "take",
]

_JSON_ACCEPT = "application/json, text/plain;q=0.9, */*;q=0.5"
_WORD_RE = re.compile(r"[\w'\u2019.-]+", re.UNICODE)
_ISO_HINT = re.compile(r"^\d{4}-\d{2}-\d{2}")


# ---------------------------------------------------------------------------
# Small, defensive readers
# ---------------------------------------------------------------------------
def dig(data: Any, *path: str | int, default: Any = None) -> Any:
    """Read ``data[a][b][c]`` without raising when the shape is not what we hoped.

    Numeric strings index sequences too, because JSON APIs write
    ``"last_known_institutions": {"0": {...}}`` about as often as they write a list.

    >>> dig({"a": {"b": [1, 2]}}, "a", "b", 1)
    2
    >>> dig({"a": {"b": [{"c": 3}]}}, "a", "b", "0", "c")
    3
    >>> dig({"a": 1}, "a", "missing", default="fallback")
    'fallback'
    """
    current = data
    for step in path:
        if isinstance(step, str) and step.isdigit() and isinstance(current, (list, tuple, dict)):
            step = int(step)
        if isinstance(step, int):
            if not isinstance(current, (list, tuple)) or not -len(current) <= step < len(current):
                return default
            current = current[step]
            continue
        if not isinstance(current, dict) or step not in current:
            return default
        current = current[step]
    return current


def first_present(source: Any, *rest: Any, default: Any = None) -> Any:
    """First non-empty value — from a mapping's keys, or from the arguments.

    Both call styles are common in this codebase::

        first_present(record, "display_name", "name")   # keys of an API record
        first_present(record.get("id"), "https://x")    # a fallback chain

    The mapping form is used when the first argument is a mapping and every
    remaining argument is a string; otherwise the arguments are treated as the
    candidate values themselves.
    """
    if isinstance(source, dict) and all(isinstance(item, str) for item in rest):
        candidates = [dig(source, key) for key in rest]
    else:
        candidates = [source, *rest]
    for value in candidates:
        if value not in (None, "", [], {}):
            return value
    return default


def take(values: Any, limit: int) -> list[Any]:
    """The first ``limit`` items of a sequence, tolerating any other shape."""
    return list(as_list(values))[: max(0, limit)]


def as_list(value: Any) -> list[Any]:
    """Coerce ``None`` / scalar / list into a list (for ``urls``-shaped fields)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def summarise(value: Any, *, limit: int = 120) -> str:
    """A short, single-line, human-readable rendering of an API field."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        parts = []
        for item in as_list(value)[:5]:
            if isinstance(item, dict):
                label = first_present(item, "value", "url", "name", "title", "display_name", "id")
                parts.append(str(label) if label not in (None, "") else "…")
            else:
                parts.append(str(item))
        text = "; ".join(parts) if parts else "…"
    else:
        text = str(value)
    text = " ".join(text.split())
    return text[:limit]


def require_mapping(value: Any, what: str) -> dict[str, Any]:
    """Assert an API answered with a JSON object, not a string or a list."""
    if not isinstance(value, dict):
        raise SourceError(
            f"{what}: expected a JSON object, got {type(value).__name__} — "
            "the endpoint moved or returned an error page"
        )
    return value


def require_sequence(value: Any, what: str) -> list[Any]:
    """Assert an API answered with a JSON array."""
    if not isinstance(value, list):
        raise SourceError(
            f"{what}: expected a JSON array, got {type(value).__name__} — "
            "the endpoint moved or returned an error page"
        )
    return value


def name_tokens(name: str) -> list[str]:
    """Lowercased, punctuation-stripped name parts (drops single letters)."""
    return [token.lower() for token in _WORD_RE.findall(name) if len(token) > 1]


def name_matches(candidate: str | None, wanted: str, *, allow_partial: bool = False) -> bool:
    """True when a returned name plausibly *is* the name we asked about.

    Name-based sources must never present a same-name stranger as a match, so
    this requires every token of the wanted name to appear in the candidate.
    With ``allow_partial``, a single-token candidate counts only when the wanted
    name is a single token too — that keeps "Madonna" from matching "Madonna
    University" while still allowing mononyms.
    """
    if not candidate:
        return False
    want = set(name_tokens(wanted))
    got = set(name_tokens(candidate))
    if not want or not got:
        return False
    if want <= got:
        return True
    return allow_partial and len(want) == 1 and bool(want & got)


def iso_from_epoch(value: Any) -> str | None:
    """Normalise the three timestamp shapes APIs actually return to ISO-8601."""
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, str):
        text = value.strip()
        if _ISO_HINT.match(text):
            return text
        try:
            value = float(text)
        except ValueError:
            return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds <= 0:
            return None
        if seconds > 10_000_000_000:  # milliseconds (Lichess, JS APIs)
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    return None


def md5_hex(value: str) -> str:
    """Gravatar's identifier scheme: md5 of the trimmed, lowercased address."""
    # md5 is mandated by Gravatar's URL scheme, not chosen as a security hash.
    return hashlib.md5(value.strip().lower().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class JsonResult:
    """One fetch plus its parsed payload (``None`` when the body was not JSON)."""

    response: Any  # HttpResponse, kept loose to avoid a circular import at runtime
    payload: Any | None = None
    parse_error: str | None = None
    request_url: str = ""

    @property
    def status(self) -> int:
        return int(self.response.status)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def attempts(self) -> int:
        return int(getattr(self.response, "attempts", 1))

    def describe(self) -> str:
        bits = [f"HTTP {self.status}"]
        if self.request_url:
            bits.append(self.request_url)
        if self.parse_error:
            bits.append(self.parse_error)
        return " — ".join(bits)


# ---------------------------------------------------------------------------
# The base class
# ---------------------------------------------------------------------------
class ApiSource(BaseSource):
    """A source that reads a public JSON API."""

    #: Confidence a *structured record* produced by this source earns.
    record_confidence: Confidence = Confidence.CONFIRMED

    # -- transport -------------------------------------------------------
    async def fetch_json(
        self,
        url: str,
        *,
        params: Any = None,
        headers: dict[str, str] | None = None,
        accept: str | None = None,
    ) -> JsonResult:
        """GET ``url`` and parse JSON, translating failures into honest states.

        Network-level problems raise :class:`HttpError` (contained by
        :meth:`BaseSource.execute`); HTTP error *statuses* come back inside the
        result so each source can produce the right status text for its API.
        """
        if params:
            from urllib.parse import urlencode

            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{urlencode(params)}"
        response = await self.http.fetch(
            url, accept=accept or _JSON_ACCEPT, extra_headers=headers
        )
        result = JsonResult(response=response, request_url=url)
        if not response.ok:
            return result  # status-driven outcome, decided by outcome_for()
        if not response.text.strip():
            result.parse_error = "empty body"
            return result
        try:
            result.payload = response.json()
        except SourceError as exc:
            result.parse_error = str(exc)
        return result

    # -- outcome construction -------------------------------------------
    def outcome_for(
        self,
        result: JsonResult,
        *,
        identifier: str,
        started: float,
        findings: list[Finding] | None = None,
        not_found_reason: str | None = None,
        error: str | None = None,
        extra_evidence: str = "",
    ) -> SourceOutcome:
        """Turn a :class:`JsonResult` into a status, refusing hollow hits."""
        status = result.status
        base = {
            "http_status": status,
            "query_url": result.request_url,
            "attempts": result.attempts,
        }
        if status in (404, 410):
            return self._outcome(
                ScanStatus.NOT_FOUND,
                started,
                error=not_found_reason or f"HTTP {status}: no such {self.kind.value}",
                **base,
            )
        if status in (401, 403, 451):
            return self._outcome(
                ScanStatus.BLOCKED,
                started,
                error=(
                    error
                    or f"HTTP {status}: the API refused an anonymous client — "
                    "existence cannot be determined (this is unknown, not absent)"
                ),
                skipped_reason=f"HTTP {status}",
                **base,
            )
        if status == 429:
            return self._outcome(
                ScanStatus.SKIPPED_RATE_LIMITED,
                started,
                skipped_reason="HTTP 429 from the API",
                error=error or "rate limited by the API — re-run later",
                **base,
            )
        if status >= 500:
            return self._outcome(
                ScanStatus.ERROR,
                started,
                error=error or f"HTTP {status}: the API is unhealthy",
                **base,
            )
        if not result.ok:
            return self._outcome(
                ScanStatus.ERROR, started, error=error or f"unexpected HTTP {status}", **base
            )
        if result.payload is None:
            return self._outcome(
                ScanStatus.ERROR,
                started,
                error=error
                or (
                    "the API answered 200 but the body was not JSON "
                    f"({result.parse_error or 'unknown reason'}) — refusing to guess"
                ),
                **base,
            )

        if findings:
            if extra_evidence:
                for finding in findings:
                    if extra_evidence not in finding.evidence:
                        finding.evidence = f"{finding.evidence}; {extra_evidence}"
            return self._outcome(ScanStatus.FOUND, started, findings=findings, **base)
        return self._outcome(
            ScanStatus.NOT_FOUND,
            started,
            error=not_found_reason or f"the API returned no record for {identifier!r}",
            **base,
        )

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def quote(identifier: str) -> str:
        """Percent-encode an identifier for use inside a path segment."""
        return quote(identifier, safe="")

    @staticmethod
    def md5(value: str) -> str:
        """Gravatar-style md5 hash of a normalized value (its URL scheme, not a protection)."""
        return md5_hex(value)

    def require_mapping(self, result: JsonResult, what: str) -> dict[str, Any]:
        """Assert the fetched payload is a JSON object, raising :class:`SourceError`."""
        return require_mapping(result.payload, f"{what} ({result.describe()})")

    def require_sequence(self, result: JsonResult, what: str) -> list[Any]:
        """Assert the fetched payload is a JSON array."""
        return require_sequence(result.payload, f"{what} ({result.describe()})")

    @staticmethod
    def link_extra(extra: dict[str, Any] | None) -> dict[str, Any]:
        """Normalise a source's ``extra`` block (kept for the older sources' spelling)."""
        return dict(extra or {})

    def record_finding(
        self,
        *,
        identifier: str,
        url: str,
        evidence: str,
        confidence: Confidence | None = None,
        title: str | None = None,
        display_name: str | None = None,
        bio: str | None = None,
        avatar_url: str | None = None,
        location: str | None = None,
        account_created_at: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> Finding:
        return self.finding(
            identifier=identifier,
            url=url,
            confidence=confidence or self.record_confidence,
            evidence=evidence,
            title=title,
            display_name=display_name,
            bio=bio,
            avatar_url=avatar_url,
            location=location,
            account_created_at=account_created_at,
            extra=extra,
        )

    def exposure_finding(
        self,
        *,
        identifier: str,
        url: str,
        evidence: str,
        exposure: list[str],
        extra: dict[str, object] | None = None,
    ) -> Finding:
        """A finding whose value is *what it leaks*, for the report's exposure list."""
        payload = dict(extra or {})
        payload["exposure"] = [item for item in exposure if item]
        return self.record_finding(
            identifier=identifier, url=url, evidence=evidence, extra=payload
        )


def elapsed_wall_clock(started: float) -> int:
    """Milliseconds since a ``time.perf_counter()`` reading."""
    return max(0, int((time.perf_counter() - started) * 1000))


# Kept importable for sources that want the target's own display label in a title.
def target_label(target: ScanTarget) -> str:
    return target.display()
