"""Signature-driven probes against public profile pages.

A :class:`SiteSpec` describes *how to ask* a site and *how to read the answer*,
using only things every anonymous browser also sees:

* the status code (``404`` is the classic "no such user"),
* a stable phrase the site renders for a missing profile
  (``"Sorry, this page isn't available"``), and/or
* a redirect to a sign-in page instead of a profile.

Nothing here tries to defeat a control. If a page is behind a sign-in wall, a
CAPTCHA, or a rate limit, the source reports that state (``blocked`` /
``skipped_rate_limited``) instead of working around it — "unknown" is a
respectable answer and a lie is not. Sites that render everything client-side
(so the HTML says nothing useful) ship **disabled** with a note, because a gap
is better than a guess.

Three detectors cover virtually every public site:

``marker``   a unique phrase appears only on a real profile page (strongest).
``absence``  the site returns HTTP 200 plus a known "no such user" phrase when
             the account is missing; anything else is treated as a hit.
``status``   404 means absent, 200 means present. Noisy by nature, so a
             status-only spec is forbidden from claiming better than
             ``medium`` confidence.

Specs live in ``d3ta1l3r/data/sites.json`` — data, not code — so site coverage
can be extended without touching Python. ``d3ta1l3r calibrate`` measures a
spec's real-world accuracy by probing handles that certainly do and certainly
do not exist, which is the only honest way to trust a signature.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from ..errors import ConfigError
from ..models import Confidence, ScanStatus, ScanTarget, SourceKind, SourceOutcome
from .base import BaseSource, SourceMeta, classify_status
from .notfound import classify_page

__all__ = ["SiteSpec", "UsernameProbeSource", "load_site_specs", "specs_from_dicts"]

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "sites.json"
_ACCEPT_HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

_DETECTORS = {"marker", "absence", "status"}


@dataclass(frozen=True, slots=True)
class SiteSpec:
    """Declarative description of one public-page probe."""

    id: str
    name: str
    url: str
    category: str
    kind: SourceKind = SourceKind.USERNAME
    detector: str = "marker"
    found_marker: str | None = None
    not_found_marker: str | None = None
    absent_statuses: tuple[int, ...] = (404, 410)
    confidence_found: Confidence = Confidence.HIGH
    confidence_absent: Confidence = Confidence.HIGH
    login_redirect_markers: tuple[str, ...] = ()
    """Redirect paths that mean "sign-in wall" — reported as ``blocked``, never as absent."""

    absent_redirect_markers: tuple[str, ...] = ()
    """Redirect paths that legitimately mean "no such profile" (e.g. ``/`` or ``/404``)."""
    docs_url: str = ""
    notes: str = ""
    enabled_by_default: bool = True
    verified_on: str | None = None
    weight: int = 200

    def __post_init__(self) -> None:
        placeholder = "{" + self.kind.value + "}"
        if placeholder not in self.url:
            raise ConfigError(
                f"site spec {self.id!r}: url must contain the {placeholder} placeholder"
            )
        if self.detector not in _DETECTORS:
            raise ConfigError(f"site spec {self.id!r}: unknown detector {self.detector!r}")
        if self.detector == "marker" and not (self.found_marker or self.not_found_marker):
            raise ConfigError(
                f"site spec {self.id!r}: marker detector needs found_marker or not_found_marker"
            )
        if self.detector == "absence" and not self.not_found_marker:
            raise ConfigError(
                f"site spec {self.id!r}: absence detector needs a not_found_marker phrase"
            )
        ceiling = Confidence.MEDIUM if self.detector == "status" else Confidence.HIGH
        if self.confidence_found.rank > ceiling.rank:
            raise ConfigError(
                f"site spec {self.id!r}: a {self.detector}-only probe may not claim "
                f"{self.confidence_found.value} confidence — lower the claim or add a signature"
            )
        if not self.name.strip() or not self.category.strip():
            raise ConfigError(f"site spec {self.id!r}: name and category are required")
        if urlsplit(self.url).scheme not in ("http", "https"):
            raise ConfigError(f"site spec {self.id!r}: url must be absolute http(s)")

    def profile_url(self, identifier: str) -> str:
        return self.url.format(**{self.kind.value: quote(identifier, safe="")})

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SiteSpec:
        known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        unknown = set(data) - known
        if unknown:
            raise ConfigError(
                f"site spec {data.get('id', '?')!r}: unknown field(s) {', '.join(sorted(unknown))}"
            )
        payload = dict(data)
        payload["kind"] = SourceKind(payload.get("kind", "username"))
        for key in ("absent_statuses", "login_redirect_markers", "absent_redirect_markers"):
            if key in payload:
                payload[key] = tuple(payload[key])
        for key in ("confidence_found", "confidence_absent"):
            if key in payload:
                payload[key] = Confidence(payload[key])
        return cls(**payload)


class UsernameProbeSource(BaseSource):
    """One public-page probe described by a :class:`SiteSpec`."""

    def __init__(self, spec: SiteSpec, fetcher: Any | None = None) -> None:
        super().__init__(fetcher)
        self.spec = spec
        self.meta = SourceMeta(
            id=spec.id,
            name=spec.name,
            kind=spec.kind,
            category=spec.category,
            description=spec.notes or f"public profile probe for {spec.name}",
            docs_url=spec.docs_url,
            homepage=spec.url.split("{", 1)[0],
            enabled_by_default=spec.enabled_by_default,
            weight=spec.weight,
            notes=spec.notes,
        )

    def query_url(self, identifier: str) -> str:
        return self.spec.profile_url(identifier)

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = time.perf_counter()
        url = self.spec.profile_url(identifier)
        response = await self.http.fetch(url, accept=_ACCEPT_HTML)
        http_status = response.status

        def outcome(
            status: ScanStatus,
            *,
            findings: list[Any] | None = None,
            error: str | None = None,
            skipped_reason: str | None = None,
        ) -> SourceOutcome:
            return self._outcome(
                status,
                started,
                findings=findings,
                http_status=http_status,
                error=error,
                skipped_reason=skipped_reason,
                query_url=url,
                attempts=response.attempts,
            )

        # 1. The status code decides outright for 404/410, 401/403/451, 429 and 5xx.
        terminal = classify_status(response)
        if terminal is ScanStatus.NOT_FOUND:
            return outcome(
                terminal,
                error=(
                    f"HTTP {http_status} for {url} — site reports no such "
                    f"{self.spec.kind.value}"
                ),
            )
        if terminal is not None:
            return outcome(
                terminal,
                error=f"HTTP {http_status} from {url}",
                skipped_reason=f"HTTP {http_status}" if terminal.is_skip else None,
            )

        # 2. Redirects: a sign-in wall means "unknown", a known absent-redirect means absent.
        if _redirect_matches(response.final_url, url, self.spec.login_redirect_markers):
            return outcome(
                ScanStatus.BLOCKED,
                error=(
                    f"redirected to {response.final_url}, which is a sign-in wall — "
                    "existence cannot be determined anonymously (this is a gap, not an answer)"
                ),
                skipped_reason="sign-in wall",
            )
        if _redirect_matches(response.final_url, url, self.spec.absent_redirect_markers):
            return outcome(
                ScanStatus.NOT_FOUND,
                error=f"redirected to {response.final_url} (site's 'no such profile' redirect)",
            )

        # 3. Signature detection on the body.
        body = response.text
        lowered = body.lower()

        # The site's own phrase first (better evidence), then the generic registry
        # in notfound.py — "User Not Found", "doesn't exist", "no such user" and
        # friends. An ambiguous phrase (private profile, bot check, suspended
        # account) is a gap, never a confident "not found".
        verdict = classify_page(
            body, markers=tuple(filter(None, (self.spec.not_found_marker,)))
        )
        if verdict is not None and verdict.certain:
            label = (
                "the not-found signature"
                if self.spec.not_found_marker
                and verdict.phrase == self.spec.not_found_marker.lower()
                else "the not-found phrase"
            )
            return outcome(
                ScanStatus.NOT_FOUND,
                error=f"HTTP {http_status} but {label} {verdict.phrase!r} matches",
            )
        if verdict is not None and not verdict.certain:
            return outcome(
                ScanStatus.BLOCKED,
                error=f"HTTP {http_status} but {verdict.evidence}",
                skipped_reason="ambiguous page",
            )

        if self.spec.found_marker and self.spec.found_marker.lower() in lowered:
            evidence = (
                f"HTTP {http_status} and page contains {self.spec.found_marker!r} "
                f"(GET {url}; {len(body)} bytes, {response.elapsed_ms} ms)"
            )
            return outcome(
                ScanStatus.FOUND,
                findings=[
                    self.finding(
                        identifier=identifier,
                        url=url,
                        confidence=self.spec.confidence_found,
                        evidence=evidence,
                        extra={
                            "detector": self.spec.detector,
                            "verified_on": self.spec.verified_on,
                            "final_url": response.final_url,
                        },
                    )
                ],
            )

        if self.spec.detector == "absence":
            evidence = (
                f"HTTP {http_status} and the page does not contain the site's "
                f"not-found phrase {self.spec.not_found_marker!r} "
                f"(GET {url}; {len(body)} bytes, {response.elapsed_ms} ms)"
            )
            return outcome(
                ScanStatus.FOUND,
                findings=[
                    self.finding(
                        identifier=identifier,
                        url=url,
                        confidence=self.spec.confidence_found,
                        evidence=evidence,
                        extra={
                            "detector": "absence",
                            "not_found_phrase": self.spec.not_found_marker,
                            "final_url": response.final_url,
                        },
                    )
                ],
            )

        if self.spec.detector == "status":
            evidence = (
                f"HTTP {http_status} for {url} (no stable page signature exists — "
                "status-code-only heuristic, verify by hand)"
            )
            return outcome(
                ScanStatus.FOUND,
                findings=[
                    self.finding(
                        identifier=identifier,
                        url=url,
                        confidence=self.spec.confidence_found,
                        evidence=evidence,
                        extra={
                            "detector": "status",
                            "verified_on": self.spec.verified_on,
                            "final_url": response.final_url,
                        },
                    )
                ],
            )

        # 4. Neither signature matched: surface it instead of guessing.
        return outcome(
            ScanStatus.ERROR,
            error=(
                f"ambiguous response: HTTP {http_status} matched neither the found nor the "
                f"not-found signature for '{self.spec.name}' — the site layout probably "
                "changed. Run `d3ta1l3r calibrate --sites "
                f"{self.spec.id}` or update the spec."
            ),
        )


def _redirect_matches(final_url: str, original_url: str, markers: Sequence[str]) -> bool:
    if not markers:
        return False
    final, original = urlsplit(final_url), urlsplit(original_url)
    if final.path.rstrip("/") == original.path.rstrip("/") and final.netloc == original.netloc:
        return False
    haystack = f"{final.path}?{final.query}".lower()
    return any(marker.lower() in haystack for marker in markers)


@lru_cache(maxsize=8)
def _load_file(path: str) -> tuple[SiteSpec, ...]:
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"site spec file not found: {file}")
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"could not read site spec file {file}: {exc}") from exc
    raw_specs = payload.get("sites") if isinstance(payload, dict) else payload
    if not isinstance(raw_specs, list):
        raise ConfigError(f"{file}: expected a JSON object with a 'sites' array")
    return tuple(specs_from_dicts(raw_specs))


def load_site_specs(
    *, include_disabled: bool = True, path: Path | str | None = None
) -> list[SiteSpec]:
    """Load built-in (or custom) site specs, validated and ordered."""
    specs = list(_load_file(str(path or _DATA_FILE)))
    if not include_disabled:
        specs = [s for s in specs if s.enabled_by_default]
    specs.sort(key=lambda s: (s.weight, s.name.lower()))
    return specs


def specs_from_dicts(raw_specs: Iterable[dict[str, Any]]) -> list[SiteSpec]:
    """Validate a list of raw dicts into :class:`SiteSpec` objects."""
    specs: list[SiteSpec] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_specs):
        if not isinstance(raw, dict):
            raise ConfigError(f"site spec #{index} is not an object")
        spec = SiteSpec.from_dict(raw)
        if spec.id in seen:
            raise ConfigError(f"duplicate site spec id {spec.id!r}")
        seen.add(spec.id)
        specs.append(spec)
    return specs


def specs_as_dicts(specs: Sequence[SiteSpec]) -> list[dict[str, Any]]:
    """Round-trip helper (used by ``--dump-sites`` and tests)."""
    out = []
    for spec in specs:
        row = {k: getattr(spec, k) for k in SiteSpec.__dataclass_fields__}  # type: ignore[attr-defined]
        row["kind"] = spec.kind.value
        row["confidence_found"] = spec.confidence_found.value
        row["confidence_absent"] = spec.confidence_absent.value
        row["absent_statuses"] = list(spec.absent_statuses)
        row["login_redirect_markers"] = list(spec.login_redirect_markers)
        row["absent_redirect_markers"] = list(spec.absent_redirect_markers)
        out.append(row)
    return out
