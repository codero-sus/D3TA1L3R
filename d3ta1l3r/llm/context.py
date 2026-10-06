"""Turn stored scans and the watchlist into a numbered digest a model can cite.

The digest is the only thing the model ever sees, so this module is where the
privacy decisions actually happen:

* every line carries a stable id (``S1``, ``F1-003``, ``G1-07``, ``E2``, ``B2-1``)
  so an answer can point at something checkable instead of paraphrasing it;
* values are rendered through the same masks the CLI and dashboard use unless
  the caller explicitly asks for raw ones — which
  :class:`~d3ta1l3r.llm.chat.ChatSession` does only because the operator chose
  it and the model is on this machine;
* the digest is trimmed to a character budget, biggest signal first, because a
  1.5B model with a 2048-token window cannot read a whole scan directory.

Ids are assigned in a deterministic order (scans newest first, findings in the
report's own confidence order) so the same question about the same reports
produces the same ids — which is what makes "it said F1-003" mean something
tomorrow.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding, ScanReport, ScanStatus
from ..vault import VaultEntry, VaultKind

__all__ = [
    "ContextItem",
    "ScanContext",
    "build_context",
    "render_entry_line",
    "scrub_text",
]

_GAP_STATUSES = frozenset(
    {
        ScanStatus.ERROR,
        ScanStatus.TIMEOUT,
        ScanStatus.BLOCKED,
        ScanStatus.SKIPPED_ROBOTS,
        ScanStatus.SKIPPED_RATE_LIMITED,
    }
)
_MAX_EVIDENCE = 160


def _clip(text: str, limit: int = _MAX_EVIDENCE) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_entry_line(entry: VaultEntry, *, include_values: bool) -> str:
    """One watchlist entry: ``E2 email al***@example.com | last: pwned x3``."""
    value = entry.value if include_values else entry.masked
    if entry.kind is VaultKind.PASSWORD:
        value = "(password; only a verifier is kept)" if include_values else entry.masked
    line = f"{entry.kind.value} {value or '(no value)'}"
    if entry.label:
        line += f" | label: {entry.label}"
    if entry.last_status:
        line += f" | last check: {entry.last_status}"
        if entry.last_count > 0:
            line += f" ({entry.last_count} record(s))"
        if entry.last_checked:
            line += f" on {entry.last_checked[:10]}"
    else:
        line += " | never checked"
    if not entry.recheckable:
        line += " | cannot be re-checked automatically"
    return line


@dataclass(frozen=True, slots=True)
class ContextItem:
    """One citable line of context."""

    id: str
    kind: str  # scan | finding | gap | watchlist | breach
    text: str
    refs: dict[str, Any] = field(default_factory=dict)

    def line(self) -> str:
        return f"[{self.id}] {self.text}"


@dataclass(slots=True)
class ScanContext:
    """The digest handed to a model, plus the ids it is allowed to cite."""

    items: list[ContextItem]
    reports: list[ScanReport] = field(default_factory=list)
    values_included: bool = False
    breach: dict[str, Any] | None = None

    def by_id(self, item_id: str) -> ContextItem | None:
        wanted = item_id.strip().upper()
        return next((item for item in self.items if item.id == wanted), None)

    def ids(self) -> set[str]:
        return {item.id for item in self.items}

    def findings(self) -> list[ContextItem]:
        return [item for item in self.items if item.kind == "finding"]

    def render(self, *, max_chars: int = 6000, kinds: Sequence[str] | None = None) -> str:
        """The digest as text, trimmed to ``max_chars`` without splitting a line."""
        wanted = set(kinds) if kinds else None
        out: list[str] = []
        used = 0
        for item in self.items:
            if wanted is not None and item.kind not in wanted:
                continue
            line = item.line()
            if out and used + len(line) + 1 > max_chars:
                out.append(f"… {len(self.items) - len(out)} more lines omitted")
                break
            out.append(line)
            used += len(line) + 1
        return "\n".join(out)

    def to_dict(self, *, max_chars: int = 6000) -> dict[str, Any]:
        return {
            "values_included": self.values_included,
            "scans": [r.scan_id for r in self.reports],
            "items": len(self.items),
            "digest": self.render(max_chars=max_chars),
        }


def build_context(
    reports: Iterable[ScanReport] = (),
    *,
    watchlist: Sequence[VaultEntry] = (),
    breach: dict[str, Any] | None = None,
    include_values: bool = False,
    max_findings_per_scan: int | None = None,
) -> ScanContext:
    """Build the citable digest.

    ``include_values`` is the operator's explicit choice (``ask`` defaults to
    raw because the model is local, the library defaults to masked): with it
    off, a model — or a log of the prompt — never sees the identifier itself.
    """
    ordered = sorted(reports, key=lambda r: r.started_at, reverse=True)
    items: list[ContextItem] = []

    for index, report in enumerate(ordered, start=1):
        scan_tag = f"S{index}"
        findings = report.findings
        if max_findings_per_scan is not None:
            findings = findings[:max_findings_per_scan]
        categories = sorted({f.category for f in findings})
        target_label = (
            _raw_target(report)
            if include_values
            else _masked_target(report, fallback=report.target.display())
        )
        items.append(
            ContextItem(
                id=scan_tag,
                kind="scan",
                text=(
                    f"scan of {target_label}"
                    f"{' (DEMO fixtures — not a real account)' if report.demo else ''}"
                    f" | started {report.started_at.date().isoformat()}"
                    f" | findings {len(findings)}"
                    f" | sources {report.stats.sources_hit} hit, "
                    f"{report.stats.sources_failed} failed of {report.stats.sources_total}"
                    f" | categories: {', '.join(categories) or 'none'}"
                ),
                refs={"scan_id": report.scan_id, "demo": report.demo},
            )
        )
        for number, finding in enumerate(findings, start=1):
            item_id = f"F{index}-{number:03d}"
            items.append(
                ContextItem(
                    id=item_id,
                    kind="finding",
                    text=_finding_line(finding, include_values=include_values),
                    refs={
                        "scan_id": report.scan_id,
                        "source_id": finding.source_id,
                        "url": finding.url,
                        "confidence": finding.confidence.value,
                        "category": finding.category,
                    },
                )
            )
        for number, outcome in enumerate(_gaps(report), start=1):
            reason = outcome.error or outcome.skipped_reason or outcome.status.value
            items.append(
                ContextItem(
                    id=f"G{index}-{number:02d}",
                    kind="gap",
                    text=(
                        f"gap: {outcome.source_id} ({outcome.category}) was not checked — "
                        f"{outcome.status.value}: {_clip(reason, 120)}"
                    ),
                    refs={"scan_id": report.scan_id, "source_id": outcome.source_id},
                )
            )
        for number, warning in enumerate(report.warnings, start=1):
            items.append(
                ContextItem(
                    id=f"W{index}-{number:02d}",
                    kind="gap",
                    text=f"scan warning: {_clip(warning, 160)}",
                    refs={"scan_id": report.scan_id},
                )
            )

    for number, entry in enumerate(watchlist, start=1):
        items.append(
            ContextItem(
                id=f"E{number}",
                kind="watchlist",
                text=render_entry_line(entry, include_values=include_values),
                refs={
                    "entry_id": entry.entry_id,
                    "kind": entry.kind.value,
                    "last_status": entry.last_status,
                    "recheckable": entry.recheckable,
                },
            )
        )

    for number, check in enumerate(_breach_checks(breach), start=1):
        items.append(
            ContextItem(
                id=f"B{number}",
                kind="breach",
                text=_breach_line(check),
                refs={"source_id": check.get("source_id", ""), "status": check.get("status", "")},
            )
        )

    if not include_values:
        pairs = _scrub_pairs(ordered, list(watchlist))
        items = [
            ContextItem(
                id=item.id, kind=item.kind, text=scrub_text(item.text, pairs), refs=item.refs
            )
            for item in items
        ]

    return ScanContext(
        items=items,
        reports=list(ordered),
        values_included=include_values,
        breach=breach,
    )


# ---------------------------------------------------------------------------
def _scrub_pairs(reports: Sequence[ScanReport], watchlist: Sequence[VaultEntry]) -> list[tuple[str, str]]:
    """``(raw, masked)`` for every identifier the digest knows about.

    Masking each field is not enough on its own: a finding's URL usually embeds
    the handle (``https://github.com/alice``), and a user-written label may quote
    the value it labels. So masked mode composes each line and then replaces any
    raw identifier it can still find, longest first, so a short handle cannot be
    substituted inside a longer address.
    """
    from urllib.parse import quote

    pairs: dict[str, str] = {}

    def add(raw: str, masked: str) -> None:
        raw = (raw or "").strip()
        if raw and masked and raw != masked:
            pairs[raw] = masked
            encoded = quote(raw, safe="")
            if encoded != raw:
                pairs[encoded] = masked

    for report in reports:
        target = report.target
        add(target.username, _mask_like(target.username))
        add(target.email, _mask_like(target.email))
        add(target.name, _mask_like(target.name))
        for finding in report.findings:
            add(finding.identifier, _mask_like(finding.identifier))
    for entry in watchlist:
        if entry.value:
            add(entry.value, entry.masked)
    return sorted(pairs.items(), key=lambda pair: len(pair[0]), reverse=True)


def scrub_text(text: str, pairs: Sequence[tuple[str, str]]) -> str:
    """Replace every raw identifier still present in ``text`` with its mask."""
    for raw, masked in pairs:
        if raw in text:
            text = text.replace(raw, masked)
    return text


def _raw_target(report: ScanReport) -> str:
    """The target as the operator typed it, for prompts that asked for raw values.

    ``ScanTarget.display()`` masks the email even in raw mode — correct for a
    report heading, wrong here: ``--include-values`` is an explicit decision that
    the model may see the identifiers, and a half-masked target would make the
    digest inconsistent with its own setting.
    """
    target = report.target
    parts: list[str] = []
    if target.username:
        parts.append(f"@{target.username}")
    if target.email:
        parts.append(target.email)
    if target.name:
        parts.append(target.name)
    if target.domain:
        parts.append(f"domain:{target.domain}")
    if target.location:
        parts.append(f"({target.location})")
    return " ".join(parts) or report.target.display()


def _masked_target(report: ScanReport, *, fallback: str) -> str:
    """A target label safe to put in a prompt: every part of it masked.

    ``ScanTarget.display()`` masks the email but shows the handle and the name
    in full, which is right for a local report heading and wrong for a digest
    whose whole promise is that identifiers stay masked unless asked for.
    """
    target = report.target
    parts: list[str] = []
    if target.username:
        parts.append(f"@{_mask_like(target.username)}")
    if target.email:
        parts.append(_mask_like(target.email))
    if target.name:
        parts.append("name: " + _mask_like(target.name))
    if target.domain:
        parts.append(f"domain:{target.domain}")
    if target.location:
        parts.append(f"({target.location})")
    return " ".join(parts) or fallback


def _finding_line(finding: Finding, *, include_values: bool) -> str:
    identifier = finding.identifier if include_values else _mask_like(finding.identifier)
    parts = [
        f"{finding.confidence.value.upper()} {finding.source_name}",
        f"({finding.category})",
        f"for {identifier}",
        f"→ {finding.url}",
    ]
    if finding.display_name:
        parts.insert(3, f"name: {finding.display_name}")
    if finding.location:
        parts.append(f"location: {finding.location}")
    if finding.evidence:
        parts.append(f"why: {_clip(finding.evidence, 120)}")
    if finding.extra.get("homonym_warning"):
        parts.append("homonym risk: this source matches names only")
    if finding.extra.get("inferred"):
        parts.append("the handle was inferred, not supplied")
    return " ".join(parts)


def _mask_like(value: str) -> str:
    """Best-effort mask for a finding identifier we did not get as a typed value.

    The validators in :mod:`d3ta1l3r.core.security` raise rather than return a
    bool — they exist to reject input, not to classify it — so this uses the
    neutral pieces (``EMAIL_RE``, :func:`mask_phone`) and a digit test instead.
    """
    from ..core.security import EMAIL_RE, mask_email, mask_phone

    text = str(value or "")
    if EMAIL_RE.match(text):
        return mask_email(text)
    digits = sum(char.isdigit() for char in text)
    if digits >= 7 and digits >= len(text) - 4:
        return mask_phone(text)
    if len(text) <= 2:
        return "••" if text else ""
    return f"{text[0]}…{text[-1]}"


def _gaps(report: ScanReport) -> list[Any]:
    return [outcome for outcome in report.outcomes if outcome.status in _GAP_STATUSES]


def _breach_checks(breach: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not breach:
        return []
    report = breach.get("report") or {}
    return [check for check in (report.get("checks") or []) if isinstance(check, dict)]


def _breach_line(check: dict[str, Any]) -> str:
    status = str(check.get("status", "unknown"))
    where = check.get("source_name") or check.get("source_id") or "a breach source"
    what = check.get("masked_value") or check.get("kind") or "an identifier"
    detail = _clip(check.get("detail") or check.get("evidence") or "", 120)
    return f"breach check: {where} says {status} for {what}. {detail}".strip()
