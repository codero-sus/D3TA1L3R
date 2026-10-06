"""Citation extraction and verification.

A 1.5B model asked about a security report will occasionally cite ``F1-007``
when the digest only went up to ``F1-005``, or invent ``S4`` because a fourth
scan felt plausible. In a tool whose whole point is "what you read is what was
checked", that is the failure mode worth engineering against.

So every answer is scanned for bracketed ids, each one is looked up in the
context that produced the answer, and the result travels with the answer:
:attr:`Answer.unknown_citations` lists ids the model made up,
:attr:`Answer.grounded` is false when an answer about the report cites nothing
citable at all. The CLI and the dashboard both print that verdict next to the
answer, so a confident-sounding hallucination is visible as one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["CitationReport", "extract_citations", "strip_unknown_citations", "verify_citations"]

#: ``[F1-003]``, ``[S2]``, ``[E4]``, ``[G1-07]``, ``[W1-02]``, ``[B3]`` — the
#: shapes :mod:`d3ta1l3r.llm.context` hands out.
_CITATION_RE = re.compile(r"\[\s*([A-Za-z]\d+(?:-\d+)?)\s*\]")
_VALID_SHAPE = re.compile(r"\A[A-Z]\d+(?:-\d+)?\Z")


@dataclass(slots=True)
class CitationReport:
    """Which ids an answer cited, and whether they exist in its context."""

    cited: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    known: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.unknown

    def to_dict(self) -> dict[str, object]:
        return {"cited": self.cited, "known": self.known, "unknown": self.unknown, "ok": self.ok}


def extract_citations(text: str) -> list[str]:
    """All bracketed ids in ``text``, uppercased, de-duplicated, in order."""
    seen: dict[str, None] = {}
    for match in _CITATION_RE.finditer(text or ""):
        candidate = match.group(1).upper()
        if _VALID_SHAPE.match(candidate):
            seen.setdefault(candidate, None)
    return list(seen)


def verify_citations(text: str, known_ids: set[str]) -> CitationReport:
    """Split an answer's citations into ones that exist and ones invented."""
    known_upper = {item.upper() for item in known_ids}
    report = CitationReport(cited=extract_citations(text))
    for item_id in report.cited:
        (report.known if item_id in known_upper else report.unknown).append(item_id)
    return report


def strip_unknown_citations(text: str, unknown: list[str]) -> str:
    """Remove invented ids from an answer, keeping everything else intact.

    Used by the dashboard, where showing a fabricated id — even marked — invites
    a screenshot of it. The CLI keeps the annotated form because a developer
    asking "did the model lie to me?" deserves to see exactly where.
    """
    cleaned = text
    for item_id in unknown:
        cleaned = re.sub(rf"\[\s*{re.escape(item_id)}\s*\]", "[removed-invalid-citation]", cleaned)
    return cleaned
