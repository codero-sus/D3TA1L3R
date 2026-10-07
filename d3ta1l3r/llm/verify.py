"""Ask a local model to judge whether each finding is *you* — only when asked.

This is the one place a model is allowed an opinion about identity, so it is
built to be defensible rather than impressive:

**It never runs unless the operator selects it.** ``--verify`` on the CLI, or the
checkbox in the dashboard. A plain scan, a plain ``ask`` and the retrieval
backend never call into this module, and a test asserts that.

**It does not touch the deterministic confidence.** A finding's ``confidence``
stays whatever the detector measured. The model's opinion is stored beside it as
:class:`FindingVerdict` — a separate field, with the model id and the reason —
and the report renders the two side by side. An operator reading the output sees
"I could not check this" and "the model thinks this is not you" as the different
claims they are, rather than a single number that quietly moved.

**It must quote the finding.** The prompt requires the model to answer id by id
and to cite the ids it used; a verdict whose id was not in front of it, or whose
sentence does not parse, becomes ``UNSURE`` rather than a guess. Silently
swallowing a malformed answer as "MINE" would be the worst possible failure mode
for an audit tool.

**It sees what it is given.** Masked values stay masked unless the operator asked
for raw ones, the same rule as the rest of the chat, and ``--about`` is the way
to hand it the facts only the user knows ("my bios say chess and Delhi"), because
no page can prove those.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..models import Confidence, Finding, ScanReport
from .backends import ExtractiveBackend, LLMBackend
from .backends import (  # noqa: F401 - re-exported for callers that monkeypatch
    select_backend as _select_backend,
)
from .prompt import build_messages

__all__ = [
    "VERIFICATION_SYSTEM_PROMPT",
    "FindingVerdict",
    "Verdict",
    "VerdictTally",
    "build_verification_messages",
    "parse_verdicts",
    "render_verification_markdown",
    "verify_findings",
]

VERIFICATION_SYSTEM_PROMPT = """You are D3TA1L3R's identity reviewer. The user ran a self-audit \
of their own public footprint and wants a second opinion on which findings are really theirs.

You will be given:
* the identifiers the user searched for (their own),
* optionally, facts they stated about themselves,
* a numbered list of findings with the evidence each detector recorded.

For EVERY finding, answer with exactly one line:
VERDICT <id> MINE|NOT_MINE|UNSURE — <one short sentence of reasoning>

Rules:
1. Use MINE only when the evidence connects the finding to this specific person:
   the identifier matches exactly, a display name matches a stated fact, or the
   account's own text mentions something only they stated.
2. Use NOT_MINE when the page clearly belongs to a different person: a different
   display name with no other connection, a different location, or a generic
   placeholder profile.
3. Use UNSURE when the evidence is a bare 200 response, an inferred handle, a
   common name, or anything else that does not distinguish this person from
   anyone else. UNSURE is the correct and expected answer most of the time —
   a guess is worse than an admission.
4. Do not invent findings, ids, urls or facts. Do not output anything except the
   VERDICT lines."""

_VERDICT_LINE = re.compile(
    r"VERDICT\s+\[?\s*(?P<id>[A-Za-z]?\d+(?:-\d+)?)\s*\]?\s*"
    r"(?P<verdict>MINE|NOT[_\s-]?MINE|NOTMINE|UNSURE)\b"
    r"(?:\s*[—\-–:]\s*(?P<reason>.*))?",  # noqa: RUF001 - the model emits any of these dashes
    re.IGNORECASE,
)


class Verdict(str, Enum):
    """What a model may say about one finding. There is no fourth, quiet option."""

    MINE = "mine"
    NOT_MINE = "not_mine"
    UNSURE = "unsure"

    @property
    def label(self) -> str:
        return {
            "mine": "looks like you",
            "not_mine": "probably not you",
            "unsure": "cannot tell",
        }[self.value]


@dataclass(slots=True)
class FindingVerdict:
    """One model judgement, kept strictly separate from measured confidence."""

    finding_id: str
    verdict: Verdict
    reason: str = ""
    source_id: str = ""
    url: str = ""
    measured_confidence: str = ""
    model: str = ""
    parsed: bool = True
    """False when the model's line did not parse; the verdict is then UNSURE."""

    @property
    def disagrees_with_evidence(self) -> bool:
        """True when a strong finding is called NOT_MINE — worth a human look."""
        return self.verdict is Verdict.NOT_MINE and self.measured_confidence in {
            Confidence.CONFIRMED.value,
            Confidence.HIGH.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "label": self.verdict.label,
            "reason": self.reason,
            "source_id": self.source_id,
            "url": self.url,
            "measured_confidence": self.measured_confidence,
            "model": self.model,
            "parsed": self.parsed,
            "overrides_evidence": self.disagrees_with_evidence,
            "note": (
                "a model opinion, not a detection: the confidence above was measured, "
                "this was judged"
            ),
        }


@dataclass(slots=True)
class VerdictTally:
    """Counts per verdict, plus the honest total."""

    mine: int = 0
    not_mine: int = 0
    unsure: int = 0
    unparsed: int = 0
    considered: int = 0

    def add(self, verdict: FindingVerdict) -> None:
        self.considered += 1
        if not verdict.parsed:
            self.unparsed += 1
        if verdict.verdict is Verdict.MINE:
            self.mine += 1
        elif verdict.verdict is Verdict.NOT_MINE:
            self.not_mine += 1
        else:
            self.unsure += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "considered": self.considered,
            "mine": self.mine,
            "not_mine": self.not_mine,
            "unsure": self.unsure,
            "unparsed": self.unparsed,
        }


@dataclass(slots=True)
class VerificationResult:
    """The verdicts for one verification run, with the model that produced them."""

    verdicts: list[FindingVerdict] = field(default_factory=list)
    backend: str = ""
    model: str = ""
    is_model: bool = False
    about: str = ""
    values_included: bool = False
    elapsed_ms: int = 0
    notes: list[str] = field(default_factory=list)

    def tally(self) -> VerdictTally:
        tally = VerdictTally()
        for verdict in self.verdicts:
            tally.add(verdict)
        return tally

    def by_id(self, finding_id: str) -> FindingVerdict | None:
        return next((v for v in self.verdicts if v.finding_id == finding_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "model": self.model,
            "is_model": self.is_model,
            "about": self.about,
            "values_included": self.values_included,
            "elapsed_ms": self.elapsed_ms,
            "tally": self.tally().to_dict(),
            "verdicts": [verdict.to_dict() for verdict in self.verdicts],
            "notes": list(self.notes),
            "disclaimer": (
                "Verdicts are a local model's opinion about identity. They never replace the "
                "measured confidence, and a wrong MINE is more likely than a wrong finding: "
                "check the URL before deleting or keeping an account."
            ),
        }


def build_verification_messages(
    findings: Sequence[tuple[str, Finding]],
    *,
    identifiers: str = "",
    about: str = "",
    include_values: bool = False,
    system: str = VERIFICATION_SYSTEM_PROMPT,
) -> list[dict[str, str]]:
    """The prompt: numbered findings, the operator's own facts, and the rules."""
    lines = ["The user searched for these identifiers they own: " + (identifiers or "(none given)")]
    if about:
        lines.append(f"Facts the user stated about themselves: {about}")
    lines.append("")
    lines.append("Findings to judge:")
    for finding_id, finding in findings:
        identifier = finding.identifier if include_values else _mask(finding.identifier)
        detail = [f"{finding.confidence.value.upper()} confidence", finding.source_name]
        if finding.display_name:
            detail.append(f"name shown: {finding.display_name}")
        if finding.location:
            detail.append(f"location: {finding.location}")
        if finding.bio:
            detail.append(f"bio: {finding.bio[:120]}")
        if finding.account_created_at:
            detail.append(f"account since: {finding.account_created_at}")
        if finding.evidence:
            detail.append(f"evidence: {finding.evidence[:200]}")
        lines.append(f"[{finding_id}] {identifier} — " + " | ".join(detail))
    lines.append("")
    lines.append(
        "Answer with one VERDICT line per finding. If the evidence cannot tell this "
        "person apart from anyone else, answer UNSURE."
    )
    question = "\n".join(lines)
    return build_messages(question, "", system=system)


def _identifiers_for(report: ScanReport, *, include_values: bool) -> list[str]:
    """What the prompt says the user searched for.

    Masked mode reuses the redacted ``display()`` label; raw mode spells the
    identifiers out, because a model cannot judge whether a found handle is the
    user's without seeing the handle. Raw mode is the operator's explicit choice
    and is recorded in the result.
    """
    target = report.target
    if not include_values:
        label = target.display()
        return [label] if label else []
    parts = []
    if target.username:
        parts.append(f"@{target.username}")
    if target.email:
        parts.append(target.email)
    if target.name:
        parts.append(target.name)
    if target.domain:
        parts.append(f"domain:{target.domain}")
    if target.location:
        parts.append(f"location: {target.location}")
    return parts


def _mask(value: str) -> str:
    from ..core.security import EMAIL_RE, mask_email

    text = str(value or "")
    if EMAIL_RE.match(text):
        return mask_email(text)
    if len(text) <= 2:
        return "••" if text else ""
    return f"{text[0]}…{text[-1]}"


def parse_verdicts(
    text: str, *, known_ids: Sequence[str], model: str = ""
) -> list[FindingVerdict]:
    """Parse ``VERDICT <id> MINE|NOT_MINE|UNSURE — reason`` lines.

    Anything unparseable becomes ``UNSURE`` with ``parsed=False`` and the raw line
    as the reason, and an id the model invented is dropped rather than attached to
    a real finding. Both behaviours are tested.
    """
    known = {item.upper(): item for item in known_ids}
    verdicts: list[FindingVerdict] = []
    seen: set[str] = set()
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _VERDICT_LINE.search(line)
        if match is None:
            if line.upper().startswith("VERDICT"):
                # It tried to answer but not in a shape we can trust.
                verdicts.append(
                    FindingVerdict(
                        finding_id="",
                        verdict=Verdict.UNSURE,
                        reason=f"unparseable line: {line[:160]}",
                        model=model,
                        parsed=False,
                    )
                )
            continue
        item_id = known.get(match.group("id").upper(), "")
        if not item_id:
            continue  # an id that was never in the prompt
        word = re.sub(r"[\s_-]", "", match.group("verdict").upper())
        verdict = {
            "MINE": Verdict.MINE,
            "NOTMINE": Verdict.NOT_MINE,
            "UNSURE": Verdict.UNSURE,
        }[word]
        if item_id in seen:
            continue
        seen.add(item_id)
        verdicts.append(
            FindingVerdict(
                finding_id=item_id,
                verdict=verdict,
                reason=(match.group("reason") or "").strip()[:300],
                model=model,
            )
        )
    return verdicts


def verify_findings(
    reports: Sequence[ScanReport],
    backend: LLMBackend | None = None,
    *,
    about: str = "",
    include_values: bool = False,
    limit: int | None = None,
    only_uncertain: bool = False,
    notes: Sequence[str] = (),
) -> VerificationResult:
    """Run the identity review over the findings of ``reports``.

    ``only_uncertain`` skips findings that measured ``CONFIRMED``/``HIGH`` — the
    ones a detector already tied to the user, which need no second opinion and
    are the most expensive to ask about.
    """
    started = time.perf_counter()
    backend = backend or ExtractiveBackend()
    numbered: list[tuple[str, Finding]] = []
    identifiers: list[str] = []
    for index, report in enumerate(reports, start=1):
        identifiers.extend(_identifiers_for(report, include_values=include_values))
        for finding in report.findings:
            if only_uncertain and finding.confidence in {Confidence.CONFIRMED, Confidence.HIGH}:
                continue
            finding_id = f"F{index}-{len(numbered) + 1:03d}"
            numbered.append((finding_id, finding))
    if limit is not None:
        numbered = numbered[: max(0, limit)]

    result = VerificationResult(
        backend=backend.name,
        model=backend.model_id,
        is_model=backend.is_model,
        about=about,
        values_included=include_values,
        notes=list(notes),
    )
    if not numbered:
        result.notes.append("no findings to review")
        result.elapsed_ms = int((time.perf_counter() - started) * 1000)
        return result

    messages = build_verification_messages(
        numbered,
        identifiers="; ".join(identifiers),
        about=about,
        include_values=include_values,
    )
    known_ids = [finding_id for finding_id, _ in numbered]
    index = dict(numbered)

    text = ""
    try:
        text = backend.generate(messages, context_text="")
    except Exception as exc:  # a broken model must not lose the findings
        result.notes.append(
            f"the {backend.name} backend failed ({exc.__class__.__name__}); "
            "every finding is reported UNSURE"
        )

    parsed = parse_verdicts(text, known_ids=known_ids, model=backend.model_id)
    answered = {verdict.finding_id for verdict in parsed if verdict.finding_id}
    for verdict in parsed:
        finding = index.get(verdict.finding_id)
        if finding is not None:
            verdict.source_id = finding.source_id
            verdict.url = finding.url
            verdict.measured_confidence = finding.confidence.value
    # Anything the model skipped is stated plainly rather than left out: a missing
    # line must not read as "no opinion needed".
    for finding_id, finding in numbered:
        if finding_id in answered:
            continue
        parsed.append(
            FindingVerdict(
                finding_id=finding_id,
                verdict=Verdict.UNSURE,
                reason="the model did not answer for this finding",
                source_id=finding.source_id,
                url=finding.url,
                measured_confidence=finding.confidence.value,
                model=backend.model_id,
                parsed=not backend.is_model,
            )
        )
    order = dict(enumerate(known_ids))
    order = {finding_id: position for position, finding_id in order.items()}
    result.verdicts = sorted(parsed, key=lambda verdict: order.get(verdict.finding_id, 9999))
    result.elapsed_ms = int((time.perf_counter() - started) * 1000)
    return result


def render_verification_markdown(result: VerificationResult, *, max_rows: int = 60) -> str:
    """A human-readable table, prefixed with what it is and what it is not."""
    tally = result.tally()
    lines = [
        "## Identity review (local model)",
        "",
        f"Model: `{result.model or 'unknown'}` ({result.backend})"
        f"{'' if result.is_model else ' — retrieval, not generation'}",
        f"Findings reviewed: {tally.considered} · looks like you: {tally.mine} · "
        f"probably not you: {tally.not_mine} · cannot tell: {tally.unsure}",
        "",
        "> These are a model's *opinions* about identity, kept separate from the measured "
        "confidence column. They are not evidence, and a wrong \"looks like you\" is more "
        "likely than a wrong finding.",
        "",
    ]
    if result.about:
        lines.append(f"Stated by you: {result.about}")
        lines.append("")
    if not result.verdicts:
        lines.append("Nothing was reviewed.")
        return "\n".join(lines)
    lines.extend(["| Finding | Measured | Verdict | Why |", "| --- | --- | --- | --- |"])
    for verdict in result.verdicts[:max_rows]:
        flag = " ⚠" if verdict.disagrees_with_evidence else ""
        lines.append(
            f"| `{verdict.finding_id}` | {verdict.measured_confidence or '?'} | "
            f"{verdict.verdict.label}{flag} | {(verdict.reason or '—').replace('|', '/')} |"
        )
    if len(result.verdicts) > max_rows:
        lines.append(f"| … | | | {len(result.verdicts) - max_rows} more |")
    if tally.unparsed:
        lines.append("")
        lines.append(
            f"{tally.unparsed} line(s) could not be parsed and were recorded as "
            "\"cannot tell\" rather than guessed at."
        )
    return "\n".join(lines)


def to_json(result: VerificationResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
