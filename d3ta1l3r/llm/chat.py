"""One chat session over a :class:`~d3ta1l3r.llm.context.ScanContext`.

A session is deliberately boring, and deliberately not persisted:

* **Nothing is written to disk.** History lives in the object and dies with the
  process. The vault is the encrypted home of your identifiers; a plain
  transcript of a conversation *about* them sitting next to the reports would
  quietly undo that.
* **Every answer carries its provenance.** Which backend answered, which ids it
  cited, which ids it invented, and whether it was grounded at all are fields on
  :class:`Answer`, not prose the caller has to parse — so both the CLI and the
  dashboard can put the honesty next to the answer.
* **An invented citation cannot be silently displayed.** :meth:`ask` verifies
  citations against the context that was sent and records the misses in
  :attr:`Answer.unknown_citations`; :meth:`Answer.clean_text` removes them for
  display surfaces that should not repeat a fabrication at all.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .backends import ExtractiveBackend, LLMBackend
from .cite import CitationReport, strip_unknown_citations, verify_citations
from .context import ScanContext
from .prompt import build_messages, history_messages

__all__ = ["Answer", "ChatSession"]


@dataclass(slots=True)
class Answer:
    """A grounded (or explicitly ungrounded) answer about the user's own reports."""

    question: str
    text: str
    backend: str
    model: str
    is_model: bool
    citations: list[str] = field(default_factory=list)
    unknown_citations: list[str] = field(default_factory=list)
    grounded: bool = False
    elapsed_ms: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def citation_problem(self) -> str:
        """A one-line explanation of what is wrong with the citations, if anything."""
        if self.unknown_citations:
            return (
                "the model cited "
                + ", ".join(f"[{item}]" for item in self.unknown_citations)
                + " which is not in the context — treat those sentences as unreliable"
            )
        if self.is_model and not self.citations:
            return "the answer cites no context id, so it is not tied to anything that was checked"
        return ""

    def clean_text(self, *, strip_unknown: bool = False) -> str:
        """The answer text, optionally with invented citations removed entirely."""
        if strip_unknown and self.unknown_citations:
            return strip_unknown_citations(self.text, self.unknown_citations)
        return self.text

    def to_dict(self, *, strip_unknown: bool = False) -> dict[str, Any]:
        return {
            "question": self.question,
            "answer": self.clean_text(strip_unknown=strip_unknown),
            "backend": self.backend,
            "model": self.model,
            "is_model": self.is_model,
            "citations": list(self.citations),
            "unknown_citations": list(self.unknown_citations),
            "grounded": self.grounded,
            "citation_problem": self.citation_problem,
            "elapsed_ms": self.elapsed_ms,
            "notes": list(self.notes),
        }


class ChatSession:
    """Ask questions about one context; keep a short, in-memory history."""

    def __init__(
        self,
        context: ScanContext,
        backend: LLMBackend | None = None,
        *,
        max_history: int = 4,
        context_chars: int = 6000,
        notes: Sequence[str] = (),
    ) -> None:
        self.context = context
        self.backend = backend or ExtractiveBackend()
        self.max_history = max_history
        self.context_chars = context_chars
        self.notes = list(notes)
        self.history: list[tuple[str, str]] = []

    # -- state -----------------------------------------------------------
    def _context_text(self) -> str:
        return self.context.render(max_chars=self.context_chars)

    def _message_context(self) -> str:
        """What goes in the prompt. Raw values are the caller's choice, not ours."""
        text = self._context_text()
        if self.context.values_included:
            text += (
                "\n(See the note above: this machine is the only place these values "
                "exist. Do not repeat identifiers you were not asked about.)"
            )
        return text

    # -- asking ----------------------------------------------------------
    def ask(self, question: str) -> Answer:
        """Send one question. Never raises for a bad model answer — reports it."""
        question = (question or "").strip()
        if not question:
            raise ValueError("a question is required")
        started = time.perf_counter()
        history = history_messages(self.history, limit=self.max_history)
        messages = build_messages(
            question, self._message_context(), history=history
        )
        notes = list(self.notes)
        error = ""
        try:
            text = self.backend.generate(messages, context_text=self._context_text())
        except Exception as exc:  # a broken model must not break the report view
            error = f"{exc.__class__.__name__}: {exc}"
            notes.append(f"the {self.backend.name} backend failed ({error}); answered from the report")
            fallback = ExtractiveBackend()
            text = fallback.generate(messages, context_text=self._context_text())

        verdict: CitationReport = verify_citations(text, self.context.ids())
        grounded = bool(verdict.known) or not self.backend.is_model
        answer = Answer(
            question=question,
            text=text,
            backend=self.backend.name,
            model=self.backend.model_id,
            is_model=self.backend.is_model,
            citations=verdict.cited,
            unknown_citations=verdict.unknown,
            grounded=grounded,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            notes=notes,
        )
        self.history.append((question, text))
        if len(self.history) > self.max_history * 2:
            self.history = self.history[-self.max_history :]
        return answer

    def reset(self) -> None:
        """Forget the conversation (the context stays)."""
        self.history.clear()

    def describe(self) -> dict[str, Any]:
        info = self.backend.describe()
        info.update(
            {
                "context_items": len(self.context.items),
                "scans": [report.scan_id for report in self.context.reports],
                "values_included": self.context.values_included,
                "turns": len(self.history),
                "context_chars": self.context_chars,
                "stored_to_disk": False,
            }
        )
        return info
