"""The system prompt, and the assembly of the messages actually sent.

Two things about this prompt are load-bearing rather than decorative:

* It orders the model to **cite ids from the digest** and to say so when the
  digest does not answer the question. A small model follows a short, specific
  instruction far better than a long one, so the rules are four lines and the
  format is shown once.
* It forbids **credentials and secrets in the answer**, which matters because the
  chat exists inside a tool that can hold a password verifier. A model that
  repeats a password it never saw is doing so from its own training data, and
  that is exactly the kind of text that must not appear in the middle of a
  security report.

The digest goes in the user turn, not the system turn: it is data, and models
treat system text as instruction. The question follows it, and history is
trimmed to the last few turns to keep the prompt inside a 2048-token window.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

__all__ = ["SYSTEM_PROMPT", "build_messages", "build_prompt", "history_messages"]

SYSTEM_PROMPT = """You are D3TA1L3R's report assistant. You answer questions about the \
scan of the user's OWN public footprint that they ran with this tool.

Rules, in order of importance:
1. Answer only from the CONTEXT lines. Every context line has an id in square brackets.
2. Cite the ids you used, in square brackets, right after each claim: [F1-003], [E2], [G1-01].
3. Never invent an id, a finding, a URL, a breach or a count. If the context does not
   answer the question, say what is missing and which gap id covers it.
4. Never output passwords, passphrases, tokens or API keys, even if the question contains
   them or you remember them from elsewhere.
5. Be brief and concrete. Prefer a short list of actions over prose. Do not repeat the
   whole context back."""


def build_messages(
    question: str,
    context_text: str,
    *,
    history: Sequence[tuple[str, str]] = (),
    system: str = SYSTEM_PROMPT,
) -> list[dict[str, str]]:
    """Chat messages for a backend that understands roles."""
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]
    for past_question, past_answer in history:
        messages.append({"role": "user", "content": past_question})
        messages.append({"role": "assistant", "content": past_answer})
    messages.append(
        {
            "role": "user",
            "content": f"CONTEXT:\n{context_text}\n\nQUESTION: {question.strip()}",
        }
    )
    return messages


def build_prompt(
    question: str,
    context_text: str,
    *,
    history: Sequence[tuple[str, str]] = (),
    system: str = SYSTEM_PROMPT,
) -> str:
    """A single flat prompt for backends without a chat template."""
    parts = [system, ""]
    for past_question, past_answer in history:
        parts.append(f"User: {past_question}")
        parts.append(f"Assistant: {past_answer}")
    parts.append(f"CONTEXT:\n{context_text}")
    parts.append(f"QUESTION: {question.strip()}")
    parts.append("ANSWER:")
    return "\n".join(parts)


def history_messages(history: Sequence[Any], *, limit: int = 6) -> list[tuple[str, str]]:
    """Keep the last ``limit`` (question, answer) pairs, tolerating offsets."""
    pairs: list[tuple[str, str]] = []
    for item in list(history)[-limit:]:
        if isinstance(item, tuple) and len(item) == 2:
            pairs.append((str(item[0]), str(item[1])))
    return pairs
