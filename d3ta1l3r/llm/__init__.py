"""Ask questions about your own scans with a model that runs on this machine.

The chat feature exists because a report is a lot of JSON and the questions
people actually have are conversational: *"what should I fix first?"*, *"which
of these still exposes my real name?"*, *"what changed since last week?"*.

Three rules shape the design, and they follow from the rest of D3TA1L3R:

1. **The model is local, always.** Two real backends are supported — a GGUF
   file through ``llama-cpp-python``, or an Ollama daemon on loopback — and
   neither may point at a remote host. :class:`~d3ta1l3r.llm.backends.OllamaBackend`
   refuses any host that is not ``127.0.0.1``/``localhost``/``::1``. Nothing
   about your footprint is sent to a company to be summarised.

2. **Answers are grounded in ids.** The context is a numbered digest
   (``F1-003`` is finding 3 of scan 1, ``E2`` is watchlist entry 2, ``G1-07`` is
   a gap), the prompt requires citations, and
   :func:`d3ta1l3r.llm.cite.verify_citations` checks every id the model emits
   against the ids that were actually in front of it. An invented citation is
   reported as such instead of quietly becoming a claim about you.

3. **A model is optional.** :class:`~d3ta1l3r.llm.backends.ExtractiveBackend`
   answers from the report itself with no model installed at all, so the chat
   panel is never a dead box on a machine that cannot afford the weights. It
   says plainly which backend answered, and so does every other answer.

Chat transcripts live in process memory only. The vault already holds the raw
identifiers; a second copy of them in an unencrypted transcript file next to the
reports would undo that, so nothing here is ever written to disk.
"""

from __future__ import annotations

from .backends import (
    BACKENDS,
    ExtractiveBackend,
    LlamaCppBackend,
    LLMBackend,
    OllamaBackend,
    backend_status,
    model_doctor,
    recommend_models,
    select_backend,
)
from .chat import Answer, ChatSession
from .cite import CitationReport, extract_citations, verify_citations
from .context import ContextItem, ScanContext, build_context
from .models import (
    CATALOG,
    ModelSpec,
    default_models_dir,
    download_model,
    hf_search,
    list_downloaded,
)
from .prompt import SYSTEM_PROMPT, build_messages
from .verify import (
    FindingVerdict,
    Verdict,
    VerificationResult,
    parse_verdicts,
    verify_findings,
)

__all__ = [
    "BACKENDS",
    "CATALOG",
    "SYSTEM_PROMPT",
    "Answer",
    "ChatSession",
    "CitationReport",
    "ContextItem",
    "ExtractiveBackend",
    "FindingVerdict",
    "LLMBackend",
    "LlamaCppBackend",
    "ModelSpec",
    "OllamaBackend",
    "ScanContext",
    "Verdict",
    "VerificationResult",
    "backend_status",
    "build_context",
    "build_messages",
    "default_models_dir",
    "download_model",
    "extract_citations",
    "hf_search",
    "list_downloaded",
    "model_doctor",
    "parse_verdicts",
    "recommend_models",
    "select_backend",
    "verify_citations",
    "verify_findings",
]
