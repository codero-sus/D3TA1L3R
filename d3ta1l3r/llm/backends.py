"""Local backends: a GGUF file, a loopback Ollama daemon, or no model at all.

The 4 GB target shapes every default here. A quantised 1.5B model is about
1.1 GB of file, ~1.2 GB resident with a 2048-token window, and a 3B Q4 model is
about 2.4 GB — both fit beside a browser and an editor on a 4 GB machine, and
neither needs a GPU. :func:`recommend_models` prints that table;
:func:`model_doctor` checks a file on disk *before* loading it, because finding
out that a 4 GB model does not fit is better done with arithmetic than with the
OOM killer.

What each backend refuses to do:

* :class:`LlamaCppBackend` will not load a file that is not a GGUF, will not
  exceed the RAM budget by more than a small margin, and needs
  ``llama-cpp-python`` — an optional dependency, so the engine and CLI keep
  working without it.
* :class:`OllamaBackend` will not talk to a remote host. "Local model" is
  enforced with a loopback check rather than promised in documentation.
* :class:`ExtractiveBackend` will not pretend to be a model: it answers from the
  digest, says so, and exists so that the chat never becomes a dead box on a
  machine that cannot spare the RAM.
"""

from __future__ import annotations

import ipaddress
import math
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..errors import UsageError
from .prompt import build_prompt

__all__ = [
    "BACKENDS",
    "CORTEX_DEFAULT_HOST",
    "CORTEX_DEFAULT_MODEL",
    "GGUF_MAGIC",
    "OLLAMA_AUTO",
    "CortexBackend",
    "ExtractiveBackend",
    "LLMBackend",
    "LlamaCppBackend",
    "ModelRecommendation",
    "OllamaBackend",
    "backend_status",
    "estimate_model_ram_mb",
    "is_loopback_host",
    "is_private_lan_host",
    "model_doctor",
    "recommend_models",
    "select_backend",
]

GGUF_MAGIC = b"GGUF"

#: 4 GB is the stated target. The budget is checked before a load, not after.
DEFAULT_RAM_BUDGET_MB = 4096
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

OLLAMA_DEFAULT_HOST = "http://127.0.0.1:11434"
#: ``auto`` asks the daemon what it has instead of guessing a name that may not
#: be pulled. An explicit name still wins, and still fails loudly if absent.
OLLAMA_AUTO = "auto"
OLLAMA_DEFAULT_MODEL = OLLAMA_AUTO

#: Cortex LLM Hoster is a local GGUF hoster that speaks the OpenAI wire format.
#: Loopback is the default; a private-LAN host needs --cortex-host to be explicit.
CORTEX_DEFAULT_HOST = "http://127.0.0.1:8624"
CORTEX_DEFAULT_MODEL = OLLAMA_AUTO
CORTEX_API_KEY_ENV = "CORTEX_API_KEY"


@dataclass(slots=True)
class ModelRecommendation:
    """One row of the "what actually fits in 4 GB" table."""

    name: str
    parameters: str
    quantised_size_mb: int
    ram_mb: int
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "parameters": self.parameters,
            "download_mb": self.quantised_size_mb,
            "ram_mb": self.ram_mb,
            "note": self.note,
            "fits_4gb": self.ram_mb <= DEFAULT_RAM_BUDGET_MB,
        }


_RECOMMENDATIONS: tuple[ModelRecommendation, ...] = (
    ModelRecommendation(
        name="TinyLlama-1.1B-Chat (Q4_K_M)",
        parameters="1.1B",
        quantised_size_mb=670,
        ram_mb=900,
        note="smallest useful chat model; keeps ~3 GB free, quality is modest",
    ),
    ModelRecommendation(
        name="Qwen2.5-1.5B-Instruct (Q4_K_M)",
        parameters="1.5B",
        quantised_size_mb=1120,
        ram_mb=1500,
        note="best balance for this size of machine; good at following cite-the-id rules",
    ),
    ModelRecommendation(
        name="Llama-3.2-3B-Instruct (Q4_K_M)",
        parameters="3B",
        quantised_size_mb=2020,
        ram_mb=2400,
        note="noticeably better prose; tight but usable on 4 GB with nothing else open",
    ),
    ModelRecommendation(
        name="Phi-3-mini-4k-instruct (Q4)",
        parameters="3.8B",
        quantised_size_mb=2300,
        ram_mb=2700,
        note="upper bound for 4 GB; expect swapping if a browser is open",
    ),
)


class LLMBackend:
    """Common surface for every way of answering a question."""

    name = "backend"
    is_model = True
    """False for the fallback that answers from the digest without a model."""

    def __init__(self, *, max_tokens: int = 400, temperature: float = 0.2) -> None:
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.load_seconds: float | None = None

    # -- capability ------------------------------------------------------
    @property
    def model_id(self) -> str:  # pragma: no cover - overridden
        return self.name

    def available(self) -> tuple[bool, str]:  # pragma: no cover - overridden
        return False, "not implemented"

    # -- generation ------------------------------------------------------
    def generate(self, messages: Sequence[dict[str, str]], *, context_text: str = "") -> str:
        """Produce an answer. ``context_text`` is used by the fallback."""
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        ok, reason = self.available()
        return {
            "name": self.name,
            "model": self.model_id,
            "available": ok,
            "reason": reason,
            "is_model": self.is_model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "load_seconds": self.load_seconds,
        }


# ---------------------------------------------------------------------------
class LlamaCppBackend(LLMBackend):
    """A GGUF file on this disk, through the optional ``llama-cpp-python``."""

    name = "llama_cpp"

    def __init__(
        self,
        model_path: Path | str,
        *,
        threads: int | None = None,
        context_window: int = 2048,
        ram_budget_mb: int = DEFAULT_RAM_BUDGET_MB,
        max_tokens: int = 400,
        temperature: float = 0.2,
    ) -> None:
        super().__init__(max_tokens=max_tokens, temperature=temperature)
        self.model_path = Path(model_path).expanduser()
        self.threads = threads or _default_threads()
        self.context_window = context_window
        self.ram_budget_mb = ram_budget_mb
        self._llm: Any = None

    @property
    def model_id(self) -> str:
        return self.model_path.name

    def estimate_ram_mb(self) -> int:
        return estimate_model_ram_mb(self.model_path, context_window=self.context_window)

    def available(self) -> tuple[bool, str]:
        if not self.model_path.is_file():
            return False, f"no model file at {self.model_path}"
        try:
            with self.model_path.open("rb") as handle:
                if handle.read(4) != GGUF_MAGIC:
                    return False, f"{self.model_path.name} is not a GGUF file"
        except OSError as exc:  # pragma: no cover - unreadable path
            return False, f"could not read {self.model_path}: {exc}"
        estimate = self.estimate_ram_mb()
        if estimate > self.ram_budget_mb:
            return False, (
                f"about {estimate} MB of RAM needed but the budget is "
                f"{self.ram_budget_mb} MB — use a smaller quantisation or raise --ram-budget"
            )
        try:
            import llama_cpp  # noqa: F401
        except ImportError:
            return False, "llama-cpp-python is not installed (pip install llama-cpp-python)"
        return True, "ready"

    # -- loading ---------------------------------------------------------
    def _load(self) -> Any:
        if self._llm is not None:
            return self._llm
        import llama_cpp

        started = time.perf_counter()
        self._llm = llama_cpp.Llama(
            model_path=str(self.model_path),
            n_ctx=self.context_window,
            n_threads=self.threads,
            n_batch=128,
            verbose=False,
        )
        self.load_seconds = round(time.perf_counter() - started, 2)
        return self._llm

    def generate(self, messages: Sequence[dict[str, str]], *, context_text: str = "") -> str:
        llm = self._load()
        try:
            result = llm.create_chat_completion(
                messages=list(messages),
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )
            return str(result["choices"][0]["message"]["content"]).strip()
        except (AttributeError, KeyError, TypeError):
            # Older builds (and plain completion-only models) have no chat API.
            prompt = build_prompt(
                _question_from(messages), context_text, history=()
            )
            result = llm(prompt, max_tokens=self.max_tokens, temperature=self.temperature)
            return str(result["choices"][0]["text"]).strip()

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update(
            {
                "model_path": str(self.model_path),
                "threads": self.threads,
                "context_window": self.context_window,
                "estimated_ram_mb": self.estimate_ram_mb(),
                "ram_budget_mb": self.ram_budget_mb,
            }
        )
        return info


# ---------------------------------------------------------------------------
class OllamaBackend(LLMBackend):
    """A model served by an Ollama daemon — on loopback, and only on loopback."""

    name = "ollama"

    def __init__(
        self,
        model: str = OLLAMA_DEFAULT_MODEL,
        *,
        host: str = OLLAMA_DEFAULT_HOST,
        timeout: float = 120.0,
        transport: httpx.BaseTransport | None = None,
        max_tokens: int = 400,
        temperature: float = 0.2,
    ) -> None:
        super().__init__(max_tokens=max_tokens, temperature=temperature)
        if not is_loopback_host(host):
            raise UsageError(
                f"OllamaBackend refuses the non-local host {host!r}: this chat is for a "
                "model running on this machine, and pointing it elsewhere would send your "
                "footprint to someone else's server"
            )
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout
        self._transport = transport
        self._checked: tuple[bool, str] | None = None
        self._served: list[str] | None = None
        #: What ``auto`` resolved to, so the report names the model that answered.
        self._resolved: str | None = None

    @property
    def resolved_model(self) -> str:
        """The name sent to the daemon. ``auto`` resolves during :meth:`available`."""
        return self._resolved or self.model

    @property
    def model_id(self) -> str:
        return self.resolved_model

    def served_models(self) -> list[str]:
        """What the daemon has, as of the last probe (may probe now)."""
        if self._served is None:
            self.available()
        return list(self._served or [])

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.host, timeout=self.timeout, transport=self._transport
        )

    def available(self) -> tuple[bool, str]:
        if self._checked is not None:
            return self._checked
        try:
            with self._client() as client:
                response = client.get("/api/tags")
        except httpx.HTTPError as exc:
            self._checked = (False, f"no Ollama daemon at {self.host} ({exc.__class__.__name__})")
            return self._checked
        if response.status_code != 200:
            self._checked = (False, f"Ollama at {self.host} answered {response.status_code}")
            return self._checked
        try:
            models = [str(item.get("name", "")) for item in response.json().get("models", [])]
        except (ValueError, AttributeError):
            self._checked = (False, f"Ollama at {self.host} sent a response this code cannot read")
            return self._checked
        self._served = models
        if not models:
            self._checked = (False, "Ollama is running but has no models (ollama pull llama3.2:1b)")
            return self._checked
        if self.model == OLLAMA_AUTO:
            picked = _first_chat_model(models)
            if not picked:
                self._checked = (
                    False,
                    "Ollama only has embedding models, which cannot answer a question "
                    "(ollama pull llama3.2:1b)",
                )
                return self._checked
            self._resolved = picked
            self._checked = (
                True,
                f"ready (auto-picked {picked} of {len(models)} model(s) on this daemon)",
            )
            return self._checked
        if self.model not in models and f"{self.model}:latest" not in models:
            self._checked = (
                False,
                f"Ollama does not have {self.model} (available: {', '.join(models[:4])})",
            )
            return self._checked
        self._resolved = self.model
        self._checked = (True, "ready")
        return self._checked

    def generate(self, messages: Sequence[dict[str, str]], *, context_text: str = "") -> str:
        if self._resolved is None:
            ok, reason = self.available()
            if not ok:
                raise UsageError(f"Ollama cannot answer: {reason}")
        payload = {
            "model": self.resolved_model,
            "messages": list(messages),
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        with self._client() as client:
            response = client.post("/api/chat", json=payload)
        if response.status_code != 200:
            raise UsageError(f"Ollama answered {response.status_code}: {response.text[:200]}")
        try:
            data = response.json()
        except ValueError as exc:  # pragma: no cover - malformed daemon response
            raise UsageError("Ollama sent a response this code cannot read") from exc
        message = data.get("message") or {}
        text = str(message.get("content") or data.get("response") or "").strip()
        if not text:
            raise UsageError("Ollama returned an empty answer")
        return text

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"host": self.host, "local_only": True})
        return info


def _first_chat_model(models: Sequence[str]) -> str:
    """The first non-embedding model. Embedding models cannot answer a question."""
    for name in models:
        if name and "embed" not in name.lower():
            return name
    return ""


# ---------------------------------------------------------------------------
class CortexBackend(LLMBackend):
    """A GGUF served by **Cortex LLM Hoster** over its OpenAI-compatible API.

    Cortex supervises ``llama-server`` from llama.cpp and publishes
    ``/v1/chat/completions``. The wire format is the one OpenAI popularised;
    the model is a file on a machine you control, which is the whole difference
    between this and a hosted API — no prompt leaves your network, and no
    account or credit card is involved.

    The host rule mirrors Ollama's, with one deliberate exception: a private
    LAN address (10/8, 172.16/12, 192.168/16) is allowed *if you name it* with
    ``--cortex-host``, because running the model on a home server is a normal
    way to spare a 4 GB laptop. A public address is refused outright.
    """

    name = "cortex"

    def __init__(
        self,
        model: str = CORTEX_DEFAULT_MODEL,
        *,
        host: str = CORTEX_DEFAULT_HOST,
        api_key: str | None = None,
        allow_lan: bool = False,
        timeout: float = 120.0,
        transport: httpx.BaseTransport | None = None,
        max_tokens: int = 400,
        temperature: float = 0.2,
    ) -> None:
        super().__init__(max_tokens=max_tokens, temperature=temperature)
        refusal = cortex_host_refusal(host, allow_lan=allow_lan)
        if refusal:
            raise UsageError(refusal)
        self.model = model
        self.host = host.rstrip("/")
        self.allow_lan = allow_lan
        self.on_lan = not is_loopback_host(host)
        # Cortex secures itself with a bearer key when CORTEX_API_KEY is set.
        # Reading the environment is opt-out via api_key="" — unlike a hosted
        # API, this key unlocks our own server, not someone else's account.
        self._api_key = os.environ.get(CORTEX_API_KEY_ENV, "") if api_key is None else api_key
        self.timeout = timeout
        self._transport = transport
        self._checked: tuple[bool, str] | None = None
        self._served: list[str] | None = None
        self._resolved: str | None = None

    @property
    def resolved_model(self) -> str:
        """The model id sent to Cortex. ``auto`` resolves during :meth:`available`."""
        return self._resolved or self.model

    @property
    def model_id(self) -> str:
        return self.resolved_model

    def served_models(self) -> list[str]:
        """What Cortex serves, as of the last probe (may probe now)."""
        if self._served is None:
            self.available()
        return list(self._served or [])

    def _client(self) -> httpx.Client:
        headers = {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}
        return httpx.Client(
            base_url=self.host,
            timeout=self.timeout,
            transport=self._transport,
            headers=headers,
        )

    def available(self) -> tuple[bool, str]:
        if self._checked is not None:
            return self._checked
        try:
            with self._client() as client:
                response = client.get("/v1/models")
        except httpx.HTTPError as exc:
            self._checked = (False, f"no Cortex server at {self.host} ({exc.__class__.__name__})")
            return self._checked
        if response.status_code == 401:
            self._checked = (
                False,
                f"Cortex at {self.host} wants a bearer key (set {CORTEX_API_KEY_ENV})",
            )
            return self._checked
        if response.status_code != 200:
            self._checked = (False, f"Cortex at {self.host} answered {response.status_code}")
            return self._checked
        try:
            served = [str(item.get("id", "")) for item in response.json().get("data", [])]
        except (ValueError, AttributeError):
            self._checked = (
                False,
                f"Cortex at {self.host} sent a /v1/models response this code cannot read",
            )
            return self._checked
        self._served = [name for name in served if name]
        if not self._served:
            self._checked = (
                False,
                f"Cortex is running but serves no models (add a GGUF at {self.host})",
            )
            return self._checked
        if self.model == OLLAMA_AUTO:
            self._resolved = self._served[0]
            self._checked = (
                True,
                f"ready (auto-picked {self._resolved} of {len(self._served)} model(s) on Cortex)",
            )
            return self._checked
        if self.model not in self._served:
            self._checked = (
                False,
                f"Cortex does not serve {self.model} (available: {', '.join(self._served[:4])})",
            )
            return self._checked
        self._resolved = self.model
        self._checked = (True, "ready")
        return self._checked

    def generate(self, messages: Sequence[dict[str, str]], *, context_text: str = "") -> str:
        if self._resolved is None:
            ok, reason = self.available()
            if not ok:
                raise UsageError(f"Cortex cannot answer: {reason}")
        payload = {
            "model": self.resolved_model,
            "messages": list(messages),
            "stream": False,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        with self._client() as client:
            response = client.post("/v1/chat/completions", json=payload)
        if response.status_code == 401:
            raise UsageError(
                f"Cortex wants a bearer key (set {CORTEX_API_KEY_ENV} to the key you gave Cortex)"
            )
        if response.status_code != 200:
            raise UsageError(f"Cortex answered {response.status_code}: {response.text[:200]}")
        try:
            data = response.json()
        except ValueError as exc:  # pragma: no cover - malformed server response
            raise UsageError("Cortex sent a response this code cannot read") from exc
        choices = data.get("choices") or []
        if not choices:
            raise UsageError("Cortex returned no choices")
        first = choices[0] or {}
        message = first.get("message") or {}
        text = str(message.get("content") or first.get("text") or "").strip()
        if not text:
            raise UsageError("Cortex returned an empty answer")
        return text

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.update({"host": self.host, "local_only": not self.on_lan, "on_lan": self.on_lan})
        return info


#: The networks that mean "your own LAN". Listed literally rather than left to
#: the stdlib's private-network predicate, which is broader than RFC1918 — it
#: also answers True for the documentation ranges (203.0.113.0/24), link-local
#: (169.254.0.0/16) and other reserved blocks that are not your home network.
LAN_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def is_private_lan_host(host: str) -> bool:
    """True for an RFC1918 literal (10/8, 172.16/12, 192.168/16), not loopback.

    Hostnames are not resolved: a name could point anywhere, and a DNS answer
    is not something this decision should wait on or trust.
    """
    candidate = (host or "").strip().lower()
    if "://" in candidate:
        candidate = urlsplit(candidate).netloc
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]
    if candidate.startswith("["):  # [::1]:8624
        candidate = candidate[1:].split("]", 1)[0]
    else:
        candidate = candidate.split(":", 1)[0]
    candidate = candidate.strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    if address.is_loopback:
        return False
    return any(address in network for network in LAN_NETWORKS)


def cortex_host_refusal(host: str, *, allow_lan: bool) -> str:
    """Why a Cortex host is refused, or ``""`` when it is acceptable.

    Loopback always passes. A private LAN address passes only when the caller
    asked for it. Anything else — a public name, a cloud IP — is refused, for
    the same reason Ollama refuses it: a "local model" that is really an HTTP
    call to a company is data exfiltration with better wording.
    """
    if is_loopback_host(host):
        return ""
    if not is_private_lan_host(host):
        return (
            f"CortexBackend refuses the non-local host {host!r}: this chat is for a model "
            "on this machine or on your own LAN, and pointing it at a public address "
            "would send your footprint to someone else's server"
        )
    if not allow_lan:
        return (
            f"{host!r} is on your LAN but not on this machine. Name it on purpose with "
            "--cortex-host HOST: the model and your prompt then travel over your "
            "network instead of staying on loopback."
        )
    return ""


# ---------------------------------------------------------------------------
class ExtractiveBackend(LLMBackend):
    """Answers from the digest itself. No weights, no network, no invention.

    This is not a language model and does not claim to be one; it is the reason
    the chat still works on a machine that cannot afford a model, and the reason
    the test suite can assert exact answers. It ranks context lines against the
    question with a small keyword scorer and returns the winners with their ids.
    """

    name = "extractive"
    is_model = False

    def __init__(self, *, max_items: int = 8) -> None:
        super().__init__(max_tokens=0, temperature=0.0)
        self.max_items = max_items

    @property
    def model_id(self) -> str:
        return "keyword retrieval over the report"

    def available(self) -> tuple[bool, str]:
        return True, "always available (no model loaded)"

    def generate(self, messages: Sequence[dict[str, str]], *, context_text: str = "") -> str:
        question = _question_from(messages)
        return answer_from_context(question, context_text, max_items=self.max_items)

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info["note"] = "no model installed — this answers from the report by keyword retrieval"
        return info


# ---------------------------------------------------------------------------
def is_loopback_host(host: str) -> bool:
    """True for ``127.0.0.1``/``localhost``/``::1``, with or without a port/scheme."""
    candidate = (host or "").strip().lower()
    if "://" in candidate:
        candidate = urlsplit(candidate).netloc
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]
    if candidate.startswith("["):  # [::1]:11434
        candidate = candidate[1:].split("]", 1)[0]
    else:
        candidate = candidate.split(":", 1)[0]
    return candidate.strip("[]") in {"127.0.0.1", "localhost", "::1"}


def _default_threads() -> int:
    """Leave headroom on a small machine: at most 4 threads, at most cores - 1."""
    cores = os.cpu_count() or 2
    return max(1, min(4, cores - 1 if cores > 2 else cores))


def estimate_model_ram_mb(path: Path | str, *, context_window: int = 2048) -> int:
    """Rough resident size: file bytes plus the KV cache, in MB.

    Deliberately an over-estimate for a memory-mapped load — being told a model
    will not fit when it would is a much cheaper mistake than the reverse.
    """
    try:
        size = Path(path).stat().st_size
    except OSError:
        return 0
    weights = size / (1024 * 1024)
    kv_cache = context_window * 0.12  # ~0.12 MB per 1k tokens per 1B parameters
    overhead = 120.0
    return math.ceil(weights + kv_cache + overhead)


def recommend_models(ram_budget_mb: int = DEFAULT_RAM_BUDGET_MB) -> list[ModelRecommendation]:
    """The models that fit, smallest first."""
    return [item for item in _RECOMMENDATIONS if item.ram_mb <= ram_budget_mb] or [
        _RECOMMENDATIONS[0]
    ]


def model_doctor(
    model_path: Path | str | None = None,
    *,
    ram_budget_mb: int = DEFAULT_RAM_BUDGET_MB,
    context_window: int = 2048,
    ollama_model: str = OLLAMA_DEFAULT_MODEL,
    ollama_host: str = OLLAMA_DEFAULT_HOST,
    cortex_model: str = CORTEX_DEFAULT_MODEL,
    cortex_host: str = CORTEX_DEFAULT_HOST,
) -> dict[str, Any]:
    """What would answer a question on this machine right now, and why."""
    probes: list[LLMBackend] = []
    if model_path is not None:
        probes.append(
            LlamaCppBackend(
                model_path, ram_budget_mb=ram_budget_mb, context_window=context_window
            )
        )
    probes.append(
        OllamaBackend(ollama_model, host=ollama_host, transport=None)
        if is_loopback_host(ollama_host)
        else OllamaBackend(ollama_model, host=OLLAMA_DEFAULT_HOST)
    )
    # A LAN Cortex is only probed when the host was named on purpose; the doctor
    # should not go knocking on the network by itself.
    probes.append(
        CortexBackend(cortex_model, host=cortex_host, allow_lan=cortex_host != CORTEX_DEFAULT_HOST)
        if is_loopback_host(cortex_host) or is_private_lan_host(cortex_host)
        else CortexBackend(cortex_model, host=CORTEX_DEFAULT_HOST)
    )
    probes.append(ExtractiveBackend())
    backends = [probe.describe() for probe in probes]
    chosen = next((item["name"] for item in backends if item["available"]), None)
    file_info: dict[str, Any] = {}
    if model_path is not None:
        path = Path(model_path).expanduser()
        if path.is_file():
            with path.open("rb") as handle:
                magic = handle.read(4)
            file_info = {
                "path": str(path),
                "size_mb": round(path.stat().st_size / (1024 * 1024)),
                "gguf": magic == GGUF_MAGIC,
                "estimated_ram_mb": estimate_model_ram_mb(
                    path, context_window=context_window
                ),
                "fits_budget": estimate_model_ram_mb(path, context_window=context_window)
                <= ram_budget_mb,
            }
    return {
        "ram_budget_mb": ram_budget_mb,
        "context_window": context_window,
        "threads": _default_threads(),
        "selected": chosen,
        "model_file": file_info,
        "backends": backends,
        "recommendations": [item.to_dict() for item in recommend_models(ram_budget_mb)],
    }


def backend_status() -> list[dict[str, Any]]:
    """Every backend and whether it could answer, without loading anything."""
    return [
        OllamaBackend().describe(),
        CortexBackend().describe(),
        LlamaCppBackend(Path("model.gguf")).describe(),
        ExtractiveBackend().describe(),
    ]


BACKENDS = ("llama_cpp", "ollama", "cortex", "extractive")


def select_backend(
    *,
    prefer: str = "auto",
    model_path: Path | str | None = None,
    ollama_model: str = OLLAMA_DEFAULT_MODEL,
    ollama_host: str = OLLAMA_DEFAULT_HOST,
    cortex_model: str = CORTEX_DEFAULT_MODEL,
    cortex_host: str = CORTEX_DEFAULT_HOST,
    cortex_api_key: str | None = None,
    allow_cortex_lan: bool = False,
    threads: int | None = None,
    context_window: int = 2048,
    ram_budget_mb: int = DEFAULT_RAM_BUDGET_MB,
    max_tokens: int = 400,
    temperature: float = 0.2,
    transport: httpx.BaseTransport | None = None,
) -> tuple[LLMBackend, list[str]]:
    """Pick a backend. Returns ``(backend, notes)`` — the notes explain fallbacks.

    ``auto`` prefers, in order: the GGUF you named, an Ollama model on this
    machine, a model served by Cortex LLM Hoster, then retrieval. An explicit
    ``prefer`` that is unavailable raises rather than silently degrading, because
    a user who typed ``--backend llama_cpp`` wants to know it did not happen.
    """
    notes: list[str] = []
    candidates: dict[str, LLMBackend] = {
        "llama_cpp": LlamaCppBackend(
            model_path or Path("model.gguf"),
            threads=threads,
            context_window=context_window,
            ram_budget_mb=ram_budget_mb,
            max_tokens=max_tokens,
            temperature=temperature,
        ),
        "ollama": OllamaBackend(
            ollama_model,
            host=ollama_host,
            transport=transport,
            max_tokens=max_tokens,
            temperature=temperature,
        ),
        "cortex": CortexBackend(
            cortex_model,
            host=cortex_host,
            api_key=cortex_api_key,
            allow_lan=allow_cortex_lan,
            transport=transport,
            max_tokens=max_tokens,
            temperature=temperature,
        ),
        "extractive": ExtractiveBackend(),
    }
    order = ["llama_cpp", "ollama", "cortex", "extractive"] if prefer == "auto" else [prefer]
    if prefer != "auto" and prefer not in candidates:
        raise UsageError(f"unknown backend {prefer!r}; choose from {', '.join(BACKENDS)} or auto")

    first_choice = order[0]
    first_reason = ""
    for name in order:
        backend = candidates[name]
        ok, reason = backend.available()
        if ok:
            if name != first_choice:
                notes.append(f"{first_choice} unavailable ({first_reason}), using {name}")
            return backend, notes
        notes.append(f"{name}: {reason}")
        if not first_reason:
            first_reason = reason
        if prefer != "auto":
            raise UsageError(f"--backend {prefer} cannot be used: {reason}")
    return candidates["extractive"], notes


# ---------------------------------------------------------------------------
_STOPWORDS = frozenset(
    (
        "a", "an", "and", "are", "as", "at", "be", "by", "can", "did", "do", "does", "for",
        "from", "had", "has", "have", "how", "i", "in", "is", "it", "its", "me", "my", "of",
        "on", "or", "should", "so", "than", "that", "the", "their", "them", "then", "there",
        "these", "this", "to", "was", "were", "what", "when", "where", "which", "who", "why",
        "will", "with", "you", "your",
    )
)


def _question_from(messages: Sequence[dict[str, str]]) -> str:
    """Recover the question from the assembled messages (last user turn)."""
    for message in reversed(list(messages)):
        if message.get("role") == "user":
            content = str(message.get("content", ""))
            marker = "QUESTION:"
            return content.split(marker, 1)[1].strip() if marker in content else content.strip()
    return ""


def _tokens(text: str) -> list[str]:
    cleaned = "".join(char if char.isalnum() else " " for char in (text or "").lower())
    return [word for word in cleaned.split() if word and word not in _STOPWORDS]


def answer_from_context(question: str, context_text: str, *, max_items: int = 8) -> str:
    """Rank context lines against the question and return them with their ids."""
    lines = [line.strip() for line in (context_text or "").splitlines() if line.strip()]
    if not lines:
        return (
            "There is no context to answer from: no stored scans were found and the "
            "watchlist is empty. Run a scan first, then ask again."
        )
    question_tokens = set(_tokens(question))
    scored: list[tuple[float, int, str]] = []
    for position, line in enumerate(lines):
        body = line.lower()
        overlap = sum(1 for token in question_tokens if token in body)
        # Prefer what a security question usually wants: hits, then gaps.
        weight = 0.0
        if "[F" in line:
            weight = 2.0 if "CONFIRMED" in line or "HIGH" in line else 1.0
        elif "[G" in line or "[W" in line:
            weight = 0.6
        elif "[B" in line:
            weight = 1.2
        elif "[E" in line:
            weight = 0.8
        elif "[S" in line:
            weight = 0.3
        score = overlap * 3.0 + weight
        scored.append((score, -position, line))
    scored.sort(reverse=True)
    chosen = [line for score, _, line in scored[:max_items] if score > 0] or [
        line for _, _, line in scored[: min(3, len(scored))]
    ]

    headline = (
        "No local model is installed, so this is a direct answer from your report "
        "(keyword retrieval, not generation). These are the lines that match "
        f"“{question.strip()}”:"
    )
    return headline + "\n" + "\n".join(chosen)
