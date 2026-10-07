"""A catalogue of local models, and downloads straight from Hugging Face.

Two things this module is careful about:

**Sizes are arithmetic, not vibes.** Every entry carries a download size and an
estimated resident size, and :func:`local_ram_mb` reads the machine's own memory
so ``models pull`` can say "this will not fit" *before* spending 4 GB of disk on
a download that then fails to load. The estimates are deliberately pessimistic:
a model that would have fitted and refuses is a smaller mistake than one that
swaps a 4 GB machine to death.

**Nothing is downloaded implicitly.** ``models pull`` is the only thing here that
touches the network, it prints the URL and the size first, and the file lands in
``<models>/<id>.gguf`` only after its length (and, when the Hub reports one, its
SHA-256) has been checked. A partial download is left as ``.part`` and can be
resumed with a ranged request, so a dropped connection costs the remaining bytes
rather than the whole file.

What leaves the machine when you pull a model is the model id and the request
itself — the same thing any download reveals. No report, no identifier and no
vault content is ever part of a model request; the code has no path that could
send one.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

import httpx

from ..errors import UsageError

__all__ = [
    "CATALOG",
    "HF_HOST",
    "ModelSpec",
    "custom_catalog_path",
    "default_models_dir",
    "describe_disk",
    "download_model",
    "filter_models",
    "find_model",
    "format_bytes",
    "hf_search",
    "list_downloaded",
    "load_custom_models",
    "local_ram_mb",
    "model_path",
    "resolve_downloaded_model",
    "save_custom_model",
    "spec_from_reference",
    "total_size_mb",
]

HF_HOST = "https://huggingface.co"
_ENV_MODELS_DIR = "D3TA1L3R_MODELS"
_ENV_HF_TOKEN = "HF_TOKEN"  # a name, not a secret; read-only use
_CHUNK = 1024 * 256
ProgressCallback = Callable[[str, int, int], None]
"""``(phase, done_bytes, total_bytes)``; ``total`` is ``-1`` when unknown."""


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """One downloadable GGUF file, sized honestly."""

    id: str
    name: str
    repo: str
    filename: str
    parameters: str
    quant: str
    size_mb: int
    ram_mb: int
    context: int = 4096
    license: str = "unknown"
    tags: tuple[str, ...] = ()
    note: str = ""
    revision: str = "main"
    official: bool = True
    """False for entries the operator added themselves (``models add``)."""

    @property
    def url(self) -> str:
        return f"{HF_HOST}/{self.repo}/resolve/{self.revision}/{self.filename}"

    @property
    def reference(self) -> str:
        """The ``repo/filename`` form accepted by ``models add`` and ``ask --model``."""
        return f"{self.repo}/{self.filename}"

    @property
    def is_powerful(self) -> bool:
        return "powerful" in self.tags

    @property
    def fits_4gb(self) -> bool:
        return self.ram_mb <= 4096

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.update(
            {
                "url": self.url,
                "reference": self.reference,
                "fits_4gb": self.fits_4gb,
                "is_powerful": self.is_powerful,
                "tags": list(self.tags),
            }
        )
        return payload

    def to_json(self) -> dict[str, Any]:
        """The subset written into a custom catalogue file."""
        return {
            "id": self.id,
            "name": self.name,
            "repo": self.repo,
            "filename": self.filename,
            "parameters": self.parameters,
            "quant": self.quant,
            "size_mb": self.size_mb,
            "ram_mb": self.ram_mb,
            "context": self.context,
            "license": self.license,
            "tags": list(self.tags),
            "note": self.note,
            "revision": self.revision,
            "official": False,
        }


#: Curated GGUF builds. Sizes are the published file sizes rounded up; RAM
#: includes the KV cache for the model's default context plus runtime overhead,
#: so it is an over-estimate by design. Sorted below rather than by hand, so an
#: entry added in the wrong place cannot quietly break "smallest first".
_CATALOG_ENTRIES: tuple[ModelSpec, ...] = (
    ModelSpec(
        id="tinyllama-1.1b-chat-q4_k_m",
        name="TinyLlama 1.1B Chat",
        repo="TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF",
        filename="tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
        parameters="1.1B",
        quant="Q4_K_M",
        size_mb=670,
        ram_mb=900,
        context=2048,
        license="apache-2.0",
        tags=("small", "fast", "4gb"),
        note="smallest useful chat model; answers short questions reliably, prose is plain",
    ),
    ModelSpec(
        id="qwen2.5-1.5b-instruct-q4_k_m",
        name="Qwen2.5 1.5B Instruct",
        repo="Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        filename="qwen2.5-1.5b-instruct-q4_k_m.gguf",
        parameters="1.5B",
        quant="Q4_K_M",
        size_mb=1120,
        ram_mb=1500,
        context=4096,
        license="apache-2.0",
        tags=("small", "4gb", "recommended"),
        note="best all-round choice on a 4 GB machine; follows the cite-the-id rules well",
    ),
    ModelSpec(
        id="llama-3.2-3b-instruct-q4_k_m",
        name="Llama 3.2 3B Instruct",
        repo="bartowski/Llama-3.2-3B-Instruct-GGUF",
        filename="Llama-3.2-3B-Instruct-Q4_K_M.gguf",
        parameters="3B",
        quant="Q4_K_M",
        size_mb=2020,
        ram_mb=2400,
        context=4096,
        license="llama3.2",
        tags=("4gb", "balanced"),
        note="noticeably better prose; comfortable on 4 GB with little else open",
    ),
    ModelSpec(
        id="phi-3-mini-4k-instruct-q4",
        name="Phi-3 Mini 4K Instruct",
        repo="microsoft/Phi-3-mini-4k-instruct-gguf",
        filename="Phi-3-mini-4k-instruct-q4.gguf",
        parameters="3.8B",
        quant="Q4",
        size_mb=2300,
        ram_mb=2700,
        context=4096,
        license="mit",
        tags=("4gb", "balanced", "reasoning"),
        note="strong at short reasoning; the practical upper bound for 4 GB",
    ),
    ModelSpec(
        id="mistral-7b-instruct-v0.3-q4_k_m",
        name="Mistral 7B Instruct v0.3",
        repo="bartowski/Mistral-7B-Instruct-v0.3-GGUF",
        filename="Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
        parameters="7B",
        quant="Q4_K_M",
        size_mb=4370,
        ram_mb=5400,
        context=8192,
        license="apache-2.0",
        tags=("powerful", "8gb"),
        note="the classic 7B; needs ~6 GB free RAM, so not a 4 GB machine",
    ),
    ModelSpec(
        id="qwen2.5-7b-instruct-q4_k_m",
        name="Qwen2.5 7B Instruct",
        repo="Qwen/Qwen2.5-7B-Instruct-GGUF",
        filename="qwen2.5-7b-instruct-q4_k_m.gguf",
        parameters="7B",
        quant="Q4_K_M",
        size_mb=4680,
        ram_mb=5900,
        context=8192,
        license="apache-2.0",
        tags=("powerful", "8gb", "recommended-powerful"),
        note="best quality-per-byte at 7B; excellent at long, evidence-heavy answers",
    ),
    ModelSpec(
        id="llama-3.1-8b-instruct-q4_k_m",
        name="Llama 3.1 8B Instruct",
        repo="bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
        filename="Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
        parameters="8B",
        quant="Q4_K_M",
        size_mb=4920,
        ram_mb=6100,
        context=8192,
        license="llama3.1",
        tags=("powerful", "8gb"),
        note="strong instruction following; prefers 12 GB of RAM to be comfortable",
    ),
    ModelSpec(
        id="qwen2.5-14b-instruct-q4_k_m",
        name="Qwen2.5 14B Instruct",
        repo="Qwen/Qwen2.5-14B-Instruct-GGUF",
        filename="qwen2.5-14b-instruct-q4_k_m.gguf",
        parameters="14B",
        quant="Q4_K_M",
        size_mb=8990,
        ram_mb=10500,
        context=8192,
        license="apache-2.0",
        tags=("powerful", "16gb"),
        note="genuinely capable summariser; 16 GB machine with nothing else running",
    ),
    ModelSpec(
        id="qwen2.5-32b-instruct-q4_k_m",
        name="Qwen2.5 32B Instruct",
        repo="Qwen/Qwen2.5-32B-Instruct-GGUF",
        filename="qwen2.5-32b-instruct-q4_k_m.gguf",
        parameters="32B",
        quant="Q4_K_M",
        size_mb=19800,
        ram_mb=23000,
        context=8192,
        license="apache-2.0",
        tags=("powerful", "32gb", "workstation"),
        note="near-frontier quality locally; needs a workstation with ~24 GB free",
    ),
    ModelSpec(
        id="deepseek-r1-distill-qwen-7b-q4_k_m",
        name="DeepSeek-R1 Distill Qwen 7B",
        repo="bartowski/DeepSeek-R1-Distill-Qwen-7B-GGUF",
        filename="DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf",
        parameters="7B",
        quant="Q4_K_M",
        size_mb=4680,
        ram_mb=5900,
        context=8192,
        license="mit",
        tags=("powerful", "8gb", "reasoning"),
        note="reasoning-tuned; slower, better at multi-step questions about a report",
    ),
)

#: The catalogue as callers see it: cheapest-to-run first.
CATALOG: tuple[ModelSpec, ...] = tuple(
    sorted(_CATALOG_ENTRIES, key=lambda spec: (spec.ram_mb, spec.id))
)


def default_models_dir() -> Path:
    """``$D3TA1L3R_MODELS``, else ``~/.cache/d3ta1l3r/models``.

    A cache directory rather than a project directory: models are large, public
    and worth reusing across repositories.
    """
    override = os.environ.get(_ENV_MODELS_DIR, "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".cache" / "d3ta1l3r" / "models"


def custom_catalog_path(models_dir: Path | str | None = None) -> Path:
    return Path(models_dir or default_models_dir()) / "catalog.json"


def model_path(spec: ModelSpec, models_dir: Path | str | None = None) -> Path:
    return Path(models_dir or default_models_dir()) / f"{spec.id}.gguf"


def format_bytes(count: int) -> str:
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TiB"  # pragma: no cover - unreachable


def format_mb(mb: int) -> str:
    return f"{mb / 1024:.1f} GB" if mb >= 1024 else f"{mb} MB"


def total_size_mb(specs: Iterable[ModelSpec]) -> int:
    return sum(spec.size_mb for spec in specs)


def local_ram_mb() -> int | None:
    """Total physical memory in MB, or ``None`` when the platform will not say."""
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        try:
            for line in meminfo.read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
        except (OSError, ValueError, IndexError):  # pragma: no cover - unusual /proc
            pass
    try:  # pragma: no cover - macOS and other POSIX
        pages = os.sysconf("SC_PHYS_PAGES")
        size = os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and size > 0:
            return int(pages * size // (1024 * 1024))
    except (ValueError, OSError, AttributeError):
        pass
    return None  # pragma: no cover - Windows


def describe_disk(models_dir: Path | str | None = None) -> dict[str, Any]:
    """Free space where models would land, plus what is already there."""
    directory = Path(models_dir or default_models_dir())
    probe = directory if directory.exists() else directory.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        usage = shutil.disk_usage(probe)
        free_mb, total = int(usage.free // (1024 * 1024)), int(usage.total // (1024 * 1024))
    except OSError:  # pragma: no cover - unusual filesystems
        free_mb, total = -1, -1
    return {
        "directory": str(directory),
        "exists": directory.exists(),
        "free_mb": free_mb,
        "total_mb": total,
        "ram_mb": local_ram_mb(),
    }


# ---------------------------------------------------------------------------
# catalogue assembly
# ---------------------------------------------------------------------------
def load_custom_models(models_dir: Path | str | None = None) -> tuple[ModelSpec, ...]:
    """Models the operator added with ``models add`` (an empty tuple if none)."""
    path = custom_catalog_path(models_dir)
    if not path.is_file():
        return ()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UsageError(f"{path} is not readable as JSON: {exc}") from exc
    entries = raw.get("models") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise UsageError(f"{path} should hold a list of models")
    specs: list[ModelSpec] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            specs.append(replace(_spec_from_dict(entry), official=False))
        except (TypeError, ValueError) as exc:
            raise UsageError(f"{path} has an entry this code cannot read: {exc}") from exc
    return tuple(specs)


def _spec_from_dict(data: dict[str, Any]) -> ModelSpec:
    known = set(ModelSpec.__dataclass_fields__)  # type: ignore[attr-defined]
    payload = {k: v for k, v in data.items() if k in known}
    payload["tags"] = tuple(payload.get("tags") or ())
    return ModelSpec(**payload)


def save_custom_model(spec: ModelSpec, models_dir: Path | str | None = None) -> Path:
    """Add or replace a custom entry in the catalogue file."""
    directory = Path(models_dir or default_models_dir())
    directory.mkdir(parents=True, exist_ok=True)
    path = custom_catalog_path(directory)
    existing = [item for item in load_custom_models(directory) if item.id != spec.id]
    existing.append(replace(spec, official=False))
    payload = {"models": [item.to_json() for item in sorted(existing, key=lambda s: s.id)]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def remove_custom_model(model_id: str, models_dir: Path | str | None = None) -> bool:
    directory = Path(models_dir or default_models_dir())
    existing = load_custom_models(directory)
    remaining = [item for item in existing if item.id != model_id]
    if len(remaining) == len(existing):
        return False
    path = custom_catalog_path(directory)
    payload = {"models": [item.to_json() for item in remaining]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return True


def catalogue(models_dir: Path | str | None = None) -> tuple[ModelSpec, ...]:
    """Curated entries plus the operator's own, custom ones last."""
    return CATALOG + load_custom_models(models_dir)


def spec_from_reference(
    reference: str,
    *,
    repo: str = "",
    filename: str = "",
    model_id: str = "",
    name: str = "",
    parameters: str = "",
    quant: str = "unknown",
    size_mb: int = 0,
    ram_mb: int = 0,
    context: int = 4096,
    license: str = "unknown",
    tags: Sequence[str] = (),
    note: str = "",
    revision: str = "main",
) -> ModelSpec:
    """Build a spec for any GGUF on the Hub.

    ``reference`` is either ``repo/filename.gguf`` or a bare filename with
    ``--repo`` given separately. Sizes default to ``0`` meaning "measure at
    download time", which is what :func:`download_model` does when the server
    reports a length.
    """
    text = (reference or "").strip()
    if not repo and not filename:
        if "/" not in text:
            raise UsageError(
                "give the model as REPO/FILE.gguf (for example "
                "TheBloke/dolphin-2.9-llama3-8b-GGUF/dolphin-2.9-llama3-8b.Q4_K_M.gguf)"
            )
        repo, _, filename = text.rpartition("/")
        # When only two slash-separated parts arrive, the file lives in the repo.
        if "/" not in repo and not filename.endswith(".gguf"):
            raise UsageError(
                "give the model as REPO/FILE.gguf so the file inside the repository is clear"
            )
    repo = (repo or text).strip().strip("/")
    filename = (filename or "").strip()
    if not repo or "/" not in repo:
        raise UsageError(f"{repo!r} does not look like a Hugging Face repository (owner/name)")
    if not filename:
        raise UsageError("a filename is required (the .gguf file inside the repository)")
    if not filename.lower().endswith(".gguf"):
        raise UsageError(f"{filename!r} is not a .gguf file")
    derived_id = model_id or _slug_id(f"{repo.split('/')[-1]}-{filename}")
    return ModelSpec(
        id=derived_id,
        name=name or f"{repo.split('/')[-1]} ({filename.rsplit('/', 1)[-1]})",
        repo=repo,
        filename=filename,
        parameters=parameters or "unknown",
        quant=quant or "unknown",
        size_mb=max(0, int(size_mb)),
        ram_mb=max(0, int(ram_mb)) or max(0, int(size_mb)),
        context=max(512, int(context)),
        license=license or "unknown",
        tags=tuple(dict.fromkeys((*tags, "custom"))),
        note=note,
        revision=revision or "main",
        official=False,
    )


def _slug_id(value: str) -> str:
    keep = [char.lower() if char.isalnum() else "-" for char in value]
    slug = "".join(keep)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")[:80]


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------
def filter_models(
    query: str = "",
    *,
    specs: Sequence[ModelSpec] | None = None,
    fits_mb: int | None = None,
    tag: str = "",
    powerful_only: bool = False,
    downloaded_dir: Path | str | None = None,
) -> list[ModelSpec]:
    """Search the catalogue by substring, memory, tag, or "what is already here"."""
    rows = list(specs if specs is not None else catalogue())
    if query:
        needle = query.strip().lower()
        rows = [
            spec
            for spec in rows
            if needle in spec.id.lower()
            or needle in spec.name.lower()
            or needle in spec.repo.lower()
            or needle in spec.parameters.lower()
            or needle in spec.quant.lower()
            or any(needle in item for item in spec.tags)
        ]
    if fits_mb is not None:
        rows = [spec for spec in rows if spec.ram_mb <= fits_mb]
    if tag:
        rows = [spec for spec in rows if tag.lower() in spec.tags]
    if powerful_only:
        rows = [spec for spec in rows if spec.is_powerful]
    if downloaded_dir is not None:
        rows = [spec for spec in rows if model_path(spec, downloaded_dir).is_file()]
    return sorted(rows, key=lambda spec: (spec.ram_mb, spec.id))


def find_model(
    query: str, *, specs: Sequence[ModelSpec] | None = None
) -> ModelSpec | None:
    """Exact id, then ``repo/filename``, then a unique substring; ``None`` if unsure."""
    rows = list(specs if specs is not None else catalogue())
    needle = (query or "").strip()
    if not needle:
        return None
    lowered = needle.lower()
    for spec in rows:
        if spec.id == lowered or spec.reference == needle:
            return spec
    matches = [
        spec
        for spec in rows
        if lowered in spec.id.lower()
        or lowered in spec.name.lower()
        or lowered in spec.reference.lower()
    ]
    return matches[0] if len(matches) == 1 else None


def list_downloaded(models_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Every ``*.gguf`` in the models directory, with its size and catalogue match."""
    directory = Path(models_dir or default_models_dir())
    if not directory.is_dir():
        return []
    known = {spec.id: spec for spec in catalogue(directory)}
    found: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.gguf")):
        spec = known.get(path.stem)
        size = path.stat().st_size
        found.append(
            {
                "path": str(path),
                "file": path.name,
                "id": path.stem,
                "size_mb": round(size / (1024 * 1024)),
                "catalogued": spec is not None,
                "name": spec.name if spec else path.stem,
                "ram_mb": spec.ram_mb if spec else None,
                "parameters": spec.parameters if spec else "",
                "quant": spec.quant if spec else "",
            }
        )
    return found


def resolve_downloaded_model(
    models_dir: Path | str | None = None, *, ram_budget_mb: int | None = None
) -> Path | None:
    """Best downloaded model for ``ask --model auto``: largest that still fits.

    Largest-that-fits rather than first-found, because the user downloaded it
    deliberately and a 7B answer is better than a 1.1B one when the machine can
    hold it.
    """
    directory = Path(models_dir or default_models_dir())
    if not directory.is_dir():
        return None
    budget = ram_budget_mb or local_ram_mb() or 4096
    candidates: list[tuple[int, Path]] = []
    for path in directory.glob("*.gguf"):
        spec = find_model(path.stem)
        estimate = spec.ram_mb if spec else round(path.stat().st_size / (1024 * 1024)) + 400
        if estimate <= budget:
            candidates.append((estimate, path))
    if not candidates:
        return None
    return max(candidates, key=lambda pair: pair[0])[1]


# ---------------------------------------------------------------------------
# Hugging Face
# ---------------------------------------------------------------------------
def _client(transport: httpx.BaseTransport | None = None, timeout: float = 30.0) -> httpx.Client:
    headers = {"User-Agent": "D3TA1L3R/0.1.0 (local model downloader)"}
    token = os.environ.get(_ENV_HF_TOKEN, "").strip()
    if token:
        # Present only if the operator set it: gated repositories need it, and
        # nothing else here reads or stores the token.
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(
        timeout=timeout, headers=headers, transport=transport, follow_redirects=True
    )


def hf_search(
    query: str, *, limit: int = 10, transport: httpx.BaseTransport | None = None
) -> list[dict[str, Any]]:
    """Live search on the Hub for GGUF repositories.

    Optional by design: the curated catalogue works with no network at all, so a
    blocked or offline machine loses a convenience, not a feature.
    """
    params = {"search": query, "filter": "gguf", "limit": str(max(1, min(limit, 50)))}
    try:
        with _client(transport) as client:
            response = client.get(f"{HF_HOST}/api/models", params=params)
    except httpx.HTTPError as exc:
        raise UsageError(
            f"could not reach {HF_HOST} ({exc.__class__.__name__}). The curated catalogue "
            "(`d3ta1l3r models list`) works offline; live search needs a network route."
        ) from exc
    if response.status_code == 401:
        raise UsageError("Hugging Face refused the request (401) — check HF_TOKEN if you set one")
    if response.status_code != 200:
        raise UsageError(f"Hugging Face answered {response.status_code} for the search")
    try:
        payload = response.json()
    except ValueError as exc:
        raise UsageError("Hugging Face sent a search response this code cannot read") from exc
    if not isinstance(payload, list):
        raise UsageError("Hugging Face sent an unexpected search response shape")
    out: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "repo": item.get("id", ""),
                "downloads": item.get("downloads", 0),
                "likes": item.get("likes", 0),
                "updated": (item.get("lastModified") or "")[:10],
                "gated": bool(item.get("gated", False)),
                "url": f"{HF_HOST}/{item.get('id', '')}",
            }
        )
    return out


def hf_file_metadata(
    spec: ModelSpec, *, transport: httpx.BaseTransport | None = None, timeout: float = 30.0
) -> dict[str, Any]:
    """Size (and SHA-256 when the Hub reports one) for one file in a repository.

    Used to check a download against the Hub's own numbers rather than trusting
    whatever arrived over the wire.
    """
    url = f"{HF_HOST}/api/models/{spec.repo}/tree/{spec.revision}"
    try:
        with _client(transport, timeout=timeout) as client:
            response = client.get(url, params={"recursive": "false"})
    except httpx.HTTPError as exc:
        raise UsageError(f"could not reach {HF_HOST}: {exc.__class__.__name__}") from exc
    if response.status_code != 200:
        raise UsageError(
            f"Hugging Face answered {response.status_code} for {spec.repo} — check the "
            "repository name, or set HF_TOKEN for a gated one"
        )
    try:
        rows = response.json()
    except ValueError as exc:  # pragma: no cover - malformed response
        raise UsageError("Hugging Face sent file metadata this code cannot read") from exc
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and row.get("path") == spec.filename:
            lfs = row.get("lfs") or {}
            return {
                "size": int(row.get("size") or lfs.get("size") or 0),
                "sha256": str(lfs.get("sha256") or row.get("oid") or ""),
                "url": spec.url,
            }
    return {"size": 0, "sha256": "", "url": spec.url}


def _looks_like_html(head: bytes) -> bool:
    lowered = head.lstrip().lower()
    return lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html")


def download_model(
    spec: ModelSpec,
    models_dir: Path | str | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
    progress: ProgressCallback | None = None,
    resume: bool = True,
    verify: bool = True,
    force: bool = False,
    timeout: float = 30.0,
    expected_sha256: str = "",
) -> Path:
    """Stream one GGUF into the models directory. Returns the final path.

    The file appears at its final name only after the length (and hash, when
    known) check passes, so an interrupted or truncated download can never be
    mistaken for a usable model. With ``resume``, a previous ``.part`` is
    continued with a ranged request.
    """
    directory = Path(models_dir or default_models_dir())
    directory.mkdir(parents=True, exist_ok=True)
    final = model_path(spec, directory)
    part = final.with_suffix(final.suffix + ".part")

    if final.is_file() and not force:
        if spec.size_mb and abs(final.stat().st_size - spec.size_mb * 1024 * 1024) > (
            spec.size_mb * 1024 * 1024 * 0.05
        ):
            raise UsageError(
                f"{final} exists but does not match the catalogue size — re-run with --force "
                "to download it again, or `models remove` it"
            )
        return final

    headers: dict[str, str] = {}
    offset = 0
    if part.is_file() and resume:
        offset = part.stat().st_size
        if offset:
            headers["Range"] = f"bytes={offset}-"
    mode = "ab" if offset else "wb"
    if progress:
        progress("start", offset, -1)

    digest = hashlib.sha256()
    if offset and part.is_file():  # hash what is already on disk so the check works
        with part.open("rb") as existing:
            for chunk in iter(lambda: existing.read(_CHUNK), b""):
                digest.update(chunk)

    try:
        with (
            _client(transport, timeout=timeout) as client,
            client.stream("GET", spec.url, headers=headers) as response,
        ):
                if response.status_code == 416:
                    raise UsageError(
                        f"the server says {spec.url} has no remaining bytes — delete {part} "
                        "and try again"
                    )
                if response.status_code not in (200, 206):
                    raise UsageError(
                        f"Hugging Face answered {response.status_code} for {spec.url} "
                        "(404 usually means the file name is wrong, 401/403 that the "
                        "repository is gated and needs HF_TOKEN)"
                    )
                resumed = response.status_code == 206
                if offset and not resumed:
                    # The server ignored our Range: start over rather than append
                    # a second copy of the file to the first.
                    offset, mode = 0, "wb"
                    digest = hashlib.sha256()
                total = _content_length(response, offset)
                done = offset
                with part.open(mode) as handle:
                    for chunk in response.iter_bytes(_CHUNK):
                        if not chunk:
                            continue
                        if done == 0 and len(chunk) >= 16 and _looks_like_html(chunk[:64]):
                            raise UsageError(
                                f"{spec.url} returned a web page instead of a model — the "
                                "repository or file name is probably wrong"
                            )
                        handle.write(chunk)
                        digest.update(chunk)
                        done += len(chunk)
                        if progress:
                            progress("download", done, total)
    except httpx.HTTPError as exc:
        raise UsageError(
            f"the download of {spec.url} failed ({exc.__class__.__name__}). It stopped at "
            f"{format_bytes(part.stat().st_size if part.is_file() else 0)}; re-run to resume."
        ) from exc

    size = part.stat().st_size
    if total > 0 and size != total:
        raise UsageError(
            f"the download is incomplete: {format_bytes(size)} of {format_bytes(total)}. "
            f"Re-run to resume from {part.name}."
        )

    if progress:
        progress("verify", size, size)
    if verify:
        wanted = (expected_sha256 or "").lower()
        if wanted and digest.hexdigest() != wanted:
            part.unlink(missing_ok=True)
            raise UsageError(
                f"{spec.filename} does not match the SHA-256 the Hub reports — the file was "
                "discarded rather than handed to the model loader"
            )

    final.unlink(missing_ok=True)
    part.rename(final)
    if progress:
        progress("done", size, size)
    return final


def _content_length(response: httpx.Response, offset: int) -> int:
    raw = response.headers.get("content-length", "")
    try:
        length = int(raw)
    except ValueError:
        return -1
    # A 206 reports the remaining bytes; the total is offset + remaining.
    return length + offset if response.status_code == 206 else length


def _ordered_unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))
