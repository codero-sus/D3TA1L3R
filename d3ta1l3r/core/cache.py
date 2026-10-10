"""Optional on-disk response cache.

Why a cache is a privacy feature: repeating a scan while tuning filters should
not re-query third-party sites about you. With ``--cache`` the second run reads
from disk, so the remote service sees one request instead of ten.

Cache entries are truncated copies of public responses keyed by a hash of the
request, stored under ``<cache_dir>/requests/``. They may still contain your
own profile data — keep the directory private, or pass ``--no-cache`` after the
audit and delete it.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["CacheEntry", "ResponseCache"]

_MAX_ENTRY_BYTES = 512 * 1024


@dataclass(slots=True)
class CacheEntry:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    fetched_at: float
    final_url: str
    redirects: list[str]

    @property
    def age(self) -> float:
        return max(0.0, time.time() - self.fetched_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "body": self.body,
            "fetched_at": self.fetched_at,
            "final_url": self.final_url,
            "redirects": self.redirects,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheEntry:
        return cls(
            url=data["url"],
            status=int(data["status"]),
            headers=dict(data.get("headers") or {}),
            body=data.get("body", ""),
            fetched_at=float(data.get("fetched_at") or 0),
            final_url=data.get("final_url") or data["url"],
            redirects=list(data.get("redirects") or []),
        )


class ResponseCache:
    """Tiny JSON-file cache. No external store, no background threads."""

    def __init__(self, directory: Path, ttl: float = 86_400.0) -> None:
        self.directory = Path(directory).expanduser()
        self.ttl = ttl
        self.directory.mkdir(parents=True, exist_ok=True)
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key_for(url: str, *, method: str = "GET", accept: str = "") -> str:
        material = f"{method.upper()} {url} {accept}".encode()
        return hashlib.sha256(material).hexdigest()[:32]

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def get(self, key: str) -> CacheEntry | None:
        path = self._path(key)
        if not path.is_file():
            self.misses += 1
            return None
        try:
            raw = path.read_text(encoding="utf-8")
            entry = CacheEntry.from_dict(json.loads(raw))
        except (OSError, ValueError, KeyError):
            self.misses += 1
            return None
        if self.ttl and entry.age > self.ttl:
            self.misses += 1
            return None
        self.hits += 1
        return entry

    def set(self, key: str, entry: CacheEntry) -> None:
        payload = json.dumps(entry.to_dict(), ensure_ascii=False)
        if len(payload.encode("utf-8")) > _MAX_ENTRY_BYTES:
            return  # oversized responses are not worth caching
        path = self._path(key)
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(path)
        except OSError:
            tmp.unlink(missing_ok=True)

    def purge(self) -> int:
        removed = 0
        for path in self.directory.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:  # pragma: no cover - best effort
                pass
        return removed

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ResponseCache(dir={self.directory!s}, hits={self.hits}, misses={self.misses})"
