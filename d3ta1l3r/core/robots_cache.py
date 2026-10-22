"""A robots.txt cache that survives the process.

robots.txt is roughly half of the traffic in a broad scan: 944 sources meant
944 probes and 924 robots.txt fetches. Within one run those are already
de-duplicated per origin, but nothing survives between runs, so a second scan
of the same person pays the whole 924 again for files that almost never change.

This caches them on disk. RFC 9309 §2.3.1.4 says a crawler should refresh
robots.txt no more than once every 24 hours, and the TTL here defaults to
exactly that — it is a compliance-recommended interval, not a number picked for
speed.

What is stored is the *parsed decision inputs*, not just the bytes: the raw
text, the HTTP status, and when it was fetched. Replaying a 404 as "no
rules" and a 403 as "disallowed" has to survive a restart, or the cache would
silently change what the tool is allowed to do.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

__all__ = ["DEFAULT_ROBOTS_TTL", "RobotsDiskCache"]

#: RFC 9309 recommends refreshing robots.txt at most once a day.
DEFAULT_ROBOTS_TTL = 86_400.0

_SCHEMA = 1


@dataclass(slots=True)
class CachedRobots:
    """One origin's robots.txt, as fetched."""

    origin: str
    status: int
    text: str
    fetched_at: float  # epoch seconds

    def is_fresh(self, ttl: float) -> bool:
        """Whether this entry is still inside its TTL."""
        return (time.time() - self.fetched_at) < ttl


class RobotsDiskCache:
    """A tiny JSON-per-origin store under a cache directory.

    Deliberately not a database. There are hundreds of entries at most, each a
    few kilobytes, read once per origin per scan. Files are easier to inspect,
    to delete, and to reason about than a locked binary store.
    """

    def __init__(self, directory: Path | str, ttl: float = DEFAULT_ROBOTS_TTL) -> None:
        self.directory = Path(directory)
        self.ttl = ttl
        self.hits = 0
        self.misses = 0
        self.writes = 0

    # -- paths ------------------------------------------------------------
    def _path_for(self, origin: str) -> Path:
        digest = hashlib.sha256(origin.encode("utf-8")).hexdigest()[:32]
        return self.directory / f"{digest}.json"

    # -- api --------------------------------------------------------------
    def get(self, origin: str) -> CachedRobots | None:
        """Return a fresh entry for ``origin``, or ``None``."""
        path = self._path_for(origin)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            self.misses += 1
            return None
        try:
            payload = json.loads(raw)
            if payload.get("schema") != _SCHEMA:
                self.misses += 1
                return None
            entry = CachedRobots(
                origin=payload["origin"],
                status=int(payload["status"]),
                text=payload.get("text", ""),
                fetched_at=float(payload["fetched_at"]),
            )
        except (ValueError, KeyError, TypeError):
            self.misses += 1
            return None
        if entry.origin != origin or not entry.is_fresh(self.ttl):
            self.misses += 1
            return None
        self.hits += 1
        return entry

    def put(self, origin: str, status: int, text: str) -> None:
        """Store one origin's robots.txt. Never raises — a cache is not critical."""
        entry = CachedRobots(origin=origin, status=status, text=text, fetched_at=time.time())
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            payload: dict[str, Any] = {"schema": _SCHEMA, **asdict(entry)}
            path = self._path_for(origin)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(path)  # atomic: a partial file is worse than a miss
            self.writes += 1
        except OSError:
            pass

    def clear(self) -> int:
        """Delete every cached entry. Returns how many were removed."""
        removed = 0
        try:
            for path in self.directory.glob("*.json"):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
        except OSError:
            return removed
        return removed

    def stats(self) -> dict[str, int]:
        """Counters for the report, so the saving is attributable."""
        return {"hits": self.hits, "misses": self.misses, "writes": self.writes}
