"""Remember, between runs, which hostnames are on the public internet.

The in-memory guard (:mod:`d3ta1l3r.core.hostguard`) de-duplicates within a
single scan, but nothing survived the process, so a second scan paid for ~942
resolutions all over again. The answer to "is ``github.com`` public" does not
change between Tuesday and Wednesday, and it is the single most expensive thing
this tool asks.

Stored as one JSON file of host -> timestamp. There are about a thousand
entries at a few dozen bytes each, so a single file is simpler than a directory
of them and can be read in one go.

What is deliberately *not* stored
---------------------------------

**Only proven-public results are cached.** A host that failed to resolve, or
that resolved to a private address, is always re-resolved on the next run. Two
reasons: a transient DNS failure must not lock a site out for a day, and a
refusal must never be remembered as weaker than it was. Caching only the
positive direction means a cached value can never make the guard more
permissive than a fresh lookup would.

The syntactic checks — scheme, embedded credentials, literal private addresses
and blocked suffixes — run on every URL on every run regardless of this store.
Only the expensive question, "does this name resolve to public addresses", is
remembered, and only when the answer was yes.
"""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from typing import Any

__all__ = ["DEFAULT_HOST_TTL", "HostValidationStore"]

#: Six hours. Long enough to make repeat scans cheap, short enough that a host
#: genuinely moving behind a firewall is noticed the same day.
DEFAULT_HOST_TTL = 21_600.0

_SCHEMA = 1


class HostValidationStore:
    """A tiny on-disk store of hostnames already known to be public.

    Never raises: it is an optimisation sitting next to a security check, and a
    cache that can crash a scan is worse than no cache. Every method degrades to
    a miss.
    """

    def __init__(self, path: Path | str, ttl: float = DEFAULT_HOST_TTL) -> None:
        self.path = Path(path)
        self.ttl = ttl
        self.hits = 0
        self.misses = 0
        self.writes = 0
        self._loaded: dict[str, float] | None = None
        self._dirty = False

    # -- storage ----------------------------------------------------------
    def _load(self) -> dict[str, float]:
        if self._loaded is None:
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if raw.get("schema") == _SCHEMA and isinstance(raw.get("hosts"), dict):
                    self._loaded = {
                        str(k): float(v)
                        for k, v in raw["hosts"].items()
                        if isinstance(k, str)
                    }
                else:
                    self._loaded = {}
            except (OSError, ValueError, TypeError):
                self._loaded = {}
        return self._loaded

    def flush(self) -> None:
        """Write pending entries back to disk, if there are any."""
        if not self._dirty or self._loaded is None:
            return
        self._dirty = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload: dict[str, Any] = {"schema": _SCHEMA, "hosts": self._loaded}
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(self.path)  # atomic
            self.writes += 1
        except OSError:
            pass

    # -- api --------------------------------------------------------------
    def is_known_public(self, host: str) -> bool:
        """Whether ``host`` is recorded as public and still inside its TTL."""
        stamp = self._load().get(host)
        if stamp is None:
            self.misses += 1
            return False
        if (time.time() - stamp) >= self.ttl:
            self.misses += 1
            return False
        self.hits += 1
        return True

    def remember_public(self, host: str) -> None:
        """Record that ``host`` resolved to public addresses."""
        self._load()[host] = time.time()
        self._dirty = True

    def clear(self) -> int:
        """Forget every stored host. Returns how many were dropped."""
        count = len(self._load())
        self._loaded = {}
        self._dirty = True
        with contextlib.suppress(OSError):
            self.path.unlink()
        return count

    def stats(self) -> dict[str, int]:
        """Counters for the report, so the saving is attributable."""
        return {"hits": self.hits, "misses": self.misses, "writes": self.writes}
