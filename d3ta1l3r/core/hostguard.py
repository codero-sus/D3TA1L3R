"""An SSRF guard that does not re-resolve DNS on every single request.

The guard in :mod:`d3ta1l3r.core.security` is correct and deliberately blunt:
``is_public_host(host, resolve=True)`` resolves every A/AAAA record so that a
name pointing at ``127.0.0.1`` cannot be used to probe the machine's own
services. That is the right check. Doing it *per request* is what is expensive.

Measured on this codebase (944 sources, 1 876 requests)::

    pure assert_public_url, no DNS      5.2 us/call
    the same, via asyncio.to_thread    83.3 us/call   <- 16x, thread dispatch
    socket.getaddrinfo                12 620 us/call  <- 2400x, and uncached

A scan of 944 sources therefore spent most of its wall clock inside
``getaddrinfo``, serialised onto a thread pool the size of
``min(32, cpu_count + 4)``. The async semaphore was set to 1024 and the scan
still behaved as though it were running about six requests at a time, because
six threads were all that were available to do the work.

This module keeps the check and removes the repetition:

* **Syntactic checks run inline.** They are pure string and ``ipaddress`` work
  costing ~5 us. Sending them to a thread costs 16x more than running them.
* **DNS results are cached per host** for a bounded TTL.
* **Concurrent requests to one host share one lookup** (single-flight), so a
  burst of twenty sources on ``github.com`` produces one resolution, not twenty.

The deliberate trade-off
------------------------

Caching a validation means a name that validated as public is trusted for the
lifetime of the cache entry. If an attacker controls DNS for a scanned host
they can answer with a public address, wait for the entry to be cached, then
re-point the name at an internal address — DNS rebinding. The window here is
the TTL, and the attacker must already control resolution for that name.

For this tool's purpose — a self-audit against a fixed, shipped catalogue of
public sites, where the only user-supplied part of a URL is the handle in the
path — that is a small risk next to a 14x slowdown. It is nonetheless a real
one, so it is configurable rather than silent:

* ``ttl`` bounds the window (default 60 s, ``0`` disables caching entirely).
* ``strict`` mode (``ttl=0``) restores resolve-every-time behaviour.

What is *not* cached is the syntactic decision: scheme, embedded credentials,
literal private addresses and blocked suffixes are re-checked on every URL,
every redirect hop. Only the expensive part — "does this name resolve to
public addresses" — is remembered.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

from ..errors import ForbiddenTargetError
from .security import assert_public_url

__all__ = ["DEFAULT_DNS_TTL", "HostGuard", "dns_executor"]

#: How long a successful host validation is reused, in seconds.
DEFAULT_DNS_TTL = 60.0

_MAX_CACHE_ENTRIES = 8192

_executor: ThreadPoolExecutor | None = None
_executor_lock = asyncio.Lock()


def dns_threads_started() -> bool:
    """Whether the shared DNS executor has been created yet.

    Used to decide if forking is safe. A process that has never started the
    executor has no worker threads, so a fork cannot inherit a lock mid-flight.
    """
    return _executor is not None


def dns_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    """A shared executor sized for blocking DNS, not for CPU work.

    The default executor is ``min(32, cpu_count + 4)`` threads and is shared
    with every other ``to_thread`` caller in the process. ``getaddrinfo`` is
    blocking I/O, so it wants a pool sized for concurrency rather than for
    cores.
    """
    global _executor
    if _executor is None:
        if max_workers is None:
            max_workers = min(128, max(16, (os.cpu_count() or 4) * 16))
        _executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="d3ta1l3r-dns"
        )
    return _executor


class HostGuard:
    """Per-host SSRF validation with a TTL cache and single-flight DNS.

    One instance belongs to one scan (or one :class:`~d3ta1l3r.core.http.Fetcher`).
    It is not thread-safe and does not need to be: it only ever runs inside the
    event loop that owns it.
    """

    def __init__(
        self,
        *,
        resolve: bool = True,
        ttl: float = DEFAULT_DNS_TTL,
        max_entries: int = _MAX_CACHE_ENTRIES,
        executor: ThreadPoolExecutor | None = None,
        resolver: Callable[[str], bool] | None = None,
        store: Any | None = None,
    ) -> None:
        self.resolve = resolve
        self.ttl = max(0.0, ttl)
        self.max_entries = max(64, max_entries)
        self._executor = executor or dns_executor()
        #: Injectable so tests can prove the caching contract without a network.
        self._resolver = resolver or _resolve_is_public
        #: Optional cross-run store; only proven-public hosts are remembered.
        self._store = store

        self._cache: dict[str, float] = {}          # host -> expiry (monotonic)
        self._pending: dict[str, asyncio.Future[bool]] = {}
        self._lock = asyncio.Lock()

        # Diagnostics, surfaced in the report so a speedup is attributable.
        self.dns_lookups = 0
        self.cache_hits = 0
        self.shared_lookups = 0
        self.cross_run_hits = 0

    # -- introspection ----------------------------------------------------
    @property
    def cache_size(self) -> int:
        """How many hosts are currently remembered."""
        return len(self._cache)

    def stats(self) -> dict[str, int]:
        """Counters for the report, so a speedup can be attributed to something."""
        return {
            "dns_lookups": self.dns_lookups,
            "cache_hits": self.cache_hits,
            "shared_lookups": self.shared_lookups,
            "cross_run_hits": self.cross_run_hits,
            "hosts_cached": len(self._cache),
        }

    # -- validation -------------------------------------------------------
    async def check(self, url: str, *, base: str | None = None) -> str:
        """Return the normalised ``url`` or raise :class:`ForbiddenTargetError`.

        Every call re-runs the cheap syntactic checks. Only the DNS question is
        cached.
        """
        # Inline: this is ~5 us of string parsing. A thread round-trip is 83 us.
        try:
            candidate = assert_public_url(url, resolve=False, base=base)
        except ForbiddenTargetError:
            raise
        except OSError as exc:  # pragma: no cover - defensive
            raise ForbiddenTargetError(f"could not validate URL: {exc}") from exc

        if not self.resolve:
            return candidate

        host = urlsplit(candidate).hostname or ""
        if not host:  # pragma: no cover - assert_public_url already rejects this
            raise ForbiddenTargetError(f"refusing URL without a host: {candidate}")

        now = time.monotonic()
        expiry = self._cache.get(host)
        if expiry is not None and now < expiry:
            self.cache_hits += 1
            return candidate

        # Known public from an earlier run and still inside its TTL: accept it
        # without a lookup, and memoise it here so the store is read once.
        if self._store is not None and self._store.is_known_public(host):
            self.cross_run_hits += 1
            self._remember(host)
            return candidate

        ok = await self._validate(host)
        if not ok:
            raise ForbiddenTargetError(
                f"refusing to contact non-public host {host!r} (SSRF guard)"
            )
        return candidate

    async def _validate(self, host: str) -> bool:
        """Resolve ``host`` at most once, even under a burst of concurrent requests."""
        loop = asyncio.get_running_loop()

        pending: asyncio.Future[bool] | None = None
        owner = False

        async with self._lock:
            now = time.monotonic()
            expiry = self._cache.get(host)
            if expiry is not None and now < expiry:
                self.cache_hits += 1
                return True
            pending = self._pending.get(host)
            if pending is not None:
                # Somebody else is already resolving this host; wait for them
                # rather than starting a second identical lookup.
                self.shared_lookups += 1
            else:
                future: asyncio.Future[bool] = loop.create_future()
                self._pending[host] = future
                owner = True

        if pending is not None:
            # Awaited *outside* the lock. Holding the lock across this await
            # would make one slow lookup hold up validation for every other
            # host in the scan — the serialisation this module exists to remove.
            return await asyncio.shield(pending)

        try:
            self.dns_lookups += 1
            result = await loop.run_in_executor(self._executor, self._resolver, host)
        except BaseException as exc:
            if owner:
                self._pending.pop(host, None)
            if not future.done():
                future.set_exception(exc)
            raise
        else:
            if owner:
                self._pending.pop(host, None)
            if not future.done():
                future.set_result(result)
            if result and self.ttl > 0:
                self._remember(host)
            if result and self._store is not None:
                self._store.remember_public(host)
            return result

    def _remember(self, host: str) -> None:
        if len(self._cache) >= self.max_entries:
            # Drop the entries closest to expiry; cheap and good enough for a
            # bounded cache that is deliberately short-lived.
            now = time.monotonic()
            for stale in sorted(self._cache, key=lambda h: self._cache[h])[
                : self.max_entries // 4
            ]:
                if self._cache.get(stale, now) <= now:
                    self._cache.pop(stale, None)
            if len(self._cache) >= self.max_entries:
                self._cache.clear()
        self._cache[host] = time.monotonic() + self.ttl

    def forget(self, host: str) -> None:
        """Drop one host from the cache (used when a name starts failing)."""
        self._cache.pop(host, None)

    def clear(self) -> None:
        """Forget every cached host."""
        self._cache.clear()
        self._pending.clear()

    def flush(self) -> None:
        """Persist anything worth remembering for the next run."""
        if self._store is not None:
            self._store.flush()


def _resolve_is_public(host: str) -> bool:
    """Blocking half of the guard, run on the DNS executor."""
    from .security import is_public_host  # local import keeps the cycle shallow

    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    return all(is_public_host(addr, resolve=False) for addr in addresses)
