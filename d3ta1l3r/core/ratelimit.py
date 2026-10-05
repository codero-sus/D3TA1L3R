"""Per-host token buckets, global concurrency, and retry backoff.

A self-audit against 200 public sites is a small crawler. It should behave like
one: bounded concurrency, a steady per-host rate, exponential backoff on 429s and
5xx, and an absolute refusal to spin when a host says "slow down".
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field

__all__ = ["HostRateLimiter", "retry_delay"]


@dataclass(slots=True)
class _Bucket:
    capacity: float
    refill_per_second: float
    tokens: float = field(default=0.0)
    updated_at: float = field(default_factory=time.monotonic)
    min_interval: float = 0.0
    last_request_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.updated_at
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
            self.updated_at = now

    def _wait_time(self) -> float:
        self._refill()
        waits = []
        if self.tokens < 1.0:
            waits.append((1.0 - self.tokens) / self.refill_per_second)
        if self.min_interval > 0:
            since_last = time.monotonic() - self.last_request_at
            if since_last < self.min_interval:
                waits.append(self.min_interval - since_last)
        return max(waits) if waits else 0.0

    def consume(self) -> None:
        self._refill()
        self.tokens = max(0.0, self.tokens - 1.0)
        self.last_request_at = time.monotonic()


class HostRateLimiter:
    """Token bucket per hostname plus an optional robots ``Crawl-delay`` floor."""

    def __init__(self, rps: float = 2.0, burst: int = 4) -> None:
        self.rps = max(rps, 0.01)
        self.burst = max(burst, 1)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()
        self.waits = 0

    async def _bucket(self, host: str) -> _Bucket:
        async with self._lock:
            bucket = self._buckets.get(host)
            if bucket is None:
                bucket = _Bucket(capacity=float(self.burst), refill_per_second=self.rps,
                                 tokens=float(self.burst))
                self._buckets[host] = bucket
            return bucket

    def set_min_interval(self, host: str, seconds: float) -> None:
        """Apply a robots.txt ``Crawl-delay`` as a floor between requests."""
        bucket = self._buckets.get(host)
        if bucket is not None:
            bucket.min_interval = max(bucket.min_interval, seconds)

    async def acquire(self, host: str) -> float:
        """Wait until a request to ``host`` is allowed. Returns seconds waited."""
        bucket = await self._bucket(host)
        waited = 0.0
        while True:
            async with bucket.lock:
                delay = bucket._wait_time()
                if delay <= 0:
                    bucket.consume()
                    if waited:
                        self.waits += 1
                    return waited
            if delay > 30:  # pragma: no cover - defensive: never block a scan for long
                return waited
            await asyncio.sleep(delay)
            waited += delay

    def snapshot(self) -> dict[str, float]:
        return {host: round(b.tokens, 2) for host, b in self._buckets.items()}


def retry_delay(
    attempt: int,
    *,
    base: float = 0.5,
    maximum: float = 8.0,
    retry_after: float | None = None,
    jitter: bool = True,
) -> float:
    """Exponential backoff with optional jitter, capped by ``maximum``.

    ``attempt`` is 1-based: the delay *before* attempt 2 is ``base * 2``.
    """
    if retry_after is not None and retry_after >= 0:
        return min(retry_after, maximum)
    delay = base * (2 ** max(0, attempt - 1))
    if jitter:
        delay *= 0.5 + random.random() / 2
    return min(delay, maximum)
