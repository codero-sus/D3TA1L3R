"""robots.txt policy (RFC 9309), cached per host.

Rules implemented:

* ``200`` → parse the file and obey ``Disallow`` / ``Crawl-delay`` for our token.
* ``404`` / ``410`` → nothing disallowed (a missing file means "go ahead").
* ``401`` / ``403`` → treats the whole site as disallowed (RFC 9309 §2.3.1.3).
* ``5xx`` / unreachable → disallowed, *unless* ``robots_fail_open`` is set.

When robots.txt disallows a probe, the source is reported as
``skipped_robots`` rather than silently dropped — "this site blocks automated
checks" is genuinely useful information in a self-audit, and hiding it would be
a lie about coverage.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from ..errors import RobotsDeniedError, SourceError
from .robots_cache import RobotsDiskCache

__all__ = ["RobotsPolicy"]

_USER_AGENT_TOKEN = "D3TA1L3R"
_MAX_ROBOTS_BYTES = 512 * 1024


@dataclass(slots=True)
class _Rules:
    parser: RobotFileParser | None
    fetched_at: float
    outcome: str  # "allowed" | "disallowed" | "error"
    crawl_delay: float | None = None
    note: str = ""


@dataclass(slots=True)
class RobotsPolicy:
    """Fetch, cache, and consult robots.txt using the engine's own Fetcher.

    Defaults are taken from the fetcher's :class:`~d3ta1l3r.config.ScanConfig`,
    so a caller that flips ``robots_fail_open`` in the config gets the behaviour
    it asked for without having to remember to pass it here as well.
    """

    fetcher: Any
    enabled: bool | None = None
    fail_open: bool | None = None
    cache_ttl: float | None = None
    crawl_delay_cap: float | None = None
    user_agent_token: str = _USER_AGENT_TOKEN
    disk_cache: RobotsDiskCache | None = None
    _cache: dict[str, _Rules] = field(default_factory=dict)
    _pending: dict[str, asyncio.Future] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        config = getattr(self.fetcher, "config", None)
        if config is None:  # pragma: no cover - fetcher always carries a config
            self.enabled = True if self.enabled is None else self.enabled
            self.fail_open = False if self.fail_open is None else self.fail_open
            self.cache_ttl = 3600.0 if self.cache_ttl is None else self.cache_ttl
            self.crawl_delay_cap = 10.0 if self.crawl_delay_cap is None else self.crawl_delay_cap
            return
        if self.enabled is None:
            self.enabled = getattr(config, "respect_robots", True)
        if self.fail_open is None:
            self.fail_open = getattr(config, "robots_fail_open", False)
        if self.cache_ttl is None:
            self.cache_ttl = getattr(config, "robots_cache_ttl", 3600.0)
        if self.crawl_delay_cap is None:
            self.crawl_delay_cap = getattr(config, "crawl_delay_cap", 10.0)

    async def _rules_for(self, url: str) -> _Rules:
        """Rules for the origin of ``url``, fetching at most once per origin.

        Three layers, cheapest first: the in-memory cache for this run, the disk
        cache from earlier runs, then a fetch that concurrent callers share
        rather than repeat. Without the sharing, a host with four sources would
        fetch the same robots.txt four times.
        """
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        cached = self._cache.get(origin)
        if cached and (time.monotonic() - cached.fetched_at) < self.cache_ttl:
            return cached

        if self.disk_cache is not None:
            stored = self.disk_cache.get(origin)
            if stored is not None:
                rules = self._rules_from_stored(origin, stored)
                self._cache[origin] = rules
                return rules

        pending = self._pending.get(origin)
        if pending is not None:
            return await asyncio.shield(pending)

        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[origin] = future
        try:
            robots_url = f"{origin}/robots.txt"
            rules = await self._load(robots_url)
        except BaseException as exc:
            self._pending.pop(origin, None)
            if not future.done():
                future.set_exception(exc)
            raise
        self._pending.pop(origin, None)
        self._cache[origin] = rules
        if not future.done():
            future.set_result(rules)
        return rules

    def _rules_from_stored(self, origin: str, stored: Any) -> _Rules:
        """Rebuild rules from a disk entry; consult the fetcher for crawl delay."""
        if stored.status in (401, 403):
            return _Rules(None, time.monotonic(), "disallowed",
                          note=f"robots.txt HTTP {stored.status} (cached)")
        if stored.status in (404, 410):
            return _Rules(None, time.monotonic(), "allowed",
                          note="no robots.txt (cached)")
        if stored.status >= 400:
            outcome = "allowed" if self.fail_open else "disallowed"
            return _Rules(None, time.monotonic(), outcome,
                          note=f"robots.txt HTTP {stored.status} (cached)")
        parser = RobotFileParser()
        parser.set_url(stored.origin)
        try:
            parser.parse(stored.text.splitlines())
        except Exception:
            return _Rules(None, time.monotonic(), "allowed",
                          note="cached robots.txt would not parse")
        return _Rules(parser, time.monotonic(), "allowed",
                      crawl_delay=self._crawl_delay_of(parser))

    async def _load(self, robots_url: str) -> _Rules:
        origin = robots_url[: -len("/robots.txt")] if robots_url.endswith("/robots.txt") else robots_url
        try:
            # fetch_raw: anti-recursion — robots.txt itself is never robots-checked.
            response = await self.fetcher.fetch_raw(
                robots_url, accept="text/plain", use_cache=True, check_robots=False
            )
        except Exception as exc:
            # A fetch failure is not cached: it is usually transient, and
            # remembering "disallowed" for a day over one timeout would quietly
            # stop a site being scanned long after the network recovered.
            if self.fail_open:
                return _Rules(None, time.monotonic(), "allowed", note=f"robots fetch failed: {exc}")
            return _Rules(None, time.monotonic(), "disallowed", note=f"robots fetch failed: {exc}")

        status = response.status
        if self.disk_cache is not None:
            self.disk_cache.put(origin, status, response.text if status < 400 else "")
        if status in (401, 403):
            return _Rules(None, time.monotonic(), "disallowed", note=f"robots.txt HTTP {status}")
        if status in (404, 410):
            return _Rules(None, time.monotonic(), "allowed", note=f"no robots.txt (HTTP {status})")
        if status >= 400:
            if self.fail_open:
                return _Rules(None, time.monotonic(), "allowed", note=f"robots.txt HTTP {status}")
            return _Rules(None, time.monotonic(), "disallowed", note=f"robots.txt HTTP {status}")

        parser = RobotFileParser()
        parser.set_url(robots_url)
        try:
            parser.parse(response.text.splitlines())
        except Exception as exc:
            raise SourceError(f"could not parse robots.txt from {robots_url}: {exc}") from exc

        return _Rules(parser, time.monotonic(), "allowed",
                      crawl_delay=self._crawl_delay_of(parser))

    def _crawl_delay_of(self, parser: RobotFileParser) -> float | None:
        """The ``Crawl-delay`` for this user agent, capped."""
        try:
            raw_delay = parser.crawl_delay(self.user_agent_token)
            if raw_delay is not None:
                return min(float(raw_delay), self.crawl_delay_cap)
        except (TypeError, ValueError):  # pragma: no cover - malformed Crawl-delay
            return None
        return None

    async def check(self, url: str) -> None:
        """Raise :class:`RobotsDeniedError` when ``url`` may not be fetched."""
        if not self.enabled:
            return
        rules = await self._rules_for(url)
        if rules.outcome == "disallowed":
            raise RobotsDeniedError(f"robots.txt disallows {url} ({rules.note or 'disallow all'})")
        if rules.parser is None:
            return
        if not rules.parser.can_fetch(self.user_agent_token, url):
            raise RobotsDeniedError(f"robots.txt disallows {url} for {self.user_agent_token}")

    def crawl_delay(self, url: str) -> float | None:
        """The site's requested crawl delay for ``url``, or None when robots.txt said
        nothing. Never guessed: an absent directive means no delay, not zero."""
        rules = self._cache.get(f"{urlsplit(url).scheme}://{urlsplit(url).netloc}")
        return rules.crawl_delay if rules else None

    def known_origins(self) -> list[str]:  # pragma: no cover - diagnostics
        """Origins whose robots.txt has been fetched; diagnostics only."""
        return sorted(self._cache)
