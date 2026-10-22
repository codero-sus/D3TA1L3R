"""Sharding and the host guard — especially the promise they make about politeness.

The claim worth testing is not "it is faster"; that is a benchmark. The claim
worth testing is that splitting a scan across processes does not change what a
remote host experiences. A tool that gets faster by quietly doubling the
request rate against somebody's server has not been optimised, it has been rude.
"""

from __future__ import annotations

import asyncio

import pytest

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.hostguard import DEFAULT_DNS_TTL, HostGuard
from d3ta1l3r.core.parallel import plan_shards, recommended_workers, shard_key
from d3ta1l3r.errors import ForbiddenTargetError
from d3ta1l3r.models import ScanTarget


def _sources(mode: int = 15):
    from d3ta1l3r.core.engine import ScanEngine

    return ScanEngine(ScanConfig(mode=mode)).selected_sources()


class TestShardPlanning:
    def test_no_host_is_split_across_shards(self) -> None:
        """The invariant the whole design rests on.

        If one host lands in two shards, two token buckets police it and the
        polite per-host rate silently doubles.
        """
        target = ScanTarget.create(username="alice")
        groups = plan_shards(_sources(), target, 4)
        where: dict[str, set[int]] = {}
        for index, group in enumerate(groups):
            for source in group:
                where.setdefault(shard_key(source, target), set()).add(index)
        split = {h: i for h, i in where.items() if len(i) > 1}
        assert not split, f"hosts in more than one shard: {list(split)[:5]}"

    def test_shards_are_balanced(self) -> None:
        groups = plan_shards(_sources(), ScanTarget.create(username="alice"), 4)
        sizes = [len(g) for g in groups]
        assert max(sizes) - min(sizes) <= 1, f"uneven shards: {sizes}"

    def test_no_source_is_lost_or_duplicated(self) -> None:
        sources = _sources(6)
        groups = plan_shards(sources, ScanTarget.create(username="alice"), 3)
        assert sorted(s.id for g in groups for s in g) == sorted(s.id for s in sources)

    def test_one_shard_returns_everything(self) -> None:
        groups = plan_shards(_sources(3), ScanTarget.create(username="alice"), 1)
        assert len(groups) == 1

    def test_a_source_that_cannot_build_a_url_still_gets_placed(self) -> None:
        """A broken source must not quietly vanish from the scan."""

        class Broken:
            id = "broken"

            def identifier_for(self, target):
                raise RuntimeError("no identifier")

            def query_url(self, identifier):
                raise RuntimeError("no url")

        assert shard_key(Broken(), ScanTarget.create(username="alice")) == "broken"


class TestWorkerChoice:
    def test_small_scans_stay_in_process(self) -> None:
        assert recommended_workers(50, ScanConfig()) == 0

    def test_a_large_scan_uses_the_cpus_it_has(self) -> None:
        workers = recommended_workers(900, ScanConfig())
        assert 0 <= workers <= 8

    def test_the_configured_number_wins(self) -> None:
        assert recommended_workers(10, ScanConfig(), explicit=3) == 3

    def test_zero_means_zero(self) -> None:
        assert recommended_workers(9000, ScanConfig(), explicit=0) == 0

    def test_config_workers_is_honoured(self) -> None:
        assert recommended_workers(9000, ScanConfig(workers=5)) == 5


class TestConcurrencyIsDividedNotMultiplied:
    def test_a_shard_gets_a_slice_of_the_budget(self) -> None:
        from d3ta1l3r.core.parallel import _shard_config

        config = ScanConfig(mode=3)
        config.rate.global_concurrency = 16
        assert _shard_config(config, 4).rate.global_concurrency == 4

    def test_the_original_config_is_not_mutated(self) -> None:
        from d3ta1l3r.core.parallel import _shard_config

        config = ScanConfig(mode=3)
        config.rate.global_concurrency = 16
        _shard_config(config, 4)
        assert config.rate.global_concurrency == 16

    def test_max_sites_is_not_applied_twice(self) -> None:
        from d3ta1l3r.core.parallel import _shard_config

        assert _shard_config(ScanConfig(mode=3, max_sites=10), 4).max_sites is None


def counting_resolver(delay: float = 0.0):
    """A stub resolver that never touches the network, and counts calls.

    ``delay`` makes the lookup slow enough for concurrent callers to pile up on
    it, which is the only way to observe single-flight: an instant resolver
    finishes before the second caller asks, and every caller then looks like a
    cache hit.
    """
    import threading
    import time

    calls: list[str] = []
    lock = threading.Lock()

    def resolve(host: str) -> bool:
        with lock:
            calls.append(host)
        if delay:
            time.sleep(delay)
        return True

    return resolve, calls


def guarded(resolver, **kwargs) -> HostGuard:
    return HostGuard(resolve=True, resolver=resolver, **kwargs)


class TestHostGuard:
    def test_it_still_refuses_a_loopback_address(self) -> None:
        with pytest.raises(ForbiddenTargetError):
            asyncio.run(HostGuard(resolve=False).check("http://127.0.0.1/admin"))

    def test_it_still_refuses_a_non_http_scheme(self) -> None:
        with pytest.raises(ForbiddenTargetError):
            asyncio.run(HostGuard(resolve=False).check("file:///etc/passwd"))

    def test_it_still_refuses_embedded_credentials(self) -> None:
        with pytest.raises(ForbiddenTargetError):
            asyncio.run(HostGuard(resolve=False).check("http://user:pass@example.com/"))

    def test_a_public_name_passes(self) -> None:
        url = asyncio.run(HostGuard(resolve=False).check("https://example.com/alice"))
        assert url == "https://example.com/alice"

    def test_the_second_check_hits_the_cache(self) -> None:
        """The whole point: one lookup per host, not one per request."""
        resolve, calls = counting_resolver()
        guard = guarded(resolve, ttl=60.0)
        asyncio.run(guard.check("https://example.com/a"))
        asyncio.run(guard.check("https://example.com/b"))
        assert guard.cache_hits == 1
        assert calls == ["example.com"], "one resolution for two requests"

    def test_a_zero_ttl_never_caches(self) -> None:
        """The conservative setting must actually be conservative."""
        resolve, calls = counting_resolver()
        guard = guarded(resolve, ttl=0.0)
        asyncio.run(guard.check("https://example.com/a"))
        asyncio.run(guard.check("https://example.com/b"))
        assert guard.cache_hits == 0 and guard.cache_size == 0
        assert len(calls) == 2, "ttl=0 must resolve every single time"

    def test_concurrent_checks_share_one_lookup(self) -> None:
        """A burst against one host must not become a burst of DNS."""
        resolve, calls = counting_resolver(delay=0.05)
        guard = guarded(resolve, ttl=60.0)

        async def burst():
            await asyncio.gather(
                *[guard.check(f"https://example.com/{i}") for i in range(20)]
            )

        asyncio.run(burst())
        assert len(calls) == 1, f"20 concurrent requests, {len(calls)} lookups"
        assert guard.shared_lookups == 19

    def test_the_default_ttl_is_a_bounded_window(self) -> None:
        assert 0 < DEFAULT_DNS_TTL <= 300

    def test_forget_drops_one_host(self) -> None:
        resolve, _ = counting_resolver()
        guard = guarded(resolve, ttl=60.0)
        asyncio.run(guard.check("https://example.com/a"))
        guard.forget("example.com")
        assert guard.cache_size == 0

    def test_clear_empties_everything(self) -> None:
        resolve, _ = counting_resolver()
        guard = guarded(resolve, ttl=60.0)
        asyncio.run(guard.check("https://example.com/a"))
        guard.clear()
        assert guard.cache_size == 0

    def test_stats_are_reported(self) -> None:
        resolve, _ = counting_resolver()
        guard = guarded(resolve, ttl=60.0)
        asyncio.run(guard.check("https://example.com/a"))
        asyncio.run(guard.check("https://example.com/b"))
        assert guard.stats()["cache_hits"] == 1
        assert guard.stats()["hosts_cached"] == 1

    def test_different_hosts_are_tracked_separately(self) -> None:
        resolve, _ = counting_resolver()
        guard = guarded(resolve, ttl=60.0)
        asyncio.run(guard.check("https://example.com/a"))
        asyncio.run(guard.check("https://github.com/a"))
        assert guard.cache_size == 2


class TestCachingDoesNotOpenAHole:
    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/internal",
            "http://192.168.1.1/admin",
            "http://[::1]/x",
        ],
    )
    def test_private_targets_are_refused_every_time(self, url: str) -> None:
        """These are rejected syntactically, so the cache is never involved.

        That is the design: only the expensive DNS question is remembered. The
        cheap decisions are re-made on every URL, including every redirect hop,
        and a refusal is never cached as an approval.
        """
        resolve, calls = counting_resolver()
        guard = guarded(resolve, ttl=60.0)
        for _ in range(3):
            with pytest.raises(ForbiddenTargetError):
                asyncio.run(guard.check(url))
        assert guard.cache_size == 0
        assert calls == [], "a syntactic refusal must never reach the resolver"
