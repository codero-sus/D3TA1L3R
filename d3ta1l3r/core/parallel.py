"""Shard a scan across processes when there are enough sources for it to pay.

Why sharding by host
--------------------

The obvious way to parallelise — hand every process a slice of the source list —
is wrong here. Politeness in this tool is enforced *per host* by a token bucket
(:class:`~d3ta1l3r.core.ratelimit.HostRateLimiter`). If two processes both
believe they may send two requests a second to ``github.com``, the host actually
receives four, and a split that looked free silently doubles the load on
somebody else's server.

So sources are partitioned by hostname: every request to a given host stays in
one process, where the one bucket for that host is the only one that exists.
Splitting the work then does not multiply it.

What this buys, and what it does not
------------------------------------

It buys CPU parallelism. Once DNS is cached (see :mod:`.hostguard`) a broad scan
stops being network-bound and becomes bound by Python: building requests,
following redirects, reading robots.txt, running detectors over response
bodies. That work is spread thinly across thousands of small calls rather than
sitting in one hot function, so there is nothing to optimise — only more cores
help. Each process runs its own event loop over its own slice.

It deliberately does **not** buy more network concurrency. Total in-flight
requests stay where the operator put them: each process gets
``global_concurrency / n_processes``, so the aggregate is unchanged. If you want
more requests in flight, raise ``--jobs``; that is a separate decision with a
separate footprint, and conflating the two would make "I asked for 8 processes"
silently mean "I asked for 8x the traffic".

When it is off
--------------

Forking costs real time. Below ``parallel_min_sources`` the whole scan finishes
before the workers would have finished starting, so the default is to stay in
one process. It is also disabled when a transport is injected — that only
happens for the demo transport and in tests, neither of which can cross a
process boundary.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urlsplit

from ..config import ScanConfig
from ..models import ScanTarget, SourceOutcome

__all__ = ["plan_shards", "recommended_workers", "scan_sharded", "shard_key"]


def shard_key(source: Any, target: ScanTarget) -> str:
    """The hostname that decides which process a source belongs to.

    Uses the same two calls the engine makes (:meth:`identifier_for` then
    :meth:`query_url`) so the host grouped on is exactly the host that will be
    contacted. A source that cannot produce one falls back to its own id, which
    still scans it and merely places it arbitrarily.
    """
    try:
        identifier = source.identifier_for(target)
        url = source.query_url(identifier) if identifier else None
        if url:
            return urlsplit(url).hostname or source.id
    except Exception:
        pass
    return source.id


def plan_shards(
    sources: Sequence[Any], target: ScanTarget, shards: int
) -> list[list[Any]]:
    """Split ``sources`` into ``shards`` groups, keeping each host whole.

    Groups are balanced by *source count*, not by expected latency: a group full
    of slow hosts would otherwise decide the runtime while other processes sit
    idle. Hosts are dealt to the currently-lightest group, largest first.
    """
    if shards <= 1:
        return [list(sources)]

    by_host: dict[str, list[Any]] = {}
    for source in sources:
        by_host.setdefault(shard_key(source, target), []).append(source)

    groups: list[list[Any]] = [[] for _ in range(shards)]
    sizes = [0] * shards
    for _host, items in sorted(by_host.items(), key=lambda kv: -len(kv[1])):
        lightest = min(range(shards), key=lambda i: (sizes[i], i))
        groups[lightest].extend(items)
        sizes[lightest] += len(items)
    return [g for g in groups if g]


def recommended_workers(n_sources: int, config: ScanConfig, explicit: int | None = None) -> int:
    """How many *extra* processes to use. ``0`` means stay in-process.

    Off unless asked for. That is a measured decision, not caution: sharding a
    944-source demo scan across four processes made it *slower* (0.80x), because
    forking and pickling several hundred source objects costs more than the
    per-source work it parallelises — at least when response bodies are small.

    It is expected to pay when bodies are large and parsing is heavy, which is
    the part that is genuinely CPU-bound. Until that is measured on hardware
    with a real network, the default stays single-process so that nobody gets a
    slower scan for free. Enable it with ``--workers N`` and measure.
    """
    if explicit is not None:
        return max(0, explicit)
    if config.workers:
        return max(0, config.workers)
    return 0


async def scan_sharded(
    config: ScanConfig,
    sources: Sequence[Any],
    target: ScanTarget,
    *,
    workers: int | None = None,
    on_event: Callable[[Any], None] | None = None,
    pool_factory: Callable[..., Any] | None = None,
) -> tuple[list[SourceOutcome], dict]:
    """Run ``sources`` across processes and return every outcome, in one list.

    Falls back to an in-process scan on any failure to start workers. A
    self-audit tool that refuses to run because it cannot fork is worse than one
    that runs a bit slower, so parallelism here is an optimisation, never a
    requirement.
    """
    n_extra = recommended_workers(len(sources), config, workers)
    if n_extra <= 0:
        return await _scan_in_process(config, list(sources), target, on_event=on_event), _zero_stats()

    groups = plan_shards(list(sources), target, n_extra + 1)
    if len(groups) < 2:
        return await _scan_in_process(config, list(sources), target, on_event=on_event), _zero_stats()

    # Each shard gets a slice of the concurrency budget so the aggregate is
    # what the operator asked for, not n_processes times that.
    per_shard = max(1, config.rate.global_concurrency // len(groups))
    # Source objects are picklable, so hand each child its own list rather than
    # making it rebuild the whole 944-entry catalogue just to throw most away.
    payloads = [(_shard_config(config, per_shard), group, target) for group in groups]

    factory = pool_factory or _default_pool
    global _last_stats
    try:
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, _run_pool, factory, payloads, len(groups)
        )
    except Exception:
        _last_stats = []
        return await _scan_in_process(config, list(sources), target, on_event=on_event), _zero_stats()

    outcomes: list[SourceOutcome] = []
    stats = {"hosts_contacted": 0, "http_requests": 0, "cache_hits": 0,
             "dns_lookups": 0, "shared_lookups": 0}
    for group_outcomes in results:
        outcomes.extend(group_outcomes)
    stats["hosts_contacted"] = len({_host(o) for o in outcomes if _host(o)})
    for key in ("http_requests", "cache_hits", "dns_lookups", "shared_lookups"):
        stats[key] = sum(g.get(key, 0) for g in _last_stats)
    if on_event is not None:
        for index, outcome in enumerate(outcomes):
            result = on_event(("outcome", index + 1, len(outcomes), outcome))
            if asyncio.iscoroutine(result):
                await result
    return outcomes, stats


# -- process-side ---------------------------------------------------------


def _shard_config(config: ScanConfig, concurrency: int) -> ScanConfig:
    """A copy of ``config`` with the shard's slice of the concurrency budget.

    ``max_sites`` is cleared because the parent already applied it: leaving it
    set would truncate each shard to the same first N sources.
    """
    import copy

    shard = copy.copy(config)
    shard.rate = copy.copy(config.rate)
    shard.rate.global_concurrency = concurrency
    shard.max_sites = None
    return shard


def _default_pool(max_workers: int) -> Any:
    from concurrent.futures import ProcessPoolExecutor

    return ProcessPoolExecutor(max_workers=max_workers, mp_context=_start_context())


def _start_context():
    """Pick the cheapest start method that is also safe.

    Measured here, four workers, doing nothing:

        fork    4.5 ms
        fork   29.8 ms  (forkserver)
        spawn  53-116 ms

    ``fork`` is an order of magnitude cheaper because it skips interpreter and
    module start-up entirely. The usual reason to avoid it is that forking a
    process with live threads can hand a child a lock that was held at fork
    time, and the child then waits for a thread that does not exist in it.

    But that only applies once threads exist. The DNS executor is created
    lazily, so a process that has not run a scan yet has no worker threads and
    ``fork`` is completely safe — and it is exactly the cheap case we want.
    After that, fall back to ``forkserver``, which starts one clean process up
    front and forks from that: no re-running the caller's module, no inherited
    locks.

    ``spawn`` is the last resort. It re-executes the main module in every
    child, which runs the caller's top-level code N more times — surprising,
    and fatal for a script with no ``if __name__ == "__main__":`` guard.
    Windows has only this.
    """
    import multiprocessing as mp

    from .hostguard import dns_threads_started

    candidates = ("fork", "forkserver", "spawn") if not dns_threads_started() \
        else ("forkserver", "spawn")
    for method in candidates:
        try:
            return mp.get_context(method)
        except ValueError:
            continue
    return mp.get_context()  # pragma: no cover - platform default


def _run_pool(factory: Callable[..., Any], payloads: list[tuple], n: int) -> list[list[SourceOutcome]]:
    """Drive the pool synchronously; called from a worker thread."""
    global _last_stats
    with factory(n) as pool:
        raw = list(pool.map(_scan_shard, payloads))
    _last_stats = [r[1] for r in raw]
    return [r[0] for r in raw]


def _scan_shard(payload: tuple) -> list[SourceOutcome]:
    """Scan one shard. Runs in a child process.

    Top-level and argument-only so it can be pickled by the pool.
    """
    config, sources, target = payload
    from .engine import ScanEngine, demo_transport_for

    # A transport cannot cross the process boundary, so the child builds its
    # own. Only demo mode can do this, which is why only demo mode is sharded
    # when the caller injected a transport.
    transport = demo_transport_for(target) if config.demo else None
    engine = ScanEngine(config, sources=list(sources), transport=transport)
    report = asyncio.run(engine.scan(target))
    stats = {
        "http_requests": int(report.stats.http_requests or 0),
        "hosts_contacted": len(_hosts_of(report)),
        "cache_hits": int(report.options.get("cache_hits", 0)),
        "dns_lookups": int(report.options.get("dns_lookups", 0)),
        "shared_lookups": int(report.options.get("dns_shared_lookups", 0)),
    }
    return list(report.outcomes), stats


_last_stats: list[dict] = []


def _zero_stats() -> dict:
    return {"hosts_contacted": 0, "http_requests": 0, "cache_hits": 0,
            "dns_lookups": 0, "shared_lookups": 0}


def _host(outcome: Any) -> str | None:
    url = getattr(outcome, "query_url", None)
    if not url:
        return None
    try:
        return urlsplit(url).hostname
    except Exception:
        return None


def _hosts_of(report: Any) -> set:
    """Hostnames this report actually contacted, taken from the outcomes."""
    hosts = set()
    for outcome in report.outcomes:
        url = getattr(outcome, "query_url", None)
        if url:
            try:
                host = urlsplit(url).hostname
            except Exception:
                host = None
            if host:
                hosts.add(host)
    return hosts


async def _scan_in_process(
    config: ScanConfig,
    sources: list[Any],
    target: ScanTarget,
    *,
    on_event: Callable[[Any], None] | None = None,
) -> list[SourceOutcome]:
    from .engine import ScanEngine

    engine = ScanEngine(config, sources=sources, on_event=on_event)
    report = await engine.scan(target)
    return list(report.outcomes)
