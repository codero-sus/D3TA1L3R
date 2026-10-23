"""Measure scan wall-clock against a fixed-latency mock network.

Real networks are noisy, so a speedup measured against one is not reproducible.
This harness pins the only variable that matters for scheduling: every request
costs exactly ``--latency`` seconds. Whatever wall-clock remains is the tool's
own doing — concurrency, rate limiting, robots handling, parsing.

Run:  .venv/bin/python benchmarks/throughput.py --mode 3 --mode 15
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.engine import ScanEngine
from d3ta1l3r.models import ScanTarget


class LatencyTransport(httpx.AsyncBaseTransport):
    """Every request costs ``latency`` seconds, nothing else.

    Counts requests so the benchmark can report throughput as well as time.
    """

    def __init__(self, latency: float = 0.20) -> None:
        self.latency = latency
        self.requests = 0
        self.by_path: dict[str, int] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        key = str(request.url.host or "?")
        self.by_path[key] = self.by_path.get(key, 0) + 1
        await asyncio.sleep(self.latency)
        return httpx.Response(
            404,
            request=request,
            headers={"content-type": "text/html; charset=utf-8"},
            text="<html><body>nothing here</body></html>",
        )


async def one(config: ScanConfig, target: ScanTarget, transport: LatencyTransport) -> tuple[float, int]:
    """Run one scan; return (seconds, source_count)."""
    engine = ScanEngine(config, transport=transport, on_event=None)
    started = time.perf_counter()
    report = await engine.scan(target)
    return time.perf_counter() - started, len(report.outcomes)


async def measure(mode: int, latency: float, runs: int) -> dict:
    times: list[float] = []
    counts: list[int] = []
    requests: list[int] = []
    for _ in range(runs):
        transport = LatencyTransport(latency)
        config = ScanConfig(mode=mode, use_cache=False, respect_robots=True)
        seconds, count = await one(config, ScanTarget.create(username="alice"), transport)
        times.append(seconds)
        counts.append(count)
        requests.append(transport.requests)
    return {
        "mode": mode,
        "seconds": statistics.median(times),
        "sources": statistics.median(counts),
        "requests": statistics.median(requests),
        "ideal": latency * (statistics.median(requests) / max(config_rate(mode), 1)),
    }


def config_rate(mode: int) -> int:
    from d3ta1l3r.config import ScanConfig

    return ScanConfig(mode=mode).rate.global_concurrency


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", type=int, action="append", default=[])
    parser.add_argument("--latency", type=float, default=0.20)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    modes = args.mode or [3, 15]
    print(f"latency={args.latency}s  runs={args.runs}  (median of {args.runs})\n")
    print(f"{'mode':>5} {'sources':>8} {'requests':>9} {'conc':>5} {'seconds':>9} {'ideal':>8} {'sources/s':>10}")
    for mode in modes:
        r = await measure(mode, args.latency, args.runs)
        conc = config_rate(mode)
        ideal = args.latency * r["requests"] / conc
        rate = r["sources"] / r["seconds"] if r["seconds"] else 0
        print(
            f"{r['mode']:>5} {r['sources']:>8.0f} {r['requests']:>9.0f} {conc:>5} "
            f"{r['seconds']:>9.2f} {ideal:>8.2f} {rate:>10.1f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
