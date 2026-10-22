"""Measure the scan pipeline end to end, single process vs sharded.

Must be run as a file, not ``python - <<EOF``: the forkserver pool needs a real
main module.

    .venv/bin/python benchmarks/parallel_check.py

Demo mode is used because it never touches the network, which makes the numbers
reproducible offline and independent of DNS. What is measured is the cost this
tool actually controls: scheduling, request building, robots handling, and
response parsing.
"""

from __future__ import annotations

import asyncio
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.engine import ScanEngine
from d3ta1l3r.models import ScanTarget

ROUNDS = 3


def mk(mode=15, *, conc=16, workers=0, ttl=60.0, demo=True):
    cfg = ScanConfig(mode=mode, use_cache=False, dns_ttl=ttl, workers=workers, demo=demo)
    cfg.rate.global_concurrency = conc
    return cfg


async def timed(cfg: ScanConfig, runs: int = ROUNDS):
    times, last = [], None
    for _ in range(runs):
        start = time.perf_counter()
        last = await ScanEngine(cfg).scan(ScanTarget.create(username="alice"))
        times.append(time.perf_counter() - start)
    return statistics.median(times), last


async def main() -> int:
    rows = [
        ("1 process   conc=16", mk(conc=16, workers=0)),
        ("1 process   conc=64", mk(conc=64, workers=0)),
        ("1 process   conc=256", mk(conc=256, workers=0)),
        ("2 processes conc=256", mk(conc=256, workers=1)),
        ("4 processes conc=256", mk(conc=256, workers=3)),
    ]

    base = None
    print(f"{'configuration':<24}{'seconds':>9}{'vs 1 proc':>11}{'sources':>9}", flush=True)
    for label, cfg in rows:
        sec, rep = await timed(cfg)
        if base is None:
            base = sec
        print(f"{label:<24}{sec:>9.2f}{base / sec:>10.2f}x{len(rep.outcomes):>9}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
