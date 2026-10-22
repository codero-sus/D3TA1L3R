"""End-to-end benchmark: old settings vs accelerated, single vs multi-process.

Must be run as a file (not ``python - <<EOF``) because the forkserver pool
needs a real main module.

    .venv/bin/python benchmarks/parallel_check.py
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from d3ta1l3r.config import ScanConfig
from d3ta1l3r.core.engine import ScanEngine
from d3ta1l3r.models import ScanTarget


async def timed(cfg: ScanConfig, runs: int = 2):
    best, last = 1e9, None
    for _ in range(runs):
        start = time.perf_counter()
        last = await ScanEngine(cfg).scan(ScanTarget.create(username="alice"))
        best = min(best, time.perf_counter() - start)
    return best, last


def mk(mode=15, *, conc=16, ttl=0.0, workers=0):
    cfg = ScanConfig(mode=mode, use_cache=False, dns_ttl=ttl, workers=workers)
    cfg.rate.global_concurrency = conc
    return cfg


async def main() -> int:
    rows = [
        ("old defaults   conc=16  ttl=0   1 proc", mk(conc=16, ttl=0.0, workers=0)),
        ("dns cache only conc=16  ttl=60  1 proc", mk(conc=16, ttl=60.0, workers=0)),
        ("+ concurrency  conc=128 ttl=60  1 proc", mk(conc=128, ttl=60.0, workers=0)),
        ("+ concurrency  conc=256 ttl=60  1 proc", mk(conc=256, ttl=60.0, workers=0)),
        ("+ 2 processes  conc=256 ttl=60  2 proc", mk(conc=256, ttl=60.0, workers=1)),
        ("+ 4 processes  conc=256 ttl=60  4 proc", mk(conc=256, ttl=60.0, workers=3)),
    ]

    base = None
    print(f"{'configuration':<42} {'seconds':>8} {'speedup':>9} {'sources':>8} {'reqs':>6}")
    for label, cfg in rows:
        sec, rep = await timed(cfg)
        if base is None:
            base = sec
        print(
            f"{label:<42} {sec:>8.2f} {base / sec:>8.2f}x "
            f"{len(rep.outcomes):>8} {rep.stats.http_requests:>6}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
