"""Minimal library usage: scan your own identifiers and print a readable summary.

Run it in demo mode first (no network, synthetic results)::

    python examples/quickstart.py --demo
    python examples/quickstart.py -u your_handle -e you@example.com
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from d3ta1l3r import ScanConfig, ScanEngine, ScanTarget  # noqa: E402
from d3ta1l3r.models import ScanEvent, ScanStatus  # noqa: E402

GAPS = {
    ScanStatus.BLOCKED,
    ScanStatus.SKIPPED_ROBOTS,
    ScanStatus.SKIPPED_RATE_LIMITED,
    ScanStatus.ERROR,
    ScanStatus.TIMEOUT,
}


def on_progress(event: ScanEvent) -> None:
    """Progress callbacks can be sync or async; this one just prints."""
    if event.type == "source_finished" and event.status == ScanStatus.FOUND:
        print(f"  ✔ {event.source_name} ({event.findings_count} finding)")


async def main() -> int:
    parser = argparse.ArgumentParser(description="D3TA1L3R quickstart")
    parser.add_argument("-u", "--username")
    parser.add_argument("-e", "--email")
    parser.add_argument("-n", "--name")
    parser.add_argument("-d", "--domain")
    parser.add_argument("--demo", action="store_true", help="synthetic fixtures, no network")
    parser.add_argument("--min-confidence", default=None,
                        choices=["low", "medium", "high", "confirmed"])
    args = parser.parse_args()

    if not any((args.username, args.email, args.name, args.domain)):
        parser.error("supply at least one of -u/-e/-n/-d")

    target = ScanTarget.create(
        username=args.username, email=args.email, name=args.name, domain=args.domain
    )
    config = ScanConfig(demo=args.demo)

    print(f"Auditing {target.display()} …")
    report = await ScanEngine(config, on_event=on_progress).scan(target)

    print(f"\n{report.stats.findings_total} finding(s) from {report.stats.sources_hit} "
          f"of {report.stats.sources_total} sources ({report.duration_ms / 1000:.1f}s)")

    floor = args.min_confidence
    rank = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
    for finding in report.findings:
        if floor and finding.confidence.rank < rank[floor]:
            continue
        print(f"\n[{finding.confidence.value.upper()}] {finding.title or finding.source_name}")
        print(f"  url:      {finding.url}")
        print(f"  evidence: {finding.evidence}")
        for item in (finding.extra.get("exposure") or [])[:6]:
            print(f"  exposed:  {item}")

    gaps = [o for o in report.outcomes if o.status in GAPS]
    if gaps:
        print(f"\n{len(gaps)} source(s) could not be checked — these are unknown, not clean:")
        for outcome in gaps[:10]:
            print(f"  - {outcome.source_name}: {outcome.error or outcome.skipped_reason}")

    if report.demo:
        print("\n(demo mode: these results are synthetic and describe nobody)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
