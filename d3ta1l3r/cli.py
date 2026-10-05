"""Command-line interface.

    d3ta1l3r scan --username alice --email me@example.com --name "Alice Doe"
    d3ta1l3r sources --kind username
    d3ta1l3r calibrate --all            # measure the false-positive rate of the probes
    d3ta1l3r diff scans/old.json scans/new.json
    d3ta1l3r web --port 8000            # local dashboard

Design notes:

* Exit codes are meaningful so the tool can run in CI:
  ``0`` success, ``1`` bad usage, ``2`` runtime failure, ``3`` ``--fail-on-new``
  triggered (something new about you appeared online).
* ``--demo`` never touches the network; every report it produces is flagged.
* Reports are written to disk (JSON + Markdown + HTML) because a self-audit is
  something you re-read and compare later, not just a terminal scroll.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import random
import re
import string
import sys
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import ScanConfig
from .core.engine import ScanEngine
from .core.report import diff_reports, render_html, render_json, render_markdown
from .errors import D3ta1l3rError, UsageError
from .models import (
    EVENT_SCAN_FINISHED,
    EVENT_SOURCE_FINISHED,
    Confidence,
    ScanEvent,
    ScanReport,
    ScanStatus,
    ScanTarget,
)

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_FAILURE = 2
EXIT_NEW_FINDINGS = 3

DEFAULT_OUTPUT_DIR = Path("scans")

_ANSI = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
}


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="d3ta1l3r",
        description=(
            "D3TA1L3R — audit your own public footprint across public sites and "
            "unauthenticated APIs."
        ),
        epilog=(
            "Only public, unauthenticated endpoints are queried, and only identifiers you "
            "supply are used. Sites that require a login, defeat automation, or disallow "
            "robots are reported as gaps instead of being worked around. See docs/SCOPE.md."
        ),
    )
    parser.add_argument("--version", action="version", version=f"D3TA1L3R {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a self-audit")
    scan.add_argument("-u", "--username", action="append", default=[],
                      help="handle to check (repeatable, e.g. -u alice -u alice_dev)")
    scan.add_argument("-e", "--email", action="append", default=[],
                      help="email address to check (repeatable)")
    scan.add_argument("-n", "--name", action="append", default=[],
                      help="personal name to check (repeatable)")
    scan.add_argument("-d", "--domain", action="append", default=[],
                      help="domain you own, for an RDAP registration check (repeatable)")
    scan.add_argument("--location", default=None, help="coarse location hint, e.g. 'Delhi, IN'")
    scan.add_argument("--sources", default=None,
                      help="comma-separated source ids to run exclusively (see `sources`)")
    scan.add_argument("--exclude-sources", default=None, help="comma-separated source ids to skip")
    scan.add_argument("--categories", default=None, help="comma-separated categories to include")
    scan.add_argument("--kind", default=None,
                      help="comma-separated identifier kinds: username,email,name,domain")
    scan.add_argument("--max-sites", type=int, default=None,
                      help="cap the number of sources (handy for a quick pass)")
    scan.add_argument("--min-confidence", choices=[c.value for c in Confidence], default=None,
                      help="only report findings at or above this confidence")
    scan.add_argument("--demo", action="store_true",
                      help="use synthetic fixtures instead of the network (no real queries)")
    scan.add_argument("--no-robots", dest="respect_robots", action="store_false", default=True,
                      help="ignore robots.txt (not recommended; some sources will be blocked)")
    scan.add_argument("--robots-fail-open", action="store_true",
                      help="scan anyway when robots.txt cannot be fetched (RFC 9309 says don't)")
    scan.add_argument("--timeout", type=float, default=None, help="per-request timeout, seconds")
    scan.add_argument("--connect-timeout", type=float, default=None, help="connect timeout, seconds")
    scan.add_argument("--jobs", "-j", type=int, default=None,
                      help="maximum concurrent sources (default 16)")
    scan.add_argument("--rps", type=float, default=None, help="requests per second per host")
    scan.add_argument("--retries", type=int, default=None, help="retries per request (default 2)")
    scan.add_argument("--cache-dir", default=None,
                      help="reuse responses from this directory (repeat scans hit fewer sites)")
    scan.add_argument("--no-redirects", dest="follow_redirects", action="store_false", default=True)
    scan.add_argument("--allow-private-hosts", dest="strict_ssrf", action="store_false", default=True,
                      help=argparse.SUPPRESS)
    scan.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT_DIR),
                      help="directory for reports (default: ./scans)")
    scan.add_argument("--format", default="json,markdown,html",
                      help="comma-separated formats: json,markdown,html")
    scan.add_argument("--stdout", choices=["json", "markdown", "none"], default="markdown",
                      help="what to print when finished (default: markdown)")
    scan.add_argument("--compare", default=None,
                      help="previous report JSON; print what changed since that scan")
    scan.add_argument("--fail-on-new", action="store_true",
                      help="exit 3 when --compare finds findings that did not exist before")
    scan.add_argument("-v", "--verbose", action="store_true", help="stream per-source progress")
    scan.add_argument("-q", "--quiet", action="store_true",
                      help="only print the final summary line")

    sources = sub.add_parser("sources", help="list every source and what it checks")
    sources.add_argument("--kind", default=None, help="filter by identifier kind")
    sources.add_argument("--category", default=None, help="filter by category")
    sources.add_argument("--enabled-only", action="store_true",
                         help="hide sources that are disabled by default")
    sources.add_argument("--json", action="store_true", help="machine-readable output")
    sources.add_argument("--check", action="store_true",
                         help="live check: query one known-real handle and report which sources work")

    calibrate = sub.add_parser(
        "calibrate", help="measure probe accuracy: false positives and layout drift"
    )
    calibrate.add_argument("--sites", default=None,
                           help="comma-separated site ids to calibrate (default: all enabled)")
    calibrate.add_argument("--all", action="store_true", help="include sites disabled by default")
    calibrate.add_argument("--absent-samples", type=int, default=2,
                           help="how many certainly-bogus handles to probe per site (default 2)")
    calibrate.add_argument("--expect-hit", action="append", default=[],
                           metavar="SITE_ID=HANDLE",
                           help="ground truth: a handle you own on that site, to confirm detection")
    calibrate.add_argument("--timeout", type=float, default=None)
    calibrate.add_argument("--jobs", "-j", type=int, default=None)
    calibrate.add_argument("--cache-dir", default=None)
    calibrate.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT_DIR))
    calibrate.add_argument("--json", action="store_true", help="print the raw calibration JSON")

    diff = sub.add_parser("diff", help="compare two report files")
    diff.add_argument("previous", help="older report JSON")
    diff.add_argument("current", help="newer report JSON")
    diff.add_argument("--json", action="store_true", help="print machine-readable output")

    web = sub.add_parser("web", help="serve the local dashboard")
    web.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    web.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    web.add_argument("--output", default=str(DEFAULT_OUTPUT_DIR), help="scan storage directory")
    web.add_argument("--demo", action="store_true",
                     help="run the dashboard in demo mode (synthetic results, no network)")
    web.add_argument("--reload", action="store_true", help="auto-reload on code changes")
    web.add_argument("--timeout", type=float, default=None)
    web.add_argument("--jobs", "-j", type=int, default=None)
    web.add_argument("--rps", type=float, default=None)
    web.add_argument("--no-robots", dest="respect_robots", action="store_false", default=True)
    return parser


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "sources":
            return cmd_sources(args)
        if args.command == "calibrate":
            return cmd_calibrate(args)
        if args.command == "diff":
            return cmd_diff(args)
        if args.command == "web":
            return cmd_web(args)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except D3ta1l3rError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print("\ninterrupted", file=sys.stderr)
        return 130
    parser.print_help()
    return EXIT_USAGE


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    usernames = _split_values(args.username)
    emails = _split_values(args.email)
    names = _split_values(args.name)
    domains = _split_values(args.domain)
    if not any((usernames, emails, names, domains)):
        raise UsageError("supply at least one of --username, --email, --name or --domain")

    targets: list[ScanTarget] = []
    for username in usernames or [None]:
        for email in emails or [None]:
            for name in names or [None]:
                for domain in domains or [None]:
                    targets.append(
                        ScanTarget.create(
                            username=username, email=email, name=name,
                            location=args.location, domain=domain,
                        )
                    )

    config = _config_from_args(args)
    # Machine-readable stdout must stay parseable: human output goes to stderr then.
    human_stream = sys.stderr if args.stdout == "json" else sys.stdout
    console = _Console(verbose=args.verbose, quiet=args.quiet, stream=human_stream)
    min_confidence = Confidence(args.min_confidence) if args.min_confidence else None
    exit_code = EXIT_OK

    for index, target in enumerate(targets, start=1):
        if len(targets) > 1 and not args.quiet:
            console.note(f"[{index}/{len(targets)}] {target.display()}")
        report = asyncio.run(_run_scan(target, config, console, args.demo))
        if min_confidence is not None:
            report = _filter_confidence(report, min_confidence)
        written = _write_reports(report, Path(args.output), args.format)

        previous = _load_report(args.compare) if args.compare else None
        diff = diff_reports(previous, report) if previous else None

        if args.stdout == "json":
            print(render_json(report))
        elif args.stdout == "markdown" and not args.quiet:
            print(render_markdown(report))
        if diff is not None:
            print(diff.render_markdown())
            if args.fail_on_new and diff.new_findings:
                exit_code = EXIT_NEW_FINDINGS

        console.summary(report, written, demo=args.demo)
    return exit_code


async def _run_scan(
    target: ScanTarget, config: ScanConfig, console: _Console, demo: bool
) -> ScanReport:
    engine = ScanEngine(config, on_event=console.event)
    return await engine.scan(target)


def _filter_confidence(report: ScanReport, minimum: Confidence) -> ScanReport:
    """Drop findings below the requested confidence floor (keeps coverage rows)."""
    from .models import SourceOutcome

    filtered: list[SourceOutcome] = []
    for outcome in report.outcomes:
        kept = [f for f in outcome.findings if f.confidence.rank >= minimum.rank]
        hidden = len(outcome.findings) - len(kept)
        status, note = outcome.status, outcome.error
        if outcome.findings and not kept:
            # Everything this source found was weaker than the floor: it is no longer a "hit".
            status = ScanStatus.NOT_FOUND
            note = (
                f"all {hidden} finding(s) from this source were below "
                f"--min-confidence {minimum.value} and are hidden"
            )
        elif hidden:
            note = f"({hidden} weaker finding(s) hidden by --min-confidence)"
        filtered.append(
            SourceOutcome(
                source_id=outcome.source_id,
                source_name=outcome.source_name,
                kind=outcome.kind,
                status=status,
                category=outcome.category,
                findings=kept,
                http_status=outcome.http_status,
                error=note,
                duration_ms=outcome.duration_ms,
                skipped_reason=outcome.skipped_reason,
                docs_url=outcome.docs_url,
                query_url=outcome.query_url,
                attempts=outcome.attempts,
            )
        )
    report.outcomes = filtered
    if minimum.rank > Confidence.LOW.rank:
        report.warnings.append(
            f"Findings below {minimum.value} confidence were filtered out of this report "
            "(--min-confidence); re-run without the flag to see them."
        )
    report.refresh_stats()
    return report


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------
def cmd_sources(args: argparse.Namespace) -> int:
    engine = ScanEngine(ScanConfig())
    rows = engine.describe_sources()
    if args.kind:
        wanted = set(_split_values([args.kind]))
        rows = [row for row in rows if row["kind"] in wanted]
    if args.category:
        wanted = set(_split_values([args.category]))
        rows = [row for row in rows if row["category"] in wanted]
    if args.enabled_only:
        rows = [row for row in rows if row["enabled_by_default"]]

    if args.check:
        return _live_source_check(rows, args)

    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK

    print(f"{len(rows)} source(s)\n")
    by_category: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_category.setdefault(row["category"], []).append(row)
    for category, entries in sorted(by_category.items()):
        print(f"  {category.upper()}")
        for row in entries:
            flag = "" if row["enabled_by_default"] else "  (disabled by default)"
            print(f"    {row['id']:<32} {row['kind']:<9} {row['name']}{flag}")
            print(f"        {row['description']}")
            notes = (row.get("notes") or "").strip()
            if notes and notes != row["description"].strip():
                print(f"        note: {notes}")
        print()
    print("Run `d3ta1l3r scan --sources <id,id>` to run a subset.")
    print("Calibrate before trusting a signature: `d3ta1l3r calibrate --all`.")
    return EXIT_OK


def _live_source_check(rows: list[dict[str, Any]], args: argparse.Namespace) -> int:
    """Probe a single well-known public handle to see which sources answer at all."""
    handle = "torvalds"
    print(f"Live check with the public handle '{handle}' (network required)…\n")
    config = ScanConfig(strict_ssrf=True)
    engine = ScanEngine(config)
    report = asyncio.run(engine.scan(ScanTarget.create(username=handle)))
    for outcome in report.outcomes:
        if outcome.kind.value != "username":
            continue
        symbol = {"found": "✔", "not_found": "·"}.get(outcome.status.value, "!")
        print(f"  {symbol} {outcome.source_name:<28} {outcome.status.value:<18} "
              f"{outcome.error or ''}".rstrip())
    print(f"\n{report.stats.sources_hit}/{report.stats.sources_total} sources returned data.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# calibrate
# ---------------------------------------------------------------------------
def cmd_calibrate(args: argparse.Namespace) -> int:
    """Ground-truth measurement of the HTML probes.

    Two questions, both answerable without touching anyone else's data:

    1. **False positives** — probe obviously-bogus handles (``zzq-<random>``).
       Any site that calls those "found" is a site you cannot trust.
    2. **Missed detection** — probe handles *you* supply as ``--expect-hit
       site=handle``. A site that does not report your own account is broken
       (or your account is private).
    """
    from .sources.probe import UsernameProbeSource, load_site_specs

    specs = load_site_specs(include_disabled=bool(args.all))
    if args.sites:
        wanted = set(_split_values([args.sites]))
        specs = [spec for spec in specs if spec.id in wanted]
        if not specs:
            raise UsageError("no matching site ids — see `d3ta1l3r sources`")
    if not specs:
        raise UsageError("no sites selected")

    config = _config_from_args(args, for_calibrate=True)
    engine = ScanEngine(config, sources=[UsernameProbeSource(spec) for spec in specs])

    expectation: dict[str, str] = {}
    for item in args.expect_hit:
        site_id, _, handle = item.partition("=")
        if not site_id or not handle:
            raise UsageError(f"--expect-hit wants SITE_ID=HANDLE, got {item!r}")
        expectation[site_id.strip()] = handle.strip()

    bogus = [_bogus_handle() for _ in range(max(1, args.absent_samples))]
    results: dict[str, dict[str, Any]] = {
        spec.id: {"id": spec.id, "name": spec.name, "absent_probes": [], "present_probe": None}
        for spec in specs
    }

    async def run_all() -> None:
        for handle in bogus:
            report = await engine.scan(ScanTarget.create(username=handle))
            for outcome in report.outcomes:
                entry = results.get(outcome.source_id)
                if entry is None:
                    continue
                entry["absent_probes"].append(
                    {
                        "handle": handle,
                        "status": outcome.status.value,
                        "http_status": outcome.http_status,
                        "evidence": (outcome.findings[0].evidence if outcome.findings else outcome.error),
                    }
                )
        for site_id, handle in expectation.items():
            report = await engine.scan(ScanTarget.create(username=handle))
            outcome = report.outcome(site_id)
            if outcome is not None:
                results[site_id]["present_probe"] = {
                    "handle": handle,
                    "status": outcome.status.value,
                    "http_status": outcome.http_status,
                }

    started = time.perf_counter()
    asyncio.run(run_all())
    elapsed = time.perf_counter() - started

    rows = [_calibration_row(entry) for entry in results.values()]
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool_version": __version__,
        "bogus_handles": bogus,
        "expectations": expectation,
        "elapsed_seconds": round(elapsed, 1),
        "sites": rows,
    }

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"calibration-{stamp}.json"
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        _print_calibration(rows)
        print(f"Saved: {path}")
    return EXIT_OK


def _calibration_row(entry: dict[str, Any]) -> dict[str, Any]:
    absent = entry["absent_probes"]
    false_positives = [a for a in absent if a["status"] == "found"]
    ambiguous = [a for a in absent if a["status"] == "error"]
    unknown = [a for a in absent if a["status"] in {"blocked", "skipped_robots", "timeout"}]
    good_absent = [a for a in absent if a["status"] == "not_found"]
    verdict = "trustworthy"
    if false_positives:
        verdict = "FALSE POSITIVES — do not trust"
    elif ambiguous:
        verdict = "ambiguous — spec needs updating"
    elif unknown and not good_absent:
        verdict = "unreachable anonymously"
    present = entry["present_probe"]
    if present:
        if present["status"] == "found":
            verdict = f"{verdict}; detects ground-truth account"
        elif present["status"] == "not_found":
            verdict = "MISSES a known account — reduce confidence / disable"
        else:
            verdict = f"{verdict}; ground-truth probe returned {present['status']}"
    return {
        "id": entry["id"],
        "name": entry["name"],
        "verdict": verdict,
        "absent_probes": absent,
        "present_probe": present,
        "counts": {
            "absent_confirmed": len(good_absent),
            "false_positive": len(false_positives),
            "ambiguous": len(ambiguous),
            "unknown": len(unknown),
        },
    }


def _print_calibration(rows: list[dict[str, Any]]) -> None:
    print(f"{'site':<28}{'absent ok':>10}{'false pos':>11}{'ambiguous':>11}  verdict")
    print("-" * 100)
    for row in sorted(rows, key=lambda r: r["verdict"]):
        counts = row["counts"]
        print(
            f"{row['id']:<28}{counts['absent_confirmed']:>10}{counts['false_positive']:>11}"
            f"{counts['ambiguous']:>11}  {row['verdict']}"
        )
    print()
    bad = [r for r in rows if r["counts"]["false_positive"]]
    if bad:
        print("Sites reporting accounts for bogus handles (disable or lower confidence):")
        for row in bad:
            print(f"  - {row['id']} ({row['name']})")
    else:
        print("No false positives observed. Absent-path signatures behaved correctly.")


def _bogus_handle() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"zzq{suffix}"


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
def cmd_diff(args: argparse.Namespace) -> int:
    previous = _load_report(args.previous)
    current = _load_report(args.current)
    difference = diff_reports(previous, current)
    if args.json:
        print(json.dumps(difference.to_dict(), indent=2))
    else:
        print(difference.render_markdown())
    return EXIT_NEW_FINDINGS if difference.new_findings else EXIT_OK


def _load_report(path: str | Path) -> ScanReport:
    file = Path(path)
    if not file.is_file():
        raise UsageError(f"report not found: {file}")
    try:
        return ScanReport.from_json(file.read_text(encoding="utf-8"))
    except (ValueError, KeyError) as exc:
        raise UsageError(f"{file} is not a D3TA1L3R report JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# web
# ---------------------------------------------------------------------------
def cmd_web(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise UsageError(
            "the dashboard needs extra packages: pip install 'd3ta1l3r[web]'"
        ) from exc

    from .web.app import AppSettings, create_app

    settings = AppSettings(
        output_dir=Path(args.output),
        demo=bool(args.demo),
        config=_config_from_args(args),
    )
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(settings)
    print(f"D3TA1L3R dashboard → http://{args.host}:{args.port}  (Ctrl-C to stop)")
    if args.demo:
        print("DEMO MODE: scans are served from synthetic fixtures; no third party is contacted.")
    uvicorn.run(app, host=args.host, port=args.port, reload=bool(args.reload), log_level="info")
    return EXIT_OK


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _config_from_args(args: argparse.Namespace, *, for_calibrate: bool = False) -> ScanConfig:
    overrides: dict[str, Any] = {}
    if getattr(args, "timeout", None) is not None:
        overrides["timeout"] = args.timeout
        overrides["connect_timeout"] = min(args.connect_timeout or 5.0, args.timeout)
    if getattr(args, "connect_timeout", None) is not None:
        overrides["connect_timeout"] = args.connect_timeout
    if getattr(args, "respect_robots", None) is not None:
        overrides["respect_robots"] = args.respect_robots
    if getattr(args, "robots_fail_open", False):
        overrides["robots_fail_open"] = True
    if getattr(args, "jobs", None):
        from .config import RateLimitConfig

        overrides["rate"] = RateLimitConfig(global_concurrency=max(1, args.jobs))
    if getattr(args, "rps", None) is not None:
        from .config import RateLimitConfig

        base = overrides.get("rate") or RateLimitConfig()
        base.per_host_rps = args.rps
        base.per_host_burst = max(1, int(max(args.rps, 1)))
        overrides["rate"] = base
    if getattr(args, "retries", None) is not None:
        from .config import RateLimitConfig

        base = overrides.get("rate") or RateLimitConfig()
        base.max_retries = max(0, args.retries)
        overrides["rate"] = base
    if getattr(args, "cache_dir", None):
        overrides["cache_dir"] = Path(args.cache_dir).expanduser()
        overrides["use_cache"] = True
    if getattr(args, "follow_redirects", None) is not None:
        overrides["follow_redirects"] = args.follow_redirects
    if getattr(args, "strict_ssrf", None) is not None:
        overrides["strict_ssrf"] = args.strict_ssrf
    if getattr(args, "demo", False):
        overrides["demo"] = True
    if not for_calibrate:
        if getattr(args, "sources", None):
            overrides["enabled_sources"] = frozenset(_split_values([args.sources]))
        if getattr(args, "exclude_sources", None):
            overrides["disabled_sources"] = frozenset(_split_values([args.exclude_sources]))
        if getattr(args, "categories", None):
            overrides["categories"] = frozenset(_split_values([args.categories]))
        if getattr(args, "kind", None):
            overrides["kinds"] = frozenset(_split_values([args.kind]))
        if getattr(args, "max_sites", None):
            overrides["max_sites"] = args.max_sites
    return ScanConfig.from_env(**overrides)


def _split_values(values: Sequence[str]) -> list[str]:
    """Accept repeated flags and comma-separated lists.

    Splitting on whitespace would be wrong here: ``--name "Demo User"`` is one
    identifier, not two, so only commas separate values.
    """
    out: list[str] = []
    for value in values:
        if value is None:
            continue
        for part in str(value).split(","):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _write_reports(report: ScanReport, out_dir: Path, formats: str) -> list[Path]:
    wanted = {fmt.strip().lower() for fmt in formats.split(",") if fmt.strip()}
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.started_at.strftime("%Y%m%dT%H%M%SZ")
    slug = _slug(report.target.display()) or "scan"
    stem = f"{stamp}-{slug}-{report.scan_id}"
    written: list[Path] = []
    if "json" in wanted:
        path = out_dir / f"{stem}.json"
        path.write_text(render_json(report), encoding="utf-8")
        written.append(path)
    if "markdown" in wanted or "md" in wanted:
        path = out_dir / f"{stem}.md"
        path.write_text(render_markdown(report), encoding="utf-8")
        written.append(path)
    if "html" in wanted:
        path = out_dir / f"{stem}.html"
        path.write_text(render_html(report), encoding="utf-8")
        written.append(path)
    return written


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:60]


class _Console:
    """Terminal progress + summary, tty-aware and CI-friendly."""

    def __init__(
        self, *, verbose: bool = False, quiet: bool = False, stream: Any = None
    ) -> None:
        self.verbose = verbose
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self.is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._last_line = 0.0
        self._started = time.perf_counter()

    def _paint(self, text: str, colour: str = "") -> str:
        if not self.is_tty:
            return text
        return f"{_ANSI.get(colour, '')}{text}{_ANSI['reset']}"

    def event(self, event: ScanEvent) -> None:
        if self.quiet:
            return
        if self.verbose:
            print(f"  {event.message}", file=self.stream)
            return
        if event.type in {EVENT_SOURCE_FINISHED, EVENT_SCAN_FINISHED} and self.is_tty:
            now = time.perf_counter()
            if now - self._last_line < 0.05 and event.completed < event.total:
                return
            self._last_line = now
            bar_width = 28
            filled = int(bar_width * (event.percent / 100))
            bar = "█" * filled + "░" * (bar_width - filled)
            line = f"  [{bar}] {event.percent:5.1f}%  {event.completed}/{event.total}  {event.message[:44]}"
            self.stream.write("\r" + line.ljust(110))
            self.stream.flush()
            if event.type == EVENT_SCAN_FINISHED:
                self.stream.write("\n")

    def note(self, message: str) -> None:
        if not self.quiet:
            print(message, file=self.stream)

    def summary(self, report: ScanReport, written: Sequence[Path] = (), *, demo: bool = False) -> None:
        if self.quiet:
            print(
                f"{report.target.display()}: {report.stats.findings_total} finding(s), "
                f"{report.stats.sources_total} sources, {report.stats.sources_failed} error(s)",
                file=self.stream,
            )
            return
        stats = report.stats
        print(file=self.stream)
        print(self._paint(f"D3TA1L3R — {report.target.display()}", "bold"), file=self.stream)
        if demo:
            print(
                self._paint("  DEMO MODE — synthetic results, no third-party requests made.", "red"),
                file=self.stream,
            )
        print(
            f"  {stats.findings_total} finding(s) from {stats.sources_hit} source(s) · "
            f"{stats.sources_total} checked · {stats.sources_skipped} skipped · "
            f"{stats.sources_failed} failed · {report.duration_ms / 1000:.1f}s · "
            f"{stats.http_requests} request(s) to {stats.hosts_contacted} host(s)",
            file=self.stream,
        )
        for finding in report.findings[:12]:
            colour = {
                Confidence.CONFIRMED: "green",
                Confidence.HIGH: "cyan",
                Confidence.MEDIUM: "yellow",
                Confidence.LOW: "grey",
            }[finding.confidence]
            label = self._paint(f"{finding.confidence.value:>9}", colour)
            print(f"    {label}  {finding.source_name:<22} {finding.url}", file=self.stream)
        if len(report.findings) > 12:
            print(f"    … and {len(report.findings) - 12} more in the report", file=self.stream)
        gaps = [o for o in report.outcomes if not o.ok or o.status.is_skip]
        if gaps:
            print(
                self._paint(
                    f"  {len(gaps)} source(s) could not be checked (blocked, robots, errors) — "
                    "these are gaps, not clean results.",
                    "yellow",
                ),
                file=self.stream,
            )
        for path in written:
            print(f"  wrote {path}", file=self.stream)
        print(file=self.stream)
        print(
            self._paint("  Next: open the HTML report, or `d3ta1l3r web` for the dashboard.", "dim"),
            file=self.stream,
        )


def _ensure_utf8_stdout() -> None:  # pragma: no cover - platform shim
    if os.name == "nt":  # pragma: no cover
        with contextlib.suppress(Exception):
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]


if __name__ == "__main__":  # pragma: no cover
    _ensure_utf8_stdout()
    sys.exit(main())
