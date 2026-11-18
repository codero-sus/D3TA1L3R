"""Check what your own photos and audio files reveal before you publish them.

Runs entirely offline: parsing is standard-library byte work, and the map link
in a GPS finding is text composed from the coordinates — it is never opened.

    python examples/media_audit.py photo.jpg
    python examples/media_audit.py ~/Pictures --scrub
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from d3ta1l3r.media import (
    analyze_path,
    iter_media_files,
    render_markdown,
    scrub_path,
)


def main(argv: list[str] | None = None) -> int:
    """Walk the given paths, print a summary, and optionally scrub."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="files or directories")
    parser.add_argument("--scrub", action="store_true", help="write .clean copies too")
    parser.add_argument("--markdown", metavar="PATH", help="write a full Markdown report")
    args = parser.parse_args(argv)

    files = list(iter_media_files(args.paths))
    if not files:
        print("no media files found", file=sys.stderr)
        return 1

    reports = []
    for path in files:
        report = analyze_path(path)
        reports.append(report)
        print(f"{report.name}: score {report.score}/100 — {report.verdict}")
        for exposure in report.exposures[:5]:
            print(f"  {exposure.severity.value:<8} {exposure.label}: {exposure.value}")

    if args.scrub:
        for report in reports:
            if report.format.value in {"jpeg", "png", "webp", "flac", "mp3"}:
                result, destination = scrub_path(report.name)
                print(f"  scrubbed → {destination} (residual {result.residual_score})")

    if args.markdown:
        Path(args.markdown).write_text(
            "\n\n---\n\n".join(render_markdown(report) for report in reports),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
