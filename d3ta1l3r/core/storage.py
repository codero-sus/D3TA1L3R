"""Scan storage: the report directory the CLI and the dashboard share.

A self-audit is a series of snapshots, so reports are stored on disk in a stable,
sortable layout::

    scans/20260512T101500Z-alice-9f2c1a3b4c5d.json
    scans/20260512T101500Z-alice-9f2c1a3b4c5d.md
    scans/20260512T101500Z-alice-9f2c1a3b4c5d.html

Scan files contain personal data about whoever was scanned. The store keeps
them in one directory so a single ``d3ta1l3r purge`` (or ``rm -rf scans``) is a
complete clean-up, and it never writes them anywhere else.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ..models import ScanReport
from .report import render_html, render_json, render_markdown

__all__ = ["ScanMeta", "ScanStore"]

_STEM_RE = re.compile(r"^(?P<stamp>\d{8}T\d{6}Z)-(?P<slug>.*?)-(?P<scan_id>[0-9a-f]{6,32})$")


@dataclass(slots=True)
class ScanMeta:
    """Cheap summary of a stored scan, for dashboards and listings."""

    scan_id: str
    path: Path
    target_display: str
    started_at: str
    findings: int
    sources_hit: int
    sources_total: int
    sources_failed: int
    demo: bool
    html_path: Path | None = None
    markdown_path: Path | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "scan_id": self.scan_id,
            "path": str(self.path),
            "target_display": self.target_display,
            "started_at": self.started_at,
            "findings": self.findings,
            "sources_hit": self.sources_hit,
            "sources_total": self.sources_total,
            "sources_failed": self.sources_failed,
            "demo": self.demo,
            "has_html": self.html_path is not None,
            "has_markdown": self.markdown_path is not None,
        }


class ScanStore:
    """Read/write reports in one directory. No database, no hidden state."""

    def __init__(self, directory: Path | str = Path("scans")) -> None:
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(parents=True, exist_ok=True)

    # -- paths -----------------------------------------------------------
    def stems(self) -> Iterator[tuple[Path, re.Match[str] | None]]:
        for path in sorted(self.directory.glob("*.json")):
            yield path, _STEM_RE.match(path.stem)

    def path_for(self, report: ScanReport, suffix: str = ".json") -> Path:
        stamp = report.started_at.strftime("%Y%m%dT%H%M%SZ")
        slug = _slug(report.target.display()) or "scan"
        return self.directory / f"{stamp}-{slug}-{report.scan_id}{suffix}"

    def find(self, scan_id: str) -> Path | None:
        for path, match in self.stems():
            if match and match.group("scan_id") == scan_id:
                return path
            if path.stem.endswith(f"-{scan_id}"):
                return path
        return None

    # -- write -----------------------------------------------------------
    def save(
        self, report: ScanReport, *, formats: tuple[str, ...] = ("json", "markdown", "html")
    ) -> list[Path]:
        written: list[Path] = []
        if "json" in formats:
            path = self.path_for(report, ".json")
            path.write_text(render_json(report), encoding="utf-8")
            written.append(path)
        if "markdown" in formats:
            path = self.path_for(report, ".md")
            path.write_text(render_markdown(report), encoding="utf-8")
            written.append(path)
        if "html" in formats:
            path = self.path_for(report, ".html")
            path.write_text(render_html(report), encoding="utf-8")
            written.append(path)
        return written

    # -- read ------------------------------------------------------------
    def load(self, scan_id: str) -> ScanReport | None:
        path = self.find(scan_id)
        if path is None:
            return None
        return self.load_path(path)

    @staticmethod
    def load_path(path: Path) -> ScanReport:
        return ScanReport.from_json(path.read_text(encoding="utf-8"))

    def list(self, *, limit: int | None = None) -> list[ScanMeta]:
        metas: list[ScanMeta] = []
        for path, match in self.stems():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            stats = raw.get("stats") or {}
            scan_id = str(raw.get("scan_id") or (match.group("scan_id") if match else path.stem))
            metas.append(
                ScanMeta(
                    scan_id=scan_id,
                    path=path,
                    target_display=str(raw.get("target_display") or "?"),
                    started_at=str(raw.get("started_at") or ""),
                    findings=int(stats.get("findings_total") or 0),
                    sources_hit=int(stats.get("sources_hit") or 0),
                    sources_total=int(stats.get("sources_total") or 0),
                    sources_failed=int(stats.get("sources_failed") or 0),
                    demo=bool(raw.get("demo", False)),
                    html_path=path.with_suffix(".html") if path.with_suffix(".html").exists() else None,
                    markdown_path=path.with_suffix(".md") if path.with_suffix(".md").exists() else None,
                )
            )
        metas.sort(key=lambda meta: meta.started_at, reverse=True)
        return metas[:limit] if limit else metas

    # -- delete ----------------------------------------------------------
    def delete(self, scan_id: str) -> int:
        """Remove every artefact of one scan. Returns the number of files removed.

        The path is resolved once: after the ``.json`` is gone the scan is no
        longer discoverable, so looking it up per-suffix would orphan the
        Markdown and HTML siblings.
        """
        path = self.find(scan_id)
        if path is None:
            return 0
        removed = 0
        for suffix in (".json", ".md", ".html"):
            candidate = path.with_suffix(suffix)
            if candidate.exists():
                candidate.unlink()
                removed += 1
        return removed

    def purge(self) -> int:
        """Delete every stored scan. Returns the number of files removed."""
        removed = 0
        for pattern in ("*.json", "*.md", "*.html"):
            for path in self.directory.glob(pattern):
                try:
                    path.unlink()
                    removed += 1
                except OSError:  # pragma: no cover - best effort
                    continue
        return removed


def _slug(value: str, *, limit: int = 36) -> str:
    """A short, filesystem-safe label for the target, e.g. ``demo-user-de-example-com``.

    Truncation keeps multi-identifier scans (handle + email + name + domain)
    from producing a filename nobody can read or tab-complete.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if len(slug) <= limit:
        return slug
    return slug[:limit].rstrip("-")
