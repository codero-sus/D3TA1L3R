"""Report rendering: Markdown, standalone HTML, and report-to-report diffs.

Reports are the artefact a person actually reads, so they carry three things
that most scanners leave out:

* **Provenance** — tool version, transport settings, and a hash of the signature
  database, so a finding can be reproduced later.
* **Coverage** — every source's fate, including the ones that were skipped,
  refused, or broke. "Nothing found" and "not checked" must never look alike.
* **Evidence** — the exact reason a source believes it has a hit, right next to
  the confidence label.

``diff_reports`` answers the question a self-audit exists to answer: *what
changed since last time?*
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..models import Confidence, Finding, ScanReport, ScanStatus

__all__ = ["ReportDiff", "diff_reports", "render_html", "render_json", "render_markdown"]

_STATUS_LABEL = {
    ScanStatus.FOUND: ("hit", "found"),
    ScanStatus.NOT_FOUND: ("·", "no account"),
    ScanStatus.ERROR: ("!", "error"),
    ScanStatus.TIMEOUT: ("!", "timeout"),
    ScanStatus.BLOCKED: ("⊘", "blocked / sign-in wall"),
    ScanStatus.SKIPPED_ROBOTS: ("⚑", "skipped: robots.txt"),
    ScanStatus.SKIPPED_RATE_LIMITED: ("~", "skipped: rate limited"),
    ScanStatus.SKIPPED_DISABLED: ("-", "skipped: disabled"),
    ScanStatus.SKIPPED_NO_INPUT: ("-", "skipped: no identifier"),
}

_CONFIDENCE_LABEL = {
    Confidence.CONFIRMED: "CONFIRMED",
    Confidence.HIGH: "HIGH",
    Confidence.MEDIUM: "MEDIUM",
    Confidence.LOW: "LOW",
}


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def render_markdown(report: ScanReport) -> str:
    """A report that reads well in a terminal, a PR, or a note-to-self."""
    out: list[str] = []
    add = out.append
    add(f"# D3TA1L3R self-audit — {report.target.display()}")
    add("")
    if report.demo:
        add("> **DEMO MODE.** Every result below is synthetic, generated locally from fixtures.")
        add("> No third-party service was contacted.")
        add("")
    add(f"- **Scan id:** `{report.scan_id}`")
    add(f"- **Started:** {_fmt(report.started_at)}")
    add(f"- **Duration:** {report.duration_ms / 1000:.1f}s")
    add(f"- **Tool:** D3TA1L3R {report.tool_version}")
    add(
        f"- **Coverage:** {report.stats.sources_total} sources — "
        f"{report.stats.sources_hit} with results, "
        f"{report.stats.sources_skipped} skipped, "
        f"{report.stats.sources_failed} failed"
    )
    add(f"- **Findings:** {report.stats.findings_total}")
    add("")

    if report.findings:
        add("## Findings")
        add("")
        for category, findings in report.findings_by_category().items():
            add(f"### {category} ({len(findings)})")
            add("")
            for finding in findings:
                add(f"#### {_CONFIDENCE_LABEL[finding.confidence]} — {finding.title or finding.source_name}")
                add("")
                add(f"- **Where:** [{finding.url}]({finding.url})")
                add(f"- **Identifier:** `{finding.identifier}`")
                add(f"- **Why this counts as a hit:** {finding.evidence}")
                if finding.bio:
                    add(f"- **Public bio:** {_one_line(finding.bio)}")
                if finding.location:
                    add(f"- **Public location:** {finding.location}")
                if finding.account_created_at:
                    add(f"- **Account created:** {finding.account_created_at}")
                exposure = finding.extra.get("exposure")
                if isinstance(exposure, list) and exposure:
                    add("- **Exposed fields:** " + "; ".join(str(item) for item in exposure))
                if finding.extra.get("homonym_warning"):
                    add("- **Warning:** name matches are not identity — confirm before acting.")
                add("")
    else:
        add("## Findings")
        add("")
        add("No accounts were located on the sources that ran. Check the coverage tables below "
            "before concluding you are invisible: skipped and failed sources are *unknown*, "
            "not clean.")
        add("")

    add("## Coverage")
    add("")
    for kind in ("username", "email", "name", "domain"):
        outcomes = [o for o in report.outcomes if o.kind.value == kind]
        if not outcomes:
            continue
        add(f"### {kind} sources ({len(outcomes)})")
        add("")
        add("| Result | Source | Category | HTTP | Time | Detail |")
        add("| --- | --- | --- | --- | --- | --- |")
        for outcome in outcomes:
            icon, label = _STATUS_LABEL[outcome.status]
            detail = outcome.error or outcome.skipped_reason or ""
            if outcome.status is ScanStatus.FOUND:
                detail = f"{len(outcome.findings)} finding(s)"
            add(
                f"| {icon} {label} | {outcome.source_name} (`{outcome.source_id}`) | "
                f"{outcome.category} | {outcome.http_status or '—'} | "
                f"{outcome.duration_ms} ms | {_one_line(detail, 90)} |"
            )
        add("")

    if report.warnings:
        add("## Caveats")
        add("")
        for warning in report.warnings:
            add(f"- {warning}")
        add("")

    add("## Remaining gaps (verify by hand)")
    add("")
    gaps = [
        o
        for o in report.outcomes
        if o.status
        in {
            ScanStatus.BLOCKED,
            ScanStatus.SKIPPED_ROBOTS,
            ScanStatus.SKIPPED_RATE_LIMITED,
            ScanStatus.ERROR,
            ScanStatus.TIMEOUT,
        }
    ]
    if gaps:
        add("| Source | Status | Why it could not be checked |")
        add("| --- | --- | --- |")
        for outcome in gaps:
            _, label = _STATUS_LABEL[outcome.status]
            add(
                f"| {outcome.source_name} (`{outcome.source_id}`) | {label} | "
                f"{_one_line(outcome.error or outcome.skipped_reason or 'unknown', 110)} |"
            )
    else:
        add("None — every selected source produced a definitive answer.")
    add("")

    add("## How to read confidence")
    add("")
    add("| Label | Meaning |")
    add("| --- | --- |")
    add("| CONFIRMED | A structured public API record describes the account. |")
    add("| HIGH | Unambiguous site signal (dedicated not-found response, stable phrase). |")
    add("| MEDIUM | Signature or status heuristic; verify before relying on it. |")
    add("| LOW | Weak heuristic or a same-name candidate. Treat as a lead, not a fact. |")
    add("")
    add(f"_Reproduce: recorded with signature database `{report.options.get('signature_db_sha256', 'n/a')}`._")
    add("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def render_json(report: ScanReport, *, indent: int | None = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)


# ---------------------------------------------------------------------------
# HTML (standalone, no assets, safe to email to yourself)
# ---------------------------------------------------------------------------
_CSS = """
:root { color-scheme: light dark; --bg:#0f1115; --panel:#171a21; --ink:#e8eaf0; --muted:#9aa3b2;
        --line:#252a34; --accent:#5eead4; --warn:#fbbf24; --bad:#fb7185; --ok:#4ade80; }
* { box-sizing: border-box; }
body { margin:0; padding:2.5rem 1.25rem 4rem; background:var(--bg); color:var(--ink);
       font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size:1.7rem; margin:0 0 .35rem; letter-spacing:-.02em; }
h2 { font-size:1.15rem; margin:2.4rem 0 .8rem; border-bottom:1px solid var(--line); padding-bottom:.4rem; }
h3 { font-size:.95rem; margin:1.6rem 0 .6rem; color:var(--muted); text-transform:uppercase;
     letter-spacing:.08em; font-weight:600; }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
.meta { display:flex; flex-wrap:wrap; gap:.5rem 1.25rem; color:var(--muted); font-size:.86rem; margin:.6rem 0 0; }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:.75rem; margin:1.4rem 0; }
.stat { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:.8rem .9rem; }
.stat b { display:block; font-size:1.5rem; letter-spacing:-.02em; }
.stat span { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.06em; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:1rem 1.1rem;
        margin:.7rem 0; }
.card h4 { margin:0 0 .35rem; font-size:1rem; }
.card p { margin:.25rem 0; color:var(--muted); font-size:.9rem; }
.badge { display:inline-block; font-size:.7rem; font-weight:700; letter-spacing:.06em; padding:.15rem .5rem;
         border-radius:999px; border:1px solid currentColor; margin-right:.5rem; vertical-align:2px; }
.confirmed { color:var(--ok); } .high { color:var(--accent); } .medium { color:var(--warn); } .low { color:var(--muted); }
table { width:100%; border-collapse:collapse; font-size:.88rem; }
th,td { text-align:left; padding:.45rem .5rem; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }
tr.found td:first-child { color:var(--ok); } tr.error td:first-child, tr.timeout td:first-child { color:var(--bad); }
tr.blocked td:first-child { color:var(--warn); } tr.skipped_robots td:first-child,
tr.skipped_rate_limited td:first-child { color:var(--muted); }
.warn { background:#3a2b0c; border-left:3px solid var(--warn); padding:.7rem .9rem; border-radius:8px;
        margin:.5rem 0; font-size:.88rem; }
.demo { background:#3a1220; border-left:3px solid var(--bad); padding:.8rem 1rem; border-radius:8px; }
code { background:#0b0d12; border:1px solid var(--line); border-radius:6px; padding:.05rem .35rem; font-size:.85em; }
.bar { height:.5rem; background:var(--line); border-radius:999px; overflow:hidden; margin:.9rem 0 0; }
.bar > i { display:block; height:100%; background:linear-gradient(90deg,var(--accent),var(--ok)); }
footer { margin-top:3rem; color:var(--muted); font-size:.82rem; border-top:1px solid var(--line); padding-top:1rem; }
.tag { color:var(--muted); font-size:.78rem; }
"""


def render_html(report: ScanReport) -> str:
    """Standalone single-file HTML report (no external assets, no JS required)."""
    esc = html.escape
    parts: list[str] = []
    add = parts.append

    add("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    add("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    add("<meta name='robots' content='noindex,nofollow'>")
    add(f"<title>D3TA1L3R self-audit — {esc(report.target.display())}</title>")
    add(f"<style>{_CSS}</style></head><body><main>")

    add(f"<h1>D3TA1L3R self-audit — {esc(report.target.display())}</h1>")
    add(
        "<div class='meta'>"
        f"<span>scan <code>{esc(report.scan_id)}</code></span>"
        f"<span>{esc(_fmt(report.started_at))}</span>"
        f"<span>{(report.duration_ms / 1000):.1f}s</span>"
        f"<span>D3TA1L3R {esc(report.tool_version)}</span>"
        f"<span>signatures <code>{esc(str(report.options.get('signature_db_sha256', 'n/a')))}</code></span>"
        "</div>"
    )
    if report.demo:
        add("<div class='demo'><b>Demo mode.</b> Every result here is synthetic, produced locally "
            "from fixtures. No third-party service was contacted.</div>")

    add("<div class='stats'>")
    for value, label in (
        (report.stats.findings_total, "findings"),
        (report.stats.sources_hit, "sources with results"),
        (report.stats.sources_skipped, "skipped"),
        (report.stats.sources_failed, "failed"),
        (report.stats.hosts_contacted, "hosts contacted"),
        (report.stats.http_requests, "http requests"),
    ):
        add(f"<div class='stat'><b>{value}</b><span>{label}</span></div>")
    add("</div>")

    if report.warnings:
        add("<h2>Caveats</h2>")
        for warning in report.warnings:
            add(f"<div class='warn'>{esc(warning)}</div>")

    add("<h2>Findings</h2>")
    if not report.findings:
        add("<p class='tag'>Nothing located on the sources that ran — read the coverage table "
            "below: skipped and failed sources are <em>unknown</em>, not clean.</p>")
    for category, findings in report.findings_by_category().items():
        add(f"<h3>{esc(category)} — {len(findings)}</h3>")
        for finding in findings:
            add(_finding_card(finding, esc))

    add("<h2>Coverage</h2>")
    for kind in ("username", "email", "name", "domain"):
        outcomes = [o for o in report.outcomes if o.kind.value == kind]
        if not outcomes:
            continue
        add(f"<h3>{esc(kind)} sources — {len(outcomes)}</h3>")
        add("<table><thead><tr><th>Result</th><th>Source</th><th>HTTP</th><th>Time</th>"
            "<th>Detail</th></tr></thead><tbody>")
        for outcome in outcomes:
            icon, label = _STATUS_LABEL[outcome.status]
            detail = outcome.error or outcome.skipped_reason or ""
            if outcome.status is ScanStatus.FOUND:
                detail = f"{len(outcome.findings)} finding(s)"
            add(
                f"<tr class='{outcome.status.value}'><td>{esc(icon)} {esc(label)}</td>"
                f"<td><a href='{esc(outcome.query_url or outcome.docs_url or '#')}' rel='noopener noreferrer nofollow'>"
                f"{esc(outcome.source_name)}</a><br><span class='tag'>{esc(outcome.source_id)}</span></td>"
                f"<td>{outcome.http_status or '—'}</td><td>{outcome.duration_ms}&thinsp;ms</td>"
                f"<td>{esc(_one_line(detail, 160))}</td></tr>"
            )
        add("</tbody></table>")

    add("<footer>")
    add("<p>Confidence: <b class='confirmed'>CONFIRMED</b> structured API record · "
        "<b class='high'>HIGH</b> unambiguous site signal · "
        "<b class='medium'>MEDIUM</b> signature/status heuristic · "
        "<b class='low'>LOW</b> weak heuristic or same-name candidate.</p>")
    add("<p>Generated locally by D3TA1L3R. This file contains personal data about the target of "
        "the scan — keep it private, and delete it when you are done.</p>")
    add("</footer></main></body></html>")
    return "".join(parts)


def _finding_card(finding: Finding, esc) -> str:
    title = esc(finding.title or finding.source_name)
    rows = [f"<p><a href='{esc(finding.url)}' rel='noopener noreferrer nofollow'>{esc(finding.url)}</a></p>"]
    rows.append(f"<p><b>Why this is a hit:</b> {esc(finding.evidence)}</p>")
    if finding.display_name:
        rows.append(f"<p><b>Name:</b> {esc(finding.display_name)}</p>")
    if finding.bio:
        rows.append(f"<p><b>Bio:</b> {esc(_one_line(finding.bio, 240))}</p>")
    if finding.location:
        rows.append(f"<p><b>Location:</b> {esc(finding.location)}</p>")
    if finding.account_created_at:
        rows.append(f"<p><b>Created:</b> {esc(finding.account_created_at)}</p>")
    exposure = finding.extra.get("exposure")
    if isinstance(exposure, list) and exposure:
        rows.append("<p><b>Exposed:</b> " + esc("; ".join(str(x) for x in exposure)) + "</p>")
    if finding.extra.get("homonym_warning"):
        rows.append("<p><b>Warning:</b> name matches are not identity — confirm before acting.</p>")
    avatar = (
        f"<img src='{esc(finding.avatar_url)}' alt='' width='44' height='44' "
        "style='border-radius:50%;float:right;margin-left:.75rem'>"
        if finding.avatar_url
        else ""
    )
    return (
        f"<div class='card'>{avatar}"
        f"<h4><span class='badge {finding.confidence.value}'>{_CONFIDENCE_LABEL[finding.confidence]}</span>"
        f"{title}</h4>" + "".join(rows) + "</div>"
    )


# ---------------------------------------------------------------------------
# Diffs
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ReportDiff:
    """What changed between two scans of the same target."""

    previous_scan_id: str
    current_scan_id: str
    target: str
    new_findings: list[Finding] = field(default_factory=list)
    removed_findings: list[Finding] = field(default_factory=list)
    changed_sources: list[tuple[str, str, str]] = field(default_factory=list)
    days_between: float = 0.0

    @property
    def empty(self) -> bool:
        return not (self.new_findings or self.removed_findings or self.changed_sources)

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_scan_id": self.previous_scan_id,
            "current_scan_id": self.current_scan_id,
            "target": self.target,
            "days_between": round(self.days_between, 2),
            "new_findings": [f.to_dict() for f in self.new_findings],
            "removed_findings": [f.to_dict() for f in self.removed_findings],
            "changed_sources": [
                {"source_id": sid, "was": was, "now": now} for sid, was, now in self.changed_sources
            ],
        }

    def render_markdown(self) -> str:
        out = [
            f"# Changes since scan `{self.previous_scan_id}`",
            "",
            f"Target: {self.target} · {self.days_between:.1f} days apart",
            "",
        ]
        if self.new_findings:
            out += ["## New findings", ""]
            for finding in self.new_findings:
                out.append(
                    f"- **{_CONFIDENCE_LABEL[finding.confidence]}** {finding.title or finding.source_name} "
                    f"— <{finding.url}>"
                )
            out.append("")
        if self.removed_findings:
            out += ["## Findings that disappeared", ""]
            for finding in self.removed_findings:
                out.append(f"- {finding.title or finding.source_name} — <{finding.url}>")
            out.append("")
        if self.changed_sources:
            out += ["## Source status changes", "", "| Source | Was | Now |", "| --- | --- | --- |"]
            for source_id, was, now in self.changed_sources:
                out.append(f"| `{source_id}` | {was} | {now} |")
            out.append("")
        if self.empty:
            out.append("_No changes detected._")
        return "\n".join(out)


def diff_reports(previous: ScanReport, current: ScanReport) -> ReportDiff:
    """Compare two scans of the same target by finding URL and source status."""
    diff = ReportDiff(
        previous_scan_id=previous.scan_id,
        current_scan_id=current.scan_id,
        target=current.target.display(),
    )
    diff.days_between = (current.started_at - previous.started_at).total_seconds() / 86400

    before = {f.dedupe_key(): f for f in previous.findings}
    after = {f.dedupe_key(): f for f in current.findings}
    diff.new_findings = [finding for key, finding in after.items() if key not in before]
    diff.removed_findings = [finding for key, finding in before.items() if key not in after]

    for outcome in current.outcomes:
        old = previous.outcome(outcome.source_id)
        if old is None:
            continue
        if old.status is not outcome.status:
            diff.changed_sources.append((outcome.source_id, old.status.value, outcome.status.value))
    return diff


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _fmt(moment: datetime | None) -> str:
    if moment is None:
        return "—"
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _one_line(text: str | None, limit: int = 200) -> str:
    if not text:
        return ""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"
