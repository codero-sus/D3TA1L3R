"""Writing your own source: two ways to extend D3TA1L3R.

1. **Add a public-page probe** by describing it in JSON (no Python at all).
   Useful for a niche forum that exposes a plain profile page.
2. **Write an API source** when a site publishes a structured record.

Both are then passed straight to the engine; nothing else in the tool needs to
know about them.

Run it offline first::

    python examples/custom_source.py --demo
    python examples/custom_source.py -u your_handle            # real requests

The example target (``https://example.com/{username}``) does not exist as a
service — replace it with a site you actually want to check, and calibrate the
signature before trusting it::

    d3ta1l3r calibrate --sites my_forum_user
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from d3ta1l3r import ScanConfig, ScanEngine, ScanTarget  # noqa: E402
from d3ta1l3r.models import Confidence, ScanStatus, SourceKind, SourceOutcome  # noqa: E402
from d3ta1l3r.sources.api.base import ApiSource, dig  # noqa: E402
from d3ta1l3r.sources.base import SourceMeta  # noqa: E402
from d3ta1l3r.sources.probe import SiteSpec, UsernameProbeSource  # noqa: E402

# ---------------------------------------------------------------------------
# 1. A declarative probe: "this forum shows an error phrase for missing users"
# ---------------------------------------------------------------------------
FORUM_SPEC = SiteSpec(
    id="my_forum_user",
    name="My Forum",
    url="https://forum.example.net/u/{username}",
    category="community",
    detector="marker",
    # Phrase that appears only on a real profile page:
    found_marker="user-profile-header",
    # Phrase the site renders for a handle that does not exist:
    not_found_marker="user not found",
    # Path the site redirects to when it wants you to sign in (means "unknown"):
    login_redirect_markers=["/login"],
    confidence_found=Confidence.HIGH,
    notes="Custom example spec — calibrate before trusting it.",
    weight=500,
)


# ---------------------------------------------------------------------------
# 2. An API source: structured JSON from a fictional internal service
# ---------------------------------------------------------------------------
class NotesServiceUser(ApiSource):
    """Looks up an account in an internal notes service with a public read API."""

    meta = SourceMeta(
        id="notes_service_user",
        name="Notes Service (API)",
        kind=SourceKind.USERNAME,
        category="identity",
        description="Public account record from the notes service's read-only API.",
        docs_url="https://notes.example.net/api",
        # Not enabled by default: a plugin should opt in explicitly, normally by
        # adding it to the package rather than passing it to one ScanEngine.
        enabled_by_default=True,
        weight=501,
    )

    def query_url(self, identifier: str) -> str:
        return f"https://notes.example.net/api/users/{self.quote(identifier)}"

    async def run(self, identifier: str, target: ScanTarget) -> SourceOutcome:
        started = self.now()
        result = await self.fetch_json(self.query_url(identifier))
        if not result.ok:  # 404/403/429/5xx handled centrally and labelled honestly
            return self.outcome_for(result, identifier=identifier, started=started)

        data = self.require_mapping(result, "Notes service user")
        finding = self.finding(
            identifier=identifier,
            url=self.query_url(identifier),
            confidence=Confidence.CONFIRMED,
            evidence=(
                "notes.example.net returned the account record for "
                f"'{dig(data, 'username', default=identifier)}'"
            ),
            title=f"Notes @{dig(data, 'username', default=identifier)}",
            display_name=dig(data, "display_name"),
            bio=dig(data, "bio"),
            account_created_at=dig(data, "created_at"),
            extra={"visibility": dig(data, "visibility")},
        )
        return self.outcome_for(result, identifier=identifier, started=started, findings=[finding])


async def main() -> int:
    parser = argparse.ArgumentParser(description="D3TA1L3R custom-source example")
    parser.add_argument("-u", "--username", default="example_user")
    parser.add_argument("--demo", action="store_true",
                        help="use the built-in fixtures (your plugin will report a gap)")
    parser.add_argument("--probe-only", action="store_true",
                        help="run only the declarative spec, not the API source")
    args = parser.parse_args()

    sources = [UsernameProbeSource(FORUM_SPEC)]
    if not args.probe_only:
        sources.append(NotesServiceUser())

    engine = ScanEngine(ScanConfig(demo=args.demo), sources=sources)
    report = await engine.scan(ScanTarget.create(username=args.username))

    print(f"custom scan finished in {report.duration_ms / 1000:.1f}s")
    for outcome in report.outcomes:
        label = outcome.status.value
        detail = outcome.error or outcome.skipped_reason or ""
        print(f"  {outcome.source_id:<22} {label:<18} {detail[:80]}")
        for finding in outcome.findings:
            print(f"      → {finding.confidence.value.upper()}: {finding.evidence}")

    # Every plugin is also subject to the containment rule: an unexpected payload
    # or a broken site produces an error outcome, never a fabricated finding.
    errors = [o for o in report.outcomes if o.status is ScanStatus.ERROR]
    skipped = [o for o in report.outcomes if o.status is ScanStatus.SKIPPED_ROBOTS]
    if args.demo:
        print(
            "\nIn --demo mode the fictional example.net hosts have no fixtures, so the\n"
            "robots.txt fetch fails closed and both sources report 'skipped_robots'.\n"
            "Run without --demo (and with a real site) to see live results."
        )
    else:
        print(f"\n{len(errors)} error(s), {len(skipped)} robots skip(s) — a plugin that\n"
              "cannot reach its site reports a gap; it never guesses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
