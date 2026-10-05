# D3TA1L3R

**Automated self-audit of your own public digital footprint.**

D3TA1L3R takes identifiers *you* own — a handle, an email address, your name, a
domain — and checks them against **81 public sources** (68 enabled by default): curated profile pages
matched by signature, and public unauthenticated JSON APIs that return
structured records. It then tells you three things most tools gloss over:

1. **What it found**, with a confidence label and the exact evidence behind it.
2. **What it could not check** — sign-in walls, robots.txt refusals, rate limits,
   broken signatures. A gap is reported as a gap, never as "clean".
3. **What changed** since your last scan, so you can watch your own footprint
   drift over time.

```console
$ d3ta1l3r scan -u alice -e me@example.com -d example.com
D3TA1L3R — @alice al***@example.com domain:example.com
  7 finding(s) from 7 source(s) · 60 checked · 4 skipped · 1 failed · 5.8s · 71 request(s) to 52 host(s)
    confirmed  GitHub (REST API)      https://github.com/alice
    confirmed  Gravatar               https://gravatar.com/…
     confirmed  GitLab (API)          https://gitlab.com/alice
      medium  Steam                   https://steamcommunity.com/id/alice
  4 source(s) could not be checked (blocked, robots, errors) — these are gaps, not clean results.
  wrote scans/20261005T091500Z-alice-a1b2c3d4e5f6.json
  wrote scans/20261005T091500Z-alice-a1b2c3d4e5f6.md
  wrote scans/20261005T091500Z-alice-a1b2c3d4e5f6.html
```

> **Scope.** This is a *self*-audit tool. It only ever queries the identifiers you
> give it, only against public endpoints, and it never touches people-search
> brokers, breach corpora, phone/address lookups or credential dumps. It does not
> defeat logins, CAPTCHAs or anti-bot controls. Read
> [`docs/SCOPE.md`](docs/SCOPE.md) before pointing it at anything.

---

## Why it exists

Most "OSINT" tooling is built to investigate *other* people, and its output is a
pile of maybe-matches with no provenance. That is a bad fit for the actual
question most people have: *what of mine is already out there, and can I trust
what this tool just told me?*

So D3TA1L3R is built the other way around:

| Design choice | Why |
| --- | --- |
| Every hit carries `evidence` and a confidence level | `CONFIRMED` (a structured API record) is never printed next to `LOW` (a name collision) as if they were the same claim |
| Skipped and failed sources are first-class results | "We could not check Instagram" is information; silently dropping it is a lie about coverage |
| `d3ta1l3r calibrate` measures its own false-positive rate | HTML signatures rot. Calibration probes handles that certainly do not exist and names any site that claims to have found them |
| Demo mode | The whole pipeline (and the dashboard) can be shown and tested with zero requests to third parties |
| Reports record the signature-database hash and transport settings | A finding can be reproduced months later against the same spec set |
| robots.txt is honoured and failures are surfaced | Politeness is a feature, and obeying a site's wishes is a legitimate outcome |

## Install

```bash
git clone https://github.com/codero-sus/D3TA1L3R.git && cd D3TA1L3R

python -m venv .venv && . .venv/bin/activate
pip install -e .            # engine + CLI
pip install -e '.[web]'     # ...plus the dashboard
pip install -e '.[dev]'     # ...plus the test suite
```

Python 3.10+. The only runtime dependency is `httpx`; the web dashboard adds
FastAPI/uvicorn/Jinja2, and nothing else is needed even then.

## Quick start

```bash
# 1. See what would be checked, and what is deliberately not
d3ta1l3r sources

# 2. Run a real scan of your own identifiers
d3ta1l3r scan -u yourhandle -e you@example.com -n "Your Name" -d yourdomain.com

# 3. Read the report (Markdown / HTML / JSON are all written)
open scans/*.html

# 4. Try it safely first, or in an environment with no egress
d3ta1l3r scan -u anything --demo

# 5. Open the dashboard
d3ta1l3r web --port 8000            # then browse http://localhost:8000
```

Reports land in `./scans/` as `20261005T091500Z-<target>-<scan_id>.{json,md,html}`.
[`examples/sample-report.md`](examples/sample-report.md) is one of them, generated
entirely in demo mode, so you can judge the output before installing anything.
They contain personal data — the directory is gitignored on purpose, and
`rm -rf scans` is a complete clean-up.

### Common flags

```bash
--sources github_api_user,gravatar_api_email   # run a subset (see `d3ta1l3r sources`)
--exclude-sources instagram_user               # skip noisy or slow ones
--categories developer,identity                # filter by category
--kind username,email                          # filter by identifier type
--min-confidence high                          # hide the low-confidence guesses
--max-sites 20                                 # quick pass
--cache-dir .cache                             # don't re-query sites you already scanned
--no-robots                                    # ignore robots.txt (not recommended)
--compare scans/<old>.json --fail-on-new       # exit 3 if something new appeared (CI)
-o reports/                                    # where to write reports
```

## What gets checked

`d3ta1l3r sources` prints the full inventory. Highlights:

- **Developer / identity** — GitHub, GitLab, Codeberg, Docker Hub, Keybase
  (including your published proofs), npm (by maintainer *and* by maintainer
  email), PyPI, crates.io, Codepen, Kaggle, LeetCode, Exercism, Hugging Face…
- **Social / media / gaming** — Bluesky, Mastodon, Hacker News, Chess.com,
  Lichess, Codeforces, speedrun.com, Steam, Letterboxd, Last.fm, AniList,
  SoundCloud, Behance, Dribbble, DeviantArt, itch.io, osu!…
- **Identity** — Gravatar profiles bound to your email (often the most revealing
  thing you forgot about), and RDAP registration records for your domains
  (including an expiry warning).
- **Research records** — OpenAlex, arXiv, PubMed, ORCID, Wikipedia; always
  `LOW` confidence, because names are not unique and a same-name paper is not
  you.

Sites that require a login, fight automation, or are unverified ship
**disabled by default** with a note explaining why — see
[`docs/SOURCES.md`](docs/SOURCES.md) for the list and the rules a spec must obey.

## Confidence, honestly

| Label | Meaning | Act on it? |
| --- | --- | --- |
| `CONFIRMED` | A structured public API record describes the account. | Yes |
| `HIGH` | Unambiguous site signal (dedicated not-found response + a stable phrase). | Yes |
| `MEDIUM` | Signature or status-code heuristic. | Verify first |
| `LOW` | Weak heuristic, or a same-name candidate. | Treat as a lead only |

Statuses that are **not** findings: `blocked` (sign-in wall or refused access),
`skipped: robots.txt`, `skipped: rate limited`, `error` (including "the page
layout changed and the signature no longer matches"). All of them mean *unknown*.

### Calibrating the signatures

```bash
d3ta1l3r calibrate --all                          # bogus-handle false-positive check
d3ta1l3r calibrate --sites steam_user --expect-hit steam_user=your_account
```

The first form probes handles such as `zzq4f9c1a7b2e3d` (which certainly do not
exist) and flags any site that claims to have found them. The second verifies
that a site still detects an account you know exists. Results are saved to
`scans/calibration-*.json`. Run this before trusting a `HIGH` label on a site
you have never seen the tool check before.

## Watching for changes

```bash
d3ta1l3r diff scans/2026-09-01T120000Z-alice-*.json scans/2026-10-01T120000Z-alice-*.json
d3ta1l3r scan -u alice --compare scans/<previous>.json --fail-on-new   # exits 3 if new
```

A diff reports findings that appeared, findings that vanished (accounts you
deleted, pages you locked down) and sources whose answer changed, so it is a
usable "did anything about me change this month?" command — and exit code `3`
makes it a CI gate.

## Dashboard

```bash
d3ta1l3r web --port 8000            # binds 0.0.0.0 so containers/proxies can reach it
d3ta1l3r web --host 127.0.0.1       # bind to loopback if you are the only user
d3ta1l3r web --demo                 # synthetic results, no outbound requests
```

The dashboard runs scans, streams live progress over Server-Sent Events (with
polling fallback), renders the same findings and coverage tables, offers
JSON/Markdown/standalone-HTML export, and can run the calibration check. It
stores everything in the same `scans/` directory as the CLI. All request URLs in
the frontend are relative, so it works unchanged behind a reverse proxy.

## Library use

```python
import asyncio
from d3ta1l3r import ScanConfig, ScanEngine, ScanTarget

async def main() -> None:
    engine = ScanEngine(ScanConfig())
    report = await engine.scan(
        ScanTarget.create(username="alice", email="alice@example.com")
    )
    for finding in report.findings:
        print(f"{finding.confidence.value:>9}  {finding.source_name:<22} {finding.url}")
        print(f"           why: {finding.evidence}")
    for outcome in report.outcomes:
        if not outcome.ok:
            print(f"  gap: {outcome.source_name} — {outcome.error or outcome.skipped_reason}")

asyncio.run(main())
```

More in [`examples/`](examples/): a quickstart and a custom source plugin.

## Architecture

```
d3ta1l3r/
  models.py           typed results (Finding, SourceOutcome, ScanReport…), stdlib only
  config.py           timeouts, politeness limits, source filters
  cli.py              scan | sources | calibrate | diff | web
  core/
    security.py       identifier validation + the SSRF guard (every URL goes through it)
    http.py           one transport: manual redirects, retries, body caps, robots, cache
    robots.py         RFC 9309 robots.txt, cached per host
    ratelimit.py      per-host token buckets, global concurrency, backoff
    engine.py         source selection, bounded concurrency, failure containment, events
    report.py         Markdown / standalone HTML / JSON + report diffs
    storage.py        the scans/ directory layout
    demo.py           synthetic fixtures for --demo
  sources/
    base.py           source contract: one question, one identifier kind, explainable hits
    probe.py          signature-driven public-page probes (specs live in data/sites.json)
    api/              typed clients for public JSON APIs
  data/sites.json     the signature database (data, not code)
  web/                FastAPI dashboard + templates + assets
tests/                276 tests, offline via httpx.MockTransport
```

Design rules enforced in code (and in the test suite):

- **One transport.** Every request goes through `Fetcher`: robots check, SSRF
  guard per URL *and per redirect hop*, retries with `Retry-After`, a 256 KiB
  body cap, and header filtering. Sources cannot bypass it.
- **Sources cannot crash a scan.** `BaseSource.execute` converts any exception
  into a recorded status; a source that returns the wrong payload shape raises
  instead of inventing a hit.
- **Deterministic output.** Outcomes are ordered by source weight, so two scans
  of the same target diff cleanly.

## Development

```bash
pip install -e '.[dev]'
pytest                       # 276 tests, no network access required
pytest -m network            # opt-in: the handful of live checks
ruff check d3ta1l3r tests
```

The test suite runs entirely against `httpx.MockTransport` plus the demo
fixtures, so it also works in a sandbox with no egress. Tests are expected to
pin the tool's *claims*, not just its code paths: signature semantics, the
"unknown ≠ absent" rule, escaping of hostile content in reports, the SSRF guard,
and the exit codes CI depends on.

## Legal and ethical use

- Only audit identifiers **you own**. Running this against someone else is a
  privacy violation in most jurisdictions and may breach computer-misuse law.
- Everything here is public, unauthenticated information — the same thing any
  visitor sees. That does not make bulk processing of someone else's data lawful.
- Respect the sites you touch: leave the default rate limits and robots
  behaviour alone, and set a contact address
  (`export D3TA1L3R_UA_EMAIL=you@example.com`) so operators can reach you.
- Reports are personal data. Keep them private; delete them when you are done.

MIT licensed — see [LICENSE](LICENSE).
