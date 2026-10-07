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
pip install -e '.[dev]'     # ...plus the dashboard stack and the test suite
```

Python 3.10+. Runtime dependencies are `httpx` (the engine) and `cryptography`
(the vault); the web dashboard adds FastAPI/uvicorn/Jinja2/python-multipart. The
scanning engine itself is stdlib-only, and nothing is needed beyond those even
then.

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

# 6. Build an encrypted watchlist of your own identifiers
d3ta1l3r vault init                 # prompts for a passphrase (>= 12 chars)
d3ta1l3r vault add --kind email you@example.com --label personal
d3ta1l3r vault add --kind password --store-hash   # checked via k-anonymity, never stored

# 7. Check that watchlist against breach sources
d3ta1l3r breach run                 # exit 3 if something was found, 2 if nothing could be checked

# 8. ...and have the dashboard re-check it every time you log in
d3ta1l3r web --vault --port 8000    # the login passphrase *is* the vault passphrase

# 9. Ask questions about your own scans — with a model on this machine
d3ta1l3r ask "what should I fix first, and what could not be checked?"

# 10. Pick a model, and fetch it only if you decide to
d3ta1l3r models list                 # the catalogue, smallest first, with licences
d3ta1l3r models pull qwen2.5-1.5b-instruct-q4_k_m   # asks, then downloads, then verifies

# 11. Optionally, let that model give a second opinion on who is who
d3ta1l3r ask --verify --about "my bios mention chess and Berlin" --only-uncertain
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

## Vault and breach watch

Your identifiers live in one encrypted file, and the breach watch re-checks them.

```bash
d3ta1l3r vault init                       # scrypt + Fernet, written 0600
d3ta1l3r vault add --kind email you@example.com --label personal
d3ta1l3r vault add --kind phone "+91 98100 00010"
d3ta1l3r vault add --kind username yourhandle
d3ta1l3r vault list                       # masked values only
d3ta1l3r vault where                      # path + file permissions, no passphrase needed
d3ta1l3r vault rotate --new-passphrase-file new.txt
d3ta1l3r breach run                       # check everything, record the outcome
d3ta1l3r breach sources                   # what is usable, and what each one sends
```

`vault add` checks the entry immediately, so a password you paste is checked
before it is forgotten. What the breach sources do and do not do:

| Source | Needs | Sends | Answer |
| --- | --- | --- | --- |
| `pwned_passwords` | nothing | 5 hex characters of `SHA-1(password)` | `pwned` (with a count) or `clean` |
| `hibp_breaches` | your own HIBP key | the email address itself | `pwned` (with breach names) or `clean` |
| `local_corpus` | a file you supply (`--corpus`) | nothing | match / no match |

Three rules the code enforces, because breach checking is where tools like this
usually go wrong:

- **Passwords are never stored.** `--store-hash` keeps a SHA-1 *verifier* so the
  dashboard can re-check a password at login; without it, the password is checked
  once and forgotten. Turn it off for anything you do not want testable offline
  by someone who learns your vault passphrase.
- **No dumps.** D3TA1L3R never downloads, mirrors or bundles a leaked database.
  A corpus is a file you already have; `d3ta1l3r breach corpus-hash plain.txt`
  turns a plaintext list into hashes so you can match without keeping the values.
- **A gap is not a pass.** Without an HIBP key, or when a service rate-limits you,
  or when a password has no verifier, the run reports `unknown` with a reason.
  `breach run` exits `3` when something was found and `2` when nothing could be
  checked at all — so a CI job can tell "clean" from "we could not look".

Everything above also happens from the dashboard: `d3ta1l3r web --vault` asks for
the vault passphrase **at login** (there is no second password to remember) and
re-checks the watchlist the moment you sign in. The passphrase is entered in the
browser and never passed to the server process as an argument; sessions are
`HttpOnly` + `SameSite=Lax`, live 8 hours, and die when the process restarts.
Five failed logins lock that address out for five minutes.

## Ask your own scans (a local model, or none)

A report answers the questions you thought to ask. `ask` answers the ones you
think of while reading it — *what should I fix first?*, *which of these still
exposes my real name?*, *what could not be checked?* — using a model that runs
**on this machine**, or, if there is no model, plain retrieval over the report.

```bash
d3ta1l3r ask --list-models "which model fits?"     # probe backends + the 4 GB table
d3ta1l3r ask "what should I fix first?"            # masks identifiers by default
d3ta1l3r ask "where is my handle visible?" --include-values
d3ta1l3r ask --report scans/20261005T091500Z-demo_user-abc123.json "what changed?"
d3ta1l3r ask "is my email in the breach watch?" --json
```

Two backends are real, and both are local:

```bash
pip install llama-cpp-python                # optional extra, builds from source
d3ta1l3r ask --model ~/models/qwen2.5-1.5b-instruct-q4_k_m.gguf "summarise"

# or an Ollama daemon on loopback (the only host it will talk to)
ollama pull llama3.2:1b
d3ta1l3r ask --backend ollama --ollama-model llama3.2:1b "summarise"
```

### The catalogue, and where the weights come from

Ten GGUF models ship as a catalogue — sizes, resident memory, context window and
licence for each — and nothing is fetched until you name one:

```bash
d3ta1l3r models list                      # smallest first, with licence and provenance
d3ta1l3r models list --fits-memory        # only what this machine's RAM can hold
d3ta1l3r models list --downloaded --json  # what you already have, for scripts
d3ta1l3r models search qwen2.5 gguf       # live Hugging Face search (no key needed)
d3ta1l3r models add TheBloke/Some-7B-GGUF/some-7b.Q4_K_M.gguf --name "Some 7B"
d3ta1l3r models pull qwen2.5-1.5b-instruct-q4_k_m   # size shown, confirmation asked
d3ta1l3r models path                      # where models live, plus free space
d3ta1l3r models remove some-7b            # --catalogue-only forgets the entry, keeps the file
```

The catalogue is listed **before** anything is downloaded, every entry names its
licence and repository, and `models pull` prints the download size and asks
first (`--yes` to skip). Files land in `~/.cache/d3ta1l3r/models` (or
`$D3TA1L3R_MODELS`); a partial download keeps its `.part` file and resumes with
one range request, a finished one is checked against the length and SHA-256 the
repository reports, and a file that turns out to be an HTML page is rejected
rather than kept. Nothing is bundled with this tool and nothing is downloaded
unless you ask for it by name. `HF_TOKEN` is used only if you have already put
one in your environment — the public models here need no key.

The dashboard shows the same catalogue on the main page — name, parameters,
download size, memory, licence and repository for every entry, with a *download*
button per row. That button asks for the size and licence in a confirmation
dialog before anything starts, one download runs at a time, and progress is
reported while it runs; nothing is fetched by looking at the page.

Right-sized for a 4 GB machine (CPU only, no GPU):

| Model | Download | Resident | Note |
| --- | --- | --- | --- |
| TinyLlama-1.1B-Chat Q4_K_M | ~670 MB | ~900 MB | smallest useful chat model |
| Qwen2.5-1.5B-Instruct Q4_K_M | ~1.1 GB | ~1.5 GB | the best balance at this size |
| Llama-3.2-3B-Instruct Q4_K_M | ~2.0 GB | ~2.4 GB | better prose, little headroom left |
| Phi-3-mini-4k-instruct Q4 | ~2.3 GB | ~2.7 GB | upper bound; expect swapping |

The catalogue goes up to 32B (`qwen2.5-32b-instruct-q4_k_m`, ~19.8 GB) for
machines that can take it. `--ram-budget` (default 4096 MB) makes the tool
*refuse* a model that would not fit rather than letting the OOM killer decide,
and the KV cache is counted with the weights.

`d3ta1l3r ask --model` accepts a path to a `.gguf`, a catalogue id,
`repo/file.gguf`, or `auto` — which picks the best model that is downloaded *and*
fits here, and says so when there is none.

If this machine cannot reach `huggingface.co` — a locked-down network, a sandbox,
a proxy that only allows some hosts — `models pull` says so and stops, leaving a
`.part` file it can resume from later. `models list` still works (the catalogue is
local), and a file fetched elsewhere can either be dropped into the models
directory or pointed at directly: `d3ta1l3r ask --model ~/Downloads/model.gguf`.

What the feature promises, and what the tests pin:

- **It is local, and that is enforced.** `OllamaBackend` raises on any non-loopback
  host; there is no hosted-model client in the codebase, and a test asserts no
  commercial model API is named anywhere under `d3ta1l3r/llm/`.
- **Answers cite ids.** The prompt is a numbered digest (`F1-003` is finding 3 of
  scan 1, `E2` is watchlist entry 2, `G1-01` is a gap) and the model must cite
  what it used. Invented ids are detected and reported by the CLI; the dashboard
  removes them before rendering.
- **Masked by default.** Identifiers reach the prompt as `al***@example.com`
  unless you pass `--include-values`. Masking also scrubs finding URLs, evidence
  text and labels, because that is where a handle actually hides.
- **Nothing is written to disk.** Transcripts live in memory for the session and
  are dropped on logout; asking a question never adds a file next to your reports.
- **No model is a valid answer.** Without `llama-cpp-python` or Ollama, the same
  command answers from the report by retrieval and says so — the chat is never a
  dead box, and it never pretends a retrieval answer came from a model.

The dashboard has the same panel (question box, raw-values toggle, "answered by"
line) on the main page once you are signed in. `ask` needs a report: run a scan
first, or point it at a JSON file with `--report`.

### Verifying that a finding is really you (opt-in)

Some findings are ambiguous: a handle that matches, on a site that never shows a
name. `--verify` hands those to the local model and asks it to judge each one —
but **only when you ask for it**. A plain `scan`, `ask`, `web` or `breach` run
never does this, and a test asserts it.

```bash
d3ta1l3r ask --verify --about "my bios mention chess; I lived in Berlin until 2024"
d3ta1l3r ask --verify --about-file about-me.txt --only-uncertain   # skip what is already clear
d3ta1l3r ask --verify --verify-limit 10 --verify-markdown > review.md
d3ta1l3r ask --verify --json                                       # for the dashboard or a script
```

The model answers one `VERDICT <id> MINE|NOT_MINE|UNSURE — reason` line per
finding, and the parser is strict on purpose:

- **A verdict is an opinion, never evidence.** It is stored beside the measured
  confidence and cannot raise it. A `NOT_MINE` about a `confirmed`/`high`
  finding is printed with a ⚠ because one of the two is wrong, and the tool will
  not guess which.
- **Gibberish is not "yes".** An unparseable `VERDICT` line becomes `unsure` and
  is marked `parsed: false`; an id the model invented is dropped; a finding the
  model skipped is filled in as "the model did not answer", not left blank. The
  prompt tells the model to say `UNSURE` whenever the evidence cannot tell two
  people apart, and "it's me" is the failure mode the whole design leans against.
- **No model, no verdict.** If neither `llama-cpp-python` nor Ollama is
  available, `--verify` exits with an error and judges nothing, rather than
  printing a page of `unsure` lines that would read like a completed review.
- **Masked by default.** The identifiers you searched reach the prompt as
  `al***@example.com` unless you pass `--include-values`; either way, nothing is
  written to disk.

The dashboard has the same feature on the main page, behind a checkbox: the
*Review identity* button is disabled until you tick it, the reviewed findings and
their measured confidence appear side by side with the verdict and the reason,
and a disagreement with a strong finding is marked in place. Verdicts are written
into the page as text, never as HTML.

What this is *not*: proof of ownership. It cannot distinguish you from a
namesake with a similar profile, and a wrong "looks like you" is more likely
than a wrong finding. A cryptographic check — a DNS `TXT` record, a `rel=me`
link, a token posted in a profile you control — would be stronger evidence, and
is not implemented yet; `docs/SCOPE.md` records it as a known gap.

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
d3ta1l3r web --vault --port 8000    # unlock your watchlist at login
```

The dashboard runs scans, streams live progress over Server-Sent Events (with
polling fallback), renders the same findings and coverage tables, offers
JSON/Markdown/standalone-HTML export, and can run the calibration check. With
`--vault` it also serves the watchlist, masks every value it renders, and runs
the breach watch at each login. It stores everything in the same `scans/`
directory as the CLI (breach reports under `scans/breach/`). All request URLs in
the frontend are relative, so it works unchanged behind a reverse proxy; the CSRF
guard trusts the request `Host`, `X-Forwarded-Host`, anything in
`D3TA1L3R_TRUSTED_ORIGINS`, and the E2B sandbox preview origin when
`E2B_SANDBOX_ID` is set.

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
  cli.py              scan | sources | calibrate | diff | vault | breach | web
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
  vault.py            encrypted watchlist (scrypt + Fernet, atomic 0600 writes)
  breach.py           breach sources: k-anonymity range API, HIBP, local corpus
  llm/                the local report chat (GGUF, loopback Ollama, retrieval)
    context.py        the numbered digest a model may cite
    backends.py       local-only backends + the 4 GB sizing arithmetic
    cite.py           citation verification (invented ids are caught)
  web/                FastAPI dashboard + templates + assets
    auth.py           sessions, login throttle, CSRF/origin guard
tests/                526 tests, offline via httpx.MockTransport
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
- **A check that did not happen is a gap.** `clean` is only ever produced by a
  source that answered; everything else is `unknown` with a reason, in both the
  scan engine and the breach watch. The tests assert that a missing key, a 429 or
  a missing corpus never turns into good news.
- **Secrets stay out of the process table.** The vault passphrase arrives by
  prompt, `D3TA1L3R_VAULT_PASSPHRASE` or `--passphrase-file`; a password to check
  arrives by prompt or stdin. Neither is ever an argument, and no password is ever
  written to disk.

## Development

```bash
pip install -e '.[dev]'
pytest                       # 526 tests, no network access required
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
- Breach checking is for **your own** identifiers. Never point the watchlist at
  an address you do not control: the HIBP endpoint takes a raw address, and
  running it against somebody else's is exactly the abuse HIBP's own terms
  prohibit.
- D3TA1L3R ships no dump and never downloads one. If you keep a corpus, keep it
  hashed (`d3ta1l3r breach corpus-hash`) and delete it when you are done.

MIT licensed — see [LICENSE](LICENSE).
