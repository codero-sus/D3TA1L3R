# Scope, boundaries and threat model

D3TA1L3R is a **self-audit** tool. This document states precisely what it will
and will not do, and why — so that the boundary is a design property you can
verify in the code, not a promise in a README.

## 1. What it does

Given identifiers you supply — a handle, an email address, a personal name, a
domain you own — D3TA1L3R:

1. Queries **public, unauthenticated** endpoints: curated public profile pages
   (matched against declared signatures) and public JSON APIs that need no key.
2. Records, for every source, what happened: a hit, a definitive absence, or one
   of the honest *unknown* states (sign-in wall, robots refusal, rate limit,
   transport error, changed layout).
3. Writes a report that separates high-confidence evidence from weak
   heuristics, lists what it could not check, and can be diffed against a
   previous scan.

That's the entire feature set. There is no "expand" mode, no person enumeration,
no correlation across people.

## 2. What it refuses to do

These are hard limits, enforced by omission and by guards in code:

| Refused | Where it is enforced |
| --- | --- |
| People-search brokers, data brokers, background-check services | No such source exists; `docs/SOURCES.md` explains why adding one is out of scope |
| Breach corpora, credential dumps, paste-site lookups | Same; `Have I Been Pwned`-style checks are deliberately absent even though they need only an email address |
| Phone number, home address, relatives, "who lives at" lookups | Not implemented; `validate_username` also rejects the query shapes they would need |
| Scraping behind a login, CAPTCHA solving, IP rotation, UA spoofing to evade blocks | `core/http.py` sends one honest User-Agent and treats 401/403 as `blocked`; sites that fight automation ship `enabled_by_default: false` |
| Querying identifiers other than the ones supplied | Sources read `ScanTarget.identifiers` and nothing else; there is no pivot/enumeration step |
| Reaching internal, loopback or metadata addresses | `assert_public_url` runs on **every** URL *and every redirect hop* (`core/security.py`), with an optional DNS-level check (default on) |
| Bulk scraping: hundreds of probes per site, unbounded concurrency | Per-host token bucket (`--rps`, default 2/s), global concurrency cap (default 16), `--max-sites`, capped `Crawl-delay` honouring, response retry caps |

If you need something on the left-hand side of that table, D3TA1L3R is the wrong
tool, and for a third party's identifiers it is also the wrong *act*.

## 3. Why the limits are where they are

- **Public ≠ fair game.** Publicly reachable data about a person is still
  personal data under GDPR/UK-GDPR, India's DPDP Act, and similar regimes.
  Processing it without a lawful basis is the problem, not the retrieval
  mechanism. That is why the tool is framed around *your own* identifiers.
- **Terms of service matter.** LinkedIn, X, Reddit and similar sites prohibit
  automated access and enforce it technically. Working around that would be
  both a ToS breach and (in several jurisdictions) a computer-misuse question.
  Those sources ship disabled with a note telling you to review your profile
  while signed in.
- **Unknown must look unknown.** Most harm from OSINT tooling comes from
  confident-but-wrong output. Every ambiguous case is surfaced as an error or a
  gap, and every heuristic carries a confidence label.
- **Politeness is self-interest.** A tool that hammers public infrastructure
  gets rate-limited, blocked, or gets your IP banned. Defaults are slow on
  purpose and `--no-robots` is documented as "not recommended".

## 4. Data handling

- **Inputs**: kept in memory for the duration of a scan; written into reports
  only as part of the target description. Emails are masked in logs and console
  output (`al***@example.com`).
- **Outputs**: reports under `./scans/` (or `-o DIR`). They contain the findings
  — which is personal data about you. The directory is gitignored; the dashboard
  has a delete button per scan; `rm -rf scans` is a complete clean-up.
- **Cache** (`--cache-dir`): truncated copies of public responses, keyed by a
  hash of the request URL. Delete it with the reports.
- **Network**: requests go directly from your machine to the target site. There
  is no telemetry, no analytics, no update check, and no central service. The
  tool has no server component.
- **Credentials**: none. D3TA1L3R never asks for a username/password/token for
  any third-party service, and has no code path that could use one.

## 5. Threat model

What D3TA1L3R defends against:

- **Targeting a private network.** Every URL — including user-supplied custom
  templates and each redirect hop — passes `assert_public_url`, which rejects
  non-HTTP(S) schemes, embedded credentials, single-label hostnames, blocked
  suffixes (`.local`, `.internal`, …), and non-global IPs (`127.0.0.1`,
  `10/8`, `169.254.169.254`, `::1`, …). With `strict_ssrf=True` (default) every
  A/AAAA record is resolved and must be global, which also blunts DNS rebinding.
- **Weaponised content.** Responses are read with a 256 KiB cap
  (`--max-body-bytes` equivalent in config), decoded defensively, and parsed
  structurally. HTML never executes; report renderers escape all interpolated
  values (there is a test that feeds `<script>` and `onerror=` into every field
  and asserts the output is inert).
- **A hostile site hijacking the scan.** Redirect chains are manual and capped;
  cross-origin redirects are re-validated; response headers are filtered to the
  ones the tool actually reads.
- **A malformed/hostile API response inventing a hit.** Sources declare the
  payload shape they expect (`require_mapping` / `require_sequence`) and raise
  otherwise; the exception becomes an `error` outcome, never a finding.
- **A crashed scan.** Every source is wrapped: any exception becomes a recorded
  outcome with a message. There is a test that runs a source which raises
  `RuntimeError` and asserts the rest of the scan completes.

What it does **not** defend against (out of scope): a compromised local machine,
a hostile local network capturing traffic (use a trusted network; there is no
proxy/tunnel feature), and misidentification by *other* tools that scan you.

## 6. Responsible use checklist

Before a scan:

- [ ] Every identifier belongs to me (or I have written authorisation).
- [ ] I understand the report will contain personal data and will be stored on
      this machine.
- [ ] I have set `D3TA1L3R_UA_EMAIL` so contacted site operators can reach me.
- [ ] I have left rate limits and robots.txt handling at their defaults.

After a scan:

- [ ] I have read the *Remaining gaps* section — and I am not treating it as
      "nothing found".
- [ ] If a `HIGH`/`MEDIUM` finding looks like a false positive, I have run
      `d3ta1l3r calibrate` for that site.
- [ ] I have decided what to do about each real finding (delete the account,
      tighten privacy settings, or accept it).
- [ ] I have deleted the reports and cache when I no longer need them.

## 7. Reporting a problem

If a source in this repository behaves badly — bypasses a control, ignores
robots.txt, or produces systematic false positives — that is a bug and it should
be reported as one. The same goes for any source that turns out to be
disproportionate for a self-audit; the fix is usually to disable it by default
with a note, which is exactly how the X, LinkedIn, Facebook and Reddit sources
are handled today.
