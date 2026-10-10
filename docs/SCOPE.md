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

It also keeps an **encrypted watchlist** of your own identifiers and re-checks it
against **breach sources** on demand and at every dashboard login:

4. Holds your emails, phone numbers, handles, domains and (optionally) password
   verifiers in a local file encrypted with scrypt + Fernet, mode `0600`, opened
   with a passphrase that is never written anywhere.
5. Checks that watchlist against breach sources — see §2 for exactly which, and
   what leaves the machine in each case.

That's the entire feature set. There is no "expand" mode, no person enumeration,
no correlation across people, and no way to point the watchlist at somebody
else's identifiers without lying to yourself about what you are doing.

## 2. What it refuses to do

These are hard limits, enforced by omission and by guards in code:

| Refused | Where it is enforced |
| --- | --- |
| People-search brokers, data brokers, background-check services | No such source exists; `docs/SOURCES.md` explains why adding one is out of scope |
| Breach corpora, credential dumps, paste-site lookups | D3TA1L3R never downloads, mirrors, scrapes or bundles one. There is no corpus in the repository, no "search the dumps" feature, and no aggregator endpoint anywhere in the code. Leak *checking* (§2a) only ever asks a service about your own identifier, or matches against a file you already have |
| Phone number, home address, relatives, "who lives at" lookups | Not implemented; `validate_username` also rejects the query shapes they would need |
| Scraping behind a login, CAPTCHA solving, IP rotation, UA spoofing to evade blocks | `core/http.py` sends one honest User-Agent and treats 401/403 as `blocked`; sites that fight automation ship `enabled_by_default: false` |
| Querying identifiers other than the ones supplied | Sources read `ScanTarget.identifiers` and nothing else; there is no pivot/enumeration step |
| Reaching internal, loopback or metadata addresses | `assert_public_url` runs on **every** URL *and every redirect hop* (`core/security.py`), with an optional DNS-level check (default on) |
| Bulk scraping: hundreds of probes per site, unbounded concurrency | Per-host token bucket (`--rps`, default 2/s), global concurrency cap (default 16), `--max-sites`, capped `Crawl-delay` honouring, response retry caps |

If you need something on the left-hand side of that table, D3TA1L3R is the wrong
tool, and for a third party's identifiers it is also the wrong *act*.

## 2a. Leak checking, and exactly what it costs in exposure

This is the one place where the tool talks about breaches, so the mechanism is
spelled out rather than implied. Passwords are checked with **k-anonymity**:
the password is hashed locally with SHA-1, only the first five hexadecimal
characters travel to the range API, and the full-hash comparison happens on this
machine. That is the same construction HIBP publishes for "Pwned Passwords", and
the test suite asserts that the request the transport actually saw carries
nothing but that five-character prefix.

There are three breach sources, and each one is bounded by what it sends:

| Source | What you need | What leaves the machine | What you get |
| --- | --- | --- | --- |
| `pwned_passwords` | nothing | **five hexadecimal characters of `SHA-1(password)`** — never the password, never the full hash | `pwned` with a count, or `clean` |
| `hibp_breaches` | your own HIBP API key (`D3TA1L3R_HIBP_KEY`) | the email address itself, plus the key | `pwned` with the breach names, or `clean` |
| `local_corpus` | a file *you* supply | nothing at all | `pwned`/`clean` per match in your file |

Consequences that were designed in, not discovered later:

- **Passwords are never stored.** `d3ta1l3r vault add --kind password` keeps the
  length and the outcome. It keeps a SHA-1 verifier *only* with `--store-hash`,
  which is what allows the automatic re-check at login; without it the password
  is checked once and forgotten. A verifier is a real secret: it is stored inside
  the encrypted payload and anyone who learns your vault passphrase can test
  those hashes offline, so leave `--store-hash` off unless you want the watch.
- **No accounts are enumerated.** Every check takes one of *your* identifiers.
  There is no "which of my emails is in this dump" fan-out and no address list to
  walk.
- **A check that did not happen is a gap.** A missing HIBP key, an HTTP 429, an
  unreachable corpus file, a password stored without a verifier: each one is
  reported as `unknown`/`unsupported` with a reason. Only `pwned` and `clean` are
  answers, and `clean` is only ever produced by a source that actually answered.
  `d3ta1l3r breach run` exits `3` when something was found, `2` when nothing
  could be checked at all.
- **No consolidation.** Results are never merged into a "risk score", never sent
  anywhere, and never enriched with data from another source.

## 2b. The local model: a model on your machine, or none

`ask` (CLI and dashboard) can turn a report into prose. That is a new place where
personal data could travel, so the rules are explicit:

- **Three real backends, all on hardware you control.** A GGUF file loaded with
  `llama-cpp-python`; an Ollama daemon on loopback; or a GGUF served by
  [Cortex LLM Hoster](https://github.com/codero-sus/Cortex_LLMHoster), which
  supervises `llama-server` from llama.cpp and publishes the OpenAI-compatible
  `/v1/chat/completions`. The wire format is someone else's; the model, the
  weights and the prompt are not.

  The host rules differ slightly, and the difference is deliberate:

  | Backend | Loopback | Your LAN | Public address |
  | --- | --- | --- | --- |
  | `llama_cpp` | in-process | — | — |
  | `ollama` | allowed | refused | refused |
  | `cortex` | allowed | allowed **if you name it** with `--cortex-host` | refused |

  Ollama refuses any host that is not `127.0.0.1`/`localhost`/`::1`. Cortex
  additionally accepts `10/8`, `172.16/12` and `192.168/16` — and only those
  three ranges, checked literally rather than with `ipaddress.is_private`, which
  is broader than RFC1918 and would also have let the documentation ranges
  through. Running the model on a home server is a normal way to spare a 4 GB
  laptop, so it is permitted, but it is permitted on purpose: the default is
  loopback, and naming a host is the opt-in. Hostnames are never accepted as
  LAN, because a name could resolve anywhere.

  A "local model" that is really an HTTP call to a company is data exfiltration
  with better wording, so every refusal above is a hard error rather than a
  warning. There is no hosted-model client anywhere in the codebase, and a test
  asserts that no commercial model endpoint is named under `d3ta1l3r/llm/`.
  Cortex is not an exception to that rule: it is a server you run, and its
  `CORTEX_API_KEY` unlocks your own box, not an account with a vendor.

- **You do not have to guess the model's name.** `--ollama-model` and
  `--cortex-model` default to `auto`: the server is asked what it has, and the
  first model that can hold a conversation is used (embedding-only models are
  skipped — they cannot answer). Naming one explicitly is still checked against
  what the server reports, and a name it does not have is an error that lists
  what it does have rather than a silent substitution.
- **Masked by default.** The digest the model sees carries `al***@example.com`,
  not your address. `--include-values` (CLI) or the panel's checkbox includes the
  real identifiers — an explicit, per-invocation decision, defensible only
  because the model runs on hardware you control — this machine, or a box on your
  own LAN when you have pointed Cortex at one. Masking is a scrub, not a format: it
  also covers finding URLs (`https://github.com/alice`), evidence strings and
  labels, which is where a handle usually hides.
- **Answers are tied to ids.** Context lines are numbered (`F1-003` = finding 3
  of scan 1, `E2` = watchlist entry 2, `G1-01` = a gap) and the model is required
  to cite them. Every cited id is verified against the context that produced the
  answer: invented ids are reported by the CLI and stripped by the dashboard, and
  an answer with no citation is marked ungrounded rather than trusted.
- **A gap stays a gap.** The digest includes the sources that could not be
  checked, so "what could not be checked?" is answerable. The prompt forbids
  inventing findings, counts or URLs, and a model failure degrades to retrieval
  over the report with a note in the answer.
- **No model is a supported state.** Without any of the three backends the same command
  answers from the report by keyword retrieval and says so; the dashboard shows
  which backend spoke, including when the answer was not generated at all.
- **Size, honestly.** `--ram-budget` (default 4096 MB) refuses to load a GGUF
  whose weights plus KV cache do not fit, and `d3ta1l3r ask --list-models` prints
  what fits a 4 GB machine before anything is downloaded. Nothing here needs a
  GPU.
- **The transcript is not a document.** Conversations are held in memory per
  session and dropped on logout or exit. Chat is not evidence: the reports are.

## 2c. Which weights, and who decided to fetch them

The catalogue exists so that "use a bigger model" does not mean "run an
unlabelled blob". Downloads are deliberately dull:

- **Nothing downloads itself.** The catalogue — size, resident memory, context
  window, licence and the repository each file comes from — is printed *before*
  any transfer, and `models pull <id>` states the download size and asks for
  confirmation first. `--yes` exists for scripts; no default is ever yes.
- **One host, one purpose.** `huggingface.co` appears only as a file host for
  GGUF downloads and the search/metadata API that describes them. It is not an
  inference endpoint: the model is fetched once and then loaded from disk by
  `llama-cpp-python`, and no question ever leaves the machine. The ban in §2b on
  hosted inference endpoints stands unchanged.
- **No keys required.** The curated entries are public. `HF_TOKEN` is used only
  if it is already in your environment (for gated repositories you added
  yourself); without it, the tool still works and says what it could not reach.
- **Integrity, then trust.** A finished download must match the byte length —
  and, when the repository reports one, the SHA-256 — from the source. A mismatch
  is deleted rather than loaded, a truncated file keeps its `.part` marker and is
  never treated as complete, and a response that is an HTML page instead of a
  model is rejected with that reason.
- **Resumable, not restarting.** An interrupted download resumes with a single
  `Range` request; if the server ignores the range and sends the whole file, the
  download restarts from zero instead of corrupting the result.
- **You can point it anywhere.** `models add` takes any GGUF reference on Hugging
  Face, including models this project has never heard of — the licence and
  provenance you record are what the report shows.
- **Nothing is redistributed.** This repository ships no weights. What you
  download is governed by the licence printed next to it, not by this project's
  licence.

## 2d. "Is this really me?" — an opinion, on request only

A scan can measure that a page exists; it cannot know the account is yours. The
one feature that tries to answer that question is fenced accordingly:

- **Opt-in, per run.** Verification happens only under `ask --verify`. It never
  runs during `scan`, `web`, `breach`, `diff`, a scheduled re-check, or a plain
  `ask`; a test asserts that a normal `ask` does not reach the verifier at all.
- **A verdict is not a measurement.** The model's judgement is stored in a
  separate field with the model id and its stated reason. It cannot raise a
  finding's confidence — there is no code path from a verdict back into the
  measured column — and a `NOT_MINE` against a `confirmed`/`high` finding is
  flagged as a disagreement instead of silently overruling the scan or the model.
- **Uncertainty is the default outcome.** The prompt requires `UNSURE` whenever
  the evidence cannot separate the user from a namesake. Unparseable lines become
  `UNSURE` and are marked as unparsed, invented finding ids are dropped, and
  findings the model skipped are recorded as unanswered.
- **No model, no review.** If no local model is available the command fails and
  says nothing was judged. Printing a wall of "cannot tell" would look like a
  review that found nothing.
- **Masked by default**, like `ask`; `--include-values` is the explicit override,
  and the fact that raw values were sent is recorded in the result.
- **Known gap, stated plainly: this is not proof of ownership.** A determined
  namesake with a similar profile can be called "you", and this project cannot
  currently distinguish that. Cryptographic ownership proof — a DNS `TXT` record,
  a `rel=me` link, or a token posted on a profile you control, then fetched and
  checked by the tool — is the honest way to answer the question, is not
  implemented, and should not be described as working. Until then, treat every
  verdict as what it is: a language model's opinion about a URL.

## 2e. Updating: delegation, not download-and-execute

`d3ta1l3r update` checks GitHub's public releases API for a newer version. An
updater is a supply-chain decision rather than a convenience, so the rules are
the strict ones:

- **Nothing is checked unless you run it.** No check on startup, none during a
  scan, no telemetry, no background timer. A self-audit tool that phones home on
  every invocation leaks when you audit and what version you patch from.
- **Report, then command, then question — in that order.** The version, the
  release notes, the URL and the exact argv are printed before anything is
  asked. `--check` never offers to install at all.
- **No release asset is ever downloaded and executed.** Fetching a tarball over
  HTTPS and installing it by hand would replace the trust already placed in PyPI
  or in your clone with trust in whoever can answer for the hostname. The work
  is delegated: `pip install --upgrade d3ta1l3r` for a packaged install,
  `git pull --ff-only` for a clone. Both are relationships you already accepted
  when you installed it the first time. `--ff-only` additionally means a dirty
  or diverged clone fails loudly rather than producing a tree neither side can
  describe.
- **The command is a list, never a shell string**, and it invokes
  `sys.executable -m pip` so the upgrade lands in the interpreter running this
  code, not whichever `pip` is first on `PATH`. `subprocess` is called with no
  `shell=`, and a test asserts that.
- **A pre-release is never installed automatically.** `--yes` accepts `0.2.0`
  and refuses `0.2.0-rc1`; `--pre` opts in.
- **Versions compare numerically**, not as text: `"0.10.0" < "0.9.0"` as strings,
  which would report you as current when you are two releases behind.
- **Unknown installs get no guess.** If this copy is neither a clone nor a
  packaged install, the command prints where to get the release instead of
  inventing one.
- **An unreachable API is a failure, not a shrug.** The check exits non-zero and
  prints the releases URL. GitHub's unauthenticated limit (60/hour per IP) is
  reported rather than retried.

The request is one unauthenticated, key-free `GET`, like every other source
here. It carries no identifier of yours — no handle, no email, no version of a
scan — so it reveals only that someone at this address runs D3TA1L3R.

`updater.sh` and `updater.bat` in the repository root are wrappers, not a second
implementation. They find the project's virtualenv (or `d3ta1l3r` on `PATH`, or
any interpreter that can import the package), pass your arguments through, and
fall back to the same git or pip command if no CLI exists. They contain no
version logic of their own, because a supply-chain decision written three times
is a decision that drifts in two of them. Tests assert what they must *not*
contain: no `curl | sh`, no `Invoke-Expression`, no `eval`, no disabled TLS
verification, and no release API of their own.

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
- **Credentials**: none, for any third party. D3TA1L3R never asks for a
  username/password/token for any site it scans, and has no code path that could
  use one. The single secret it handles is the passphrase to your own vault.
- **Vault** (`vault/watchlist.vault`, or `$D3TA1L3R_VAULT`): one file, mode
  `0600`, written atomically, containing your identifiers under scrypt
  (n=2^15, r=8) + Fernet and a per-vault fingerprint key. The passphrase is read
  from the terminal, `D3TA1L3R_VAULT_PASSPHRASE` or `--passphrase-file` — never
  from `argv`, where it would land in shell history and `ps`. A wrong passphrase
  or a modified byte fails closed with "nothing was decrypted". There is no
  recovery path and no escrow: lose the passphrase and the file is gone.
- **Breach reports** (`scans/breach/*.json`, `latest.json`): counts, statuses and
  masked values only — the same personal-data rules as scan reports apply.
- **Report chat** (`d3ta1l3r ask`, and the dashboard panel): the question, the
  digest and the answer exist only in memory. Nothing is written to disk, so the
  clean-up rules for reports do not apply to it, and closing the process is the
  whole story. Model weights you download yourself (a GGUF file, an Ollama
  model) live wherever you put them; D3TA1L3R never fetches one for you.

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

- **Somebody reading the vault file.** It is `0600` and encrypted; the KDF cost
  makes online guessing against a 12-character-minimum passphrase useless, and
  login attempts against the dashboard are throttled (5 tries, then a 300 s
  lockout per address). What it does not defend against is a weak passphrase you
  reuse elsewhere, or malware running as you while the vault is unlocked.
- **A hostile page in your browser driving the dashboard.** The session cookie is
  `HttpOnly` + `SameSite=Lax`, mutating requests are checked against an origin
  allowlist, and the session key is per process, so a restart invalidates every
  session.

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
- [ ] If I use a vault: I know where the file is (`d3ta1l3r vault where`), it is
      `0600`, and I have decided whether to back it up (there is no recovery).
- [ ] I have read what each breach source sends — and I am not treating a gap as
      good news.
- [ ] If I used `ask`: I know which backend answered, the raw-values flag was my
      choice, and nothing it said replaces the report it came from.
- [ ] If I pulled a model: I read the licence and the size before downloading,
      and I know which repository the file came from.
- [ ] If I used `--verify`: I chose to run it, I know a `MINE` is an opinion and
      not proof, and I checked the URL of anything I acted on.

## 7. Reporting a problem

If a source in this repository behaves badly — bypasses a control, ignores
robots.txt, or produces systematic false positives — that is a bug and it should
be reported as one. The same goes for any source that turns out to be
disproportionate for a self-audit; the fix is usually to disable it by default
with a note, which is exactly how the X, LinkedIn, Facebook and Reddit sources
are handled today.
