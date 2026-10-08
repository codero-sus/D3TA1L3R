"""Command-line interface.

    d3ta1l3r scan --username alice --email me@example.com --name "Alice Doe"
    d3ta1l3r sources --kind username
    d3ta1l3r calibrate --all            # measure the false-positive rate of the probes
    d3ta1l3r diff scans/old.json scans/new.json
    d3ta1l3r vault init                 # encrypted watchlist of your own identifiers
    d3ta1l3r breach run                 # re-check that watchlist against breach sources
    d3ta1l3r web --vault                # local dashboard, unlocked with the vault passphrase

Design notes:

* Exit codes are meaningful so the tool can run in CI:
  ``0`` success, ``1`` bad usage, ``2`` runtime failure, ``3`` ``--fail-on-new``
  triggered (something new about you appeared online).
* ``--demo`` never touches the network; every report it produces is flagged.
* Reports are written to disk (JSON + Markdown + HTML) because a self-audit is
  something you re-read and compare later, not just a terminal scroll.
* The vault passphrase is read from the terminal, ``D3TA1L3R_VAULT_PASSPHRASE``
  or ``--passphrase-file`` — never from argv, where it would land in shell
  history and ``ps`` output.
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
from .breach import (
    BreachConfig,
    BreachReport,
    BreachStatus,
    build_breach_sources,
    hash_corpus_lines,
    record_outcomes,
    run_breach_check,
    save_breach_report,
    transient_password_entry,
)
from .config import ScanConfig
from .core.engine import ScanEngine
from .core.report import diff_reports, render_html, render_json, render_markdown
from .core.storage import ScanStore
from .errors import D3ta1l3rError, UsageError
from .llm import (
    ChatSession,
    build_context,
    model_doctor,
    select_backend,
    verify_findings,
)
from .llm import models as model_catalog
from .llm.verify import render_verification_markdown
from .models import (
    EVENT_SCAN_FINISHED,
    EVENT_SOURCE_FINISHED,
    Confidence,
    ScanEvent,
    ScanReport,
    ScanStatus,
    ScanTarget,
)
from .vault import (
    Vault,
    VaultEntry,
    VaultKind,
    default_vault_path,
    file_permissions,
    is_locked_down,
    passphrase_from_file,
    prompt_password,
    prompt_secret,
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
    scan.add_argument("--browser", nargs="?", const="default", default=None, metavar="NAME",
                      help="send browser-shaped navigation headers (chrome/firefox/safari/edge). "
                           "Still robots-aware, still rate-limited, still shows From: if "
                           "D3TA1L3R_UA_EMAIL is set. Default: off (the tool identifies itself).")
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
    sources.add_argument("--not-found-phrases", dest="not_found_phrases", action="store_true",
                         help="print the page phrases that mean 'no such account' "
                              "(and the ambiguous ones reported as gaps)")
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
    calibrate.add_argument("--browser", nargs="?", const="default", default=None, metavar="NAME",
                           help="browser-shaped headers, as for `scan --browser`")
    calibrate.add_argument("--timeout", type=float, default=None)
    calibrate.add_argument("--jobs", "-j", type=int, default=None)
    calibrate.add_argument("--cache-dir", default=None)
    calibrate.add_argument("-o", "--output", default=str(DEFAULT_OUTPUT_DIR))
    calibrate.add_argument("--json", action="store_true", help="print the raw calibration JSON")

    diff = sub.add_parser("diff", help="compare two report files")
    diff.add_argument("previous", help="older report JSON")
    diff.add_argument("current", help="newer report JSON")
    diff.add_argument("--json", action="store_true", help="print machine-readable output")

    vault_common = argparse.ArgumentParser(add_help=False)
    vault_common.add_argument("--vault", metavar="PATH", default=None,
                              help="vault file (default: $D3TA1L3R_VAULT or vault/watchlist.vault)")
    vault_common.add_argument("--passphrase-file", default=None,
                              help="read the passphrase from this file instead of prompting")
    vault_common.add_argument("--demo", action="store_true",
                              help="run the breach check that follows from local fixtures")

    breach_common = argparse.ArgumentParser(add_help=False)
    breach_common.add_argument("--vault", metavar="PATH", default=None,
                               help="vault file with the watchlist to check")
    breach_common.add_argument("--passphrase-file", default=None,
                               help="read the vault passphrase from this file")
    breach_common.add_argument("--corpus", action="append", default=[], metavar="FILE",
                               help="local file of hashes/plaintext to match against (repeatable)")
    breach_common.add_argument("--hibp-key-file", default=None,
                               help="file holding your HIBP API key (the key is never an argument)")
    breach_common.add_argument("--demo", action="store_true",
                               help="answer from local fixtures: no network, synthetic results")
    breach_common.add_argument("--json", action="store_true", help="machine-readable output")
    breach_common.add_argument("-o", "--output", default=None,
                               help="write the report under this directory (scans/breach/)")
    breach_common.add_argument("--quiet", "-q", action="store_true",
                               help="only print the headline")
    breach_common.add_argument("--timeout", type=float, default=None)
    breach_common.add_argument("--jobs", "-j", type=int, default=None)
    breach_common.add_argument("--rps", type=float, default=None)

    vault = sub.add_parser(
        "vault",
        parents=[vault_common],
        help="manage the encrypted watchlist of your own identifiers",
        description=(
            "The vault is an encrypted local file (scrypt + Fernet, mode 0600) holding "
            "identifiers you own. It is the same file the dashboard unlocks at login and "
            "`breach run` re-checks. Passwords are never stored: at most a SHA-1 verifier "
            "is kept so they can be re-checked through the k-anonymity range API."
        ),
    )
    vault_sub = vault.add_subparsers(dest="vault_command", required=True)

    v_init = vault_sub.add_parser("init", parents=[vault_common],
                                  help="create a new empty vault")
    v_init.add_argument("--force", action="store_true", help="overwrite an existing file")
    v_init.add_argument("--from-scan", default=None, metavar="REPORT_JSON",
                        help="seed the watchlist from the identifiers of a stored scan")

    vault_sub.add_parser("unlock", parents=[vault_common],
                         help="decrypt the vault and print a summary")

    v_add = vault_sub.add_parser("add", parents=[vault_common], help="add an identifier")
    v_add.add_argument("--kind", required=True, choices=[k.value for k in VaultKind],
                       help="what the value is")
    v_add.add_argument("value", nargs="?", default=None,
                       help="the identifier (omit for a password: it is prompted for)")
    v_add.add_argument("--label", default="", help="your own label, e.g. 'work email'")
    v_add.add_argument("--notes", default="", help="free-form note kept inside the vault")
    v_add.add_argument("--store-hash", action="store_true",
                       help="keep a SHA-1 verifier so a password can be re-checked later")
    v_add.add_argument("--no-check", dest="check_now", action="store_false", default=True,
                       help="store it without running a breach check now")

    v_list = vault_sub.add_parser("list", parents=[vault_common],
                                  help="list the watchlist (masked)")
    v_list.add_argument("--json", action="store_true")

    v_remove = vault_sub.add_parser("remove", parents=[vault_common], help="remove one entry")
    v_remove.add_argument("entry_id", help="id shown by `vault list`")
    v_remove.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")

    v_rotate = vault_sub.add_parser(
        "rotate",
        parents=[vault_common],
        help="re-encrypt the vault under a new passphrase",
        description=(
            "Re-encrypts in place. The *current* passphrase opens the vault the usual "
            "way (prompt, D3TA1L3R_VAULT_PASSPHRASE or --passphrase-file); the new one "
            "comes from --new-passphrase-file or is prompted for twice."
        ),
    )
    v_rotate.add_argument("--new-passphrase-file", default=None,
                          help="read the new passphrase from this file instead of prompting")
    v_where = vault_sub.add_parser("where", parents=[vault_common],
                                   help="show the vault path and file permissions (no unlock)")
    v_where.add_argument("--json", action="store_true")

    breach = sub.add_parser(
        "breach",
        parents=[breach_common],
        help="check your identifiers against breach sources",
        description=(
            "Breach checking for your own identifiers. D3TA1L3R never downloads, scrapes "
            "or bundles leaked databases: passwords go through the Pwned Passwords "
            "k-anonymity range API (five hex characters of the SHA-1 leave the machine), "
            "account-level email lookups need your own HIBP key, and a local corpus is a "
            "file you supply yourself. A check that did not happen is reported as a gap, "
            "never as clean. Exit codes: 0 nothing found, 3 something was found in breach "
            "data, 2 nothing could be checked."
        ),
    )
    breach_sub = breach.add_subparsers(dest="breach_command", required=True)

    b_run = breach_sub.add_parser("run", parents=[breach_common],
                                  help="check every entry in the watchlist")
    b_run.add_argument("--no-save", dest="save", action="store_false", default=None,
                       help="do not record the outcomes back into the vault")
    b_run.add_argument("--markdown", action="store_true",
                       help="print the full Markdown report instead of the summary")

    b_check = breach_sub.add_parser("check", parents=[breach_common],
                                    help="check one identifier without touching the vault")
    b_check.add_argument("value", nargs="?", default=None, help="the identifier to check")
    b_check.add_argument("--kind", choices=[k.value for k in VaultKind], default=None,
                         help="what the value is (default: work it out from the value)")

    b_sources = breach_sub.add_parser("sources", parents=[breach_common],
                                      help="list the breach sources and whether they are usable")
    b_sources.add_argument("--check", action="store_true",
                           help="live-probe the sources with a known-breached password")

    b_hash = breach_sub.add_parser("corpus-hash", parents=[breach_common],
                                   help="hash a plaintext list so it can be matched without the values")
    b_hash.add_argument("file", help="file with one plaintext value per line")
    b_hash.add_argument("--algorithm", choices=["sha1", "sha256", "sha512"], default="sha256")
    b_hash.add_argument("--stdout", action="store_true", help="print the hashes to stdout")

    web = sub.add_parser("web", help="serve the local dashboard")
    web.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    web.add_argument("--port", type=int, default=7248, help="port (default 7248)")
    web.add_argument("--output", default=str(DEFAULT_OUTPUT_DIR), help="scan storage directory")
    web.add_argument("--demo", action="store_true",
                     help="run the dashboard in demo mode (synthetic results, no network)")
    web.add_argument("--reload", action="store_true", help="auto-reload on code changes")
    web.add_argument("--vault", nargs="?", const="", default=None, metavar="PATH",
                     help="unlock this vault at login (no PATH: the default vault). "
                          "Without it the dashboard has no watchlist and no login.")
    web.add_argument("--timeout", type=float, default=None)
    web.add_argument("--jobs", "-j", type=int, default=None)
    web.add_argument("--rps", type=float, default=None)
    web.add_argument("--no-robots", dest="respect_robots", action="store_false", default=True)
    web.add_argument("--model", metavar="PATH",
                     help="GGUF file for the local report chat (needs llama-cpp-python)")
    web.add_argument("--chat-backend", choices=("auto", "llama_cpp", "ollama", "extractive"),
                     default="auto",
                     help="which local backend answers questions about the scans")
    web.add_argument("--ollama-model", default="llama3.2:1b", metavar="NAME",
                     help="Ollama model name for the chat (default llama3.2:1b)")
    web.add_argument("--ollama-host", default="http://127.0.0.1:11434", metavar="URL",
                     help="Ollama daemon; loopback only")
    ask = sub.add_parser(
        "ask",
        help="ask a question about your stored scans with a model on this machine",
        description=(
            "Answers are produced by a local model only (llama_cpp GGUF file or a "
            "loopback Ollama daemon) or, when neither is available, by retrieval over "
            "the report itself. Every answer cites ids from the digest it was given."
        ),
    )
    ask.add_argument("question", nargs="?", help="the question, e.g. 'what should I fix first?'")
    ask.add_argument("--report", action="append", type=Path, metavar="FILE",
                     help="a report JSON to ask about (repeatable; default: stored scans)")
    ask.add_argument("--scan", action="append", metavar="ID", help="a stored scan id (repeatable)")
    ask.add_argument("--limit", type=int, default=3,
                     help="how many recent scans to include by default (default 3)")
    ask.add_argument("--output", "-o", default=str(DEFAULT_OUTPUT_DIR),
                     help="where reports are stored (default: scans/)")
    ask.add_argument("--no-watchlist", dest="no_watchlist", action="store_true",
                     help="do not read the vault, even if one is present")
    ask.add_argument("--backend", choices=("auto", "llama_cpp", "ollama", "extractive"),
                     default="auto",
                     help="which local backend to use (default: auto, best available)")
    ask.add_argument("--model", metavar="PATH|ID|auto",
                     help="GGUF file, a catalogue id, repo/file.gguf, or 'auto' for the "
                          "largest downloaded model that fits")
    ask.add_argument("--ollama-model", default="llama3.2:1b", metavar="NAME",
                     help="Ollama model name (default llama3.2:1b)")
    ask.add_argument("--ollama-host", default="http://127.0.0.1:11434", metavar="URL",
                     help="Ollama daemon; loopback only")
    ask.add_argument("--threads", type=int, default=None,
                     help="CPU threads for the model (default: cores - 1, capped at 4)")
    ask.add_argument("--context-size", type=int, default=2048, metavar="TOKENS",
                     help="model context window (default 2048; smaller = less RAM)")
    ask.add_argument("--ram-budget", type=int, default=4096, metavar="MB",
                     help="refuse to load a model that needs more than this (default 4096)")
    ask.add_argument("--context-chars", type=int, default=6000, metavar="N",
                     help="how much of the digest to put in the prompt (default 6000)")
    ask.add_argument("--max-findings", type=int, default=None, metavar="N",
                     help="at most N findings per scan in the prompt")
    ask.add_argument("--include-values", dest="include_values", action="store_true",
                     help="send raw identifiers to the model (default: masked)")
    ask.add_argument("--yes", "-y", action="store_true",
                     help="do not print the masking note (for scripts)")
    ask.add_argument(
        "--verify", action="store_true",
        help="ask the local model to judge whether each finding is really you "
             "(opt-in; the measured confidence is never changed)",
    )
    ask.add_argument("--about", default="", metavar="TEXT",
                     help="facts only you know, to help the reviewer: e.g. "
                          "'my bios mention chess and Delhi'")
    ask.add_argument("--about-file", type=Path, metavar="FILE",
                     help="read --about from a file")
    ask.add_argument("--only-uncertain", action="store_true",
                     help="with --verify: skip findings already at confirmed/high confidence")
    ask.add_argument("--verify-limit", type=int, default=None, metavar="N",
                     help="with --verify: judge at most N findings (a small model is slow)")
    ask.add_argument("--verify-markdown", action="store_true",
                     help="with --verify: print the review as Markdown")
    ask.add_argument("--list-models", action="store_true",
                     help="show which backends work here and what fits in 4 GB, then exit")
    ask.add_argument("--json", action="store_true", help="print the answer as JSON")
    ask.add_argument("--vault", nargs="?", const="", default=None, metavar="PATH",
                     help="vault to read the watchlist from (default: the standard vault)")
    ask.add_argument("--passphrase-file", metavar="FILE",
                     help="read the vault passphrase from this file instead of prompting")
    ask.add_argument("--demo", action="store_true", help="mark demo reports in the digest")
    models = sub.add_parser(
        "models",
        help="list, add and download GGUF models (Hugging Face), sized for this machine",
        description=(
            "A curated catalogue that works offline, plus download and search against "
            "Hugging Face. Nothing is downloaded without being asked for by name."
        ),
    )
    models_sub = models.add_subparsers(dest="models_command", required=True)

    list_cmd = models_sub.add_parser("list", help="show the catalogue")
    list_cmd.add_argument("--search", default="", help="substring filter")
    list_cmd.add_argument("--fits-memory", action="store_true",
                          help="only models that fit this machine's RAM")
    list_cmd.add_argument("--powerful", action="store_true",
                          help="only the larger, higher-quality models")
    list_cmd.add_argument("--tag", default="", help="filter by tag, e.g. reasoning, 4gb")
    list_cmd.add_argument("--downloaded", action="store_true",
                          help="only models already downloaded here")
    list_cmd.add_argument("--json", action="store_true")

    search_cmd = models_sub.add_parser("search", help="search Hugging Face for GGUF repos")
    search_cmd.add_argument("query")
    search_cmd.add_argument("--limit", type=int, default=10)
    search_cmd.add_argument("--json", action="store_true")

    add_cmd = models_sub.add_parser(
        "add", help="add any GGUF on Hugging Face to your catalogue (e.g. a bigger model)"
    )
    add_cmd.add_argument("reference", help="REPO/FILE.gguf, e.g. owner/repo/model-Q4_K_M.gguf")
    add_cmd.add_argument("--repo", default="", help="repository, if given separately")
    add_cmd.add_argument("--filename", default="", help="file inside the repo, if separate")
    add_cmd.add_argument("--id", default="", help="short id to pull it by")
    add_cmd.add_argument("--name", default="")
    add_cmd.add_argument("--parameters", default="", help="e.g. 7B")
    add_cmd.add_argument("--quant", default="", help="e.g. Q4_K_M")
    add_cmd.add_argument("--size-mb", type=int, default=0, help="download size, if known")
    add_cmd.add_argument("--ram-mb", type=int, default=0, help="RAM it needs, if known")
    add_cmd.add_argument("--context-size", type=int, default=4096, help="model context window")
    add_cmd.add_argument("--license", default="", help="e.g. apache-2.0, llama3.1")
    add_cmd.add_argument("--tag", action="append", default=[], help="free-form tag (repeatable)")
    add_cmd.add_argument("--note", default="")
    add_cmd.add_argument("--revision", default="main")

    remove_cmd = models_sub.add_parser("remove", help="delete a downloaded model")
    remove_cmd.add_argument("model_id")
    remove_cmd.add_argument("--yes", "-y", action="store_true")
    remove_cmd.add_argument("--catalogue-only", action="store_true",
                            help="drop the custom catalogue entry, keep the file")

    pull_cmd = models_sub.add_parser("pull", help="download a model from Hugging Face")
    pull_cmd.add_argument("model", help="catalogue id, or repo/filename.gguf")
    pull_cmd.add_argument("--yes", "-y", action="store_true", help="do not ask first")
    pull_cmd.add_argument("--force", action="store_true", help="download even if present")
    pull_cmd.add_argument("--no-verify", dest="verify", action="store_false", default=True,
                          help="skip the length/SHA-256 check")

    path_cmd = models_sub.add_parser("path", help="where models live, and how much space is free")
    path_cmd.add_argument("--json", action="store_true")
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
        if args.command == "vault":
            return cmd_vault(args)
        if args.command == "breach":
            return cmd_breach(args)
        if args.command == "ask":
            return cmd_ask(args)
        if args.command == "models":
            return cmd_models(args)
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
    """List the source inventory — or the phrases the not-found detector looks for."""
    if getattr(args, "not_found_phrases", False):
        return _print_not_found_phrases(args)
    return _sources_inventory(args)


def _print_not_found_phrases(args: argparse.Namespace) -> int:
    """Show exactly which page wording means "this account is not there"."""
    from .sources.notfound import phrase_registry

    registry = phrase_registry()
    if getattr(args, "json", False):
        print(json.dumps(registry, indent=2))
        return EXIT_OK
    print("Phrases that make a 200 OK mean \"no such account\":\n")
    for phrase in registry["absent"]:
        print(f"  - {phrase}")
    print(
        "\nAmbiguous wording, reported as a gap rather than as an answer "
        "(it also covers private,\nsuspended and bot-check pages):\n"
    )
    for phrase in registry["ambiguous"]:
        print(f"  - {phrase}")
    print(
        "\nSites can override this with their own not_found_marker in data/sites.json;\n"
        "that marker is checked first and quoted in the report."
    )
    return EXIT_OK


def _sources_inventory(args: argparse.Namespace) -> int:
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

    vault_path = _web_vault_path(args)
    if vault_path is not None and not vault_path.is_file():
        raise UsageError(
            f"no vault at {vault_path} — create one with `d3ta1l3r vault init` "
            "(or start without --vault to skip the watchlist)"
        )

    settings = AppSettings(
        output_dir=Path(args.output),
        demo=bool(args.demo),
        config=_config_from_args(args),
        vault_path=vault_path,
        breach_config=_breach_config(args),
        chat_backend=args.chat_backend,
        chat_model_path=Path(args.model).expanduser() if args.model else None,
        ollama_model=args.ollama_model,
        ollama_host=args.ollama_host,
    )
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(settings)
    print(f"D3TA1L3R dashboard → http://{args.host}:{args.port}  (Ctrl-C to stop)")
    if vault_path is not None:
        print(f"Watchlist: {vault_path}")
        print("  Sign in with the vault passphrase. It is entered in the browser and is")
        print("  never passed to this process; each login re-checks the watchlist.")
        _verify_vault_at_startup(vault_path)
    if args.model:
        print(f"Report chat: {args.model} (local GGUF; raw values are opt-in per question)")
    elif args.chat_backend == "extractive":
        print("Report chat: retrieval over the report (no model loaded).")
    elif args.demo:
        print("Report chat: a local model if one is available (the page says which).")
    if args.demo:
        print("DEMO MODE: scans are served from synthetic fixtures; no third party is contacted.")
    uvicorn.run(app, host=args.host, port=args.port, reload=bool(args.reload), log_level="info")
    return EXIT_OK


def _verify_vault_at_startup(path: Path) -> None:
    """Check the passphrase before serving — but only when there is one to read.

    An interactive start gets a hidden prompt, and an operator who exported
    ``D3TA1L3R_VAULT_PASSPHRASE`` is checked against that. A headless start
    (container, supervisor, preview sandbox) has no terminal at all, and
    blocking there would stop the server on input that can never arrive — so it
    says who will ask instead. The unlock itself always happens in the browser
    login, which is exactly what makes a login worth re-checking the watchlist on.
    """
    if not os.isatty(0) and not os.environ.get("D3TA1L3R_VAULT_PASSPHRASE"):
        print("  no terminal to check the passphrase with — the login page will ask for it.")
        return
    try:
        Vault.open(path, prompt_secret("Vault passphrase", confirm=False))
    except D3ta1l3rError as exc:
        print(f"  warning: {exc}", file=sys.stderr)
    else:
        print("  passphrase verified.")


# ---------------------------------------------------------------------------
# vault
# ---------------------------------------------------------------------------
def cmd_vault(args: argparse.Namespace) -> int:
    if args.vault_command == "where":
        return _vault_where(args)
    if args.vault_command == "init":
        return _vault_init(args)

    vault = _open_vault(args)
    if args.vault_command == "unlock":
        return _vault_summary(vault)
    if args.vault_command == "list":
        return _vault_list(vault, args)
    if args.vault_command == "add":
        return _vault_add(vault, args)
    if args.vault_command == "remove":
        return _vault_remove(vault, args)
    if args.vault_command == "rotate":
        return _vault_rotate(vault, args)
    raise UsageError(f"unknown vault command: {args.vault_command}")


def _vault_path(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "vault", None)
    return Path(explicit).expanduser() if explicit else default_vault_path()


def _passphrase(args: argparse.Namespace, *, confirm: bool = False) -> str:
    """Resolve the passphrase without ever taking it from argv."""
    path = getattr(args, "passphrase_file", None)
    if path:
        return passphrase_from_file(path)
    return prompt_secret("Vault passphrase", confirm=confirm)


def _open_vault(args: argparse.Namespace) -> Vault:
    path = _vault_path(args)
    if not path.is_file():
        raise UsageError(f"no vault at {path} — create one with `d3ta1l3r vault init`")
    return Vault.open(path, _passphrase(args))


def _breach_config(args: argparse.Namespace) -> BreachConfig:
    overrides: dict[str, Any] = {}
    key_file = getattr(args, "hibp_key_file", None)
    if key_file:
        overrides["hibp_api_key"] = passphrase_from_file(key_file).strip()
    corpora = tuple(Path(raw).expanduser() for raw in (getattr(args, "corpus", None) or ()))
    if corpora:
        overrides["corpora"] = corpora
    demo = getattr(args, "demo", False)
    return BreachConfig.from_env(demo=bool(demo), **overrides)


def _web_vault_path(args: argparse.Namespace) -> Path | None:
    """`--vault` (with or without a path) or an exported ``D3TA1L3R_VAULT``."""
    raw = getattr(args, "vault", None)
    if raw:
        return Path(raw).expanduser()
    if raw == "":
        return default_vault_path()
    if os.environ.get("D3TA1L3R_VAULT"):
        return default_vault_path()
    return None


def _vault_where(args: argparse.Namespace) -> int:
    path = _vault_path(args)
    exists = path.is_file()
    payload = {
        "path": str(path),
        "exists": exists,
        "permissions": file_permissions(path) if exists else "",
        "locked_down": is_locked_down(path) if exists else False,
        "size_bytes": path.stat().st_size if exists else 0,
        "from_environment": bool(os.environ.get("D3TA1L3R_VAULT")),
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return EXIT_OK
    print(f"vault: {path}")
    if not exists:
        print("  not created yet — run `d3ta1l3r vault init`")
        return EXIT_OK
    print(f"  size: {payload['size_bytes']} bytes")
    if payload["locked_down"]:
        print(f"  permissions: {payload['permissions']} (owner-only, as intended)")
    else:
        print(f"  permissions: {payload['permissions']} ← should be 0600; run `chmod 600 {path}`")
    print("  contents are encrypted; without the passphrase the file reveals nothing but")
    print("  its size and format. Back it up somewhere you trust: there is no recovery.")
    return EXIT_OK


def _vault_init(args: argparse.Namespace) -> int:
    path = _vault_path(args)
    # Load the seed report *before* touching the disk: a bad path must not leave
    # a half-created vault behind.
    seed = _load_report(args.from_scan) if args.from_scan else None
    passphrase = _passphrase(args, confirm=True)
    vault = Vault.create(path, passphrase, overwrite=bool(args.force))
    added = _seed_from_report(vault, seed) if seed is not None else 0
    print(f"created {path}")
    print(f"  permissions: {file_permissions(path)} (owner-only)")
    if added:
        print(f"  seeded {added} identifier(s) from {args.from_scan}")
    print("  next: `d3ta1l3r vault add --kind email you@example.com`")
    print("        `d3ta1l3r breach run`   re-checks the whole watchlist")
    print("  the passphrase cannot be recovered — losing it means losing the file.")
    return EXIT_OK


def _seed_from_report(vault: Vault, report: ScanReport) -> int:
    """Copy the identifiers of a stored scan into a fresh vault."""
    target = report.target
    pairs = [
        (VaultKind.USERNAME, target.username),
        (VaultKind.EMAIL, target.email),
        (VaultKind.DOMAIN, target.domain),
    ]
    added = 0
    for kind, value in pairs:
        if not value:
            continue
        _, created = vault.add(kind, value, label="from scan", notes=f"scan {report.scan_id}")
        added += int(created)
    if added:
        vault.save()
    return added


def _vault_summary(vault: Vault) -> int:
    info = vault.describe()
    by_kind = ", ".join(f"{kind} {count}" for kind, count in sorted(info["by_kind"].items()))
    print(f"unlocked: {info['path']}")
    print(f"  format: {info['format']} · kdf: {info['kdf']}")
    print(f"  created: {info['created_at']} · updated: {info['updated_at']}")
    print(f"  entries: {info['entries']}{f' ({by_kind})' if by_kind else ''}")
    print(f"  re-checkable without asking you again: {info['recheckable']}")
    return EXIT_OK


def _vault_list(vault: Vault, args: argparse.Namespace) -> int:
    entries = vault.watchlist()
    if args.json:
        print(
            json.dumps(
                {
                    "summary": vault.describe(),
                    "entries": [entry.public_dict() for entry in entries],
                },
                indent=2,
            )
        )
        return EXIT_OK
    if not entries:
        print("the watchlist is empty — `d3ta1l3r vault add --kind email you@example.com`")
        return EXIT_OK
    print(f"{len(entries)} watched identifier(s) in {vault.path}\n")
    for entry in entries:
        label = f"  [{entry.label}]" if entry.label else ""
        last = (
            f"last: {entry.last_status}"
            + (f" ({entry.last_count})" if entry.last_count and entry.last_count > 0 else "")
            if entry.last_status
            else "never checked"
        )
        print(f"  {entry.kind.value:<9} {entry.masked:<24}{label}")
        print(f"      {last} · id {entry.entry_id}"
              + ("" if entry.recheckable else " · cannot be re-checked (no verifier kept)"))
    print("\nMasked values only: the real ones stay inside the encrypted file.")
    print("`d3ta1l3r breach run` re-checks everything that has a verifier.")
    return EXIT_OK


def _vault_add(vault: Vault, args: argparse.Namespace) -> int:
    kind = VaultKind(args.kind)
    value = args.value
    if not value and kind is VaultKind.PASSWORD:
        value = prompt_password("Password to check (it is never stored)")
    if not value:
        raise UsageError("give the value as an argument (passwords are prompted for instead)")
    entry, created = vault.add(
        kind, value, label=args.label, notes=args.notes, store_hash=bool(args.store_hash)
    )
    vault.save()
    print(f"{'added' if created else 'already watched'}: {entry.kind.label} {entry.masked}")
    print(f"  id: {entry.entry_id}")
    if kind is VaultKind.PASSWORD:
        if args.store_hash:
            print("  kept a SHA-1 verifier (not the password) so it can be re-checked later")
        else:
            print("  nothing is retained: the password is checked once and forgotten")
    if not args.check_now:
        return EXIT_OK

    probe = (
        transient_password_entry(value, label=entry.display, entry_id=entry.entry_id)
        if kind is VaultKind.PASSWORD
        else entry
    )
    report = asyncio.run(
        run_breach_check(
            [probe],
            scan_config=_config_from_args(args, for_breach=True),
            breach_config=_breach_config(args),
        )
    )
    if report.checks:
        record_outcomes(vault, report)
        vault.save()
    print()
    _print_breach(
        report, verbose=False, single=True, demo=bool(getattr(args, "demo", False))
    )
    return EXIT_NEW_FINDINGS if report.counts().get("pwned") else EXIT_OK


def _vault_remove(vault: Vault, args: argparse.Namespace) -> int:
    entry = vault.get(args.entry_id)
    if entry is None:
        raise UsageError(f"no entry with id {args.entry_id} in {vault.path}")
    if not args.yes:
        answer = input(f"remove {entry.kind.label} {entry.masked}? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("left it alone.")
            return EXIT_OK
    vault.remove(entry.entry_id)
    vault.save()
    print(f"removed {entry.masked} · {len(vault)} entry(ies) left")
    return EXIT_OK


def _vault_rotate(vault: Vault, args: argparse.Namespace) -> int:
    new_file = getattr(args, "new_passphrase_file", None)
    passphrase = (
        passphrase_from_file(new_file)
        if new_file
        else prompt_secret("New vault passphrase", confirm=True)
    )
    vault.rotate(passphrase)
    print(f"re-encrypted {vault.path} under a new passphrase")
    print("  entries and keyed fingerprints are unchanged; the old passphrase no longer works.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# breach
# ---------------------------------------------------------------------------
def cmd_breach(args: argparse.Namespace) -> int:
    if args.breach_command == "sources":
        return _breach_sources(args)
    if args.breach_command == "corpus-hash":
        return _breach_corpus_hash(args)
    if args.breach_command == "check":
        return _breach_check_one(args)
    if args.breach_command == "run":
        return _breach_run(args)
    raise UsageError(f"unknown breach command: {args.breach_command}")


def _breach_sources(args: argparse.Namespace) -> int:
    config = _breach_config(args)
    rows = [source.describe(config) for source in build_breach_sources(config)]
    for corpus in config.corpora:
        if not corpus.is_file():
            print(f"warning: corpus not found: {corpus}", file=sys.stderr)
    if getattr(args, "check", False):
        return _breach_live_check(config, args)
    if getattr(args, "json", False):
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    print(f"{len(rows)} breach source(s)\n")
    for row in rows:
        state = "ready" if row["available"] else "unavailable"
        print(f"  {row['id']:<20} {state:<12} {row['name']}")
        print(f"      {row['description']}")
        if row["available"]:
            print(f"      sends: {row['sends_data']}")
        else:
            print(f"      needs: {row['unavailable_reason']}")
        print(f"      docs: {row['docs_url']}")
    print("\nA source that cannot answer produces a gap in the report, never a clean result.")
    print("Set D3TA1L3R_HIBP_KEY (or --hibp-key-file) for account-level email checks.")
    return EXIT_OK


def _breach_live_check(config: BreachConfig, args: argparse.Namespace) -> int:
    """Prove the password path works, using the most-breached password there is."""
    known = "password"
    entry = transient_password_entry(known, label="known-bad sample")
    report = asyncio.run(
        run_breach_check(
            [entry],
            scan_config=_config_from_args(args, for_breach=True),
            breach_config=config,
        )
    )
    print(f"Live probe with the well-known password {known!r} (network required):")
    for check in report.checks:
        mark = "!" if check.status is BreachStatus.PWNED else "·"
        print(f"  {mark} {check.source_id:<20} {check.status.value:<8} {check.detail}")
    for gap in report.unavailable:
        print(f"  - {gap['source_id']:<20} unavailable: {gap['reason']}")
    return EXIT_OK


def _breach_check_one(args: argparse.Namespace) -> int:
    value = args.value
    kind = VaultKind(args.kind) if args.kind else _infer_kind(value)
    if value is None and kind is VaultKind.PASSWORD:
        value = prompt_password("Password to check (it is never stored)")
    if not value:
        raise UsageError("give the value to check, e.g. `breach check --kind password`")
    entry = _standalone_entry(kind, value)

    report = asyncio.run(
        run_breach_check(
            [entry],
            scan_config=_config_from_args(args, for_breach=True),
            breach_config=_breach_config(args),
        )
    )
    if getattr(args, "json", False):
        print(report.to_json())
    else:
        _print_breach(report, verbose=False)
    return _breach_exit_code(report)


def _standalone_entry(kind: VaultKind, value: str) -> VaultEntry:
    """Validate an identifier the way the vault would, without needing a vault.

    ``breach check`` must accept the same spellings as ``vault add`` (that is how
    ``+91 98100 00010`` becomes a lookup key), so the normalisation rules are
    shared rather than re-implemented here.
    """
    from .vault import normalise_value

    normalised = normalise_value(kind, value)
    if kind is VaultKind.PASSWORD:
        return transient_password_entry(normalised, label="(command line)")
    return VaultEntry(kind=kind, value=normalised)


def _infer_kind(value: str | None) -> VaultKind:
    raw = (value or "").strip()
    if not raw:
        return VaultKind.PASSWORD
    if "@" in raw:
        return VaultKind.EMAIL
    if re.fullmatch(r"\+?[0-9][0-9\s().-]{5,}", raw):
        return VaultKind.PHONE
    if re.fullmatch(r"[0-9a-fA-F]{40}", raw):
        return VaultKind.PASSWORD  # a SHA-1: the k-anonymity API's own identifier
    return VaultKind.USERNAME


def _breach_run(args: argparse.Namespace) -> int:
    vault = _open_vault(args)
    config = _breach_config(args)
    # Validate the paths the caller gave us before anything else: a typo in
    # --corpus is a usage error whether or not the watchlist happens to be empty.
    for corpus in config.corpora:
        if not corpus.is_file():
            raise UsageError(f"corpus file not found: {corpus}")

    entries = vault.watchlist()
    if not entries:
        print("the watchlist is empty — add an identifier first:")
        print("  d3ta1l3r vault add --kind email you@example.com")
        return EXIT_OK
    on_event = None
    if not (args.quiet or args.json):
        def on_event(event: dict[str, Any]) -> None:
            kind = str(event.get("type", ""))
            if kind in {"entry_started", "source_unavailable"}:
                print(f"  {event.get('message', '')}", file=sys.stderr)

    report = asyncio.run(
        run_breach_check(
            entries,
            scan_config=_config_from_args(args, for_breach=True),
            breach_config=config,
            on_event=on_event,
        )
    )
    if args.save is not False:
        record_outcomes(vault, report)
        vault.save()
    output = getattr(args, "output", None)
    saved = save_breach_report(report, Path(output)) if output else None

    if args.json:
        print(report.to_json())
    else:
        print()
        _print_breach(report, verbose=bool(args.markdown))
    if saved is not None:
        print(f"\nreport: {saved}", file=sys.stderr)
    return _breach_exit_code(report)


def _breach_exit_code(report: BreachReport) -> int:
    if report.counts().get("pwned"):
        return EXIT_NEW_FINDINGS
    if report.nothing_was_checked:
        return EXIT_FAILURE
    return EXIT_OK


def _breach_corpus_hash(args: argparse.Namespace) -> int:
    source = Path(args.file)
    if not source.is_file():
        raise UsageError(f"file not found: {source}")
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    hashed = hash_corpus_lines(lines, algorithm=args.algorithm)
    body = "\n".join(hashed)
    if args.stdout or not args.output:
        print(body)
    else:
        target = Path(args.output)
        target.mkdir(parents=True, exist_ok=True)
        out = target / f"{source.stem}-{args.algorithm}.txt"
        out.write_text(body + "\n", encoding="utf-8")
        print(f"wrote {len(hashed)} hash(es) to {out}")
    print(
        f"\n{len(hashed)} of {len(lines)} line(s) hashed with {args.algorithm}.",
        file=sys.stderr,
    )
    print("Match it with `d3ta1l3r breach run --corpus <that file>` or `breach check`.", file=sys.stderr)
    return EXIT_OK


def _print_breach(
    report: BreachReport, *, verbose: bool, single: bool = False, demo: bool = False
) -> None:
    counts = report.entry_counts()
    print(report.headline())
    if verbose:
        print()
        print(report.render_markdown())
        return
    if single and demo:
        # One identifier, demo fixtures: the full markdown headline rules are
        # noise on the back of a question the user just asked interactively.
        for check in report.checks:
            print(f"  {check.source_id}: {check.status.value} — {check.detail or check.evidence}")
        for gap in report.unavailable:
            print(f"  ! {gap['source_id']}: {gap['reason'][:96]}")
        return
    for entry in report.entries:
        detail = " · ".join(
            f"{check.source_id}: {check.status.value}" for check in report.checks_for(entry.entry_id)
        )
        print(f"  {entry.kind.value:<9} {entry.masked:<24} {detail or 'not checked'}")
    for gap in report.unavailable:
        print(f"  ! {gap['source_id']}: {gap['reason'][:96]}")
    print(
        f"\n{len(report.entries)} identifier(s): {counts.get('pwned', 0)} in breach data · "
        f"{counts.get('clean', 0)} not found · "
        f"{counts.get('unknown', 0) + counts.get('unsupported', 0)} not checked"
    )


# ---------------------------------------------------------------------------
# models (local catalogue + Hugging Face downloads)
# ---------------------------------------------------------------------------
def cmd_models(args: argparse.Namespace) -> int:
    """List, search, add and download local models.

    The catalogue is curated and ships with the tool, so `models list` works on a
    machine with no network. `models search` and `models pull` are the only parts
    that talk to Hugging Face, and a download is never implicit: the URL and size
    are printed before the first byte is requested.
    """
    action = args.models_command
    if action == "path":
        return _models_path(args)
    if action == "list":
        return _models_list(args)
    if action == "search":
        return _models_search(args)
    if action == "add":
        return _models_add(args)
    if action == "remove":
        return _models_remove(args)
    if action == "pull":
        return _models_pull(args)
    raise UsageError(f"unknown models command: {action}")


def _models_path(args: argparse.Namespace) -> int:
    directory = model_catalog.default_models_dir()
    disk = model_catalog.describe_disk(directory)
    if getattr(args, "json", False):
        print(json.dumps(disk, indent=2))
        return EXIT_OK
    print(f"models directory: {disk['directory']}")
    print(f"  exists: {'yes' if disk['exists'] else 'no'}")
    if disk["free_mb"] >= 0:
        print(f"  free space: {model_catalog.format_mb(disk['free_mb'])}")
    ram = disk.get("ram_mb")
    print(f"  RAM: {model_catalog.format_mb(ram) if ram else 'unknown on this platform'}")
    print(f"  custom catalogue: {model_catalog.custom_catalog_path(directory)}")
    print("Set D3TA1L3R_MODELS to keep the models somewhere else.")
    return EXIT_OK


def _models_list(args: argparse.Namespace) -> int:
    directory = model_catalog.default_models_dir()
    downloaded = {row["id"] for row in model_catalog.list_downloaded(directory)}
    specs = model_catalog.filter_models(
        getattr(args, "search", "") or "",
        fits_mb=(getattr(args, "fits_memory", False) and model_catalog.local_ram_mb()) or None,
        tag=getattr(args, "tag", "") or "",
        powerful_only=bool(getattr(args, "powerful", False)),
        downloaded_dir=directory if getattr(args, "downloaded", False) else None,
    )
    payload = [
        {**spec.to_dict(), "downloaded": spec.id in downloaded,
         "path": str(model_catalog.model_path(spec, directory))}
        for spec in specs
    ]
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return EXIT_OK
    if not payload:
        print("nothing in the catalogue matches that filter.")
        return EXIT_OK
    ram = model_catalog.local_ram_mb()
    print(f"{len(payload)} model(s)"
          f"{f' · this machine has {model_catalog.format_mb(ram)} of RAM' if ram else ''}\n")
    for row in payload:
        mark = "*" if row["downloaded"] else " "
        fit = "fits here" if ram and row["ram_mb"] <= ram else (
            "may not fit" if ram and not row["fits_4gb"] else "4 GB")
        print(f" {mark} {row['id']:<40} {row['parameters']:>5} {row['quant']:<9}"
              f" {model_catalog.format_mb(row['size_mb']):>8} download"
              f" · {model_catalog.format_mb(row['ram_mb']):>8} RAM · {fit}")
        print(f"     {row['name']} — {row['note']}")
        print(f"     {row['url']}")
    print("\n* = already downloaded. `d3ta1l3r models pull <id>` fetches one;")
    print("`d3ta1l3r ask --model auto` uses the largest downloaded model that fits.")
    return EXIT_OK


def _models_search(args: argparse.Namespace) -> int:
    rows = model_catalog.hf_search(args.query, limit=args.limit)
    if getattr(args, "json", False):
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    if not rows:
        print(f"no GGUF repositories matched {args.query!r}")
        return EXIT_OK
    print(f"{len(rows)} Hugging Face repository(ies) matching {args.query!r}:\n")
    for row in rows:
        flags = " [gated]" if row["gated"] else ""
        print(f"  {row['repo']}{flags}")
        print(f"     {row['downloads']} downloads · {row['likes']} likes · updated {row['updated']}")
        print(f"     {row['url']}")
    print("\nAdd one of these with:")
    print("  d3ta1l3r models add REPO/FILE.gguf --ram MB && d3ta1l3r models pull <id>")
    return EXIT_OK


def _models_add(args: argparse.Namespace) -> int:
    spec = model_catalog.spec_from_reference(
        args.reference,
        repo=args.repo or "",
        filename=args.filename or "",
        model_id=args.id or "",
        name=args.name or "",
        parameters=args.parameters or "",
        quant=args.quant or "unknown",
        size_mb=args.size_mb or 0,
        ram_mb=args.ram_mb or 0,
        context=args.context_size,
        license=args.license or "unknown",
        tags=tuple(_split_values(args.tag or [])),
        note=args.note or "",
        revision=args.revision,
    )
    path = model_catalog.save_custom_model(spec)
    print(f"added to the catalogue: {spec.id}")
    print(f"  {spec.name}")
    print(f"  {spec.url}")
    if spec.ram_mb:
        print(f"  estimated RAM: {model_catalog.format_mb(spec.ram_mb)}")
    else:
        print("  estimated RAM: unknown until it is measured at download time")
    print(f"  catalogue: {path}")
    print(f"\nnext: d3ta1l3r models pull {spec.id}")
    return EXIT_OK


def _models_remove(args: argparse.Namespace) -> int:
    directory = model_catalog.default_models_dir()
    removed_entry = model_catalog.remove_custom_model(args.model_id, directory)
    path = model_catalog.model_path(
        model_catalog.ModelSpec(
            id=args.model_id, name="", repo="", filename="", parameters="", quant="",
            size_mb=0, ram_mb=0,
        ),
        directory,
    )
    removed_file = False
    if path.is_file() and not args.catalogue_only:
        if not args.yes:
            answer = input(f"delete {path} ({model_catalog.format_bytes(path.stat().st_size)})? [y/N] ")
            if answer.strip().lower() not in {"y", "yes"}:
                print("left the file alone.")
                if removed_entry:
                    print("removed the catalogue entry only.")
                return EXIT_OK
        path.unlink()
        removed_file = True
    if not removed_entry and not removed_file:
        raise UsageError(f"nothing called {args.model_id!r} in the catalogue or on disk")
    if removed_entry:
        print(f"removed {args.model_id} from the custom catalogue")
    if removed_file:
        print(f"deleted {path}")
    if not removed_entry and not removed_file:  # pragma: no cover - unreachable
        return EXIT_FAILURE
    return EXIT_OK


def _models_pull(args: argparse.Namespace) -> int:
    directory = model_catalog.default_models_dir()
    specs = model_catalog.catalogue(directory)
    spec = model_catalog.find_model(args.model, specs=specs)
    if spec is None:
        matches = model_catalog.filter_models(args.model, specs=specs, fits_mb=None)[:5]
        hint = (
            " Did you mean: " + ", ".join(item.id for item in matches) + "?"
            if matches
            else " Run `d3ta1l3r models list` to see the catalogue."
        )
        raise UsageError(f"no model called {args.model!r} in the catalogue.{hint}")

    final = model_catalog.model_path(spec, directory)
    if final.is_file() and not args.force:
        print(f"already downloaded: {final}")
        print("Use --force to fetch it again.")
        return EXIT_OK

    disk = model_catalog.describe_disk(directory)
    ram = disk.get("ram_mb")
    print(f"{spec.name} ({spec.parameters}, {spec.quant})")
    print(f"  from:   {spec.url}")
    print(f"  size:   {model_catalog.format_mb(spec.size_mb or 0)}"
          f"{' (as published)' if spec.size_mb else ' (measured at download time)'}")
    print(f"  to:     {final}")
    if disk["free_mb"] >= 0 and spec.size_mb:
        needed = spec.size_mb * 1024 * 1024
        free = disk["free_mb"] * 1024 * 1024
        if needed > free:
            raise UsageError(
                f"not enough disk: {model_catalog.format_mb(spec.size_mb)} needed, "
                f"{model_catalog.format_mb(disk['free_mb'])} free in {directory}"
            )
        print(f"  disk:   {model_catalog.format_mb(disk['free_mb'])} free (ok)")
    if ram and spec.ram_mb > ram:
        print(f"  warning: this needs about {model_catalog.format_mb(spec.ram_mb)} of RAM "
              f"and this machine has {model_catalog.format_mb(ram)} — it will download, "
              "but loading it may fail or swap.")
    if not args.yes:
        print("\nDownload it? [y/N] ", end="", flush=True)
        answer = input().strip().lower()
        if answer not in {"y", "yes"}:
            print("nothing downloaded.")
            return EXIT_OK

    def progress(phase: str, done: int, total: int) -> None:
        if phase == "done":
            print(f"\rdownloaded {model_catalog.format_bytes(done)}" + " " * 20)
            return
        if total > 0:
            percent = done / total * 100
            print(
                f"\r{phase}: {model_catalog.format_bytes(done)} / "
                f"{model_catalog.format_bytes(total)} ({percent:.0f}%)",
                end="",
                flush=True,
            )
        else:
            print(f"\r{phase}: {model_catalog.format_bytes(done)}", end="", flush=True)

    expected = ""
    if args.verify and spec.official:
        with contextlib.suppress(UsageError):  # metadata is a bonus, not a gate
            meta = model_catalog.hf_file_metadata(spec)
            expected = meta.get("sha256", "")
            if not spec.size_mb and meta.get("size"):
                print(f"  size:   {model_catalog.format_bytes(meta['size'])} (from the Hub)")

    path = model_catalog.download_model(
        spec,
        directory,
        progress=progress,
        verify=args.verify,
        force=args.force,
        expected_sha256=expected,
    )
    print(f"\nmodel ready: {path}")
    print(f"  use it with: d3ta1l3r ask --model {path} \"what should I fix first?\"")
    return EXIT_OK


# ---------------------------------------------------------------------------
# ask (local model, optional)
# ---------------------------------------------------------------------------
def cmd_ask(args: argparse.Namespace) -> int:
    """Answer a question about your own stored scans with a local model.

    Three things make this safe to point at a report full of personal data:
    the model is on this machine (``llama_cpp`` or a loopback Ollama — never a
    remote host), answers must cite ids from the digest they were given, and
    nothing here is written to disk. The trust prompt exists because
    ``Ctrl-R`` plus a plausible sentence is exactly how a wrong answer becomes
    a fact.
    """
    if getattr(args, "list_models", False):
        return _ask_models()
    if not args.question and not getattr(args, "verify", False):
        raise UsageError(
            "ask a question: d3ta1l3r ask \"what should I fix first?\"  "
            "(use --list-models to see what fits in 4 GB, or --verify to review findings)"
        )

    reports, watchlist, breach = _ask_sources(args)
    if not reports and not watchlist:
        raise UsageError(
            "there is nothing to ask about yet: run a scan, or add something to the "
            "watchlist with `d3ta1l3r vault add`"
        )

    backend, notes = select_backend(
        prefer=args.backend,
        model_path=_resolve_model_argument(args),
        ollama_model=args.ollama_model,
        ollama_host=args.ollama_host,
        threads=args.threads,
        context_window=args.context_size,
        ram_budget_mb=args.ram_budget,
    )
    include_values = _confirm_raw_values(args, backend)
    context = build_context(
        reports,
        watchlist=watchlist,
        breach=breach,
        include_values=include_values,
        max_findings_per_scan=args.max_findings,
    )
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    if backend.is_model:
        print(
            f"answering with {backend.name} ({backend.model_id}); "
            f"{len(context.items)} context line(s), raw values "
            f"{'included' if include_values else 'masked'}",
            file=sys.stderr,
        )
    else:
        print(
            "no local model available — answering from the report itself "
            "(see `d3ta1l3r ask --list-models`)",
            file=sys.stderr,
        )

    if getattr(args, "verify", False):
        return _run_verification(args, reports, backend, notes, include_values)

    session = ChatSession(context, backend, notes=notes, context_chars=args.context_chars)
    answer = session.ask(args.question)
    if args.json:
        print(json.dumps(answer.to_dict(), indent=2))
        return EXIT_OK

    print()
    print(answer.text.strip())
    problem = answer.citation_problem
    if problem:
        print(f"\n! {problem}", file=sys.stderr)
    else:
        print(
            f"\n— {len(answer.citations)} citation(s), all present in the context, "
            f"in {answer.elapsed_ms} ms. Nothing was written to disk.",
            file=sys.stderr,
        )
    return EXIT_OK


def _resolve_model_argument(args: argparse.Namespace) -> Path | None:
    """Turn ``--model`` into a GGUF path.

    Accepts a path, a catalogue id, ``repo/filename.gguf``, or ``auto`` — which
    picks the largest *downloaded* model that fits this machine, because the
    user downloaded it deliberately and a 7B answer beats a 1.1B one when the
    memory is there.
    """
    raw = (getattr(args, "model", None) or "").strip()
    if not raw:
        return None
    if raw.lower() in {"auto", "downloaded"}:
        chosen = model_catalog.resolve_downloaded_model()
        if chosen is None:
            print(
                "note: no downloaded model fits this machine; run "
                "`d3ta1l3r models list --fits-memory` and `d3ta1l3r models pull <id>`.",
                file=sys.stderr,
            )
        return chosen
    candidate = Path(raw).expanduser()
    if candidate.is_file() or candidate.suffix.lower() == ".gguf" or os.sep in raw:
        return candidate
    spec = model_catalog.find_model(raw)
    if spec is not None:
        path = model_catalog.model_path(spec)
        if not path.is_file():
            raise UsageError(
                f"{spec.id} is in the catalogue but not downloaded yet — "
                f"run `d3ta1l3r models pull {spec.id}`"
            )
        return path
    raise UsageError(
        f"no model called {raw!r}: it is not a file, not a catalogue id. "
        "Try `d3ta1l3r models list`."
    )


def _run_verification(
    args: argparse.Namespace,
    reports: list[ScanReport],
    backend: Any,
    notes: list[str],
    include_values: bool,
) -> int:
    """The opt-in identity review: model opinions, never evidence."""
    if any(report.demo for report in reports):
        print(
            "note: some reports are demo runs — verdicts about synthetic accounts say "
            "nothing about a real person.",
            file=sys.stderr,
        )
    about = args.about
    if args.about_file:
        try:
            about = args.about_file.expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise UsageError(f"could not read {args.about_file}: {exc}") from exc
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    if not backend.is_model:
        # Refusing beats "reviewing" with a keyword search: a page of "cannot tell"
        # lines looks like a review that found nothing, which is a different claim
        # from "no model was installed to do the reviewing".
        raise UsageError(
            "identity verification needs a model, and none is available here. "
            "Download one (`d3ta1l3r models list --fits-memory`, then "
            "`d3ta1l3r models pull <id>` with llama-cpp-python installed) or run "
            "Ollama on this machine. Nothing was judged."
        )
    print(
        f"reviewing with {backend.name} ({backend.model_id}); identifiers "
        f"{'included raw' if include_values else 'masked'}",
        file=sys.stderr,
    )

    result = verify_findings(
        reports,
        backend,
        about=about,
        include_values=include_values,
        limit=args.verify_limit,
        only_uncertain=args.only_uncertain,
        notes=notes,
    )
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return EXIT_OK
    if args.verify_markdown:
        print(render_verification_markdown(result))
        return EXIT_OK

    tally = result.tally()
    if not result.verdicts:
        print("Nothing to review: the selected scans have no findings.")
        return EXIT_OK
    print(f"Identity review · model {result.model or 'unknown'} ({result.backend})")
    print(f"  {tally.considered} finding(s): {tally.mine} look like you · "
          f"{tally.not_mine} probably not you · {tally.unsure} cannot tell\n")
    for verdict in result.verdicts:
        mark = {"mine": "=", "not_mine": "x", "unsure": "?"}[verdict.verdict.value]
        flag = "  <- disagrees with a strong finding" if verdict.disagrees_with_evidence else ""
        print(f"  [{mark}] {verdict.finding_id}  {verdict.measured_confidence or '?':<9} "
              f"{verdict.verdict.label:<16} {(verdict.reason or '—')[:80]}{flag}")
    print(
        "\nA model opinion, not a detection: the measured confidence is unchanged. "
        "Check the URL\nbefore acting on a verdict, especially a 'looks like you'."
    )
    if tally.unparsed:
        print(f"  {tally.unparsed} line(s) did not parse and were recorded as \"cannot tell\".")
    return EXIT_OK


def _ask_models() -> int:
    """What would run here, and what fits in 4 GB."""
    report = model_doctor()
    print(f"RAM budget: {report['ram_budget_mb']} MB · context {report['context_window']} tokens "
          f"· threads {report['threads']}")
    print(f"selected: {report['selected'] or 'nothing — see below'}\n")
    for backend in report["backends"]:
        state = "ready" if backend["available"] else "unavailable"
        print(f"  {backend['name']:<11} {state:<12} {backend['model']}")
        if not backend["available"]:
            print(f"      why: {backend['reason']}")
    print("\nModels that fit this machine (quantised, CPU-only):")
    for item in report["recommendations"]:
        print(
            f"  {item['name']:<36} ~{item['download_mb']:>5} MB download, "
            f"~{item['ram_mb']:>4} MB RAM  — {item['note']}"
        )
    print("\nTo use a GGUF file:")
    print("  pip install llama-cpp-python")
    print("  d3ta1l3r ask --model ~/models/qwen2.5-1.5b-instruct-q4_k_m.gguf \"what should I fix first?\"")
    print("Or point at an Ollama daemon on this machine:")
    print("  ollama pull llama3.2:1b && d3ta1l3r ask --backend ollama \"what changed?\"")
    return EXIT_OK


def _ask_sources(
    args: argparse.Namespace,
) -> tuple[list[ScanReport], list[VaultEntry], dict[str, Any] | None]:
    """Load the reports (and watchlist) the question is about."""
    reports: list[ScanReport] = []
    for path in args.report or []:
        reports.append(_load_report(path))

    store = ScanStore(Path(args.output))
    if not reports:
        wanted = args.scan or [meta.scan_id for meta in store.list(limit=args.limit)]
        if not args.scan:
            print(
                f"using the {len(wanted)} most recent scan(s) in {store.directory}",
                file=sys.stderr,
            )
        for scan_id in wanted:
            report = store.load(scan_id)
            if report is None:
                raise UsageError(f"no stored scan with id {scan_id} in {store.directory}")
            reports.append(report)

    watchlist: list[VaultEntry] = []
    if not args.no_watchlist:
        # A missing vault is not an error here: `ask` is useful against stored
        # reports alone, and the watchlist only sharpens the answer.
        path = _vault_path(args)
        if path.is_file():
            watchlist = Vault.open(path, _passphrase(args)).entries
    return reports, watchlist, None


def _confirm_raw_values(args: argparse.Namespace, backend: Any) -> bool:
    """Raw identifiers in the prompt are opt-in, and said out loud when implied.

    The digest is masked by default. ``--include-values`` includes them, and
    ``--yes`` is the explicit acknowledgement that the model will see them, so
    an interactive user is told in as many words rather than finding out later
    from a log of prompts.
    """
    if args.include_values:
        return True
    if not args.yes:
        print(
            "note: identifiers in the prompt are masked; pass --include-values to "
            "send them raw (only ever to a local model).",
            file=sys.stderr,
        )
    return False


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _config_from_args(
    args: argparse.Namespace, *, for_calibrate: bool = False, for_breach: bool = False
) -> ScanConfig:
    """Translate CLI flags into a :class:`ScanConfig`.

    ``for_breach`` drops the source/kind *filters*: for ``vault add`` and
    ``breach check`` the ``--kind`` flag describes the identifier being checked,
    not a subset of scan sources, and there are no site sources involved at all.
    """
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
    if getattr(args, "browser", None) is not None:
        overrides["browser_profile"] = args.browser or "off"
    if not for_calibrate and not for_breach:
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
