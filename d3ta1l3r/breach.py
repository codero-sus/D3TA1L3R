"""Breach and leak checks for identifiers you own.

Three sources ship here, and the difference between them matters more than the
code does:

``pwned_passwords``
    The **key-free, privacy-preserving** one. Your password is hashed locally
    with SHA-1 and only the **first five hexadecimal characters** of that hash
    are sent to ``api.pwnedpasswords.com/range/<prefix>``; the response lists
    hash suffixes and counts, and the match is completed on this machine. The
    server never learns the password, or even enough of its hash to test
    candidates. This is the same k-anonymity scheme password managers and
    browsers use.

``hibp_breaches``
    Account-level checking for **your own email address** against Have I Been
    Pwned's breach list. HIBP requires a (paid) API key for this endpoint, so the
    source is **disabled unless you provide one** via ``D3TA1L3R_HIBP_KEY``. With
    no key it reports a *gap* — never "clean" — because "we did not look" and
    "you are not in any breach" must never look the same.

``local_corpus``
    Matching against a **file you supply yourself** (``--corpus``); nothing
    leaves the machine. This is the supported way to answer "is my data in this
    leak I downloaded?" without D3TA1L3R ever becoming a leak-acquisition tool:
    it will not fetch, scrape, aggregate or bundle breach dumps, and no corpus
    ships with it. Build one from your own records with
    ``d3ta1l3r breach corpus-hash``, or point ``--corpus`` at a hash list you
    already have.

The rule that shapes every return path: **a check that did not happen is not a
pass.** Rate limits, missing keys, network failures, unsupported identifier types
and robots refusals all surface as :attr:`BreachStatus.UNKNOWN`, which reports
under "not checked" with the reason and which the dashboard shows as a gap rather
than a green tick. Only a source that genuinely answered can return
:attr:`BreachStatus.CLEAN`.

Phone numbers are a deliberate limitation: no key-free service maps a number to
breach records, and reverse-lookup services are out of scope, so phone entries
report a gap with that explanation unless a local corpus covers them.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .config import DEFAULT_USER_AGENT, ScanConfig
from .core.http import Fetcher
from .errors import UsageError
from .vault import VaultEntry, VaultKind

__all__ = [
    "BreachCheck",
    "BreachConfig",
    "BreachReport",
    "BreachSource",
    "BreachStatus",
    "HibpBreachedAccountSource",
    "LocalCorpusSource",
    "PwnedPasswordsSource",
    "build_breach_sources",
    "demo_transport",
    "hash_corpus_lines",
    "record_outcomes",
    "render_breach_markdown",
    "run_breach_check",
    "save_breach_report",
    "transient_password_entry",
]

_ENV_HIBP_KEY = "D3TA1L3R_HIBP_KEY"
_PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

_HASH_PREFIXES = {"sha1", "sha256", "sha512"}
_HASH_LENGTHS = {40: "sha1", 64: "sha256", 128: "sha512"}
_KIND_TAGS = {"email", "phone", "username", "domain"}

ProgressCallback = Callable[[dict[str, Any]], None]


class BreachStatus(str, Enum):
    """Outcome of one (identifier, source) check.

    ``CLEAN`` and ``PWNED`` are the only two states that represent an answer;
    everything else means the check did not actually happen.
    """

    CLEAN = "clean"
    PWNED = "pwned"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"

    @property
    def is_answer(self) -> bool:
        return self in (BreachStatus.CLEAN, BreachStatus.PWNED)

    @property
    def is_hit(self) -> bool:
        return self is BreachStatus.PWNED


@dataclass(slots=True)
class BreachCheck:
    """One source's verdict on one watched identifier."""

    entry_id: str
    kind: VaultKind
    label: str
    masked_value: str
    source_id: str
    source_name: str
    status: BreachStatus
    count: int = -1
    """How many records/breaches matched. ``-1`` when the source does not count."""
    detail: str = ""
    evidence: str = ""
    breaches: list[str] = field(default_factory=list)
    checked_at: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "kind": self.kind.value,
            "label": self.label,
            "masked_value": self.masked_value,
            "source_id": self.source_id,
            "source_name": self.source_name,
            "status": self.status.value,
            "count": self.count,
            "detail": self.detail,
            "evidence": self.evidence,
            "breaches": self.breaches,
            "checked_at": self.checked_at,
            "duration_ms": self.duration_ms,
        }


@dataclass(slots=True)
class BreachConfig:
    """Everything the checks need that is not in :class:`ScanConfig`.

    ``demo`` is derived from the :class:`ScanConfig` by :func:`run_breach_check`,
    so callers never set it twice: in demo mode every request is answered by a
    local fixture transport and no third party is contacted.
    """

    hibp_api_key: str = ""
    corpora: tuple[Path, ...] = ()
    include_unavailable_sources: bool = True
    demo: bool = False

    @classmethod
    def from_env(cls, **overrides: Any) -> BreachConfig:
        key = overrides.pop("hibp_api_key", None)
        if key is None:
            key = os.environ.get(_ENV_HIBP_KEY, "").strip()
        return cls(hibp_api_key=key, **overrides)

    @property
    def has_hibp_key(self) -> bool:
        return bool(self.hibp_api_key.strip())


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------
class BreachSource:
    """Base class for a breach-check source.

    Subclasses implement :meth:`check_one` and declare which
    :class:`~d3ta1l3r.vault.VaultKind` values they can answer for. Two rules:

    * a source returns ``UNKNOWN``/``UNSUPPORTED`` rather than guessing, and
    * a source never lets an exception escape :meth:`check` — a broken source
      becomes a visible gap, not a crashed run.
    """

    id: str = "breach_source"
    name: str = "breach source"
    kinds: frozenset[VaultKind] = frozenset()
    description: str = ""
    docs_url: str = ""
    homepage: str = ""
    sends_data: str = ""
    """Human-readable statement of what leaves the machine (shown by the CLI/UI)."""

    def __init__(self, fetcher: Fetcher | None = None) -> None:
        self.fetcher = fetcher

    def bind(self, fetcher: Fetcher) -> BreachSource:
        self.fetcher = fetcher
        return self

    @property
    def http(self) -> Fetcher:
        if self.fetcher is None:  # pragma: no cover - programming error
            raise RuntimeError(f"breach source {self.id} is not bound to a Fetcher")
        return self.fetcher

    def supports(self, entry: VaultEntry) -> bool:
        return entry.kind in self.kinds

    def available(self, config: BreachConfig) -> tuple[bool, str]:
        """``(usable, reason_if_not)`` — the reason is shown to the operator."""
        return True, ""

    def prepare(self, entries: Sequence[VaultEntry], config: BreachConfig) -> None:
        """Optional hook for batch sources (called once per run)."""

    async def check(self, entry: VaultEntry, config: BreachConfig) -> BreachCheck:
        started = time.perf_counter()
        try:
            return await self.check_one(entry, config)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # containment: a source may never fail a run
            return self._result(
                entry,
                BreachStatus.UNKNOWN,
                detail=f"{type(exc).__name__}: {exc}",
                evidence="the source failed before it could answer",
                started=started,
            )

    async def check_one(self, entry: VaultEntry, config: BreachConfig) -> BreachCheck:
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------
    def _result(
        self,
        entry: VaultEntry,
        status: BreachStatus,
        *,
        count: int = -1,
        detail: str = "",
        evidence: str = "",
        breaches: Sequence[str] = (),
        started: float | None = None,
    ) -> BreachCheck:
        return BreachCheck(
            entry_id=entry.entry_id,
            kind=entry.kind,
            label=entry.display,
            masked_value=entry.masked,
            source_id=self.id,
            source_name=self.name,
            status=status,
            count=count,
            detail=detail,
            evidence=evidence,
            breaches=list(breaches),
            checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            duration_ms=int((time.perf_counter() - started) * 1000) if started else 0,
        )

    def describe(self, config: BreachConfig) -> dict[str, Any]:
        usable, reason = self.available(config)
        return {
            "id": self.id,
            "name": self.name,
            "kinds": sorted(k.value for k in self.kinds),
            "description": self.description,
            "docs_url": self.docs_url,
            "homepage": self.homepage,
            "sends_data": self.sends_data,
            "available": usable,
            "unavailable_reason": "" if usable else reason,
        }


class PwnedPasswordsSource(BreachSource):
    """k-anonymity password checking against the Pwned Passwords range API."""

    id = "pwned_passwords"
    name = "Pwned Passwords (k-anonymity)"
    kinds = frozenset({VaultKind.PASSWORD})
    description = (
        "Checks a password against the Pwned Passwords corpus without revealing it: "
        "only the first five characters of its SHA-1 leave this machine."
    )
    docs_url = "https://haveibeenpwned.com/API/v3#PwnedPasswords"
    homepage = "https://haveibeenpwned.com/Passwords"
    sends_data = (
        "5 hexadecimal characters of SHA-1(password) — never the password, and never "
        "the full hash"
    )

    async def check_one(self, entry: VaultEntry, config: BreachConfig) -> BreachCheck:
        started = time.perf_counter()
        if not entry.password_sha1:
            return self._result(
                entry,
                BreachStatus.UNKNOWN,
                detail=(
                    "this password was stored without a verifier, so it cannot be re-checked "
                    "automatically — add it again with --store-hash to allow that"
                ),
                evidence="no verifier was kept for this entry, by design",
                started=started,
            )
        status, count, evidence = await self.check_hash(entry.password_sha1, started=started)
        return self._result(
            entry,
            status,
            count=count,
            detail=self._detail(status, count),
            evidence=evidence,
            started=started,
        )

    async def check_hash(
        self, sha1_hex: str, *, started: float | None = None
    ) -> tuple[BreachStatus, int, str]:
        """Look up a SHA-1 hash. Returns ``(status, count, evidence)``."""
        digest = sha1_hex.strip().lower()
        if len(digest) != 40 or not all(ch in "0123456789abcdef" for ch in digest):
            raise UsageError("a password hash must be 40 hexadecimal characters")
        prefix, suffix = digest[:5], digest[5:].upper()
        # Nothing but the five-character prefix is ever placed in a URL. There is
        # a test that inspects the request the transport actually saw.
        url = _PWNED_RANGE_URL.format(prefix=prefix)
        response = await self.http.fetch(
            url, accept="text/plain", extra_headers={"Add-Padding": "true"}
        )
        if response.status == 404:
            # An empty bucket: no hash in the corpus starts with this prefix.
            return BreachStatus.CLEAN, 0, f"no hash with prefix {prefix} is in the corpus"
        if not response.ok:
            raise RuntimeError(f"HTTP {response.status} from {response.final_url}")
        lines = [line for line in response.text.splitlines() if line.strip()]
        for line in lines:
            candidate, _, raw_count = line.strip().partition(":")
            if candidate.upper() != suffix:
                continue
            try:
                count = int(raw_count.strip())
            except ValueError:
                count = -1
            return (
                BreachStatus.PWNED,
                count,
                f"hash prefix {prefix} + matching suffix was seen {count} time(s) in the corpus",
            )
        return (
            BreachStatus.CLEAN,
            0,
            f"none of the {len(lines)} hashes under prefix {prefix} matched",
        )

    @staticmethod
    def _detail(status: BreachStatus, count: int) -> str:
        if status is BreachStatus.PWNED:
            return f"seen in {count} breach record(s)" if count >= 0 else "present in the corpus"
        return "not present in the Pwned Passwords corpus"

    @staticmethod
    def sha1_of(password: str) -> str:
        """SHA-1 of a password. This value never leaves the machine whole."""
        # SHA-1 is the API's identifier, not a security choice.
        return hashlib.sha1(password.encode("utf-8")).hexdigest()


class HibpBreachedAccountSource(BreachSource):
    """Account-level breach listing for your own email addresses (needs a key)."""

    id = "hibp_breaches"
    name = "Have I Been Pwned (account breaches)"
    kinds = frozenset({VaultKind.EMAIL})
    description = (
        "Lists the public breaches an email address appears in. Requires your own HIBP "
        "API key; without one this reports a gap instead of a clean bill of health."
    )
    docs_url = "https://haveibeenpwned.com/API/v3#BreachesForAccount"
    homepage = "https://haveibeenpwned.com"
    sends_data = "the email address itself (this HIBP endpoint takes the raw address)"

    def available(self, config: BreachConfig) -> tuple[bool, str]:
        if config.demo:
            # Demo mode answers from a local fixture; nothing leaves the machine.
            return True, ""
        if config.has_hibp_key:
            return True, ""
        return (
            False,
            f"needs an HIBP API key (set {_ENV_HIBP_KEY}); HIBP does not serve this "
            "endpoint anonymously, and D3TA1L3R will not pretend it checked",
        )

    async def check_one(self, entry: VaultEntry, config: BreachConfig) -> BreachCheck:
        started = time.perf_counter()
        url = _HIBP_BREACH_URL.format(account=quote(entry.value, safe=""))
        response = await self.http.fetch(
            url,
            accept="application/json",
            extra_headers={"hibp-api-key": config.hibp_api_key, "user-agent": DEFAULT_USER_AGENT()},
        )
        if response.status == 404:
            return self._result(
                entry,
                BreachStatus.CLEAN,
                count=0,
                detail="not found in any public breach HIBP tracks",
                evidence="HIBP answered 404, which is its 'no breaches' response",
                started=started,
            )
        if response.status == 401:
            return self._result(
                entry,
                BreachStatus.UNKNOWN,
                detail="HIBP rejected the API key (HTTP 401)",
                evidence="the configured key is missing, expired or incorrect",
                started=started,
            )
        if response.status == 429:
            return self._result(
                entry,
                BreachStatus.UNKNOWN,
                detail="HIBP rate limit reached (HTTP 429) — try again later",
                evidence="no answer was obtained, so this is a gap, not a pass",
                started=started,
            )
        if not response.ok:
            return self._result(
                entry,
                BreachStatus.UNKNOWN,
                detail=f"HIBP answered HTTP {response.status}",
                evidence=f"the request to {url} did not succeed",
                started=started,
            )
        payload = response.json()
        if not isinstance(payload, list):
            raise RuntimeError(
                f"HIBP returned {type(payload).__name__}, expected a list of breaches"
            )
        names = [
            str(item.get("Name") or item.get("Title") or "unnamed breach")
            for item in payload
            if isinstance(item, dict)
        ]
        if not names:
            return self._result(
                entry,
                BreachStatus.CLEAN,
                count=0,
                detail="HIBP returned an empty breach list",
                evidence="no breaches are recorded for this address",
                started=started,
            )
        return self._result(
            entry,
            BreachStatus.PWNED,
            count=len(names),
            detail=(
                f"appears in {len(names)} public breach(es): {', '.join(names[:6])}"
                + (" …" if len(names) > 6 else "")
            ),
            evidence="HIBP listed this address in its breach set",
            breaches=names,
            started=started,
        )


class LocalCorpusSource(BreachSource):
    """Match watchlist entries against a hash/literal list you supply.

    Supported line formats (blank lines and ``#`` comments ignored)::

        sha1:<40 hex>        sha256:<64 hex>        sha512:<128 hex>
        40-hex               bare SHA-1
        64-hex               bare SHA-256
        email@example.com    a literal address
        email@example.com:hunter2   an address:password pair (the address is matched)
        plain:<text>         a literal value of any kind
        +14155550123         a literal phone number

    The file is streamed once per run and only *matches* are retained, so a
    multi-gigabyte corpus costs memory proportional to the watchlist rather than
    to the corpus. Nothing is uploaded, and D3TA1L3R never downloads a corpus
    for you.
    """

    id = "local_corpus"
    name = "Local corpus file"
    kinds = frozenset(VaultKind)
    description = (
        "Matches your watchlist against a breach or hash list you already have on disk. "
        "Nothing leaves the machine, and no corpus ships with D3TA1L3R."
    )
    docs_url = "https://github.com/codero-sus/D3TA1L3R/blob/main/docs/SCOPE.md"
    homepage = ""
    sends_data = "nothing — matching happens entirely on this machine"

    def __init__(self, corpus: Path, *, name: str | None = None) -> None:
        super().__init__()
        self.corpus = Path(corpus)
        # One instance per file: giving each its own id keeps a report readable when
        # several corpora are checked in the same run.
        self.id = f"local_corpus[{self.corpus.name}]"
        self.name = name or f"Local corpus ({self.corpus.name})"
        self._matches: dict[str, tuple[int, str]] = {}
        self._lines = 0
        self._error = ""
        self._prepared = False

    def available(self, config: BreachConfig) -> tuple[bool, str]:
        if not self.corpus.is_file():
            return False, f"no corpus file at {self.corpus} (pass --corpus PATH)"
        return True, ""

    def prepare(self, entries: Sequence[VaultEntry], config: BreachConfig) -> None:
        """Stream the corpus once, keeping only entries we actually watch."""
        self._matches = {}
        self._lines = 0
        self._error = ""
        self._prepared = True
        if not self.corpus.is_file():
            self._error = f"corpus file not found: {self.corpus}"
            return

        wanted = _corpus_keys(entries)
        if not wanted:
            return
        try:
            with self.corpus.open("r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    self._lines += 1
                    key = _corpus_line_key(raw)
                    if key is None:
                        continue
                    entry_id = wanted.get(key)
                    if entry_id is None:
                        continue
                    count, sample = self._matches.get(entry_id, (0, ""))
                    self._matches[entry_id] = (count + 1, sample or key)
        except OSError as exc:
            self._error = f"could not read {self.corpus}: {exc}"

    async def check_one(self, entry: VaultEntry, config: BreachConfig) -> BreachCheck:
        if not self._prepared:
            self.prepare([entry], config)
        if self._error:
            return self._result(
                entry,
                BreachStatus.UNKNOWN,
                detail=self._error,
                evidence="the corpus could not be read, so nothing was checked",
            )
        if _corpus_key(entry) is None:
            return self._result(
                entry,
                BreachStatus.UNSUPPORTED,
                detail=(
                    "this entry keeps no value or verifier to match with, so the local "
                    "corpus cannot cover it (add it with --store-hash)"
                ),
            )
        found = self._matches.get(entry.entry_id)
        if found is None:
            return self._result(
                entry,
                BreachStatus.CLEAN,
                count=0,
                detail=f"not present in {self.name} ({self._lines} lines scanned)",
                evidence=f"neither the value nor its hash appears in {self.name}",
            )
        count, sample = found
        return self._result(
            entry,
            BreachStatus.PWNED,
            count=count,
            detail=f"{count} matching line(s) in {self.name} (first: {sample[:60]})",
            evidence=f"{self.name} contains this value or one of its hashes",
            breaches=[self.name],
        )


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
async def run_breach_check(
    entries: Sequence[VaultEntry],
    *,
    scan_config: ScanConfig | None = None,
    breach_config: BreachConfig | None = None,
    sources: Sequence[BreachSource] | None = None,
    transport: Any | None = None,
    on_event: ProgressCallback | None = None,
) -> BreachReport:
    """Check every entry against every applicable source.

    Entries are processed serially so progress stays readable; the shared HTTP
    layer still applies per-host pacing, retries and robots handling, so hitting
    the password API many times stays polite.
    """
    config = breach_config or BreachConfig.from_env()
    scan_config = scan_config or ScanConfig()
    if scan_config.demo and not config.demo:
        # Demo mode is decided in exactly one place: the scan config the caller
        # built. It must be folded in *before* availability is judged, so that a
        # source answered by a local fixture is not reported as a gap.
        config = replace(config, demo=True)
    sources = list(sources if sources is not None else build_breach_sources(config))

    available: list[BreachSource] = []
    unavailable: list[dict[str, str]] = []
    for source in sources:
        usable, reason = source.available(config)
        if usable:
            available.append(source)
        elif config.include_unavailable_sources:
            unavailable.append(
                {"source_id": source.id, "source_name": source.name, "reason": reason}
            )
            _emit(
                on_event,
                {
                    "type": "source_unavailable",
                    "source_id": source.id,
                    "source_name": source.name,
                    "message": reason,
                },
            )

    report = BreachReport(entries=list(entries), unavailable=unavailable)
    if not entries:
        report.finished_at = datetime.now(timezone.utc)
        return report

    for source in available:
        source.prepare(entries, config)

    if transport is None and scan_config.demo:
        transport = demo_transport()

    async with Fetcher(scan_config, transport=transport) as fetcher:
        bound = [source.bind(fetcher) for source in available]
        for index, entry in enumerate(entries, start=1):
            _emit(
                on_event,
                {
                    "type": "entry_started",
                    "message": f"checking {entry.kind.label} {entry.masked}",
                    "kind": entry.kind.value,
                    "masked_value": entry.masked,
                    "completed": index - 1,
                    "total": len(entries),
                    "percent": round((index - 1) / len(entries) * 100, 1),
                },
            )
            for source in bound:
                if not source.supports(entry):
                    continue
                _emit(
                    on_event,
                    {
                        "type": "source_started",
                        "message": f"{source.name}: {entry.masked}",
                        "source_id": source.id,
                        "source_name": source.name,
                        "completed": index - 1,
                        "total": len(entries),
                    },
                )
                check = await source.check(entry, config)
                report.checks.append(check)
                _emit(
                    on_event,
                    {
                        "type": "source_finished",
                        "message": f"{source.name}: {check.status.value}",
                        "source_id": source.id,
                        "source_name": source.name,
                        "status": check.status.value,
                        "detail": check.detail,
                        "completed": index,
                        "total": len(entries),
                        "percent": round(index / len(entries) * 100, 1),
                    },
                )

    report.finished_at = datetime.now(timezone.utc)
    return report


def demo_transport() -> Any:
    """The synthetic transport used when ``ScanConfig.demo`` is set."""
    from .core.demo import DemoTransport

    return DemoTransport()


def _emit(on_event: ProgressCallback | None, event: dict[str, Any]) -> None:
    if on_event is None:
        return
    with contextlib.suppress(Exception):  # an observer must never break a run
        on_event(event)


@dataclass(slots=True)
class BreachReport:
    """The outcome of one watchlist run."""

    entries: list[VaultEntry]
    checks: list[BreachCheck] = field(default_factory=list)
    unavailable: list[dict[str, str]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    # -- views -----------------------------------------------------------
    @property
    def pwned(self) -> list[BreachCheck]:
        return [check for check in self.checks if check.status.is_hit]

    @property
    def unknown(self) -> list[BreachCheck]:
        return [check for check in self.checks if not check.status.is_answer]

    @property
    def clean(self) -> list[BreachCheck]:
        return [check for check in self.checks if check.status is BreachStatus.CLEAN]

    @property
    def sources_used(self) -> list[str]:
        return sorted({check.source_id for check in self.checks})

    @property
    def nothing_was_checked(self) -> bool:
        return not self.checks

    def counts(self) -> dict[str, int]:
        buckets = {status.value: 0 for status in BreachStatus}
        for check in self.checks:
            buckets[check.status.value] += 1
        return buckets

    @property
    def duration_ms(self) -> int:
        if not self.finished_at:
            return 0
        return max(0, int((self.finished_at - self.started_at).total_seconds() * 1000))

    def entry_status(self, entry_id: str) -> BreachStatus:
        """The strongest verdict across sources for one entry."""
        statuses = [c.status for c in self.checks if c.entry_id == entry_id]
        if any(s is BreachStatus.PWNED for s in statuses):
            return BreachStatus.PWNED
        if any(s is BreachStatus.CLEAN for s in statuses):
            return BreachStatus.CLEAN
        if statuses and all(s is BreachStatus.UNSUPPORTED for s in statuses):
            return BreachStatus.UNSUPPORTED
        return BreachStatus.UNKNOWN

    def checks_for(self, entry_id: str) -> list[BreachCheck]:
        return [check for check in self.checks if check.entry_id == entry_id]

    # -- serialisation ---------------------------------------------------
    def entry_counts(self) -> dict[str, int]:
        """How many *identifiers* (not individual checks) ended up in each state.

        ``counts()`` counts checks — one entry can produce several, one per source,
        which is what a report needs. This view answers the question a person
        actually asks: "how many of my identifiers were found, cleared, or left
        unchecked?".
        """
        tally = {status.value: 0 for status in BreachStatus}
        for entry in self.entries:
            tally[self.entry_status(entry.entry_id).value] += 1
        return tally

    def headline(self) -> str:
        """One line a human can read at a glance (used by the CLI and the dashboard)."""
        counts = self.entry_counts()
        found = counts.get("pwned", 0)
        gaps = counts.get("unknown", 0) + counts.get("unsupported", 0)
        if self.nothing_was_checked:
            return "Nothing could be checked — every configured source was unavailable."
        parts: list[str] = []
        if found:
            parts.append(f"{found} identifier(s) found in breach data")
        if counts.get("clean"):
            parts.append(f"{counts['clean']} not found")
        if gaps:
            parts.append(f"{gaps} not checked")
        return " · ".join(parts) or "no results"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "d3ta1l3r/breach/1",
            "headline": self.headline(),
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": (
                self.finished_at.isoformat(timespec="seconds") if self.finished_at else None
            ),
            "duration_ms": self.duration_ms,
            "entries": [
                {
                    "entry_id": entry.entry_id,
                    "kind": entry.kind.value,
                    "label": entry.display,
                    "masked_value": entry.masked,
                    "status": self.entry_status(entry.entry_id).value,
                    "checks": [c.to_dict() for c in self.checks_for(entry.entry_id)],
                }
                for entry in self.entries
            ],
            "counts": self.counts(),
            "entry_counts": self.entry_counts(),
            "nothing_was_checked": self.nothing_was_checked,
            "checks": [check.to_dict() for check in self.checks],
            "unavailable_sources": self.unavailable,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def render_markdown(self) -> str:
        return render_breach_markdown(self)


# ---------------------------------------------------------------------------
# report rendering
# ---------------------------------------------------------------------------
def _label(check: BreachCheck) -> str:
    """Human label for a check, avoiding "Alice (`Al***`)" duplication."""
    if check.label and check.label != check.masked_value:
        return f"{check.label} (`{check.masked_value}`)"
    return f"`{check.masked_value}`"


_GAP_NOTE = (
    "Only `pwned` and `clean` are answers. Everything else means the check did "
    "not happen — read those lines as gaps, not as good news."
)


def render_breach_markdown(report: BreachReport) -> str:
    """Human report: what leaked, what was checked, and what was not."""
    lines: list[str] = ["# D3TA1L3R breach watch", ""]
    lines.append(
        f"- **Watchlist:** {len(report.entries)} identifier(s) · "
        f"**sources:** {len(report.sources_used)} · "
        f"**duration:** {report.duration_ms / 1000:.1f}s"
    )
    entry_counts = report.entry_counts()
    lines.append(
        f"- **Results:** {entry_counts['pwned']} in breach data · "
        f"{entry_counts['clean']} not found · "
        f"{entry_counts['unknown'] + entry_counts['unsupported']} not checked"
    )
    lines.append("")

    if report.nothing_was_checked:
        lines += [
            "**Nothing was checked.** No breach source could answer for this watchlist — "
            "see the gaps below. This is not a clean result.",
            "",
        ]

    if report.pwned:
        lines += ["## Found in breach data", ""]
        for check in report.pwned:
            lines.append(f"- **{_label(check)}** — {check.source_name}: {check.detail}")
            if check.breaches:
                lines.append(f"  - breaches: {', '.join(check.breaches[:12])}")
        lines += [
            "",
            "Change the password anywhere it was used, starting with your email account, "
            "and enable two-factor authentication. If it was reused, treat every account "
            "that shared it as compromised.",
            "",
        ]

    if report.clean:
        lines += ["## Checked and not found", ""]
        for check in report.clean:
            lines.append(f"- {_label(check)} — {check.source_name}")
        lines += [""]

    if report.unknown or report.unavailable:
        lines += ["## Not checked (gaps)", "", _GAP_NOTE, ""]
        for check in report.unknown:
            lines.append(
                f"- {_label(check)} — {check.source_name}: {check.detail or check.evidence}"
            )
        for gap in report.unavailable:
            lines.append(f"- **{gap['source_name']}** — source unavailable: {gap['reason']}")
        lines += [""]

    lines += [
        "## What left this machine",
        "",
        "* Password checks sent **five characters of a SHA-1 hash**, nothing else.",
        "* Email checks (only when an HIBP key is configured) sent the **address itself**.",
        "* Local corpus checks sent **nothing at all**.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# corpus helpers
# ---------------------------------------------------------------------------
def _corpus_key(entry: VaultEntry) -> str | None:
    """The canonical key for an entry (mirrors :func:`_corpus_keys`)."""
    if entry.kind is VaultKind.PASSWORD:
        return f"sha1:{entry.password_sha1}" if entry.password_sha1 else None
    return f"plain:{entry.value.lower()}" if entry.value else None


def _corpus_keys(entries: Iterable[VaultEntry]) -> dict[str, str]:
    """Every representation of an entry a corpus line might use: ``key -> entry_id``.

    An email is indexed in plain, SHA-1, SHA-256 and SHA-512 forms, so a corpus
    of hashes works as well as a corpus of addresses.
    """
    index: dict[str, str] = {}
    for entry in entries:
        if entry.kind is VaultKind.PASSWORD:
            if entry.password_sha1:
                index[f"sha1:{entry.password_sha1}"] = entry.entry_id
            continue
        if not entry.value:
            continue
        value = entry.value.lower()
        index[f"plain:{value}"] = entry.entry_id
        encoded = value.encode("utf-8")
        index[f"sha1:{hashlib.sha1(encoded).hexdigest()}"] = entry.entry_id
        index[f"sha256:{hashlib.sha256(encoded).hexdigest()}"] = entry.entry_id
        index[f"sha512:{hashlib.sha512(encoded).hexdigest()}"] = entry.entry_id
    return index


def _is_hex(value: str) -> bool:
    return bool(value) and all(ch in "0123456789abcdef" for ch in value)


def _corpus_line_key(raw_line: str) -> str | None:
    """Normalise one corpus line into a lookup key, or ``None`` to ignore it."""
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    lowered = line.lower()

    if ":" in lowered:
        tag, _, rest = lowered.partition(":")
        tag, rest = tag.strip(), rest.strip()
        if tag in _HASH_PREFIXES and _is_hex(rest):
            return f"{tag}:{rest}"
        if tag == "plain" and rest:
            return f"plain:{rest}"
        if tag in _KIND_TAGS and rest:
            return f"plain:{rest}"
        if tag and rest:
            # "user@example.com:hunter2" and similar pairs: match on the account.
            return f"plain:{tag}"

    if _is_hex(lowered) and len(lowered) in _HASH_LENGTHS:
        return f"{_HASH_LENGTHS[len(lowered)]}:{lowered}"
    return f"plain:{lowered}"


def hash_corpus_lines(lines: Iterable[str], *, algorithm: str = "sha256") -> list[str]:
    """Hash plaintext lines so a corpus can be kept and matched without the values.

    Build one from *your own* exported records — never from a dump you intend to
    pass on — and keep the output beside your vault.
    """
    if algorithm not in _HASH_PREFIXES:
        raise UsageError("algorithm must be sha1, sha256 or sha512")
    out: list[str] = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        digest = hashlib.new(algorithm, value.lower().encode("utf-8")).hexdigest()
        out.append(f"{algorithm}:{digest}")
    return out


def transient_password_entry(
    password: str, *, label: str = "", entry_id: str = ""
) -> VaultEntry:
    """A throwaway entry for a password we hold in memory right now.

    It exists only long enough to be checked through the same code path as a
    stored entry, and is never persisted: the vault keeps the *outcome* (a count
    and a timestamp), and — only when the caller asked for it — a SHA-1 verifier
    that makes later automatic checks possible. Pass ``entry_id`` of the stored
    entry so the outcome can be recorded against it.
    """
    return VaultEntry(
        kind=VaultKind.PASSWORD,
        entry_id=entry_id,
        label=label,
        password_length=len(password),
        password_sha1=PwnedPasswordsSource.sha1_of(password),
    )


def record_outcomes(vault: Any, report: BreachReport) -> None:
    """Copy a report's per-entry outcomes into the vault and save (metadata only).

    Only entries that produced at least one check are touched. A run in which
    every source was unavailable leaves the previous answer — or the
    "never checked" state — alone: the gap belongs to that run, and writing
    "unknown" over a real result would quietly destroy information.
    """
    if vault is None:
        return
    for entry in report.entries:
        checks = report.checks_for(entry.entry_id)
        if not checks:
            continue
        status = report.entry_status(entry.entry_id)
        vault.record_check(
            entry.entry_id, status=status.value, count=max(c.count for c in checks)
        )
    if getattr(vault, "dirty", False):
        vault.save()


def save_breach_report(report: BreachReport, directory: Path | str) -> Path | None:
    """Write a breach report (and ``latest.json``) under ``<directory>/breach/``."""
    try:
        target = Path(directory) / "breach"
        target.mkdir(parents=True, exist_ok=True)
        stamp = report.started_at.strftime("%Y%m%dT%H%M%SZ")
        path = target / f"{stamp}-watchlist.json"
        body = report.to_json() + "\n"
        path.write_text(body, encoding="utf-8")
        (target / "latest.json").write_text(body, encoding="utf-8")
        return path
    except OSError:  # pragma: no cover - disk problems must not break the run
        return None


def build_breach_sources(config: BreachConfig | None = None) -> list[BreachSource]:
    """Default source set for a run (the orchestrator binds a fetcher to each)."""
    config = config or BreachConfig.from_env()
    sources: list[BreachSource] = [PwnedPasswordsSource(), HibpBreachedAccountSource()]
    sources.extend(LocalCorpusSource(corpus) for corpus in config.corpora)
    return sources
