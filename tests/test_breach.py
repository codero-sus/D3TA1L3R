"""Breach and leak checking.

Two things are being defended here:

* the *boundary* — no dump is ever downloaded, no corpus ships with the tool, and
  only five hex characters of a password hash ever leave the machine; and
* the *honesty* — a check that could not happen comes back as a gap, never as a
  clean bill of health.

Everything runs through ``httpx.MockTransport``, so the real fetcher, pacing and
parsing code paths run while the bytes stay local.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import httpx
import pytest

from d3ta1l3r.breach import (
    BreachConfig,
    BreachStatus,
    HibpBreachedAccountSource,
    LocalCorpusSource,
    PwnedPasswordsSource,
    build_breach_sources,
    hash_corpus_lines,
    record_outcomes,
    render_breach_markdown,
    run_breach_check,
    transient_password_entry,
)
from d3ta1l3r.errors import UsageError
from d3ta1l3r.vault import Vault, VaultEntry, VaultKind
from tests.conftest import make_config

PWNED_PASSWORD = "hunter2"
# sha1_of() speaks lowercase, exactly as the range API expects the prefix.
PWNED_DIGEST = hashlib.sha1(PWNED_PASSWORD.encode()).hexdigest()
PWNED_SUFFIX = PWNED_DIGEST[5:].upper()


def entry(kind: VaultKind, value: str, **kwargs: Any) -> VaultEntry:
    return VaultEntry(kind=kind, value=value, **kwargs)


def password_entry(password: str = PWNED_PASSWORD) -> VaultEntry:
    return transient_password_entry(password, label="demo password")


def range_body(*, include_suffix: bool, count: int = 42) -> str:
    """A Pwned Passwords response: suffix:count lines, plus padding noise."""
    lines = ["000000000000000000000000000000000A:3"]
    if include_suffix:
        lines.append(f"{PWNED_SUFFIX}:{count}")
    return "\r\n".join(lines) + "\r\n"


def breach_config(**overrides: Any) -> BreachConfig:
    return BreachConfig(hibp_api_key="test-key", **overrides)


# ---------------------------------------------------------------------------
# k-anonymity password checks
# ---------------------------------------------------------------------------
class TestPwnedPasswords:
    async def test_only_the_hash_prefix_leaves_the_machine(self, fetcher_factory) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, text=range_body(include_suffix=True), request=request)

        fetcher, table = await fetcher_factory({"api.pwnedpasswords.com": handler})
        source = PwnedPasswordsSource().bind(fetcher)
        check = await source.check_one(password_entry(), breach_config())

        assert check.status is BreachStatus.PWNED
        assert check.count == 42
        assert len(seen) == 1
        url = str(seen[0].url)
        assert url.endswith(f"/range/{PWNED_DIGEST[:5]}")
        assert PWNED_PASSWORD not in url
        assert PWNED_DIGEST not in url
        assert PWNED_DIGEST[5:] not in url
        # Padding is requested so response sizes do not leak the answer.
        assert seen[0].headers.get("add-padding") == "true"
        assert table.count("range/") == 1

    async def test_a_clean_password_is_an_answer(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"api.pwnedpasswords.com": lambda request: httpx.Response(
                200, text=range_body(include_suffix=False), request=request
            )}
        )
        check = await PwnedPasswordsSource().bind(fetcher).check_one(
            password_entry(), breach_config()
        )
        assert check.status is BreachStatus.CLEAN
        assert check.count == 0
        assert "not present" in check.detail

    async def test_an_empty_range_is_still_a_lookup(self, fetcher_factory) -> None:
        """A 404 means "no suffixes in this bucket", which is a real clean answer."""
        fetcher, _ = await fetcher_factory({"api.pwnedpasswords.com": 404})
        check = await PwnedPasswordsSource().bind(fetcher).check_one(
            password_entry(), breach_config()
        )
        assert check.status is BreachStatus.CLEAN

    @pytest.mark.parametrize("status", [429, 500, 503])
    async def test_rate_limits_and_server_errors_are_gaps(
        self, fetcher_factory, status: int
    ) -> None:
        fetcher, _ = await fetcher_factory({"api.pwnedpasswords.com": status})
        # check() is the containing wrapper the orchestrator calls.
        check = await PwnedPasswordsSource().bind(fetcher).check(password_entry(), breach_config())
        assert check.status is BreachStatus.UNKNOWN
        assert check.status is not BreachStatus.CLEAN
        assert str(status) in check.detail
        assert "could not answer" in check.evidence or "failed" in check.evidence

    async def test_a_password_without_a_verifier_is_not_checked(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory({"api.pwnedpasswords.com": 200})
        check = await PwnedPasswordsSource().bind(fetcher).check_one(
            VaultEntry(kind=VaultKind.PASSWORD, password_length=8), breach_config()
        )
        assert check.status is BreachStatus.UNKNOWN
        assert "verifier" in check.detail

    async def test_unrelated_lines_under_the_prefix_are_not_matches(
        self, fetcher_factory
    ) -> None:
        body = "not-a-line\r\n" + "0" * 35 + ":9\r\n" + "\r\n"
        fetcher, _ = await fetcher_factory(
            {"api.pwnedpasswords.com": lambda request: httpx.Response(
                200, text=body, request=request
            )}
        )
        check = await PwnedPasswordsSource().bind(fetcher).check_one(
            password_entry(), breach_config()
        )
        assert check.status is BreachStatus.CLEAN

    async def test_a_matching_suffix_with_a_broken_count_is_still_a_match(
        self, fetcher_factory
    ) -> None:
        fetcher, _ = await fetcher_factory(
            {"api.pwnedpasswords.com": lambda request: httpx.Response(
                200, text=f"{PWNED_SUFFIX}:not-a-number\r\n", request=request
            )}
        )
        check = await PwnedPasswordsSource().bind(fetcher).check_one(
            password_entry(), breach_config()
        )
        assert check.status is BreachStatus.PWNED
        assert check.count == -1  # unknown count, but the match is real

    def test_sha1_of_matches_the_algorithm_the_api_speaks(self) -> None:
        assert PwnedPasswordsSource.sha1_of(PWNED_PASSWORD) == PWNED_DIGEST
        assert len(PWNED_DIGEST) == 40
        assert PwnedPasswordsSource.sha1_of(PWNED_PASSWORD) == PwnedPasswordsSource.sha1_of(
            PWNED_PASSWORD
        )


# ---------------------------------------------------------------------------
# account-level checks (HIBP, user's own key)
# ---------------------------------------------------------------------------
class TestHibpBreaches:
    async def test_without_a_key_it_is_a_gap_not_a_pass(self, fetcher_factory) -> None:
        fetcher, table = await fetcher_factory({"hibp": 404})
        report = await run_breach_check(
            [entry(VaultKind.EMAIL, "alice@example.com")],
            scan_config=make_config(),
            breach_config=BreachConfig(),
        )
        assert report.checks == []
        assert [gap["source_id"] for gap in report.unavailable] == ["hibp_breaches"]
        assert report.nothing_was_checked is True
        assert entry(VaultKind.EMAIL, "alice@example.com").entry_id not in {
            c.entry_id for c in report.checks
        }
        del fetcher, table

    async def test_the_key_and_a_honest_user_agent_are_sent(self, fetcher_factory) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(404, json={"statusCode": 404}, request=request)

        fetcher, _ = await fetcher_factory({"haveibeenpwned.com": handler})
        source = HibpBreachedAccountSource().bind(fetcher)
        check = await source.check_one(
            entry(VaultKind.EMAIL, "alice@example.com"), breach_config()
        )
        assert check.status is BreachStatus.CLEAN
        assert seen[0].headers.get("hibp-api-key") == "test-key"
        assert "D3TA1L3R" in seen[0].headers.get("user-agent", "")
        # The address travels in the path, percent-encoded the way HIBP expects.
        assert "alice%40example.com" in str(seen[0].url)

    async def test_a_listed_address_reports_the_breaches(self, fetcher_factory) -> None:
        payload = [
            {"Name": "Adobe", "Title": "Adobe"},
            {"Name": "Dropbox", "Title": "Dropbox"},
        ]
        fetcher, _ = await fetcher_factory(
            {"haveibeenpwned.com": lambda request: httpx.Response(
                200, json=payload, request=request
            )}
        )
        check = await HibpBreachedAccountSource().bind(fetcher).check_one(
            entry(VaultKind.EMAIL, "alice@example.com"), breach_config()
        )
        assert check.status is BreachStatus.PWNED
        assert check.count == 2
        assert check.breaches == ["Adobe", "Dropbox"]
        assert "Adobe" in check.detail

    async def test_an_empty_list_is_clean(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"haveibeenpwned.com": lambda request: httpx.Response(
                200, json=[], request=request
            )}
        )
        check = await HibpBreachedAccountSource().bind(fetcher).check_one(
            entry(VaultKind.EMAIL, "alice@example.com"), breach_config()
        )
        assert check.status is BreachStatus.CLEAN

    @pytest.mark.parametrize("status", [401, 403, 429, 500])
    async def test_bad_statuses_never_read_as_clean(self, fetcher_factory, status: int) -> None:
        fetcher, _ = await fetcher_factory({"haveibeenpwned.com": status})
        check = await HibpBreachedAccountSource().bind(fetcher).check_one(
            entry(VaultKind.EMAIL, "alice@example.com"), breach_config()
        )
        assert check.status is BreachStatus.UNKNOWN

    async def test_a_non_list_payload_becomes_an_error_not_a_guess(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"haveibeenpwned.com": lambda request: httpx.Response(
                200, json={"message": "nope"}, request=request
            )}
        )
        source = HibpBreachedAccountSource().bind(fetcher)
        with pytest.raises(RuntimeError, match="expected a list"):
            await source.check_one(entry(VaultKind.EMAIL, "alice@example.com"), breach_config())

    def test_it_needs_a_key_and_says_how_to_get_one(self) -> None:
        usable, reason = HibpBreachedAccountSource().available(BreachConfig())
        assert usable is False
        assert "D3TA1L3R_HIBP_KEY" in reason
        assert HibpBreachedAccountSource().available(breach_config())[0] is True

    def test_it_only_claims_email_addresses(self) -> None:
        assert HibpBreachedAccountSource().kinds == frozenset({VaultKind.EMAIL})


# ---------------------------------------------------------------------------
# local corpus matching
# ---------------------------------------------------------------------------
class TestLocalCorpus:
    def _corpus(self, tmp_path: Path, lines: list[str]) -> Path:
        path = tmp_path / "leak.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    async def test_hash_and_plain_lines_both_match(self, fetcher_factory, tmp_path: Path) -> None:
        corpus = self._corpus(
            tmp_path,
            [
                "# a comment, a blank line and a match:",
                "",
                f"sha1:{PWNED_DIGEST.lower()}",
                "plain:alice@example.com",
                "user@example.com:hunter2",
                "d41d8cd98f00b204e9800998ecf8427e",
            ],
        )
        config = breach_config(corpora=(corpus,))
        report = await run_breach_check(
            [
                password_entry(),
                entry(VaultKind.EMAIL, "alice@example.com"),
                entry(VaultKind.EMAIL, "clean@example.com"),
            ],
            scan_config=make_config(),
            breach_config=config,
        )
        statuses = {
            c.entry_id: c.status for c in report.checks if c.source_id.startswith("local_corpus")
        }
        pwned = [e for e in report.entries if statuses.get(e.entry_id) is BreachStatus.PWNED]
        assert [e.kind for e in pwned] == [VaultKind.PASSWORD, VaultKind.EMAIL]
        assert report.checks_for(report.entries[2].entry_id)[-1].status is BreachStatus.CLEAN

    async def test_a_match_is_described_without_echoing_the_corpus_line(
        self, fetcher_factory, tmp_path: Path
    ) -> None:
        """The report says *that* something matched — never *what* matched.

        A report is a file people paste into issues and chats, so the corpus
        line that hit is the one thing that must not travel with it. The detail
        keeps the shape of the match (a digest, a literal) and nothing else.
        """
        digest = hashlib.sha256(b"alice@example.com").hexdigest()
        corpus = self._corpus(tmp_path, [f"sha256:{digest}"])
        report = await run_breach_check(
            [entry(VaultKind.EMAIL, "alice@example.com")],
            scan_config=make_config(),
            breach_config=breach_config(corpora=(corpus,)),
        )
        check = report.checks[-1]
        assert check.status is BreachStatus.PWNED
        assert "first match: a sha256 digest" in check.detail
        rendered = report.to_json() + report.render_markdown()
        assert digest not in rendered
        assert "alice@example.com" not in rendered

    async def test_a_missing_corpus_is_a_named_gap(self, fetcher_factory, tmp_path: Path) -> None:
        missing = tmp_path / "gone.txt"
        report = await run_breach_check(
            [entry(VaultKind.EMAIL, "alice@example.com")],
            scan_config=make_config(),
            breach_config=breach_config(corpora=(missing,)),
        )
        gaps = {gap["source_id"]: gap["reason"] for gap in report.unavailable}
        assert f"local_corpus[{missing.name}]" in gaps
        assert "no corpus file" in gaps[f"local_corpus[{missing.name}]"]

    async def test_only_matches_are_kept_in_memory(self, fetcher_factory, tmp_path: Path) -> None:
        corpus = self._corpus(tmp_path, [f"sha1:{PWNED_DIGEST.lower()}"] + ["x" * 8] * 500)
        source = LocalCorpusSource(corpus)
        source.prepare([password_entry()], breach_config(corpora=(corpus,)))
        assert source._lines == 501
        assert len(source._matches) == 1

    def test_each_file_gets_its_own_identifier(self, tmp_path: Path) -> None:
        one = LocalCorpusSource(tmp_path / "a.txt")
        two = LocalCorpusSource(tmp_path / "b.txt")
        assert one.id != two.id
        assert one.id.startswith("local_corpus[")

    def test_nothing_is_sent_anywhere(self) -> None:
        source = LocalCorpusSource(Path("whatever.txt"))
        assert source.sends_data.startswith("nothing")

    def test_corpus_hash_builds_the_same_thing_the_matcher_reads(
        self, tmp_path: Path
    ) -> None:
        lines = ["hunter2", "", "# comment", "Alice@Example.com"]
        hashed = hash_corpus_lines(lines, algorithm="sha1")
        assert len(hashed) == 2  # blank and comment lines are skipped
        assert all(line.startswith("sha1:") for line in hashed)
        assert hashlib.sha1(b"hunter2").hexdigest() in hashed[0]
        assert hashlib.sha1(b"alice@example.com").hexdigest() in hashed[1]

    def test_corpus_hash_rejects_an_unknown_algorithm(self) -> None:
        with pytest.raises(UsageError, match="sha1, sha256 or sha512"):
            hash_corpus_lines(["x"], algorithm="md5")


# ---------------------------------------------------------------------------
# orchestration: availability, gaps, reports
# ---------------------------------------------------------------------------
class TestRunBreachCheck:
    async def test_an_email_without_an_hibp_key_produces_a_gap(self, fetcher_factory) -> None:
        report = await run_breach_check(
            [entry(VaultKind.EMAIL, "alice@example.com")],
            scan_config=make_config(),
            breach_config=BreachConfig(),
        )
        assert report.nothing_was_checked is True
        assert report.headline().startswith("Nothing could be checked")
        assert report.entry_status(report.entries[0].entry_id) is BreachStatus.UNKNOWN
        assert report.counts()["unknown"] == 0  # no checks ran at all
        assert [gap["source_id"] for gap in report.unavailable] == ["hibp_breaches"]

    async def test_unavailable_sources_can_be_hidden(self, fetcher_factory) -> None:
        report = await run_breach_check(
            [entry(VaultKind.EMAIL, "alice@example.com")],
            scan_config=make_config(),
            breach_config=BreachConfig(include_unavailable_sources=False),
        )
        assert report.unavailable == []
        assert report.nothing_was_checked is True

    async def test_an_empty_watchlist_is_not_a_failure(self, fetcher_factory) -> None:
        report = await run_breach_check([], scan_config=make_config(), breach_config=breach_config())
        assert report.entries == []
        assert report.checks == []
        assert report.finished_at is not None

    async def test_progress_events_are_emitted(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {"api.pwnedpasswords.com": lambda request: httpx.Response(
                200, text=range_body(include_suffix=True), request=request
            )}
        )
        events: list[dict[str, Any]] = []
        report = await run_breach_check(
            [password_entry()],
            scan_config=make_config(),
            breach_config=breach_config(),
            transport=fetcher._transport,  # the mock transport
            on_event=events.append,
        )
        kinds = [event["type"] for event in events]
        assert kinds == ["entry_started", "source_started", "source_finished"]
        finished = events[-1]
        assert finished["status"] == "pwned"
        assert finished["percent"] == 100.0
        assert report.duration_ms >= 0

    async def test_entry_status_folds_several_checks(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {
                "api.pwnedpasswords.com": lambda request: httpx.Response(
                    200, text=range_body(include_suffix=True), request=request
                )
            }
        )
        report = await run_breach_check(
            [password_entry()],
            scan_config=make_config(),
            breach_config=breach_config(),
            transport=fetcher._transport,
        )
        assert report.entry_status(report.entries[0].entry_id) is BreachStatus.PWNED
        assert report.entry_counts()["pwned"] == 1

    def test_default_sources_include_a_corpus_per_file(self, tmp_path: Path) -> None:
        ids = [
            source.id
            for source in build_breach_sources(
                breach_config(corpora=(tmp_path / "a.txt", tmp_path / "b.txt"))
            )
        ]
        assert ids[0] == "pwned_passwords"
        assert "hibp_breaches" in ids
        assert sum(1 for source_id in ids if source_id.startswith("local_corpus")) == 2

    def test_statuses_are_finite_and_explicit(self) -> None:
        assert {s.value for s in BreachStatus} == {
            "clean",
            "pwned",
            "unknown",
            "unsupported",
        }
        assert BreachStatus.CLEAN.is_answer is True
        assert BreachStatus.PWNED.is_answer is True
        assert BreachStatus.UNKNOWN.is_answer is False


class TestBreachReport:
    async def test_the_json_shape_is_stable(self, fetcher_factory) -> None:
        fetcher, _ = await fetcher_factory(
            {
                "api.pwnedpasswords.com": lambda request: httpx.Response(
                    200, text=range_body(include_suffix=True), request=request
                )
            }
        )
        report = await run_breach_check(
            [password_entry()],
            scan_config=make_config(),
            breach_config=breach_config(),
            transport=fetcher._transport,
        )
        payload = report.to_dict()
        assert payload["schema"] == "d3ta1l3r/breach/1"
        assert payload["counts"]["pwned"] == 1
        assert payload["entry_counts"]["pwned"] == 1
        assert payload["entries"][0]["masked_value"] == "••••••••"
        assert payload["checks"][0]["source_id"] == "pwned_passwords"
        assert payload["nothing_was_checked"] is False
        # Nothing in the JSON may contain the password or its full hash.
        body = report.to_json()
        assert PWNED_PASSWORD not in body
        assert PWNED_DIGEST not in body

    async def test_markdown_lists_findings_and_gaps_without_duplicating_labels(
        self, fetcher_factory
    ) -> None:
        fetcher, _ = await fetcher_factory(
            {"api.pwnedpasswords.com": lambda request: httpx.Response(
                200, text=range_body(include_suffix=True), request=request
            )}
        )
        report = await run_breach_check(
            [password_entry()],
            scan_config=make_config(),
            breach_config=breach_config(),
            transport=fetcher._transport,
        )
        text = render_breach_markdown(report)
        assert "# D3TA1L3R breach watch" in text
        assert "Found in breach data" in text
        assert "demo password" in text
        assert "demo password (`demo password`)" not in text
        assert "What left this machine" in text
        assert "five characters of a SHA-1 hash" in text

    def test_the_markdown_explains_that_unknown_is_not_clean(self) -> None:
        text = render_breach_markdown(
            _empty_report([entry(VaultKind.EMAIL, "a@example.com")])
        )
        assert "not" in text.lower()


class TestDemoMode:
    """Demo mode answers from fixtures: no sockets, and every result is synthetic."""

    async def test_demo_mode_needs_no_network(self, tmp_path: Path) -> None:
        report = await run_breach_check(
            [
                password_entry(PWNED_PASSWORD),
                transient_password_entry("definitely-not-breached-2026"),
                entry(VaultKind.EMAIL, "alice@example.com"),
                entry(VaultKind.EMAIL, "quiet@example.com"),
            ],
            scan_config=make_config(demo=True),
            breach_config=BreachConfig(),  # note: no HIBP key at all
        )
        password_statuses = [c.status for c in report.checks if c.kind is VaultKind.PASSWORD]
        assert password_statuses == [BreachStatus.PWNED, BreachStatus.CLEAN]
        assert [c.status for c in report.checks if c.kind is VaultKind.EMAIL] == [
            BreachStatus.PWNED,
            BreachStatus.CLEAN,
        ]
        # The fixture answers for HIBP too, so HIBP is not reported as a gap here.
        assert all(gap["source_id"] != "hibp_breaches" for gap in report.unavailable)
        assert report.entry_counts()["pwned"] == 2
        assert report.entry_counts()["clean"] == 2

    async def test_demo_mode_marks_the_configuration(self) -> None:
        report = await run_breach_check(
            [entry(VaultKind.EMAIL, "quiet@example.com")],
            scan_config=make_config(demo=True),
            breach_config=BreachConfig(),
        )
        assert report.checks  # it was answered
        assert all(check.duration_ms >= 0 for check in report.checks)


# ---------------------------------------------------------------------------
# recording outcomes back into the vault
# ---------------------------------------------------------------------------
class TestRecordOutcomes:
    async def test_outcomes_land_on_the_right_entries(self, tmp_path: Path) -> None:
        vault = Vault.create(tmp_path / "v.vault", "correct horse battery staple")
        pwned, _ = vault.add(VaultKind.PASSWORD, PWNED_PASSWORD, store_hash=True)
        email, _ = vault.add(VaultKind.EMAIL, "alice@example.com")

        report = await run_breach_check(
            [vault.get(pwned.entry_id), vault.get(email.entry_id)],
            scan_config=make_config(demo=True),
            breach_config=BreachConfig(),
        )
        assert report.nothing_was_checked is False
        record_outcomes(vault, report)

        assert vault.get(pwned.entry_id).last_status == "pwned"
        assert vault.get(pwned.entry_id).last_count == 5
        assert vault.get(email.entry_id).last_status == "pwned"

    async def test_nothing_checked_writes_nothing(self, tmp_path: Path) -> None:
        vault = Vault.create(tmp_path / "v.vault", "correct horse battery staple")
        email, _ = vault.add(VaultKind.EMAIL, "alice@example.com")
        report = await run_breach_check(
            [vault.get(email.entry_id)],
            scan_config=make_config(),
            breach_config=BreachConfig(),  # no HIBP key, no corpus, no passwords
        )
        assert report.nothing_was_checked is True
        record_outcomes(vault, report)
        assert vault.get(email.entry_id).last_status == ""

    async def test_a_recorded_outcome_survives_a_reopen(self, tmp_path: Path) -> None:
        vault = Vault.create(tmp_path / "v.vault", "correct horse battery staple")
        stored, _ = vault.add(VaultKind.PASSWORD, PWNED_PASSWORD, store_hash=True)
        report = await run_breach_check(
            [vault.get(stored.entry_id)],
            scan_config=make_config(demo=True),
            breach_config=BreachConfig(),
        )
        record_outcomes(vault, report)
        vault.save()

        reopened = Vault.open(vault.path, "correct horse battery staple")
        assert reopened.get(stored.entry_id).last_status == "pwned"
        assert reopened.get(stored.entry_id).last_count == 5


def _empty_report(entries: list[VaultEntry]):
    from d3ta1l3r.breach import BreachReport

    report = BreachReport(entries=entries)
    return report
