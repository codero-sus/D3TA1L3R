"""Identifier validation and the SSRF guard — the tool's safety boundary."""

from __future__ import annotations

import pytest

from d3ta1l3r.core.security import (
    assert_public_url,
    is_public_host,
    mask_email,
    mask_phone,
    normalise_phone,
    redact,
    registrable_domain,
    render_template,
    validate_category,
    validate_domain,
    validate_email,
    validate_location,
    validate_name,
    validate_phone,
    validate_source_id,
    validate_template,
    validate_username,
)
from d3ta1l3r.errors import ForbiddenTargetError, UsageError


class TestUsernameValidation:
    @pytest.mark.parametrize("raw,expected", [
        ("alice", "alice"),
        ("@alice", "alice"),
        ("  alice  ", "alice"),
        ("Al1ce_Dev", "Al1ce_Dev"),
        ("a.b-c_d", "a.b-c_d"),
        ("ab", "ab"),
    ])
    def test_accepts_real_handles(self, raw: str, expected: str) -> None:
        assert validate_username(raw) == expected

    @pytest.mark.parametrize("raw", [
        "", "   ", "a b", "a/b", "a?b", "a#b", "a\\b", "-lead", ".lead", "trail.",
        "double..dot", "a" * 40, "alice@example.com", "javascript:alert(1)", "a%d",
    ])
    def test_rejects_anything_that_is_not_a_bare_handle(self, raw: str) -> None:
        with pytest.raises(UsageError):
            validate_username(raw)


class TestOtherIdentifiers:
    def test_email_is_lowercased_and_validated(self) -> None:
        assert validate_email("  Me@Example.COM ") == "me@example.com"

    @pytest.mark.parametrize("raw", ["", "no-at-sign", "a@b", "a@@b.com", "a b@c.com", "x" * 250 + "@y.com"])
    def test_email_rejects_nonsense(self, raw: str) -> None:
        with pytest.raises(UsageError):
            validate_email(raw)

    def test_masked_emails_leak_nothing_useful(self) -> None:
        assert mask_email("myname@example.com") == "my***@example.com"
        assert mask_email("ab@example.com") == "***@example.com"

    def test_name_rules(self) -> None:
        assert validate_name("  Alice   Doe ") == "Alice Doe"
        assert validate_name("Ada Lovelace") == "Ada Lovelace"
        for bad in ["", "A", "Alice123", "Alice <script>", "a" * 90]:
            with pytest.raises(UsageError):
                validate_name(bad)

    def test_location_rules(self) -> None:
        assert validate_location("Delhi, IN") == "Delhi, IN"
        with pytest.raises(UsageError):
            validate_location("D")

    def test_domain_normalises_pasted_urls(self) -> None:
        assert validate_domain("https://Example.COM/path?x=1") == "example.com"
        assert validate_domain("example.com.") == "example.com"

    @pytest.mark.parametrize("raw", ["", "localhost", "127.0.0.1", "1.2.3.4", "-bad.com", "a..b.com", "nodot"])
    def test_domain_rejects_non_domains(self, raw: str) -> None:
        with pytest.raises(UsageError):
            validate_domain(raw)

    def test_registrable_domain_handles_two_label_suffixes(self) -> None:
        assert registrable_domain("api.github.com") == "github.com"
        assert registrable_domain("www.example.co.uk") == "example.co.uk"
        assert registrable_domain("example.com") == "example.com"


class TestTemplateValidation:
    def test_renders_and_percent_encodes(self) -> None:
        assert validate_template("https://x.com/{username}", "username")
        assert render_template("https://x.com/{username}", username="a b/c") == "https://x.com/a%20b%2Fc"

    @pytest.mark.parametrize("template,identifier", [
        ("https://x.com/{nickname}", "username"),      # unknown placeholder
        ("https://x.com/static", "username"),          # no placeholder
        ("https://x.com/{username}/{email}", "email"),  # two placeholder kinds
        ("https://x.com/{email}", "username"),          # wrong identifier for the flag
        ("https://x.com/{username", "username"),        # unbalanced brace
    ])
    def test_rejects_bad_templates(self, template: str, identifier: str) -> None:
        with pytest.raises(UsageError):
            validate_template(template, identifier)

    def test_no_way_to_smuggle_a_list_of_people(self) -> None:
        """Templates take one scalar per identifier: no loops, no multi-target queries."""
        rendered = render_template("https://x.com/search?q={name}", name="a,b c&d=e")
        assert rendered == "https://x.com/search?q=a%2Cb%20c%26d%3De"


class TestSsrfGuard:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/",
        "http://localhost:8000/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://0.0.0.0/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "http://user:pass@example.com/",
        "http://internal-host/",
        "http://something.local/",
    ])
    def test_blocks_private_and_non_http_targets(self, url: str) -> None:
        with pytest.raises(ForbiddenTargetError):
            assert_public_url(url, resolve=False)

    @pytest.mark.parametrize("url", [
        "https://api.github.com/users/alice",
        "https://example.com/robots.txt",
    ])
    def test_allows_ordinary_public_urls(self, url: str) -> None:
        assert assert_public_url(url, resolve=False) == url

    def test_public_host_classification(self) -> None:
        assert is_public_host("example.com") is True
        assert is_public_host("api.github.com") is True
        assert is_public_host("localhost") is False
        assert is_public_host("127.0.0.1") is False
        assert is_public_host("10.1.2.3") is False
        assert is_public_host("myhost") is False  # single label = internal
        assert is_public_host("server.local") is False
        assert is_public_host("") is False

    def test_handler_subdomains_are_contactable(self) -> None:
        """Subdomain-based profiles exist (and may contain underscores)."""
        assert is_public_host("alice.tumblr.com", resolve=False) is True
        assert is_public_host("demo_user.tumblr.com", resolve=False) is True
        assert is_public_host("demo-user.itch.io", resolve=False) is True

    def test_dns_resolution_check_is_opt_in(self) -> None:
        # 'resolve=True' must not accept a host that cannot resolve publicly.
        with pytest.raises(ForbiddenTargetError):
            assert_public_url("https://this-host-does-not-exist-8f3a9b.invalid/", resolve=True)


class TestValidationRejectsWrongTypes:
    """A non-string identifier must be a usage error, not a TypeError.

    Identifiers reach these functions from JSON bodies and from argparse, where
    a list or a number is entirely possible. Crashing with a TypeError there
    would surface as a traceback instead of a message.
    """

    @pytest.mark.parametrize("bad", [None, 123, ["alice"], {"a": 1}, 4.5])
    def test_username(self, bad: object) -> None:
        with pytest.raises(UsageError):
            validate_username(bad)

    @pytest.mark.parametrize("bad", [None, 123, ["a@b.com"]])
    def test_email(self, bad: object) -> None:
        with pytest.raises(UsageError):
            validate_email(bad)

    @pytest.mark.parametrize("bad", [None, 123, ["+14155550123"]])
    def test_phone(self, bad: object) -> None:
        with pytest.raises(UsageError):
            validate_phone(bad)


class TestSourceIdAndCategoryValidation:
    def test_a_slug_is_normalised(self) -> None:
        assert validate_source_id("  GitHub_User ") == "github_user"
        assert validate_category("  Social ") == "social"

    @pytest.mark.parametrize("bad", ["", "has space", "Upper!", "a/b", "../etc", "-lead", "trail-"])
    def test_anything_that_is_not_a_slug_is_rejected(self, bad: str) -> None:
        with pytest.raises(UsageError):
            validate_source_id(bad)
        with pytest.raises(UsageError):
            validate_category(bad)


class TestRenderTemplate:
    def test_an_unknown_placeholder_is_an_error_not_a_crash(self) -> None:
        with pytest.raises(UsageError):
            render_template("{nope}", username="alice")

    def test_an_unbalanced_brace_is_rejected(self) -> None:
        with pytest.raises(UsageError):
            validate_template("{username", "alice")


class TestPhoneNumbers:
    def test_normalise_strips_separators(self) -> None:
        assert normalise_phone("+1 (415) 555-0123") == "+14155550123"
        assert normalise_phone("+44 20 7946 0958") == "+442079460958"

    def test_a_number_longer_than_e164_allows_is_rejected(self) -> None:
        with pytest.raises(UsageError):
            validate_phone("+" + "1" * 20)

    def test_masking_leaves_at_most_the_country_code(self) -> None:
        masked = mask_phone("+14155550123")
        assert "0123" not in masked, "the subscriber number must not survive masking"
        assert masked.startswith("+")

    def test_a_value_too_short_to_mask_is_fully_hidden(self) -> None:
        assert mask_phone("1") == "***"
        assert mask_phone("") == "***"


class TestRedaction:
    """redact() is for messages that may be logged: it masks email-shaped text.

    It is deliberately not a general masker — a value that is not an email is
    left alone rather than shredded, because a log line reading "su***" is
    useless for debugging and a secret is usually not what is being passed in.
    """

    def test_an_empty_value_stays_empty(self) -> None:
        assert redact("") == ""

    def test_the_local_part_of_an_email_is_masked(self) -> None:
        redacted = redact("alice@example.com")
        assert "alice" not in redacted
        assert "example.com" in redacted, "the domain is what makes a log line useful"

    def test_a_non_email_value_is_left_alone(self) -> None:
        assert redact("supersecretvalue") == "supersecretvalue"

    def test_every_email_in_a_message_is_masked(self) -> None:
        redacted = redact("failed for alice@example.com and bob@example.org")
        assert "alice@" not in redacted
        assert "bob@" not in redacted


class TestPublicUrlGuard:
    def test_a_url_with_no_host_is_refused(self) -> None:
        with pytest.raises(ForbiddenTargetError):
            assert_public_url("http:///path")

    def test_a_non_http_scheme_is_refused(self) -> None:
        with pytest.raises(ForbiddenTargetError):
            assert_public_url("file:///etc/passwd")

    def test_an_ipv6_literal_is_classified(self) -> None:
        # loopback ::1 is not a public host
        assert is_public_host("::1") is False
