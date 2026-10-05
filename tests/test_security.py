"""Identifier validation and the SSRF guard — the tool's safety boundary."""

from __future__ import annotations

import pytest

from d3ta1l3r.core.security import (
    assert_public_url,
    is_public_host,
    mask_email,
    registrable_domain,
    render_template,
    validate_domain,
    validate_email,
    validate_location,
    validate_name,
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
