"""The shared helpers every API source parses with.

These are small and pure, and every one of the 40-odd API sources goes through
them, so a wrong answer here is a wrong answer everywhere. They are also where
parsing meets an untrusted network: a field can be a list, a dict, a scalar or
absent, and the endpoint can be an error page wearing a 200.
"""

from __future__ import annotations

import pytest

from d3ta1l3r.errors import SourceError
from d3ta1l3r.sources.api.base import (
    as_list,
    dig,
    first_present,
    iso_from_epoch,
    md5_hex,
    name_matches,
    name_tokens,
    quote,
    require_mapping,
    require_sequence,
    summarise,
    take,
)


class TestDig:
    """Read a nested field without letting a strange shape end the scan."""

    def test_it_walks_dicts_and_lists(self) -> None:
        assert dig({"a": {"b": [1, 2]}}, "a", "b", 1) == 2

    def test_numeric_strings_index_sequences(self) -> None:
        """APIs write {"0": {...}} about as often as they write a list."""
        assert dig({"a": {"b": [{"c": 3}]}}, "a", "b", "0", "c") == 3

    def test_a_missing_key_gives_the_default(self) -> None:
        assert dig({"a": 1}, "a", "missing", default="fallback") == "fallback"
        assert dig({"a": 1}, "nope", "deeper") is None

    def test_an_out_of_range_index_gives_the_default(self) -> None:
        assert dig({"a": [1, 2]}, "a", 9, default="x") == "x"
        assert dig({"a": [1, 2]}, "a", -9, default="x") == "x"

    def test_it_never_raises_on_a_hostile_shape(self) -> None:
        """A field that turned into a string must not crash the parser."""
        assert dig({"a": "now-a-string"}, "a", "b", "c") is None
        assert dig(None, "a") is None
        assert dig([1, 2], "a", default="d") == "d"


class TestAsList:
    @pytest.mark.parametrize("value,expected", [
        (None, []),
        ("single", ["single"]),
        (["a", "b"], ["a", "b"]),
        (("a",), ["a"]),
        (0, [0]),
    ])
    def test_coercion(self, value: object, expected: list) -> None:
        assert as_list(value) == expected

    def test_take_caps_and_tolerates_a_negative_limit(self) -> None:
        assert take([1, 2, 3, 4], 2) == [1, 2]
        assert take([1, 2], 0) == []
        assert take([1, 2], -5) == []
        assert take("scalar", 3) == ["scalar"]


class TestSummarise:
    def test_none_becomes_an_empty_string(self) -> None:
        assert summarise(None) == ""

    def test_dicts_are_reduced_to_their_label(self) -> None:
        text = summarise([{"name": "Example University"}, {"value": "https://x.example"}])
        assert "Example University" in text
        assert "https://x.example" in text

    def test_a_dict_with_no_usable_label_is_not_dropped_silently(self) -> None:
        """An ellipsis says "something was here"; an empty string would not."""
        assert summarise([{"nothing": "useful"}]) == "…"

    def test_whitespace_is_collapsed(self) -> None:
        assert summarise("  lots\n\n  of   space ") == "lots of space"

    def test_the_result_is_capped(self) -> None:
        assert len(summarise("x" * 500, limit=20)) == 20


class TestRequireShape:
    def test_a_sequence_must_be_a_list(self) -> None:
        with pytest.raises(SourceError, match=r"expected a JSON array"):
            require_sequence({"error": "not found"}, "the endpoint")

    def test_the_error_names_the_endpoint(self) -> None:
        """'the endpoint moved' is actionable; 'TypeError' is not."""
        with pytest.raises(SourceError, match=r"the endpoint"):
            require_sequence("nope", "the endpoint")

    def test_a_mapping_must_be_a_dict(self) -> None:
        with pytest.raises(SourceError, match=r"expected a JSON object"):
            require_mapping([1, 2], "the endpoint")

    def test_valid_shapes_pass_through(self) -> None:
        assert require_sequence([1], "x") == [1]
        assert require_mapping({"a": 1}, "x") == {"a": 1}


class TestNameMatching:
    """Name lookups must not present a same-name stranger as the user.

    Personal names are not unique, so this is the single function standing
    between a name-based source and a false claim about a real person.
    """

    def test_an_exact_name_matches(self) -> None:
        assert name_matches("Alice Doe", "Alice Doe") is True

    def test_reordered_tokens_still_match(self) -> None:
        assert name_matches("Doe, Alice", "Alice Doe") is True

    def test_a_different_person_does_not_match(self) -> None:
        assert name_matches("Bob Doe", "Alice Doe") is False

    def test_a_subset_of_the_wanted_name_does_not_match(self) -> None:
        """'Alice' is not 'Alice Doe' — half a name is not a person."""
        assert name_matches("Alice", "Alice Doe") is False

    def test_a_mononym_matches_a_mononym(self) -> None:
        assert name_matches("Madonna", "Madonna") is True

    def test_a_superset_candidate_matches_by_design(self) -> None:
        """Searching "Madonna" does surface a record called "Madonna University".

        These are pinned LOW with a homonym warning and listed for a human, so
        the useful move is to show the record, not to guess that it is irrelevant.
        """
        assert name_matches("Madonna University", "Madonna") is True

    def test_a_disjoint_name_never_matches_even_partially(self) -> None:
        assert name_matches("Bob Smith", "Alice", allow_partial=True) is False

    def test_partial_allows_a_single_token_overlap_when_asked(self) -> None:
        assert name_matches("Alice", "Alice", allow_partial=True) is True

    def test_an_empty_candidate_never_matches(self) -> None:
        assert name_matches(None, "Alice Doe") is False
        assert name_matches("", "Alice Doe") is False
        assert name_matches("   ", "Alice Doe") is False

    def test_single_letters_are_not_name_tokens(self) -> None:
        assert name_tokens("A B Doe") == ["doe"]

    def test_hyphens_and_apostrophes_stay_inside_a_token(self) -> None:
        """Splitting "Alice-Jane" would invent two people from one name."""
        assert name_tokens("Alice-Jane O'Brien") == ["alice-jane", "o'brien"]


class TestSmallHelpers:
    def test_first_present_returns_the_first_usable_key(self) -> None:
        assert first_present({"a": None, "b": "", "c": "here"}, "a", "b", "c") == "here"
        assert first_present({"a": None}, "a", "missing") is None

    def test_quote_encodes_reserved_characters(self) -> None:
        assert quote("a?b&c") == "a%3Fb%26c"
        assert quote("plain") == "plain"

    def test_md5_hex_is_stable_and_lowercase(self) -> None:
        assert md5_hex("alice@example.com") == md5_hex("alice@example.com")
        assert md5_hex("alice@example.com") != md5_hex("bob@example.com")
        assert md5_hex("a").islower()
        assert len(md5_hex("anything")) == 32

    @pytest.mark.parametrize("raw", ["not-a-number", "", None, "abc"])
    def test_iso_from_epoch_rejects_nonsense(self, raw: object) -> None:
        assert iso_from_epoch(raw) is None

    def test_iso_from_epoch_reads_seconds_and_milliseconds(self) -> None:
        assert iso_from_epoch(1_700_000_000) is not None
        assert iso_from_epoch(1_700_000_000_000) is not None
        assert iso_from_epoch("1700000000") is not None
