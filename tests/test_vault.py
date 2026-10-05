"""The encrypted watchlist vault.

Everything here runs offline. The point of the vault is that it holds
identifiers that are worth something to an attacker, so the tests care as much
about what the file *does not* contain as about what the API returns.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from d3ta1l3r import vault as vault_mod
from d3ta1l3r.errors import UsageError
from d3ta1l3r.vault import (
    FORMAT,
    MIN_PASSPHRASE_LENGTH,
    Vault,
    VaultEntry,
    VaultError,
    VaultKind,
    default_vault_path,
    file_permissions,
    is_locked_down,
    normalise_value,
    passphrase_from_file,
)

PASSPHRASE = "correct horse battery staple"
NEW_PASSPHRASE = "a different long passphrase"
SECRETS = ("hunter2", "alice@example.com", "alice", "+919810000010", "9810000010")


@pytest.fixture()
def vault(tmp_path: Path) -> Vault:
    return Vault.create(tmp_path / "watchlist.vault", PASSPHRASE)


def _raw(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# creation and file handling
# ---------------------------------------------------------------------------
class TestCreation:
    def test_create_writes_a_locked_down_encrypted_file(self, tmp_path: Path) -> None:
        path = tmp_path / "watchlist.vault"
        vault = Vault.create(path, PASSPHRASE)
        assert path.is_file()
        assert len(vault) == 0
        payload = json.loads(_raw(path))
        assert payload["format"] == FORMAT
        assert payload["cipher"] == "fernet"
        assert payload["kdf"]["name"] == "scrypt"
        assert "payload" in payload and isinstance(payload["payload"], str)
        assert payload["entry_count"] == 0

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_permissions_are_owner_only(self, tmp_path: Path) -> None:
        path = tmp_path / "watchlist.vault"
        Vault.create(path, PASSPHRASE)
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600
        assert file_permissions(path) == "0o600"
        assert is_locked_down(path) is True

    def test_create_refuses_to_clobber_an_existing_vault(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="already exists"):
            Vault.create(vault.path, PASSPHRASE)

    def test_create_can_overwrite_when_asked(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "old@example.com")
        vault.save()
        fresh = Vault.create(vault.path, PASSPHRASE, overwrite=True)
        assert len(fresh) == 0

    @pytest.mark.parametrize("bad", ["", "short", "12345678901"])
    def test_short_passphrases_are_refused(self, tmp_path: Path, bad: str) -> None:
        with pytest.raises(UsageError, match="passphrase"):
            Vault.create(tmp_path / "v.vault", bad)

    def test_the_length_floor_is_what_the_constant_says(self, tmp_path: Path) -> None:
        assert MIN_PASSPHRASE_LENGTH == 12
        with pytest.raises(UsageError, match=str(MIN_PASSPHRASE_LENGTH)):
            Vault.create(tmp_path / "v.vault", "x" * (MIN_PASSPHRASE_LENGTH - 1))

    def test_default_path_is_env_or_local(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("D3TA1L3R_VAULT", raising=False)
        assert default_vault_path() == Path("vault") / "watchlist.vault"
        monkeypatch.setenv("D3TA1L3R_VAULT", str(tmp_path / "custom.vault"))
        assert default_vault_path() == tmp_path / "custom.vault"


# ---------------------------------------------------------------------------
# round trip, masking, and what never reaches the disk
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_all_kinds_survive_a_save_and_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "v.vault"
        vault = Vault.create(path, PASSPHRASE)
        added = {
            VaultKind.EMAIL: "Alice@Example.com",
            VaultKind.PHONE: "+91 98100 00010",
            VaultKind.USERNAME: "Alice_dev",
            VaultKind.DOMAIN: "Example.com",
            VaultKind.PASSWORD: "hunter2",
        }
        for kind, value in added.items():
            vault.add(kind, value, store_hash=True)
        vault.save()

        reopened = Vault.open(path, PASSPHRASE)
        assert sorted(e.kind.value for e in reopened.entries) == sorted(k.value for k in added)
        assert {e.kind: e.value for e in reopened.entries}[VaultKind.EMAIL] == "alice@example.com"
        assert {e.kind: e.value for e in reopened.entries}[VaultKind.PHONE] == "+919810000010"

    def test_the_file_never_contains_the_identifiers(self, vault: Vault, tmp_path: Path) -> None:
        for kind, value in (
            (VaultKind.EMAIL, "alice@example.com"),
            (VaultKind.PHONE, "+919810000010"),
            (VaultKind.USERNAME, "alice_dev"),
            (VaultKind.DOMAIN, "example.com"),
        ):
            vault.add(kind, value)
        password, _ = vault.add(VaultKind.PASSWORD, "hunter2", store_hash=True)
        vault.save()

        raw = _raw(vault.path)
        for secret in SECRETS:
            assert secret not in raw, secret
        assert "alice_dev" not in raw
        # The SHA-1 verifier is real (it is what makes an automatic re-check
        # possible) but it lives *inside* the ciphertext, so the file on disk
        # still gives an attacker nothing to test guesses against.
        assert password.password_sha1 != ""
        assert password.password_sha1 not in raw
        assert password.password_sha1 in json.dumps(vault.entries and [password.to_dict()])

    def test_passwords_are_never_stored(self, vault: Vault) -> None:
        entry, created = vault.add(VaultKind.PASSWORD, "correct-horse-battery")
        assert created and entry.value == ""
        assert entry.password_length == len("correct-horse-battery")
        assert entry.password_sha1 == ""  # no verifier unless asked for
        assert entry.recheckable is False

    def test_store_hash_keeps_only_a_verifier(self, vault: Vault) -> None:
        entry, _ = vault.add(VaultKind.PASSWORD, "hunter2", store_hash=True)
        assert entry.password_sha1 == "f3bbbd66a63d4bf1747940578ec3d0103530e21d"
        assert entry.recheckable is True
        assert "hunter2" not in _raw(vault.path)

    def test_masked_values_are_safe_to_display(self, vault: Vault) -> None:
        email, _ = vault.add(VaultKind.EMAIL, "alice@example.com")
        phone, _ = vault.add(VaultKind.PHONE, "+91 98100 00010")
        password, _ = vault.add(VaultKind.PASSWORD, "hunter2")
        assert email.masked == "al***@example.com"
        assert phone.masked == "+91******10"
        assert password.masked == "••••••••"
        for entry in (email, phone, password):
            assert "hunter2" not in entry.masked

    def test_labels_and_notes_round_trip(self, vault: Vault) -> None:
        entry, _ = vault.add(
            VaultKind.EMAIL, "work@example.com", label="work", notes="old job"
        )
        vault.save()
        again = Vault.open(vault.path, PASSPHRASE).get(entry.entry_id)
        assert again is not None
        assert again.label == "work"
        assert again.notes == "old job"
        assert again.display == "work"


# ---------------------------------------------------------------------------
# dedupe, identity, and removal
# ---------------------------------------------------------------------------
class TestIdentity:
    def test_adding_the_same_value_twice_is_not_a_duplicate(self, vault: Vault) -> None:
        first, created = vault.add(VaultKind.EMAIL, "alice@example.com")
        second, created_again = vault.add(VaultKind.EMAIL, "ALICE@example.com")
        assert created is True and created_again is False
        assert first.entry_id == second.entry_id
        assert len(vault) == 1

    def test_the_same_text_in_different_kinds_is_two_entries(self, vault: Vault) -> None:
        vault.add(VaultKind.USERNAME, "example")
        vault.add(VaultKind.DOMAIN, "example.com")
        assert len(vault) == 2

    def test_fingerprints_are_stable_across_passphrase_rotation(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "alice@example.com")
        before = vault.fingerprint(VaultKind.EMAIL, "alice@example.com")
        vault.rotate(NEW_PASSPHRASE)
        reopened = Vault.open(vault.path, NEW_PASSPHRASE)
        assert reopened.fingerprint(VaultKind.EMAIL, "alice@example.com") == before

    def test_fingerprints_are_keyed_not_hashes(self, tmp_path: Path) -> None:
        one = Vault.create(tmp_path / "a.vault", PASSPHRASE)
        two = Vault.create(tmp_path / "b.vault", PASSPHRASE)
        assert one.fingerprint(VaultKind.EMAIL, "alice@example.com") != two.fingerprint(
            VaultKind.EMAIL, "alice@example.com"
        )

    def test_remove_reports_whether_anything_went(self, vault: Vault) -> None:
        entry, _ = vault.add(VaultKind.EMAIL, "alice@example.com")
        assert vault.remove(entry.entry_id) is True
        assert vault.remove(entry.entry_id) is False
        assert len(vault) == 0

    def test_record_check_only_touches_the_named_entry(self, vault: Vault) -> None:
        one, _ = vault.add(VaultKind.EMAIL, "a@example.com")
        two, _ = vault.add(VaultKind.EMAIL, "b@example.com")
        vault.record_check(one.entry_id, status="pwned", count=4)
        assert vault.get(one.entry_id).last_status == "pwned"
        assert vault.get(one.entry_id).last_count == 4
        assert vault.get(two.entry_id).last_status == ""
        assert vault.dirty is True


# ---------------------------------------------------------------------------
# unlocking, tampering and rotation
# ---------------------------------------------------------------------------
class TestUnlock:
    def test_wrong_passphrase_is_refused(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="wrong passphrase"):
            Vault.open(vault.path, "not the passphrase")

    def test_verify_passphrase_is_true_only_for_the_right_one(self, vault: Vault) -> None:
        assert vault.verify_passphrase(PASSPHRASE) is True
        assert vault.verify_passphrase(PASSPHRASE + "!") is False
        assert vault.verify_passphrase("") is False

    def test_a_modified_payload_is_detected(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "alice@example.com")
        vault.save()
        payload = json.loads(_raw(vault.path))
        payload["payload"] = payload["payload"][:-8] + "AAAAAAAA"
        vault.path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(VaultError, match=r"altered|wrong passphrase"):
            Vault.open(vault.path, PASSPHRASE)

    def test_a_missing_file_says_so(self, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="no vault"):
            Vault.open(tmp_path / "absent.vault", PASSPHRASE)

    def test_rotate_needs_the_new_passphrase_twice_when_confirmed(self, vault: Vault) -> None:
        with pytest.raises(UsageError, match="did not match"):
            vault.rotate(NEW_PASSPHRASE, confirm="something else")

    def test_rotate_locks_out_the_old_passphrase(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "alice@example.com")
        vault.rotate(NEW_PASSPHRASE)
        assert Vault.open(vault.path, NEW_PASSPHRASE) is not None
        with pytest.raises(VaultError):
            Vault.open(vault.path, PASSPHRASE)

    def test_rotate_keeps_every_entry(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "alice@example.com")
        vault.add(VaultKind.PASSWORD, "hunter2", store_hash=True)
        vault.rotate(NEW_PASSPHRASE)
        reopened = Vault.open(vault.path, NEW_PASSPHRASE)
        assert reopened.describe()["entries"] == 2
        assert reopened.describe()["recheckable"] == 2


# ---------------------------------------------------------------------------
# normalisation and validation (shared with the CLI)
# ---------------------------------------------------------------------------
class TestNormalisation:
    def test_emails_are_lowercased_and_validated(self, vault: Vault) -> None:
        entry, _ = vault.add(VaultKind.EMAIL, "  Alice@Example.COM ")
        assert entry.value == "alice@example.com"
        with pytest.raises(UsageError):
            vault.add(VaultKind.EMAIL, "not-an-email")

    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("+91 98100 00010", "+919810000010"),
            ("0091 98100 00010", "+919810000010"),
            ("(415) 555-0123", "4155550123"),
        ],
    )
    def test_phones_are_canonicalised(self, given: str, expected: str) -> None:
        assert normalise_value(VaultKind.PHONE, given) == expected

    def test_a_number_without_country_code_stays_local(self) -> None:
        """No leading + or 00, so the number is not presumed international."""
        assert normalise_value(VaultKind.PHONE, "5550123") == "5550123"

    def test_a_number_too_short_to_be_real_is_refused(self) -> None:
        with pytest.raises(UsageError, match="too short"):
            normalise_value(VaultKind.PHONE, "555012")

    def test_usernames_keep_their_case_but_are_checked(self) -> None:
        assert normalise_value(VaultKind.USERNAME, " Alice_Dev ") == "Alice_Dev"
        with pytest.raises(UsageError):
            normalise_value(VaultKind.USERNAME, "bad handle")

    def test_domains_are_lowercased(self) -> None:
        assert normalise_value(VaultKind.DOMAIN, "Example.COM") == "example.com"


# ---------------------------------------------------------------------------
# description and passphrase input
# ---------------------------------------------------------------------------
class TestDescribe:
    def test_describe_exposes_no_values(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "alice@example.com")
        vault.add(VaultKind.PHONE, "+91 98100 00010")
        vault.add(VaultKind.PASSWORD, "hunter2", store_hash=True)
        vault.add(VaultKind.PASSWORD, "a-much-longer-passphrase")
        info = vault.describe()
        assert info["format"] == FORMAT
        assert info["kdf"] == "scrypt"
        assert info["entries"] == 4
        assert info["by_kind"] == {"email": 1, "phone": 1, "password": 2}
        assert info["recheckable"] == 3
        assert "hunter2" not in json.dumps(info)

    def test_public_dict_is_masked_and_leaks_nothing(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "alice@example.com")
        vault.add(VaultKind.PHONE, "+91 98100 00010")
        vault.add(VaultKind.PASSWORD, "hunter2", store_hash=True)
        # ensure_ascii=False: json.dumps would otherwise escape the mask's bullets,
        # and this test is about what a human-facing renderer actually emits.
        body = json.dumps(
            [entry.public_dict() for entry in vault.entries], ensure_ascii=False
        )
        for secret in ("alice@example.com", "98100", "hunter2"):
            assert secret not in body, secret
        assert "al***@example.com" in body
        assert "••••••••" in body
        # The verifier is not part of the public view either.
        assert hashlib.sha1(b"hunter2").hexdigest() not in body

    def test_repr_names_the_file_but_not_the_contents(self, vault: Vault) -> None:
        vault.add(VaultKind.EMAIL, "alice@example.com")
        text = repr(vault)
        assert "alice@example.com" not in text
        assert "entries=1" in text


class TestPassphraseInput:
    def test_passphrase_file_reads_the_first_line(self, tmp_path: Path) -> None:
        secret = tmp_path / "pass.txt"
        secret.write_text(PASSPHRASE + "\nignored\n", encoding="utf-8")
        assert passphrase_from_file(secret) == PASSPHRASE

    def test_an_empty_passphrase_file_is_a_usage_error(self, tmp_path: Path) -> None:
        secret = tmp_path / "empty.txt"
        secret.write_text("", encoding="utf-8")
        with pytest.raises(UsageError, match="empty"):
            passphrase_from_file(secret)

    def test_a_missing_passphrase_file_is_a_usage_error(self, tmp_path: Path) -> None:
        with pytest.raises(UsageError, match="could not read"):
            passphrase_from_file(tmp_path / "nope.txt")

    def test_prompt_secret_uses_the_environment_when_not_a_tty(
        self, monkeypatch, capsys
    ) -> None:
        monkeypatch.setenv("D3TA1L3R_VAULT_PASSPHRASE", PASSPHRASE)
        monkeypatch.setattr(vault_mod.os, "isatty", lambda _fd: False)
        assert vault_mod.prompt_secret("passphrase") == PASSPHRASE

    def test_prompt_password_does_not_reuse_the_vault_passphrase(
        self, monkeypatch
    ) -> None:
        """A password to check must never come from the vault passphrase variable."""
        monkeypatch.setenv("D3TA1L3R_VAULT_PASSPHRASE", PASSPHRASE)
        monkeypatch.setattr(vault_mod.sys.stdin, "isatty", lambda: False)
        monkeypatch.setattr(vault_mod.sys, "stdin", _FakeStdin("hunter2\n"))
        assert vault_mod.prompt_password("password") == "hunter2"

    def test_prompt_password_needs_something_on_stdin(self, monkeypatch) -> None:
        monkeypatch.setattr(vault_mod.sys, "stdin", _FakeStdin(""))
        with pytest.raises(UsageError, match="stdin"):
            vault_mod.prompt_password("password")


class _FakeStdin:
    def __init__(self, text: str) -> None:
        self._text = text

    def isatty(self) -> bool:
        return False

    def readline(self) -> str:
        return self._text


class TestEntryHelpers:
    def test_entry_id_is_generated_when_missing(self) -> None:
        entry = VaultEntry(kind=VaultKind.EMAIL, value="a@example.com")
        assert entry.entry_id
        assert VaultEntry.from_dict(entry.to_dict()).entry_id == entry.entry_id

    def test_kind_labels_are_human_readable(self) -> None:
        assert VaultKind.EMAIL.label == "email address"
        assert VaultKind.USERNAME.is_identifier is True
        assert VaultKind.PASSWORD.is_identifier is False

    def test_dirty_flag_tracks_changes(self, vault: Vault) -> None:
        assert vault.dirty is False
        vault.add(VaultKind.EMAIL, "a@example.com")
        assert vault.dirty is True
        vault.save()
        assert vault.dirty is False
