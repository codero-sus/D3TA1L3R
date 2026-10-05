"""Encrypted local vault for the identifiers you want watched.

This is the only place D3TA1L3R ever stores a secret, and it stores as little as
it possibly can:

* **Plaintext passwords are never written, never logged, never returned.** A
  password you hand to ``vault add password`` is hashed in memory to derive an
  identity fingerprint, checked once against the k-anonymity password API, and
  then dropped. What lands on disk is an HMAC keyed with a random
  256-bit ``fingerprint_key`` that lives *inside* the encrypted payload — so the
  file on its own is not a crackable password list.
* **Emails, phone numbers, handles and domains** are stored inside the encrypted
  payload, because they are the whole point of a watchlist. They are masked
  everywhere they are displayed (CLI listings, the dashboard, logs).
* **Everything is encrypted with AES-128-CBC + HMAC-SHA256 (Fernet) under a key
  derived with scrypt** (n=32768, r=8, p=1) from your passphrase, with a fresh
  random salt per vault. Wrong passphrase or a tampered file fails closed: the
  MAC does not verify and nothing is decrypted.

Two deliberate properties:

1. **The fingerprint key is independent of the passphrase**, so rotating the
   passphrase does not invalidate the fingerprints that dedupe entries — the
   re-encryption keeps them stable.
2. **The only metadata in the clear** is the format version, the KDF parameters,
   the salt, timestamps and an entry count. No identifier ever appears outside
   the ciphertext; there is a test asserting the raw file bytes contain neither
   an email address nor a phone number.

Passwords and passphrases are read through :func:`d3ta1l3r.vault.prompt_secret`
(getpass) or a ``0600`` file, never from a command-line argument — argv is
visible to every process on the machine via ``/proc`` and lands in shell history.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .core.security import (
    mask_email,
    mask_phone,
    validate_domain,
    validate_email,
    validate_phone,
    validate_username,
)
from .errors import D3ta1l3rError, UsageError

__all__ = [
    "FORMAT",
    "MIN_PASSPHRASE_LENGTH",
    "Vault",
    "VaultEntry",
    "VaultError",
    "VaultKind",
    "default_vault_path",
    "file_permissions",
    "is_locked_down",
    "normalise_value",
    "passphrase_from_file",
    "prompt_password",
    "prompt_secret",
]

#: On-disk format identifier. Bump when the payload schema changes.
FORMAT = "d3ta1l3r/vault/1"

_CIPHER = "fernet"
_FINGERPRINT_KEY_BYTES = 32
_SALT_BYTES = 16

# scrypt parameters. 128 * n * r = 32 MiB of working memory and ~60-120 ms per
# derivation on a laptop: cheap enough for an interactive unlock, expensive
# enough to make an offline guessing attack on the file unpleasant.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 2**27

_ENV_PASSPHRASE = "D3TA1L3R_VAULT_PASSPHRASE"
_ENV_VAULT = "D3TA1L3R_VAULT"

#: Shortest passphrase accepted for a new or rotated vault.
MIN_PASSPHRASE_LENGTH = 12


class VaultError(D3ta1l3rError):
    """The vault could not be opened, written, or trusted."""


class VaultKind(str, Enum):
    """What a watched identifier is. Every kind maps to a validation rule."""

    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    DOMAIN = "domain"
    PASSWORD = "password"

    @property
    def is_identifier(self) -> bool:
        """True for kinds that can be looked up in breach data by value."""
        return self is not VaultKind.PASSWORD

    @property
    def label(self) -> str:
        return {
            "email": "email address",
            "phone": "phone number",
            "username": "handle",
            "domain": "domain",
            "password": "password",
        }[self.value]


def normalise_value(kind: VaultKind, value: str) -> str:
    """Validate and canonicalise an identifier for a given kind.

    Public because ``d3ta1l3r breach check`` must normalise a one-off value
    exactly the way a stored entry would have been normalised.
    """
    return _normalise(kind, value)


def _normalise(kind: VaultKind, value: str) -> str:
    """Validate and canonicalise a value so comparisons and dedupe are stable."""
    if not isinstance(value, str):
        raise UsageError(f"{kind.label} must be a string")
    raw = value.strip()
    if kind is VaultKind.EMAIL:
        return validate_email(raw)
    if kind is VaultKind.PHONE:
        return validate_phone(raw)
    if kind is VaultKind.USERNAME:
        return validate_username(raw)
    if kind is VaultKind.DOMAIN:
        return validate_domain(raw)
    if not raw:
        raise UsageError("password must not be empty")
    return raw


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _mask(kind: VaultKind, value: str) -> str:
    if kind is VaultKind.EMAIL:
        return mask_email(value)
    if kind is VaultKind.PHONE:
        return mask_phone(value)
    if kind is VaultKind.PASSWORD:
        return "••••••••"
    if kind is VaultKind.DOMAIN:
        return value if len(value) <= 24 else f"{value[:21]}…"
    return value if len(value) <= 3 else f"{value[0]}…{value[-1]}"


@dataclass(slots=True)
class VaultEntry:
    """One watched identifier. The password field never holds a password."""

    kind: VaultKind
    value: str = ""
    label: str = ""
    entry_id: str = ""
    added_at: str = ""
    fingerprint: str = ""
    password_length: int = 0
    """Length of a watched password — useful context, harmless on its own."""
    password_sha1: str = ""
    """Only present when added with ``store_hash=True``; it enables automatic
    re-checks. Empty means "check-once, keep no verifier" (the default)."""
    last_checked: str = ""
    last_status: str = ""
    last_count: int = -1
    notes: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.kind, str):  # tolerate dicts from older files
            self.kind = VaultKind(self.kind)
        if not self.entry_id:
            self.entry_id = secrets.token_hex(4)

    # -- presentation ----------------------------------------------------
    @property
    def masked(self) -> str:
        return _mask(self.kind, self.value)

    @property
    def display(self) -> str:
        return self.label or self.masked

    @property
    def recheckable(self) -> bool:
        """Can a later run re-check this without asking for the secret again?"""
        if self.kind is VaultKind.PASSWORD:
            return bool(self.password_sha1)
        return bool(self.value)

    # -- serialisation ---------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Serialise for the *encrypted payload* — this contains the raw value.

        Never hand this to a terminal, a template, a log or a JSON API. Use
        :meth:`public_dict` for anything a human or a browser can see.
        """
        return {
            "entry_id": self.entry_id,
            "kind": self.kind.value,
            "value": self.value,
            "label": self.label,
            "added_at": self.added_at,
            "fingerprint": self.fingerprint,
            "password_length": self.password_length,
            "password_sha1": self.password_sha1,
            "last_checked": self.last_checked,
            "last_status": self.last_status,
            "last_count": self.last_count,
            "notes": self.notes,
        }

    def public_dict(self) -> dict[str, Any]:
        """Serialise for display: masked value, outcome metadata, no secret.

        The password field never holds a password, and the SHA-1 verifier is
        deliberately left out: it is the one piece of an entry that lets someone
        who has it test guesses offline.
        """
        return {
            "entry_id": self.entry_id,
            "kind": self.kind.value,
            "kind_label": self.kind.label,
            "label": self.label,
            "masked_value": self.masked,
            "display": self.display,
            "recheckable": self.recheckable,
            "added_at": self.added_at,
            "last_checked": self.last_checked,
            "last_status": self.last_status,
            "last_count": self.last_count,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultEntry:
        known = set(cls.__slots__)  # type: ignore[attr-defined]
        payload = {k: v for k, v in data.items() if k in known}
        payload["kind"] = VaultKind(payload.get("kind", "email"))
        return cls(**payload)


class Vault:
    """An unlocked (or freshly created) encrypted watchlist.

    Instances are created through :meth:`create` or :meth:`open`; both return an
    unlocked vault. Nothing is written until :meth:`save`.
    """

    def __init__(
        self,
        path: Path,
        key: bytes,
        payload: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        self.path = Path(path)
        self._key = key  # passphrase-derived; encrypts the payload
        self._payload = payload
        self.metadata = metadata
        self.dirty = False

    # -- construction ----------------------------------------------------
    @classmethod
    def create(
        cls, path: Path | str, passphrase: str, *, overwrite: bool = False
    ) -> Vault:
        """Create a new empty vault. Refuses to clobber an existing file."""
        path = Path(path)
        _check_passphrase(passphrase, confirm=None)
        if path.exists() and not overwrite:
            raise VaultError(
                f"{path} already exists — refusing to overwrite a vault "
                "(use --force only if you are sure it is disposable)"
            )
        salt = os.urandom(_SALT_BYTES)
        key = _derive_key(passphrase, salt, _kdf_params())
        payload = {
            "entries": [],
            "fingerprint_key": base64.b64encode(os.urandom(_FINGERPRINT_KEY_BYTES)).decode(),
            "notes": "",
        }
        metadata = {
            "format": FORMAT,
            "created_at": _now(),
            "updated_at": _now(),
            "kdf": _kdf_params(salt),
            "cipher": _CIPHER,
            "entry_count": 0,
        }
        vault = cls(path, key, payload, metadata)
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path | str, passphrase: str) -> Vault:
        """Decrypt a vault. Raises :class:`VaultError` on a bad passphrase."""
        path = Path(path)
        raw = _read_file(path)
        metadata = _validate_header(raw, path)
        kdf = metadata["kdf"]
        try:
            salt = base64.b64decode(kdf["salt"], validate=True)
        except (KeyError, ValueError) as exc:
            raise VaultError(f"{path}: vault header is damaged (bad salt)") from exc
        key = _derive_key(passphrase, salt, kdf)
        payload = _decrypt(raw["payload"], key, path)
        if not isinstance(payload.get("fingerprint_key"), str):
            raise VaultError(f"{path}: vault payload is missing its fingerprint key")
        return cls(path, key, payload, metadata)

    def verify_passphrase(self, passphrase: str) -> bool:
        """Constant-cost-ish check used by the dashboard login."""
        try:
            rederived = _derive_key(passphrase, self._salt(), self.metadata["kdf"])
            return hmac.compare_digest(rederived, self._key)
        except Exception:  # pragma: no cover - defensive
            return False

    # -- entries ---------------------------------------------------------
    @property
    def entries(self) -> list[VaultEntry]:
        return [VaultEntry.from_dict(row) for row in self._payload.get("entries", [])]

    def get(self, entry_id: str) -> VaultEntry | None:
        for entry in self.entries:
            if entry.entry_id == entry_id:
                return entry
        return None

    def watchlist(self, kind: VaultKind | None = None) -> list[VaultEntry]:
        entries = self.entries
        if kind is not None:
            entries = [e for e in entries if e.kind is kind]
        return entries

    def add(
        self,
        kind: VaultKind,
        value: str,
        *,
        label: str = "",
        notes: str = "",
        store_hash: bool = False,
    ) -> tuple[VaultEntry, bool]:
        """Add an identifier. Returns ``(entry, created)``.

        For ``kind=PASSWORD`` the value is the password itself: it is validated,
        fingerprinted, and (only with ``store_hash``) reduced to a SHA-1 that can
        be re-checked later. It is never stored.
        """
        kind = VaultKind(kind)
        normalised = _normalise(kind, value)
        fingerprint = self.fingerprint(kind, normalised)

        for existing in self._payload.setdefault("entries", []):
            if existing.get("fingerprint") == fingerprint:
                # Same secret: refresh the human-facing fields, keep history.
                if label:
                    existing["label"] = label
                if notes:
                    existing["notes"] = notes
                self.dirty = True
                return VaultEntry.from_dict(existing), False

        entry = VaultEntry(
            kind=kind,
            value="" if kind is VaultKind.PASSWORD else normalised,
            label=label,
            added_at=_now(),
            fingerprint=fingerprint,
            notes=notes,
        )
        if kind is VaultKind.PASSWORD:
            entry.password_length = len(normalised)
            if store_hash:
                # SHA-1 is not chosen here: it is the identifier the k-anonymity
                # API is defined in terms of.
                entry.password_sha1 = hashlib.sha1(normalised.encode("utf-8")).hexdigest()
        else:
            entry.value = normalised
        self._payload["entries"].append(entry.to_dict())
        self.dirty = True
        return entry, True

    def remove(self, entry_id: str) -> bool:
        entries = self._payload.get("entries", [])
        remaining = [row for row in entries if row.get("entry_id") != entry_id]
        if len(remaining) == len(entries):
            return False
        self._payload["entries"] = remaining
        self.dirty = True
        return True

    def record_check(
        self, entry_id: str, *, status: str, count: int = -1, when: str | None = None
    ) -> None:
        """Remember the outcome of a breach check (metadata only)."""
        for row in self._payload.get("entries", []):
            if row.get("entry_id") == entry_id:
                row["last_checked"] = when or _now()
                row["last_status"] = status
                row["last_count"] = count
                self.dirty = True
                return

    # -- crypto helpers --------------------------------------------------
    def fingerprint(self, kind: VaultKind, value: str) -> str:
        """Keyed identity for a value — stable across passphrase rotation."""
        material = f"{kind.value}:{value}".encode()
        return hmac.new(self._fingerprint_key, material, hashlib.sha256).hexdigest()[:32]

    def derive_subkey(self, purpose: str, *, length: int = 32) -> bytes:
        """Purpose-separated subkey derived from the vault key (HKDF-style)."""
        return hmac.new(self._key, purpose.encode(), hashlib.sha256).digest()[:length]

    @property
    def _fingerprint_key(self) -> bytes:
        raw = self._payload.get("fingerprint_key", "")
        try:
            return base64.b64decode(raw, validate=True)
        except (ValueError, TypeError) as exc:  # pragma: no cover - corrupt payload
            raise VaultError(f"{self.path}: fingerprint key is not valid base64") from exc

    def _salt(self) -> bytes:
        return base64.b64decode(self.metadata["kdf"]["salt"], validate=True)

    # -- persistence -----------------------------------------------------
    def save(self) -> Path:
        """Atomically write the vault with ``0600`` permissions."""
        blob = _encrypt(self._payload, self._key)
        self.metadata["updated_at"] = _now()
        self.metadata["entry_count"] = len(self._payload.get("entries", []))
        document = {**self.metadata, "payload": blob}
        _atomic_write(self.path, json.dumps(document, indent=2) + "\n")
        self.dirty = False
        return self.path

    def rotate(self, new_passphrase: str, *, confirm: str | None = None) -> None:
        """Re-encrypt under a new passphrase (entries and fingerprints survive)."""
        _check_passphrase(new_passphrase, confirm=confirm)
        salt = os.urandom(_SALT_BYTES)
        self._key = _derive_key(new_passphrase, salt, _kdf_params())
        self.metadata["kdf"] = _kdf_params(salt)
        self.metadata["rotated_at"] = _now()
        self.save()

    # -- misc ------------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        """Non-secret summary, safe to log, print or render."""
        entries = self.entries
        by_kind: dict[str, int] = {}
        for entry in entries:
            by_kind[entry.kind.value] = by_kind.get(entry.kind.value, 0) + 1
        return {
            "path": str(self.path),
            "format": self.metadata.get("format", FORMAT),
            "created_at": self.metadata.get("created_at", ""),
            "updated_at": self.metadata.get("updated_at", ""),
            "entries": len(entries),
            "by_kind": by_kind,
            "recheckable": sum(1 for e in entries if e.recheckable),
            "kdf": self.metadata.get("kdf", {}).get("name", "scrypt"),
        }

    def __len__(self) -> int:
        return len(self._payload.get("entries", []))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Vault {self.path} entries={len(self)}>"


# ---------------------------------------------------------------------------
# key derivation and envelope
# ---------------------------------------------------------------------------
def _kdf_params(salt: bytes | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {
        "name": "scrypt",
        "n": _SCRYPT_N,
        "r": _SCRYPT_R,
        "p": _SCRYPT_P,
        "length": 32,
    }
    if salt is not None:
        params["salt"] = base64.b64encode(salt).decode()
    return params


def _derive_key(passphrase: str, salt: bytes, params: dict[str, Any]) -> bytes:
    """scrypt(passphrase, salt) → 32 bytes. Raises VaultError if unusable."""
    _require_cryptography()
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    n = int(params.get("n", _SCRYPT_N))
    r = int(params.get("r", _SCRYPT_R))
    p = int(params.get("p", _SCRYPT_P))
    length = int(params.get("length", 32))
    if n < 2 or n & (n - 1):
        raise VaultError(f"vault header declares an invalid scrypt cost: n={n}")
    # OpenSSL needs headroom above the algorithm's own 128*r*n requirement.
    try:
        try:
            kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p, maxmem=_SCRYPT_MAXMEM)
        except TypeError:
            # cryptography >= 50 removed the explicit memory cap; older releases
            # need it because their default (10 MiB) is below scrypt's own
            # 128 * n * r = 32 MiB requirement for these parameters.
            kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
        return kdf.derive(passphrase.encode("utf-8"))
    except VaultError:
        raise
    except Exception as exc:  # pragma: no cover - platform/OpenSSL limitation
        raise VaultError(f"could not derive a key from the passphrase: {exc}") from exc


def _fernet(key: bytes):  # type: ignore[no-untyped-def]
    _require_cryptography()
    from cryptography.fernet import Fernet

    return Fernet(base64.urlsafe_b64encode(key))


def _encrypt(payload: dict[str, Any], key: bytes) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _fernet(key).encrypt(blob).decode("ascii")


def _decrypt(blob: str, key: bytes, path: Path) -> dict[str, Any]:
    from cryptography.fernet import InvalidToken

    try:
        raw = _fernet(key).decrypt(blob.encode("ascii"))
    except InvalidToken as exc:
        raise VaultError(
            f"{path}: wrong passphrase, or the vault has been altered "
            "(the authentication tag did not verify). Nothing was decrypted."
        ) from exc
    except Exception as exc:  # pragma: no cover - malformed ciphertext
        raise VaultError(f"{path}: could not decrypt the vault payload: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - tamper/format change
        raise VaultError(f"{path}: decrypted payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise VaultError(f"{path}: decrypted payload is not an object")
    return payload


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise VaultError(
            "the vault needs the 'cryptography' package, which is part of a normal "
            "install: pip install cryptography (or reinstall d3ta1l3r)"
        ) from exc


# ---------------------------------------------------------------------------
# file handling
# ---------------------------------------------------------------------------
def _read_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise VaultError(
            f"no vault at {path} — create one with `d3ta1l3r vault init`"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VaultError(f"{path}: not a vault file ({exc})") from exc
    except OSError as exc:
        raise VaultError(f"{path}: could not read the vault ({exc})") from exc
    if not isinstance(raw, dict):
        raise VaultError(f"{path}: not a vault file (expected a JSON object)")
    return raw


def _validate_header(raw: dict[str, Any], path: Path) -> dict[str, Any]:
    fmt = raw.get("format")
    if fmt != FORMAT:
        raise VaultError(
            f"{path}: unsupported vault format {fmt!r} (this build writes {FORMAT!r})"
        )
    kdf = raw.get("kdf")
    if not isinstance(kdf, dict) or not kdf.get("salt"):
        raise VaultError(f"{path}: vault header is missing its KDF parameters")
    if kdf.get("name") != "scrypt":
        raise VaultError(f"{path}: unsupported key derivation {kdf.get('name')!r}")
    if not isinstance(raw.get("payload"), str) or not raw["payload"]:
        raise VaultError(f"{path}: vault has no payload")
    return {
        "format": fmt,
        "created_at": raw.get("created_at", ""),
        "updated_at": raw.get("updated_at", ""),
        "rotated_at": raw.get("rotated_at", ""),
        "kdf": kdf,
        "cipher": raw.get("cipher", _CIPHER),
        "entry_count": raw.get("entry_count", 0),
    }


def _atomic_write(path: Path, text: str) -> None:
    """Write via a temporary file in the same directory, then rename.

    Keeps the vault readable only by its owner (``0600``) and makes an
    interrupted write harmless: either the old file or the new one exists.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        raise VaultError(f"could not write {path}: {exc}") from exc
    finally:
        if tmp.exists():  # pragma: no cover - cleanup after a failed rename
            with contextlib.suppress(OSError):
                tmp.unlink()
    # An existing file may have had looser permissions than the new one.
    with contextlib.suppress(OSError):  # pragma: no cover - e.g. a filesystem without chmod
        os.chmod(path, 0o600)


def file_permissions(path: Path) -> str:
    """Octal permission string of a vault file, for the ``vault where`` report."""
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except OSError:  # pragma: no cover - unreadable path
        return ""


def is_locked_down(path: Path) -> bool:
    """True when a vault file is not group/world readable."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:  # pragma: no cover
        return False
    return not (mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH))


# ---------------------------------------------------------------------------
# passphrase handling
# ---------------------------------------------------------------------------
def _check_passphrase(passphrase: str, *, confirm: str | None) -> None:
    if not isinstance(passphrase, str) or not passphrase:
        raise UsageError("the vault passphrase must not be empty")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise UsageError(
            f"the vault passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters "
            "(it is the only thing protecting the identifiers in the vault)"
        )
    if confirm is not None and passphrase != confirm:
        raise UsageError("the passphrases did not match")


def prompt_secret(what: str = "Vault passphrase", *, confirm: bool = False) -> str:
    """Read a secret from the terminal, never from argv.

    Non-interactive callers should set ``D3TA1L3R_VAULT_PASSPHRASE`` (documented
    as a convenience for automation, with the caveat that it is visible to other
    processes owned by the same user) or pass ``--passphrase-file``.
    """
    import getpass

    if not os.isatty(0):  # pragma: no cover - interactive path
        from_env = os.environ.get(_ENV_PASSPHRASE)
        if not from_env:
            raise UsageError(
                "no terminal available: set D3TA1L3R_VAULT_PASSPHRASE or use "
                "--passphrase-file for non-interactive use"
            )
        return from_env
    first = getpass.getpass(f"{what}: ")
    if confirm:
        again = getpass.getpass(f"{what} (again): ")
        if first != again:
            raise UsageError("the passphrases did not match")
    return first


def prompt_password(what: str = "Password to check") -> str:
    """Read a password that is *not* the vault passphrase.

    An interactive terminal gets a hidden prompt; otherwise one line is read from
    stdin, so ``printf '%s' "$secret" | d3ta1l3r vault add --kind password``
    works. The value is deliberately never taken from argv or from an environment
    variable — in particular it is not ``D3TA1L3R_VAULT_PASSPHRASE``, which would
    mean comparing the passphrase that protects the vault against a breach corpus.
    """
    import getpass

    if sys.stdin.isatty():
        return getpass.getpass(f"{what}: ")
    value = sys.stdin.readline().rstrip("\r\n")
    if not value:
        raise UsageError(
            f"no terminal and nothing on stdin: pipe the {what.lower()} in, e.g. "
            "`printf '%s' \"$secret\" | d3ta1l3r vault add --kind password --store-hash`"
        )
    return value


def passphrase_from_file(path: Path | str) -> str:
    """Read a passphrase from the first line of a file (expected mode ``0600``)."""
    file = Path(path)
    try:
        text = file.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"could not read the passphrase file {file}: {exc}") from exc
    passphrase = text.splitlines()[0] if text.splitlines() else ""
    if not passphrase:
        raise UsageError(f"the passphrase file {file} is empty")
    return passphrase


def default_vault_path() -> Path:
    """``$D3TA1L3R_VAULT`` or ``./vault/watchlist.vault``."""
    from_env = os.environ.get(_ENV_VAULT)
    if from_env:
        return Path(from_env).expanduser()
    return Path("vault") / "watchlist.vault"



