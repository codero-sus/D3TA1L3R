"""Check for a newer D3TA1L3R, and apply it when you say so.

An updater in a security tool is a supply-chain decision, not a convenience, so
this one is deliberately conservative about what it will do on its own:

* **Nothing happens unless you run it.** There is no check on startup, no check
  on ``scan``, no telemetry, no background timer. A self-audit tool that phones
  home on every invocation leaks when you use it and what version you run, which
  is information about your patch level.
* **It reports before it changes anything.** ``update`` prints what it found and
  the exact command it would run, and waits for ``y``. ``--check`` never offers
  to install at all.
* **It never downloads and executes a release asset.** A tarball fetched over
  HTTPS and installed by hand would replace the trust you already placed in PyPI
  or in your clone with trust in whoever can answer for this hostname. So the
  update is delegated: ``pip install --upgrade`` for an installed package,
  ``git pull --ff-only`` for a clone. Both are the same trust relationship you
  accepted when you installed it the first time.
* **The command is a list, never a shell string**, and it runs
  ``sys.executable -m pip`` so the upgrade lands in the interpreter that is
  actually running this code rather than whatever ``pip`` is first on ``PATH``.
* **A pre-release is never installed automatically.** ``--yes`` will take
  ``0.2.0`` but stop at ``0.2.0-rc1``; ``--pre`` opts in.

The only request is a GET to the public GitHub releases API. It is
unauthenticated and key-free, like every other source in this tool; GitHub's
unauthenticated rate limit (60/hour per IP) is respected by reporting the
failure rather than retrying.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any

import httpx

from . import __version__

__all__ = [
    "UPDATE_API",
    "UpdateInfo",
    "apply_update",
    "check_for_update",
    "install_kind",
    "is_newer",
    "parse_version",
    "update_command",
]

UPDATE_API = "https://api.github.com/repos/codero-sus/D3TA1L3R/releases/latest"
PROJECT_URL = "https://github.com/codero-sus/D3TA1L3R"
DEFAULT_TIMEOUT = 15.0

#: Dist-tags we will not install unless asked. Anything after a hyphen is a
#: pre-release in semver, and a security tool should not quietly move you onto
#: one.
_PRERELEASE = re.compile(r"[-+]")


class UpdateError(Exception):
    """The update check or the update itself could not be completed."""


# ---------------------------------------------------------------------------
def parse_version(text: str) -> tuple[int, ...]:
    """``"v0.2.1"`` -> ``(0, 2, 1)``. Non-numeric parts stop the parse.

    Comparison has to be numeric: ``"0.10.0" < "0.9.0"`` as strings, which would
    tell you that you are up to date when you are two minor versions behind.
    """
    cleaned = (text or "").strip().lstrip("vV")
    cleaned = cleaned.split("-", 1)[0].split("+", 1)[0]
    parts: list[int] = []
    for chunk in cleaned.split("."):
        if not chunk.isdigit():
            break
        parts.append(int(chunk))
    return tuple(parts)


def is_newer(candidate: str, current: str) -> bool:
    """True when ``candidate`` sorts above ``current``. Equal is not newer."""
    left, right = parse_version(candidate), parse_version(current)
    if not left or not right:
        # Unparseable on either side: fall back to inequality so a version we
        # cannot compare still gets looked at rather than silently skipped.
        return bool(candidate) and candidate.strip().lstrip("vV") != (
            current or ""
        ).strip().lstrip("vV")
    return left > right


@dataclass(slots=True)
class UpdateInfo:
    """What the release API said, next to what is running here."""

    current: str
    latest: str = ""
    url: str = ""
    published_at: str = ""
    notes: str = ""
    prerelease: bool = False
    kind: str = "unknown"
    reachable: bool = True
    message: str = ""
    command: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return bool(self.reachable and self.latest and is_newer(self.latest, self.current))

    def to_dict(self) -> dict[str, Any]:
        return {
            "current": self.current,
            "latest": self.latest or None,
            "update_available": self.available,
            "url": self.url or None,
            "published_at": self.published_at or None,
            "prerelease": self.prerelease,
            "install_kind": self.kind,
            "command": list(self.command),
            "message": self.message or None,
        }


# ---------------------------------------------------------------------------
def install_kind(package_root: Path | None = None) -> str:
    """``"git"``, ``"pip"`` or ``"unknown"`` — how this copy was installed.

    Getting this wrong means running the wrong update mechanism, so a clone is
    detected first: a ``.git`` directory beside the package means you are
    running from a checkout, and ``pip install --upgrade`` would leave the code
    you are executing untouched.
    """
    root = package_root if package_root is not None else Path(__file__).resolve().parent.parent
    if (root / ".git").is_dir():
        return "git"
    try:
        metadata.version("d3ta1l3r")
    except metadata.PackageNotFoundError:
        return "unknown"
    return "pip"


def update_command(kind: str, package_root: Path | None = None) -> list[str]:
    """The argv that would update this install. A list, never a shell string.

    ``--ff-only`` matters for the git path: a fast-forward cannot rewrite
    history you pushed or silently merge over your own commits, so a dirty or
    diverged clone fails loudly instead of producing a tree neither of us can
    describe.
    """
    if kind == "git":
        root = package_root if package_root is not None else Path(__file__).resolve().parent.parent
        return ["git", "-C", str(root), "pull", "--ff-only"]
    if kind == "pip":
        return [sys.executable, "-m", "pip", "install", "--upgrade", "d3ta1l3r"]
    return []


# ---------------------------------------------------------------------------
def check_for_update(
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    current: str = __version__,
) -> UpdateInfo:
    """Ask GitHub for the newest release. Never changes anything on disk."""
    kind = install_kind()
    info = UpdateInfo(current=current, kind=kind)
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            response = client.get(
                UPDATE_API, headers={"Accept": "application/vnd.github+json"}
            )
    except httpx.HTTPError as exc:
        info.reachable = False
        info.message = (
            f"could not reach the release API ({exc.__class__.__name__}). "
            f"Check {PROJECT_URL}/releases yourself."
        )
        return info
    if response.status_code == 404:
        info.message = "this project has no published releases yet"
        info.latest = ""
        return info
    if response.status_code == 403 and "rate limit" in response.text.lower():
        info.reachable = False
        info.message = (
            "GitHub is rate-limiting this address (60 requests/hour unauthenticated). "
            f"Check {PROJECT_URL}/releases yourself."
        )
        return info
    if response.status_code != 200:
        info.reachable = False
        info.message = f"the release API answered {response.status_code}"
        return info
    try:
        payload = response.json()
    except ValueError:
        info.reachable = False
        info.message = "the release API sent something that is not JSON"
        return info
    if not isinstance(payload, dict):
        info.reachable = False
        info.message = "the release API sent an unexpected shape"
        return info

    tag = str(payload.get("tag_name") or payload.get("name") or "")
    info.latest = tag
    info.url = str(payload.get("html_url") or f"{PROJECT_URL}/releases/latest")
    info.published_at = str(payload.get("published_at") or "")
    info.notes = str(payload.get("body") or "").strip()
    info.prerelease = bool(payload.get("prerelease")) or bool(_PRERELEASE.search(tag))
    info.command = update_command(kind)
    if not tag:
        info.message = "the newest release has no version tag"
    elif not info.available:
        info.message = f"up to date (this is {current}, newest release is {tag})"
    return info


# ---------------------------------------------------------------------------
def apply_update(info: UpdateInfo, *, allow_prerelease: bool = False) -> tuple[int, str]:
    """Run the update command. Returns ``(exit_code, output)``.

    Refuses rather than guesses: an unknown install, a pre-release you did not
    opt into, or a version the checker could not reach all stop here with a
    message instead of running something.
    """
    if not info.available:
        return 0, info.message or "nothing to do"
    if info.prerelease and not allow_prerelease:
        return 1, (
            f"{info.latest} is a pre-release, so it is not installed automatically. "
            "Pass --pre if you want it, or wait for the stable tag."
        )
    if not info.command:
        return 1, (
            "this copy is not a git clone and not a pip-installed package, so there is "
            f"no update command to run. Download the newest release from {info.url}."
        )
    try:
        done = subprocess.run(
            info.command, capture_output=True, text=True, check=False
        )
    except OSError as exc:  # git or the interpreter is missing
        return 1, f"could not run {' '.join(info.command)}: {exc}"
    output = "\n".join(part for part in (done.stdout, done.stderr) if part).strip()
    return done.returncode, output


def dumps_json(info: UpdateInfo) -> str:
    """The machine-readable form used by ``--json``."""
    return json.dumps(info.to_dict(), indent=2, sort_keys=True)
