"""The two updater wrappers in the repository root.

These are deliberately thin: `updater.sh` and `updater.bat` locate a Python and
hand your arguments to `d3ta1l3r update`. The alternative — reimplementing
version comparison in bash and in batch — would put a supply-chain decision in
three places, two of which no test could reach.

So most of what these tests pin is what the scripts must *not* contain. An
updater that fetches code and runs it is the failure mode, whether it is written
in Python or in shell.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SH = ROOT / "updater.sh"
BAT = ROOT / "updater.bat"

#: Fetching a remote script and piping it to a shell is the classic installer
#: foot-gun; none of these may appear in either wrapper.
REMOTE_EXECUTE = (
    "curl",
    "wget",
    "Invoke-Expression",
    "Invoke-WebRequest",
    "iex(",
    "irm ",
    "| sh",
    "| bash",
    "| sudo",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8").lower()


class TestTheyExist:
    def test_both_wrappers_are_in_the_root(self) -> None:
        assert SH.is_file(), "updater.sh belongs in the repository root"
        assert BAT.is_file(), "updater.bat belongs in the repository root"

    def test_the_shell_script_is_executable(self) -> None:
        """Without the mode bit, `./updater.sh` fails with a permission error."""
        assert SH.stat().st_mode & stat.S_IXUSR

    def test_the_shell_script_uses_lf_line_endings(self) -> None:
        """A CR before the shebang makes Linux look for `/bin/bash^M`."""
        assert b"\r\n" not in SH.read_bytes()


class TestTheyAreSafe:
    @pytest.mark.parametrize("term", REMOTE_EXECUTE)
    def test_no_remote_script_is_piped_to_a_shell(self, term: str) -> None:
        for path in (SH, BAT):
            assert term.lower() not in read(path), f"{path.name} may not {term}"

    def test_neither_evaluates_dynamic_text(self) -> None:
        assert "eval " not in read(SH)
        assert "eval(" not in read(BAT)

    def test_neither_disables_tls_verification(self) -> None:
        for path in (SH, BAT):
            body = read(path)
            assert "--insecure" not in body
            assert "-k " not in body
            assert "verify=false" not in body

    def test_neither_reimplements_the_version_check(self) -> None:
        """The comparison lives in updater.py; a second copy would drift."""
        for path in (SH, BAT):
            body = read(path)
            assert "releases/latest" not in body, f"{path.name} must not query the API itself"

    def test_the_fallback_commands_match_the_python_ones(self) -> None:
        """git/pipe delegation only, and fast-forward only for git."""
        for path in (SH, BAT):
            body = read(path)
            assert "pull --ff-only" in body, f"{path.name} must refuse to rewrite history"
            assert "pip install --upgrade d3ta1l3r" in body


class TestTheyDelegate:
    def test_both_pass_arguments_through(self) -> None:
        assert '"$@"' in SH.read_text(encoding="utf-8"), "--check/--yes must reach the CLI"
        assert "%*" in BAT.read_text(encoding="utf-8")

    def test_both_resolve_their_own_directory(self) -> None:
        """So they can be run from anywhere, not only from the repository root."""
        assert "bash_source" in read(SH)
        assert "%~dp0" in BAT.read_text(encoding="utf-8")

    def test_both_prefer_the_project_virtualenv(self) -> None:
        assert ".venv/bin/d3ta1l3r" in read(SH)
        assert ".venv\\scripts\\d3ta1l3r.exe" in read(BAT)

    def test_the_shell_script_fails_fast(self) -> None:
        assert "set -euo pipefail" in SH.read_text(encoding="utf-8")

    def test_the_batch_script_uses_delayed_expansion_for_the_exit_code(self) -> None:
        """`%errorlevel%` inside a parenthesised block is expanded too early."""
        body = BAT.read_text(encoding="utf-8")
        assert "setlocal enabledelayedexpansion" in body
        assert "!errorlevel!" in body


class TestShellScriptRuns:
    def test_it_is_valid_bash(self) -> None:
        if shutil.which("bash") is None:  # pragma: no cover - always true on CI
            pytest.skip("bash is not installed")
        done = subprocess.run(
            ["bash", "-n", str(SH)], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stderr

    def test_it_reaches_the_cli_without_touching_the_network(self) -> None:
        """`--help` proves the wrapper found and invoked the CLI.

        Deliberately not `--check`: that would query GitHub, and the suite must
        not spend the unauthenticated rate limit (60/hour per IP).
        """
        cli = ROOT / ".venv" / "bin" / "d3ta1l3r"
        if not cli.is_file():  # pragma: no cover - depends on the checkout
            pytest.skip("no .venv in this checkout")
        done = subprocess.run(
            [str(SH), "--help"], capture_output=True, text=True, check=False, cwd="/tmp"
        )
        assert done.returncode == 0, done.stderr
        assert "--check" in done.stdout, "the wrapper must forward arguments"
        assert "usage" in done.stdout.lower()

    @pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX-only check")
    def test_it_works_from_another_directory(self) -> None:
        """The whole point of resolving BASH_SOURCE rather than using $PWD."""
        cli = ROOT / ".venv" / "bin" / "d3ta1l3r"
        if not cli.is_file():  # pragma: no cover - depends on the checkout
            pytest.skip("no .venv in this checkout")
        done = subprocess.run(
            [str(SH), "--help"], capture_output=True, text=True, check=False, cwd=ROOT.parent
        )
        assert done.returncode == 0, done.stderr
