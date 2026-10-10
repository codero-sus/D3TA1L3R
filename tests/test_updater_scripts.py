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


def code_of(path: Path) -> str:
    """The file with comment lines removed, lowercased.

    Bans have to apply to code rather than to prose: the scripts explain *why*
    they avoid `curl | sh` and `${2PY2}`, and a test that matched the
    explanation would pass even after someone put the thing back in.
    """
    kept = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.lower().startswith("rem "):
            continue
        kept.append(line)
    return "\n".join(kept).lower()


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
            assert term.lower() not in code_of(path), f"{path.name} may not {term}"

    def test_neither_evaluates_dynamic_text(self) -> None:
        assert "eval " not in code_of(SH)
        assert "eval(" not in code_of(BAT)

    def test_neither_disables_tls_verification(self) -> None:
        for path in (SH, BAT):
            body = code_of(path)
            assert "--insecure" not in body
            assert "-k " not in body
            assert "verify=false" not in body

    def test_neither_reimplements_the_version_check(self) -> None:
        """The comparison lives in updater.py; a second copy would drift."""
        for path in (SH, BAT):
            body = code_of(path)
            assert "releases/latest" not in body, f"{path.name} must not query the API itself"

    def test_the_fallback_commands_match_the_python_ones(self) -> None:
        """git/pipe delegation only, and fast-forward only for git."""
        for path in (SH, BAT):
            body = code_of(path)
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

    def test_both_honour_the_configured_python(self) -> None:
        for path in (SH, BAT):
            body = code_of(path)
            assert "python.env" in body, f"{path.name} must read python.env"
            assert "2py2" in body, f"{path.name} must read the 2PY2 variable"

    def test_the_shell_script_never_tries_to_expand_2py2_directly(self) -> None:
        """${2PY2} is a bad substitution and $2PY2 is positional-2 plus "PY2".

        Both fail silently or loudly, and either would make the feature look
        implemented while reading the wrong thing, so the broken forms are
        banned outright and `printenv` is required instead.
        """
        body = code_of(SH)
        assert "${2PY2" not in body, "bash cannot expand a name starting with a digit"
        assert "printenv" in body, "read it with printenv, which has no such rule"

    @pytest.mark.skipif(
        __import__("sys").platform.startswith("win"), reason="bash is POSIX"
    )
    def test_the_shell_script_has_no_gnu_only_flags(self) -> None:
        """macOS still ships bash 3.2, and `dirname --` is not portable."""
        body = code_of(SH)
        assert "dirname --" not in body
        assert "readlink -f" not in body, "not on stock macOS"

    def test_the_shell_script_fails_fast(self) -> None:
        assert "set -euo pipefail" in SH.read_text(encoding="utf-8")

    def test_the_batch_script_uses_delayed_expansion_for_the_exit_code(self) -> None:
        """`%errorlevel%` inside a parenthesised block is expanded too early."""
        body = BAT.read_text(encoding="utf-8")
        assert "setlocal enabledelayedexpansion" in body
        assert "!errorlevel!" in body


class _StubRepo:
    """A throwaway checkout with stub interpreters, so resolution is observable."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = root / "calls.log"
        (root / "repo").mkdir(parents=True)
        (root / "bin").mkdir(parents=True)
        self.stub = root / "bin" / "portable-python"
        # Records every invocation, and claims to have d3ta1l3r importable.
        self.stub.write_text(
            "#!/bin/sh\n"
            f'echo "$*" >> {self.calls}\n'
            'case "$*" in *"import d3ta1l3r"*) exit 0 ;; esac\n'
            'exit 0\n'
        )
        self.stub.chmod(0o755)
        self.script = root / "repo" / "updater.sh"
        self.script.write_text((Path(__file__).resolve().parent.parent / "updater.sh").read_text())
        self.script.chmod(0o755)

    def run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        import os

        merged = dict(os.environ)
        merged.update(env or {})
        if self.calls.exists():
            self.calls.unlink()
        return subprocess.run(
            [str(self.script), *args], capture_output=True, text=True, check=False,
            cwd=str(self.root / "repo"), env=merged,
        )

    def invoked(self) -> str:
        return self.calls.read_text() if self.calls.exists() else ""


@pytest.fixture()
def stub_repo(tmp_path: Path) -> _StubRepo:
    return _StubRepo(tmp_path)


class TestPythonResolution:
    """2PY2 / D3TA1L3R_PYTHON / python.env, and the precedence between them."""

    def test_the_env_var_is_read_even_though_it_is_not_a_valid_identifier(
        self, stub_repo: _StubRepo
    ) -> None:
        """`2PY2` begins with a digit, so ${2PY2} is a bad substitution and a
        bare $2PY2 expands to positional parameter 2 plus the text "PY2"."""
        done = stub_repo.run("--check", env={"2PY2": str(stub_repo.stub)})
        assert done.returncode == 0, done.stderr
        assert "-m d3ta1l3r update --check" in stub_repo.invoked()

    def test_the_second_env_var_works_when_exported_normally(
        self, stub_repo: _StubRepo
    ) -> None:
        stub_repo.run("--check", env={"D3TA1L3R_PYTHON": str(stub_repo.stub)})
        assert "-m d3ta1l3r update --check" in stub_repo.invoked()

    @pytest.mark.parametrize(
        "content",
        [
            "PYTHON={path}\n",
            "# a comment\n\nPYTHON={path}\n",
            "PYTHON_PATH={path}\n",
            "2PY2={path}\n",
            "{path}\n",                 # bare path, no KEY=
            'PYTHON="{path}"\n',        # quoted
            "PYTHON={path}\r\n",        # CRLF, as saved on Windows
            '# c\r\nPYTHON="{path}"\r\n',
        ],
    )
    def test_python_env_is_read_in_every_accepted_form(
        self, stub_repo: _StubRepo, content: str
    ) -> None:
        (stub_repo.root / "repo" / "python.env").write_text(
            content.format(path=stub_repo.stub)
        )
        done = stub_repo.run("--check")
        assert done.returncode == 0, done.stderr
        assert "-m d3ta1l3r update --check" in stub_repo.invoked()

    def test_the_env_var_beats_python_env(self, stub_repo: _StubRepo) -> None:
        """An explicit override should win over the project-wide file."""
        winner = stub_repo.root / "bin" / "winner"
        winner.write_text(
            "#!/bin/sh\n"
            f'echo "$*" >> {stub_repo.calls}\n'
            'case "$*" in *"import d3ta1l3r"*) exit 0 ;; esac\nexit 0\n'
        )
        winner.chmod(0o755)
        (stub_repo.root / "repo" / "python.env").write_text(f"PYTHON={stub_repo.stub}\n")
        stub_repo.run("--check", env={"2PY2": str(winner)})
        log = stub_repo.invoked()
        assert "winner" not in log, "the log records arguments, not paths"
        assert log.count("-m d3ta1l3r update --check") == 1, "only one python may run"

    def test_an_unusable_python_is_reported_and_skipped(
        self, stub_repo: _StubRepo
    ) -> None:
        """A path that has moved must not turn into a dead end."""
        (stub_repo.root / "repo" / "python.env").write_text("PYTHON=/nonexistent/python\n")
        done = stub_repo.run("--check")
        assert "cannot be imported" in done.stderr
        assert "ignoring" in done.stderr

    def test_arguments_reach_the_cli_through_the_wrapper(
        self, stub_repo: _StubRepo
    ) -> None:
        stub_repo.run("--check", "--yes", "--json", env={"2PY2": str(stub_repo.stub)})
        assert "-m d3ta1l3r update --check --yes --json" in stub_repo.invoked()


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
