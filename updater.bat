@echo off
rem Update D3TA1L3R on Windows.
rem
rem A wrapper, not a second implementation. The version comparison, the release
rem lookup and every refusal rule live in `d3ta1l3r update`; restating them here
rem would mean three copies of a supply-chain decision, two of them untested. So
rem this script finds the right Python and hands your arguments to the CLI:
rem
rem     updater.bat                check, show the release, ask, then act
rem     updater.bat --check        report only; change nothing
rem     updater.bat --yes          non-interactive (still never a pre-release)
rem     updater.bat --pre          allow a pre-release
rem     updater.bat --json         machine-readable, for scripts
rem
rem If the CLI cannot be found it falls back to the same two commands the Python
rem code would have run: `git pull --ff-only` in a clone, or
rem `pip install --upgrade d3ta1l3r` for a packaged install. It never downloads a
rem release archive and executes it -- see docs\SCOPE.md 2e.
rem
rem Works from any directory; it resolves the repository from its own location.

setlocal enabledelayedexpansion
set "here=%~dp0"
rem %~dp0 keeps a trailing backslash; drop it so the paths below read cleanly.
rem (A trailing backslash before a closing quote also confuses `if exist`.)
if "%here:~-1%"=="\" set "here=%here:~0,-1%"

rem 1. The virtualenv next to the checkout, which is what the docs build.
if exist "%here%\.venv\Scripts\d3ta1l3r.exe" (
    "%here%\.venv\Scripts\d3ta1l3r.exe" update %*
    exit /b !errorlevel!
)

rem 2. Whatever d3ta1l3r is on PATH.
where d3ta1l3r >nul 2>nul
if not errorlevel 1 (
    d3ta1l3r update %*
    exit /b !errorlevel!
)

rem 3. An interpreter that can actually import the package. Finding `py` is not
rem    enough -- if d3ta1l3r is not installed in it, running the module would
rem    fail here instead of falling through to git or pip below.
set "pycmd="
set "pyany="
where py >nul 2>nul
if not errorlevel 1 (
    set "pyany=py -3"
    py -3 -c "import d3ta1l3r" >nul 2>nul
    if not errorlevel 1 set "pycmd=py -3"
)
if not defined pyany (
    where python >nul 2>nul
    if not errorlevel 1 (
        set "pyany=python"
        python -c "import d3ta1l3r" >nul 2>nul
        if not errorlevel 1 set "pycmd=python"
    )
)
if defined pycmd (
    %pycmd% -m d3ta1l3r update %*
    exit /b !errorlevel!
)

echo d3ta1l3r is not installed in a way this script can find. 1>&2
echo   tried: "%here%\.venv\Scripts\d3ta1l3r.exe", d3ta1l3r on PATH, py -3 -m d3ta1l3r 1>&2

rem No CLI anywhere: use the mechanism the CLI would have chosen, and say which
rem one and why, rather than guessing quietly.
if exist "%here%\.git" (
    where git >nul 2>nul
    if not errorlevel 1 (
        echo this looks like a clone, so: git pull --ff-only 1>&2
        git -C "%here%" pull --ff-only
        exit /b !errorlevel!
    )
)

rem pycmd is empty by the time we get here (a usable one would have exited above),
rem so the pip fallback needs pyany: any interpreter at all.
if defined pyany (
    echo falling back to: pip install --upgrade d3ta1l3r 1>&2
    %pyany% -m pip install --upgrade d3ta1l3r
    exit /b !errorlevel!
)

echo no Python 3 and no git found. Install Python 3.10+ or git, then retry. 1>&2
exit /b 1
