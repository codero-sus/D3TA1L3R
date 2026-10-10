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
rem Which Python, first match wins:
rem
rem   1. %2PY2%           - an environment variable holding a Python path.
rem                         ("2PY2" = a *second* Python, not Python 2: portable
rem                         and embeddable builds usually are not on PATH.)
rem   2. %D3TA1L3R_PYTHON% - the same idea under a name every shell can export.
rem   3. python.env       - a file beside this script naming one. Optional;
rem                         see python.env.example.
rem   3. .venv\Scripts\d3ta1l3r.exe  - the virtualenv the docs build.
rem   4. d3ta1l3r on PATH.
rem   5. py -3 / python   - any launcher that can import the package.
rem
rem An interpreter named in 1 or 2 is checked before being trusted; if it cannot
rem import d3ta1l3r this script says so and keeps looking, rather than dying on
rem a path that has moved. If no CLI can be found at all it falls back to the
rem same two commands the Python code would have run: `git pull --ff-only` in a
rem clone, or `pip install --upgrade d3ta1l3r` for a packaged install. It never
rem downloads a release archive and executes it -- see docs\SCOPE.md 2e.
rem
rem Works from any directory; it resolves the repository from its own location.

setlocal enabledelayedexpansion
set "here=%~dp0"
rem %~dp0 keeps a trailing backslash; drop it so the paths below read cleanly.
rem (A trailing backslash before a closing quote also confuses `if exist`.)
if "%here:~-1%"=="\" set "here=%here:~0,-1%"

set "configured="
set "cfgsrc="

rem 1-2. An environment variable, 2PY2 first. Read with delayed expansion on
rem    purpose: !2PY2! cannot be mistaken for a %2 argument reference.
if defined 2PY2 (
    set "configured=!2PY2!"
    set "cfgsrc=%%2PY2%%"
)
if not defined configured (
    if defined D3TA1L3R_PYTHON (
        set "configured=!D3TA1L3R_PYTHON!"
        set "cfgsrc=%%D3TA1L3R_PYTHON%%"
    )
)

rem 3. python.env beside this script. `tokens=1,* delims==` splits KEY=value;
rem    a line with no "=" arrives whole in %%K and is treated as a bare path.
rem    `eol=#` drops comment lines.
if not defined configured (
    if exist "%here%\python.env" (
        for /f "usebackq eol=# tokens=1,* delims==" %%K in ("%here%\python.env") do (
            if not defined configured (
                if "%%L"=="" (
                    if not "%%K"=="" (
                        set "configured=%%K"
                        set "cfgsrc=python.env"
                    )
                ) else (
                    if /i "%%K"=="PYTHON" set "configured=%%L" & set "cfgsrc=python.env"
                    if /i "%%K"=="PYTHON_PATH" set "configured=%%L" & set "cfgsrc=python.env"
                    if /i "%%K"=="PYTHON_EXE" set "configured=%%L" & set "cfgsrc=python.env"
                    if /i "%%K"=="PYTHON_BIN" set "configured=%%L" & set "cfgsrc=python.env"
                    if /i "%%K"=="PYTHON_HOME" set "configured=%%L" & set "cfgsrc=python.env"
                    if /i "%%K"=="2PY2" set "configured=%%L" & set "cfgsrc=python.env"
                )
            )
        )
    )
    if not defined configured (
        echo updater.bat: "%here%\python.env" has no usable Python path in it; ignoring it. 1>&2
    )
)

rem Tidy the value: strip enclosing quotes, then a stray carriage return. A
rem python.env saved with CRLF endings can leave a CR glued to the value, and a
rem path with one never exists -- so drop the last character and retry rather
rem than declaring the configured interpreter broken.
if defined configured (
    set "c=!configured!"
    rem The ~ modifier strips quotes from a for variable, which is safer than
    rem trying to escape a literal " inside a comparison.
    for /f "delims=" %%Q in ("!c!") do set "c=%%~Q"
    if not exist "!c!" (
        set "t=!c:~0,-1!"
        if exist "!t!" set "c=!t!"
    )
    set "configured=!c!"
)

rem Trust it only if it can import the package.
set "pycmd="
if defined configured (
    "!configured!" -c "import d3ta1l3r" >nul 2>nul
    if not errorlevel 1 (
        set "pycmd=!configured!"
    ) else (
        echo updater.bat: ignoring !cfgsrc! -^> "!configured!": d3ta1l3r cannot be imported with it. 1>&2
    )
)

rem 1-3. A configured interpreter runs the module directly.
if defined pycmd (
    "!pycmd!" -m d3ta1l3r update %*
    exit /b !errorlevel!
)

rem 3. The virtualenv next to the checkout.
if exist "%here%\.venv\Scripts\d3ta1l3r.exe" (
    "%here%\.venv\Scripts\d3ta1l3r.exe" update %*
    exit /b !errorlevel!
)

rem 4. Whatever d3ta1l3r is on PATH.
where d3ta1l3r >nul 2>nul
if not errorlevel 1 (
    d3ta1l3r update %*
    exit /b !errorlevel!
)

rem 5. An interpreter that can actually import the package. Finding `py` is not
rem    enough -- if d3ta1l3r is not installed in it, running the module would
rem    fail here instead of falling through to git or pip below.
set "pyany="
where py >nul 2>nul
if not errorlevel 1 (
    set "pyany=py -3"
    py -3 -c "import d3ta1l3r" >nul 2>nul
    if not errorlevel 1 (
        py -3 -m d3ta1l3r update %*
        exit /b !errorlevel!
    )
)
if not defined pyany (
    where python >nul 2>nul
    if not errorlevel 1 (
        set "pyany=python"
        python -c "import d3ta1l3r" >nul 2>nul
        if not errorlevel 1 (
            python -m d3ta1l3r update %*
            exit /b !errorlevel!
        )
    )
)

rem No CLI anywhere: use the mechanism the CLI would have chosen, and say which
rem one and why, rather than guessing quietly.
echo updater.bat: d3ta1l3r is not installed in a way this script can find. 1>&2
echo   tried: %%2PY2%%, "%here%\python.env", "%here%\.venv\Scripts\d3ta1l3r.exe", d3ta1l3r on PATH, py -3 -m d3ta1l3r 1>&2

if exist "%here%\.git" (
    where git >nul 2>nul
    if not errorlevel 1 (
        echo updater.bat: this looks like a clone, so: git pull --ff-only 1>&2
        git -C "%here%" pull --ff-only
        exit /b !errorlevel!
    )
)

rem Prefer the interpreter the user named, even if the package is missing from
rem it: pip install is exactly how you would fix that.
set "pippython="
if defined configured (
    set "pippython=!configured!"
) else if defined pyany (
    set "pippython=!pyany!"
)

if defined pippython (
    echo updater.bat: falling back to: pip install --upgrade d3ta1l3r 1>&2
    !pippython! -m pip install --upgrade d3ta1l3r
    exit /b !errorlevel!
)

echo updater.bat: no Python 3 and no git found. Set 2PY2, or create python.env, then retry. 1>&2
exit /b 1
