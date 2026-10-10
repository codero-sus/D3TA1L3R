#!/usr/bin/env bash
#
# Update D3TA1L3R on Linux, macOS and WSL.
#
# This is a wrapper, not a second implementation. The version comparison, the
# release lookup and every refusal rule live in `d3ta1l3r update`; duplicating
# them here in shell would mean three copies of a supply-chain decision, two of
# them untested. So this script's whole job is to find the right Python and hand
# your arguments to the CLI:
#
#     ./updater.sh                 # check, show the release, ask, then act
#     ./updater.sh --check         # report only; change nothing
#     ./updater.sh --yes           # non-interactive (still never a pre-release)
#     ./updater.sh --pre           # allow a pre-release
#     ./updater.sh --json          # machine-readable, for scripts
#
# Which Python, first match wins:
#
#   1. 2PY2               — an environment variable holding a Python path.
#                           ("2PY2" = a *second* Python, not Python 2: portable
#                           and embeddable builds are usually not on PATH.)
#   2. D3TA1L3R_PYTHON    — the same idea, as a name a shell can actually
#                           export. See the note below.
#   3. python.env         — a file beside this script naming one. Optional;
#                           see python.env.example.
#   3. .venv/bin/d3ta1l3r — the virtualenv the docs tell you to build.
#   4. d3ta1l3r on PATH.
#   5. python3 / python   — any interpreter that can import the package.
#
# An interpreter named in 1 or 2 is checked before being trusted; if it cannot
# import d3ta1l3r the script says so and keeps looking, rather than dying on a
# path that has moved. If no CLI can be found at all it falls back to the same
# two commands the Python code would have run: `git pull --ff-only` in a clone,
# or `pip install --upgrade d3ta1l3r` for a packaged install. What it never does
# is fetch a release archive over the network and execute it — docs/SCOPE.md 2e.
#
# Works from any directory; it resolves the repository from its own location.
#
# Portability: written for bash 3.2 (what stock macOS still ships) as well as
# bash 5 on Linux. No GNU-only flags, no `dirname --`, no associative arrays.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
name="$(basename "${BASH_SOURCE[0]}")"

warn() { printf '%s: %s\n' "$name" "$*" >&2; }

# Read the first usable Python path out of a python.env file.
#
# Accepts `KEY=value` (KEY one of PYTHON, PYTHON_PATH, PYTHON_EXE, PYTHON_BIN,
# PYTHON_HOME, 2PY2) or a bare path on its own line, and tolerates comments,
# blank lines, CRLF endings (a file saved on Windows), stray whitespace and
# surrounding quotes. IFS does the trimming; the ${line%$'\r'} handles the CR.
read_python_env() {
    local file="$1" line key value
    [ -f "$file" ] || return 1
    while IFS=$' \t' read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [ -n "$line" ] || continue
        case "$line" in
            '#'*) continue ;;
            *=*)
                key="${line%%=*}"
                value="${line#*=}"
                ;;
            *)
                key="PYTHON"
                value="$line"
                ;;
        esac
        case "$key" in
            PYTHON | PYTHON_PATH | PYTHON_EXE | PYTHON_BIN | PYTHON_HOME | 2PY2) ;;
            *) continue ;;
        esac
        value="${value%$'\r'}"
        case "$value" in
            '"'*'"')
                value="${value#\"}"
                value="${value%\"}"
                ;;
            "'"*"'")
                value="${value#\'}"
                value="${value%\'}"
                ;;
        esac
        [ -n "$value" ] || continue
        printf '%s' "$value"
        return 0
    done < "$file"
    return 1
}

# An interpreter is only usable if it can actually import the package.
usable_python() {
    local candidate="$1"
    [ -n "$candidate" ] || return 1
    if [ -x "$candidate" ]; then
        "$candidate" -c 'import d3ta1l3r' >/dev/null 2>&1 || return 1
        return 0
    fi
    command -v "$candidate" >/dev/null 2>&1 || return 1
    "$candidate" -c 'import d3ta1l3r' >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Read an environment variable whose name a shell would refuse to expand.
#
# `2PY2` begins with a digit, which makes it an invalid identifier: ${2PY2} is a
# "bad substitution", and a bare $2PY2 expands to positional parameter 2
# followed by the literal text "PY2" -- silently the wrong value, with no error.
# `export 2PY2=...` is rejected for the same reason, so it has to be put in the
# environment by something else: `env 2PY2=/path ./updater.sh`, a service unit,
# or a Windows `set`. printenv does not care about identifier rules at all.
env_value() {
    local name="$1"
    command -v printenv >/dev/null 2>&1 || return 1
    printenv "$name" 2>/dev/null
}

# 1-2. An environment variable, 2PY2 first.
configured=""
configured_source=""
for var in 2PY2 D3TA1L3R_PYTHON; do
    value="$(env_value "$var" || true)"
    if [ -n "$value" ]; then
        configured="$value"
        configured_source="$var (environment)"
        break
    fi
done

# 3. python.env beside this script.
if [ -z "$configured" ] && [ -f "$here/python.env" ]; then
    if configured="$(read_python_env "$here/python.env")"; then
        configured_source="python.env"
    else
        configured=""
        warn "$here/python.env has no usable Python path in it; ignoring it."
    fi
fi

pycmd=""
if [ -n "$configured" ]; then
    if usable_python "$configured"; then
        pycmd="$configured"
    else
        warn "ignoring $configured_source -> '$configured': d3ta1l3r cannot be imported with it."
    fi
fi

# 1-3. A configured interpreter runs the module directly.
# 4.   The project virtualenv.
# 5.   d3ta1l3r on PATH.
if [ -n "$pycmd" ]; then
    exec "$pycmd" -m d3ta1l3r update "$@"
elif [ -x "$here/.venv/bin/d3ta1l3r" ]; then
    exec "$here/.venv/bin/d3ta1l3r" update "$@"
elif command -v d3ta1l3r >/dev/null 2>&1; then
    exec d3ta1l3r update "$@"
fi

# 6. Any interpreter that can import the package.
auto=""
for candidate in python3 python; do
    if usable_python "$candidate"; then
        auto="$candidate"
        break
    fi
done
if [ -n "$auto" ]; then
    exec "$auto" -m d3ta1l3r update "$@"
fi

# ---------------------------------------------------------------------------
# No CLI anywhere: use the mechanism the CLI would have chosen, and say which
# one and why, rather than guessing quietly.
warn "d3ta1l3r is not installed in a way this script can find."
warn "  tried: 2PY2, D3TA1L3R_PYTHON, $here/python.env, $here/.venv/bin/d3ta1l3r,"
warn "         d3ta1l3r on PATH, python3 -m d3ta1l3r"

# Prefer the interpreter the user named, even if the package is missing from it:
# `pip install` is exactly how you would fix that.
pip_python="${configured:-$auto}"

if [ -d "$here/.git" ] && command -v git >/dev/null 2>&1; then
    warn "this looks like a clone, so: git pull --ff-only"
    exec git -C "$here" pull --ff-only
fi

if [ -n "$pip_python" ]; then
    warn "falling back to: pip install --upgrade d3ta1l3r"
    exec "$pip_python" -m pip install --upgrade d3ta1l3r
fi

warn "no python3 and no git found. Set 2PY2 (or D3TA1L3R_PYTHON), or create python.env, then retry."
exit 1
