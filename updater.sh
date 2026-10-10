#!/usr/bin/env bash
#
# Update D3TA1L3R on Linux/macOS/WSL.
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
# If the CLI really is not available it falls back to the same two commands the
# Python code would have run: `git pull --ff-only` in a clone, or
# `pip install --upgrade d3ta1l3r` for a packaged install. What it never does is
# fetch a release archive over the network and execute it — see docs/SCOPE.md 2e.
#
# Works from any directory; it resolves the repository from its own location.

set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# 1. A virtualenv next to the checkout is the one the docs tell you to build.
# 2. Otherwise whatever `d3ta1l3r` is on PATH.
# 3. Otherwise run the module through any Python 3 we can find.
cli=""
if [[ -x "$here/.venv/bin/d3ta1l3r" ]]; then
    cli="$here/.venv/bin/d3ta1l3r"
elif command -v d3ta1l3r >/dev/null 2>&1; then
    cli="d3ta1l3r"
fi

if [[ -n "$cli" ]]; then
    exec "$cli" update "$@"
fi

python_bin=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        python_bin="$candidate"
        break
    fi
done

if [[ -n "$python_bin" ]] && "$python_bin" -c 'import d3ta1l3r' >/dev/null 2>&1; then
    exec "$python_bin" -m d3ta1l3r update "$@"
fi

# No CLI anywhere. Fall back to the mechanism the CLI would have chosen, and say
# which one and why, rather than guessing quietly.
echo "d3ta1l3r is not installed in a way this script can find." >&2
echo "  tried: $here/.venv/bin/d3ta1l3r, d3ta1l3r on PATH, python3 -m d3ta1l3r" >&2

if [[ -d "$here/.git" ]] && command -v git >/dev/null 2>&1; then
    echo "this looks like a clone, so: git pull --ff-only" >&2
    exec git -C "$here" pull --ff-only
fi

if [[ -n "$python_bin" ]]; then
    echo "falling back to: pip install --upgrade d3ta1l3r" >&2
    exec "$python_bin" -m pip install --upgrade d3ta1l3r
fi

echo "no python3 and no git found. Install Python 3.10+ or git, then retry." >&2
exit 1
