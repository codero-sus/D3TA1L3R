#!/usr/bin/env bash
#
# Start the dashboard with a throwaway vault and one demo scan, so there is
# something to look at. Safe to run repeatedly: it reuses anything it already
# has and never touches your real vault at ~/.d3ta1l3r.
#
#     ./scripts/preview.sh                 # http://localhost:7248
#     ./scripts/preview.sh --port 8000
#     ./scripts/preview.sh --fresh         # throw away the old preview data
#     PORT=9000 PASSPHRASE=other ./scripts/preview.sh
#
# The passphrase is printed at the end because it is generated into a file in
# the preview directory; it is a demo value, not a secret.
#
# It installs only the `.[web]` extra, which is enough to serve the dashboard.
# Running the test suite needs more: `pip install -e '.[all]'`.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

port="${PORT:-7248}"
dir="${PREVIEW_DIR:-/tmp/d3t-preview}"
passphrase="${PASSPHRASE:-preview-passphrase-2026}"

fresh=0
while [ $# -gt 0 ]; do
    case "$1" in
        --port) port="${2:?--port needs a value}"; shift 2 ;;
        --fresh) fresh=1; shift ;;
        -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

cd "$root"

# 1. An interpreter for this checkout, if one is not already built.
if [ ! -x "$root/.venv/bin/d3ta1l3r" ]; then
    echo "building .venv (first run takes a moment)..."
    python3 -m venv .venv
    .venv/bin/pip install -q -e '.[web]'
fi
cli="$root/.venv/bin/d3ta1l3r"

# 2. A throwaway vault and one demo scan, so the pages are not empty.
if [ "$fresh" = 1 ]; then
    rm -rf "$dir"
fi
if [ ! -f "$dir/watchlist.vault" ]; then
    echo "seeding preview data in $dir ..."
    mkdir -p "$dir"
    # not a credential: a throwaway passphrase for a demo vault under /tmp
    printf '%s\n' "$passphrase" > "$dir/pass"  # ggignore
    export D3TA1L3R_VAULT="$dir/watchlist.vault"
    export D3TA1L3R_VAULT_PASSPHRASE="$passphrase"
    "$cli" vault init --passphrase-file "$dir/pass" >/dev/null
    "$cli" vault add --kind email you@example.com --label personal >/dev/null || true
    "$cli" vault add --kind username demo_user --label handle >/dev/null || true
    "$cli" scan -u demo_user -e demo.user@example.com -d example.com \
        --demo -o "$dir" -q >/dev/null || true
fi

echo
echo "  D3TA1L3R dashboard -> http://localhost:$port"
echo "  sign in with: $passphrase"
echo "  preview data: $dir  (--fresh to rebuild it)"
echo

exec env D3TA1L3R_VAULT="$dir/watchlist.vault" \
    "$cli" web --host 0.0.0.0 --port "$port" --vault --output "$dir"
