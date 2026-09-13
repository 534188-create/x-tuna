#!/bin/sh
set -eu

# Run from a source checkout, or download the current release artifact when
# this file was fetched directly from GitHub.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$ROOT/dist/lucx-post-configure.sh" ]; then
    exec sh "$ROOT/dist/lucx-post-configure.sh" "$@"
fi

command -v curl >/dev/null 2>&1 || {
    printf '%s\n' 'curl is required for the online bootstrap.' >&2
    exit 2
}
ref=${X_TUNA_REF:-main}
url=${X_TUNA_ARTIFACT_URL:-https://raw.githubusercontent.com/534188-create/x-tuna/$ref/dist/lucx-post-configure.sh}
sum_url=${X_TUNA_SUMS_URL:-https://raw.githubusercontent.com/534188-create/x-tuna/$ref/dist/SHA256SUMS}
tmp=$(mktemp)
sum=$(mktemp)
cleanup() { rm -f "$tmp" "$sum"; }
trap cleanup EXIT HUP INT TERM
curl --fail --location --retry 3 --connect-timeout 15 --max-time 600 "$url" -o "$tmp"
if [ -n "${X_TUNA_INSTALL_SHA256:-}" ]; then
    expected=$X_TUNA_INSTALL_SHA256
else
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 60 \
        "$sum_url" -o "$sum"
    expected=$(awk '$2 == "lucx-post-configure.sh" { print $1; exit }' "$sum")
fi
case "$expected" in
    [0-9a-fA-F][0-9a-fA-F]*) ;;
    *) printf '%s\n' 'A valid SHA-256 for the installer is required.' >&2; exit 2 ;;
esac
actual=$(sha256sum "$tmp" | awk '{print $1}')
[ "$(printf '%s' "$actual" | tr 'A-F' 'a-f')" = "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ] || {
    printf '%s\n' 'Installer checksum mismatch.' >&2
    exit 2
}
chmod 0700 "$tmp"
exec sh "$tmp" "$@"
