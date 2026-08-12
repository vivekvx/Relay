#!/usr/bin/env bash
# install.sh: installs Callsign — clones this repo, then runs its
# setup.sh <handle> — nothing else.
# Read this file before piping it to bash if you'd rather not; it's short.
#
# Usage: curl -fsSL <raw-url>/install.sh | bash -s <handle>
#
# Clone location: $CALLSIGN_INSTALL_DIR if set, else ~/callsign. Home
# directory by default (not the caller's cwd) since a curl|bash one-liner
# can be run from anywhere — cwd might already be an unrelated git repo
# or a messy Downloads folder; ~/callsign is a stable, predictable spot
# every time.

set -uo pipefail

REPO_URL="https://github.com/vivekvx/callsign.git"
TARGET_DIR="${CALLSIGN_INSTALL_DIR:-$HOME/callsign}"
HANDLE="${1:-}"

fail() {
    printf '\033[1;31mFAIL:\033[0m %s\n' "$1" >&2
    [ -n "${2:-}" ] && printf '  Fix: %s\n' "$2" >&2
    exit 1
}

if ! command -v git >/dev/null 2>&1; then
    fail "git not found on PATH" "install Xcode Command Line Tools: xcode-select --install"
fi

if [ -d "$TARGET_DIR" ]; then
    if [ -d "$TARGET_DIR/.git" ] && git -C "$TARGET_DIR" remote get-url origin 2>/dev/null | grep -qiE "vivekvx/(callsign|Relay)"; then
        echo "==> $TARGET_DIR is already a Callsign checkout, updating it"
        if [ -n "$(git -C "$TARGET_DIR" status --porcelain)" ]; then
            fail "$TARGET_DIR has uncommitted local changes" "commit/stash them, or remove the directory and re-run this installer"
        fi
        git -C "$TARGET_DIR" pull --ff-only || fail "git pull failed in $TARGET_DIR" "resolve manually, then run: cd $TARGET_DIR && ./setup.sh $HANDLE"
    else
        fail "$TARGET_DIR already exists and isn't a Callsign checkout" "set CALLSIGN_INSTALL_DIR to a different path and re-run, e.g.: CALLSIGN_INSTALL_DIR=~/callsign2 curl -fsSL <url>/install.sh | bash -s $HANDLE"
    fi
else
    echo "==> Cloning Callsign into $TARGET_DIR"
    git clone "$REPO_URL" "$TARGET_DIR" || fail "git clone failed"
fi

cd "$TARGET_DIR"
exec ./setup.sh "$HANDLE"
