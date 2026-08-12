#!/usr/bin/env bash
# Callsign one-shot setup — steps 2-6 of the Quick Start in README.md
# (step 1, cloning the repo, happens before this script is even
# reachable — see README.md's "Quick Start" for the exact one-line
# instruction a person pastes to their own coding agent).
#
# Idempotent: safe to re-run after a partial failure. Every step checks
# its own already-done state before acting, rather than assuming a
# clean slate.
#
# macOS only, deliberately (Homebrew for prerequisites; PostgreSQL
# binary paths assume Homebrew's postgresql@16 keg). Linux/Windows
# support is explicitly out of scope for this pass, not a silent gap —
# see README.md's "Quick Start" section for the same statement.
#
# Bash chosen over a "properly cross-platform" alternative (a Python
# bootstrap script, say) because there is no cross-platform target here
# to justify one — this is macOS-only by explicit scope, and every tool
# this script shells out to (brew, cargo, initdb) is itself a native
# binary; a Python wrapper would only add an interpreter dependency
# this script doesn't otherwise need before Python exists.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"
CALLSIGN_BIN="$VENV_DIR/bin/callsign"
DEFAULT_REGISTRY_URL="https://relay-registry.onrender.com"

# ---------------------------------------------------------------------
# Output helpers — every message an agent running this needs to be able
# to parse is prefixed distinctly, so a failure is never just a bare
# stack trace with no indication of WHICH step or WHY.
# ---------------------------------------------------------------------
step() { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m  ok:\033[0m %s\n' "$1"; }
fail() {
    printf '\033[1;31m  FAIL:\033[0m %s\n' "$1" >&2
    [ -n "${2:-}" ] && printf '  Fix: %s\n' "$2" >&2
    exit 1
}

# ---------------------------------------------------------------------
# Step 0: prerequisite checks — explicit, named, one clear fix each.
# Nothing below this block assumes any of these silently exist.
# ---------------------------------------------------------------------
step "Checking prerequisites"

if [ "$(uname -s)" != "Darwin" ]; then
    fail "this script supports macOS only (uname -s reported $(uname -s))" \
         "Linux/Windows setup is out of scope for this pass — see README.md's Quick Start section, and PRD.md if you want to help extend it."
fi

PYTHON_BIN="$(command -v python3.12 || command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then
    fail "no python3 found on PATH" "brew install python@3.12"
fi
if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    fail "$PYTHON_BIN is $("$PYTHON_BIN" --version 2>&1), but agent/pyproject.toml requires >=3.12" \
         "brew install python@3.12   (then re-run this script — it will pick up the new interpreter via 'python3.12' on PATH)"
fi
ok "$($PYTHON_BIN --version 2>&1) at $PYTHON_BIN"

if ! command -v cargo >/dev/null 2>&1; then
    fail "no cargo/rustc found on PATH — needed to build identity/'s Rust bridge (maturin develop)" \
         "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   (then restart your shell, or 'source \$HOME/.cargo/env')"
fi
ok "cargo $(cargo --version 2>&1 | awk '{print $2}')"

PG_BIN_DIR=""
for candidate in "$(command -v initdb 2>/dev/null | xargs dirname 2>/dev/null || true)" "/opt/homebrew/opt/postgresql@16/bin" "/usr/local/opt/postgresql@16/bin"; do
    if [ -n "$candidate" ] && [ -x "$candidate/initdb" ]; then
        PG_BIN_DIR="$candidate"
        break
    fi
done
if [ -z "$PG_BIN_DIR" ]; then
    echo "  note: no local PostgreSQL binaries found — fine for normal use (the shared hosted registry needs none of this locally); only needed if you later opt into running your own registry via 'callsign switchboard'."
else
    ok "PostgreSQL binaries at $PG_BIN_DIR (only used if you opt into a local registry)"
fi

# ---------------------------------------------------------------------
# Step 1: venv (idempotent — reuses an existing one untouched)
# ---------------------------------------------------------------------
step "Setting up Python virtual environment"
if [ -x "$VENV_DIR/bin/python" ]; then
    ok "already exists at $VENV_DIR"
else
    "$PYTHON_BIN" -m venv "$VENV_DIR" || fail "python3 -m venv failed" "check disk space / permissions in $SCRIPT_DIR"
    ok "created at $VENV_DIR"
fi

# ---------------------------------------------------------------------
# Step 2: dependencies (idempotent — pip install is a no-op when
# already satisfied). Deliberately NOT `pip install -r
# requirements-dev.txt` as-is: that file's relay_identity line installs
# a pinned, possibly-stale commit from GitHub over the network — this
# script instead builds identity/'s Rust bridge from the LOCAL checkout
# via maturin develop (step 3), which is the actually-correct source of
# truth for someone setting up from their own fresh clone.
# ---------------------------------------------------------------------
step "Installing Python dependencies"
"$VENV_DIR/bin/pip" install -q -U pip || fail "pip self-upgrade failed" "check network connectivity"
"$VENV_DIR/bin/pip" install -q fastapi uvicorn sqlalchemy psycopg psycopg-binary httpx mcp maturin \
    || fail "pip install of core dependencies failed" "re-run this script — pip install is safe to retry"
"$VENV_DIR/bin/pip" install -q -e agent \
    || fail "pip install -e agent failed (installs the 'callsign' CLI console script)" "check agent/pyproject.toml is present and valid"
ok "fastapi, uvicorn, sqlalchemy, psycopg, httpx, mcp, maturin, and the 'callsign' CLI installed"

# ---------------------------------------------------------------------
# Step 3: identity/ Rust bridge (idempotent — maturin develop rebuilds
# and reinstalls every time, which is exactly "safe to re-run")
# ---------------------------------------------------------------------
step "Building identity/'s Rust bridge (maturin develop)"
(
    cd identity/python
    "$VENV_DIR/bin/maturin" develop --release
) || fail "maturin develop failed" "check 'cargo build' alone works inside identity/ first — this is almost always a Rust toolchain issue, not a Callsign one"
ok "relay_identity built and installed into the venv"

# ---------------------------------------------------------------------
# Step 4: confirm the shared hosted registry is reachable. No local
# registry/Postgres startup here anymore — every install points at one
# always-on shared registry by default (see agent/cli.py's
# DEFAULT_REGISTRY_URL). Running your own registry instead is still
# possible (callsign switchboard, or `callsign setup --registry-url ...`)
# but is an explicit opt-in, not what a fresh install does.
# ---------------------------------------------------------------------
step "Checking the shared hosted registry is reachable"
if curl -fsSL -o /dev/null --max-time 60 "$DEFAULT_REGISTRY_URL/openapi.json"; then
    ok "hosted registry reachable at $DEFAULT_REGISTRY_URL"
else
    echo "  note: couldn't reach $DEFAULT_REGISTRY_URL just now — it may be waking from" \
         "an idle spin-down (free tier, can take ~50s). Continuing; 'callsign setup'" \
         "below will retry."
fi

# ---------------------------------------------------------------------
# Step 5: handle + registration (callsign setup does both in one call —
# the old separate init/register steps were unified upstream)
# ---------------------------------------------------------------------
HANDLE="${1:-}"
if [ -z "$HANDLE" ]; then
    if [ -t 0 ]; then
        read -r -p $'\nYour handle (e.g. your first name, lowercase, no spaces): ' HANDLE
    fi
fi
if [ -z "$HANDLE" ]; then
    fail "no handle given" "run: ./setup.sh <handle>   (e.g. ./setup.sh vivek)"
fi

step "Writing local config and registering @$HANDLE"
"$CALLSIGN_BIN" setup --handle "$HANDLE" --non-interactive \
    || fail "callsign setup failed" "if this is a re-run with a DIFFERENT identity than before, pass --force via: $CALLSIGN_BIN setup --handle $HANDLE --non-interactive --force"
ok "config written to ~/.callsign/config.toml"

# ---------------------------------------------------------------------
# Step 6: health check
# ---------------------------------------------------------------------
step "Confirming everything actually works"
MYNUMBER_OUTPUT="$("$CALLSIGN_BIN" mynumber)"
echo "$MYNUMBER_OUTPUT"
if echo "$MYNUMBER_OUTPUT" | grep -q "MISMATCH"; then
    fail "callsign mynumber reports a key mismatch" "the registered pubkey doesn't match this machine's local key — re-run with --force on callsign setup, or pick a different handle"
fi
if ! echo "$MYNUMBER_OUTPUT" | grep -q "relay_number:"; then
    fail "callsign mynumber did not report a relay_number — registration may not have completed" "run: $CALLSIGN_BIN setup --handle $HANDLE --non-interactive   then re-run this script"
fi
RELAY_NUMBER="$(echo "$MYNUMBER_OUTPUT" | awk -F': ' '/^relay_number:/ {print $2}')"

printf '\n\033[1;32m✓ Callsign is set up.\033[0m\n\n'
printf '  handle:       @%s\n' "$HANDLE"
printf '  relay number: %s   (give this out like a phone number)\n\n' "$RELAY_NUMBER"
printf '  Next: exchange relay numbers with a friend, then run:\n'
printf '    %s contacts add <name> <their-relay-number>\n' "$CALLSIGN_BIN"
printf '    %s call <name> "your question"\n\n' "$CALLSIGN_BIN"
