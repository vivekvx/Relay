# Relay

A "phone number" for your coding agent — lets your Claude Code / terminal
agent ask another person's agent a question, with the responding agent
sharing only an explicitly human-approved slice of context, never a raw
memory dump. See `PRD.md` for the full spec and `CLAUDE.md` for agent
operating instructions before writing any code in this repo.

## Quick Start

The whole point of Relay is that a friend gets their own local Relay set
up in one message, not by manually running a dozen commands. Two ways to
do it — pick whichever you're comfortable with, both are fully supported:

**Option A — one-line install.** Paste this into your own terminal
(replace `<handle>` with a handle for yourself, e.g. your first name):

```
curl -fsSL https://raw.githubusercontent.com/vivekvx/Relay/main/install.sh | bash -s <handle>
```

`install.sh` is a short, readable script — clone it and read it yourself
first if you'd rather not pipe curl straight into bash (a reasonable
thing to want): https://github.com/vivekvx/Relay/blob/main/install.sh.
It does exactly one thing: clone Relay into `~/relay`, then run
`setup.sh <handle>` from inside it. No other network calls, no
telemetry, nothing hidden.

**Option B — clone and read first.** If you'd rather review everything
before running anything, or someone sent you this repo to set up
yourself, paste this to your own coding agent (Claude Code, Codex,
Antigravity — any of them; nothing below assumes which one):

> Clone https://github.com/vivekvx/Relay.git, run `./setup.sh <a
> handle for me, e.g. my first name>` from inside it, and tell me my
> Relay handle and relay number once it's done.

Both options land in the same place. `setup.sh` creates a Python venv,
installs dependencies, builds `identity/`'s Rust bridge, registers your
identity with the shared hosted registry, and confirms everything with a
real health check. It's idempotent — safe to re-run if anything fails
partway.

Your identity, private keys, and capsules stay 100% local to your own
machine — never uploaded anywhere. Only routing (handle → endpoint) and
audit metadata (who queried whom, when) live on the shared registry;
capsule content and query/response text never do (see `PRD.md` §4 for
the hard boundary). Running your own registry instead of the shared one
is possible (`relay serve-registry`, or `relay init --registry-url ...`)
but is an explicit opt-in for advanced/private use, not what a normal
install does.

**Requires** (macOS only for this pass — Linux/Windows setup is a
known, stated gap, not silently unsupported): Python 3.12+ and
Rust/cargo. `setup.sh` checks for each and prints the exact `brew`/
`rustup` command to install whichever is missing, then stops with a
clear, specific message rather than a raw crash — safe for your agent
to read the output, fix the one missing thing, and re-run. (PostgreSQL
is only needed if you opt into running your own registry instead of the
shared hosted one — see "Running the registry locally" below.)

Once it's done, give your **relay number** (not your handle — it's an
opaque routing id, same trust model as a phone number) to a friend out
of band (text, Slack, in person), and save theirs:

```
relay contacts add <name> <their-relay-number>
relay ask <name> "your question"
```

The rest of this README is reference detail for the same CLI/MCP
surface `setup.sh` just set up for you.

## CLI

```
cd agent && ../.venv/bin/pip install -e .
relay serve-registry        # one-time+: starts the local registry, detached, own Postgres — see below
relay init                  # one-time: writes ~/.relay/config.toml (handle, capsule dir, registry URL)
relay register              # publishes your public keys to the registry
relay whoami                 # confirms your local key actually matches what's registered
relay ask <handle> "question"
relay check <request_id>     # follow up on a "pending" ask later
relay listen                 # blocks, answers incoming asks with a live terminal approval prompt
relay grant <handle> --scope <capsule-id,...>
relay grants <handle>        # look up a grant_id to revoke
relay revoke <grant_id>
```

## Running the registry locally

`relay serve-registry` starts the registry detached (`setsid`-style —
survives the launching terminal closing) on **its own dedicated port and
Postgres cluster**, not the common defaults (8000 / 5432). This is
deliberate: on a dev machine running other projects, those default
ports are exactly where an unrelated project's Docker container is
likely already listening — which happened during this project's own
development (an unrelated FastAPI backend was silently answering
Relay's health checks on port 8000 for days before anyone noticed,
because both apps' generic 404 responses looked alike).

- API: `http://localhost:8088` (override with `--port`). Bound to
  `127.0.0.1` by default — not reachable from other devices on your
  network, only this machine. To let another device on your LAN reach
  it, pass `--host 0.0.0.0` or set `RELAY_REGISTRY_HOST=0.0.0.0`:
  `relay serve-registry --host 0.0.0.0`. This is real network exposure,
  opt-in only — anyone on the same network can then reach these HTTP
  endpoints (still rate-limited, still routing/audit metadata only, per
  this project's non-negotiable no-capsule-content boundary — the
  security model doesn't change, only who can reach the door).
- Postgres: a dedicated cluster at `~/.relay/pgdata`, port `5544`,
  database `relay_registry` (override with `--database-url`)
- Logs: `~/.relay/registry.log` (API), `~/.relay/pg.log` (Postgres)
- PID: `~/.relay/registry.pid`

```
relay serve-registry     # idempotent — says "already running" if it is
relay registry-status    # reachable? pid? verified as Relay specifically,
                          # not just "something answered" (see note above)
```

`registry-status`/`serve-registry`'s reachability check verifies the
OpenAPI title is literally `"Relay Registry"` — not just that some HTTP
server 404s on an unknown route, which is what let the MandateCheck
collision go unnoticed.

## Using Relay from inside your coding agent (MCP)

`agent/mcp_server.py` is a standard MCP server: it speaks JSON-RPC over
stdio, exposes `relay_ask`/`relay_grant`/`relay_revoke`/`relay_check`/
`relay_pending_requests`/`relay_respond_to_request` with plain JSON
Schema `inputSchema`s, and returns results as standard text
content-blocks. Nothing in it is Claude-Code-specific — it's been
verified working against Claude Code and against a real Antigravity/
Gemini agent session (raw `initialize` → `tools/list` → `tools/call`
handshake plus a live tool call through `agy -p`). Every client below
launches the exact same command; only the config file format/location
differs.

The command and env every client needs (fill in your own paths/handle):

```
command: /absolute/path/to/Relay/.venv/bin/python3
args:    ["/absolute/path/to/Relay/agent/mcp_server.py"]
env:
  PYTHONPATH:          /absolute/path/to/Relay/agent
  RELAY_HANDLE:        your-handle
  RELAY_KEY_DIR:       /absolute/path/to/keys/dir
  RELAY_CAPSULE_DIR:   /absolute/path/to/capsules/dir
  RELAY_REGISTRY_URL:  https://relay-registry.onrender.com
```

### Claude Code

Project-scoped: create `.mcp.json` in the repo root:

```json
{
  "mcpServers": {
    "relay": {
      "command": "/absolute/path/to/Relay/.venv/bin/python3",
      "args": ["/absolute/path/to/Relay/agent/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/Relay/agent",
        "RELAY_HANDLE": "your-handle",
        "RELAY_KEY_DIR": "/absolute/path/to/keys/dir",
        "RELAY_CAPSULE_DIR": "/absolute/path/to/capsules/dir",
        "RELAY_REGISTRY_URL": "https://relay-registry.onrender.com"
      }
    }
  }
}
```

Restart Claude Code (or run `/mcp` to reconnect) after adding this.

### Antigravity (and the Gemini CLI, which shares the same config)

Global, not project-scoped: add a `relay` entry under `mcpServers` in
`~/.gemini/antigravity/mcp_config.json` (this is a symlink to the real
file at `~/.gemini/config/mcp_config.json`, shared with the Gemini
CLI — one entry registers Relay for both):

```json
{
  "mcpServers": {
    "relay": {
      "command": "/absolute/path/to/Relay/.venv/bin/python3",
      "args": ["/absolute/path/to/Relay/agent/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/Relay/agent",
        "RELAY_HANDLE": "your-handle",
        "RELAY_KEY_DIR": "/absolute/path/to/keys/dir",
        "RELAY_CAPSULE_DIR": "/absolute/path/to/capsules/dir",
        "RELAY_REGISTRY_URL": "https://relay-registry.onrender.com"
      }
    }
  }
}
```

Restart Antigravity (or start a new agent session) after adding this.

### Any other MCP-compliant client

Config file format is not standardized across vendors, but the server
itself is: point your client's MCP config at the same `command`/`args`/
`env` shown above, however that client expresses it (most use a
`mcpServers` map like the two above; check your client's docs for the
exact file/location).

### Behavior once connected

Asking your agent something like "ask @friend why they chose postgres
over redis" calls the real `relay_ask` tool, which runs the exact same
`wiring/flows.py` code the CLI and registry use — no terminal script
involved.

Note: `relay_ask`'s MCP tool call only waits ~5 seconds for a live
answer (`dispatch_tool_call`'s default); if the other side hasn't
approved yet, it returns `{"status": "pending", ...}` — the answer
still arrives once approved, but this one-shot MCP call has already
returned by then. See `scripts/manual-walkthrough/` for the standing
two-terminal test setup.
