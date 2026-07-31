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
installs dependencies, builds `identity/`'s Rust bridge, starts your own
local registry (on dedicated ports 8088/5544 — never the common
8000/5432 defaults, which collide with other projects' Docker containers
on real dev machines), registers your identity, and confirms everything
with a real health check. It's idempotent — safe to re-run if anything
fails partway.

**Requires** (macOS only for this pass — Linux/Windows setup is a
known, stated gap, not silently unsupported): Python 3.12+, Rust/cargo,
and PostgreSQL binaries. `setup.sh` checks for each and prints the exact
`brew`/`rustup` command to install whichever is missing, then stops
with a clear, specific message rather than a raw crash — safe for your
agent to read the output, fix the one missing thing, and re-run.

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

- API: `http://localhost:8088` (override with `--port`)
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

## Using Relay from inside Claude Code (MCP)

`agent/mcp_server.py` exposes `relay_ask`/`relay_grant`/`relay_revoke` as
MCP tools over stdio. Register it as a project-scoped MCP server by
creating `.mcp.json` in the repo root:

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
        "RELAY_REGISTRY_URL": "http://localhost:8088"
      }
    }
  }
}
```

Restart Claude Code (or run `/mcp` to reconnect) after adding this.
Once connected, asking Claude Code something like "ask @friend why they
chose postgres over redis" calls the real `relay_ask` tool, which runs
the exact same `wiring/flows.py` code the CLI and registry use — no
terminal script involved.

Note: `relay_ask`'s MCP tool call only waits ~5 seconds for a live
answer (`dispatch_tool_call`'s default); if the other side hasn't
approved yet, it returns `{"status": "pending", ...}` — the answer
still arrives once approved, but this one-shot MCP call has already
returned by then. See `scripts/manual-walkthrough/` for the standing
two-terminal test setup.
