# Manual two-terminal walkthrough (via the `relay` CLI)

Superseded the old raw `PYTHONPATH=agent python3 terminal_*.py` commands
now that `relay` is a real console script (see repo `README.md`). The
`friend-capsules/why-postgres-ratelimit.md` fixture and the two
`terminal_*.py` scripts are kept here for reference but the CLI path
below is the current one.

Registry running first (see repo `README.md` / earlier setup):
`uvicorn registry.app:app --port 8000`.

## Terminal A — @vivek

```bash
cd /Users/vivek/.superset/projects/Relay
source .venv/bin/activate
RELAY_CONFIG=scripts/manual-walkthrough/vivek-home/config.toml relay init \
  --handle vivek --capsule-dir scripts/manual-walkthrough/vivek-capsules \
  --registry-url http://localhost:8000 --key-dir scripts/manual-walkthrough/vivek-keys
RELAY_CONFIG=scripts/manual-walkthrough/vivek-home/config.toml relay register
RELAY_CONFIG=scripts/manual-walkthrough/vivek-home/config.toml relay ask friend \
  "why did you choose postgres over redis for rate limiting?"
```

## Terminal B — @friend

```bash
cd /Users/vivek/.superset/projects/Relay
source .venv/bin/activate
RELAY_CONFIG=scripts/manual-walkthrough/friend-home/config.toml relay init \
  --handle friend --capsule-dir scripts/manual-walkthrough/friend-capsules \
  --registry-url http://localhost:8000 --key-dir scripts/manual-walkthrough/friend-keys
RELAY_CONFIG=scripts/manual-walkthrough/friend-home/config.toml relay register
RELAY_CONFIG=scripts/manual-walkthrough/friend-home/config.toml relay listen
```

`RELAY_CONFIG` is the one deliberate escape hatch (see `agent/cli.py`'s
header comment) — it lets one machine run two identities for this test;
normally each person just runs `relay init`/`relay register`/`relay ask`
with no env var at all.

Known gap unchanged from the manual-script version: no `why matched:`
line or suggested-span shortcut appears in the approval prompt —
`wiring/flows.py::process_incoming_ask` still doesn't pass `match_info`
into `request_approval` (see `agent/ARCHITECTURE.md`).
