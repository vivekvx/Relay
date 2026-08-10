# Shared local-state path constants. Moved out of cli.py so both cli.py
# and mcp_server.py import the same values from wiring/ rather than one
# importing from the other (mcp_server.py must not depend on cli.py —
# wrong dependency direction, cli.py is the CLI entrypoint, not a
# library).

from pathlib import Path

REGISTRY_HOME = Path.home() / ".relay"
SERVE_PID_FILE = REGISTRY_HOME / "serve.pid"
SERVE_META_FILE = REGISTRY_HOME / "serve.json"  # {"pid": ..., "started_at": isoformat}
SERVE_LOG_FILE = REGISTRY_HOME / "serve.log"
