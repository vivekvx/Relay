# Minimal stdlib logging, not structlog (CLAUDE.md §4: no new framework/
# dependency without asking first — stdlib is the only unilateral choice
# available). Emits key=value lines to stdout; Render captures container
# stdout as logs natively, no extra plumbing needed on that side.
#
# Hard boundary, unchanged: callers of this logger must never pass
# capsule content, query text, or response text as a field value
# (CLAUDE.md §2) — only handles, outcomes, sizes, and trace/nonce ids.

import logging
import sys


class KVFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"event={record.getMessage()} logger={record.name}"
        extra = getattr(record, "kv", None)
        if extra:
            base += " " + " ".join(f"{k}={v}" for k, v in extra.items())
        return base


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(KVFormatter())
    root = logging.getLogger("registry")
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    root.propagate = False
