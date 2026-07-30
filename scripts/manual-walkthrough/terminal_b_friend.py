"""Terminal B (@friend). Thin runner: calls existing wiring.flows functions
only, no new application logic. Registers @friend if needed, then blocks
in run_poll_loop with the REAL terminal input()/print() (no injected
input_fn/output_fn) so the approval prompt actually appears here and
actually reads what you type."""

import os

from resolver.rate_limiter import RateLimiter
from wiring.flows import PendingResponseRegistry, run_poll_loop
from wiring.local_state import LocalIdentity
from wiring.registry_client import RegistryClient, RegistryRejection

KEY_DIR = "/Users/vivek/.superset/projects/Relay/scripts/manual-walkthrough/friend-keys"
CAPSULE_DIR = os.environ.get(
    "RELAY_CAPSULE_DIR",
    "/Users/vivek/.superset/projects/Relay/scripts/manual-walkthrough/friend-capsules",
)
REGISTRY_URL = "http://localhost:8000"

identity = LocalIdentity.load_or_create("friend", KEY_DIR)
registry = RegistryClient.create(REGISTRY_URL)

try:
    registry.register_identity(identity.handle, identity.public_key_hex, identity.encryption_public_key_hex)
    print(f"registered @friend (pubkey {identity.public_key_hex[:12]}...)")
except RegistryRejection as e:
    if e.outcome == "duplicate_handle":
        print("@friend already registered, continuing")
    else:
        raise

rate_limiter = RateLimiter()
response_registry = PendingResponseRegistry()  # unused on this side, run_poll_loop requires it

print("listening for incoming asks every 2s (Ctrl+C to stop)...")
run_poll_loop(identity, registry, CAPSULE_DIR, rate_limiter, response_registry, interval_secs=2.0)
