"""Terminal A (@vivek). Thin runner: calls existing wiring.flows functions
only, no new application logic. Registers @vivek if needed, starts a
background poll loop (to receive the ask_response), then sends one real
`ask` to @friend and prints whatever comes back."""

import sys
import threading

from resolver.rate_limiter import RateLimiter
from wiring.flows import PendingResponseRegistry, ask, run_poll_loop
from wiring.local_state import LocalIdentity
from wiring.registry_client import RegistryClient, RegistryRejection

KEY_DIR = "/Users/vivek/.superset/projects/Relay/scripts/manual-walkthrough/vivek-keys"
REGISTRY_URL = "http://localhost:8000"

identity = LocalIdentity.load_or_create("vivek", KEY_DIR)
registry = RegistryClient.create(REGISTRY_URL)

try:
    registry.register_identity(identity.handle, identity.public_key_hex, identity.encryption_public_key_hex)
    print(f"registered @vivek (pubkey {identity.public_key_hex[:12]}...)")
except RegistryRejection as e:
    if e.outcome == "duplicate_handle":
        print("@vivek already registered, continuing")
    else:
        raise

rate_limiter = RateLimiter()
response_registry = PendingResponseRegistry()

# Background poll loop: the only thing that will ever deliver @friend's
# ask_response back into response_registry for ask() to pick up.
poll_thread = threading.Thread(
    target=run_poll_loop,
    args=(identity, registry, "/nonexistent-capsule-dir-vivek-has-none", rate_limiter, response_registry),
    kwargs={"interval_secs": 2.0},
    daemon=True,
)
poll_thread.start()

question = sys.argv[1] if len(sys.argv) > 1 else "why did you choose postgres over redis for rate limiting?"
print(f'asking @friend: "{question}"')
print("(waiting up to 5 minutes for @friend to approve in Terminal B...)")

result = ask(
    identity,
    registry,
    "friend",
    question,
    response_registry,
    wait_attempts=60,
    wait_interval=5.0,
)

print("\n=== result ===")
print(result)
