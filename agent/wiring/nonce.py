# Nonce generation for outgoing signed requests. identity's contract
# (payload.rs's NONCE_HEX_LEN / is_nonce_well_formed, mirrored by
# relay_identity's PyO3 bridge and registry's grant_payload.py): exactly
# 32 lowercase hex characters (16 random bytes). Cryptographically
# random — secrets.token_hex uses the OS CSPRNG, same trust level as
# identity's own key generation (rand::rng()/OsRng).

import secrets

NONCE_HEX_LEN = 32


def generate_nonce() -> str:
    return secrets.token_hex(NONCE_HEX_LEN // 2)
