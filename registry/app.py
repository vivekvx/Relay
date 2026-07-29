# Composition root for the hosted registry (FastAPI + PostgreSQL).
# Responsibility per PRD.md §4.2 "Audit trail" / §7 Tech Stack:
# handle->endpoint resolution, public key storage, signed-request
# routing, and audit METADATA only — never capsule content.
# TODO: wire up api/, models/, db/ once implementation begins.
