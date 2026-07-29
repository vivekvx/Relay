# Composition root for the hosted registry (FastAPI + PostgreSQL).
# PRD.md §4.2 "Audit trail" / §7 Tech Stack: handle->endpoint
# resolution, public key storage, signed-request routing, and audit
# METADATA only — never capsule content. See registry/ARCHITECTURE.md
# for the hard boundary this component enforces.

from fastapi import FastAPI

from registry.api import (
    approval_routes,
    audit_routes,
    grant_routes,
    identity_routes,
    relay_routes,
)

app = FastAPI(title="Relay Registry")

app.include_router(identity_routes.router)
app.include_router(relay_routes.router)
app.include_router(grant_routes.router)
app.include_router(approval_routes.router)
app.include_router(audit_routes.router)
