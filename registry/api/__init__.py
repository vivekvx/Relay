# Routes: identity registration, signed-request relay/queueing, and
# audit read endpoints (metadata only). Per PRD.md §4.2 "Audit trail"
# and §3 (Core User Flows) — registry role is routing only, never
# content. TODO: implement route handlers, service-layer separation
# per CLAUDE.md §5 (no fat route handlers).
