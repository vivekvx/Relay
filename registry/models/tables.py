# SQLAlchemy Core table definitions mirroring db/schema.sql exactly.
# Core (not ORM classes) — this is a thin metadata layer for building
# typed queries in the services layer; schema.sql is the source of
# truth for constraints/triggers, this just needs to agree with it on
# column names/types. PRD.md §6 (Data Model).

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Column,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    DateTime,
)

metadata = MetaData()

identities = Table(
    "identities",
    metadata,
    Column("handle", Text, primary_key=True),
    Column("public_key_hex", Text, nullable=False),  # Ed25519, signing — unchanged
    Column("x25519_public_key_hex", Text, nullable=False),  # X25519, encryption — new
    Column("created_at", DateTime(timezone=True), nullable=False),
)

grants = Table(
    "grants",
    metadata,
    Column("id", Text, primary_key=True),
    Column("grantor", Text, ForeignKey("identities.handle"), nullable=False),
    Column("grantee", Text, ForeignKey("identities.handle"), nullable=False),
    Column("grant_type", Text, nullable=False),
    Column("scope_capsule_ids", ARRAY(Text), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("revoked_at", DateTime(timezone=True), nullable=True),
)

approval_requests = Table(
    "approval_requests",
    metadata,
    Column("id", Text, primary_key=True),
    Column("sender", Text, ForeignKey("identities.handle"), nullable=False),
    Column("recipient", Text, ForeignKey("identities.handle"), nullable=False),
    Column("candidate_capsule_ids", ARRAY(Text), nullable=False),
    Column("state", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("resolved_grant_id", Text, ForeignKey("grants.id"), nullable=True),
)

pending_relay_queue = Table(
    "pending_relay_queue",
    metadata,
    Column("id", Text, primary_key=True),
    Column("sender", Text, ForeignKey("identities.handle"), nullable=False),
    Column("recipient", Text, ForeignKey("identities.handle"), nullable=False),
    Column("request_type", Text, nullable=False),
    Column("nonce", Text, nullable=False),
    Column("request_ts", BigInteger, nullable=False),
    Column("payload", LargeBinary, nullable=False),
    Column("signature_hex", Text, nullable=False),
    Column("content_ciphertext", LargeBinary, nullable=True),  # opaque, see schema.sql
    Column("enqueued_at", DateTime(timezone=True), nullable=False),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
)

nonce_log = Table(
    "nonce_log",
    metadata,
    Column("sender", Text, primary_key=True),
    Column("nonce", Text, primary_key=True),
    Column("request_ts", BigInteger, nullable=False),
    Column("seen_at", DateTime(timezone=True), nullable=False),
)

rate_limit_events = Table(
    "rate_limit_events",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("sender", Text, nullable=False),
    Column("recipient", Text, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
)

rate_limit_config = Table(
    "rate_limit_config",
    metadata,
    Column("recipient", Text, ForeignKey("identities.handle"), primary_key=True),
    Column("limit_per_hour", Integer, nullable=False),
)

approval_expiry_config = Table(
    "approval_expiry_config",
    metadata,
    Column("recipient", Text, ForeignKey("identities.handle"), primary_key=True),
    Column("default_expiry_secs", Integer, nullable=False),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("sender", Text, nullable=True),
    Column("recipient", Text, nullable=True),
    Column("event_type", Text, nullable=False),
    Column("outcome", Text, nullable=False),
    Column("detail", Text, nullable=True),
)
