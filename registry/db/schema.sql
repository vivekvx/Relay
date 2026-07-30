-- Registry schema. PRD.md §4.2 "Audit trail" / §6 (Data Model).
--
-- Hard boundary (restated): this schema has NO column anywhere capable
-- of holding capsule content, document/excerpt text, or private key
-- material. identities.public_key_hex is exactly 64 lowercase hex
-- chars (32 bytes) — the shape of an Ed25519 public key; this cannot
-- structurally distinguish a public key from a private key of the same
-- length (both are 32 bytes), so it is not a defense against someone
-- deliberately submitting their private key here — see registry's
-- ARCHITECTURE.md for that limitation.
--
-- Idempotent: safe to re-run (CREATE ... IF NOT EXISTS / CREATE OR
-- REPLACE / DROP TRIGGER IF EXISTS then CREATE).

-- public_key_hex: Ed25519 signing public key (unchanged from before this
-- task — existing signature-verification code paths keep using this
-- column exactly as before). x25519_public_key_hex: the new encryption
-- public key, added so a sender can look up a recipient's key and
-- encrypt query content end-to-end (identity/ARCHITECTURE.md "Why two
-- keypairs"). Both columns use the same 64-hex-char shape check —
-- separate keys, same structural validation pattern.
-- relay_number: an OPAQUE routing identifier, separate from handle —
-- same category of data as handle (routing metadata, PRD.md §4.2), not
-- content, so it belongs in this table exactly like handle/public keys
-- already do; this does not widen the registry's hard boundary (see
-- registry/ARCHITECTURE.md). Server-generated at registration (never
-- client-supplied — a client choosing its own opaque id would let it
-- pick something guessable/colliding, or claim someone else's), 8 lower-
-- hex chars, same shape-check convention as public_key_hex.
CREATE TABLE IF NOT EXISTS identities (
    handle                  TEXT PRIMARY KEY,
    public_key_hex          TEXT NOT NULL CHECK (public_key_hex ~ '^[0-9a-f]{64}$'),
    x25519_public_key_hex   TEXT NOT NULL CHECK (x25519_public_key_hex ~ '^[0-9a-f]{64}$'),
    relay_number            TEXT NOT NULL UNIQUE CHECK (relay_number ~ '^[0-9a-f]{8}$'),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grants (
    id                  TEXT PRIMARY KEY,
    grantor             TEXT NOT NULL REFERENCES identities(handle),
    grantee             TEXT NOT NULL REFERENCES identities(handle),
    grant_type          TEXT NOT NULL CHECK (grant_type IN ('standing', 'ad_hoc')),
    scope_capsule_ids   TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants (grantee);

CREATE TABLE IF NOT EXISTS approval_requests (
    id                      TEXT PRIMARY KEY,
    sender                  TEXT NOT NULL REFERENCES identities(handle),
    recipient               TEXT NOT NULL REFERENCES identities(handle),
    candidate_capsule_ids   TEXT[] NOT NULL DEFAULT '{}',
    state                   TEXT NOT NULL DEFAULT 'pending'
                                CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,
    resolved_grant_id       TEXT REFERENCES grants(id)
);

-- Opaque relay envelope: the registry holds this only long enough to
-- deliver it to the recipient. `payload` is the identity module's
-- canonical byte encoding (sender/recipient/request_type/timestamp/
-- nonce ONLY — that format has no field for query text or capsule
-- content, so this table structurally cannot hold either in that
-- column).
--
-- `content_ciphertext` is the gap-closer: query/capsule-adjacent
-- content, encrypted end-to-end to the recipient's X25519 public key
-- BEFORE it ever reaches the registry (identity/'s encryption.rs). This
-- column is opaque to the registry BY CONSTRUCTION — the registry has
-- no X25519 private key material anywhere (see hard boundary in
-- ARCHITECTURE.md) and therefore cannot decrypt it under any code path,
-- not merely by convention of not trying to. No registry code parses,
-- inspects, or validates its structure — it is stored and relayed
-- byte-for-byte. The size CHECK below is a plausibility bound
-- (consistent with expected ciphertext sizes for short query text), not
-- content inspection.
CREATE TABLE IF NOT EXISTS pending_relay_queue (
    id                  TEXT PRIMARY KEY,
    sender              TEXT NOT NULL REFERENCES identities(handle),
    recipient           TEXT NOT NULL REFERENCES identities(handle),
    request_type        TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    request_ts          BIGINT NOT NULL,
    payload             BYTEA NOT NULL,
    signature_hex       TEXT NOT NULL,
    content_ciphertext  BYTEA
                            CHECK (content_ciphertext IS NULL OR octet_length(content_ciphertext) <= 65536),
    enqueued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pending_relay_recipient ON pending_relay_queue (recipient, delivered_at);

-- Replay defense (PRD.md §5 R6): uniqueness on (sender, nonce) is
-- enforced by the primary key itself, not just an application-level
-- check-then-insert (which would race).
CREATE TABLE IF NOT EXISTS nonce_log (
    sender      TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    request_ts  BIGINT NOT NULL,
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (sender, nonce)
);

-- Rate limiting (PRD.md §5 R3): event log, not a mutable counter row —
-- counted over a trailing 1-hour window at check time. Matches the
-- resolver's sliding-window approach for consistency.
CREATE TABLE IF NOT EXISTS rate_limit_events (
    id          BIGSERIAL PRIMARY KEY,
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_events_lookup ON rate_limit_events (sender, recipient, occurred_at);

-- Per-recipient override of the default limit — the capsule owner
-- configures their own limit (same pattern as approval expiry).
CREATE TABLE IF NOT EXISTS rate_limit_config (
    recipient       TEXT PRIMARY KEY REFERENCES identities(handle),
    limit_per_hour  INT NOT NULL CHECK (limit_per_hour > 0)
);

-- Approval expiry default override (approver-configurable, default 5h
-- applied in application code — PRD.md §6).
CREATE TABLE IF NOT EXISTS approval_expiry_config (
    recipient           TEXT PRIMARY KEY REFERENCES identities(handle),
    default_expiry_secs INT NOT NULL CHECK (default_expiry_secs > 0)
);

-- Audit log: metadata only (who/what/when/outcome), never content.
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sender      TEXT,
    recipient   TEXT,
    event_type  TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    detail      TEXT
);

-- Structural append-only guarantee: this trigger rejects UPDATE/DELETE
-- on audit_log regardless of which DB role issues the statement,
-- including the table owner. See ARCHITECTURE.md for what this does
-- and does not guarantee (a superuser can still `DROP TRIGGER`).
CREATE OR REPLACE FUNCTION reject_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation();
