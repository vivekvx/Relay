# Pydantic API request/response schemas. PRD.md §6 (Data Model).
#
# `model_config = {"extra": "forbid"}` on every request body is a
# structural defense (framework-enforced, not hand-rolled): an incoming
# payload with an unexpected extra field (e.g. a client mistakenly or
# maliciously attaching "content"/"excerpt"/"document") is rejected by
# Pydantic itself before any handler code runs.

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RegisterIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    handle: str = Field(min_length=1, max_length=64)
    public_key_hex: str = Field(pattern=r"^[0-9a-f]{64}$")  # Ed25519, signing
    x25519_public_key_hex: str = Field(pattern=r"^[0-9a-f]{64}$")  # X25519, encryption


class RelaySubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload_hex: str  # identity module's canonical byte encoding, hex
    signature_hex: str = Field(pattern=r"^[0-9a-f]{128}$")  # 64-byte Ed25519 sig
    # Opaque, end-to-end encrypted to the recipient's X25519 public key
    # before it ever reaches the registry — never parsed/inspected here.
    content_ciphertext_hex: str | None = None


class PendingRelayItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    sender: str
    recipient: str
    request_type: str
    nonce: str
    request_ts: int
    payload_hex: str
    signature_hex: str
    content_ciphertext_hex: str | None = None
    enqueued_at: datetime
    delivered_at: datetime | None = None


class CreateGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grantor: str
    grantee: str
    grant_type: str = Field(pattern=r"^(standing|ad_hoc)$")
    scope_capsule_ids: list[str] = Field(default_factory=list)
    expires_at: datetime | None = None
    timestamp: int
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    signature_hex: str = Field(pattern=r"^[0-9a-f]{128}$")


class RevokeGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grant_id: str
    timestamp: int
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    signature_hex: str = Field(pattern=r"^[0-9a-f]{128}$")


class CreateApprovalRequestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sender: str
    recipient: str
    candidate_capsule_ids: list[str] = Field(default_factory=list)
    expiry_secs_override: int | None = None


class ResolveApprovalRequestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval_request_id: str
    decision: str = Field(pattern=r"^(approved|denied)$")
