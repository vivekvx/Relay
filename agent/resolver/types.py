# Input/output shapes for the resolver, matching PRD.md §6 (Data Model)
# for Capsule, Grant, and ApprovalRequest. Minimal dataclasses — the
# real capsule/grant persistence lives in agent/capsules/ and the
# registry (out of scope here); these are the in-memory contracts the
# resolver operates on per this task's scope.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class GrantType(Enum):
    STANDING = "standing"
    AD_HOC = "ad_hoc"


class ApprovalState(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(frozen=True)
class SenderIdentity:
    """Already-authenticated sender handle (signature verification is the
    identity module's job, out of scope here — PRD.md §4.2 Identity layer)."""
    handle: str


@dataclass(frozen=True)
class Capsule:
    id: str
    shareable: bool
    shareable_with: frozenset[str]  # handles allowed to receive this capsule
    tags: frozenset[str] = field(default_factory=frozenset)
    content: str = ""  # used only by candidate search, never by scope resolution


@dataclass(frozen=True)
class Grant:
    type: GrantType
    grantor: str
    grantee: str
    capsule_ids: frozenset[str]
    revoked: bool = False
    expires_at: datetime | None = None  # None = no expiry (standing, until revoked)

    def is_valid(self, now: datetime) -> bool:
        """Checked at capsule-load time, not cached from request start —
        PRD.md §3.1 step 8 (revocation-race requirement)."""
        if self.revoked:
            return False
        if self.expires_at is not None and now >= self.expires_at:
            return False
        return True


@dataclass(frozen=True)
class ApprovalRequest:
    sender: str
    query: str
    created_at: datetime
    expiry_duration: timedelta
    candidate_capsule_ids: tuple[str, ...] = ()
    state: ApprovalState = ApprovalState.PENDING

    @property
    def expires_at(self) -> datetime:
        return self.created_at + self.expiry_duration

    def resolved_state(self, now: datetime) -> ApprovalState:
        """On expiry with no response, resolves to DENIED — auto-deny,
        never a silent grant. PRD.md §6 Approval Request."""
        if self.state == ApprovalState.PENDING and now >= self.expires_at:
            return ApprovalState.DENIED
        return self.state
