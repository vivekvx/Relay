# Decision-type definitions owned by this module. No IO, no logic beyond
# cheap structural invariants — see interaction.py for rendering and input
# capture.
#
# Inputs (ApprovalRequest, Capsule, ApprovalState) are NOT redefined here —
# they're imported directly from resolver.types, the real, already-built
# contract. See ARCHITECTURE.md "Built against real resolver types" for
# confirmation.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto

from resolver.types import ApprovalRequest, ApprovalState, Capsule

__all__ = [
    "ApprovalRequest",
    "ApprovalState",
    "Capsule",
    "Outcome",
    "ExcerptBounds",
    "ApprovalDecision",
    "GrantPromotion",
]


class Outcome(Enum):
    """Finer-grained than resolver.types.ApprovalState on purpose: the
    resolver only needs to know PENDING/APPROVED/DENIED/EXPIRED for grant
    bookkeeping, but the approver's actual choice — whole doc vs. excerpt
    vs. manual answer — changes what content (if any) may leave this
    machine, so this module needs to preserve that distinction."""

    APPROVED_WHOLE = auto()
    APPROVED_EXCERPT = auto()
    DENIED = auto()
    MANUAL_ANSWER = auto()
    EXPIRED = auto()


@dataclass(frozen=True)
class ExcerptBounds:
    capsule_id: str
    start: int
    end: int


@dataclass(frozen=True)
class ApprovalDecision:
    outcome: Outcome
    approved_capsule_ids: tuple[str, ...] = ()  # set only for APPROVED_WHOLE
    excerpt: ExcerptBounds | None = None  # set only for APPROVED_EXCERPT
    manual_answer: str | None = None  # set only for MANUAL_ANSWER
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        # ponytail: cheap shape check, not a validation framework — catches
        # a caller constructing a decision with the wrong fields for its
        # outcome before it ever reaches the (later, out-of-scope) persistence
        # layer.
        if self.outcome is Outcome.APPROVED_WHOLE and not self.approved_capsule_ids:
            raise ValueError("APPROVED_WHOLE requires approved_capsule_ids")
        if self.outcome is Outcome.APPROVED_EXCERPT and self.excerpt is None:
            raise ValueError("APPROVED_EXCERPT requires excerpt bounds")
        if self.outcome is Outcome.MANUAL_ANSWER and not self.manual_answer:
            raise ValueError("MANUAL_ANSWER requires manual_answer text")


@dataclass(frozen=True)
class GrantPromotion:
    """Standing-grant promotion, offered after a decision — structurally
    separate from ApprovalDecision on purpose. "I approved this one request"
    and "I'm creating a standing grant" are different security actions with
    different blast radii; they must never be collapsed into one return
    type's optional field.
    """

    grantee_handle: str
    scope_description: str
    capsule_ids: tuple[str, ...]
