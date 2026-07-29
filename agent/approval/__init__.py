# Terminal-based approval UI, plus Approval Request expiry/auto-deny
# logic. Per PRD.md §3.2 (Ad Hoc Approval Flow) and §6 (Approval
# Request data model): approver-configurable `expiry_duration`
# (default 5 hours), whole-doc and excerpt-level approval, and
# auto-deny on expiry — this behavior is not configurable and must
# never silently grant access.
#
# See ARCHITECTURE.md for the decision-object contract and the one known
# upstream gap (resolver.search_candidates carries no match-reason/span).

from .interaction import request_approval, request_grant_promotion
from .types import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalState,
    Capsule,
    ExcerptBounds,
    GrantPromotion,
    Outcome,
)

__all__ = [
    "request_approval",
    "request_grant_promotion",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalState",
    "Capsule",
    "ExcerptBounds",
    "GrantPromotion",
    "Outcome",
]
