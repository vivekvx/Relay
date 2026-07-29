# THE deterministic scope-resolution component.
#
# MUST NEVER invoke an LLM, at any step, including candidate-document
# search for the ad hoc approval flow. See PRD.md §5 Requirements R1,
# R7, R8, and CLAUDE.md §2 (Non-negotiable invariants) — scope
# resolution must be complete, deterministic, and finished before any
# LLM call. Also re-validates grant/approval status at capsule-load
# time (PRD.md §3.1 step 8, §4.2 component 3) — a revocation must take
# effect immediately, not only at request intake.
#
# TODO: implementation.
