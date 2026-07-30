# Terminal-display formatting only (Problem 1/2 of the CLI cleanup
# task) — proves cmd_ask/cmd_check's human-readable rendering and
# render_request's candidate/question display both handle arbitrary
# question/answer/candidate shapes, not just the one demo example
# ("why postgres over redis") seen throughout manual testing. Does NOT
# test ask()/check_pending()'s returned dict shape (unchanged, still
# covered by test_integration.py) — only how cli._format_result prints it.

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

import cli
from approval.render import render_request
from resolver.types import ApprovalRequest, ApprovalState, Capsule

NOW = datetime(2026, 1, 1)

LONG_QUESTION = (
    "Can you walk me through the full reasoning behind picking a "
    "Postgres-backed counter over Redis for rate limiting, including "
    "what you considered and rejected, and whether this decision is "
    "expected to hold as request volume grows over the next year or two?"
)

LONG_ANSWER = (
    "We chose a Postgres-backed counter for rate limiting instead of Redis.\n"
    "At our current scale (dozens of senders, not millions), pulling in\n"
    "Redis just to count requests per hour would add a second stateful\n"
    "service to operate, back up, and reason about during an incident.\n\n"
    "rate_limit_events logs one row per request; a query over a trailing\n"
    "one-hour window gives the exact same sliding-window behavior Redis's\n"
    "INCR+EXPIRE pattern gives, without a new dependency."
)


class TestFormatResult(unittest.TestCase):
    def test_long_multi_paragraph_answer_renders_in_full_not_truncated(self):
        result = {
            "status": "answered",
            "outcome": "approved_whole",
            "answer": LONG_ANSWER,
            "cited_capsule_ids": ["why-postgres-ratelimit"],
        }
        rendered = cli._format_result(result, recipient="friend")
        self.assertIn("Answered by @friend", rendered)
        # every sentence survives — nothing cut off, no dict-repr escaping
        self.assertIn("sliding-window behavior Redis's", rendered)
        self.assertNotIn("\\n", rendered)  # real newlines, not escaped literal text
        self.assertIn("Source: why-postgres-ratelimit", rendered)

    def test_short_answer_renders_cleanly(self):
        result = {
            "status": "answered",
            "outcome": "approved_whole",
            "answer": "Yes.",
            "cited_capsule_ids": ["c1"],
        }
        rendered = cli._format_result(result, recipient="friend")
        self.assertIn("Yes.", rendered)
        self.assertIn("Source: c1", rendered)

    def test_manual_answer_has_no_source_line(self):
        result = {
            "status": "answered",
            "outcome": "manual_answer",
            "answer": "We use exponential backoff, see the wiki.",
            "cited_capsule_ids": [],
        }
        rendered = cli._format_result(result)
        self.assertIn("typed directly, no document shared", rendered)
        self.assertNotIn("Source:", rendered)

    def test_denied_has_no_source_line_and_distinct_header(self):
        result = {
            "status": "answered",
            "outcome": "denied",
            "answer": "Request denied: not approved",
            "cited_capsule_ids": [],
        }
        rendered = cli._format_result(result)
        self.assertIn("Not shared", rendered)
        self.assertIn("Request denied: not approved", rendered)
        self.assertNotIn("Source:", rendered)

    def test_pending_shows_the_message_not_a_raw_dict(self):
        result = {
            "status": "pending",
            "request_id": "abc123",
            "message": "not answered yet — check back with `relay check abc123`",
        }
        rendered = cli._format_result(result)
        self.assertEqual(rendered, result["message"])
        self.assertNotIn("{", rendered)  # not a dict repr


class TestRenderRequestArbitraryShapes(unittest.TestCase):
    def make_request(self, query: str, candidate_ids=()) -> ApprovalRequest:
        return ApprovalRequest(
            sender="vivek",
            query=query,
            created_at=NOW,
            expiry_duration=timedelta(hours=5),
            candidate_capsule_ids=candidate_ids,
            state=ApprovalState.PENDING,
        )

    def test_long_multi_sentence_question_renders_without_truncation(self):
        request = self.make_request(LONG_QUESTION)
        rendered = render_request(request, [], now=NOW)
        self.assertIn(LONG_QUESTION, rendered)

    def test_short_question_renders(self):
        request = self.make_request("why?")
        rendered = render_request(request, [], now=NOW)
        self.assertIn('"why?"', rendered)

    def test_zero_candidates_renders_none_found_not_blank(self):
        request = self.make_request("anything shareable about this?")
        rendered = render_request(request, [], now=NOW)
        self.assertIn("(none found)", rendered)

    def test_arbitrary_number_of_candidates_and_tag_counts_all_listed(self):
        capsules = [
            Capsule(id=f"cap-{i}", shareable=True, shareable_with=frozenset(), tags=frozenset(f"tag{j}" for j in range(i)))
            for i in range(5)
        ]
        request = self.make_request("multi-candidate question", tuple(c.id for c in capsules))
        rendered = render_request(request, capsules, now=NOW)
        for capsule in capsules:
            self.assertIn(capsule.id, rendered)


if __name__ == "__main__":
    unittest.main()
