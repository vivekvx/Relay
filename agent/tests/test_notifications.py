# Unit tests for wiring/notifications.py — subprocess.run is mocked so
# running this suite never actually pops a real macOS notification.

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from wiring.notifications import notify_new_approval_request


class TestNotifyNewApprovalRequest(unittest.TestCase):
    @patch("wiring.notifications.subprocess.run")
    def test_success_returns_true_and_includes_sender_and_query(self, mock_run):
        mock_run.return_value.returncode = 0
        result = notify_new_approval_request("vivek", "why postgres over redis?")
        self.assertTrue(result)
        script = mock_run.call_args.args[0][2]  # ["osascript", "-e", script]
        self.assertIn("vivek", script)
        self.assertIn("why postgres over redis?", script)
        self.assertIn("relay pending", script)

    @patch("wiring.notifications.subprocess.run")
    def test_nonzero_returncode_returns_false(self, mock_run):
        mock_run.return_value.returncode = 1
        self.assertFalse(notify_new_approval_request("vivek", "q"))

    @patch("wiring.notifications.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_osascript_returns_false_not_raise(self, mock_run):
        self.assertFalse(notify_new_approval_request("vivek", "q"))

    @patch("wiring.notifications.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="osascript", timeout=5))
    def test_timeout_returns_false_not_raise(self, mock_run):
        self.assertFalse(notify_new_approval_request("vivek", "q"))

    @patch("wiring.notifications.subprocess.run")
    def test_query_with_quotes_is_escaped_not_broken(self, mock_run):
        mock_run.return_value.returncode = 0
        notify_new_approval_request("vivek", 'what about "this" specifically?')
        script = mock_run.call_args.args[0][2]
        self.assertIn('\\"this\\"', script)


if __name__ == "__main__":
    unittest.main()
