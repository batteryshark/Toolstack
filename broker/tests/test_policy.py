"""Policy decisions: allow / review / deny, with default-deny."""

import unittest

from broker import policy

POLICY = {"tools": {"echo": {"say": "allow", "shout": "review"}}}


class Decide(unittest.TestCase):
    def test_allow(self):
        self.assertEqual(policy.decide(POLICY, "echo", "say"), policy.ALLOW)

    def test_review(self):
        self.assertEqual(policy.decide(POLICY, "echo", "shout"), policy.REVIEW)

    def test_missing_op_denies(self):
        self.assertEqual(policy.decide(POLICY, "echo", "delete"), policy.DENY)

    def test_missing_tool_denies(self):
        self.assertEqual(policy.decide(POLICY, "db", "read"), policy.DENY)

    def test_empty_policy_denies(self):
        self.assertEqual(policy.decide({}, "echo", "say"), policy.DENY)

    def test_unknown_effect_denies(self):
        self.assertEqual(policy.decide({"tools": {"x": {"y": "maybe"}}}, "x", "y"), policy.DENY)

    def test_refresh_op_auto_allowed_for_any_caller(self):
        # refresh + refresh_one are broker-injected infrastructure ops; a per-caller
        # policy gate would force every operator to remember to grant them and there
        # is no scenario where a caller should be denied a secret-cache refresh. The
        # audit log still records every dispatch.
        empty = {}
        some_policy = {"tools": {"gcal": {"refresh": "deny"}}}  # explicit deny is overridden
        for op in ("refresh", "refresh_one"):
            self.assertEqual(policy.decide(empty, "gcal", op), policy.ALLOW)
            self.assertEqual(policy.decide(some_policy, "gcal", op), policy.ALLOW)


if __name__ == "__main__":
    unittest.main()
