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

    def test_refresh_requires_explicit_policy(self):
        # Infrastructure names are not authority; missing and explicit deny win.
        empty = {}
        some_policy = {"tools": {"gcal": {"refresh": "deny"}}}
        for op in ("refresh", "refresh_one"):
            self.assertEqual(policy.decide(empty, "gcal", op), policy.DENY)
            self.assertEqual(policy.decide(some_policy, "gcal", op), policy.DENY)
            explicit = {"tools": {"gcal": {op: "allow"}}}
            self.assertEqual(policy.decide(explicit, "gcal", op), policy.ALLOW)


if __name__ == "__main__":
    unittest.main()
