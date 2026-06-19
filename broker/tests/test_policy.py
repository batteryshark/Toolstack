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


class PathScoped(unittest.TestCase):
    """Rest tools: keys may scope by path glob; most-specific wins, ties most-restrictive,
    default-deny. (api/mcp keys, having no path part, are unaffected — see Decide.)"""

    P = {"tools": {"kv": {
        "GET /items/**": "allow",
        "GET /items/secret": "deny",     # carve a hole inside the broader allow
        "DELETE /items/**": "review",
        "POST": "allow",                 # bare verb = any path
    }}}

    def d(self, op, path):
        return policy.decide(self.P, "kv", op, path)

    def test_glob_allows_matching_path(self):
        self.assertEqual(self.d("GET", "/items/42"), policy.ALLOW)

    def test_more_specific_deny_overrides_broader_allow(self):
        self.assertEqual(self.d("GET", "/items/secret"), policy.DENY)

    def test_unmatched_path_denies(self):
        self.assertEqual(self.d("GET", "/admin/x"), policy.DENY)

    def test_review_rule_matches(self):
        self.assertEqual(self.d("DELETE", "/items/42"), policy.REVIEW)

    def test_bare_verb_matches_any_path(self):
        self.assertEqual(self.d("POST", "/anything/at/all"), policy.ALLOW)

    def test_single_star_stays_within_one_segment(self):
        p = {"tools": {"kv": {"GET /items/*": "allow"}}}
        self.assertEqual(policy.decide(p, "kv", "GET", "/items/42"), policy.ALLOW)
        self.assertEqual(policy.decide(p, "kv", "GET", "/items/42/sub"), policy.DENY)

    def test_double_star_spans_segments(self):
        p = {"tools": {"kv": {"GET /items/**": "allow"}}}
        self.assertEqual(policy.decide(p, "kv", "GET", "/items/42/sub"), policy.ALLOW)

    def test_intra_segment_star(self):
        p = {"tools": {"kv": {"GET /files/*.txt": "allow"}}}
        self.assertEqual(policy.decide(p, "kv", "GET", "/files/a.txt"), policy.ALLOW)
        self.assertEqual(policy.decide(p, "kv", "GET", "/files/a.png"), policy.DENY)

    def test_specificity_tie_resolves_to_most_restrictive(self):
        # /a/* and /*/b are equally specific and both match /a/b -> deny wins
        p = {"tools": {"kv": {"GET /a/*": "allow", "GET /*/b": "deny"}}}
        self.assertEqual(policy.decide(p, "kv", "GET", "/a/b"), policy.DENY)

    def test_no_path_is_least_restrictive_for_discovery(self):
        # listing a rest verb without a path: usable if any rule permits it
        self.assertEqual(policy.decide(self.P, "kv", "GET"), policy.ALLOW)
        self.assertEqual(policy.decide(self.P, "kv", "DELETE"), policy.REVIEW)

    def test_explicit_deny_key(self):
        p = {"tools": {"kv": {"DELETE /**": "deny"}}}
        self.assertEqual(policy.decide(p, "kv", "DELETE", "/items/42"), policy.DENY)


if __name__ == "__main__":
    unittest.main()
