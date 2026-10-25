import unittest

from admin.policy_edits import merge_enabled, merge_grants


class PolicyEdits(unittest.TestCase):
    def test_explicit_denial_preserves_unrendered_grants(self):
        current = {"tools": {"notes": {"read": "allow", "write": "review"},
                             "offline": {"fetch": "allow"}}}
        allow, review, deny = merge_grants(current, {"op__notes__read": "deny"})
        self.assertEqual(allow, ["offline.fetch"])
        self.assertEqual(review, ["notes.write"])
        self.assertEqual(deny, ["notes.read"])
        self.assertEqual(current["tools"]["notes"]["read"], "allow")

    def test_unavailable_enabled_tools_survive_explicit_visible_disable(self):
        current = {"enabled": ["offline", "notes"], "tools": {"cli-granted": {"read": "allow"}}}
        self.assertEqual(merge_enabled(current, {"notes": []}, []), ["offline", "cli-granted"])

    def test_invalid_effect_does_not_silently_remove_grants(self):
        with self.assertRaises(ValueError):
            merge_grants({"tools": {}}, {"op__notes__read": "invalid"})

    def test_failed_read_is_not_an_empty_policy(self):
        with self.assertRaises(AttributeError):
            merge_grants(None, {"op__notes__read": "allow"})
