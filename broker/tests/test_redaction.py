"""Redaction of free-text that may reach audit or an approval card."""

import unittest

from broker.redaction import redact, redact_request


class Redact(unittest.TestCase):
    def test_none_passes_through(self):
        self.assertIsNone(redact(None))

    def test_ordinary_text_unchanged(self):
        self.assertEqual(redact("rotate the staging key"), "rotate the staging key")

    def test_masks_long_opaque_token(self):
        out = redact("here is sk_live_" + "a" * 40)
        self.assertIn("[redacted]", out)
        self.assertNotIn("a" * 40, out)

    def test_masks_bearer(self):
        self.assertIn("[redacted]", redact("use Bearer abcdefghijklmnopqrstuvwxyz012345"))

    def test_bounds_length(self):
        out = redact("word " * 200, limit=50)
        self.assertLessEqual(len(out), 53)  # 50 + ellipsis (...)
        self.assertTrue(out.endswith("..."))


class RedactRequest(unittest.TestCase):
    def test_empty_is_none(self):
        self.assertIsNone(redact_request({}))
        self.assertIsNone(redact_request(None))

    def test_renders_arguments_so_two_calls_differ(self):
        a = redact_request({"body": {"dueDate": "2026-07-01"}})
        b = redact_request({"body": {"assignedTo": "bob"}})
        self.assertIn("2026-07-01", a)
        self.assertIn("bob", b)
        self.assertNotEqual(a, b)

    def test_masks_a_token_like_value(self):
        out = redact_request({"body": {"token": "sk_live_" + "a" * 40}})
        self.assertIn("[redacted]", out)
        self.assertNotIn("a" * 40, out)


if __name__ == "__main__":
    unittest.main()
