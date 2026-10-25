import hashlib
import unittest
from types import SimpleNamespace
from unittest import mock

from toolstack_forwarder.config import SecretUpdateRule
from toolstack_forwarder.rules import RuleError, apply_secret_update_rules, extract_value, match_status


class Extractors(unittest.TestCase):
    def rule(self, response_type, extract_path, secret="auth_token"):
        return SecretUpdateRule(
            secret_name=secret,
            response_type=response_type,
            extract_path=extract_path,
            match_status="200",
        )

    def test_match_status_exact_wildcard_and_pipe(self):
        self.assertTrue(match_status("200", 200))
        self.assertTrue(match_status("200|201", 201))
        self.assertTrue(match_status("2xx", 204))
        self.assertFalse(match_status("4xx", 204))

    def test_json_dot_path_with_list_index(self):
        value = extract_value(self.rule("json", "session.tokens.0.value"),
                              '{"session":{"tokens":[{"value":"abc"}]}}')
        self.assertEqual(value, "abc")

    def test_form_extracts_first_value(self):
        self.assertEqual(extract_value(self.rule("form", "token"), "token=a&token=b"), "a")

    def test_plaintext_uses_first_regex_group(self):
        self.assertEqual(extract_value(self.rule("plaintext", r"refresh=([A-Za-z0-9]+)"),
                                       "refresh=abc123"), "abc123")

    def test_xml_extracts_text_and_restricted_attribute(self):
        self.assertEqual(extract_value(self.rule("xml", ".//token"),
                                       "<root><token>abc</token></root>"), "abc")
        self.assertEqual(extract_value(self.rule("xml", ".//token/@value"),
                                       "<root><token value='abc'/></root>"), "abc")

    def test_missing_json_path_raises_rule_extraction_failed(self):
        with self.assertRaises(RuleError) as cm:
            extract_value(self.rule("json", "missing"), "{}")
        self.assertEqual(cm.exception.code, "rule_extraction_failed")

    def test_success_and_partial_failure_logs_only_metadata(self):
        value = "fake-low-entropy-1234"
        digest = hashlib.sha256(value.encode()).hexdigest()
        op = SimpleNamespace(secret_update_rules=(
            self.rule("json", "token", "first"), self.rule("json", "token", "second")))
        response = {"status": 200, "body": '{"token":"' + value + '"}'}
        for partial in (False, True):
            secrets = mock.Mock()
            if partial:
                secrets.writeback.side_effect = [None, OSError("fake")]
            with self.subTest(partial=partial), self.assertLogs("toolstack_forwarder.rules", level="INFO") as logs:
                if partial:
                    with self.assertRaises(RuleError) as caught:
                        apply_secret_update_rules(op, response, secrets)
                    self.assertEqual(caught.exception.envelope(), {
                        "error": "secret_update_failed", "detail": "OSError", "secret": "second"})
                else:
                    apply_secret_update_rules(op, response, secrets)
            secrets.writeback.assert_has_calls([mock.call("first", value), mock.call("second", value)])
            text = "\n".join(logs.output)
            self.assertIn("first", text)
            self.assertIn("rule=json", text)
            self.assertIn("partial writes" if partial else "second", text)
            self.assertNotIn(value, text)
            self.assertNotIn(digest, text)
            self.assertNotIn("sha256", text)


if __name__ == "__main__":
    unittest.main()
