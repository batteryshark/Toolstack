import unittest

from toolstack_forwarder.config import SecretUpdateRule
from toolstack_forwarder.rules import RuleError, extract_value, match_status


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


if __name__ == "__main__":
    unittest.main()
