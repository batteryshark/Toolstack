import json
import os
import shutil
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from toolstack_forwarder.config import SecretUpdateRule
from toolstack_forwarder.rules import (
    RuleError,
    extract_value,
    match_status,
    write_secret_via_proxy,
)


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
        self.assertEqual(extract_value(self.rule("plaintext", r"refresh=([A-Za-z0-9]+)"), "refresh=abc123"), "abc123")

    def test_xml_extracts_text_and_restricted_attribute(self):
        self.assertEqual(extract_value(self.rule("xml", ".//token"), "<root><token>abc</token></root>"), "abc")
        self.assertEqual(extract_value(self.rule("xml", ".//token/@value"), "<root><token value='abc'/></root>"), "abc")

    def test_missing_json_path_raises_rule_extraction_failed(self):
        with self.assertRaises(RuleError) as cm:
            extract_value(self.rule("json", "missing"), "{}")
        self.assertEqual(cm.exception.code, "rule_extraction_failed")


class _WriteProxy(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline().decode("latin-1").strip()
        headers = {}
        while True:
            line = self.rfile.readline().decode("latin-1")
            if line in ("\r\n", "\n", ""):
                break
            key, _, value = line.partition(":")
            headers[key.lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0") or 0))
        self.server.requests.append((request_line, json.loads(body)))
        status = self.server.status
        payload = json.dumps(self.server.body).encode()
        self.wfile.write(
            f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )


class WriteProxy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.sock = str(Path(self.tmp, "secrets.sock"))
        self.server = socketserver.UnixStreamServer(self.sock, _WriteProxy)
        self.server.requests = []
        self.server.status = 200
        self.server.body = {"ok": True}
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.env = mock.patch.dict(os.environ, {"TOOLYARD_SECRETS_SOCKET": self.sock})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_write_secret_via_proxy_posts_value_and_reason(self):
        status, body = write_secret_via_proxy("auth token", "sekret")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": True})
        request_line, payload = self.server.requests[0]
        self.assertEqual(request_line, "POST /v1/secrets/auth%20token HTTP/1.1")
        self.assertEqual(payload, {"value": "sekret", "reason": "rest secret_update_rule"})


if __name__ == "__main__":
    unittest.main()
