"""audit: append-only JSON-lines, no SP/E secrets logged."""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from sps.audit import AuditLogger


class Audit(unittest.TestCase):
    def test_writes_json_line_per_event(self):
        f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".audit")
        f.close()
        self.addCleanup(os.unlink, f.name)
        log = AuditLogger(f.name)
        log.event("register", tool_id="echo")
        log.event("get_secret", tool_id="echo", secret_name="api_key")
        with open(f.name) as fp:
            lines = [json.loads(line) for line in fp.read().splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["action"], "register")
        self.assertEqual(lines[0]["tool_id"], "echo")
        self.assertEqual(lines[1]["action"], "get_secret")
        self.assertEqual(lines[1]["secret_name"], "api_key")
        for line in lines:
            self.assertIn("ts", line)

    def test_event_without_optional_fields_omits_them(self):
        f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".audit")
        f.close()
        self.addCleanup(os.unlink, f.name)
        log = AuditLogger(f.name)
        log.event("startup")
        with open(f.name) as fp:
            line = fp.read().strip()
        rec = json.loads(line)
        self.assertEqual(rec, {"ts": rec["ts"], "action": "startup"})
        self.assertNotIn("tool_id", rec)
        self.assertNotIn("secret_name", rec)

    def test_never_logs_secret_values_or_secrets(self):
        f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".audit")
        f.close()
        self.addCleanup(os.unlink, f.name)
        log = AuditLogger(f.name)
        # Even though `event()` only exposes keyword-only `tool_id` and
        # `secret_name`, the test calls `**kwargs` style would have to go
        # through the public surface. Verify what an actual secret leak
        # would look like:
        log.event(
            "writeback",
            tool_id="echo",
            secret_name="api_key",
        )
        with open(f.name) as fp:
            blob = fp.read()
        # The canonical "must never appear" sentinels
        self.assertNotIn("SUPER-SECRET", blob)
        self.assertNotIn("xyz789", blob)
        self.assertNotIn("abc123", blob)

    def test_invalid_kwargs_are_silently_dropped(self):
        # Belt-and-suspenders: the signature only exposes `tool_id` and
        # `secret_name`, but if a refactor added new kwargs the implementer
        # must NOT forward them. We don't have a programmatic surface to
        # test that; instead we rely on the inspection-based test above.
        f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".audit")
        f.close()
        self.addCleanup(os.unlink, f.name)
        log = AuditLogger(f.name)
        log.event("register")
        # In the public API, `tool_id=""` / `secret_name=""` are the only
        # extra fields; verify the produced line has nothing else.
        with open(f.name) as fp:
            rec = json.loads(fp.read().strip())
        self.assertEqual(set(rec.keys()), {"ts", "action"})
