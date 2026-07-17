"""server: TLS scaffold + JSON-line read + auth helpers (read/write, not HTTP)."""
import io
import json
import unittest

from sps.wire import (
    MAX_BODY_BYTES,
    OversizedBodyError,
    constant_time_eq,
    err_envelope,
    read_one_json,
    write_one_json,
)


class ConstantTimeEq(unittest.TestCase):
    def test_equal(self):
        self.assertTrue(constant_time_eq("abc", "abc"))

    def test_unequal(self):
        self.assertFalse(constant_time_eq("abc", "abd"))

    def test_unicode(self):
        self.assertTrue(constant_time_eq("café", "café"))
        self.assertFalse(constant_time_eq("café", "cafe"))


class ErrEnvelope(unittest.TestCase):
    def test_each_known_message(self):
        for msg in (
            "Bad request", "Unauthorized", "Not found",
            "Not writable", "Backend error",
        ):
            env = err_envelope(msg)
            self.assertEqual(env, {"status": "error", "message": msg})
            self.assertEqual(set(env.keys()), {"status", "message"})

    def test_unknown_message_rejected(self):
        for bad in ("Forbidden", "Bad Request", "", None, 0):
            with self.assertRaises(ValueError):
                err_envelope(bad)


class ReadOneJson(unittest.TestCase):
    def _lines(self, *lines):
        if lines:
            text = "\n".join(lines) + "\n"
        else:
            text = ""
        return io.StringIO(text)

    def test_reads_a_single_object(self):
        f = self._lines('{"op": "register"}')
        msg = read_one_json(f)
        self.assertEqual(msg, {"op": "register"})

    def test_eof_yields_empty_dict_sentinel(self):
        f = self._lines()
        self.assertEqual(read_one_json(f), {})

    def test_invalid_json_raises(self):
        f = self._lines("{not json}")
        with self.assertRaises(ValueError):
            read_one_json(f)

    def test_oversized_raises(self):
        huge = '{"a": "' + ("x" * (MAX_BODY_BYTES + 100)) + '"}'
        f = io.StringIO(huge + "\n")
        with self.assertRaises(OversizedBodyError):
            read_one_json(f)


class WriteOneJson(unittest.TestCase):
    def test_writes_a_single_line_with_trailing_newline(self):
        buf = io.StringIO()
        write_one_json(buf, {"status": "ok"})
        self.assertEqual(buf.getvalue(), '{"status": "ok"}\n')

    def test_writes_are_immediately_flushable(self):
        # write_one_json calls flush() so callers can rely on read_complete
        # even when the socket layer has its own buffering.
        buf = io.StringIO()
        write_one_json(buf, {"a": 1})
        # after the call, getvalue() returns everything because flush was called
        self.assertIn('"a": 1', buf.getvalue())


class EndToEndRoundTrip(unittest.TestCase):
    def test_write_then_read(self):
        # Simulate the wire: server writes an envelope, client reads it.
        server_buf = io.StringIO()
        write_one_json(server_buf, {"status": "ok", "secrets": {"a": "V"}})
        client_buf = io.StringIO(server_buf.getvalue())
        msg = read_one_json(client_buf)
        self.assertEqual(msg, {"status": "ok", "secrets": {"a": "V"}})

    def test_max_body_size_round_trip(self):
        # Just under the cap -> reads fine.
        payload = {"x": "y" * (MAX_BODY_BYTES - 100)}
        buf = io.StringIO()
        write_one_json(buf, payload)
        out = io.StringIO(buf.getvalue())
        self.assertEqual(read_one_json(out), payload)
