"""Writable-secret proxy: the toolyard side of message-contracts §4."""

import json
import socket
import tempfile
import threading
import tomllib
import unittest
from pathlib import Path

from toolyard.config import SecretSpec, ToolDef
from toolyard.secrets import FileBackend
from toolyard.write_proxy import serve


def _tool(*secrets: SecretSpec) -> ToolDef:
    return ToolDef(id="demo", type="rest", port=1, command=None, image=None,
                   secrets=tuple(secrets), path=Path("."))


def _post(socket_path: str, name: str, value: str) -> int:
    body = json.dumps({"value": value, "reason": "test"}).encode()
    req = (f"POST /v1/secrets/{name} HTTP/1.1\r\nHost: toolyard\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    sock.sendall(req)
    raw = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk
    sock.close()
    return int(raw.split()[1])


class WriteProxy(unittest.TestCase):
    def setUp(self):
        self.secrets_file = Path(tempfile.mkdtemp()) / "secrets.toml"
        self.secrets_file.write_text('[demo]\nTOKEN = "old"\n')
        self.backend = FileBackend(self.secrets_file)
        self.tool = _tool(SecretSpec("token", "TOKEN", writable=True),
                          SecretSpec("ro", "RO", writable=False))
        self.sock_path = str(Path(tempfile.mkdtemp()) / "secrets.sock")
        self.server = serve(self.sock_path, self.tool, self.backend)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_writable_secret_is_patched_to_backend(self):
        self.assertEqual(_post(self.sock_path, "token", "new-value"), 200)
        with self.secrets_file.open("rb") as f:
            self.assertEqual(tomllib.load(f)["demo"]["TOKEN"], "new-value")

    def test_non_writable_secret_is_forbidden(self):
        self.assertEqual(_post(self.sock_path, "ro", "x"), 403)

    def test_unknown_secret_is_not_found(self):
        self.assertEqual(_post(self.sock_path, "nope", "x"), 404)


if __name__ == "__main__":
    unittest.main()
