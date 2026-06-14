"""FileBackend secret resolution."""

import os
import tempfile
import unittest
from pathlib import Path

from toolyard.config import load
from toolyard.secrets import FileBackend

REPO = Path(__file__).resolve().parents[2]
TOOL_TOML = REPO / "tools" / "echo_rest" / "toolyard.toml"


def _toml_file(text: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    f.write(text)
    f.close()
    return f.name


class Resolve(unittest.TestCase):
    def test_resolves_declared_secret_by_field(self):
        path = _toml_file('[echo]\nAPI_KEY = "dev-secret-123"\n')
        self.addCleanup(os.unlink, path)
        resolved = FileBackend(path).resolve(load(TOOL_TOML))
        self.assertEqual(resolved, {"api_key": "dev-secret-123"})

    def test_missing_secret_raises(self):
        path = _toml_file('[other]\nX = "y"\n')
        self.addCleanup(os.unlink, path)
        with self.assertRaises(KeyError):
            FileBackend(path).resolve(load(TOOL_TOML))


if __name__ == "__main__":
    unittest.main()
