"""Broker registry auto-injects refresh/refresh_one ops for tools with [[secrets]] declared.

Plan ref: docs/plans/2026-07-16-sps-overhaul.md Task 3.5. Without this injection, the broker
returns "not found" for `<tool>.refresh` and `<tool>.refresh_one` even though every tool
with declared secrets has the SPS-backed SecretClient that can serve them. With it, the
catalog lists both ops (risk="read") so the broker's policy + audit pipeline picks them
up exactly like any other op.
"""
import tempfile
import unittest
from pathlib import Path

from broker.registry import Registry


_TOML_WITH_SECRETS = """\
id = "with-secrets"
type = "api"

[entrypoint]
command = "python3 app.py"
port = 4701

[[operations]]
name = "say"
risk = "read"

[[secrets]]
name = "api_key"
field = "API_KEY"
"""

_TOML_WITHOUT_SECRETS = """\
id = "no-secrets"
type = "api"

[entrypoint]
command = "python3 app.py"
port = 4702

[[operations]]
name = "say"
risk = "read"
"""

_TOML_WITH_EMPTY_SECRETS = """\
id = "empty-secrets"
type = "api"

[entrypoint]
command = "python3 app.py"
port = 4703

[[operations]]
name = "say"
risk = "read"

[[secrets]]
"""


class RefreshOpInjection(unittest.TestCase):
    def _catalog_for(self, toml_text: str) -> dict:
        with tempfile.TemporaryDirectory() as td:
            tool_dir = Path(td) / "mytool"
            tool_dir.mkdir()
            (tool_dir / "toolyard.toml").write_text(toml_text)
            cat: dict = {}
            Registry._add_toml(cat, tool_dir / "toolyard.toml")
            return cat

    def test_injects_refresh_ops_when_secrets_declared(self):
        cat = self._catalog_for(_TOML_WITH_SECRETS)["with-secrets"]
        self.assertIn("refresh", cat["ops"])
        self.assertIn("refresh_one", cat["ops"])

    def test_refresh_ops_are_read_risk(self):
        cat = self._catalog_for(_TOML_WITH_SECRETS)["with-secrets"]
        self.assertEqual(cat["ops"]["refresh"]["risk"], "read")
        self.assertEqual(cat["ops"]["refresh_one"]["risk"], "read")

    def test_refresh_one_takes_a_name_arg(self):
        cat = self._catalog_for(_TOML_WITH_SECRETS)["with-secrets"]
        names = {a["name"] for a in cat["ops"]["refresh_one"]["args"]}
        self.assertIn("name", names)

    def test_does_not_inject_when_no_secrets_block(self):
        cat = self._catalog_for(_TOML_WITHOUT_SECRETS)["no-secrets"]
        self.assertNotIn("refresh", cat["ops"])
        self.assertNotIn("refresh_one", cat["ops"])

    def test_does_not_inject_when_secrets_block_empty(self):
        cat = self._catalog_for(_TOML_WITH_EMPTY_SECRETS)["empty-secrets"]
        self.assertNotIn("refresh", cat["ops"])
        self.assertNotIn("refresh_one", cat["ops"])

    def test_existing_ops_preserved(self):
        cat = self._catalog_for(_TOML_WITH_SECRETS)["with-secrets"]
        self.assertIn("say", cat["ops"])
        # Both the declared op and the two injected ones are present.
        self.assertEqual(set(cat["ops"]), {"say", "refresh", "refresh_one"})


if __name__ == "__main__":
    unittest.main()