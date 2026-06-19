"""admin.tool_sources: copy a tool folder into the managed tools dir + record its source."""

import shutil
import tempfile
import unittest
from pathlib import Path

from admin import tool_sources

MANIFEST = ('id = "weather"\ntype = "rest"\ndescription = "wx"\n\n'
            '[entrypoint]\ncommand = "python3 app.py"\nport = 4700\n\n'
            '[[operations]]\nname = "today"\nrisk = "low"\n')


class AddFromPath(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tool-sources-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.src.mkdir()
        (self.src / "toolyard.toml").write_text(MANIFEST, encoding="utf-8")
        (self.src / "app.py").write_text("# tool code\n", encoding="utf-8")
        self.root = self.tmp / "tools_root"

    def test_copies_into_tools_root_with_code_and_records_source(self):
        tool = tool_sources.add_from_path(str(self.src), str(self.root))
        self.assertEqual(tool["id"], "weather")
        self.assertEqual(tool["description"], "wx")
        dest = self.root / "weather"
        self.assertTrue((dest / "toolyard.toml").exists())
        self.assertTrue((dest / "app.py").exists())   # the tool's code came along
        src = tool_sources.read_source(dest)
        self.assertEqual(src["type"], "path")
        self.assertEqual(src["source"], str(self.src.resolve()))

    def test_no_manifest_raises_NoManifest(self):
        codeonly = self.tmp / "codeonly"
        codeonly.mkdir()
        (codeonly / "app.py").write_text("x", encoding="utf-8")
        with self.assertRaises(tool_sources.NoManifest):
            tool_sources.add_from_path(str(codeonly), str(self.root))

    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):
            tool_sources.add_from_path(str(self.src), str(self.root), existing_ids=["weather"])

    def test_existing_destination_not_clobbered(self):
        (self.root / "weather").mkdir(parents=True)
        with self.assertRaises(ValueError):
            tool_sources.add_from_path(str(self.src), str(self.root))

    def test_bad_source_raises(self):
        with self.assertRaises(ValueError):
            tool_sources.add_from_path(str(self.tmp / "nope"), str(self.root))

    def test_invalid_manifest_rejected_at_add_time(self):
        bad = self.tmp / "bad"
        bad.mkdir()
        # no entrypoint command/image -> validate() fails, so we don't copy a broken tool
        (bad / "toolyard.toml").write_text(
            'id = "bad"\ntype = "rest"\n[entrypoint]\nport = 4700\n\n'
            '[[operations]]\nname = "a"\nrisk = "low"\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            tool_sources.add_from_path(str(bad), str(self.root))

    def test_vcs_and_build_cruft_not_copied(self):
        (self.src / ".git").mkdir()
        (self.src / ".git" / "HEAD").write_text("ref: x", encoding="utf-8")
        (self.src / "__pycache__").mkdir()
        (self.src / "__pycache__" / "x.pyc").write_text("", encoding="utf-8")
        tool_sources.add_from_path(str(self.src), str(self.root))
        dest = self.root / "weather"
        self.assertFalse((dest / ".git").exists())
        self.assertFalse((dest / "__pycache__").exists())

    def _folder_with_id(self, name: str, tool_id: str) -> Path:
        d = self.tmp / name
        d.mkdir()
        (d / "toolyard.toml").write_text(
            f'id = "{tool_id}"\ntype = "rest"\n[entrypoint]\ncommand = "x"\nport = 4700\n\n'
            '[[operations]]\nname = "a"\nrisk = "low"\n', encoding="utf-8")
        return d

    def test_rejects_id_path_traversal(self):
        # The security premise of the slice: a manifest id with separators / .. must be rejected
        # BEFORE it's used as a path component, so nothing is written outside tools_root.
        for evil in ("../../pwned", "/tmp/pwned", "a/b", ".."):
            d = self.tmp / "evil"
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir()
            (d / "toolyard.toml").write_text(
                f'id = "{evil}"\ntype = "rest"\n[entrypoint]\ncommand = "x"\nport = 4700\n\n'
                '[[operations]]\nname = "a"\nrisk = "low"\n', encoding="utf-8")
            with self.assertRaises(ValueError, msg=evil):
                tool_sources.add_from_path(str(d), str(self.root))
        self.assertFalse((self.tmp / "pwned").exists())          # nothing escaped tools_root
        self.assertFalse((self.tmp.parent / "pwned").exists())

    def test_rejects_overlong_id(self):
        d = self._folder_with_id("longid", "a" * 100)
        with self.assertRaises(ValueError):   # a clean 400, not an OSError "name too long" 500
            tool_sources.add_from_path(str(d), str(self.root))

    def test_symlink_copied_verbatim_not_dereferenced(self):
        # A symlink in the source must NOT have its target's CONTENT materialized into the managed
        # (possibly synced) tools dir — it's recreated as a link instead.
        secret = self.tmp / "secret.txt"
        secret.write_text("TOPSECRET", encoding="utf-8")
        (self.src / "link").symlink_to(secret)
        tool_sources.add_from_path(str(self.src), str(self.root))
        self.assertTrue((self.root / "weather" / "link").is_symlink())  # a link, not a copied file

    def test_rejects_source_inside_tools_root(self):
        self.root.mkdir()
        inside = self.root / "src_inside"
        inside.mkdir()
        (inside / "toolyard.toml").write_text(MANIFEST, encoding="utf-8")
        with self.assertRaises(ValueError):
            tool_sources.add_from_path(str(inside), str(self.root))

    def test_read_source_none_when_absent(self):
        plain = self.tmp / "plain"
        plain.mkdir()
        self.assertIsNone(tool_sources.read_source(plain))


if __name__ == "__main__":
    unittest.main()
