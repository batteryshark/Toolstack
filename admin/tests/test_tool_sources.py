"""admin.tool_sources: copy a tool folder into the managed tools dir + record its source."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class AddFromGithub(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tool-gh-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "tools_root"

    def _fake_clone(self, *, with_subdir: bool):
        """Return a subprocess.run stand-in that 'clones' by populating the dest dir."""
        def run(cmd, *a, **k):
            dest = Path(cmd[-1])                       # `git clone … -- <url> <dest>`
            target = dest / "sub" if with_subdir else dest
            target.mkdir(parents=True)
            (target / "toolyard.toml").write_text(MANIFEST, encoding="utf-8")
            (target / "app.py").write_text("# code\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        return run

    def test_clones_root_and_records_github_source(self):
        with mock.patch.object(tool_sources.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(tool_sources.subprocess, "run",
                               side_effect=self._fake_clone(with_subdir=False)):
            tool = tool_sources.add_from_github("https://github.com/x/y", str(self.root), ref="main")
        self.assertEqual(tool["id"], "weather")
        src = tool_sources.read_source(self.root / "weather")
        self.assertEqual(src, {"type": "github", "url": "https://github.com/x/y",
                               "subdir": "", "ref": "main"})
        self.assertFalse((self.root / "weather" / ".git").exists())   # VCS cruft not copied

    def test_clones_subdir(self):
        with mock.patch.object(tool_sources.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(tool_sources.subprocess, "run",
                               side_effect=self._fake_clone(with_subdir=True)):
            tool = tool_sources.add_from_github("https://github.com/x/y", str(self.root), subdir="sub")
        self.assertEqual(tool["id"], "weather")
        self.assertEqual(tool_sources.read_source(self.root / "weather")["subdir"], "sub")

    def test_rejects_dangerous_or_nongit_urls(self):
        # file://, ext::/fd:: (run commands), a flag-looking URL, a bare path, ftp:// — all rejected
        for bad in ("file:///etc/passwd", "ext::sh -c whoami", "--upload-pack=evil",
                    "/local/repo", "ftp://host/x", ""):
            with self.assertRaises(ValueError, msg=bad):
                tool_sources.add_from_github(bad, str(self.root))

    def test_rejects_subdir_traversal(self):
        with mock.patch.object(tool_sources.shutil, "which", return_value="/usr/bin/git"):
            for bad in ("../etc", "a/../../b", ".."):
                with self.assertRaises(ValueError, msg=bad):
                    tool_sources.add_from_github("https://github.com/x/y", str(self.root), subdir=bad)

    def test_missing_git_errors(self):
        with mock.patch.object(tool_sources.shutil, "which", return_value=None):
            with self.assertRaises(ValueError):
                tool_sources.add_from_github("https://github.com/x/y", str(self.root))

    def test_clone_argv_is_injection_safe(self):
        # Pin the security-critical shape: a flag-looking ref is bound to --branch (never a free
        # token), and the url sits only AFTER '--'. Guards against a future arg-order regression.
        captured = {}
        def run(cmd, *a, **k):
            captured["cmd"] = list(cmd)
            dest = Path(cmd[-1])
            dest.mkdir(parents=True)
            (dest / "toolyard.toml").write_text(MANIFEST, encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with mock.patch.object(tool_sources.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(tool_sources.subprocess, "run", side_effect=run):
            tool_sources.add_from_github("https://github.com/x/y", str(self.root),
                                         ref="--upload-pack=evil")
        cmd = captured["cmd"]
        self.assertEqual(cmd[:4], ["git", "clone", "--depth", "1"])     # shallow
        self.assertIn("--branch=--upload-pack=evil", cmd)               # ref bound as a value
        self.assertNotIn("--upload-pack=evil", cmd)                     # not a standalone arg
        sep = cmd.index("--")
        self.assertEqual(cmd[sep + 1], "https://github.com/x/y")        # url only after '--'
        self.assertEqual(cmd[sep + 2], cmd[-1])                         # dest is last

    def test_clone_failure_is_clean_valueerror(self):
        def boom(cmd, *a, **k):
            raise subprocess.CalledProcessError(128, cmd, b"", b"fatal: repository not found")
        with mock.patch.object(tool_sources.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(tool_sources.subprocess, "run", side_effect=boom):
            with self.assertRaises(ValueError):
                tool_sources.add_from_github("https://github.com/x/y", str(self.root))

    def test_private_repo_gets_friendly_message(self):
        def needs_auth(cmd, *a, **k):
            raise subprocess.CalledProcessError(
                128, cmd, b"", b"fatal: could not read Username for 'https://github.com': "
                              b"terminal prompts disabled")
        with mock.patch.object(tool_sources.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(tool_sources.subprocess, "run", side_effect=needs_auth):
            with self.assertRaises(ValueError) as cm:
                tool_sources.add_from_github("https://github.com/x/private", str(self.root))
        self.assertIn("private", str(cm.exception).lower())   # not git's raw "could not read Username"


class Update(unittest.TestCase):
    def setUp(self):
        from admin import tool_authoring
        self.tool_authoring = tool_authoring
        self.tmp = Path(tempfile.mkdtemp(prefix="tool-update-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.src.mkdir()
        (self.src / "toolyard.toml").write_text(MANIFEST, encoding="utf-8")
        (self.src / "app.py").write_text("v1\n", encoding="utf-8")
        self.root = self.tmp / "tools_root"
        tool_sources.add_from_path(str(self.src), str(self.root))   # managed copy + path sidecar
        self.dest = self.root / "weather"

    def _write_src(self, toml: str):
        (self.src / "toolyard.toml").write_text(toml, encoding="utf-8")

    def test_path_update_pulls_new_code_but_keeps_operator_edits(self):
        # operator re-wires the managed tool: custom description + a re-mapped secret
        managed = self.tool_authoring.read(self.dest)
        managed["description"] = "operator note"
        managed["secrets"] = [{"name": "api_key", "field": "MY_KEY", "writable": True}]
        self.tool_authoring.write(self.dest, managed)
        # upstream advances: new code, a new operation, and its OWN description/secret
        (self.src / "app.py").write_text("v2\n", encoding="utf-8")
        self._write_src('id = "weather"\ntype = "rest"\ndescription = "upstream desc"\n'
                        '[entrypoint]\ncommand = "python3 app.py"\nport = 4700\n\n'
                        '[[operations]]\nname = "today"\nrisk = "low"\n\n'
                        '[[operations]]\nname = "tomorrow"\nrisk = "low"\n\n'
                        '[[secrets]]\nname = "api_key"\nfield = "UPSTREAM_KEY"\n')
        tool_sources.update(self.dest)
        after = self.tool_authoring.read(self.dest)
        self.assertEqual((self.dest / "app.py").read_text(), "v2\n")               # new code
        self.assertEqual({o["name"] for o in after["operations"]}, {"today", "tomorrow"})  # new op
        self.assertEqual(after["description"], "operator note")                    # operator kept
        self.assertEqual(after["secrets"][0]["field"], "MY_KEY")                   # operator kept
        self.assertTrue(after["secrets"][0]["writable"])
        self.assertEqual(tool_sources.read_source(self.dest)["type"], "path")      # sidecar kept

    def test_update_without_sidecar_is_rejected(self):
        plain = self.tmp / "plain"
        plain.mkdir()
        (plain / "toolyard.toml").write_text(MANIFEST, encoding="utf-8")
        with self.assertRaises(ValueError):
            tool_sources.update(plain)

    def test_update_source_gone_leaves_original_intact(self):
        shutil.rmtree(self.src)
        with self.assertRaises(ValueError):
            tool_sources.update(self.dest)
        self.assertTrue((self.dest / "toolyard.toml").exists())   # swap never started

    def test_update_id_change_rejected_original_intact(self):
        self._write_src('id = "renamed"\ntype = "rest"\n[entrypoint]\ncommand = "x"\nport = 4700\n\n'
                        '[[operations]]\nname = "today"\nrisk = "low"\n')
        with self.assertRaises(ValueError):
            tool_sources.update(self.dest)
        self.assertEqual(self.tool_authoring.read(self.dest)["id"], "weather")     # unchanged

    def test_successful_update_leaves_tools_root_clean(self):
        from toolyard.config import discover
        self._write_src('id = "weather"\ntype = "rest"\n[entrypoint]\ncommand = "python3 app.py"\nport = 4700\n\n'
                        '[[operations]]\nname = "today"\nrisk = "low"\n\n'
                        '[[operations]]\nname = "extra"\nrisk = "low"\n')
        tool_sources.update(self.dest)
        # no staging/backup siblings left, and discovery sees exactly one 'weather' (no shadow dir)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["weather"])
        self.assertEqual([d.id for d in discover(self.root)], ["weather"])

    def test_swap_failure_restores_original_no_orphan(self):
        from toolyard.config import discover
        self._write_src('id = "weather"\ntype = "rest"\n[entrypoint]\ncommand = "python3 app.py"\nport = 4700\n\n'
                        '[[operations]]\nname = "changed"\nrisk = "low"\n')
        real_replace = tool_sources.os.replace
        calls = {"n": 0}
        def flaky(a, b):
            calls["n"] += 1
            if calls["n"] == 2:           # fail moving the NEW version into place
                raise OSError("boom")
            return real_replace(a, b)
        with mock.patch.object(tool_sources.os, "replace", side_effect=flaky):
            with self.assertRaises(OSError):
                tool_sources.update(self.dest)
        after = self.tool_authoring.read(self.dest)
        self.assertEqual({o["name"] for o in after["operations"]}, {"today"})   # original, not "changed"
        self.assertEqual([d.id for d in discover(self.root)], ["weather"])      # no orphan shadow
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["weather"])

    def test_github_update_reclones(self):
        tool_sources.write_source(self.dest, {"type": "github", "url": "https://github.com/x/y",
                                              "subdir": "", "ref": ""})
        def fake_clone(cmd, *a, **k):
            d = Path(cmd[-1])
            d.mkdir(parents=True)
            (d / "toolyard.toml").write_text(
                'id = "weather"\ntype = "rest"\n[entrypoint]\ncommand = "python3 app.py"\nport = 4700\n\n'
                '[[operations]]\nname = "fresh"\nrisk = "low"\n', encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with mock.patch.object(tool_sources.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(tool_sources.subprocess, "run", side_effect=fake_clone):
            tool_sources.update(self.dest)
        self.assertEqual({o["name"] for o in self.tool_authoring.read(self.dest)["operations"]}, {"fresh"})


if __name__ == "__main__":
    unittest.main()
