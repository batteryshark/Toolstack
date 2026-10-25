import os
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from admin import tool_authoring, tool_sources, toolyard_ops
from admin.views.tools import tools_view
from toolyard import cli, config, runner


MANIFEST = ('id="demo"\ntype="api"\n[entrypoint]\ncommand="python3 app.py"\nport=4701\n'
            '[[operations]]\nname="read"\nrisk="read"\n')
SECRET = '\n[[secrets]]\nname="token"\nfield="TOKEN"\nitem="other"\n'


class DeclarationApproval(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        env = patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root / "state")})
        env.start()
        self.addCleanup(env.stop)
        self.source = self.root / "source"
        self.source.mkdir()
        self.manifest = self.source / "toolyard.toml"
        self.manifest.write_text(MANIFEST)
        (self.source / "app.py").write_text("# fixture\n")

    def test_update_keeps_empty_local_declarations_and_returns_difference(self):
        imported = tool_sources.add_from_path(str(self.source), str(self.root / "tools"))
        self.manifest.write_text(MANIFEST + SECRET)
        result = tool_sources.update(imported["path"])
        self.assertTrue(result["secret_declarations_changed"])
        self.assertEqual(result["secret_declarations"]["kept"], [])
        self.assertEqual(result["secret_declarations"]["upstream"][0]["item"], "other")
        self.assertEqual(config.load(Path(imported["path"]) / "toolyard.toml").secrets, ())

    def test_import_and_authoring_require_out_of_band_confirmation(self):
        self.manifest.write_text(MANIFEST + SECRET + '\nconfirm_secret_items=true\n')
        data = tool_authoring.read(self.source)
        self.assertTrue(tool_authoring.validate(data))
        self.assertEqual(tool_authoring.validate(data, confirm_secret_items=True), [])
        with self.assertRaisesRegex(ValueError, "explicitly confirm"):
            tool_sources.add_from_path(str(self.source), str(self.root / "tools"))
        tool_sources.add_from_path(str(self.source), str(self.root / "tools"), confirm_secret_items=True)

    def _record(self):
        definition = config.load(self.manifest)
        record = runner.RunningTool("demo", 4701, "process", "123", e_secret="fixture",
                                    secret_declarations=[], manifest_digest=definition.manifest_digest)
        cli._save_state({"demo": asdict(record)})
        return record

    def test_watchdog_uses_recorded_declarations_after_manifest_changes(self):
        self._record()
        self.manifest.write_text(MANIFEST + SECRET)
        fake_runner = Mock()
        fake_runner.is_alive.return_value = True
        with patch.object(runner, "get_runner", return_value=fake_runner), patch.object(runner, "_sps_register") as register:
            result = runner._reregister_results(tools_root="", tool_dirs=[str(self.source)], sps_env_path=str(self.manifest))
        self.assertEqual(result, {"demo": None})
        self.assertEqual(register.call_args.args[0].secrets, ())

    def test_legacy_record_requires_explicit_start(self):
        cli._save_state({"demo": asdict(runner.RunningTool("demo", 4701, "process", "123", e_secret="fixture"))})
        fake_runner = Mock()
        fake_runner.is_alive.return_value = True
        with patch.object(runner, "get_runner", return_value=fake_runner), patch.object(runner, "_sps_register") as register:
            result = runner._reregister_results(tools_root="", tool_dirs=[str(self.source)], sps_env_path=str(self.manifest))
        self.assertIsNotNone(result["demo"])
        register.assert_not_called()

    def test_reconcile_keeps_snapshot_and_explicit_start_adopts_disk(self):
        record = self._record()
        self.manifest.write_text(MANIFEST + SECRET)
        fake_runner = Mock()
        fake_runner.is_alive.return_value = False
        fake_runner.start.return_value = record
        with patch.object(toolyard_ops, "get_runner", return_value=fake_runner):
            toolyard_ops.start("demo", "", [str(self.source)], recovery=True)
            self.assertEqual(fake_runner.start.call_args.args[0].secrets, ())
            self.assertEqual(fake_runner.start.call_args.args[0].manifest_digest, record.manifest_digest)
            toolyard_ops.start("demo", "", [str(self.source)])
            self.assertEqual(fake_runner.start.call_args.args[0].secrets[0].item, "other")

    def test_explicit_edit_records_new_digest_and_declarations(self):
        record = self._record()
        self.manifest.write_text(MANIFEST + SECRET)
        approved = tool_authoring.read(self.source)
        self.manifest.write_text(MANIFEST)
        toolyard_ops.record_edited_declarations(approved)
        updated = cli._load_state()["demo"]
        self.assertNotEqual(updated["manifest_digest"], record.manifest_digest)
        self.assertEqual(updated["secret_declarations"][0]["item"], "other")

    def test_tools_page_displays_declarations_and_start_warning(self):
        self.manifest.write_text(MANIFEST + SECRET)
        tools = toolyard_ops.list_tools("", [str(self.source)])
        html = tools_view(user="operator", csrf="fixture", tools=tools, tools_root="")
        self.assertIn("token (item: other)", html)
        self.assertIn("host&#x27;s credentials", html)
        self.assertIn("Only start tools you trust", html)
        self.assertIn("cancel.autofocus=true", html)
