"""Offline security regressions: temporary state and mocked processes only."""
import json
import os
import stat
import tempfile
import unittest
import time
import multiprocessing
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock

from toolyard import cli, runner, netguard
from toolyard.egress_proxy import _handler, _MAX_BODY


def _state_writer(directory, key):
    os.environ["XDG_STATE_HOME"] = directory
    for _ in range(3):
        with cli.state_lock():
            state = cli._load_state()
            time.sleep(0.01)
            state[key] = {"channel_secret": key}
            cli._save_state(state)


class UpliftTests(unittest.TestCase):
    def test_bundled_echo_docker_context_and_packaging_fake_only(self):
        from toolyard.config import load
        for name in ("echo_api", "echo_mcp"):
            path = runner._REPO_ROOT / "tools" / name
            tool = replace(load(path / "toolyard.toml"), secrets=())
            fake = Mock(return_value=SimpleNamespace(returncode=0))
            with patch.dict(os.environ, {"TOOLSTACK_SPS_SKIP": "1", "TOOLSTACK_E_SECRET": ""}), patch.object(runner.DockerRunner, "_docker", fake), patch.object(runner.DockerRunner, "is_alive", return_value=True), patch.object(runner, "_start_docker_log_follower", return_value=None), patch.object(runner.time, "sleep"):
                runner.DockerRunner().start(tool)
            build = next(c.args[0] for c in fake.call_args_list if c.args[0][0] == "build")
            self.assertEqual(build[-1], str(runner._REPO_ROOT))
            self.assertIn(str(path / "Dockerfile"), build)
            source = (path / "Dockerfile").read_text()
            self.assertIn(f"tools/{name}/toolyard.toml", source)
            self.assertIn("COPY sps /app/sps", source)

    def test_failed_stop_retains_record(self):
        record = runner.RunningTool("a", 123, "process", "999", boot_id="boot", process_identity="start")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_STATE_HOME": directory}, clear=True):
            with cli.state_lock():
                cli._save_state({"a": asdict(record)})
            with patch.object(runner, "_boot_id", return_value="boot"), patch.object(runner, "_process_identity", return_value="start"), patch.object(runner.os, "kill"), patch.object(runner.os, "killpg", side_effect=PermissionError):
                with self.assertRaisesRegex(RuntimeError, "retain state"):
                    cli.cmd_down(SimpleNamespace(id="a"))
            self.assertIn("a", cli._load_state())

    def test_unknown_legacy_process_identity_refuses_stop(self):
        record = runner.RunningTool("a", 123, "process", "999")
        with patch.object(runner, "_process_identity", return_value="live"), patch.object(runner.os, "killpg") as kill:
            with self.assertRaises(runner.RunnerStartCleanupError):
                runner.ProcessRunner().stop(record)
            kill.assert_not_called()

    def test_explicit_state_path_matches_broker_channel_default(self):
        from broker.tool_state import _default_state_path
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            path = Path(directory) / "private.json"
            os.environ["TOOLSTACK_TOOLYARD_STATE"] = str(path)
            with cli.state_lock():
                cli._save_state({"a": {"channel_secret": "channel", "e_secret": "sps"}})
            self.assertEqual(cli._state_path(), path)
            self.assertEqual(_default_state_path(), path.with_name("channels.json"))

    def test_unsafe_channel_parent_refused_without_chmod(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            root = Path(directory)
            shared = root / "shared"
            shared.mkdir(mode=0o755)
            shared.chmod(0o755)
            os.environ["TOOLSTACK_TOOLYARD_STATE"] = str(root / "private" / "state.json")
            os.environ["TOOLSTACK_TOOLYARD_CHANNEL_STATE"] = str(shared / "channels.json")
            with self.assertRaisesRegex(ValueError, "owner-private"):
                cli._save_state({})
            self.assertEqual(stat.S_IMODE(shared.stat().st_mode), 0o755)
            self.assertFalse((shared / "channels.json").exists())

    def test_channel_cannot_replace_private_state_or_lock(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            root = Path(directory)
            os.environ["TOOLSTACK_TOOLYARD_STATE"] = str(root / "state.json")
            for name in ("state.json", "state.lock", "sub/../state.json"):
                os.environ["TOOLSTACK_TOOLYARD_CHANNEL_STATE"] = str(root / name)
                with self.assertRaisesRegex(ValueError, "different paths"):
                    cli._save_state({})

    def test_links_and_foreign_owner_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "linked"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                cli._atomic_private_json(link / "state.json", {})
            file = root / "state.json"
            file.symlink_to(target / "absent")
            with self.assertRaises(ValueError):
                cli._atomic_private_json(file, {})
            with patch.object(cli.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(ValueError):
                    cli._atomic_private_json(root / "other.json", {})

    def test_child_environment_drops_master_and_provider_credentials(self):
        sensitive = {"SP_SECRET": "fake", "SP_VAULT_PASSPHRASE": "fake", "SP_VAULT_PASSPHRASE_FILE": "fake", "VAULT_TOKEN": "fake", "INFISICAL_CLIENT_SECRET": "fake", "AWS_SECRET_ACCESS_KEY": "fake", "TOOLSTACK_E_SECRET": "foreign", "TOOLSTACK_CHANNEL_SECRET": "foreign"}
        with patch.dict(os.environ, {**sensitive, "PATH": "/fake/bin", "LANG": "C"}, clear=True):
            self.assertEqual(runner._child_environment(), {"PATH": "/fake/bin", "LANG": "C"})

    def test_resolved_verify_normalized_once(self):
        cfg = SimpleNamespace(sp_host="fake", sp_port=123, sp_secret="fake", sp_tls_ca="fake-ca")
        with patch("toolyard.sps_config.load_registration_config", return_value=cfg), patch.dict(os.environ, {"TOOLSTACK_SPS_VERIFY": "YeS"}, clear=True):
            resolved = runner._resolve_sps("fake.env")
        self.assertIs(resolved.verify, True)
        with patch.dict(os.environ, {"TOOLSTACK_SPS_VERIFY": "invalid"}, clear=True), patch("sps.client.SPSClient") as client:
            runner._sps_register(SimpleNamespace(id="fake", secrets=[]), "tool-key", resolved)
        self.assertIs(client.call_args.kwargs["verify"], True)

    def test_recovery_failure_is_not_complete(self):
        with patch.object(runner, "reregister_with_sps_results", return_value={"a": None, "b": "failed"}):
            result = runner.reregister_all_with_sps_detailed()
        self.assertFalse(result.complete)
        self.assertEqual(result.succeeded, ("a",))
        self.assertEqual(result.failed, ("b",))
        self.assertEqual(result.count, 1)

    def test_failed_start_cleanup_record_persisted(self):
        fake = Mock()
        record = runner.RunningTool("a", 123, "docker", "container", channel_secret="channel")
        fake.start.side_effect = runner.RunnerStartCleanupError(record)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_STATE_HOME": directory}), patch.object(cli, "discover", return_value=[SimpleNamespace(id="a")]), patch.object(cli, "get_runner", return_value=fake):
            with self.assertRaises(runner.RunnerStartCleanupError):
                cli.cmd_up(SimpleNamespace(root="fake", id=None, backend="docker"))
            self.assertEqual(cli._load_state()["a"]["handle"], "container")

    def test_interprocess_complete_update_lock(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_STATE_HOME": directory}):
            context = multiprocessing.get_context("spawn")
            children = [context.Process(target=_state_writer, args=(directory, key)) for key in ("a", "b")]
            for child in children:
                child.start()
            for child in children:
                child.join(timeout=10)
                self.assertEqual(child.exitcode, 0)
            self.assertEqual(set(cli._load_state()), {"a", "b"})

    def test_private_state_and_channel_view(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_STATE_HOME": directory}):
            with cli.state_lock():
                cli._save_state({"a": {"e_secret": "sps-only", "channel_secret": "channel-only"}})
            path = cli._state_path()
            channel = path.with_name("channels.json")
            self.assertEqual(json.loads(channel.read_text()), {"a": {"channel_secret": "channel-only"}})
            self.assertNotIn("sps-only", channel.read_text())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(channel.stat().st_mode), 0o600)

    def test_table_lifecycle_identity(self):
        a, b = "tool-1", "tool_1"
        self.assertNotEqual(netguard._table(a), netguard._table(b))
        with patch.object(netguard.subprocess, "run") as call, patch.object(netguard.os, "rmdir"), patch("builtins.open", side_effect=OSError):
            netguard._teardown(a)
            netguard._teardown(b)
            netguard._teardown(a)
        self.assertEqual([c.args[0][-1] for c in call.call_args_list],
                         [netguard._table(a), netguard._table(b), netguard._table(a)])
        self.assertIn(netguard._table(a), netguard._ruleset(a, None))
        self.assertNotIn(netguard._table(b), netguard._ruleset(a, None))

    def test_netguard_interleaved_start_stop_fake_only(self):
        from unittest.mock import mock_open
        with patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), patch.object(netguard.os, "geteuid", return_value=0), patch.object(netguard.os, "makedirs"), patch.object(netguard.os, "rmdir"), patch.object(netguard.os, "setgroups"), patch.object(netguard.os, "setuid"), patch.object(netguard.os, "setgid"), patch.object(netguard.os, "execvp"), patch.object(netguard, "_restore_dumpable"), patch("builtins.open", mock_open()), patch.object(netguard.subprocess, "run") as call:
            netguard._run("tool-1", None, ["fake"])
            netguard._run("tool_1", None, ["fake"])
            netguard._teardown("tool-1")
            netguard._teardown("tool_1")
        deletes = [c.args[0][-1] for c in call.call_args_list if "delete" in c.args[0]]
        self.assertEqual(deletes, [netguard._table("tool-1"), netguard._table("tool_1"),
                                   netguard._table("tool-1"), netguard._table("tool_1")])

    def test_no_mutable_privileged_launch(self):
        with self.assertRaises(runner.RunnerConfigError):
            runner._netguard_argv("run", "--tool", "a")
        with self.assertRaises(runner.RunnerConfigError):
            runner.BwrapRunner().start(Mock())

    def test_strict_bool(self):
        for value in ["1", "TRUE", "yes"]:
            self.assertTrue(runner.strict_bool(value))
        for value in ["0", "false", "NO"]:
            with patch.dict(os.environ, {"TOOLSTACK_SPS_DEV": "1"}):
                self.assertFalse(runner.strict_bool(value))
        with self.assertRaises(ValueError):
            runner.strict_bool("typo")

    def test_reused_pid_not_signalled(self):
        record = runner.RunningTool("a", 123, "process", "999", boot_id="boot", process_identity="old")
        with patch.object(runner, "_boot_id", return_value="boot"), patch.object(runner, "_process_identity", return_value="new"), patch.object(runner.os, "killpg") as kill:
            with self.assertRaises(runner.RunnerStartCleanupError):
                runner.ProcessRunner().stop(record)
            self.assertFalse(runner.ProcessRunner().is_alive(record))
            kill.assert_not_called()

    def test_bounded_kill(self):
        with patch.object(runner, "_boot_id", return_value="boot"), patch.object(runner, "_process_identity", return_value="start"), patch.object(runner.os, "kill"), patch.object(runner.os, "killpg") as kill, patch.object(runner.os, "waitpid", return_value=(0, 0)), patch.object(runner.time, "monotonic", side_effect=[0, 3, 4, 6]):
            with self.assertRaises(RuntimeError):
                runner._terminate(999, "start", "boot")
        self.assertEqual([c.args[1] for c in kill.call_args_list], [runner.signal.SIGTERM, runner.signal.SIGKILL])

    def test_docker_failed_removal_raises(self):
        record = runner.RunningTool("a", 123, "docker", "container")
        with patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=1)), self.assertRaises(RuntimeError):
            runner.DockerRunner().stop(record)

    def test_egress_invalid_length_before_read_or_contact(self):
        from email.message import Message
        for length in ["-1", "junk", str(_MAX_BODY + 1), "9" * 5000]:
            handler = object.__new__(_handler(frozenset({"example.invalid"})))
            handler.path = "http://example.invalid/"
            handler.headers = Message()
            handler.headers["Content-Length"] = length
            handler.send_error = Mock()
            handler.rfile = Mock()
            handler._forward()
            handler.send_error.assert_called_once()
            handler.rfile.read.assert_not_called()

    def test_batch_persists_first_before_second_fails(self):
        defs = [SimpleNamespace(id="a"), SimpleNamespace(id="b")]
        record = runner.RunningTool("a", 123, "process", "999", channel_secret="channel")
        fake = Mock()
        fake.start.side_effect = [record, RuntimeError("second failed")]
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_STATE_HOME": directory}), patch.object(cli, "discover", return_value=defs), patch.object(cli, "get_runner", return_value=fake):
            with self.assertRaises(RuntimeError):
                cli.cmd_up(SimpleNamespace(root="fake", id=None, backend="process"))
            self.assertIn("a", cli._load_state())

    def test_unrecordable_start_rolled_back(self):
        fake = Mock()
        fake.start.return_value = runner.RunningTool("a", 123, "process", "999")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_STATE_HOME": directory}), patch.object(cli, "discover", return_value=[SimpleNamespace(id="a")]), patch.object(cli, "get_runner", return_value=fake), patch.object(cli, "_save_state", side_effect=[OSError("disk"), None]):
            with self.assertRaises(OSError):
                cli.cmd_up(SimpleNamespace(root="fake", id=None, backend="process"))
        fake.stop.assert_called_once_with(fake.start.return_value)

    def test_sps_resolution_reused_and_channel_independent(self):
        cfg = SimpleNamespace(sp_host="configured.invalid", sp_port=4444, sp_tls_ca="fake-ca", verify=False)
        tool = SimpleNamespace(id="fake", port=123, path=Path("."), command="fake", secrets=[], manifest_digest="recorded")
        with patch.object(runner, "_check_port_free"), patch.object(runner.os.path, "exists", return_value=True), patch.object(runner, "_resolve_sps", return_value=cfg) as resolve, patch.object(runner, "_sps_register") as register, patch.object(runner, "_tool_log_path", return_value=Path(os.devnull)), patch.object(runner.os, "fchmod"), patch.object(runner.os, "posix_spawn", return_value=999) as spawn, patch.object(runner, "_process_identity", return_value="start"), patch.object(runner.ProcessRunner, "is_alive", return_value=True), patch.object(runner.time, "sleep"), patch.dict(os.environ, {"TOOLSTACK_SPS_SKIP": "0", "TOOLSTACK_SPS_ENV": "fake.env"}):
            record = runner.ProcessRunner().start(tool)
        resolve.assert_called_once_with("fake.env")
        self.assertIs(register.call_args.args[2], cfg)
        env = spawn.call_args.args[2]
        self.assertEqual(env["TOOLSTACK_SPS_HOST"], cfg.sp_host)
        self.assertEqual(env["TOOLSTACK_SPS_PORT"], "4444")
        self.assertEqual(env["TOOLSTACK_SPS_CA"], "fake-ca")
        self.assertEqual(env["TOOLSTACK_SPS_VERIFY"], "0")
        self.assertEqual(env["TOOLSTACK_CHANNEL_SECRET"], record.channel_secret)
        self.assertNotEqual(record.channel_secret, record.e_secret)

    def test_egress_stream_cap_closes_upstream(self):
        from email.message import Message
        from toolyard import egress_proxy
        handler = object.__new__(_handler(frozenset({"example.invalid"})))
        handler.path = "http://example.invalid/"
        handler.command = "GET"
        handler.deadline = time.monotonic() + 30
        handler.expired = False
        handler._connect = Mock(return_value=Mock())
        handler.headers = Message()
        handler.wfile = Mock()
        handler.send_response = handler.send_header = handler.end_headers = Mock()
        upstream = Mock()
        response = upstream.getresponse.return_value
        response.getheader.return_value = None
        response.getheaders.return_value = []
        response.status = 200
        response.read1.side_effect = [b"x" * 8, b"y"]
        with patch.object(egress_proxy, "_MAX_RESPONSE", 8), patch.object(egress_proxy.http.client, "HTTPConnection", return_value=upstream):
            handler._forward()
        self.assertEqual(handler.wfile.write.call_count, 1)
        self.assertEqual(response.read1.call_args_list[-1].args[0], 1)
        upstream.close.assert_called_once()
