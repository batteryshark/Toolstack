"""Owned partial-start boundaries: all process/SPS operations are pure fakes."""
from contextlib import ExitStack
from dataclasses import asdict, replace
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch, call

from toolyard import runner, cli


class PartialCleanup(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.kill = self.stack.enter_context(patch.object(runner.os, "killpg"))
        self.probe = self.stack.enter_context(patch.object(runner.os, "kill"))
        self.wait = self.stack.enter_context(patch.object(runner.os, "waitpid", return_value=(0, 0)))
        self.identity = self.stack.enter_context(patch.object(runner, "_process_identity", return_value="start"))
        self.stack.enter_context(patch.object(runner, "_boot_id", return_value="boot"))
        self.stack.enter_context(patch.object(runner.time, "sleep"))
        self.record = runner.RunningTool("fake", 123, "process", "12345", boot_id="boot",
                                         process_identity="start", egress_pid="12346",
                                         egress_identity="start", channel_secret="fake-channel")

    def test_exit_reaped_before_any_signal_even_without_identity(self):
        self.wait.return_value = (12345, 0)
        runner._terminate(12345)
        self.kill.assert_not_called()

    def test_unknown_is_not_completion(self):
        for identity in (None, "start"):
            for result in (None, "start"):
                with self.subTest(identity=identity, snapshot=result):
                    self.identity.return_value = result
                    self.wait.side_effect = ChildProcessError
                    with patch.object(runner.time, "monotonic", side_effect=range(0, 100, 3)):
                        with self.assertRaises(RuntimeError):
                            runner._terminate(12345, identity, "boot")
                    if identity is None or result is None:
                        self.kill.assert_not_called()
                    self.kill.reset_mock()

    def test_missing_boot_never_signals(self):
        with self.assertRaises(RuntimeError):
            runner._terminate(12345, "start")
        self.kill.assert_not_called()

    def test_nonparent_stop_finishes_on_positive_absence(self):
        self.wait.side_effect = ChildProcessError
        self.probe.side_effect = [None, ProcessLookupError()]
        runner._terminate(12345, "start", "boot")
        self.kill.assert_called_once_with(12345, runner.signal.SIGTERM)
        self.assertEqual(self.probe.call_args_list, [call(12345, 0), call(12345, 0)])

    def test_absent_snapshot_needs_positive_esrch(self):
        self.identity.return_value = None
        self.wait.side_effect = ChildProcessError
        for outcome in (None, PermissionError(), OSError("unavailable")):
            with self.subTest(outcome=outcome):
                self.probe.side_effect = outcome
                with self.assertRaises(RuntimeError):
                    runner._terminate(12345, "start", "boot")
        self.probe.side_effect = ProcessLookupError
        runner._terminate(12345, "start", "boot")
        self.assertFalse(runner.ProcessRunner().is_alive(self.record))
        # Even a missing recorded start identity can be resolved by ESRCH,
        # never by the unavailable snapshot alone.
        runner._terminate(12345, None, "boot")
        self.kill.assert_not_called()

    def test_prior_boot_clears_all_helpers_without_any_pid_operation(self):
        record = replace(self.record, boot_id="previous", log_pid="12347", log_identity="log")
        cleaned = runner._cleanup_partial_start(record)
        self.assertTrue(cleaned.process_exited and cleaned.log_exited and cleaned.egress_exited)
        self.assertFalse(runner.ProcessRunner().is_alive(record))
        self.kill.assert_not_called()
        self.probe.assert_not_called()
        self.identity.assert_not_called()
        self.wait.assert_not_called()

    def test_unknown_current_boot_is_not_prior_boot(self):
        with patch.object(runner, "_boot_id", return_value=None):
            with self.assertRaises(RuntimeError):
                runner._terminate(12345, "start", "boot")
        self.kill.assert_not_called()
        self.probe.assert_not_called()
        self.wait.assert_not_called()

    def test_reused_pid_neither_reaped_nor_signalled(self):
        self.identity.return_value = "replacement"
        with self.assertRaises(RuntimeError):
            runner._terminate(12345, "start", "boot")
        self.kill.assert_not_called()
        self.wait.assert_not_called()

    def test_identity_rechecked_before_kill(self):
        # Initial reap check, TERM check, post-TERM reap check, KILL check.
        self.identity.side_effect = ["start", "start", "start", "replacement"]
        with patch.object(runner.time, "monotonic", side_effect=[0, 3]):
            with self.assertRaises(RuntimeError):
                runner._terminate(12345, "start", "boot")
        self.kill.assert_called_once_with(12345, runner.signal.SIGTERM)

    def test_permission_denied_is_uncertain_unless_positively_reaped(self):
        self.kill.side_effect = PermissionError
        with self.assertRaises(RuntimeError):
            runner._terminate(12345, "start", "boot")
        self.wait.side_effect = [(0, 0), (12345, 0)]
        runner._terminate(12345, "start", "boot")

    def test_every_helper_attempted_and_receipts_retained(self):
        record = replace(self.record, log_pid="12347", log_identity="log")
        with patch.object(runner, "_terminate", side_effect=[RuntimeError("private"), None, RuntimeError("private")]) as terminate:
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner._cleanup_partial_start(record)
        self.assertEqual(terminate.call_args_list, [call("12345", "start", "boot"),
                         call("12347", "log", "boot"), call("12346", "start", "boot")])
        self.assertTrue(error.exception.running.log_exited)
        self.assertFalse(error.exception.running.process_exited)
        self.assertFalse(error.exception.running.egress_exited)
        self.assertNotIn("private", str(error.exception))

    def test_positive_receipt_skips_reused_pid_on_retry(self):
        record = replace(self.record, process_exited=True, egress_pid=None)
        self.identity.return_value = "replacement"
        runner._cleanup_partial_start(record)
        self.kill.assert_not_called()
        self.wait.assert_not_called()

    def start_fixture(self):
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        tool = SimpleNamespace(id="fake", port=123, path=Path(directory).resolve(), command="fake", secrets=[])
        sps_env = tool.path / "fake.env"
        sps_env.touch()
        self.stack.enter_context(patch.dict(os.environ, {"TOOLSTACK_SPS_SKIP": "0", "TOOLSTACK_SPS_ENV": str(sps_env)}))
        self.stack.enter_context(patch.object(runner, "_check_port_free"))
        cfg = runner.ResolvedSPS("fake", 123, "fake-secret", "fake-ca", True)
        self.stack.enter_context(patch.object(runner, "_resolve_sps", return_value=cfg))
        self.stack.enter_context(patch.object(runner, "_sps_register"))
        unregister = self.stack.enter_context(patch.object(runner, "_sps_unregister"))
        self.stack.enter_context(patch.object(runner.ProcessRunner, "_policy", return_value=runner.SandboxPolicy(egress=runner.EgressPolicy(allow=("fake.invalid",)))))
        self.stack.enter_context(patch.object(runner, "_start_egress_proxy", return_value=("12346", 456)))
        self.stack.enter_context(patch.object(runner.os, "posix_spawn", return_value=12345))
        return tool, unregister

    def test_start_failure_retains_identities_and_attempts_sps_after_first_error(self):
        tool, unregister = self.start_fixture()
        cause = RuntimeError("original start failure")
        with patch.object(runner.ProcessRunner, "is_alive", side_effect=cause), patch.object(runner, "_terminate", side_effect=[RuntimeError(), None]) as terminate:
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner.ProcessRunner().start(tool)
        self.assertIs(error.exception.__cause__, cause)
        self.assertEqual(terminate.call_args_list, [call("12345", "start", "boot"), call("12346", "start", "boot")])
        self.assertTrue(error.exception.running.egress_exited)
        self.assertEqual(error.exception.running.sps_ca, "fake-ca")
        unregister.assert_called_once()

    def test_failure_before_main_spawn_retains_helper(self):
        tool, unregister = self.start_fixture()
        with patch.object(runner.ProcessRunner, "_spawn_argv", side_effect=ValueError("start")), patch.object(runner, "_terminate", side_effect=RuntimeError()) as terminate:
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner.ProcessRunner().start(tool)
        self.assertEqual(error.exception.running.handle, "")
        self.assertEqual(error.exception.running.egress_identity, "start")
        terminate.assert_called_once_with("12346", "start", "boot")
        unregister.assert_called_once()

    def test_egress_identity_captured_before_main_spawn_preparation(self):
        tool, _ = self.start_fixture()
        def fail_preparation(*args):
            self.identity.assert_called_once_with("12346")
            raise RuntimeError("preparation failed")
        self.identity.return_value = None
        with patch.object(runner.ProcessRunner, "_spawn_argv", side_effect=fail_preparation):
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner.ProcessRunner().start(tool)
        self.assertIsNone(error.exception.running.egress_identity)
        self.assertFalse(error.exception.running.egress_exited)
        self.kill.assert_not_called()

    def test_readiness_reap_receipt_prevents_reuse_signal(self):
        tool, unregister = self.start_fixture()
        self.wait.return_value = (12345, 0)
        with patch.object(runner, "_terminate", side_effect=RuntimeError()) as terminate:
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner.ProcessRunner().start(tool)
        self.assertTrue(error.exception.running.process_exited)
        terminate.assert_called_once_with("12346", "start", "boot")
        unregister.assert_called_once()

    def test_liveness_permission_and_missing_snapshot_are_not_dead(self):
        self.wait.side_effect = ChildProcessError
        self.probe.side_effect = PermissionError
        for identity in (None, "start"):
            self.identity.return_value = identity
            with self.assertRaises(RuntimeError):
                runner.ProcessRunner().is_alive(self.record)

    def test_real_start_error_reaches_cli_typed_persistence(self):
        tool, unregister = self.start_fixture()
        state = tool.path / "state.json"
        with patch.dict(os.environ, {"TOOLSTACK_TOOLYARD_STATE": str(state), "TOOLSTACK_TOOLYARD_CHANNEL_STATE": str(tool.path / "channels.json")}), patch.object(cli, "discover", return_value=[tool]), patch.object(runner.ProcessRunner, "is_alive", side_effect=RuntimeError("start")), patch.object(runner, "_terminate", side_effect=RuntimeError()):
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                cli.cmd_up(SimpleNamespace(root="fake", id=None, backend="process"))
            self.assertEqual(cli._load_state()["fake"], asdict(error.exception.running))
            self.assertFalse(cli._load_state()["fake"]["egress_exited"])
        unregister.assert_called_once()

    def test_cli_and_admin_save_stop_progress_before_retry(self):
        from admin import toolyard_ops
        for stop in (lambda: cli.cmd_down(SimpleNamespace(id="fake")),
                     lambda: toolyard_ops.stop("fake")):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                with patch.dict(os.environ, {"TOOLSTACK_TOOLYARD_STATE": str(root / "state.json"), "TOOLSTACK_TOOLYARD_CHANNEL_STATE": str(root / "channels.json")}):
                    cli._save_state({"fake": asdict(self.record)})
                    with patch.object(runner, "_terminate", side_effect=[None, RuntimeError("denied")]):
                        with self.assertRaises(runner.RunnerStartCleanupError):
                            stop()
                    saved = cli._load_state()["fake"]
                    self.assertTrue(saved["process_exited"])
                    self.assertFalse(saved["egress_exited"])
                    # Receipt prevents probing/signalling a subsequently reused
                    # main PID, while the remaining helper is still attempted.
                    with patch.object(runner, "_terminate") as terminate:
                        stop()
                    terminate.assert_called_once_with("12346", "start", "boot")
                    self.assertEqual(cli._load_state(), {})

    def test_cli_and_admin_save_progress_when_replacing_dead_record(self):
        from admin import toolyard_ops
        updated = replace(self.record, process_exited=True)
        fake = Mock()
        fake.is_alive.return_value = False
        fake.stop.side_effect = runner.RunnerStartCleanupError(updated)
        tool = SimpleNamespace(id="fake")
        for start in (lambda: cli.cmd_up(SimpleNamespace(id="fake", root="fake", backend="process")),
                      lambda: toolyard_ops.start("fake", "fake", [])):
            with self.subTest(start=start), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                with patch.dict(os.environ, {"TOOLSTACK_TOOLYARD_STATE": str(root / "state.json"), "TOOLSTACK_TOOLYARD_CHANNEL_STATE": str(root / "channels.json")}), patch.object(cli, "get_runner", return_value=fake), patch.object(toolyard_ops, "get_runner", return_value=fake), patch.object(cli, "discover", return_value=[tool]), patch.object(toolyard_ops, "_all_defs", return_value={"fake": tool}):
                    cli._save_state({"fake": asdict(self.record)})
                    with self.assertRaises(runner.RunnerStartCleanupError):
                        start()
                    self.assertEqual(cli._load_state()["fake"], asdict(updated))
        fake.start.assert_not_called()

    def test_docker_removal_failure_keeps_full_helper_record(self):
        tool, _ = self.start_fixture()
        tool.type, tool.image = "rest", "fake-image"
        with patch.dict(os.environ, {"TOOLSTACK_SPS_SKIP": "1", "TOOLSTACK_E_SECRET": ""}), patch.object(runner.DockerRunner, "_docker"), patch.object(runner, "_start_docker_log_follower", return_value="12347"), patch.object(runner.DockerRunner, "is_alive", side_effect=RuntimeError("start")), patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=1)), patch.object(runner, "_terminate", side_effect=RuntimeError()) as terminate:
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner.DockerRunner().start(tool)
        self.assertEqual(error.exception.running.log_identity, "start")
        self.assertEqual(error.exception.running.log_pid, "12347")
        terminate.assert_called_once_with("12347", "start", "boot")

    def test_docker_log_close_failure_still_retains_spawned_helper(self):
        tool, _ = self.start_fixture()
        tool.type, tool.image = "rest", "fake-image"
        with patch.dict(os.environ, {"TOOLSTACK_SPS_SKIP": "1", "TOOLSTACK_E_SECRET": ""}), patch.object(runner.DockerRunner, "_docker"), patch.object(runner.os, "open", return_value=99), patch.object(runner.os, "fchmod"), patch.object(runner.os, "close", side_effect=OSError("close failed")), patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)), patch.object(runner, "_terminate", side_effect=RuntimeError()) as terminate:
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner.DockerRunner().start(tool)
        self.assertEqual(error.exception.running.log_identity, "start")
        self.assertEqual(error.exception.running.log_pid, "12345")
        terminate.assert_called_once_with("12345", "start", "boot")

    def test_docker_stop_retains_reaped_helper_when_removal_fails(self):
        record = replace(self.record, backend="docker", handle="fake-container",
                         log_pid="12347", log_identity="start", egress_pid=None)
        with patch.object(runner, "_terminate"), patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(runner.RunnerStartCleanupError) as error:
                runner.DockerRunner().stop(record)
        self.assertTrue(error.exception.running.log_exited)
        with patch.object(runner, "_terminate") as terminate, patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
            runner.DockerRunner().stop(error.exception.running)
        terminate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
