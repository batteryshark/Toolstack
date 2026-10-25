"""Fake-only contracts for session, lifecycle and worker admission repairs."""
import asyncio
import json
import os
import threading
import unittest
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException
from admin import toolyard_ops
from admin.blocking import BlockingWork
from admin.sps_link import SPSLink, parse_verify
from admin import operator_audit, broker_config
from toolyard.runner import RunningTool

runner_state_lock = toolyard_ops.state_lock


class AuditFailure(unittest.TestCase):
    def test_failed_intent_audit_prevents_config_write(self):
        config = broker_config.BrokerRunConfig()
        with mock.patch("admin.operator_audit.open_store") as store, \
             mock.patch("admin.operator_audit.operations.record_admin_event", side_effect=OSError("fake")), \
             mock.patch("admin.operator_audit.broker_config.save") as save:
            with self.assertRaises(OSError):
                operator_audit.save_config(config, config, "fake-admin")
        save.assert_not_called()

    def test_completion_failure_explains_that_save_already_happened(self):
        config = broker_config.BrokerRunConfig()
        with mock.patch("admin.operator_audit.open_store"), \
             mock.patch("admin.operator_audit.operations.record_admin_event", side_effect=[None, OSError("fake")]), \
             mock.patch("admin.operator_audit.broker_config.save") as save:
            with self.assertRaisesRegex(RuntimeError, "saved but completion audit failed"):
                operator_audit.save_config(config, config, "fake-admin")
        save.assert_called_once()


class Readiness(unittest.TestCase):
    def test_strict_boolean(self):
        for text in ("1", "true", "yes", "on", " TRUE "):
            self.assertIs(parse_verify(text), True)
        for text in ("0", "false", "no", "off"):
            with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_DEV": "1"}):
                self.assertIs(parse_verify(text), False)
            with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_DEV": "0"}), self.assertRaises(ValueError):
                parse_verify(text)
        for text in ("", "typo", "2"):
            with self.assertRaises(ValueError):
                parse_verify(text)

    def test_invalid_verify_disables_readiness_not_verification(self):
        cfg = SimpleNamespace(sp_host="fake", sp_port=8743, sp_tls_ca="fake")
        with mock.patch.dict(os.environ, {"TOOLSTACK_SPS_VERIFY": "typo", "TOOLSTACK_SPS_SKIP": "0"}), \
             mock.patch("admin.sps_link.os.path.exists", return_value=True), \
             mock.patch("admin.sps_link.load_config", return_value=cfg):
            self.assertIsNone(SPSLink.from_env("/fake/unused"))


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.held = False
        @contextmanager
        def lock():
            self.assertFalse(self.held, "must not require a reentrant runner lock")
            self.held = True
            try:
                yield
            finally:
                self.held = False
        self.running = RunningTool("fake", 9999, "process", "fake-pid")
        self.runner = mock.Mock()
        self.runner.start.return_value = self.running
        def load():
            self.assertTrue(self.held)
            return {}
        def save(state):
            self.assertTrue(self.held)
        for target, kw in (
            ("state_lock", {"side_effect": lock}),
            ("_all_defs", {"return_value": {"fake": object()}}),
            ("_load_state", {"side_effect": load}),
            ("_save_state", {"side_effect": save}),
            ("get_runner", {"return_value": self.runner}),
        ):
            patcher = mock.patch.object(toolyard_ops, target, **kw)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_restart_uses_one_complete_nonreentrant_lock(self):
        toolyard_ops.restart("fake", "unused", [])
        self.runner.start.assert_called_once()

    def test_failed_persistence_rolls_back_new_start(self):
        with mock.patch.object(toolyard_ops, "_save_state", side_effect=OSError("fake disk")):
            with self.assertRaises(OSError):
                toolyard_ops.start("fake", "unused", [])
        self.runner.stop.assert_called_once_with(self.running)

    def test_failed_rollback_retains_explicit_runtime_reference(self):
        self.runner.stop.side_effect = OSError("fake cleanup")
        with mock.patch.object(toolyard_ops, "_save_state", side_effect=OSError("fake disk")):
            with self.assertRaises(toolyard_ops.UnrecordedRuntimeError) as caught:
                toolyard_ops.start("fake", "unused", [])
        self.assertIs(caught.exception.running, self.running)

    def test_runner_cleanup_failure_record_is_preserved(self):
        exc = RuntimeError("fake start cleanup failure")
        exc.running = self.running
        self.runner.start.side_effect = exc
        with mock.patch.object(toolyard_ops, "_save_state") as save:
            with self.assertRaises(RuntimeError):
                toolyard_ops.start("fake", "unused", [])
        save.assert_called_once_with({"fake": asdict(self.running)})

    def test_missing_runner_lock_fails_closed(self):
        # Test the actual adapter, not the injected fake used above.
        from toolyard import cli
        with mock.patch.object(cli, "state_lock", None, create=True):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                runner_state_lock()


class NativeLiveness(unittest.TestCase):
    def test_recorded_state_is_not_health_evidence(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/native_api.json").read_text())
        definition = SimpleNamespace(id="fake", type="api", port=9999, path=Path("/fake"), secrets=[])
        running = RunningTool("fake", 9999, "process", "fake")
        for expected in fixture["tool_states"]:
            record = {"fake": asdict(running)} if expected["running"] else {}
            runner = mock.Mock()
            if expected["alive"] is None:
                runner.is_alive.side_effect = OSError("unknown")
            else:
                runner.is_alive.return_value = expected["alive"]
            with mock.patch.object(toolyard_ops, "_load_state", return_value=record), \
                 mock.patch.object(toolyard_ops, "_all_defs", return_value={"fake": definition}), \
                 mock.patch.object(toolyard_ops, "get_runner", return_value=runner):
                tool = toolyard_ops.list_tools("unused")[0]
            self.assertEqual({key: tool[key] for key in expected}, expected)


class WorkerAdmission(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_caller_keeps_slot_until_work_finishes(self):
        work = BlockingWork(limit=1)
        entered, release = threading.Event(), threading.Event()
        def blocking():
            entered.set()
            release.wait(3)
        task = asyncio.create_task(work.run(blocking))
        try:
            while not entered.is_set():
                await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            with self.assertRaises(HTTPException) as caught:
                await work.run(lambda: None)
            self.assertEqual(caught.exception.status_code, 503)
        finally:
            release.set()
            await asyncio.to_thread(work._executor.shutdown, wait=True)

    async def test_work_is_off_loop_and_result_propagates(self):
        work = BlockingWork(limit=1)
        try:
            thread = threading.get_ident()
            self.assertNotEqual(await work.run(threading.get_ident), thread)
        finally:
            work._executor.shutdown()
