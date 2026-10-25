"""Real binding exercised with injected Popen pipes: never launches a process."""
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

import vm_proof_guard as g
from vm_proof_adapter import StopLatch, _safe_rollback, run_guard
from vm_proof_linux import LinuxSubprocessIO, PrivateFiles, open_directory
from test_vm_proof_adapter import FakeIO, RUN, config, run


class Child:
    pid = 424242

    def __init__(self, output=b"", error=b"", hung=False):
        self.stdout = self.pipe(output)
        self.stderr = self.pipe(error)
        self.code = None if hung else 0
        self.signals = []

    @staticmethod
    def pipe(data):
        r, w = os.pipe()
        os.write(w, data)
        os.close(w)
        return os.fdopen(r, "rb", buffering=0)

    def poll(self):
        return self.code

    def wait(self, timeout):
        return self.code

    def send_signal(self, sig):
        self.signals.append(sig)
        self.code = -sig


class Ownership(unittest.TestCase):
    def test_parent_repro_external_running_never_mutates(self):
        io = FakeIO()
        io.vm130 = "running"
        io.admit = None
        result = run(io, ticks=1)
        self.assertFalse(result.restored)
        self.assertFalse(any(c[:2] in (("qm", "set"), ("qm", "start"), ("qm", "shutdown")) for c in io.calls))

    def test_external_running_with_admit_still_refuses(self):
        io = FakeIO()
        io.vm130, io.admit = "running", RUN
        run(io, ticks=1)
        self.assertFalse(any(c[:2] in (("qm", "set"), ("qm", "shutdown")) for c in io.calls))

    def test_external_resize_between_readiness_and_admit(self):
        io = FakeIO()
        def admit():
            io.memory = 6000
            return RUN
        io.admit_text = admit
        result = run(io, ticks=2)
        self.assertFalse(result.restored)
        self.assertFalse(any(c[:2] in (("qm", "set"), ("qm", "start"), ("qm", "shutdown")) for c in io.calls))

    def test_owned_but_external_shape_drift_never_restores(self):
        for memory, state, start in ((6000, "stopped", False), (8192, "running", True), (4096, "running", False)):
            io = FakeIO()
            io.owned_resize, io.owned_start = True, start
            io.memory, io.vm130 = memory, state
            result = _safe_rollback(io, config())
            self.assertTrue(result.ask_parent)
            self.assertFalse(any(c[:2] in (("qm", "set"), ("qm", "shutdown")) for c in io.calls))

    def test_resize_lost_reply_restores_only_owned_stopped_4096(self):
        io = FakeIO()
        io.admit = RUN
        original = io.run
        def command(argv, timeout):
            result = original(argv, timeout)
            if argv == ("qm", "set", "130", "--memory", "4096"):
                return g.Completed(1, "")
            return result
        io.run = command
        result = run(io, ticks=2)
        self.assertTrue(result.restored)
        self.assertIn(("qm", "set", "130", "--memory", "8192"), io.calls)
        self.assertNotIn(("qm", "shutdown", "130", "--timeout", "90"), io.calls)

    def test_latch_closed_before_cleanup_on_all_exits(self):
        io = FakeIO()
        latch = StopLatch()
        io.begin_cleanup = lambda: self.assertTrue(latch.closed())
        run_guard(io, config(), latch, lambda: 0, lambda s: None, max_ticks=1)

    def test_signal_during_owned_lifecycle_shuts_down_once(self):
        io = FakeIO()
        io.admit = RUN
        latch = StopLatch()
        original = io.run
        def command(argv, timeout):
            result = original(argv, timeout)
            if argv == ("qm", "start", "130"):
                latch.trip("signal")
            return result
        io.run = command
        result = run_guard(io, config(), latch, lambda: 0, lambda s: None, max_ticks=3)
        self.assertIn("signal", result.reasons)
        self.assertEqual(io.calls.count(("qm", "shutdown", "130", "--timeout", "90")), 1)
        self.assertEqual(io.memory, 8192)

    def test_incomplete_production_baseline_cannot_admit_resize(self):
        io = FakeIO()
        io.admit = RUN
        io.prod += "\nother\tUp (healthy)"
        result = run(io, ticks=2)
        self.assertIn("production-baseline-incomplete", result.reasons)
        self.assertFalse(any(c[:2] == ("qm", "set") for c in io.calls))


class Binding(unittest.TestCase):
    def make(self, child, clock=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.chmod(temp.name, 0o700)
        calls = []
        def spawn(*a, **kw):
            calls.append((a, kw))
            return child
        io = LinuxSubprocessIO(str(Path(temp.name).resolve()), config(), StopLatch(), "/opt/toolstack",
                               popen=spawn, observe=lambda pid: 123, **({"clock": clock} if clock else {}))
        self.addCleanup(io.close)
        # Only process transport tests suppress probes; no CLI or host gate bypass.
        io.check = lambda: None
        return io, calls

    def test_real_qga_json_decoded_not_returned_as_stdout(self):
        body = json.dumps({"exited": 1, "exitcode": 0, "out-data": "nod\tUp (healthy)\n"}).encode()
        io, calls = self.make(Child(body))
        result = io.run(g.production_ps_argv(), 45)
        self.assertEqual(result.stdout, "nod\tUp (healthy)\n")
        self.assertEqual(calls[0][0][0][0], "/usr/sbin/qm")
        self.assertNotIn("shell", calls[0][1])

    def test_already_exited_short_child_needs_no_signal(self):
        child = Child(b"status: stopped")
        io, _ = self.make(child)
        io.observe = lambda pid: None
        self.assertEqual(io.run(("qm", "status", "130"), 15), g.Completed(0, "status: stopped"))
        self.assertEqual(child.signals, [])

    def test_stderr_or_qga_stderr_is_unknown_without_logging_content(self):
        for child in (Child(b"ok", b"secret-shaped diagnostic"),
                      Child(json.dumps({"exited": 1, "exitcode": 0, "out-data": "ok", "err-data": "diagnostic"}).encode())):
            io, _ = self.make(child)
            self.assertEqual(io.run(g.production_ps_argv(), 45), g.Completed(1, ""))

    def test_qga_pending_malformed_and_truncated_are_unknown(self):
        for payload in (b"not-json", b'{"pid": 33}', b'{"exited":1,"exitcode":0,"out-truncated":true}'):
            io, _ = self.make(Child(payload))
            self.assertEqual(io.run(g.production_ps_argv(), 45), g.Completed(1, ""))

    def test_hung_owned_child_timeout_signals_exact_identity(self):
        now = [0]
        def clock():
            now[0] += 20
            return now[0]
        child = Child(hung=True)
        io, _ = self.make(child, clock)
        self.assertEqual(io.run(g.production_ps_argv(), 45).code, 1)
        self.assertEqual(child.signals, [signal.SIGTERM])

    def test_reused_pid_is_never_signalled(self):
        child = Child(hung=True)
        io, _ = self.make(child)
        io.observe = lambda pid: 999
        io.cancel(child, 123)
        self.assertEqual(child.signals, [])
        child.stdout.close()
        child.stderr.close()

    def test_no_guest_build_create_or_production_mutation_can_start(self):
        child = Child()
        io, calls = self.make(child)
        io.owned_start = True
        for command in (("qm", "stop", "130"), ("qm", "set", "100", "--memory", "4096"),
                        g._guest("130", "30", ("docker", "create", "image")),
                        g._guest("130", "1200", g.onebox_build_argv(RUN))):
            with self.assertRaises(g.GuardRefusal):
                io.run(command, 45)
        self.assertEqual(calls, [])
        child.stdout.close()
        child.stderr.close()

    def test_dead_controller_and_pid_reuse_invalidate_lease(self):
        child = Child()
        io, _ = self.make(child)
        io.files.create("controller", json.dumps({"pid": 42, "start": 10}))
        io.files.create("lease", json.dumps({"run": RUN, "pid": 42, "start": 10, "monotonic": io.clock()}))
        for observation in (None, 11):
            io.observe = lambda pid: observation
            self.assertIsNone(io.lease_age())
        child.stdout.close()
        child.stderr.close()

    def test_fast_memory_trip_never_spawns_slow_qga_probe(self):
        child = Child()
        io, calls = self.make(child)
        io.read = lambda path: "MemAvailable: 1 kB" if path == "/proc/meminfo" else ""
        io.lease_age = lambda: 0
        io.check = lambda: LinuxSubprocessIO.check(io)
        with self.assertRaises(g.GuardRefusal):
            io.run(g.production_ps_argv(), 45)
        self.assertTrue(io.latch.closed())
        self.assertEqual(calls, [])
        child.stdout.close()
        child.stderr.close()

    def test_memory_trip_during_hung_child_cancels_without_waiting_timeout(self):
        child = Child(hung=True)
        io, calls = self.make(child)
        probes = [0]
        def read(path):
            if path == "/proc/meminfo":
                probes[0] += 1
                return "MemAvailable: %d kB" % (7000000 if probes[0] == 1 else 1)
            return "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0"
        io.read, io.lease_age = read, lambda: 0
        io.check = lambda: LinuxSubprocessIO.check(io)
        self.assertEqual(io.run(g.production_ps_argv(), 45).code, 1)
        self.assertEqual(len(calls), 1)
        self.assertTrue(io.latch.closed())
        self.assertEqual(child.signals, [signal.SIGTERM])

    def test_files_refuse_symlink_ancestor_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            os.symlink(root, root / "link")
            with self.assertRaises(OSError):
                open_directory(str(root / "link"))
            files = PrivateFiles(str(root))
            try:
                files.create("ready", "original")
                with self.assertRaises(FileExistsError):
                    files.create("ready", "overwrite")
                self.assertEqual(files.read("ready"), "original")
            finally:
                files.close()


if __name__ == "__main__":
    unittest.main()
