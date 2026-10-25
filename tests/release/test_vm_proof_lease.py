"""Actual private-file publication and real CLI with fake PVE only."""
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vm_proof_linux as linux
import vm_proof_guard as g
import test_vm_proof_driver as driver_tests
from vm_proof_adapter import StopLatch, run_guard
from test_vm_proof_adapter import RUN, PRESSURE, config


class LeasePublication(unittest.TestCase):
    def make(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        io = linux.LinuxSubprocessIO(str(Path(temp.name).resolve()), config(), StopLatch(), "discover",
                                    observe=lambda pid: 123, clock=lambda: 100)
        self.addCleanup(io.close)
        io.files.create("controller", json.dumps({"pid": 42, "start": 123}))
        self.record = {"pid": 42, "start": 123, "run": RUN, "monotonic": 99}
        io.files.create("lease", json.dumps(self.record))
        io.read = lambda path: "MemAvailable: 7000000 kB" if path == "/proc/meminfo" else PRESSURE
        return io

    def test_old_writer_lock_deterministically_causes_false_resource_trip(self):
        io = self.make()
        fd = io.files.file("lease", os.O_WRONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIsNone(io.lease_age())
            with self.assertRaises(g.GuardRefusal):
                io.check()
            evidence = json.loads(io.files.read("state"))["fast_probe"]
            self.assertEqual(evidence["reasons"], ["publication-locked"])
            self.assertEqual(evidence["memory_kib"], 7000000)
            self.assertEqual(evidence["psi_full_avg10"], 0)
            self.assertTrue(evidence["controller_identity_valid"])
        finally:
            os.close(fd)

    def test_atomic_reader_observes_complete_old_then_new_while_temp_locked(self):
        io = self.make()
        old_fd = io.files.file("lease", os.O_RDONLY)
        self.addCleanup(os.close, old_fd)
        write = io.files._write
        def held_write(fd, data):
            if fd == io.state_fd:
                return write(fd, data)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(io.lease_age(), 1)
            io.check()
            write(fd, data)
        with patch.object(io.files, "_write", side_effect=held_write):
            io.files.publish_lease(dict(self.record, monotonic=100))
        self.assertEqual(io.lease_age(), 0)
        self.assertEqual(json.loads(os.read(old_fd, 4096)), self.record)
        self.assertFalse((Path(io.root) / ".lease-next").exists())
        self.assertNotEqual(os.fstat(old_fd).st_ino, os.stat(Path(io.root) / "lease").st_ino)

    def test_unknown_temp_and_invalid_existing_lease_are_preserved(self):
        for fault in ("temp", "symlink", "mode", "hardlink", "malformed", "other-owner"):
            io = self.make()
            root = Path(io.root)
            if fault == "temp":
                (root / ".lease-next").write_text("unknown")
            elif fault == "symlink":
                (root / "lease").rename(root / "original")
                (root / "lease").symlink_to(root / "original")
            elif fault == "mode":
                (root / "lease").chmod(0o644)
            elif fault == "hardlink":
                os.link(root / "lease", root / "other")
            else:
                (root / "lease").write_text("bad" if fault == "malformed" else json.dumps(dict(self.record, pid=99)))
            before = (root / "lease").read_bytes()
            with self.assertRaises((OSError, ValueError, g.GuardRefusal)):
                io.files.publish_lease(dict(self.record, monotonic=100))
            self.assertEqual((root / "lease").read_bytes(), before)
            if fault == "temp":
                self.assertEqual((root / ".lease-next").read_text(), "unknown")

    def test_failed_publish_removes_only_owned_temp(self):
        io = self.make()
        with patch.object(linux.os, "replace", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                io.files.publish_lease(dict(self.record, monotonic=100))
        self.assertFalse((Path(io.root) / ".lease-next").exists())
        self.assertEqual(json.loads(io.files.read("lease")), self.record)

    def test_each_fast_probe_cause_is_bounded_and_reason_qualified(self):
        for cause in ("memory-unknown", "memory-low", "pressure-unknown", "pressure-preboot-unsettled", "lease-stale",
                      "lease-unknown", "controller-unknown", "controller-dead-or-reused", "lease-clock-invalid", "deadline"):
            io = self.make()
            if cause.startswith("memory"):
                io.read = lambda path: ("sensitive-not-recorded" if cause == "memory-unknown" else "MemAvailable: 1 kB") if path == "/proc/meminfo" else PRESSURE
            elif cause.startswith("pressure"):
                io.read = lambda path: "MemAvailable: 7000000 kB" if path == "/proc/meminfo" else ("sensitive-not-recorded" if cause == "pressure-unknown" else PRESSURE.replace("full avg10=0", "full avg10=3"))
            elif cause == "controller-dead-or-reused":
                io.observe = lambda pid: None
            elif cause == "deadline":
                io.deadline = 100
            elif cause in ("lease-stale", "lease-clock-invalid"):
                (Path(io.root) / "lease").write_text(json.dumps(dict(self.record, monotonic=0 if cause == "lease-stale" else 101)))
            else:
                (Path(io.root) / ("controller" if cause == "controller-unknown" else "lease")).unlink()
            with self.subTest(cause=cause), self.assertRaises(g.GuardRefusal):
                io.check()
            self.assertEqual(io.fast_probe["reasons"], [cause])
            self.assertNotIn("sensitive-not-recorded", io.files.read("state"))


class CLIOutcome(unittest.TestCase):
    setup_io = driver_tests.BoundDriver.setup_io

    def test_real_cli_start_abort_no_admit_and_all_jobs_complete(self):
        for scenario in ("start-abort", "no-admit", "no-proof", "complete"):
            io, host = self.setup_io()
            if scenario == "start-abort":
                io.lease_age = lambda: None if host.memory == 4096 else 0
            elif scenario == "no-admit":
                io.admit_text = lambda: None
            elif scenario == "no-proof":
                io.proof = None
                io.checkout = "/opt/toolstack"
            def factory(root, cfg, latch, checkout, source):
                io.latch = latch
                return io
            def bounded_guard(io, cfg, latch, clock, sleeper):
                return run_guard(io, cfg, latch, io.clock, lambda seconds: None, max_ticks=8)
            argv = ["guard", "--execute", "--live", "--run-id", RUN, "--root", "/var/tmp/" + RUN,
                    "--checkout", "discover", "--baseline", "nod:healthy", "--archive", "/fake/source.tar",
                    "--source-commit", host.source.commit, "--archive-sha256", host.source.sha256]
            with patch.object(linux, "host_gate"), patch("vm_proof_driver.Source.load", return_value=host.source), \
                    patch.object(linux, "LinuxSubprocessIO", side_effect=factory), \
                    patch.object(linux, "run_guard", side_effect=bounded_guard), \
                    patch.object(linux.signal, "signal"), patch.object(io, "close"):
                code = linux.cli(argv)
            result = json.loads(io.files.read("result"))
            self.assertEqual(code, 0 if scenario == "complete" else 1)
            self.assertEqual(result["proof_complete"], scenario == "complete")
            self.assertEqual(result["ask_parent"], scenario != "complete")
            self.assertEqual(result["restored"], scenario != "no-admit")
            if scenario != "complete":
                self.assertIn("proof-incomplete", result["reasons"])
                self.assertFalse(host.jobs)
            if scenario == "start-abort":
                self.assertEqual(host.memory, 8192)
                self.assertNotIn(("qm", "start", "130"), host.calls)
