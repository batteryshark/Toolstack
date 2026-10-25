"""Fake filesystem and command tests for the finite VM proof adapter."""

from pathlib import Path
import contextlib
import io
import os
import stat
import tempfile
import unittest

from vm_proof_adapter import (
    SHUTDOWN_SUBPROCESS_TIMEOUT,
    StopLatch,
    begin_build,
    cancel_owned_child,
    create_record_start,
    dry_run_plan,
    main,
    prepare_run_root,
    parse_starttime,
    run_guard,
    timeout_for,
    write_private,
)
from vm_proof_guard import (
    PROOF_PS_FORMAT,
    NOD_HEALTH_BODY,
    PARENT_MEM_AVAILABLE_KIB,
    BaselineContainer,
    Completed,
    GuardConfig,
    GuardRefusal,
    ProofRecords,
    agent_ready_argv,
    onebox_build_argv,
)

RUN = "vmproof-20261024T150000Z-a1b2c3d4"
FULL_ID = "ab" * 32
PRESSURE = (
    "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n"
    "full avg10=0.00 avg60=0.00 avg300=0.00 total=1\n"
)
FREE = (
    "               total        used        free      shared  buff/cache   available\n"
    "Mem:           7950        1000         500          10        2000        6952\n"
)


def config() -> GuardConfig:
    return GuardConfig(RUN, (BaselineContainer("nod", "healthy"),))


class FakeIO:
    def __init__(self):
        self.calls = []
        self.timeouts = []
        self.writes = []
        self.events = []
        self.vm130 = "stopped"
        self.memory = 8192
        self.admit = None
        self.lease = 0.0
        self.start_code = 0
        self.agent_code = 0
        self.fail = None
        self.container_ids = []
        self.child_list = []
        self.observed = {}
        self.low_after_start = False
        self.pressure = PRESSURE
        self.nod = NOD_HEALTH_BODY
        self.prod = "nod\tUp 11 days (healthy)"
        self.spawned = []

    def run(self, argv, timeout):
        self.calls.append(argv)
        self.timeouts.append(timeout)
        self.events.append(("run", argv))
        if self.fail is not None:
            exc = self.fail
            self.fail = None
            raise exc
        if timeout != timeout_for(argv):
            raise AssertionError((argv, timeout))
        if argv == ("qm", "set", "130", "--memory", "4096"):
            if self.vm130 != "stopped":
                return Completed(1, "")
            self.memory = 4096
            return Completed(0, "")
        if argv == ("qm", "start", "130"):
            if self.start_code == 0:
                self.vm130 = "running"
            return Completed(self.start_code, "")
        if argv == ("qm", "shutdown", "130", "--timeout", "90"):
            self.vm130 = "stopped"
            return Completed(0, "")
        if argv == ("qm", "set", "130", "--memory", "8192"):
            if self.vm130 != "stopped":
                return Completed(1, "")
            self.memory = 8192
            return Completed(0, "")
        if argv == ("qm", "status", "130"):
            return Completed(0, f"status: {self.vm130}")
        if argv == ("qm", "status", "100"):
            return Completed(0, "status: running")
        if argv == ("qm", "config", "130"):
            return Completed(0, f"memory: {self.memory}\ncores: 2\nonboot: 0\nagent: 1\n")
        if argv[0] == "curl":
            return Completed(0, self.nod)
        if argv[0] == "free":
            return Completed(0, FREE)
        if argv[:4] == ("qm", "guest", "exec", "100"):
            return Completed(0, self.prod)
        if argv == agent_ready_argv():
            return Completed(self.agent_code, "")
        if argv[:4] == ("qm", "guest", "exec", "130"):
            return self._guest(argv[7:])
        if argv[:1] == ("kill",):
            self.observed.pop(int(argv[2]), None)
            return Completed(0, "")
        raise AssertionError(argv)

    def _guest(self, inner):
        if inner[:2] == ("docker", "create"):
            return Completed(0, FULL_ID + "\n")
        if inner[:2] == ("docker", "start"):
            return Completed(0, FULL_ID)
        if inner == ("docker", "ps", "-a", "--no-trunc", "--format", PROOF_PS_FORMAT):
            return Completed(0, "")
        if inner[:5] == ("docker", "ps", "-a", "--no-trunc", "--filter"):
            return Completed(0, "")
        return Completed(0, "")

    def read(self, path):
        if path == "/proc/meminfo":
            kib = 1 if self.low_after_start and ("qm", "start", "130") in self.calls else PARENT_MEM_AVAILABLE_KIB
            return f"MemAvailable: {kib} kB\n"
        if path == "/proc/pressure/memory":
            return self.pressure
        return None

    def lease_age(self):
        return self.lease

    def admit_text(self):
        return self.admit

    def identity(self):
        return (44, 100)

    def children(self):
        return tuple(self.child_list)

    def observe(self, pid):
        return self.observed.get(pid)

    def write_new(self, name, text):
        if name in {item[0] for item in self.writes}:
            raise GuardRefusal("no-clobber")
        self.writes.append((name, text))

    def record_container(self, container_id):
        self.events.append(("record", container_id))
        self.container_ids.append(container_id)

    def records(self):
        return ProofRecords(RUN, tuple(self.container_ids), ())

    def spawn(self, argv, timeout):
        self.spawned.append((argv, timeout))
        self.child_list.append((55, 200))
        self.observed[55] = 200
        return (55, 200)


def run(io, ticks=4):
    return run_guard(io, config(), StopLatch(), lambda: 0.0, lambda _seconds: None, max_ticks=ticks)


class AdapterSafety(unittest.TestCase):
    def test_ready_is_written_before_resize_and_without_admit_nothing_starts(self):
        io = FakeIO()
        result = run(io, ticks=2)
        self.assertIn("ready", [name for name, _text in io.writes])
        self.assertNotIn(("qm", "set", "130", "--memory", "4096"), io.calls)
        self.assertNotIn("lease", [name for name, _text in io.writes])
        self.assertNotIn("admit", [name for name, _text in io.writes])
        self.assertIn("tick-limit", result.reasons)
        self.assertFalse(result.restored)
        self.assertIn("no-owned-transition", result.reasons)

    def test_lost_lease_and_bad_production_and_unknown_do_not_resize(self):
        leased = FakeIO()
        leased.lease = 100
        leased.admit = RUN
        self.assertIn("parent-lease-stale", run(leased, ticks=2).reasons)
        self.assertNotIn(("qm", "set", "130", "--memory", "4096"), leased.calls)
        bad = FakeIO()
        bad.prod = "nod\tUp 11 days (unhealthy)"
        bad.admit = RUN
        self.assertIn("production-unhealthy:nod", run(bad, ticks=1).reasons)
        unknown = FakeIO()
        unknown.pressure = None
        unknown.admit = RUN
        self.assertIn("pressure-unknown", run(unknown, ticks=1).reasons)
        self.assertNotIn(("qm", "start", "130"), unknown.calls)

    def test_running_guest_and_low_headroom_do_not_write_ready_or_resize(self):
        running = FakeIO()
        running.vm130 = "running"
        running.admit = RUN
        run(running, ticks=1)
        self.assertNotIn("ready", [name for name, _text in running.writes])
        self.assertNotIn(("qm", "set", "130", "--memory", "4096"), running.calls)
        tight = FakeIO()
        tight.admit = RUN

        def tight_read(path):
            if path == "/proc/meminfo":
                return "MemAvailable: 2097152 kB\n"
            return FakeIO.read(tight, path)

        tight.read = tight_read
        run(tight, ticks=1)
        self.assertNotIn(("qm", "set", "130", "--memory", "4096"), tight.calls)

    def test_start_failure_after_resize_restores_without_force(self):
        io = FakeIO()
        io.admit = RUN
        io.start_code = 1
        result = run(io, ticks=2)
        self.assertEqual(io.calls.count(("qm", "start", "130")), 1)
        self.assertIn(("qm", "set", "130", "--memory", "8192"), io.calls)
        self.assertLess(
            io.calls.index(("qm", "set", "130", "--memory", "4096")),
            io.calls.index(("qm", "start", "130")),
        )
        self.assertNotIn(("qm", "stop", "130"), io.calls)
        self.assertNotIn("--forceStop", [part for call in io.calls for part in call])
        self.assertEqual(io.memory, 8192)
        self.assertIn("start-failed", result.reasons)
        self.assertTrue(result.ask_parent or result.restored)

    def test_guest_agent_failure_shuts_down_once_with_finite_timeout(self):
        io = FakeIO()
        io.admit = RUN
        io.agent_code = 1
        result = run(io, ticks=10)
        self.assertIn("guest-agent-unavailable", result.reasons)
        self.assertEqual(io.calls.count(("qm", "shutdown", "130", "--timeout", "90")), 1)
        shutdown = io.calls.index(("qm", "shutdown", "130", "--timeout", "90"))
        self.assertEqual(io.timeouts[shutdown], SHUTDOWN_SUBPROCESS_TIMEOUT)
        self.assertNotIn(("qm", "stop", "130"), io.calls)
        self.assertEqual(io.memory, 8192)

    def test_low_memory_after_start_rolls_back_and_does_not_build(self):
        io = FakeIO()
        io.admit = RUN
        io.low_after_start = True
        result = run(io, ticks=4)
        self.assertIn("mem-floor", result.reasons)
        self.assertIn(("qm", "shutdown", "130", "--timeout", "90"), io.calls)
        self.assertFalse(any("build" in call for call in io.calls))

    def test_exception_funnels_to_rollback_without_start(self):
        io = FakeIO()
        io.admit = RUN
        io.fail = RuntimeError("probe failed")
        result = run(io, ticks=2)
        self.assertTrue(result.ask_parent)
        self.assertIn("exception", result.reasons)
        self.assertNotIn(("qm", "start", "130"), io.calls)

    def test_late_create_and_build_are_refused_after_stop(self):
        io = FakeIO()
        latch = StopLatch()
        latch.trip("late")
        with self.assertRaises(GuardRefusal):
            create_record_start(io, latch, ("docker", "create", "image"))
        with self.assertRaises(GuardRefusal):
            begin_build(io, latch, onebox_build_argv(RUN))
        self.assertEqual(io.calls, [])
        self.assertEqual(io.spawned, [])

    def test_create_records_full_id_before_start(self):
        io = FakeIO()
        container_id = create_record_start(io, StopLatch(), ("docker", "create", "--label", "x", "image"))
        self.assertEqual(container_id, FULL_ID)
        record_at = io.events.index(("record", FULL_ID))
        start_at = next(i for i, event in enumerate(io.events) if event[0] == "run" and event[1][7:9] == ("docker", "start"))
        self.assertLess(record_at, start_at)
        short = FakeIO()

        def short_run(argv, timeout):
            short.calls.append(argv)
            if argv[7:9] == ("docker", "create"):
                return Completed(0, "a" * 12)
            return Completed(0, "")

        short.run = short_run
        with self.assertRaises(GuardRefusal):
            create_record_start(short, StopLatch(), ("docker", "create", "image"))
        self.assertFalse(any(len(call) > 8 and call[7:9] == ("docker", "start") for call in short.calls))

    def test_cancel_uses_exact_pid_and_starttime_only(self):
        io = FakeIO()
        io.observed[44] = 101
        self.assertEqual(cancel_owned_child(io, 44, 100), "not-signalled")
        self.assertEqual(io.calls, [])
        io.observed[44] = 100

        def observe_forever(pid):
            return 100 if pid == 44 else None

        io.observe = observe_forever
        self.assertEqual(cancel_owned_child(io, 44, 100), "still-alive")
        self.assertEqual(io.calls, [("kill", "-TERM", "44"), ("kill", "-KILL", "44")])

    def test_private_root_is_absent_only_and_refuses_symlink_and_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = prepare_run_root(tmp, RUN)
            self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)
            write_private(root, "state", "container " + FULL_ID)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(root, "state")).st_mode), 0o600)
            with self.assertRaises(GuardRefusal):
                prepare_run_root(tmp, RUN)
            with self.assertRaises(GuardRefusal):
                write_private(root, "state", "overwrite")
            with self.assertRaises(GuardRefusal):
                write_private(root, "lease", "no")
            link_parent = os.path.join(tmp, "linked")
            os.symlink(tmp, link_parent)
            with self.assertRaises(GuardRefusal):
                prepare_run_root(link_parent, "vmproof-20261024T150001Z-a1b2c3d4")
            os.symlink(os.path.join(root, "state"), os.path.join(root, "log"))
            with self.assertRaises(GuardRefusal):
                write_private(root, "log", "through-symlink")

    def test_starttime_parser_and_dry_run_do_not_touch_a_host(self):
        self.assertEqual(parse_starttime("44 (python foo) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 99"), 99)
        self.assertIsNone(parse_starttime("not a stat"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
        self.assertEqual(main(["--execute", "--root", "/tmp/not-pve", "--run-id", RUN]), 2)
        plan = dry_run_plan(RUN)
        self.assertIn("no host command is executed", plan)
        self.assertIn("never writes lease", plan)
        self.assertIn("100", plan)
        source = Path(__file__).with_name("vm_proof_adapter.py").read_text()
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("subprocess.run", source)


if __name__ == "__main__":
    unittest.main()
