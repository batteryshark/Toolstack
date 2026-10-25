"""Chief PSI rule: pure boundaries and real binding with fake PVE only."""
import dataclasses
import json
import unittest

import vm_proof_guard as g
from vm_proof_adapter import _fresh, _start_guest, _safe_rollback
import test_vm_proof_driver as driver_tests
from test_vm_proof_guard import sample, config


def psi(avg10=3, avg60=0):
    return g.Pressure(0, avg10, avg60)


def text(avg10=3, avg60=0):
    return ("some avg10=0 avg60=0 avg300=0 total=0\n"
            f"full avg10={avg10} avg60={avg60} avg300=0 total=0\n")


class PressureBoundaries(unittest.TestCase):
    def tracker(self):
        state = g.PressureState()
        state.begin_boot(100)
        return state

    def test_grace_does_not_accumulate_and_exact_duration(self):
        state = self.tracker()
        for now in (100, 150, 189.999):
            self.assertFalse(state.observe(now, psi(50, 50)).rollback)
            self.assertIsNone(state.high_since)
        self.assertFalse(state.observe(190, psi()).rollback)
        self.assertEqual(state.high_since, 190)
        self.assertFalse(state.observe(219.999, psi()).rollback)
        self.assertEqual(state.observe(220, psi()).reasons, ("pressure-full-sustained",))

    def test_exact_avg10_resets_and_positive_below_threshold_passes(self):
        state = self.tracker()
        state.observe(190, psi())
        self.assertFalse(state.observe(219, psi(2)).rollback)
        self.assertIsNone(state.high_since)
        for now, value in ((220, 0.18), (230, 0.001), (240, 2)):
            self.assertFalse(state.observe(now, psi(value)).rollback)
        state.observe(250, psi(2.00001))
        self.assertFalse(state.observe(279.999, psi()).rollback)
        self.assertTrue(state.observe(280, psi()).rollback)

    def test_avg60_strict_and_grace_boundary(self):
        state = self.tracker()
        self.assertFalse(state.observe(189.999, psi(0, 99)).rollback)
        self.assertFalse(state.observe(190, psi(0, 1)).rollback)
        self.assertEqual(state.observe(190, psi(0, 1.00001)).reasons, ("pressure-full-avg60",))

    def test_unknown_resets_and_clock_fault_cannot_recover(self):
        for bad in (None, psi(float("nan")), psi(1, float("inf")), psi(-1)):
            state = self.tracker()
            state.observe(190, psi())
            self.assertTrue(state.observe(210, bad).rollback)
            self.assertIsNone(state.high_since)
            self.assertFalse(state.observe(220, psi()).rollback)
            self.assertEqual(state.high_since, 220)
        for now in (189, float("nan"), float("inf"), -1):
            state = self.tracker()
            state.observe(190, psi())
            self.assertTrue(state.observe(now, psi(0)).rollback)
            self.assertIsNone(state.high_since)
            self.assertTrue(state.observe(250, psi(0)).rollback)
        state = self.tracker()
        state.observe(210, None)
        self.assertTrue(state.observe(200, psi(0)).rollback)
        state = self.tracker()
        g.assess(sample(elapsed_seconds=190, full_avg10=3), config(), state)
        self.assertEqual(state.high_since, 190)
        self.assertTrue(g.assess(sample(elapsed_seconds=210, full_avg60=None), config(), state).rollback)
        self.assertIsNone(state.high_since)

    def test_preboot_conservative_and_no_reboot_grace(self):
        state = g.PressureState()
        self.assertFalse(state.observe(0, psi(2, 1)).rollback)
        self.assertEqual(state.observe(1, psi()).reasons, ("pressure-preboot-unsettled",))
        self.assertEqual(state.observe(31, psi()).reasons, ("pressure-full-sustained",))
        self.assertTrue(state.observe(32, psi(0, 1.01)).rollback)
        state.begin_boot(33)
        with self.assertRaises(g.GuardRefusal):
            state.begin_boot(34)

    def test_malformed_missing_duplicate_negative_nonfinite(self):
        for bad in ("", "full avg10=0", text().replace("avg60=0", "avg60=nan"),
                    text().replace("avg10=3", "avg10=-1"), text(0, "inf"),
                    text() + text(), text().replace("total=0", "total=0 total=0")):
            self.assertIsNone(g.parse_pressure(bad), bad)
        self.assertEqual(g.parse_pressure(text(0.18, 1.01)).full_avg60, 1.01)

    def test_grace_never_bypasses_other_guards_or_missing_avg60(self):
        state = self.tracker()
        trip = state.observe(101, psi(99, 99))
        base = sample(full_avg10=99, full_avg60=99, pressure_trip=trip)
        self.assertFalse(g.assess(base, config()).rollback)
        for fields in ({"mem_available_kib": 1536 * 1024 - 1}, {"nod_body": "{}"},
                       {"vm100_status": None}, {"production": None}, {"lease_age_seconds": 91},
                       {"pressure_readable": False}, {"full_avg60": None}, {"free_available_mib": None}):
            self.assertTrue(g.assess(dataclasses.replace(base, **fields), config()).rollback, fields)


class BoundPressure(unittest.TestCase):
    setup_io = driver_tests.BoundDriver.setup_io

    def ready(self):
        io, host = self.setup_io()
        self.now = 100
        io.clock = lambda: self.now
        io.deadline = 2500
        self.values = (0.18, 0)
        io.read = lambda path: "MemAvailable: 7100000 kB" if path == "/proc/meminfo" else text(*self.values)
        return io, host

    def test_start_spawn_has_durable_origin_and_during_start_grace(self):
        io, host = self.ready()
        original = io.popen
        def spawn(argv, **kwargs):
            if tuple(argv[1:]) == ("start", "130"):
                state = json.loads(io.files.read("state"))["pressure"]
                self.assertEqual(state["boot_monotonic"], 100)
                self.values = (20, 20)
                self.now = 110
            return original(argv, **kwargs)
        io.popen = spawn
        self.assertTrue(_start_guest(io, io.latch, io.config, 0))
        self.assertFalse(io.latch.closed())
        self.assertEqual(io.pressure_state.boot_monotonic, 100)
        with self.assertRaises(g.GuardRefusal):
            io.run(("qm", "start", "130"), 30)
        self.assertEqual(host.calls.count(("qm", "start", "130")), 1)

    def test_fast_fresh_driver_share_history_and_rollback_still_restores(self):
        io, host = self.ready()
        self.assertTrue(_start_guest(io, io.latch, io.config, 0))
        self.values = (3, 0)
        self.now = 190
        io.check()
        self.now = 210
        value, _ = _fresh(io, io.config, 110)
        self.assertFalse(g.assess(value, io.config).rollback)
        self.now = 219.999
        io.proof.health()
        self.assertEqual(io.pressure_state.high_since, 190)
        self.now = 220
        with self.assertRaises(g.GuardRefusal):
            io.proof.health()
        snapshot = json.loads(io.files.read("state"))["pressure"]
        self.assertEqual(snapshot["observation"]["reason"], "pressure-full-sustained")
        io.begin_cleanup()
        self.assertTrue(_safe_rollback(io, io.config).restored)
        self.assertEqual((host.vm, host.memory), ("stopped", 8192))

    def test_preboot_high_blocks_all_effects(self):
        for values in ((3, 0), (0, 1.001)):
            io, host = self.ready()
            self.values = values
            self.assertFalse(_start_guest(io, io.latch, io.config, 0))
            self.assertIsNone(io.pressure_state.boot_monotonic)
            self.assertFalse(host.calls)

    def test_lost_start_reply_has_finite_origin_and_no_second_boot(self):
        io, host = self.ready()
        original = host.command
        def command(argv, data):
            if argv == ("qm", "start", "130"):
                host.vm = "running"
                raise OSError("fake lost spawn response")
            return original(argv, data)
        host.command = command
        with self.assertRaises(OSError):
            _start_guest(io, io.latch, io.config, 0)
        self.assertEqual(io.pressure_state.boot_monotonic, 100)
        self.now = 190
        self.values = (0, 1.001)
        with self.assertRaises(g.GuardRefusal):
            io.check()
        self.assertIn("pressure-full-avg60", io.fast_probe["reasons"])
        with self.assertRaises(g.GuardRefusal):
            io.run(("qm", "start", "130"), 30)
        io.begin_cleanup()
        self.assertTrue(_safe_rollback(io, io.config).restored)

    def test_preflight_failure_never_creates_boot_origin(self):
        io, host = self.ready()
        io.owned_start = True
        host.memory = 8192  # qm start final preflight requires stopped4096.
        with self.assertRaises(g.GuardRefusal):
            io.run(("qm", "start", "130"), 30)
        self.assertIsNone(io.pressure_state.boot_monotonic)
        self.assertNotIn(("qm", "start", "130"), host.calls)

    def test_driver_grace_still_observes_bad_nod_and_production(self):
        for bad in ("nod", "production", "vm100", "unknown-psi", "memory"):
            io, host = self.ready()
            self.assertTrue(_start_guest(io, io.latch, io.config, 0))
            self.values = (20, 20)
            original = host.command
            def command(argv, data):
                if bad == "nod" and argv[0] == "curl":
                    return "{}"
                if bad == "production" and argv == g.production_ps_argv():
                    return host.qga("nod\tUp (unhealthy)")
                if bad == "vm100" and argv == ("qm", "status", "100"):
                    return "unknown"
                return original(argv, data)
            host.command = command
            if bad in ("unknown-psi", "memory"):
                io.read = lambda path: ("MemAvailable: 1 kB" if bad == "memory" else "MemAvailable: 7100000 kB") if path == "/proc/meminfo" else ("invalid" if bad == "unknown-psi" else text(20, 20))
            with self.assertRaises(g.GuardRefusal):
                io.proof.health()
