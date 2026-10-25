"""Fake-command tests for the VM proof guard. No host, SSH, or Docker access."""

from pathlib import Path
import json
import unittest

from vm_proof_guard import (
    PROOF_PS_FORMAT,
    LABEL_KEY,
    HEADROOM_MIB,
    HEAVY_BUILD_ATTEMPTS,
    MEMORY_FLOOR_MIB,
    NOD_HEALTH_BODY,
    PARENT_FREE_AVAILABLE_MIB,
    PARENT_MEM_AVAILABLE_KIB,
    BaselineContainer,
    Completed,
    GuardConfig,
    GuardRefusal,
    ListedContainer,
    ProofRecords,
    Sample,
    Vm130Config,
    admin_serve_argv,
    agent_ready_argv,
    assess,
    canonical_container_id,
    completed_from_guest,
    image_owned,
    nod_health_ok,
    content_check_argv,
    drive,
    echo_build_argv,
    guard_signal_argv,
    listen_argv,
    loopback_probe_argv,
    main,
    onebox_build_argv,
    parse_free_available_mib,
    parse_memavailable_kib,
    parse_pressure,
    process_meta_argv,
    recovery_commands,
    redact_qm_config,
    rollback,
    rollback_command_allowed,
    select_owned,
    set_password_argv,
    start_attached_argv,
    start_commands,
    start_recorded_argv,
    start_gate,
    unit_list_argv,
)

ROOT = Path(__file__).resolve().parents[2]
RUN = "vmproof-20261024T150000Z-a1b2c3d4"
OWNED = "a" * 64
OTHER = "b" * 64
SHORT = "a" * 12
IMAGE = "sha256:" + "c" * 64
SECRET = "cipassword: stage1-must-not-store"
BASELINE = (BaselineContainer("nod", "healthy"),)


def config() -> GuardConfig:
    return GuardConfig(RUN, BASELINE)


def sample(**overrides) -> Sample:
    values = dict(
        mem_available_kib=PARENT_MEM_AVAILABLE_KIB,
        pressure_readable=True,
        full_avg10=0.0,
        full_avg60=0.0,
        vm100_status="running",
        nod_body=NOD_HEALTH_BODY,
        production=(("nod", "Up 11 days (healthy)"),),
        lease_age_seconds=0.0,
        elapsed_seconds=0.0,
    )
    values.update(overrides)
    return Sample(**values)


def stopped_vm(**overrides) -> Vm130Config:
    values = dict(status="stopped", memory_mib=8192, cores=2, onboot=0)
    values.update(overrides)
    return Vm130Config(**values)


class FakeHost:
    def __init__(self, *, shutdown_sticks=False, status_unknown=False, list_fails=False,
                 stop_fails=False, image_in_use=False):
        self.calls = []
        self.vm130 = "running"
        self.memory = 4096
        self.shutdown_sticks = shutdown_sticks
        self.status_unknown = status_unknown
        self.list_fails = list_fails
        self.stop_fails = stop_fails
        self.image_in_use = image_in_use
        self.containers = {OWNED: RUN, OTHER: ""}

    def run(self, argv):
        self.calls.append(argv)
        if argv == ("qm", "status", "130"):
            text = "status: mystery" if self.status_unknown else f"status: {self.vm130}"
            return Completed(0, text)
        if argv == ("qm", "status", "100"):
            return Completed(0, "status: running")
        if argv == ("qm", "config", "130"):
            return Completed(0, f"memory: {self.memory}\ncores: 2\nonboot: 0\nagent: 1\n{SECRET}\n")
        if argv == ("qm", "shutdown", "130", "--timeout", "90"):
            if not self.shutdown_sticks:
                self.vm130 = "stopped"
            return Completed(0, "")
        if argv == ("qm", "set", "130", "--memory", "8192"):
            if self.vm130 != "stopped":
                return Completed(1, "refusing live memory change")
            self.memory = 8192
            return Completed(0, "")
        inner = argv[7:]
        if inner == ("docker", "ps", "-a", "--no-trunc", "--format", PROOF_PS_FORMAT):
            if self.list_fails:
                return Completed(1, "")
            lines = [f"{cid}\t{label}\tname-{cid[:4]}" for cid, label in self.containers.items()]
            return Completed(0, "\n".join(lines))
        if inner[:4] == ("docker", "stop", "--time", "10"):
            if self.stop_fails:
                return Completed(1, "stop failed")
            return Completed(0, inner[4])
        if inner[:2] == ("docker", "rm"):
            self.containers.pop(inner[2], None)
            return Completed(0, "")
        if inner[:5] == ("docker", "ps", "-a", "--no-trunc", "--filter"):
            return Completed(0, f"{OTHER}\n" if self.image_in_use else "")
        if inner[:3] == ("docker", "image", "inspect"):
            tags = json.dumps([f"toolstack-vmproof:{RUN}"])
            labels = json.dumps({LABEL_KEY: RUN})
            return Completed(0, f"{IMAGE}\t{tags}\t{labels}")
        if inner[:3] == ("docker", "image", "rm"):
            return Completed(0, "")
        if argv[0] == "curl":
            return Completed(0, NOD_HEALTH_BODY)
        if inner == ("docker", "ps", "--format", "{{.Names}}\t{{.Status}}"):
            return Completed(0, "nod\tUp 11 days (healthy)")
        raise AssertionError(argv)


def records() -> ProofRecords:
    return ProofRecords(RUN, (OWNED,), (IMAGE,))


def run_rollback(host: FakeHost):
    return rollback(host, config(), records())


class Assess(unittest.TestCase):
    def test_parent_baseline_continues(self):
        trip = assess(sample(), config())
        self.assertFalse(trip.rollback)
        self.assertEqual(trip.reasons, ())

    def test_low_memory_rolls_back(self):
        trip = assess(sample(mem_available_kib=MEMORY_FLOOR_MIB * 1024 - 1), config())
        self.assertTrue(trip.rollback)
        self.assertIn("mem-floor", trip.reasons)
        self.assertEqual(drive((sample(), sample(mem_available_kib=1)), config()), "rollback")

    def test_floor_boundary_is_below_not_equal(self):
        trip = assess(sample(mem_available_kib=MEMORY_FLOOR_MIB * 1024), config())
        self.assertFalse(trip.rollback)

    def test_bad_nod_health_rolls_back(self):
        trip = assess(sample(nod_body='{"ok":false,"service":"nod"}'), config())
        self.assertIn("nod-unhealthy", trip.reasons)

    def test_unknown_probes_roll_back(self):
        cases = (
            sample(mem_available_kib=None),
            sample(pressure_readable=False, full_avg10=None),
            sample(vm100_status=None),
            sample(nod_body=None),
            sample(production=None),
            sample(lease_age_seconds=None),
        )
        expected = (
            "mem-unknown", "pressure-unknown", "vm100-unknown",
            "nod-unknown", "production-unknown", "parent-lease-unknown",
        )
        for item, reason in zip(cases, expected):
            with self.subTest(reason=reason):
                self.assertIn(reason, assess(item, config()).reasons)

    def test_vm100_stopped_and_unhealthy_container(self):
        self.assertIn("vm100-not-running", assess(sample(vm100_status="stopped"), config()).reasons)
        bad = sample(production=(("nod", "Up 11 days (unhealthy)"),))
        self.assertIn("production-unhealthy:nod", assess(bad, config()).reasons)

    def test_full_pressure_stall_rolls_back_some_does_not(self):
        self.assertFalse(assess(sample(full_avg10=0.01), config()).rollback)
        self.assertIn("pressure-preboot-unsettled", assess(sample(full_avg10=2.01), config()).reasons)
        parsed = parse_pressure(
            "some avg10=1.00 avg60=0.00 avg300=0.00 total=46239720\n"
            "full avg10=0.00 avg60=0.00 avg300=0.00 total=41255963\n"
        )
        self.assertEqual(parsed.some_avg10, 1.0)
        self.assertFalse(assess(sample(full_avg10=parsed.full_avg10), config()).rollback)

    def test_lease_and_window_boundaries(self):
        self.assertFalse(assess(sample(lease_age_seconds=90), config()).rollback)
        self.assertIn("parent-lease-stale", assess(sample(lease_age_seconds=91), config()).reasons)
        self.assertFalse(assess(sample(elapsed_seconds=40 * 60 - 1), config()).rollback)
        self.assertIn("window-expired", assess(sample(elapsed_seconds=40 * 60), config()).reasons)

    def test_nonfinite_probes_and_bad_baseline_fail_closed(self):
        self.assertIsNone(parse_pressure(
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n"
            "full avg10=nan avg60=0.00 avg300=0.00 total=1\n"
        ))
        self.assertIsNone(parse_pressure(
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n"
            "full avg10=inf avg60=0.00 avg300=0.00 total=1\n"
        ))
        self.assertIn("pressure-unknown", assess(sample(full_avg10=float("nan")), config()).reasons)
        self.assertIn("window-unknown", assess(sample(elapsed_seconds=float("-inf")), config()).reasons)
        self.assertIn("parent-lease-unknown", assess(sample(lease_age_seconds=float("nan")), config()).reasons)
        self.assertIn("free-unknown", assess(sample(free_available_mib=None), config()).reasons)
        self.assertIn("probe-config-invalid", assess(sample(), GuardConfig(RUN, BASELINE, window_seconds=0)).reasons)
        self.assertIn("production-unknown", assess(sample(), GuardConfig(RUN, (BaselineContainer("nod", "yes"),))).reasons)
        self.assertTrue(nod_health_ok('{"service": "nod", "ok": true}'))
        self.assertFalse(nod_health_ok('{"ok": true, "service": "nod", "extra": 1}'))
        self.assertFalse(assess(sample(nod_body='{"ok": true, "service": "nod"}'), config()).rollback)

    def test_empty_baseline_is_unknown(self):
        trip = assess(sample(), GuardConfig(RUN, ()))
        self.assertIn("production-unknown", trip.reasons)

    def test_parent_meminfo_and_free_parsers(self):
        self.assertEqual(parse_memavailable_kib("MemAvailable:    7194384 kB\n"), PARENT_MEM_AVAILABLE_KIB)
        text = "               total        used        free      shared  buff/cache   available\nMem:           7950        1000         500          10        2000        6952\n"
        self.assertEqual(parse_free_available_mib(text), PARENT_FREE_AVAILABLE_MIB)
        self.assertIsNone(parse_pressure("not pressure"))


class OwnedFilter(unittest.TestCase):
    def test_both_id_and_label_required(self):
        listed = (
            ListedContainer(OWNED, RUN, "proof"),
            ListedContainer(OTHER, "", "preexisting"),
            ListedContainer("d" * 64, RUN, "unrecorded"),
            ListedContainer(SHORT, RUN, "truncated"),
            ListedContainer("not-an-id", RUN, "bad"),
        )
        recorded = (OWNED, "e" * 12)
        selection = select_owned(RUN, recorded, listed)
        self.assertEqual(selection.stop, (OWNED,))
        self.assertIn(f"not-owned:{'d' * 64}", selection.mismatch)
        self.assertIn("malformed-id:truncated", selection.mismatch)
        self.assertIn("malformed-id:bad", selection.mismatch)
        self.assertIn("recorded-id-rejected:" + "e" * 12, selection.mismatch)
        self.assertNotIn(SHORT, selection.stop)
        self.assertNotIn(OTHER, selection.stop)

    def test_image_id_tag_and_label_must_all_match(self):
        tags = json.dumps([f"toolstack-vmproof-echo-mcp:{RUN}"])
        labels = json.dumps({LABEL_KEY: RUN})
        self.assertTrue(image_owned(f"{IMAGE}\t{tags}\t{labels}", RUN, IMAGE))
        shared = json.dumps([f"toolstack-vmproof:{RUN}", "python:3.12-slim"])
        self.assertFalse(image_owned(f"{IMAGE}\t{shared}\t{labels}", RUN, IMAGE))
        self.assertFalse(image_owned(f"{IMAGE}\t{tags}\t{{}}", RUN, IMAGE))
        self.assertIsNone(canonical_container_id(SHORT))
        self.assertIsNone(canonical_container_id(IMAGE))


class RollbackMachine(unittest.TestCase):
    def test_command_order_filters_preexisting_and_hides_config_secret(self):
        host = FakeHost()
        report = run_rollback(host)
        self.assertTrue(report.restored)
        self.assertFalse(report.ask_parent)
        self.assertNotIn(SECRET, repr(report))
        stop = self._index(host, ("docker", "stop", "--time", "10", OWNED))
        remove = self._index(host, ("docker", "rm", OWNED))
        image = self._index(host, ("docker", "image", "rm", IMAGE))
        shutdown = self._index(host, ("qm", "shutdown", "130", "--timeout", "90"))
        statuses = [i for i, call in enumerate(host.calls) if call == ("qm", "status", "130")]
        self.assertEqual(len([i for i in statuses if i > shutdown]), 2)  # final restore recheck
        restore = self._index(host, ("qm", "set", "130", "--memory", "8192"))
        confirm = self._index(host, ("qm", "status", "100"))
        self.assertLess(stop, remove)
        self.assertLess(remove, image)
        self.assertLess(image, shutdown)
        self.assertLess(shutdown, restore)
        self.assertLess(restore, confirm)
        self.assertNotIn(("docker", "stop", "--time", "10", OTHER), [call[7:] for call in host.calls])
        self._assert_no_forbidden(host)

    def test_idempotent_second_cleanup_does_not_repeat_mutations(self):
        host = FakeHost()
        first = run_rollback(host)
        self.assertTrue(first.restored)
        host.calls.clear()
        second = run_rollback(host)
        self.assertTrue(second.restored)
        joined = [" ".join(call) for call in host.calls]
        self.assertFalse(any("shutdown" in call or "docker stop" in call or "--memory" in call for call in joined))
        self.assertIn(("qm", "status", "100"), host.calls)
        self._assert_no_forbidden(host)

    def test_graceful_shutdown_failure_does_not_poweroff_or_restore(self):
        host = FakeHost(shutdown_sticks=True)
        report = run_rollback(host)
        self.assertFalse(report.restored)
        self.assertTrue(report.ask_parent)
        self.assertIn("graceful-shutdown-failed", report.reasons)
        self.assertNotIn(("qm", "set", "130", "--memory", "8192"), host.calls)
        self._assert_no_forbidden(host)
        self.assertIn(("qm", "status", "100"), host.calls)

    def test_failed_shutdown_retry_remains_graceful(self):
        host = FakeHost(shutdown_sticks=True)
        run_rollback(host)
        host.calls.clear()
        second = run_rollback(host)
        self.assertIn("graceful-shutdown-failed", second.reasons)
        self.assertEqual([call for call in host.calls if call[:2] == ("qm", "shutdown")], [
            ("qm", "shutdown", "130", "--timeout", "90"),
        ])
        self._assert_no_forbidden(host)

    def test_unknown_vm_status_changes_nothing(self):
        host = FakeHost(status_unknown=True)
        report = run_rollback(host)
        self.assertTrue(report.ask_parent)
        self.assertIn("vm130-status-unknown", report.reasons)
        self.assertNotIn(("qm", "shutdown", "130", "--timeout", "90"), host.calls)
        self._assert_no_forbidden(host)

    def test_unknown_container_list_does_not_stop_unidentified_containers(self):
        host = FakeHost(list_fails=True)
        report = run_rollback(host)
        self.assertIn("owned-list-unknown", report.reasons)
        self.assertFalse(any(call[7:9] == ("docker", "stop") for call in host.calls if len(call) > 8))
        self.assertIn(("qm", "shutdown", "130", "--timeout", "90"), host.calls)

    def test_docker_stop_failure_does_not_kill(self):
        host = FakeHost(stop_fails=True)
        report = run_rollback(host)
        self.assertIn(f"docker-stop-failed:{OWNED}", report.reasons)
        self.assertFalse(any("kill" in call for call in host.calls))
        self.assertIn(("qm", "shutdown", "130", "--timeout", "90"), host.calls)

    def test_image_in_use_is_not_removed(self):
        host = FakeHost(image_in_use=True)
        report = run_rollback(host)
        self.assertIn(f"image-in-use:{IMAGE}", report.reasons)
        self.assertFalse(any(call[7:10] == ("docker", "image", "rm") for call in host.calls if len(call) > 9))

    def test_allowlist_rejects_production_and_broad_cleanup(self):
        rejected = (
            ("qm", "stop", "130"),
            ("qm", "set", "100", "--memory", "8192"),
            ("qm", "set", "130", "--memory", "4096"),
            ("qm", "shutdown", "130", "--timeout", "90", "--forceStop", "1"),
            ("qm", "guest", "exec", "120", "--timeout", "15", "--", "docker", "ps"),
            ("qm", "guest", "exec", "100", "--timeout", "15", "--", "docker", "stop", OWNED),
            ("qm", "guest", "exec", "130", "--timeout", "30", "--", "docker", "kill", OWNED),
            ("qm", "guest", "exec", "130", "--timeout", "30", "--", "docker", "system", "prune", "-f"),
            ("kill", "-9", "-1"),
        )
        for argv in rejected:
            with self.subTest(argv=argv):
                with self.assertRaises(GuardRefusal):
                    rollback_command_allowed(argv, RUN)

    def _index(self, host, inner):
        for index, argv in enumerate(host.calls):
            if argv == inner or argv[7:] == inner:
                return index
        self.fail(inner)

    def _assert_no_forbidden(self, host):
        for argv in host.calls:
            self.assertNotIn("stop", argv[1:2])
            self.assertNotIn("prune", argv)
            self.assertNotIn("120", argv)
            self.assertNotIn("--forceStop", argv)
            self.assertNotEqual(argv[:2], ("qm", "stop"))


class StartAndIdentity(unittest.TestCase):
    def test_parent_baseline_start_is_allowed_and_ordered(self):
        gate = start_gate(sample(), config(), stopped_vm())
        self.assertFalse(gate.rollback)
        self.assertEqual(start_commands(gate), (
            ("qm", "set", "130", "--memory", "4096"),
            ("qm", "start", "130"),
        ))

    def test_headroom_between_floor_and_reservation_refuses_start(self):
        gate = start_gate(sample(mem_available_kib=2048 * 1024), config(), stopped_vm())
        self.assertIn("mem-headroom", gate.reasons)
        self.assertNotIn("mem-floor", gate.reasons)
        self.assertEqual(start_commands(gate), ())
        self.assertEqual(HEADROOM_MIB, 5632)

    def test_resized_stopped_guest_recovers_without_start(self):
        self.assertEqual(recovery_commands(stopped_vm(memory_mib=4096)), (
            ("qm", "set", "130", "--memory", "8192"),
        ))
        self.assertEqual(recovery_commands(stopped_vm()), ())
        self.assertIsNone(recovery_commands(stopped_vm(status="running", memory_mib=4096)))
        self.assertIsNone(recovery_commands(stopped_vm(memory_mib=4096, cores=4)))

    def test_signal_requires_exact_start_identity(self):
        self.assertEqual(guard_signal_argv(44, 100, 44, 100), ("kill", "-TERM", "44"))
        self.assertIsNone(guard_signal_argv(44, 100, 44, 101))
        self.assertIsNone(guard_signal_argv(44, 100, None, None))
        self.assertIsNone(guard_signal_argv(1, 100, 1, 100))

    def test_config_redaction_and_secret_guest_payload(self):
        self.assertNotIn(SECRET, redact_qm_config(f"memory: 8192\n{SECRET}\n"))
        payload = json.dumps({"exitcode": 0, "exited": 1, "out-data": SECRET})
        self.assertEqual(completed_from_guest(payload).stdout, "")
        self.assertEqual(completed_from_guest(payload).code, 1)

    def test_main_refuses_host_execution(self):
        self.assertEqual(main([]), 2)
        self.assertIn("host execution refused", "guard library; host execution refused")
        source = (ROOT / "tests/release/vm_proof_guard.py").read_text()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)


class ProofArgv(unittest.TestCase):
    def test_builds_are_unique_root_context_and_one_heavy_attempt(self):
        self.assertEqual(HEAVY_BUILD_ATTEMPTS, 1)
        onebox = onebox_build_argv(RUN)
        echo = echo_build_argv(RUN, "tools/echo_mcp/Dockerfile")
        self.assertEqual(onebox[-1], ".")
        self.assertIn("deploy/docker/Dockerfile", onebox)
        self.assertIn("tools/echo_mcp/Dockerfile", echo)
        self.assertEqual(echo[-1], ".")
        self.assertNotIn("compose", onebox + echo)
        with self.assertRaises(GuardRefusal):
            echo_build_argv(RUN, "deploy/docker/Dockerfile")

    def test_runtime_is_loopback_without_socket_or_password(self):
        secret = "fake-password-not-in-argv"
        root = "/var/tmp/toolstack-vm-proof/" + RUN
        data = root + "/data"
        image = f"toolstack-vmproof:{RUN}"
        argv = set_password_argv(RUN, image, data, root) + admin_serve_argv(RUN, image, data, root, 18080)
        argv += content_check_argv(RUN, image) + loopback_probe_argv(18080, "/login")
        text = " ".join(argv)
        self.assertNotIn(secret, text)
        self.assertNotIn("0.0.0.0:", text)
        self.assertNotIn("docker.sock", text)
        self.assertNotIn("--rm", argv)
        self.assertIn("127.0.0.1:18080:8780", text)
        self.assertIn("--network none", text)
        self.assertIn("--restart no", text)
        self.assertEqual(start_recorded_argv(OWNED), ("docker", "start", OWNED))
        with self.assertRaises(GuardRefusal):
            start_recorded_argv(SHORT)
        self.assertEqual(start_attached_argv(OWNED)[:3], ("docker", "start", "-a"))
        with self.assertRaises(GuardRefusal):
            admin_serve_argv(RUN, image, "/opt/toolstack", root, 18080)
        with self.assertRaises(GuardRefusal):
            loopback_probe_argv(18080, "/v1/health")

    def test_boot_inventory_commands_have_no_journal_or_env(self):
        listed = " ".join(unit_list_argv() + listen_argv() + process_meta_argv() + agent_ready_argv())
        self.assertNotIn("journalctl", listed)
        self.assertNotIn("args", process_meta_argv()[-1])
        self.assertIn("comm", process_meta_argv()[-1])
        self.assertIn("/bin/true", agent_ready_argv())


if __name__ == "__main__":
    unittest.main()
