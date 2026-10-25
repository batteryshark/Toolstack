"""Finite VM 130 state machine. CLI binds LinuxSubprocessIO; default is dry-run."""

from __future__ import annotations

import os
import stat
import sys
import threading
from dataclasses import dataclass

from vm_proof_guard import (
    GUEST_TIMEOUT,
    NOD_CURL,
    PRODUCTION_VMID,
    PROOF_VMID,
    TEST_MEMORY_MIB,
    GuardConfig,
    GuardRefusal,
    ProofRecords,
    PressureState,
    Sample,
    Vm130Config,
    agent_ready_argv,
    assess,
    canonical_container_id,
    guard_signal_argv,
    parse_allowlisted_config,
    parse_free_available_mib,
    parse_memavailable_kib,
    parse_pressure,
    parse_qm_status,
    production_ps_argv,
    require_run_id,
    rollback,
    start_gate,
)

PVE_PARENT = "/var/tmp/toolstack-vm-proof"
SAMPLE_INTERVAL = 5
MAX_TICKS = 40 * 60 // SAMPLE_INTERVAL
AGENT_WAIT_TICKS = 6
SHUTDOWN_SUBPROCESS_TIMEOUT = 100
BUILD_SUBPROCESS_TIMEOUT = 1210
PRIVATE_FILES = frozenset({"config", "state", "ready", "log", "pid"})


class StopLatch:
    def __init__(self) -> None:
        self.reason: str | None = None
        self.lock = threading.RLock()

    def closed(self) -> bool:
        return self.reason is not None

    def trip(self, reason: str) -> None:
        with self.lock:
            if self.reason is None:
                self.reason = reason

    def before_effect(self) -> None:
        if self.closed():
            raise GuardRefusal("stop latch is closed")


@dataclass(frozen=True)
class AdapterResult:
    ask_parent: bool
    phase: str
    reasons: tuple[str, ...]
    restored: bool


def timeout_for(argv: tuple[str, ...]) -> int:
    if argv[:2] == ("qm", "shutdown"):
        return SHUTDOWN_SUBPROCESS_TIMEOUT
    if argv[:2] == ("qm", "start"):
        return 30
    if argv[:2] in {("qm", "set"), ("qm", "status"), ("qm", "config")}:
        return 15
    if argv[:1] == ("curl",):
        return 10
    if argv[:1] == ("free",):
        return 5
    if argv[:2] == ("kill", "-TERM") or argv[:2] == ("kill", "-KILL"):
        if len(argv) == 3 and argv[2].isdigit() and int(argv[2]) > 1:
            return 5
    if argv[:3] == ("qm", "guest", "exec-status") or (argv[:3] == ("qm", "guest", "exec") and "--synchronous" in argv):
        return 45
    if argv[:3] == ("qm", "guest", "exec") and "build" in argv:
        return BUILD_SUBPROCESS_TIMEOUT
    if argv[:3] == ("qm", "guest", "exec"):
        return 45
    if argv[:1] == ("docker",):
        return 60
    raise GuardRefusal("command has no finite timeout")


def guest_exec(inner: tuple[str, ...], timeout: str) -> tuple[str, ...]:
    if not timeout.isdigit() or int(timeout) <= 0 or int(timeout) > 1200:
        raise GuardRefusal("guest exec timeout is not a finite bound")
    return ("qm", "guest", "exec", PROOF_VMID, "--timeout", timeout, "--", *inner)


def prepare_run_root(parent: str, run_id: str) -> str:
    require_run_id(run_id)
    if not parent.startswith("/") or ".." in parent.split("/"):
        raise GuardRefusal("parent path is not absolute")
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise GuardRefusal("parent is not a real directory") from exc
    try:
        try:
            os.mkdir(run_id, 0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise GuardRefusal("run root is not absent") from exc
        leaf = os.open(run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            os.fchmod(leaf, 0o700)
            info = os.fstat(leaf)
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
                raise GuardRefusal("run root mode is not 0700")
        finally:
            os.close(leaf)
    finally:
        os.close(parent_fd)
    return parent.rstrip("/") + "/" + run_id


def write_private(root: str, name: str, text: str) -> None:
    if name not in PRIVATE_FILES:
        raise GuardRefusal("helper does not write that file")
    if name in {"lease", "admit"}:
        raise GuardRefusal("helper does not write lease or admit")
    payload = text if text.endswith("\n") else text + "\n"
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fd = os.open(
                name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=root_fd,
            )
        except OSError as exc:
            raise GuardRefusal("private file already exists") from exc
        try:
            os.write(fd, payload.encode())
            os.fsync(fd)
            os.fchmod(fd, 0o600)
            if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
                raise GuardRefusal("private file mode is not 0600")
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def parse_starttime(stat_text: str) -> int | None:
    end = stat_text.rfind(")")
    if end < 0:
        return None
    fields = stat_text[end + 1:].split()
    if len(fields) <= 19 or not fields[19].isdigit():
        return None
    value = int(fields[19])
    return value if value > 0 else None


def ready_text(run_id: str, pid: int, start: int) -> str:
    require_run_id(run_id)
    if pid <= 1 or start <= 0:
        raise GuardRefusal("ready identity is not a private process")
    return f"{run_id}\n{pid} {start}\n"


def cancel_owned_child(io, pid: int, start: int) -> str:
    observed = io.observe(pid)
    argv = guard_signal_argv(pid, start, pid if observed == start else None, observed)
    if argv is None:
        return "not-signalled"
    io.run(argv, timeout_for(argv))
    if io.observe(pid) != start:
        return "termed"
    io.run(("kill", "-KILL", str(pid)), timeout_for(("kill", "-KILL", str(pid))))
    if io.observe(pid) == start:
        return "still-alive"
    return "killed"


def create_record_start(io, latch: StopLatch, create_argv: tuple[str, ...]) -> str:
    latch.before_effect()
    wrapped = guest_exec(create_argv, GUEST_TIMEOUT)
    created = io.run(wrapped, timeout_for(wrapped))
    container_id = canonical_container_id(created.stdout)
    if created.code != 0 or container_id is None:
        latch.trip("create-id-unknown")
        raise GuardRefusal("container id was not 64 hex characters")
    io.record_container(container_id)
    latch.before_effect()
    start = guest_exec(("docker", "start", container_id), GUEST_TIMEOUT)
    started = io.run(start, timeout_for(start))
    if started.code != 0:
        latch.trip("container-start-failed")
        raise GuardRefusal("recorded container did not start")
    return container_id


def begin_build(io, latch: StopLatch, build_argv: tuple[str, ...]) -> tuple[int, int]:
    latch.before_effect()
    if build_argv[:2] != ("docker", "build"):
        raise GuardRefusal("build fence accepts only docker build")
    wrapped = guest_exec(build_argv, "1200")
    return io.spawn(wrapped, timeout_for(wrapped))


def run_guard(io, config: GuardConfig, latch: StopLatch, clock, sleeper, *, max_ticks: int = MAX_TICKS) -> AdapterResult:
    if max_ticks <= 0 or max_ticks > MAX_TICKS:
        raise GuardRefusal("tick budget is not finite")
    phase = "watch"
    ready = False
    agent_until = None
    reasons: list[str] = []
    started = clock()
    io.owned_resize = False
    io.owned_start = False
    try:
        pid, start = io.identity()
        io.write_new("pid", ready_text(config.run_id, pid, start))
        for tick in range(max_ticks):
            if latch.closed():
                break
            elapsed = clock() - started
            sample, vm130 = _fresh(io, config, elapsed)
            trip = assess(sample, config)
            if trip.rollback:
                latch.trip(trip.reasons[0])
                reasons.extend(trip.reasons)
                break
            if io.owned_resize and (vm130.memory_mib not in (4096, 8192)
                    or vm130.cores != 2 or vm130.onboot != 0):
                latch.trip("ownership-or-shape-drift")
                break
            if not ready and not start_gate(sample, config, vm130).rollback:
                io.write_new("ready", ready_text(config.run_id, pid, start))
                ready = True
            if phase == "watch":
                if not (ready and io.admit_text() == config.run_id):
                    if tick + 1 == max_ticks:
                        latch.trip("tick-limit")
                        break
                    sleeper(SAMPLE_INTERVAL)
                    continue
                phase = "start"
            if phase == "start":
                if not _start_guest(io, latch, config, clock() - started):
                    break
                phase = "agent"
                agent_until = tick + AGENT_WAIT_TICKS
                continue
            if phase == "agent":
                probed = io.run(agent_ready_argv(), timeout_for(agent_ready_argv()))
                if probed.code == 0:
                    phase = "monitor"
                    # Fixed live sequence: metadata then guarded source/Docker proof.
                    if hasattr(io, "metadata_proof"):
                        io.metadata_proof(latch)
                        latch.trip("proof-complete")
                        break
                    continue
                if agent_until is not None and tick >= agent_until:
                    latch.trip("guest-agent-unavailable")
                    break
                sleeper(SAMPLE_INTERVAL)
                continue
            if tick + 1 == max_ticks:
                latch.trip("tick-limit")
                break
            sleeper(SAMPLE_INTERVAL)
        latch.trip("finished")
        if hasattr(io, "begin_cleanup"):
            io.begin_cleanup()
        _cancel_children(io)
        report = _safe_rollback(io, config)
        ask = report.ask_parent
    except Exception:
        latch.trip(latch.reason or "exception")
        if hasattr(io, "begin_cleanup"):
            io.begin_cleanup()
        _cancel_children(io)
        report = _safe_rollback(io, config)
        reasons.append("exception")
        ask = True
    if latch.reason:
        reasons.append(latch.reason)
    merged = tuple(dict.fromkeys(reasons + list(report.reasons)))
    return AdapterResult(ask, phase, merged, report.restored)


def dry_run_plan(run_id: str) -> str:
    require_run_id(run_id)
    root = f"/var/tmp/{run_id}"
    return "\n".join((
        "dry-run: no host command is executed",
        f"python3 vm_proof_adapter.py controller --execute --live --root {root} --run-id {run_id} --checkout discover --source-commit COMMIT40 --archive-sha256 SHA64 --archive /PRIVATE/source.tar --baseline nod:healthy",
        "guard never writes lease or admit; foreground controller owns both",
        "controller PID and Linux starttime must match; lease age over 90 seconds rolls back",
        "ready acknowledgement and a fresh gate are required before qm set 130 --memory 4096",
        "confirm stopped, memory 4096, cores 2, onboot 0, then qm start 130",
        "guest agent /bin/true must answer within 6 samples or the helper rolls back",
        "one qm shutdown 130 --timeout 90 with subprocess timeout 100; no qm stop or forceStop",
        "qm set 130 --memory 8192 only after status stopped and cores/onboot are unchanged",
        "payload: exact parent-supplied git commit/archive sha256, validated before boot and guest extraction",
        "fixed async build/create/start sequence only; no arbitrary commands or in-place owner updates",
    ))


def main(argv: list[str] | None = None) -> int:
    from vm_proof_linux import cli
    return cli(argv)


def _fresh(io, config: GuardConfig, elapsed: float) -> tuple[Sample, Vm130Config]:
    if hasattr(io, "note_sample"):
        io.note_sample()
    meminfo = io.read("/proc/meminfo")
    pressure_text = io.read("/proc/pressure/memory")
    pressure = parse_pressure(pressure_text) if pressure_text is not None else None
    if not hasattr(io, "pressure_state"):
        io.pressure_state = PressureState()
    pressure_trip = io.pressure_state.observe(io.clock() if hasattr(io, "clock") else elapsed, pressure)
    if hasattr(io, "checkpoint"):
        io.checkpoint()
    available = parse_memavailable_kib(meminfo or "")
    if available is None or available < 1536 * 1024 or pressure_trip.rollback:
        # Known local emergency must not wait on QGA/HTTP production probes.
        return Sample(available, pressure is not None,
                      None if pressure is None else pressure.full_avg10,
                      None, None, None, io.lease_age(), elapsed, None,
                      None if pressure is None else pressure.full_avg60,
                      pressure_trip), Vm130Config(None, None, None, None)
    free = io.run(("free", "-m"), timeout_for(("free", "-m")))
    vm100 = io.run(("qm", "status", PRODUCTION_VMID), timeout_for(("qm", "status", PRODUCTION_VMID)))
    vm130 = io.run(("qm", "status", PROOF_VMID), timeout_for(("qm", "status", PROOF_VMID)))
    cfg = io.run(("qm", "config", PROOF_VMID), timeout_for(("qm", "config", PROOF_VMID)))
    nod = io.run(NOD_CURL, timeout_for(NOD_CURL))
    prod = io.run(production_ps_argv(), timeout_for(production_ps_argv()))
    sample = Sample(
        mem_available_kib=parse_memavailable_kib(meminfo or ""),
        pressure_readable=pressure is not None,
        full_avg10=None if pressure is None else pressure.full_avg10,
        full_avg60=None if pressure is None else pressure.full_avg60,
        pressure_trip=pressure_trip,
        vm100_status=parse_qm_status(vm100.stdout) if vm100.code == 0 else None,
        nod_body=nod.stdout if nod.code == 0 else None,
        production=_production_rows(prod.stdout) if prod.code == 0 else None,
        lease_age_seconds=io.lease_age(),
        elapsed_seconds=elapsed,
        free_available_mib=parse_free_available_mib(free.stdout) if free.code == 0 else None,
    )
    parsed = parse_allowlisted_config(cfg.stdout) if cfg.code == 0 else None
    status = parse_qm_status(vm130.stdout) if vm130.code == 0 else None
    if parsed is None:
        return sample, Vm130Config(status, None, None, None)
    return sample, Vm130Config(status, parsed.memory_mib, parsed.cores, parsed.onboot)


def _start_guest(io, latch: StopLatch, config: GuardConfig, elapsed: float) -> bool:
    latch.before_effect()
    sample, vm130 = _fresh(io, config, elapsed)
    gate = start_gate(sample, config, vm130)
    if sample.production is None or {name for name, _ in sample.production} != {item.name for item in config.baseline}:
        latch.trip("production-baseline-incomplete")
        return False
    if gate.rollback:
        latch.trip(gate.reasons[0] if gate.reasons else "start-gate")
        return False
    latch.before_effect()
    resize = ("qm", "set", PROOF_VMID, "--memory", str(TEST_MEMORY_MIB))
    # Record intent before issuing a command whose result can be lost.
    io.baseline_snapshot = vm130
    io.owned_resize = True
    if hasattr(io, "checkpoint"):
        io.checkpoint()
    if io.run(resize, timeout_for(resize)).code != 0:
        latch.trip("resize-failed")
        return False
    status = io.run(("qm", "status", PROOF_VMID), timeout_for(("qm", "status", PROOF_VMID)))
    cfg = io.run(("qm", "config", PROOF_VMID), timeout_for(("qm", "config", PROOF_VMID)))
    parsed = parse_allowlisted_config(cfg.stdout) if cfg.code == 0 else None
    confirmed = (
        status.code == 0 and parse_qm_status(status.stdout) == "stopped"
        and parsed is not None
        and parsed.memory_mib == TEST_MEMORY_MIB
        and parsed.cores == 2
        and parsed.onboot == 0
    )
    if not confirmed:
        latch.trip("resize-unconfirmed")
        return False
    latch.before_effect()
    start = ("qm", "start", PROOF_VMID)
    io.owned_start = True
    if hasattr(io, "checkpoint"):
        io.checkpoint()
    if io.run(start, timeout_for(start)).code != 0:
        latch.trip("start-failed")
        return False
    return True


def _production_rows(text: str) -> tuple[tuple[str, str], ...]:
    rows = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        name, state = line.split("\t", 1)
        rows.append((name, state))
    return tuple(rows)


def _cancel_children(io) -> None:
    if hasattr(io, "cancel_all"):
        io.cancel_all()
        return
    for pid, start in io.children():
        try:
            cancel_owned_child(io, pid, start)
        except Exception:
            continue


def _safe_rollback(io, config: GuardConfig):
    from vm_proof_guard import RollbackReport
    if not getattr(io, "owned_resize", False):
        return RollbackReport(False, False, ("no-owned-transition",), ())
    try:
        status = io.run(("qm", "status", "130"), 15)
        current = io.run(("qm", "config", "130"), 15)
        shape = parse_allowlisted_config(current.stdout) if current.code == 0 else None
        state = parse_qm_status(status.stdout) if status.code == 0 else None
        if (shape is None or shape.memory_mib not in (4096, 8192)
                or shape.cores != 2 or shape.onboot != 0 or state is None
                or (state == "running" and (not io.owned_start or shape.memory_mib != 4096))):
            return RollbackReport(False, True, ("ownership-or-shape-drift",), ())
        proof = getattr(io, "proof", None)
        proof_reasons = []
        if proof is not None and state == "running":
            try:
                proof_reasons = proof.cleanup()
            except Exception:
                proof_reasons = ["proof-cleanup-unknown: shutdown fence required"]
        elif proof is not None and proof.root_attempted:
            proof_reasons = ["guest already stopped: owned proof artifacts may remain"]
        report = rollback(_Runner(io), config, io.records(), skip_guest_cleanup=proof is not None)
        if proof_reasons:
            from dataclasses import replace
            report = replace(report, ask_parent=True, restored=False,
                             reasons=(*report.reasons, *proof_reasons))
        return report
    except Exception:
        # Final production observations remain read-only even if rollback failed.
        from vm_proof_guard import _confirm_production
        reasons = ["rollback-failed"]
        try:
            _confirm_production(_Runner(io).run, config, reasons)
        except Exception:
            reasons.append("production-confirmation-unknown")
        return RollbackReport(False, True, tuple(reasons), ())


def rollback_failure():
    from vm_proof_guard import RollbackReport
    return RollbackReport(False, True, ("rollback-failed",), ())


class _Runner:
    def __init__(self, io) -> None:
        self.io = io

    def run(self, argv: tuple[str, ...]):
        return self.io.run(argv, timeout_for(argv))


if __name__ == "__main__":
    raise SystemExit(main())
