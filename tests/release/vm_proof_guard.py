"""Fail-closed VM 130 proof guard. Library only; this file does not contact a host.

Tests inject a fake executor. Rollback stops a container only when its recorded
full 64-character id and unique label both match, and removes an image only when
its sha256 id, run label, and exact run tag all match. It shuts VM 130 down
once and restores 8192 MiB only after that guest is stopped.

Tripwires, any one of which rolls back: MemAvailable below 1.5 GiB, unreadable
pressure, full-memory stall, VM 100 not running, Nod health not the exact
parent body, baseline production container metadata missing or unhealthy,
unknown probe output, stale parent lease, or the resource window elapsing.
Rollback stops only containers whose recorded id and unique label both match,
shuts VM 130 down gracefully, and restores 8192 MiB only after it is stopped.
It never poweroffs a guest, prunes, or signals an unverified PID.
"""

from __future__ import annotations

import json
import math
import re
import sys
from dataclasses import dataclass

PROOF_VMID = "130"
PRODUCTION_VMID = "100"
TEST_MEMORY_MIB = 4096
RESTORE_MEMORY_MIB = 8192
REQUIRED_CORES = 2
REQUIRED_ONBOOT = 0
MEMORY_FLOOR_MIB = 1536
HEADROOM_MIB = TEST_MEMORY_MIB + MEMORY_FLOOR_MIB
NOD_HEALTH_URL = "http://192.168.1.199:8767/health"
NOD_HEALTH_BODY = '{"ok":true,"service":"nod"}'
LABEL_KEY = "toolstack.vmproof"
LEASE_STALE_SECONDS = 90
WINDOW_SECONDS = 40 * 60
SHUTDOWN_TIMEOUT = "90"
GUEST_TIMEOUT = "30"
PRODUCTION_TIMEOUT = "15"
HEAVY_BUILD_ATTEMPTS = 1
STATUS_CHECKS_AFTER_SHUTDOWN = 1
# Parent read-only baseline, 2026-10-24. Not a live reading.
PARENT_MEM_AVAILABLE_KIB = 7194384
PARENT_FREE_AVAILABLE_MIB = 6952

RUN_ID_RE = re.compile(r"^vmproof-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_MARKERS = (
    "cipassword",
    "BEGIN PRIVATE",
    "BEGIN OPENSSH",
    "SP_VAULT_PASSPHRASE",
)

NOD_CURL = (
    "curl", "--noproxy", "*", "-fsS",
    "--connect-timeout", "2", "--max-time", "5",
    NOD_HEALTH_URL,
)
PRODUCTION_PS_FORMAT = "{{.Names}}\t{{.Status}}"
PROOF_PS_FORMAT = '{{.ID}}\t{{.Label "toolstack.vmproof"}}\t{{.Names}}'
IMAGE_INSPECT_FORMAT = "{{.Id}}\t{{json .RepoTags}}\t{{json .Config.Labels}}"
BASELINE_EXPECTATIONS = frozenset({"healthy", "running"})


class GuardRefusal(Exception):
    """A command or identity the guard must not act on."""


@dataclass(frozen=True)
class Completed:
    code: int
    stdout: str


@dataclass(frozen=True)
class BaselineContainer:
    name: str
    expect: str


@dataclass(frozen=True)
class GuardConfig:
    run_id: str
    baseline: tuple[BaselineContainer, ...]
    window_seconds: int = WINDOW_SECONDS
    lease_stale_seconds: int = LEASE_STALE_SECONDS


@dataclass(frozen=True)
class Sample:
    mem_available_kib: int | None
    pressure_readable: bool
    full_avg10: float | None
    vm100_status: str | None
    nod_body: str | None
    production: tuple[tuple[str, str], ...] | None
    lease_age_seconds: float | None
    elapsed_seconds: float
    free_available_mib: int | None = PARENT_FREE_AVAILABLE_MIB
    full_avg60: float | None = None
    pressure_trip: Trip | None = None


@dataclass(frozen=True)
class Trip:
    rollback: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Vm130Config:
    status: str | None
    memory_mib: int | None
    cores: int | None
    onboot: int | None


@dataclass(frozen=True)
class ListedContainer:
    container_id: str
    label: str
    name: str


@dataclass(frozen=True)
class OwnedSelection:
    stop: tuple[str, ...]
    mismatch: tuple[str, ...]
    absent: tuple[str, ...]


@dataclass(frozen=True)
class ProofRecords:
    run_id: str
    container_ids: tuple[str, ...]
    image_ids: tuple[str, ...]


@dataclass(frozen=True)
class RollbackReport:
    restored: bool
    ask_parent: bool
    reasons: tuple[str, ...]
    commands: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class Pressure:
    some_avg10: float
    full_avg10: float
    full_avg60: float


class PressureState:
    """One host-monotonic history per guard; never reconstructed from guest time."""
    def __init__(self):
        self.boot_monotonic = None
        self.high_since = None
        self.last_monotonic = None
        self.fault = None
        self.observation = None

    def begin_boot(self, now):
        if (self.boot_monotonic is not None or self.fault
                or not _finite_nonnegative(now)
                or self.last_monotonic is not None and now < self.last_monotonic):
            self.high_since = None
            self.fault = "pressure-clock-or-boot-invalid"
            raise GuardRefusal(self.fault)
        self.boot_monotonic = now
        self.last_monotonic = now
        self.high_since = None

    def observe(self, now, pressure):
        reason = None
        if (not _finite_nonnegative(now)
                or self.last_monotonic is not None and now < self.last_monotonic):
            self.fault = "pressure-clock-invalid"
        if not self.fault:
            self.last_monotonic = now
        if self.fault:
            reason = self.fault
        elif pressure is None or not all(_finite_nonnegative(v) for v in
                                        (pressure.some_avg10, pressure.full_avg10, pressure.full_avg60)):
            reason = "pressure-unknown"
        else:
            if self.boot_monotonic is not None and now < self.boot_monotonic + 90:
                self.high_since = None
            else:
                if pressure.full_avg10 > 2.0:
                    if self.high_since is None:
                        self.high_since = now
                else:
                    self.high_since = None
                if pressure.full_avg60 > 1.0:
                    reason = "pressure-full-avg60"
                elif self.high_since is not None:
                    if now - self.high_since >= 30:
                        reason = "pressure-full-sustained"
                    elif self.boot_monotonic is None:
                        # No boot grace before admission; do not boot into an
                        # unresolved high-pressure interval of unknown onset.
                        reason = "pressure-preboot-unsettled"
        if reason == "pressure-unknown" or self.fault:
            self.high_since = None
        self.observation = {
            "monotonic": now if _finite_nonnegative(now) else None,
            "full_avg10": pressure.full_avg10 if pressure and _finite_nonnegative(pressure.full_avg10) else None,
            "full_avg60": pressure.full_avg60 if pressure and _finite_nonnegative(pressure.full_avg60) else None,
            "reason": reason or "pressure-valid",
        }
        return Trip(reason is not None, (reason,) if reason else ())

    def snapshot(self):
        return dict(boot_monotonic=self.boot_monotonic, high_since=self.high_since,
                    last_monotonic=self.last_monotonic, fault=self.fault,
                    grace_seconds=90, avg10_above=2.0, sustained_seconds=30,
                    avg60_above=1.0, observation=self.observation)


def require_run_id(run_id: str) -> None:
    if not RUN_ID_RE.fullmatch(run_id):
        raise GuardRefusal("run id is not the private proof form")


def parse_memavailable_kib(text: str) -> int | None:
    for line in text.splitlines():
        if not line.startswith("MemAvailable:"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
        return None
    return None


def parse_free_available_mib(text: str) -> int | None:
    """Cross-check only. MemAvailable remains the trip source."""
    header = None
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "Mem:" and header is not None:
            if header[-1].lower() != "available" or not parts[-1].isdigit():
                return None
            return int(parts[-1])
        if "available" in [item.lower() for item in parts]:
            header = parts
    return None


def parse_pressure(text: str) -> Pressure | None:
    some = full = None
    full60 = None
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] not in {"some", "full"} or parts[0] in seen:
            return None
        seen.add(parts[0])
        values = {}
        for item in parts[1:]:
            if "=" not in item:
                return None
            key, raw = item.split("=", 1)
            if key in values:
                return None
            try:
                values[key] = float(raw)
            except ValueError:
                return None
        if set(values) != {"avg10", "avg60", "avg300", "total"} or not all(_finite_nonnegative(v) for v in values.values()):
            return None
        if parts[0] == "some":
            some = values["avg10"]
        elif parts[0] == "full":
            full = values["avg10"]
            full60 = values["avg60"]
    if some is None or full is None:
        return None
    return Pressure(some, full, full60)


def nod_health_ok(body: str | None) -> bool:
    """Exact ok/service fields. Whitespace may differ; extra fields fail closed."""
    if body is None:
        return False
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    return (
        isinstance(data, dict)
        and set(data) == {"ok", "service"}
        and data["ok"] is True
        and data["service"] == "nod"
    )


def canonical_container_id(text: str) -> str | None:
    text = text.strip()
    if CONTAINER_ID_RE.fullmatch(text):
        return text
    return None


def canonical_image_id(text: str) -> str | None:
    text = text.strip()
    if IMAGE_ID_RE.fullmatch(text):
        return text
    return None


def run_tags(run_id: str) -> frozenset[str]:
    require_run_id(run_id)
    return frozenset({
        f"toolstack-vmproof:{run_id}",
        f"toolstack-vmproof-echo-mcp:{run_id}",
        f"toolstack-vmproof-echo-api:{run_id}",
    })


def _finite_nonnegative(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _nonnegative_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def assess(sample: Sample, config: GuardConfig, pressure_state=None) -> Trip:
    require_run_id(config.run_id)
    reasons: list[str] = []
    if not _nonnegative_int(config.window_seconds) or config.window_seconds <= 0:
        reasons.append("probe-config-invalid")
    if not _nonnegative_int(config.lease_stale_seconds) or config.lease_stale_seconds <= 0:
        reasons.append("probe-config-invalid")
    if not _nonnegative_int(sample.mem_available_kib):
        reasons.append("mem-unknown")
    elif sample.mem_available_kib < MEMORY_FLOOR_MIB * 1024:
        reasons.append("mem-floor")
    if not _nonnegative_int(sample.free_available_mib):
        reasons.append("free-unknown")
    pressure_valid = (sample.pressure_readable and _finite_nonnegative(sample.full_avg10)
                      and _finite_nonnegative(sample.full_avg60))
    pressure_trip = sample.pressure_trip
    if pressure_trip is None:
        pressure_trip = (pressure_state or PressureState()).observe(
            sample.elapsed_seconds,
            Pressure(0, sample.full_avg10, sample.full_avg60) if pressure_valid else None)
    if not pressure_valid:
        reasons.append("pressure-unknown")
    reasons.extend(pressure_trip.reasons)
    if sample.vm100_status is None:
        reasons.append("vm100-unknown")
    elif sample.vm100_status != "running":
        reasons.append("vm100-not-running")
    if sample.nod_body is None:
        reasons.append("nod-unknown")
    elif not nod_health_ok(sample.nod_body):
        reasons.append("nod-unhealthy")
    reasons.extend(_production_reasons(sample.production, config.baseline))
    if not _finite_nonnegative(sample.lease_age_seconds):
        reasons.append("parent-lease-unknown")
    elif sample.lease_age_seconds > config.lease_stale_seconds:
        reasons.append("parent-lease-stale")
    if not _finite_nonnegative(sample.elapsed_seconds):
        reasons.append("window-unknown")
    elif sample.elapsed_seconds >= config.window_seconds:
        reasons.append("window-expired")
    return Trip(bool(reasons), tuple(dict.fromkeys(reasons)))


def _production_reasons(production, baseline: tuple[BaselineContainer, ...]) -> list[str]:
    if not baseline or production is None:
        return ["production-unknown"]
    found = dict(production)
    reasons = []
    for item in baseline:
        if item.expect not in BASELINE_EXPECTATIONS or not item.name or "/" in item.name:
            reasons.append("production-unknown")
            continue
        status = found.get(item.name)
        if status is None:
            reasons.append(f"production-missing:{item.name}")
        elif item.expect == "healthy" and "(healthy)" not in status:
            reasons.append(f"production-unhealthy:{item.name}")
        elif item.expect == "running" and (
            not status.startswith("Up") or "unhealthy" in status
        ):
            reasons.append(f"production-unhealthy:{item.name}")
    return reasons


def start_gate(sample: Sample, config: GuardConfig, vm130: Vm130Config) -> Trip:
    reasons = list(assess(sample, config).reasons)
    if vm130.status != "stopped":
        reasons.append("vm130-not-stopped")
    if vm130.memory_mib != RESTORE_MEMORY_MIB:
        reasons.append("vm130-memory-not-baseline")
    if vm130.cores != REQUIRED_CORES or vm130.onboot != REQUIRED_ONBOOT:
        reasons.append("vm130-shape-drift")
    if sample.mem_available_kib is None or sample.mem_available_kib < HEADROOM_MIB * 1024:
        reasons.append("mem-headroom")
    return Trip(bool(reasons), tuple(dict.fromkeys(reasons)))


def start_commands(gate: Trip) -> tuple[tuple[str, ...], ...]:
    if gate.rollback:
        return ()
    commands = (
        ("qm", "set", PROOF_VMID, "--memory", str(TEST_MEMORY_MIB)),
        ("qm", "start", PROOF_VMID),
    )
    for command in commands:
        start_command_allowed(command)
    return commands


def recovery_commands(vm130: Vm130Config) -> tuple[tuple[str, ...], ...] | None:
    """Restore memory only when the guest is stopped and its shape is unchanged."""
    if vm130.status != "stopped" or vm130.cores != REQUIRED_CORES or vm130.onboot != REQUIRED_ONBOOT:
        return None
    if vm130.memory_mib == RESTORE_MEMORY_MIB:
        return ()
    if vm130.memory_mib != TEST_MEMORY_MIB:
        return None
    return (("qm", "set", PROOF_VMID, "--memory", str(RESTORE_MEMORY_MIB)),)


def select_owned(
    run_id: str,
    recorded_ids: tuple[str, ...],
    listed: tuple[ListedContainer, ...],
) -> OwnedSelection:
    require_run_id(run_id)
    recorded = {cid for cid in recorded_ids if canonical_container_id(cid)}
    stop: list[str] = []
    mismatch = [f"recorded-id-rejected:{cid}" for cid in recorded_ids if cid not in recorded]
    seen: set[str] = set()
    for item in listed:
        if canonical_container_id(item.container_id) is None:
            mismatch.append(f"malformed-id:{item.name}")
            continue
        seen.add(item.container_id)
        labeled = item.label == run_id
        known = item.container_id in recorded
        if labeled and known:
            stop.append(item.container_id)
        elif labeled or known:
            mismatch.append(f"not-owned:{item.container_id}")
    absent = tuple(cid for cid in recorded if cid not in seen)
    return OwnedSelection(tuple(stop), tuple(mismatch), absent)


def guard_signal_argv(
    recorded_pid: int,
    recorded_start: int,
    observed_pid: int | None,
    observed_start: int | None,
) -> tuple[str, ...] | None:
    if observed_pid is None or observed_start is None:
        return None
    if recorded_pid <= 1 or recorded_start <= 0:
        return None
    if observed_pid != recorded_pid or observed_start != recorded_start:
        return None
    return ("kill", "-TERM", str(recorded_pid))


def drive(samples: tuple[Sample, ...], config: GuardConfig) -> str:
    """Return the next machine action. No sleep and no executor."""
    pressure_state = PressureState()
    for sample in samples:
        if assess(sample, config, pressure_state).rollback:
            return "rollback"
    return "continue"


def guest_exec_stdout(payload: str) -> Completed | None:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("exited") != 1:
        return None
    code = data.get("exitcode")
    out = data.get("out-data", "")
    if type(code) is not int or not isinstance(out, str) or _looks_secret(out):
        return None
    return Completed(code, out)


def redact_qm_config(text: str) -> str:
    kept = []
    for line in text.splitlines():
        key = line.split(":", 1)[0].strip().lower()
        if key in {"memory", "cores", "onboot", "agent"}:
            kept.append(line.strip())
    return "\n".join(kept)


def parse_qm_status(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("status:"):
            value = line.split(":", 1)[1].strip()
            if value in {"running", "stopped"}:
                return value
            return None
    return None


def parse_allowlisted_config(text: str) -> Vm130Config | None:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        values[key.strip().lower()] = raw.strip()
    try:
        memory = int(values["memory"])
        cores = int(values["cores"])
        onboot = int(values["onboot"])
    except (KeyError, ValueError):
        return None
    return Vm130Config(None, memory, cores, onboot)


def rollback(executor, config: GuardConfig, records: ProofRecords, *, skip_guest_cleanup=False) -> RollbackReport:
    require_run_id(config.run_id)
    if records.run_id != config.run_id:
        raise GuardRefusal("records belong to another proof run")
    commands: list[tuple[str, ...]] = []
    reasons: list[str] = []

    def emit(argv: tuple[str, ...]) -> Completed:
        rollback_command_allowed(argv, config.run_id)
        commands.append(argv)
        return executor.run(argv)

    status_result = emit(("qm", "status", PROOF_VMID))
    status = parse_qm_status(status_result.stdout) if status_result.code == 0 else None
    if status is None:
        reasons.append("vm130-status-unknown")
        prod_ok = _confirm_production(emit, config, reasons)
        return _report(False, True, reasons, commands, prod_ok)
    if status == "running":
        if not skip_guest_cleanup:
            _cleanup_guest(emit, records, reasons)
        emit(("qm", "shutdown", PROOF_VMID, "--timeout", SHUTDOWN_TIMEOUT))
        status = _status_after_shutdown(emit)
        if status != "stopped":
            reasons.append("graceful-shutdown-failed")
            prod_ok = _confirm_production(emit, config, reasons)
            return _report(False, True, reasons, commands, prod_ok)
    restored_memory = _restore_memory(emit, reasons)
    prod_ok = _confirm_production(emit, config, reasons)
    ask = (not restored_memory) or (not prod_ok) or any(
        item.startswith((
            "not-owned:", "malformed-id:", "graceful-", "vm130-", "memory-",
            "owned-list-", "docker-", "image-",
        ))
        for item in reasons
    )
    return _report(restored_memory and prod_ok and not ask, ask, reasons, commands, prod_ok)


def _report(restored: bool, ask: bool, reasons: list[str], commands, prod_ok: bool) -> RollbackReport:
    if not prod_ok:
        ask = True
        restored = False
    return RollbackReport(restored, ask, tuple(reasons), tuple(commands))


def _cleanup_guest(emit, records: ProofRecords, reasons: list[str]) -> None:
    listed = emit(_guest(PROOF_VMID, GUEST_TIMEOUT, (
        "docker", "ps", "-a", "--no-trunc", "--format", PROOF_PS_FORMAT,
    )))
    if listed.code != 0:
        reasons.append("owned-list-unknown")
        return
    selection = select_owned(records.run_id, records.container_ids, _parse_ps(listed.stdout))
    reasons.extend(selection.mismatch)
    for cid in selection.stop:
        stopped = emit(_guest(PROOF_VMID, GUEST_TIMEOUT, ("docker", "stop", "--time", "10", cid)))
        if stopped.code != 0:
            reasons.append(f"docker-stop-failed:{cid}")
            continue
        removed = emit(_guest(PROOF_VMID, GUEST_TIMEOUT, ("docker", "rm", cid)))
        if removed.code != 0:
            reasons.append(f"docker-rm-failed:{cid}")
    for image_id in records.image_ids:
        _remove_image(emit, records.run_id, image_id, reasons)


def _remove_image(emit, run_id: str, image_id: str, reasons: list[str]) -> None:
    if canonical_image_id(image_id) is None:
        reasons.append(f"image-id-rejected:{image_id}")
        return
    users = emit(_guest(PROOF_VMID, PRODUCTION_TIMEOUT, (
        "docker", "ps", "-a", "--no-trunc", "--filter", f"ancestor={image_id}",
        "--format", "{{.ID}}",
    )))
    if users.code != 0:
        reasons.append(f"image-users-unknown:{image_id}")
        return
    if users.stdout.strip():
        reasons.append(f"image-in-use:{image_id}")
        return
    inspected = emit(_guest(PROOF_VMID, PRODUCTION_TIMEOUT, (
        "docker", "image", "inspect", "--format", IMAGE_INSPECT_FORMAT, image_id,
    )))
    if inspected.code != 0 or not image_owned(inspected.stdout, run_id, image_id):
        reasons.append(f"image-not-owned:{image_id}")
        return
    removed = emit(_guest(PROOF_VMID, GUEST_TIMEOUT, ("docker", "image", "rm", image_id)))
    if removed.code != 0:
        reasons.append(f"image-rm-failed:{image_id}")


def _status_after_shutdown(emit) -> str | None:
    """One status read. qm shutdown --timeout 90 already waited. No second shutdown."""
    result = emit(("qm", "status", PROOF_VMID))
    if result.code != 0:
        return None
    return parse_qm_status(result.stdout)


def _restore_memory(emit, reasons: list[str]) -> bool:
    current = emit(("qm", "config", PROOF_VMID))
    parsed = parse_allowlisted_config(current.stdout) if current.code == 0 else None
    if parsed is None:
        reasons.append("vm130-config-unknown")
        return False
    if parsed.cores != REQUIRED_CORES or parsed.onboot != REQUIRED_ONBOOT:
        reasons.append("vm130-shape-drift")
        return False
    if parsed.memory_mib == RESTORE_MEMORY_MIB:
        return True
    if parsed.memory_mib != TEST_MEMORY_MIB:
        reasons.append("vm130-memory-drift")
        return False
    stopped = emit(("qm", "status", PROOF_VMID))
    if stopped.code != 0 or parse_qm_status(stopped.stdout) != "stopped":
        reasons.append("vm130-not-stopped-before-restore")
        return False
    emit(("qm", "set", PROOF_VMID, "--memory", str(RESTORE_MEMORY_MIB)))
    checked = emit(("qm", "config", PROOF_VMID))
    again = parse_allowlisted_config(checked.stdout) if checked.code == 0 else None
    if again is None or again.memory_mib != RESTORE_MEMORY_MIB:
        reasons.append("memory-restore-unconfirmed")
        return False
    if again.cores != REQUIRED_CORES or again.onboot != REQUIRED_ONBOOT:
        reasons.append("vm130-shape-drift")
        return False
    return True


def _confirm_production(emit, config: GuardConfig, reasons: list[str]) -> bool:
    ok = True
    status = emit(("qm", "status", PRODUCTION_VMID))
    if status.code != 0 or parse_qm_status(status.stdout) != "running":
        reasons.append("vm100-not-running-after-cleanup")
        ok = False
    nod = emit(NOD_CURL)
    if nod.code != 0 or not nod_health_ok(nod.stdout):
        reasons.append("nod-unhealthy-after-cleanup")
        ok = False
    listed = emit(_guest(PRODUCTION_VMID, PRODUCTION_TIMEOUT, (
        "docker", "ps", "--format", PRODUCTION_PS_FORMAT,
    )))
    if listed.code != 0:
        reasons.append("production-unknown-after-cleanup")
        return False
    found = dict(_parse_production_ps(listed.stdout))
    for item in config.baseline:
        state = found.get(item.name)
        unhealthy = (
            item.expect not in BASELINE_EXPECTATIONS
            or state is None
            or (item.expect == "healthy" and "(healthy)" not in state)
            or (item.expect == "running" and (not state.startswith("Up") or "unhealthy" in state))
        )
        if unhealthy:
            reasons.append(f"production-unhealthy-after-cleanup:{item.name}")
            ok = False
    return ok


def _parse_ps(text: str) -> tuple[ListedContainer, ...]:
    listed = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        listed.append(ListedContainer(parts[0], parts[1], parts[2]))
    return tuple(listed)


def _parse_production_ps(text: str) -> tuple[tuple[str, str], ...]:
    rows = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        name, status = line.split("\t", 1)
        rows.append((name, status))
    return tuple(rows)


def image_owned(text: str, run_id: str, image_id: str) -> bool:
    """Owned only when id, label, and every tag are this run's. Shared tags stay."""
    parts = text.strip().split("\t")
    if len(parts) != 3 or parts[0] != image_id or canonical_image_id(image_id) is None:
        return False
    try:
        tags = json.loads(parts[1])
        labels = json.loads(parts[2])
    except json.JSONDecodeError:
        return False
    if not isinstance(tags, list) or not tags or not isinstance(labels, dict):
        return False
    if labels.get(LABEL_KEY) != run_id:
        return False
    allowed = run_tags(run_id)
    return set(tags) <= allowed


def _looks_secret(text: str) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in SECRET_MARKERS)


def _guest(vmid: str, timeout: str, inner: tuple[str, ...]) -> tuple[str, ...]:
    return ("qm", "guest", "exec", vmid, "--timeout", timeout, "--", *inner)


def rollback_command_allowed(argv: tuple[str, ...], run_id: str) -> None:
    require_run_id(run_id)
    if argv == ("qm", "status", PROOF_VMID) or argv == ("qm", "status", PRODUCTION_VMID):
        return
    if argv == ("qm", "config", PROOF_VMID):
        return
    if argv == ("qm", "shutdown", PROOF_VMID, "--timeout", SHUTDOWN_TIMEOUT):
        return
    if argv == ("qm", "set", PROOF_VMID, "--memory", str(RESTORE_MEMORY_MIB)):
        return
    if argv == NOD_CURL:
        return
    if argv[:6] == ("qm", "guest", "exec", PROOF_VMID, "--timeout", GUEST_TIMEOUT) and argv[6:7] == ("--",):
        _allow_proof_mutation(argv[7:], run_id)
        return
    if argv[:6] == ("qm", "guest", "exec", PROOF_VMID, "--timeout", PRODUCTION_TIMEOUT) and argv[6:7] == ("--",):
        _allow_proof_read(argv[7:])
        return
    if argv[:6] == ("qm", "guest", "exec", PRODUCTION_VMID, "--timeout", PRODUCTION_TIMEOUT) and argv[6:7] == ("--",):
        if argv[7:] == ("docker", "ps", "--format", PRODUCTION_PS_FORMAT):
            return
    raise GuardRefusal("rollback command is outside the owned-guest allowlist")


def _allow_proof_mutation(inner: tuple[str, ...], run_id: str) -> None:
    del run_id
    if inner == ("docker", "ps", "-a", "--no-trunc", "--format", PROOF_PS_FORMAT):
        return
    if len(inner) == 5 and inner[:4] == ("docker", "stop", "--time", "10") and canonical_container_id(inner[4]):
        return
    if len(inner) == 3 and inner[:2] == ("docker", "rm") and canonical_container_id(inner[2]):
        return
    if len(inner) == 4 and inner[:3] == ("docker", "image", "rm") and canonical_image_id(inner[3]):
        return
    raise GuardRefusal("proof guest mutation is outside the owned-container allowlist")


def _allow_proof_read(inner: tuple[str, ...]) -> None:
    if (
        len(inner) == 8
        and inner[:5] == ("docker", "ps", "-a", "--no-trunc", "--filter")
        and inner[5].startswith("ancestor=")
        and canonical_image_id(inner[5][len("ancestor="):])
        and inner[6:] == ("--format", "{{.ID}}")
    ):
        return
    if (
        len(inner) == 6
        and inner[:5] == ("docker", "image", "inspect", "--format", IMAGE_INSPECT_FORMAT)
        and canonical_image_id(inner[5])
    ):
        return
    raise GuardRefusal("proof guest read is outside the metadata allowlist")


def start_command_allowed(argv: tuple[str, ...]) -> None:
    if argv in {
        ("qm", "set", PROOF_VMID, "--memory", str(TEST_MEMORY_MIB)),
        ("qm", "start", PROOF_VMID),
    }:
        return
    raise GuardRefusal("start command is outside the stopped-VM-130 allowlist")


def onebox_build_argv(run_id: str) -> tuple[str, ...]:
    require_run_id(run_id)
    return (
        "docker", "build", "--label", f"{LABEL_KEY}={run_id}",
        "-f", "deploy/docker/Dockerfile",
        "-t", f"toolstack-vmproof:{run_id}",
        ".",
    )


def echo_build_argv(run_id: str, dockerfile: str) -> tuple[str, ...]:
    require_run_id(run_id)
    if dockerfile not in {"tools/echo_mcp/Dockerfile", "tools/echo_api/Dockerfile"}:
        raise GuardRefusal("echo build is not one of the two bundled Dockerfiles")
    name = "echo-mcp" if dockerfile.endswith("echo_mcp/Dockerfile") else "echo-api"
    return (
        "docker", "build", "--label", f"{LABEL_KEY}={run_id}",
        "-f", dockerfile, "-t", f"toolstack-vmproof-{name}:{run_id}", ".",
    )


def content_check_argv(run_id: str, image: str) -> tuple[str, ...]:
    """Create, do not run. The id is recorded before start; no --rm race."""
    require_run_id(run_id)
    _image_ref(image, run_id)
    return (
        "docker", "create", "--network", "none",
        "--label", f"{LABEL_KEY}={run_id}",
        "--entrypoint", "python3", image, "-c",
        "import sps, toolstack_forwarder, admin, shutil; print(shutil.which('admin'))",
    )


def set_password_argv(run_id: str, image: str, data_dir: str, proof_root: str) -> tuple[str, ...]:
    require_run_id(run_id)
    _image_ref(image, run_id)
    _contained(data_dir, proof_root)
    return (
        "docker", "create", "-i", "--network", "none",
        "--label", f"{LABEL_KEY}={run_id}",
        "--mount", f"type=bind,src={data_dir},dst=/data",
        "--entrypoint", "admin", image, "set-password",
    )


def admin_serve_argv(run_id: str, image: str, data_dir: str, proof_root: str, port: int) -> tuple[str, ...]:
    require_run_id(run_id)
    _image_ref(image, run_id)
    _contained(data_dir, proof_root)
    if not 1024 <= port <= 65535:
        raise GuardRefusal("admin publish port is not dynamic")
    return (
        "docker", "create", "--restart", "no", "--network", "bridge",
        "--name", f"toolstack-vmproof-{run_id}",
        "--label", f"{LABEL_KEY}={run_id}",
        "--publish", f"127.0.0.1:{port}:8780",
        "--mount", f"type=bind,src={data_dir},dst=/data",
        image,
    )


def start_recorded_argv(container_id: str) -> tuple[str, ...]:
    if canonical_container_id(container_id) is None:
        raise GuardRefusal("refusing to start an id that is not 64 hex characters")
    return ("docker", "start", container_id)


def start_attached_argv(container_id: str) -> tuple[str, ...]:
    if canonical_container_id(container_id) is None:
        raise GuardRefusal("refusing to attach an id that is not 64 hex characters")
    return ("docker", "start", "-a", "-i", container_id)


def loopback_probe_argv(port: int, path: str) -> tuple[str, ...]:
    if path != "/login" or not 1024 <= port <= 65535:
        raise GuardRefusal("probe is not the admin login page on a dynamic loopback port")
    return _guest(PROOF_VMID, PRODUCTION_TIMEOUT, (
        "curl", "--noproxy", "*", "-fsS", "--connect-timeout", "2", "--max-time", "5",
        f"http://127.0.0.1:{port}{path}",
    ))


def agent_ready_argv() -> tuple[str, ...]:
    return _guest(PROOF_VMID, GUEST_TIMEOUT, ("/bin/true",))


def production_ps_argv() -> tuple[str, ...]:
    return _guest(PRODUCTION_VMID, PRODUCTION_TIMEOUT, (
        "docker", "ps", "--format", PRODUCTION_PS_FORMAT,
    ))


def unit_list_argv() -> tuple[str, ...]:
    return _guest(PROOF_VMID, "20", (
        "systemctl", "list-units", "--type=service", "--state=running",
        "--no-pager", "--plain", "--no-legend",
    ))


def listen_argv() -> tuple[str, ...]:
    return _guest(PROOF_VMID, PRODUCTION_TIMEOUT, ("ss", "-H", "-lnt"))


def process_meta_argv() -> tuple[str, ...]:
    return _guest(PROOF_VMID, PRODUCTION_TIMEOUT, ("ps", "-eo", "pid,ppid,user,stat,comm"))


def _image_ref(image: str, run_id: str) -> None:
    if not image.startswith("toolstack-vmproof") or run_id not in image or ":" not in image:
        raise GuardRefusal("image ref is not this run's recorded tag")


def _contained(path: str, root: str) -> None:
    if not path.startswith("/") or not root.startswith("/") or ".." in path.split("/"):
        raise GuardRefusal("proof path is not an absolute child of the proof root")
    root_parts = [part for part in root.split("/") if part]
    path_parts = [part for part in path.split("/") if part]
    if path_parts[:len(root_parts)] != root_parts or len(path_parts) <= len(root_parts):
        raise GuardRefusal("proof path escapes the proof root")


def completed_from_guest(payload: str) -> Completed:
    parsed = guest_exec_stdout(payload)
    if parsed is None:
        return Completed(1, "")
    return parsed


def main(argv: list[str] | None = None) -> int:
    del argv
    print("guard library; host execution refused", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
