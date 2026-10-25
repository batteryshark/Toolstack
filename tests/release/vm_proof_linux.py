"""Linux/PVE binding for the finite QGA source/Docker proof.

Default/help is inert. `controller --live` creates an ephemeral detached guard;
the foreground controller owns admission/lease. No services are installed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import dataclasses
import fcntl
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

import vm_proof_guard as g
from vm_proof_adapter import (
    StopLatch, _fresh, parse_starttime, prepare_run_root, run_guard, timeout_for,
)
from vm_proof_inventory import inventory_commands

BINARIES = {"qm": "/usr/sbin/qm", "free": "/usr/bin/free", "curl": "/usr/bin/curl"}
LIMIT = 65536
MAX_RECORDS = 16
FILE_IDENTITY = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def identity(pid: int) -> int | None:
    if pid <= 1:
        return None
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        if text[text.rfind(")") + 2:].split()[0] == "Z":
            return None
        return parse_starttime(text)
    except (OSError, IndexError):
        return None


def open_directory(path: str) -> int:
    """Walk every ancestor without following symlinks, retaining an fd."""
    if not path.startswith("/") or any(p in (".", "..") for p in path.split("/")):
        raise g.GuardRefusal("absolute canonical directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in filter(None, path.split("/")):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class PrivateFiles:
    def __init__(self, root: str):
        self.fd = open_directory(root)
        info = os.fstat(self.fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            self.close()
            raise g.GuardRefusal("run directory must be owned and 0700")

    def close(self):
        os.close(self.fd)

    def file(self, name, flags):
        if name not in {"config", "state", "ready", "pid", "lease", "admit", "controller", "log", "result", "inventory", "owner-inventory", "proof-evidence"}:
            raise g.GuardRefusal("unknown private file")
        fd = os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            os.close(fd)
            raise g.GuardRefusal("unsafe private file")
        return fd

    def create(self, name, data):
        if name in {"ready", "admit"}:
            return self._publish_new(name, data)
        fd = self.file(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            self._write(fd, data)
        finally:
            os.close(fd)

    def read(self, name):
        if name in {"lease", "ready", "admit"}:
            with self._publication_lock(exclusive=False):
                return self._read(name, snapshot=True)
        return self._read(name)

    def _read(self, name, snapshot=False):
        fd = self.file(name, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            before = os.fstat(fd)
            data = os.read(fd, LIMIT + 1)
            if len(data) > LIMIT:
                raise g.GuardRefusal("private record too large")
            if snapshot:
                self._same_file(name, before)
                if any(getattr(before, key) != getattr(os.fstat(fd), key) for key in FILE_IDENTITY):
                    raise g.GuardRefusal("private snapshot changed")
            return data.decode()
        finally:
            os.close(fd)

    def _same_file(self, name, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise g.GuardRefusal("unsafe private snapshot")
        current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        if any(getattr(current, key) != getattr(info, key) for key in FILE_IDENTITY):
            raise g.GuardRefusal("private path changed")

    @contextmanager
    def _publication_lock(self, *, exclusive):
        # Separate open description per operation: threads/instances cannot
        # accidentally upgrade or unlock another reader's flock. No new file.
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            info, root = os.fstat(fd), os.fstat(self.fd)
            if ((info.st_dev, info.st_ino) != (root.st_dev, root.st_ino)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise g.GuardRefusal("unsafe publication directory")
            # Only lock acquisition retries, never an effect or invalid record.
            # A stuck publisher fails closed within 20 attempts/~0.1s.
            for attempt in range(20):
                try:
                    fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if attempt == 19:
                        raise
                    time.sleep(0.005)
            yield
        finally:
            os.close(fd)

    def _remove_staging(self, name, identity):
        if identity is None:
            return
        try:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if ((info.st_dev, info.st_ino) == identity and stat.S_ISREG(info.st_mode)
                    and info.st_uid == os.getuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600):
                os.unlink(name, dir_fd=self.fd)
        except FileNotFoundError:
            pass

    def _publish_new(self, target, data):
        # Only ready/admit are read concurrently with first publication. The
        # controller and initial lease are complete before guard spawn; pid is
        # written before ready and is not polled by the controller.
        name = "." + target + "-next"
        fd, identity = None, None
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.fd)
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise g.GuardRefusal("unsafe publication staging file")
            self._write(fd, data)
            with self._publication_lock(exclusive=True):
                self._same_file(name, os.fstat(fd))
                # link is an atomic absent-only claim, including against a
                # noncooperating creator. Readers cannot observe nlink=2.
                os.link(name, target, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
                linked = os.fstat(fd)
                if (linked.st_nlink != 2 or not stat.S_ISREG(linked.st_mode)
                        or linked.st_uid != os.getuid() or stat.S_IMODE(linked.st_mode) != 0o600):
                    raise g.GuardRefusal("unsafe publication claim")
                for path in (name, target):
                    current = os.stat(path, dir_fd=self.fd, follow_symlinks=False)
                    if any(getattr(current, key) != getattr(linked, key) for key in FILE_IDENTITY):
                        raise g.GuardRefusal("publication claim changed")
                os.unlink(name, dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            if fd is not None:
                os.close(fd)
            self._remove_staging(name, identity)

    @staticmethod
    def _write(fd, data):
        payload = data.encode()
        if len(payload) > LIMIT:
            raise g.GuardRefusal("private record too large")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        while payload:
            payload = payload[os.write(fd, payload):]
        os.fsync(fd)
        fcntl.flock(fd, fcntl.LOCK_UN)

    def publish_lease(self, record):
        """Controller-only replacement, serialized with complete snapshot reads."""
        owner = json.loads(self.read("controller"))
        if (type(owner.get("pid")) is not int or owner["pid"] <= 1
                or type(owner.get("start")) is not int or owner["start"] <= 0):
            raise g.GuardRefusal("invalid controller record")
        old_fd = self.file("lease", os.O_RDONLY)
        temp_fd = None
        temp_identity = None
        name = ".lease-next"
        try:
            old_info = os.fstat(old_fd)
            old = json.loads(os.read(old_fd, LIMIT + 1))
            for value in (old, record):
                if (set(value) != {"pid", "start", "run", "monotonic"}
                        or value["pid"] != owner["pid"] or value["start"] != owner["start"]
                        or value["run"] != record["run"]
                        or not g._finite_nonnegative(value["monotonic"])):
                    raise g.GuardRefusal("invalid lease publication")
            g.require_run_id(record["run"])
            if record["monotonic"] < old["monotonic"]:
                raise g.GuardRefusal("lease clock moved backwards")
            temp_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=self.fd)
            info = os.fstat(temp_fd)
            temp_identity = (info.st_dev, info.st_ino)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise g.GuardRefusal("unsafe lease temporary file")
            self._write(temp_fd, json.dumps(record))
            with self._publication_lock(exclusive=True):
                self._same_file("lease", old_info)
                self._same_file(name, os.fstat(temp_fd))
                os.replace(name, "lease", src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            os.close(old_fd)
            if temp_fd is not None:
                os.close(temp_fd)
            self._remove_staging(name, temp_identity)


class LinuxSubprocessIO:
    """One serialized command stream; each wait also checks memory/lease/time.

    Guest effects come only from the fixed GuestProof sequence, with a single
    recorded QGA async job at a time. No arbitrary shell/callback is accepted.
    Popen/identity/clock are injected by local tests, never by CLI configuration.
    """
    def __init__(self, root, config, latch, checkout, *, popen=subprocess.Popen,
                 observe=identity, clock=time.monotonic, source=None):
        self.root, self.config, self.latch, self.checkout = root, config, latch, checkout
        self.files = PrivateFiles(root)
        self.popen, self.observe, self.clock = popen, observe, clock
        self.deadline = clock() + 2400
        self.cleanup = False
        self.cleanup_deadline = None
        self.owned_resize = self.owned_start = False
        self.shutdown_sent = False
        self.active = {}
        self.unresolved_child = False
        self.full_samples = 0
        self.fast_probe = None
        self.pressure_state = g.PressureState()
        self.lease_observation = {"controller_identity_valid": None, "reason": "not-sampled"}
        self.proof = None
        if source is not None:
            from vm_proof_driver import GuestProof
            self.proof = GuestProof(self, source)
        self.files.create("state", "{}")
        self.state_fd = self.files.file("state", os.O_WRONLY)
        self.files.create("log", "bounded-qga-proof\n")
        self.files.create("config", json.dumps(dataclasses.asdict(config)))

    def close(self):
        os.close(self.state_fd)
        self.files.close()

    def identity(self):
        pid = os.getpid()
        start = self.observe(pid)
        if start is None:
            raise g.GuardRefusal("guard identity unknown")
        return pid, start

    def children(self):
        return tuple(self.active)

    def records(self):
        return g.ProofRecords(self.config.run_id, tuple(self.proof.containers) if self.proof else (),
                              tuple(self.proof.images) if self.proof else ())

    def write_new(self, name, text):
        self.files.create(name, text)

    def checkpoint(self):
        self.files._write(self.state_fd, json.dumps({
            "owned_resize": self.owned_resize, "owned_start": self.owned_start,
            "shutdown_sent": self.shutdown_sent, "children": list(self.active),
            "containers": [], "images": [], "stop": self.latch.reason,
            "baseline_vm130": dataclasses.asdict(self.baseline_snapshot) if hasattr(self, "baseline_snapshot") else None,
            "proof": self.proof.state() if self.proof else None,
            "full_samples": self.full_samples,
            "fast_probe": self.fast_probe,
            "pressure": self.pressure_state.snapshot(),
        }))

    def note_sample(self):
        self.full_samples += 1
        if self.full_samples > 480:
            self.latch.trip("sample-budget")
            raise g.GuardRefusal("full sample budget exhausted")

    def read(self, path):
        if path not in {"/proc/meminfo", "/proc/pressure/memory"}:
            raise g.GuardRefusal("not a permitted proc probe")
        try:
            with open(path) as source:
                return source.read(LIMIT)
        except OSError:
            return None

    def lease_age(self):
        self.lease_observation = {"controller_identity_valid": None, "reason": "controller-unknown"}
        try:
            owner = json.loads(self.files.read("controller"))
            if (type(owner["pid"]) is not int or type(owner["start"]) is not int
                    or self.observe(owner["pid"]) != owner["start"]):
                self.lease_observation = {"controller_identity_valid": False, "reason": "controller-dead-or-reused"}
                return None
            self.lease_observation = {"controller_identity_valid": True, "reason": "lease-unknown"}
            lease = json.loads(self.files.read("lease"))
            if lease["run"] != self.config.run_id or lease["pid"] != owner["pid"] or lease["start"] != owner["start"]:
                return None
            age = self.clock() - lease["monotonic"]
            self.lease_observation["reason"] = "valid" if g._finite_nonnegative(age) else "lease-clock-invalid"
            return age if g._finite_nonnegative(age) else None
        except BlockingIOError:
            self.lease_observation["reason"] = "publication-locked"
            return None
        except (OSError, ValueError, KeyError, TypeError, g.GuardRefusal):
            return None

    def admit_text(self):
        try:
            return self.files.read("admit").strip()
        except OSError:
            return None

    def check(self):
        if self.cleanup:
            if self.clock() >= self.cleanup_deadline:
                raise g.GuardRefusal("cleanup budget exhausted")
            return
        self.latch.before_effect()
        mem = g.parse_memavailable_kib(self.read("/proc/meminfo") or "")
        psi = g.parse_pressure(self.read("/proc/pressure/memory") or "")
        age = self.lease_age()
        reasons = []
        if mem is None or mem < 1536 * 1024:
            reasons.append("memory-unknown" if mem is None else "memory-low")
        pressure_trip = self.pressure_state.observe(self.clock(), psi)
        reasons.extend(pressure_trip.reasons)
        if age is None or age > 90:
            reasons.append(self.lease_observation["reason"] if age is None else "lease-stale")
        if self.clock() >= self.deadline:
            reasons.append("deadline")
        if reasons:
            self.fast_probe = {"memory_kib": mem, "psi_full_avg10": psi.full_avg10 if psi else None,
                               "psi_full_avg60": psi.full_avg60 if psi else None,
                               "lease_age": age, **self.lease_observation, "reasons": reasons}
            self.latch.trip("fast-probe-or-lease-trip")
            self.checkpoint()
            raise g.GuardRefusal("fast-probe-or-lease-trip")
        self.checkpoint()

    def begin_cleanup(self):
        self.latch.trip("cleanup")
        self.cleanup = True
        if self.cleanup_deadline is None:
            self.cleanup_deadline = self.clock() + 300

    def allowed(self, argv, input_data=None):
        if self.proof is not None and self.proof.permit(argv, input_data):
            return
        if input_data is not None:
            raise g.GuardRefusal("stdin is only admitted by the fixed proof receiver")
        if argv in {("free", "-m"), g.NOD_CURL, ("qm", "status", "100"),
                    ("qm", "status", "130"), ("qm", "config", "130"), g.production_ps_argv()}:
            return
        if argv == ("qm", "set", "130", "--memory", "4096"):
            if self.owned_resize and not self.cleanup and self.admit_text() == self.config.run_id:
                return
        if argv == ("qm", "start", "130"):
            if (self.owned_start and self.pressure_state.boot_monotonic is None
                    and not self.cleanup and self.admit_text() == self.config.run_id):
                return
        if argv == ("qm", "set", "130", "--memory", "8192"):
            if self.cleanup and self.owned_resize:
                return
        if argv == ("qm", "shutdown", "130", "--timeout", "90"):
            if self.cleanup and self.owned_start and not self.shutdown_sent:
                return
        if self.owned_start and argv in {g.agent_ready_argv(), g.unit_list_argv(), g.listen_argv(), g.process_meta_argv()}:
            return
        if self.owned_start and argv == g._guest("130", "30", (
                "docker", "ps", "-a", "--no-trunc", "--format", g.PROOF_PS_FORMAT)):
            return
        if self.owned_start and self.checkout != "discover" and argv in {g._guest("130", "15", c) for c in inventory_commands(self.checkout)}:
            return
        raise g.GuardRefusal("command not in boot-metadata allowlist")

    def cancel(self, child, start):
        # Popen child + exact Linux starttime; never a guessed PID or group kill.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if child.poll() is not None or self.observe(child.pid) != start:
                return
            child.send_signal(sig)
            try:
                child.wait(timeout=2)
                return
            except subprocess.TimeoutExpired:
                pass
        self.unresolved_child = child.poll() is None

    def cancel_all(self):
        for (pid, start), child in tuple(self.active.items()):
            self.cancel(child, start)
            if child.poll() is not None:
                self.active.pop((pid, start), None)

    def run(self, argv, timeout, input_data=None):
        argv = tuple(argv)
        self.allowed(argv, input_data)
        if timeout != timeout_for(argv):
            raise g.GuardRefusal("timeout differs from command bound")
        self.check()
        expected = {
            ("qm", "set", "130", "--memory", "4096"): ("stopped", 8192),
            ("qm", "start", "130"): ("stopped", 4096),
            ("qm", "set", "130", "--memory", "8192"): ("stopped", 4096),
            ("qm", "shutdown", "130", "--timeout", "90"): ("running", 4096),
        }.get(argv)
        if expected:
            status = self.run(("qm", "status", "130"), 15)
            config = self.run(("qm", "config", "130"), 15)
            shape = g.parse_allowlisted_config(config.stdout) if config.code == 0 else None
            if (status.code or g.parse_qm_status(status.stdout) != expected[0]
                    or shape is None or (shape.memory_mib, shape.cores, shape.onboot) != (expected[1], 2, 0)):
                # Intent is not ownership when the final preflight refuses to
                # issue the command. Do not undo somebody else's transition.
                if argv == ("qm", "set", "130", "--memory", "4096"):
                    self.owned_resize = False
                if argv == ("qm", "start", "130"):
                    self.owned_start = False
                self.checkpoint()
                raise g.GuardRefusal("effect refused: VM ownership/shape drift")
            self.check()
        if argv == ("qm", "start", "130"):
            # Final stopped/shape/health preflight has passed. Journal intent
            # before spawn so checks DURING qm start share this finite grace.
            # Failure/lost reply never resets it and never permits another boot.
            self.pressure_state.begin_boot(self.clock())
            self.checkpoint()
        if argv[:2] == ("qm", "shutdown"):
            self.shutdown_sent = True
            self.checkpoint()
        transfer = None
        try:
            if input_data is not None:
                if not isinstance(input_data, bytes) or len(input_data) > 1024 * 1024:
                    raise g.GuardRefusal("QGA stdin exceeds bound")
                transfer = tempfile.TemporaryFile(dir=self.root)
                transfer.write(input_data)
                transfer.seek(0)
            child = self.popen((BINARIES[argv[0]], *argv[1:]), stdin=transfer if transfer else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                               env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": self.root})
        finally:
            if transfer:
                transfer.close()
        start = self.observe(child.pid)
        if start is None and child.poll() is not None:
            # A very short command may already be reaped. No cancellation is
            # needed and no PID is signalled; still drain/validate bounded output.
            start = 0
        if start is None:
            # Never signal without identity. Command outcome is unknown; shutdown
            # remains the only owned guest fence, with the limitation reported.
            self.unresolved_child = True
            child.stdout.close()
            child.stderr.close()
            raise g.GuardRefusal("spawned-child-identity-unknown")
        self.active[(child.pid, start)] = child
        end = min(self.clock() + timeout, self.cleanup_deadline if self.cleanup else self.deadline)
        if self.cleanup and getattr(self, "proof_cleanup_deadline", None) is not None:
            end = min(end, self.proof_cleanup_deadline)
        streams = selectors.DefaultSelector()
        out, err = bytearray(), bytearray()
        try:
            for stream, target in ((child.stdout, out), (child.stderr, err)):
                os.set_blocking(stream.fileno(), False)
                streams.register(stream, selectors.EVENT_READ, target)
            while streams.get_map() or child.poll() is None:
                self.check()
                if self.clock() >= end:
                    raise TimeoutError("command timeout")
                for key, _event in streams.select(0.2):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data:
                        streams.unregister(key.fileobj)
                    else:
                        key.data.extend(data)
                        if len(out) + len(err) > LIMIT:
                            raise g.GuardRefusal("command output limit")
            code = child.wait(timeout=1)
            if code or err:
                return g.Completed(1, "")
            text = out.decode("utf-8", errors="strict")
            if argv[:3] == ("qm", "guest", "exec-status") or (argv[:3] == ("qm", "guest", "exec") and "--synchronous" in argv):
                value = json.loads(text)
                if not isinstance(value, dict):
                    return g.Completed(1, "")
                return g.Completed(0, text)
            if argv[:3] == ("qm", "guest", "exec"):
                result = g.completed_from_guest(text)
                payload = json.loads(text)
                return g.Completed(1, "") if payload.get("err-data") or payload.get("out-truncated") else result
            if argv == ("qm", "config", "130"):
                text = g.redact_qm_config(text)
            return g.Completed(0, text)
        except (TimeoutError, OSError, ValueError, g.GuardRefusal):
            self.cancel(child, start)
            return g.Completed(1, "")
        finally:
            streams.close()
            child.stdout.close()
            child.stderr.close()
            if child.poll() is not None:
                self.active.pop((child.pid, start), None)

    def metadata_proof(self, latch):
        # Single finite driver, no independent effect commands or thread races.
        inventory = []
        commands = (g.unit_list_argv(), g.listen_argv(), g.process_meta_argv())
        if self.proof is None:
            commands += tuple(g._guest("130", "15", c) for c in inventory_commands(self.checkout))
        for argv in commands:
            latch.before_effect()
            sample, shape = _fresh(self, self.config, 2400 - (self.deadline - self.clock()))
            trip = g.assess(sample, self.config)
            if trip.rollback or (shape.status, shape.memory_mib, shape.cores, shape.onboot) != ("running", 4096, 2, 0):
                latch.trip("metadata-health-or-shape-trip")
                raise g.GuardRefusal("metadata-health-or-shape-trip")
            result = self.run(argv, timeout_for(argv))
            if result.code:
                raise g.GuardRefusal("metadata-inventory-incomplete")
            inventory.append({"argv": argv, "metadata": result.stdout})
        self.files.create("inventory", json.dumps(inventory))
        if self.proof is not None:
            self.proof.execute()


def host_gate():
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/etc/pve").is_dir():
        raise g.GuardRefusal("execute requires root on Linux PVE")
    for path in BINARIES.values():
        if not os.access(path, os.X_OK):
            raise g.GuardRefusal("required PVE command unavailable")


def baseline_config(args):
    entries = []
    for raw in args.baseline:
        name, expectation = raw.rsplit(":", 1)
        if not name or not all(c.isalnum() or c in "_.-" for c in name) or expectation not in g.BASELINE_EXPECTATIONS:
            raise g.GuardRefusal("invalid baseline container")
        entries.append(g.BaselineContainer(name, expectation))
    if not entries or len({e.name for e in entries}) != len(entries) or g.BaselineContainer("nod", "healthy") not in entries:
        raise g.GuardRefusal("unique complete baseline including nod:healthy required")
    return g.GuardConfig(args.run_id, tuple(entries))


def cli(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", nargs="?", choices=("controller", "guard"))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--live", action="store_true")
    p.add_argument("--run-id")
    p.add_argument("--root")
    p.add_argument("--baseline", action="append", default=[])
    p.add_argument("--checkout")
    p.add_argument("--source-commit")
    p.add_argument("--archive-sha256")
    p.add_argument("--archive")
    args = p.parse_args(argv)
    if args.dry_run or not args.execute:
        print("dry-run: controller --execute --live --run-id RUN --root /var/tmp/RUN --checkout discover --source-commit COMMIT40 --archive-sha256 SHA64 --archive /PRIVATE/source.tar --baseline nod:healthy [--baseline NAME:healthy|running]; no host command is executed")
        return 0
    try:
        if not args.live or not args.mode or not args.root or not args.run_id or not args.checkout:
            raise g.GuardRefusal("mode/live/run-id/root/checkout/baseline required")
        g.require_run_id(args.run_id)
        if args.root != "/var/tmp/" + args.run_id:
            raise g.GuardRefusal("root must be the absent /var/tmp/RUN leaf")
        if args.checkout != "discover" and (not args.checkout.startswith("/") or ".." in args.checkout.split("/")):
            raise g.GuardRefusal("known absolute checkout path required")
        config = baseline_config(args)
        from vm_proof_driver import Source
        source = Source.load(args.archive, args.source_commit, args.archive_sha256)
        host_gate()
        if args.mode == "controller":
            return controller(args)
        latch = StopLatch()
        io = LinuxSubprocessIO(args.root, config, latch, args.checkout, source=source)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, lambda signum, frame: latch.trip("signal"))
        try:
            result = run_guard(io, config, latch, time.monotonic, time.sleep)
            if io.unresolved_child or io.active:
                result = dataclasses.replace(result, ask_parent=True, restored=False,
                                             reasons=(*result.reasons, "owned-child-exit-unconfirmed"))
            proof_complete = io.proof is not None and io.proof.completed is True
            if not proof_complete:
                result = dataclasses.replace(result, ask_parent=True,
                                             reasons=(*result.reasons, "proof-incomplete"))
            io.checkpoint()
            io.files.create("result", json.dumps(dict(dataclasses.asdict(result), proof_complete=proof_complete)))
            return 1 if result.ask_parent or not result.restored else 0
        finally:
            io.close()
    except (OSError, ValueError, g.GuardRefusal):
        print("refused or incomplete; inspect private result; no forced cleanup", file=sys.stderr)
        return 2


def controller(args):
    # Foreground lease owner, bounded independently of guard. Not a daemonized
    # heartbeat loop. Death/PID reuse of this process invalidates the lease.
    root = prepare_run_root("/var/tmp", args.run_id)
    files = PrivateFiles(root)
    pid, start = os.getpid(), identity(os.getpid())
    if start is None:
        files.close()
        raise g.GuardRefusal("controller identity unknown")
    owner = {"pid": pid, "start": start}
    files.create("controller", json.dumps(owner))
    files.create("lease", json.dumps(dict(owner, run=args.run_id, monotonic=time.monotonic())))
    cmd = [sys.executable, str(Path(__file__).with_name("vm_proof_adapter.py")), "guard",
           "--execute", "--live", "--run-id", args.run_id, "--root", root, "--checkout", args.checkout,
           "--source-commit", args.source_commit, "--archive-sha256", args.archive_sha256, "--archive", args.archive]
    for entry in args.baseline:
        cmd += ["--baseline", entry]
    child = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": root})
    guard_start = identity(child.pid)
    admitted = False
    deadline = time.monotonic() + 2400
    try:
        while child.poll() is None and time.monotonic() < deadline:
            if guard_start is None or identity(child.pid) != guard_start:
                raise g.GuardRefusal("guard identity changed")
            if not admitted:
                try:
                    expected = f"{args.run_id}\n{child.pid} {guard_start}\n"
                    if files.read("ready") != expected:
                        raise g.GuardRefusal("ready identity mismatch")
                    files.create("admit", args.run_id)
                    admitted = True
                except FileNotFoundError:
                    pass
            files.publish_lease(dict(owner, run=args.run_id, monotonic=time.monotonic()))
            time.sleep(2)
        # Never signal a possibly reused pid. Stopping lease is sufficient; guard
        # has its own 40 minute bound plus at most 300 seconds cleanup.
        return child.poll() if child.poll() is not None else 1
    finally:
        files.close()
