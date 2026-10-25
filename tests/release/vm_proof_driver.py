"""Fixed QGA async source/Docker proof, serialized with the monitor stop latch."""
import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import vm_proof_guard as g
import vm_proof_payload as payload
from vm_proof_adapter import _fresh

# Code is the installed/reviewed helper, not an arbitrary --script input.
GUEST_CODE = Path(payload.__file__).read_text()


@dataclasses.dataclass(frozen=True)
class Source:
    commit: str
    sha256: str
    data: bytes

    @classmethod
    def load(cls, path, commit, digest):
        from vm_proof_linux import open_directory
        if not path or not commit or not digest:
            raise g.GuardRefusal("archive/commit/sha256 required")
        parent, name = os.path.split(path)
        fd = open_directory(parent)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise g.GuardRefusal("archive parent must be private and owned")
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(file_fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > payload.MAX_ARCHIVE):
                    raise g.GuardRefusal("unsafe archive file")
                data = stream.read(payload.MAX_ARCHIVE + 1)
        finally:
            os.close(fd)
        payload.validate_archive(data, commit, digest)
        return cls(commit, digest, data)


class GuestProof:
    def __init__(self, io, source, sleeper=time.sleep):
        self.io, self.source, self.sleep = io, source, sleeper
        self.run = io.config.run_id
        self.expected = None
        self.pending = None
        self.sync_inflight = None
        self.jobs = []
        self.attempted = set()
        self.containers = []
        self.images = []
        self.marker = None
        self.root_attempted = False
        self.transferred = 0
        self.completed = False
        self.evidence = []
        self.leftovers = []
        self.inventory_stage = None
        self.inventory_failure = None

    def state(self):
        return {"pending": self.pending, "sync_inflight": self.sync_inflight, "jobs": self.jobs, "containers": self.containers,
                "images": self.images, "root": str(payload.root_for(self.run)), "root_attempted": self.root_attempted,
                "marker": self.marker, "complete": self.completed, "leftovers": self.leftovers,
                "transferred": self.transferred, "inventory_stage": self.inventory_stage,
                "inventory_failure": self.inventory_failure,
                "artifact_paths": [str(payload.root_for(self.run) / name) for name in
                                   ("owner", "payload-meta", "payload.tar", "src", "home", "tmp", "config", "state", "cache", "data", "runtime", "docker-config", "jobs")],
                "build_cache": "may remain; no prune; base/shared images protected",
                "commit": self.source.commit, "sha256": self.source.sha256}

    def health(self):
        sample, shape = _fresh(self.io, self.io.config, 2400 - (self.io.deadline - self.io.clock()))
        trip = g.assess(sample, self.io.config)
        if trip.rollback or (shape.status, shape.memory_mib, shape.cores, shape.onboot) != ("running", 4096, 2, 0):
            self.io.latch.trip("proof-health-trip")
            raise g.GuardRefusal("proof-health-trip")

    def permit(self, argv, input_data):
        if not self.io.owned_start or self.expected != (tuple(argv), input_data):
            return False
        if not self.io.cleanup:
            return not self.io.latch.closed()
        if input_data is not None or not self.io.latch.closed():
            return False
        if self.marker and tuple(argv) == self.command("remove", (self.marker["dev"], self.marker["ino"])):
            return self.pending is None and self.sync_inflight in (None, "remove")
        if tuple(argv[:4]) != ("qm", "guest", "exec", "130"):
            return False
        try:
            g.rollback_command_allowed(tuple(argv), self.run)
        except g.GuardRefusal:
            return False
        inner = tuple(argv[7:])
        if inner[:2] in (("docker", "stop"), ("docker", "rm")):
            return inner[-1] in self.containers
        if inner[:3] == ("docker", "image", "rm"):
            return inner[-1] in self.images
        return inner[:2] in (("docker", "ps"), ("docker", "image"))

    def command(self, action, args=(), asynchronous=False, stdin=False):
        # Call sites are a fixed sequence; argv data never becomes shell/code.
        if action not in {"inventory", "init", "chunk", "extract", "identity", "build", "create", "start", "remove"}:
            raise g.GuardRefusal("unknown proof action")
        options = ("--synchronous", "0") if asynchronous else ("--timeout", "30")
        if stdin:
            if action != "chunk":
                raise g.GuardRefusal("stdin only for bounded archive chunks")
            options += ("--pass-stdin", "1")
        return ("qm", "guest", "exec", "130", *options, "--", "python3", "-c", GUEST_CODE, self.run, action, *map(str, args))

    def call(self, argv, data=None, cleanup=False):
        with self.io.latch.lock:
            if not cleanup:
                self.io.latch.before_effect()
            if self.expected is not None:
                raise g.GuardRefusal("concurrent guest admission")
            if data is not None and (not isinstance(data, bytes) or len(data) > 1024 * 1024):
                raise g.GuardRefusal("QGA stdin limit")
            self.expected = (tuple(argv), data)
            try:
                result = self.io.run(argv, 45, input_data=data)
            finally:
                self.expected = None
            try:
                obj = json.loads(result.stdout)
            except (ValueError, TypeError):
                obj = None
            if (self.inventory_stage is not None and payload.inventory_error(obj)
                    and obj["step"] == self.inventory_stage["step"]):
                self.inventory_failure = obj
                self.io.checkpoint()
                raise g.GuardRefusal("inventory-failed:" + obj["step"] + ":" + obj["reason"])
            if result.code:
                raise g.GuardRefusal("guest command outcome unknown/failed")
            if not isinstance(obj, dict) or "error" in obj:
                raise g.GuardRefusal("guest response malformed/failed")
            return obj

    def sync(self, action, args=(), data=None, cleanup=False):
        mutation = action in {"init", "chunk", "extract", "remove"}
        if mutation:
            self.sync_inflight = action
            self.io.checkpoint()
        result = self.call(self.command(action, args, stdin=data is not None), data, cleanup)
        if mutation:
            self.sync_inflight = None
            self.io.checkpoint()
        return result

    def job(self, action, kind, extra=()):
        self.io.latch.before_effect()
        key = action + "-" + kind
        if key in self.attempted or self.pending is not None:
            raise g.GuardRefusal("job retry/concurrency refused")
        self.health()
        with self.io.latch.lock:
            self.io.latch.before_effect()
            self.attempted.add(key)
            # Record intent BEFORE QGA: a lost PID reply is an inflight unknown.
            self.pending = {"key": key, "pid": None, "identity": None, "started": self.io.clock()}
            self.io.checkpoint()
            reply = self.call(self.command(action, (kind, *extra), asynchronous=True))
            if set(reply) != {"pid"} or type(reply["pid"]) is not int or reply["pid"] <= 1:
                raise g.GuardRefusal("QGA PID missing/invalid")
            self.pending["pid"] = reply["pid"]
            self.io.checkpoint()
        # Capture wrapper starttime/boot-id BEFORE exec-status polling. A fast
        # completed wrapper leaves its absent-only identity record in the root.
        for _ in range(6):
            self.health()
            identity = self.sync("identity", (key, reply["pid"]))
            if identity == {"pending": True}:
                self.sleep(1)
                continue
            if (identity.get("pid") != reply["pid"] or type(identity.get("start")) is not int
                    or identity["start"] <= 0 or not re.fullmatch(r"[0-9a-f-]{36}", identity.get("boot", ""))):
                raise g.GuardRefusal("guest process identity unknown")
            self.pending["identity"] = identity
            self.io.checkpoint()
            break
        else:
            raise g.GuardRefusal("guest identity deadline")
        deadline = self.pending["started"] + (1200 if action == "build" else 150)
        for _ in range(240):
            self.health()  # Full VM100/Nod/container health, not only host memory.
            if self.io.clock() >= deadline:
                raise g.GuardRefusal("job deadline")
            response = self.call(("qm", "guest", "exec-status", "130", str(reply["pid"])))
            if response.get("exited") in (False, 0) and "exited" in response:
                if set(response) != {"exited"}:
                    raise g.GuardRefusal("unexpected pending QGA status")
                self.sleep(5)
                continue
            if response.get("exited") not in (True, 1) or type(response.get("exitcode")) is not int:
                raise g.GuardRefusal("unknown QGA completion")
            # QGA completion fences the wrapper. Its timeout handler waits for its
            # exact Docker CLI child. Failed/unknown builds still retain tag/cache
            # uncertainty and are never retried.
            finished = dict(self.pending, exitcode=response["exitcode"])
            if response["exitcode"] or response.get("err-data") or response.get("out-truncated"):
                self.leftovers.append("failed-job:" + key)
                self.jobs.append(finished)
                self.pending = None
                self.io.checkpoint()
                raise g.GuardRefusal("guest job failed; no retry")
            result = json.loads(response.get("out-data", ""))
            if not isinstance(result, dict) or "error" in result:
                raise g.GuardRefusal("invalid guest job result")
            # Update durable identity record before releasing pending or starting
            # anything. A malformed result stays inflight-unknown for shutdown.
            if action == "build":
                if (not g.canonical_image_id(result.get("image", "")) or result.get("label") != self.run
                        or result.get("tag") != payload.tag_for(self.run, kind)):
                    raise g.GuardRefusal("image result ownership")
                self.images.append(result["image"])
            if action == "create":
                if not g.canonical_container_id(result.get("container", "")) or result.get("label") != self.run or result.get("kind") != kind:
                    raise g.GuardRefusal("container result ownership")
                self.containers.append(result["container"])
            self.jobs.append(finished)
            self.evidence.append({"step": key, "result": result})
            self.pending = None
            self.io.checkpoint()
            return result
        raise g.GuardRefusal("job polling bound")

    def execute(self):
        self.health()
        # Metadata precedes the first guest path/source mutation. Dirty work is
        # recorded unchanged; there is no in-place-update operation in this driver.
        inventory = {}
        for step in payload.INVENTORY_STEPS:
            self.health()
            self.inventory_stage = {"step": step, "state": "started", "metadata":
                                    {k: v for k, v in inventory.items() if
                                     (k == "path" and payload.inventory_path(v)) or
                                     (k == "owner" and payload.inventory_owner(v))}}
            self.io.checkpoint()  # Durable exact intent even if QGA loses its reply.
            context = {k: v for k, v in inventory.items() if k in
                       {"path", "owner", "group", "service", "uid", "gid", "mode", "dev", "ino"}}
            try:
                inventory.update(self.sync("inventory", (self.io.checkout, step, json.dumps(context))))
            except Exception:
                if self.inventory_failure is None:
                    self.inventory_failure = {"error": "inventory-failed", "step": step,
                                              "reason": "transport-unknown",
                                              "metadata": self.inventory_stage["metadata"]}
                    self.io.checkpoint()
                raise
            self.inventory_stage["state"] = "complete"
            self.io.checkpoint()
        if not re.fullmatch(r"[0-9a-f]{40}", inventory.get("head", "").strip()):
            raise g.GuardRefusal("unknown owner checkout")
        if (not payload.inventory_path(inventory.get("path")) or
                not payload.inventory_owner(inventory.get("owner")) or
                type(inventory.get("uid")) is not int or inventory["uid"] <= 0 or
                inventory.get("root", "").strip() != inventory["path"] or
                not all(isinstance(inventory.get(k), str) for k in ("branch", "status", "submodules"))):
            raise g.GuardRefusal("incomplete owner inventory")
        self.inventory_stage = None
        self.io.files.create("owner-inventory", json.dumps(inventory))
        self.health()
        self.root_attempted = True
        self.io.checkpoint()
        self.marker = self.sync("init", (self.source.commit, self.source.sha256, len(self.source.data)))
        if (self.marker.get("run") != self.run or type(self.marker.get("ino")) is not int
                or type(self.marker.get("dev")) is not int):
            raise g.GuardRefusal("guest root identity unknown")
        self.io.checkpoint()
        for offset in range(0, len(self.source.data), payload.CHUNK):
            self.health()
            block = self.source.data[offset:offset + payload.CHUNK]
            reply = self.sync("chunk", (offset, hashlib.sha256(block).hexdigest()), base64.b64encode(block))
            if reply != {"offset": offset + len(block)}:
                raise g.GuardRefusal("chunk receipt mismatch")
            self.transferred = reply["offset"]
            self.io.checkpoint()
        self.health()
        result = self.sync("extract")
        if result.get("commit") != self.source.commit or result.get("sha256") != self.source.sha256:
            raise g.GuardRefusal("extracted source identity")
        self.evidence.append({"step": "extract-offline-units", "result": result})
        for kind in payload.KINDS:
            self.job("build", kind)
            created = self.job("create", kind)
            self.job("start", kind, (created["container"],))
        process = self.job("create", "process-sps")
        result = self.job("start", "process-sps", (process["container"],))
        if result.get("checked") != "process-sps" or result.get("exit") != 0:
            raise g.GuardRefusal("process-SPS proof missing")
        payload.validate_process_result(result.get("proof"))
        server = self.job("create", "serve")
        result = self.job("start", "serve", (server["container"],))
        if result.get("http") != 200 or result.get("checked") != "serve":
            raise g.GuardRefusal("entrypoint proof missing")
        self.completed = True
        self.io.files.create("proof-evidence", json.dumps(self.evidence))
        self.io.checkpoint()

    def cleanup(self):
        """Called only with latch CLOSED and VM ownership/shape checked.

        If a command/job could still be writing, do NOT race it with deletion.
        The owned VM shutdown is the final fence; report artifacts as leftovers.
        """
        if not self.io.cleanup or not self.io.latch.closed():
            raise g.GuardRefusal("cleanup without closed admission")
        reasons = list(self.leftovers)
        if (self.pending is not None or self.sync_inflight is not None
                or self.root_attempted and self.marker is None or self.leftovers):
            self.leftovers = reasons + ["inflight-unknown: shutdown fence required; guest artifacts retained"]
            self.io.checkpoint()
            return self.leftovers
        end = self.io.clock() + 45
        def emit(argv):
            if self.io.clock() >= end:
                raise g.GuardRefusal("proof cleanup budget")
            # Existing narrow core verifies full ID+label and image ID+tag+label.
            g.rollback_command_allowed(argv, self.run)
            with self.io.latch.lock:
                self.expected = (tuple(argv), None)
                try:
                    from vm_proof_adapter import timeout_for
                    return self.io.run(argv, timeout_for(argv))
                finally:
                    self.expected = None
        try:
            self.io.proof_cleanup_deadline = end
            g._cleanup_guest(emit, g.ProofRecords(self.run, tuple(self.containers), tuple(self.images)), reasons)
            if self.marker is not None and not reasons and self.io.clock() < end:
                removed = self.sync("remove", (self.marker["dev"], self.marker["ino"]), cleanup=True)
                if removed != {"removed": str(payload.root_for(self.run))}:
                    reasons.append("guest-artifacts-removal-unconfirmed")
        except Exception:
            reasons.append("guest-cleanup-incomplete: shutdown fence required")
        finally:
            self.io.proof_cleanup_deadline = None
        if self.images or any(j["key"].startswith("build-") for j in self.jobs) or self.leftovers:
            # No build cache/base-image prune; this residual is always explicit.
            self.evidence.append({"build_cache": "may remain; no prune; shared/base images preserved"})
        self.leftovers = reasons
        self.io.checkpoint()
        return reasons
