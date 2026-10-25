"""Local stdlib archive/receiver and real binding tests; Popen is fake only."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import vm_proof_guard as g
import vm_proof_payload as p
from vm_proof_adapter import StopLatch, _safe_rollback, run_guard
from vm_proof_driver import GuestProof, Source, GUEST_CODE
from vm_proof_linux import LinuxSubprocessIO
from test_vm_proof_linux import Child
from test_vm_proof_adapter import RUN, PRESSURE, FREE, config

COMMIT = "b" * 40
BOOT = "12345678-1234-1234-1234-123456789abc"


def archive(extra=(), commit=COMMIT, filler=0):
    output = io.BytesIO()
    entries = [(name, b"FROM python:3.12-slim\n") for name in p.DOCKERFILES.values()]
    entries.append((p.PROCESS_FIXTURE, b"# synthetic archive fixture; never executed\n"))
    entries += [("deploy/" + name, b"NoNewPrivileges=true\nStateDirectory=toolstack\nLogsDirectory=toolstack\n")
                for name in ("toolstack-admin.service", "toolstack-sps.service")]
    if filler:
        entries.append(("filler", b"x" * filler))
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as tf:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tf.addfile(member, io.BytesIO(data))
        for member in extra:
            tf.addfile(member, io.BytesIO(b""))
    return output.getvalue()


def source(filler=0):
    data = archive(filler=filler)
    return Source(COMMIT, hashlib.sha256(data).hexdigest(), data)


def process_result():
    # Fake wire evidence only; no claim that fixture ran in these unit tests.
    return {"status": "PASS", "cleanup": "reaped", "checks": list(p.PROCESS_CHECKS),
            "platform": "Linux-fake", "python": "3.12.1", "cryptography": "50.0.2",
            "boots": ["first", "second"], "ports": {"sps": 12345, "tool": 12346},
            "processes": [{"label": "sps", "pid": 10, "identity": "start10"},
                          {"label": "runner spawn", "pid": 11, "identity": "start11", "boot": BOOT, "cleanup": "reaped and absent"},
                          {"label": "tool", "pid": 11, "identity": "start11", "boot": BOOT},
                          {"label": "sps-restart", "pid": 12, "identity": "start12"}]}


class ArchiveReceiver(unittest.TestCase):
    def test_checksum_commit_member_type_and_escape_rejected(self):
        data = archive()
        digest = hashlib.sha256(data).hexdigest()
        self.assertTrue(p.validate_archive(data, COMMIT, digest))
        for commit, sha in (("c" * 40, digest), (COMMIT, "0" * 64)):
            with self.assertRaises(ValueError):
                p.validate_archive(data, commit, sha)
        for name, kind in (("/escape", tarfile.REGTYPE), ("a/../escape", tarfile.REGTYPE),
                           ("escape", tarfile.SYMTYPE), ("escape", tarfile.LNKTYPE),
                           ("escape", tarfile.FIFOTYPE), (".git/config", tarfile.REGTYPE),
                           ("deploy/docker/.env", tarfile.REGTYPE)):
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = "/outside"
            bad = archive([member])
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                p.validate_archive(bad, COMMIT, hashlib.sha256(bad).hexdigest())

    def test_absent_root_chunks_no_retry_extract_and_owner_preservation(self):
        src = source(p.CHUNK + 1)
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            root = parent / "owned"
            owner = parent / "preexisting"
            owner.mkdir()
            (owner / ".env").write_text("never-read-owner-data")
            with patch.object(p, "root_for", return_value=root):
                marker = p.dispatch(RUN, "init", [src.commit, src.sha256, str(len(src.data))], b"")
                self.assertEqual(marker["run"], RUN)
                with self.assertRaises(FileExistsError):
                    p.dispatch(RUN, "init", [src.commit, src.sha256, str(len(src.data))], b"")
                for offset in range(0, len(src.data), p.CHUNK):
                    chunk = src.data[offset:offset + p.CHUNK]
                    args = [str(offset), hashlib.sha256(chunk).hexdigest()]
                    receipt = p.dispatch(RUN, "chunk", args, base64.b64encode(chunk))
                    self.assertEqual(receipt, {"offset": offset + len(chunk)})
                    with self.assertRaises(ValueError):
                        p.dispatch(RUN, "chunk", args, base64.b64encode(chunk))
                result = p.dispatch(RUN, "extract", [], b"")
                self.assertEqual(result["commit"], COMMIT)
                self.assertTrue((root / "src/deploy/docker/Dockerfile").is_file())
                with self.assertRaises(FileExistsError):
                    p.dispatch(RUN, "extract", [], b"")
                with self.assertRaises(ValueError):
                    p.dispatch(RUN, "remove", [str(marker["dev"]), "0"], b"")
                p.dispatch(RUN, "remove", [str(marker["dev"]), str(marker["ino"])], b"")
                self.assertTrue((owner / ".env").exists())
                self.assertFalse(root.exists())

    def test_source_file_nofollow_and_private_metadata(self):
        src = source()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "source.tar"
            path.write_bytes(src.data)
            path.chmod(0o600)
            self.assertEqual(Source.load(str(path), COMMIT, src.sha256), src)
            (root / "link").symlink_to(path)
            with self.assertRaises(OSError):
                Source.load(str(root / "link"), COMMIT, src.sha256)
            path.chmod(0o644)
            with self.assertRaises(g.GuardRefusal):
                Source.load(str(path), COMMIT, src.sha256)

    def test_one_absent_job_identity_blocks_retry_and_fake_bootstrap_asserts(self):
        src = source()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "owned"
            with patch.object(p, "root_for", return_value=root), patch.object(p, "process_identity", return_value={"pid": 55, "start": 123, "boot": BOOT}), patch.object(p, "build", return_value={"image": "sha256:" + "a" * 64}) as build:
                p.dispatch(RUN, "init", [src.commit, src.sha256, str(len(src.data))], b"")
                p.dispatch(RUN, "build", ["onebox"], b"")
                with self.assertRaises(FileExistsError):
                    p.dispatch(RUN, "build", ["onebox"], b"")
                build.assert_called_once()
        self.assertIn("assert shutil.which('admin')", p.ONEBOX_CHECK)
        self.assertIn("assert", p.ECHO_CHECK)
        self.assertNotIn("getpass", p.ONEBOX_CHECK)

    def test_chunk_corruption_oversize_and_duplicate_archive_rejected(self):
        duplicate = tarfile.TarInfo("deploy/docker/Dockerfile")
        bad = archive([duplicate])
        with self.assertRaises(ValueError):
            p.validate_archive(bad, COMMIT, hashlib.sha256(bad).hexdigest())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "owned"
            src = source()
            p.initialize(root, RUN, COMMIT, src.sha256, len(src.data))
            for content, digest in ((b"!invalid!", "0" * 64),
                                    (base64.b64encode(b"fake"), "0" * 64),
                                    (base64.b64encode(b"x" * (p.CHUNK + 1)), "0" * 64)):
                with self.assertRaises(ValueError):
                    p.receive_chunk(root, 0, digest, content)
            self.assertEqual((root / "payload.tar").stat().st_size, 0)

    def test_dirty_inventory_metadata_only_no_checkout_mutation(self):
        from test_vm_proof_checkout import InventoryHarness
        with InventoryHarness() as fake:
            result = p.inventory("discover")
        self.assertIn("?? .env", result["status"])
        calls = [c for c in fake.calls if c[0] == "sudo"]
        self.assertTrue(all(c[:6] == ("sudo", "-n", "-u", "admin", "--", "git") for c in calls))
        self.assertTrue(all("--no-optional-locks" in c and "core.fsmonitor=false" in c for c in calls))
        self.assertFalse(any(word in c for c in calls for word in ("diff", "reset", "checkout", "fetch")))


class FakePVE:
    """Popen responder emulates documented QGA wire; never evaluates guest code."""
    def __init__(self):
        self.calls = []
        self.input_chunks = []
        self.vm = "stopped"
        self.memory = 8192
        self.jobs = {}
        self.job_sequence = []
        self.images = []
        self.containers = {}
        self.polls = 0
        self.low_during_build = False
        self.bad_prod_during_build = False
        self.fail_build = False
        self.lose_pid = False
        self.late_trip = None
        self.used_image = False
        self.wrong_image_label = False
        self.lost_lease = False

    def __call__(self, argv, **kwargs):
        argv = (Path(argv[0]).name, *argv[1:])
        self.calls.append(argv)
        data = kwargs["stdin"].read() if hasattr(kwargs["stdin"], "read") else None
        text = self.command(argv, data)
        return Child(text.encode())

    def command(self, argv, data):
        if argv[:2] == ("free", "-m"):
            return FREE
        if argv[0] == "curl":
            return g.NOD_HEALTH_BODY
        if argv[:2] == ("qm", "status"):
            return "status: " + ("running" if argv[2] == "100" else self.vm)
        if argv[:2] == ("qm", "config"):
            return f"memory: {self.memory}\ncores: 2\nonboot: 0\nagent: 1"
        if argv[:2] == ("qm", "set"):
            self.memory = int(argv[-1])
            return ""
        if argv[:2] == ("qm", "start"):
            self.vm = "running"
            return ""
        if argv[:2] == ("qm", "shutdown"):
            self.vm = "stopped"
            return ""
        if argv[:3] == ("qm", "guest", "exec-status"):
            self.polls += 1
            job = self.jobs[int(argv[-1])]
            if job["polls"] == 0:
                job["polls"] += 1
                return '{"exited": false}'
            failed = self.fail_build and job["action"] == "build"
            return json.dumps({"exited": True, "exitcode": 1 if failed else 0,
                               "out-data": json.dumps(job["result"])})
        if argv[:3] == ("qm", "guest", "exec"):
            inner = argv[argv.index("--") + 1:]
            if argv[3] == "100":
                bad = self.bad_prod_during_build and self.polls > 0
                return self.qga("nod\tUp (unhealthy)" if bad else "nod\tUp (healthy)")
            if inner[:3] == ("python3", "-c", GUEST_CODE):
                run, action, *args = inner[3:]
                assert run == RUN
                result = self.action(action, args, data)
                if "--synchronous" in argv:
                    pid = 500 + len(self.jobs)
                    self.jobs[pid] = {"action": action, "polls": 0, "result": result, "key": action + "-" + args[0]}
                    self.job_sequence.append(action + "-" + args[0])
                    if self.late_trip and action == "create":
                        self.late_trip()
                    return '{}' if self.lose_pid else json.dumps({"pid": pid})
                return self.qga(json.dumps(result))
            if inner == ("docker", "ps", "-a", "--no-trunc", "--format", g.PROOF_PS_FORMAT):
                return self.qga("\n".join(f"{cid}\t{RUN}\tproof" for cid in self.containers))
            if inner[:5] == ("docker", "ps", "-a", "--no-trunc", "--filter"):
                return self.qga("f" * 64 if self.used_image else "")
            if inner[:2] == ("docker", "stop"):
                return self.qga(inner[-1])
            if inner[:2] == ("docker", "rm"):
                self.containers.pop(inner[-1])
                return self.qga("")
            if inner[:3] == ("docker", "image", "inspect"):
                image = next(i for i in self.images if i["image"] == inner[-1])
                return self.qga(image["image"] + "\t" + json.dumps([image["tag"]]) + "\t" + json.dumps({g.LABEL_KEY: "other" if self.wrong_image_label else RUN}))
            if inner[:3] == ("docker", "image", "rm"):
                self.images = [i for i in self.images if i["image"] != inner[-1]]
                return self.qga("")
            return self.qga("unit metadata")
        raise AssertionError(argv)

    @staticmethod
    def qga(text):
        return json.dumps({"exited": 1, "exitcode": 0, "out-data": text})

    def action(self, action, args, data):
        if action == "inventory":
            return {"head": "a" * 40, "branch": "owner", "path": "/opt/toolstack", "root": "/opt/toolstack",
                    "owner": "admin", "uid": 1000, "gid": 1000, "submodules": "", "status": " M owner-work\n?? .env\n"}
        if action == "init":
            return {"run": RUN, "dev": 1, "ino": 2}
        if action == "chunk":
            self.input_chunks.append(data)
            block = base64.b64decode(data, validate=True)
            assert hashlib.sha256(block).hexdigest() == args[1]
            return {"offset": int(args[0]) + len(block)}
        if action == "extract":
            return {"commit": self.source.commit, "sha256": self.source.sha256, "members": 5}
        if action == "identity":
            return {"pid": int(args[1]), "start": 123, "boot": BOOT}
        if action == "build":
            image = {"image": "sha256:" + str(len(self.images) + 1) * 64, "tag": p.tag_for(RUN, args[0]), "label": RUN}
            self.images.append(image)
            return image
        if action == "create":
            cid = str(len(self.containers) + 1) * 64
            self.containers[cid] = args[0]
            return {"container": cid, "kind": args[0], "label": RUN}
        if action == "start":
            if args[0] == "process-sps":
                return {"checked": "process-sps", "exit": 0, "proof": process_result()}
            return {"checked": args[0], "http": 200} if args[0] == "serve" else {"checked": args[0], "exit": 0}
        if action == "remove":
            return {"removed": str(p.root_for(RUN))}
        raise AssertionError(action)


class BoundDriver(unittest.TestCase):
    def test_inventory_failure_qga_nonzero_persists_exact_step_before_shutdown(self):
        io, host = self.setup_io()
        original = host.action
        envelope = {"error": "inventory-failed", "step": "git-status", "reason": "command-failed",
                    "metadata": {"path": "/srv/actual-checkout", "owner": "admin"}}
        stages = []
        def action(name, args, data):
            if name == "inventory":
                state = json.loads(io.files.read("state"))["proof"]
                self.assertEqual(state["inventory_stage"]["step"], args[1])
                self.assertEqual(state["inventory_stage"]["state"], "started")
                stages.append(args[1])
                if args[1] == "git-status":
                    return envelope
            return original(name, args, data)
        host.action = action
        host.qga = lambda text: json.dumps({"exited": 1, "exitcode": 1 if json.loads(text).get("error") else 0,
                                           "out-data": text}) if text.startswith("{") else FakePVE.qga(text)
        result = run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=8)
        self.assertTrue(result.ask_parent)
        self.assertTrue(result.restored)
        state = json.loads(io.files.read("state"))["proof"]
        self.assertEqual(state["inventory_failure"], envelope)
        self.assertEqual(stages, list(p.INVENTORY_STEPS[:-1]))
        self.assertFalse(state["root_attempted"])
        self.assertFalse(state["complete"])
        self.assertEqual(state["transferred"], 0)
        self.assertEqual(host.job_sequence, [])
        self.assertEqual(host.calls.count(("qm", "shutdown", "130", "--timeout", "90")), 1)
        self.assertEqual(host.memory, 8192)

    def setup_io(self, filler=0):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = str(Path(tmp.name).resolve())
        os.chmod(root, 0o700)
        host = FakePVE()
        host.source = source(filler)
        latch = StopLatch()
        io = LinuxSubprocessIO(root, config(), latch, "discover", popen=host,
                               observe=lambda pid: 123, source=host.source)
        self.addCleanup(io.close)
        io.lease_age = lambda: None if host.lost_lease and host.polls else 0
        io.admit_text = lambda: RUN
        def read(path):
            if path == "/proc/meminfo":
                return "MemAvailable: %d kB" % (1 if host.low_during_build and host.polls else 7100000)
            return PRESSURE
        io.read = read
        io.proof.sleep = lambda seconds: None
        return io, host

    def test_full_real_binding_sequence_dirty_owner_chunks_async_and_cleanup(self):
        io, host = self.setup_io(p.CHUNK + 1)
        result = run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=8)
        self.assertFalse(result.ask_parent, result)
        self.assertTrue(result.restored)
        self.assertTrue(io.proof.completed)
        self.assertGreater(len(host.input_chunks), 1)
        self.assertTrue(all(len(c) < 1024 * 1024 for c in host.input_chunks))
        self.assertEqual(b"".join(base64.b64decode(c) for c in host.input_chunks), host.source.data)
        self.assertEqual([s for s in host.job_sequence if s.startswith("build-")], ["build-onebox", "build-echo-api", "build-echo-mcp"])
        self.assertEqual(len(io.proof.containers), 5)
        self.assertEqual(host.job_sequence[-4:], ["create-process-sps", "start-process-sps", "create-serve", "start-serve"])
        evidence = json.loads(io.files.read("proof-evidence"))
        self.assertEqual(next(e["result"]["proof"] for e in evidence if e["step"] == "start-process-sps"), process_result())
        self.assertTrue(all(len(cid) == 64 for cid in io.proof.containers))
        self.assertEqual(len(io.proof.images), 3)
        self.assertEqual(host.containers, {})
        self.assertEqual(host.images, [])
        self.assertIn(" M owner-work", json.loads(io.files.read("owner-inventory"))["status"])
        shutdown = host.calls.index(("qm", "shutdown", "130", "--timeout", "90"))
        remove_image = max(i for i, argv in enumerate(host.calls) if "rm" in argv and "image" in argv)
        self.assertLess(remove_image, shutdown)
        self.assertEqual(host.calls.count(("qm", "shutdown", "130", "--timeout", "90")), 1)
        self.assertNotIn(("qm", "stop", "130"), host.calls)
        self.assertEqual(host.memory, 8192)
        # Exec-status only for recorded QGA job IDs, with full production probes
        # between polls, and guest start jobs after durable create completion.
        polls = [i for i, c in enumerate(host.calls) if c[:3] == ("qm", "guest", "exec-status")]
        for left, right in zip(polls, polls[1:]):
            self.assertTrue(any(c == g.production_ps_argv() for c in host.calls[left + 1:right]))
        self.assertFalse(any("reset" in c or "clean" in c or "prune" in c for c in host.calls))

    def test_memory_and_production_loss_during_build_fence_without_retry(self):
        for failure in ("low_during_build", "bad_prod_during_build", "lost_lease"):
            io, host = self.setup_io()
            setattr(host, failure, True)
            result = run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=8)
            self.assertTrue(result.ask_parent)
            self.assertFalse(io.proof.completed)
            self.assertEqual(host.job_sequence, ["build-onebox"])
            self.assertIsNotNone(io.proof.pending)
            self.assertIn(("qm", "shutdown", "130", "--timeout", "90"), host.calls)
            self.assertFalse(any("remove" in c for c in host.calls))

    def test_missing_qga_pid_and_build_failure_are_no_retry_unknown(self):
        for failure in ("lose_pid", "fail_build"):
            io, host = self.setup_io()
            setattr(host, failure, True)
            result = run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=8)
            self.assertTrue(result.ask_parent)
            self.assertEqual(host.job_sequence, ["build-onebox"])
            self.assertEqual(host.calls.count(("qm", "shutdown", "130", "--timeout", "90")), 1)

    def test_stop_during_create_never_starts_unrecorded_late_container(self):
        io, host = self.setup_io()
        host.late_trip = lambda: io.latch.trip("injected-stop")
        result = run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=8)
        self.assertTrue(result.ask_parent)
        self.assertEqual(host.job_sequence, ["build-onebox", "create-onebox"])
        self.assertIsNotNone(io.proof.pending)
        self.assertTrue(io.latch.closed())
        self.assertNotIn("start-onebox", host.job_sequence)

    def test_fixed_allowlist_rejects_raw_shell_unadmitted_jobs_and_status_pid(self):
        io, host = self.setup_io()
        io.owned_start = True
        for command in (("qm", "guest", "exec-status", "130", "999"),
                        ("qm", "guest", "exec", "130", "--synchronous", "0", "--", "/bin/sh", "-c", "touch /owner"),
                        io.proof.command("build", ("onebox",), asynchronous=True)):
            with self.assertRaises(g.GuardRefusal):
                io.run(command, 45)
        self.assertEqual(host.calls, [])

    def test_source_driver_no_admit_does_not_autostart_or_transfer(self):
        io, host = self.setup_io()
        io.admit_text = lambda: None
        result = run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=1)
        self.assertFalse(result.restored)
        self.assertFalse(io.proof.root_attempted)
        self.assertFalse(host.input_chunks)
        self.assertFalse(any(c[:2] in (("qm", "set"), ("qm", "start"), ("qm", "shutdown")) for c in host.calls))

    def test_cleanup_allowlist_cannot_be_used_for_late_build(self):
        io, host = self.setup_io()
        io.owned_start = True
        io.begin_cleanup()
        command = io.proof.command("build", ("onebox",), asynchronous=True)
        io.proof.expected = (command, None)
        with self.assertRaises(g.GuardRefusal):
            io.run(command, 45)
        self.assertEqual(host.calls, [])
        io.latch.trip("stop")
        with self.assertRaises(g.GuardRefusal):
            io.proof.job("build", "onebox")
        self.assertEqual(host.calls, [])

    def test_used_or_mislabeled_images_preserved_cleanup_still_shuts_down(self):
        for fault in ("used_image", "wrong_image_label"):
            io, host = self.setup_io()
            setattr(host, fault, True)
            result = run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=8)
            self.assertTrue(result.ask_parent)
            self.assertEqual(len(host.images), 3)
            self.assertIn(("qm", "shutdown", "130", "--timeout", "90"), host.calls)
            self.assertFalse(any("remove" in c for c in host.calls))


if __name__ == "__main__":
    unittest.main()
