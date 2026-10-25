"""Fixed guest payload command/result tests. No Docker or fixture is executed."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vm_proof_payload as p
import test_vm_proof_driver as driver_tests
from test_vm_proof_driver import RUN, source, process_result
from vm_proof_adapter import run_guard
from test_vm_proof_adapter import config


class ProcessPayload(unittest.TestCase):
    def make(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve() / "proof"
        src = source()
        p.initialize(root, RUN, src.commit, src.sha256, len(src.data))
        script = root / "src" / p.PROCESS_FIXTURE
        script.parent.mkdir(parents=True, mode=0o700)
        p.private_write(script, b"# synthetic test file, never executed")
        image = {"image": "sha256:" + "a" * 64, "tag": p.tag_for(RUN, "onebox"), "label": RUN}
        p.private_write(root / "image-onebox", json.dumps(image).encode())
        self.image, self.cid = image, "c" * 64
        return root, script

    def test_create_exact_mounts_network_env_existing_image_and_record(self):
        root, script = self.make()
        with patch.object(p, "inspect_image", return_value=self.image), patch.object(p, "bounded", return_value=self.cid) as command:
            result = p.create(root, RUN, "process-sps")
        argv = command.call_args.args[0]
        self.assertEqual(argv[:2], ("docker", "create"))
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual([argv[i + 1] for i, a in enumerate(argv) if a == "--mount"],
                         [f"type=bind,src={root}/data,dst=/data", f"type=bind,src={script},dst=/proof/process_sps.py,readonly"])
        self.assertEqual(argv[argv.index("--entrypoint"):], ("--entrypoint", "python3", self.image["image"], "/proof/process_sps.py", "--root", "/data/process-sps"))
        self.assertIn("TOOLSTACK_SPS_SKIP=0", argv)
        self.assertNotIn("TOOLSTACK_SPS_SKIP=1", argv)
        self.assertIn("PYTHONPATH=/app", argv)
        self.assertNotIn("-p", argv)
        self.assertNotIn("/var/run/docker.sock", " ".join(argv))
        self.assertEqual(json.loads(p.read_private(root / "container-process-sps")), result)
        self.assertFalse((root / "data/process-sps").exists())
        self.assertEqual(p.KINDS, ("onebox", "echo-api", "echo-mcp"))

    def test_refuse_preexisting_root_and_unsafe_fixture_before_docker(self):
        for fault in ("existing", "dangling-root", "script-link", "parent-link", "directory", "root-marker", "image"):
            root, script = self.make()
            if fault == "existing":
                (root / "data/process-sps").mkdir()
            elif fault == "dangling-root":
                (root / "data/process-sps").symlink_to(root / "absent")
            elif fault == "script-link":
                script.unlink()
                script.symlink_to(root / "owner")
            elif fault == "parent-link":
                script.parent.rename(script.parent.with_name("original"))
                script.parent.symlink_to(script.parent.with_name("original"))
            elif fault == "directory":
                script.unlink()
                script.mkdir()
            elif fault == "root-marker":
                (root / "owner").write_text('{}')
            with patch.object(p, "bounded") as command, patch.object(p, "inspect_image", return_value={} if fault == "image" else self.image):
                with self.subTest(fault=fault), self.assertRaises((OSError, ValueError)):
                    p.create(root, RUN, "process-sps")
                command.assert_not_called()

    def start(self, root, result, exitcode="0", identity=None):
        path = root / "container-process-sps"
        if not path.exists():
            p.private_write(path, json.dumps({"container": self.cid, "kind": "process-sps", "label": RUN}).encode())
        responses = [self.cid + "\t" + RUN if identity is None else identity,
                     json.dumps(result), exitcode]
        with patch.object(p, "bounded", side_effect=responses) as command:
            value = p.start_container(root, RUN, "process-sps", self.cid)
        self.assertEqual(command.call_args_list[1].args, (("docker", "start", "-a", self.cid), root, 135))
        return value

    def test_start_parses_actual_json_and_records_all_19_checks(self):
        root, _ = self.make()
        result = process_result()
        self.assertEqual(len(result["checks"]), 19)
        self.assertEqual(self.start(root, result), {"checked": "process-sps", "exit": 0, "proof": result})

    def test_start_rejects_wrong_status_missing_checks_cleanup_identity_and_exit(self):
        for fault in ("status", "checks", "cleanup", "process-cleanup", "process-id", "platform", "crypto", "nonzero", "label", "no-json-proof"):
            root, _ = self.make()
            result = process_result()
            if fault == "status":
                result["status"] = "FAIL"
            elif fault == "checks":
                result["checks"].pop(10)
            elif fault == "cleanup":
                result["cleanup"] = "unknown"
            elif fault == "process-cleanup":
                result["processes"][1].pop("cleanup")
            elif fault == "process-id":
                result["processes"][1]["pid"] = 1
            elif fault == "platform":
                result["platform"] = "Darwin-fake"
            elif fault == "crypto":
                result["cryptography"] = "49.0.0"
            elif fault == "no-json-proof":
                result = None
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.start(root, result, "1" if fault == "nonzero" else "0", "wrong-label" if fault == "label" else None)

    def test_reject_unrecorded_container_and_new_build_kind(self):
        root, _ = self.make()
        with patch.object(p, "bounded") as command:
            with self.assertRaises(FileNotFoundError):
                p.start_container(root, RUN, "process-sps", self.cid)
            with patch.object(p, "root_for", return_value=root):
                with self.assertRaises(ValueError):
                    p.dispatch(RUN, "build", ["process-sps"], b"")
            command.assert_not_called()
        self.assertFalse((root / "jobs/build-process-sps").exists())


class DriverResult(unittest.TestCase):
    setup_io = driver_tests.BoundDriver.setup_io

    def test_invalid_process_proof_stops_before_serve_and_rolls_back(self):
        io, host = self.setup_io()
        original = host.action
        def action(name, args, data):
            result = original(name, args, data)
            if name == "start" and args[0] == "process-sps":
                result["proof"]["cleanup"] = "unknown"
            return result
        host.action = action
        run_guard(io, config(), io.latch, io.clock, lambda s: None, max_ticks=8)
        self.assertFalse(io.proof.completed)
        self.assertNotIn("create-serve", host.job_sequence)
        self.assertEqual(host.memory, 8192)
        self.assertEqual(host.calls.count(("qm", "shutdown", "130", "--timeout", "90")), 1)
