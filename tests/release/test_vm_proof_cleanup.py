"""Image-user regression through real transport code and fake Popen pipes only."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

import vm_proof_guard as g
from vm_proof_adapter import StopLatch, timeout_for
from vm_proof_linux import LinuxSubprocessIO
from test_vm_proof_linux import Child


RUN = "vmproof-20261024T182625Z-2b3a3e9a"
IMAGES = (
    "sha256:fb8e78e8c31cdc5fb7a8ca893d58a56358efe152145e8433ff23e5837418c9c3",
    "sha256:bc4444aff2d536d62ca0ef3ec113dda922db2abe4c17724bfb1c805fbdda582d",
    "sha256:b9e50c2fafe2ba9da97191f9c1120c8bf1b2d91096141bbefe9822a18f375cf4",
)
WARNING = "WARNING: Ignoring custom format, because both --format and --quiet are set."


class ImageUsers(unittest.TestCase):
    def exercise(self, image=IMAGES[0], *, host_error="", guest_error="", users="",
                 inspect_text=None, inspect_code=0, remove_code=0):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = str(Path(temp.name).resolve())
        os.chmod(root, 0o700)
        calls = []
        users_cmd = ("docker", "ps", "-a", "--no-trunc", "--filter",
                     "ancestor=" + image, "--format", "{{.ID}}")
        inspect_cmd = ("docker", "image", "inspect", "--format", g.IMAGE_INSPECT_FORMAT, image)
        remove_cmd = ("docker", "image", "rm", image)
        if inspect_text is None:
            inspect_text = "\t".join((image, json.dumps([sorted(g.run_tags(RUN))[0]]),
                                      json.dumps({g.LABEL_KEY: RUN})))

        def spawn(argv, **kwargs):
            self.assertEqual(argv[0], "/usr/sbin/qm")
            self.assertEqual(argv[1:4], ("guest", "exec", "130"))
            self.assertNotIn("shell", kwargs)
            inner = argv[7:]
            calls.append(inner)
            if inner == users_cmd:
                text, code, error = users, 0, guest_error
            elif inner == inspect_cmd:
                text, code, error = inspect_text, inspect_code, ""
            elif inner == remove_cmd:
                text, code, error = "", remove_code, ""
            else:
                self.fail("unexpected command: " + repr(inner))
            body = json.dumps({"exited": 1, "exitcode": code,
                               "out-data": text, "err-data": error}).encode()
            return Child(body, host_error.encode() if inner == users_cmd else b"")

        config = g.GuardConfig(RUN, (g.BaselineContainer("nod", "healthy"),))
        io = LinuxSubprocessIO(root, config, StopLatch(), "discover", popen=spawn,
                               observe=lambda pid: 123)
        self.addCleanup(io.close)
        # Isolate transport; the existing guard suite separately tests health/lease.
        io.check = lambda: None
        io.owned_start = True

        def permit(argv, data):
            g.rollback_command_allowed(tuple(argv), RUN)
            return data is None and tuple(argv[7:]) in (users_cmd, inspect_cmd, remove_cmd)

        io.proof = SimpleNamespace(permit=permit)
        reasons = []
        g._remove_image(lambda argv: io.run(argv, timeout_for(argv)), RUN, image, reasons)
        self.assertFalse(io.active)
        self.assertFalse(io.unresolved_child)
        return reasons, calls

    def test_corrected_full_id_query_all_three_ids(self):
        for image in IMAGES:
            with self.subTest(image=image):
                reasons, calls = self.exercise(image)
                self.assertEqual(reasons, [])
                self.assertEqual(len(calls), 3)
                self.assertEqual(calls[-1], ("docker", "image", "rm", image))
                self.assertNotIn("-aq", calls[0])
                self.assertEqual(calls[0][-2:], ("--format", "{{.ID}}"))

    def test_warning_remains_unknown_at_both_transport_layers(self):
        for field in ("host_error", "guest_error"):
            with self.subTest(field=field):
                reasons, calls = self.exercise(**{field: WARNING})
                self.assertEqual(reasons, ["image-users-unknown:" + IMAGES[0]])
                self.assertEqual(len(calls), 1)

    def test_foreign_or_malformed_user_output_prevents_deletion(self):
        for users in ("f" * 64 + "\n", "unexpected output"):
            reasons, calls = self.exercise(users=users)
            self.assertEqual(reasons, ["image-in-use:" + IMAGES[0]])
            self.assertEqual(len(calls), 1)

    def test_foreign_shared_or_unknown_image_identity_prevents_deletion(self):
        good_tags = [sorted(g.run_tags(RUN))[0]]
        for image, tags, labels in (
            (IMAGES[1], good_tags, {g.LABEL_KEY: RUN}),
            (IMAGES[0], ["foreign:latest"], {g.LABEL_KEY: RUN}),
            (IMAGES[0], good_tags + ["shared:latest"], {g.LABEL_KEY: RUN}),
            (IMAGES[0], good_tags, {g.LABEL_KEY: "another-run"}),
            (IMAGES[0], [], {g.LABEL_KEY: RUN}),
            (IMAGES[0], None, {}),
        ):
            text = "\t".join((image, json.dumps(tags), json.dumps(labels)))
            reasons, calls = self.exercise(inspect_text=text)
            self.assertEqual(reasons, ["image-not-owned:" + IMAGES[0]])
            self.assertEqual(len(calls), 2)

    def test_inspect_error_is_not_positive_absence(self):
        reasons, calls = self.exercise(inspect_code=1)
        self.assertEqual(reasons, ["image-not-owned:" + IMAGES[0]])
        self.assertEqual(len(calls), 2)

    def test_remove_failure_reported_without_retry(self):
        reasons, calls = self.exercise(remove_code=1)
        self.assertEqual(reasons, ["image-rm-failed:" + IMAGES[0]])
        self.assertEqual(len(calls), 3)

    def test_exact_allowlist_rejects_quiet_conflict_force_and_prune(self):
        corrected = ("docker", "ps", "-a", "--no-trunc", "--filter",
                     "ancestor=" + IMAGES[0], "--format", "{{.ID}}")
        g.rollback_command_allowed(g._guest("130", g.PRODUCTION_TIMEOUT, corrected), RUN)
        for inner in (
            (*corrected[:2], "-aq", *corrected[3:]),
            (*corrected[:-1], "{{.Names}}"),
            ("docker", "image", "rm", "--force", IMAGES[0]),
            ("docker", "image", "prune"),
        ):
            with self.assertRaises(g.GuardRefusal):
                g.rollback_command_allowed(g._guest("130", g.PRODUCTION_TIMEOUT, inner), RUN)


if __name__ == "__main__":
    unittest.main()
