"""Actual fixed inventory, fake bounded commands/NSS/stat; never sudo or Git."""
import contextlib
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vm_proof_payload as p
import vm_proof_guard as g
from vm_proof_driver import GuestProof, Source
from vm_proof_adapter import StopLatch


class InventoryHarness(contextlib.ExitStack):
    path = "/srv/actual-checkout"

    def __enter__(self):
        super().__enter__()
        self.calls = []
        self.admin = "User=admin\nGroup=admin\nWorkingDirectory=" + self.path + "\n"
        self.sps = "User=\nGroup=\nWorkingDirectory=\n"
        self.fail = None
        self.stat_text = "admin:admin 755 " + self.path
        self.info = SimpleNamespace(st_uid=1000, st_gid=1000, st_mode=stat.S_IFDIR | 0o755, st_dev=1, st_ino=2)
        self.enter_context(patch.object(p, "bounded", side_effect=self.command))
        self.directory = self.enter_context(patch.object(p, "safe_directory", side_effect=lambda _: self.info))
        account = SimpleNamespace(pw_name="admin", pw_uid=1000, pw_gid=1000)
        self.user = self.enter_context(patch.object(p.pwd, "getpwuid", return_value=account))
        self.enter_context(patch.object(p.pwd, "getpwnam", return_value=account))
        self.enter_context(patch.object(p.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=1000)))
        self.group = self.enter_context(patch.object(p.grp, "getgrgid", return_value=SimpleNamespace(gr_name="admin", gr_gid=1000)))
        return self

    def command(self, argv, root, seconds=30):
        self.calls.append(argv)
        assert seconds == 5 and root == Path("/")
        if self.fail and self.fail in argv:
            raise ValueError("RAW_SECRET_STDERR_DO_NOT_PERSIST")
        if argv[0] == "systemctl":
            assert argv[1:4] == ("show", "-p", "User,Group,WorkingDirectory")
            return self.admin if argv[-1] == "toolstack-admin.service" else self.sps
        if argv[0] == "stat":
            return self.stat_text
        assert argv[:6] == ("sudo", "-n", "-u", "admin", "--", "git")
        if "--show-toplevel" in argv:
            return self.path + "\n"
        if "--abbrev-ref" in argv:
            return "owner-branch\n"
        if "rev-parse" in argv:
            return "a" * 40 + "\n"
        if "submodule" in argv:
            return ""
        return " M owner-work\n?? .env\n R old -> new\n"


class CheckoutTests(unittest.TestCase):
    def refusal(self, fake, step, reason=None, checkout="discover"):
        with self.assertRaises(p.InventoryFailure) as caught:
            p.inventory(checkout)
        envelope = caught.exception.envelope
        self.assertTrue(p.inventory_error(envelope))
        self.assertEqual(envelope["step"], step)
        if reason:
            self.assertEqual(envelope["reason"], reason)
        self.assertNotIn("RAW_SECRET", json.dumps(envelope))
        return envelope

    def test_actual_sequence_owner_and_dirty_paths(self):
        with InventoryHarness() as fake:
            result = p.inventory("discover")
            self.assertEqual(result["owner"], "admin")
            self.assertEqual(result["sps"], {"state": "unknown-or-absent"})
            self.assertEqual(result["status"], " M owner-work\n?? .env\n R old -> new\n")
            self.assertEqual([c[0] for c in fake.calls], ["systemctl", "systemctl", "stat"] + ["sudo"] * 5)
            self.assertEqual(result["group"], "admin")
            self.assertEqual(result["mode"], 0o755)
            self.assertTrue(all(call.args == (Path(fake.path),) for call in fake.directory.call_args_list))

    def test_missing_ambiguous_and_unsafe_service_identity(self):
        for text in ("User=admin\nGroup=admin\n", "User=admin\nUser=root\nGroup=admin\nWorkingDirectory=/srv/repo\n",
                     "User=admin\nGroup=admin\nWorkingDirectory=\n",
                     "User=admin;id\nGroup=admin\nWorkingDirectory=/srv/repo\n",
                     "User=admin\nGroup=admin\nWorkingDirectory=/srv/../repo\n"):
            with self.subTest(text=text), InventoryHarness() as fake:
                fake.admin = text
                self.refusal(fake, "serviceprops", "invalid-metadata")
                self.assertEqual(len(fake.calls), 1)

    def test_known_path_verified_against_actual(self):
        with InventoryHarness() as fake:
            self.refusal(fake, "serviceprops", checkout="/opt/guessed")
        with InventoryHarness() as fake:
            self.assertEqual(p.inventory(fake.path)["path"], fake.path)

    def test_unknown_root_and_mismatched_owners(self):
        with InventoryHarness() as fake:
            fake.user.side_effect = KeyError("RAW_SECRET")
            self.refusal(fake, "statowner", "owner-unknown")
        with InventoryHarness() as fake:
            fake.user.return_value.pw_uid = 0
            self.refusal(fake, "statowner", "owner-unknown")
        with InventoryHarness() as fake:
            fake.info.st_uid = 0
            self.refusal(fake, "statowner", "owner-unknown")
        with InventoryHarness() as fake:
            fake.stat_text = "root:root 755 " + fake.path
            self.refusal(fake, "statowner", "invalid-metadata")
        with InventoryHarness() as fake:
            fake.directory.side_effect = OSError("unsafe symlink")
            self.refusal(fake, "statowner", "unsafe-directory")
        with InventoryHarness() as fake:
            fake.group.side_effect = KeyError("unknown gid")
            self.refusal(fake, "statowner", "owner-unknown")

    def test_directory_owner_is_independent_of_service_user_and_group(self):
        for user, group in (("serviceuser", "servicegroup"), ("root", "root"), ("", "")):
            with self.subTest(user=user), InventoryHarness() as fake:
                fake.admin = f"User={user}\nGroup={group}\nWorkingDirectory={fake.path}\n"
                result = p.inventory("discover")
                self.assertEqual(result["service"]["User"], user)
                self.assertEqual(result["service"]["Group"], group)
                self.assertEqual(result["owner"], "admin")
                self.assertEqual(result["group"], "admin")
                self.assertTrue(all(c[:6] == ("sudo", "-n", "-u", "admin", "--", "git")
                                    for c in fake.calls if c[0] == "sudo"))

    def test_directory_identity_change_refused_before_git(self):
        for field, value in (("st_uid", 2000), ("st_gid", 2000), ("st_ino", 99),
                             ("st_dev", 99), ("st_mode", stat.S_IFDIR | 0o700)):
            for change_call, stage in ((2, "statowner"), (3, "git-root")):
                with self.subTest(field=field, stage=stage), InventoryHarness() as fake:
                    changed = SimpleNamespace(**vars(fake.info))
                    setattr(changed, field, value)
                    fake.directory.side_effect = [fake.info] * (change_call - 1) + [changed]
                    self.refusal(fake, stage, "unsafe-directory")
                    self.assertFalse(any(c[0] == "sudo" for c in fake.calls))

    def test_denied_sudo_and_git_failure_exact_step_no_retry(self):
        for token, step in (("sudo", "git-root"), ("HEAD", "git-head"), ("status", "git-status"),
                            ("toolstack-admin.service", "serviceprops"), ("stat", "statowner")):
            with self.subTest(token=token), InventoryHarness() as fake:
                fake.fail = token
                self.refusal(fake, step, "command-failed")
                self.assertEqual(sum(token in c for c in fake.calls), 1)

    def test_optional_sps_failure_explicit_unknown(self):
        with InventoryHarness() as fake:
            fake.fail = "toolstack-sps.service"
            self.assertEqual(p.inventory("discover")["sps"], {"state": "unknown-or-absent"})

    def test_invalid_git_stdout_never_enters_failure_envelope(self):
        for token, step in (("--show-toplevel", "git-root"), ("HEAD", "git-head")):
            with InventoryHarness() as fake:
                original = fake.command
                def command(argv, root, seconds=30):
                    if token in argv:
                        return "RAW_SECRET_STDOUT_DO_NOT_PERSIST"
                    return original(argv, root, seconds)
                with patch.object(p, "bounded", side_effect=command):
                    self.refusal(fake, step, "invalid-metadata")

    def test_clean_environment_does_not_inherit_credentials(self):
        with patch.dict(p.os.environ, {"SECRET_TOKEN": "RAW_SECRET", "GIT_CONFIG_COUNT": "1", "SSH_AUTH_SOCK": "/secret"}):
            env = p.clean_env(Path("/"))
        self.assertNotIn("SECRET_TOKEN", env)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_generated_symlinks_and_mixed_descendants_are_not_inspected(self):
        # Fake descendant metadata is deliberately incompatible with the old
        # scanner. No caller may enumerate or stat these repository contents.
        descendants = [SimpleNamespace(name="admin/.venv/bin/python", st_mode=stat.S_IFLNK,
                                       target=p.sys.executable),
                       SimpleNamespace(name="dirty", st_uid=2000, st_gid=3000)]
        with InventoryHarness(), patch.object(p.os, "scandir", return_value=descendants) as scan, \
                patch.object(Path, "lstat", side_effect=AssertionError("descendant metadata read")) as lstat:
            result = p.inventory("discover")
        self.assertEqual(result["owner"], "admin")
        scan.assert_not_called()
        lstat.assert_not_called()

    def test_checkout_path_symlink_is_refused_without_following(self):
        safe_directory = p.safe_directory
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "link").symlink_to(root, target_is_directory=True)
            with InventoryHarness() as fake:
                fake.admin = f"User=admin\nGroup=admin\nWorkingDirectory={root / 'link'}\n"
                fake.directory.side_effect = safe_directory
                self.refusal(fake, "statowner", "unsafe-directory")
                self.assertFalse(any(c[0] in ("sudo", "stat") for c in fake.calls))

    def test_guest_cli_emits_only_safe_envelope(self):
        with InventoryHarness() as fake:
            fake.fail = "toolstack-admin.service"
            output = io.StringIO()
            with patch.object(p.sys, "argv", ["guest", "vmproof-20261024T161732Z-b35e26e6", "inventory", "discover", "serviceprops", "{}"]), contextlib.redirect_stdout(output):
                self.assertEqual(p.guest_main(), 1)
            self.assertTrue(p.inventory_error(json.loads(output.getvalue())))
            self.assertNotIn("RAW_SECRET", output.getvalue())

    def test_qga_error_reaches_private_state_before_raise(self):
        envelope = {"error": "inventory-failed", "step": "git-head", "reason": "command-failed",
                    "metadata": {"path": "/srv/actual-checkout", "owner": "admin"}}
        checkpoints = []
        wire = json.dumps({"exited": 1, "exitcode": 1, "out-data": json.dumps(envelope)})
        io_fake = SimpleNamespace(config=SimpleNamespace(run_id="vmproof-20261024T161732Z-b35e26e6"),
                                  latch=StopLatch(), run=lambda *a, **kw: g.completed_from_guest(wire))
        proof = GuestProof(io_fake, Source("a" * 40, "b" * 64, b""))
        io_fake.checkpoint = lambda: checkpoints.append(json.loads(json.dumps(proof.state())))
        proof.inventory_stage = {"step": "git-head", "state": "started"}
        with self.assertRaises(g.GuardRefusal):
            proof.call(("fake-qga",))
        self.assertEqual(checkpoints[-1]["inventory_failure"], envelope)
        self.assertFalse(checkpoints[-1]["complete"])
        self.assertFalse(checkpoints[-1]["root_attempted"])
        self.assertEqual(checkpoints[-1]["transferred"], 0)
        for bad in (dict(envelope, stderr="RAW_SECRET"), dict(envelope, reason="RAW_SECRET"),
                    dict(envelope, step="arbitrary"), dict(envelope, metadata={"env": "RAW_SECRET"})):
            self.assertFalse(p.inventory_error(bad))
            io_fake.run = lambda *a, **kw: g.Completed(1, json.dumps(bad))
            proof.inventory_failure = None
            count = len(checkpoints)
            with self.assertRaises(g.GuardRefusal):
                proof.call(("fake-qga",))
            self.assertIsNone(proof.inventory_failure)
            self.assertEqual(len(checkpoints), count)


if __name__ == "__main__":
    unittest.main()
