"""Real local files/flocks and deterministic interleavings; no host effects."""
import fcntl
import json
import os
from pathlib import Path
import threading
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vm_proof_linux as linux
import vm_proof_guard as g
import test_vm_proof_lease as lease_tests


class PublicationBoundaries(unittest.TestCase):
    make = lease_tests.LeasePublication.make

    def test_open_before_fstat_serializes_replacement_and_valid_snapshots(self):
        io = self.make()
        publisher = linux.PrivateFiles(io.root)
        self.addCleanup(publisher.close)
        opened, contended = threading.Event(), threading.Event()
        errors = []
        reader = threading.get_ident()
        real_open, real_flock = os.open, fcntl.flock
        def publish():
            try:
                self.assertTrue(opened.wait(2))
                publisher.publish_lease(dict(self.record, monotonic=100))
            except BaseException as exc:
                errors.append(exc)
        worker = threading.Thread(target=publish)
        def flock(fd, flags):
            try:
                return real_flock(fd, flags)
            except BlockingIOError:
                if threading.get_ident() != reader and flags & fcntl.LOCK_EX:
                    contended.set()
                raise
        def open_before_fstat(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            if name == "lease" and threading.get_ident() == reader and not opened.is_set():
                opened.set()
                self.assertTrue(contended.wait(2))
                # Old inode is still linked: writer cannot replace between open
                # and PrivateFiles.file's first fstat any more.
                self.assertEqual(os.fstat(fd).st_nlink, 1)
            return fd
        with patch.object(linux.os, "open", side_effect=open_before_fstat), \
                patch.object(linux.fcntl, "flock", side_effect=flock):
            worker.start()
            try:
                self.assertEqual(io.lease_age(), 1)
            finally:
                worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(io.lease_age(), 0)
        self.assertEqual(json.loads(io.files.read("lease"))["monotonic"], 100)
        # Repeated legitimate publications never authorize a detached snapshot.
        for _ in range(3):
            publisher.publish_lease(dict(self.record, monotonic=100))
            self.assertEqual(io.lease_age(), 0)
        io.check()

    def test_uncooperative_removal_or_replacement_never_accepts_unlinked_fd(self):
        for action in ("remove", "replace"):
            with self.subTest(action=action):
                io = self.make()
                root = Path(io.root)
                if action == "replace":
                    (root / "forged").write_text(json.dumps(self.record))
                    (root / "forged").chmod(0o600)
                real_open = os.open
                def intercept(name, flags, *args, **kwargs):
                    fd = real_open(name, flags, *args, **kwargs)
                    if name == "lease":
                        if action == "replace":
                            os.replace(root / "forged", root / "lease")
                        else:
                            (root / "lease").unlink()
                    return fd
                with patch.object(linux.os, "open", side_effect=intercept):
                    with self.assertRaises(g.GuardRefusal):
                        io.files.read("lease")

    def test_current_path_is_verified_even_when_old_inode_stays_linked(self):
        io = self.make()
        root = Path(io.root)
        real_read = os.read
        def changed_path(fd, size):
            data = real_read(fd, size)
            (root / "lease").rename(root / "detached")
            (root / "lease").write_bytes(data)
            (root / "lease").chmod(0o600)
            return data
        with patch.object(linux.os, "read", side_effect=changed_path):
            with self.assertRaises(g.GuardRefusal):
                io.files.read("lease")

    def test_unsafe_absent_stale_and_invalid_identity_remain_fail_closed(self):
        for fault in ("hardlink", "symlink", "mode", "uid", "absent", "stale", "wrong-run",
                      "wrong-pid", "wrong-start", "dead", "reused", "nonfinite"):
            with self.subTest(fault=fault):
                io = self.make()
                root = Path(io.root)
                if fault == "hardlink":
                    os.link(root / "lease", root / "other")
                elif fault == "symlink":
                    (root / "lease").rename(root / "original")
                    (root / "lease").symlink_to(root / "original")
                elif fault == "mode":
                    (root / "lease").chmod(0o644)
                elif fault == "absent":
                    (root / "lease").unlink()
                elif fault in ("dead", "reused"):
                    io.observe = lambda pid: None if fault == "dead" else 999
                elif fault != "uid":
                    record = dict(self.record)
                    record.update({"stale": {"monotonic": 0}, "nonfinite": {"monotonic": float("nan")},
                                   "wrong-run": {"run": "other"}, "wrong-pid": {"pid": 99},
                                   "wrong-start": {"start": 999}}[fault])
                    (root / "lease").write_text(json.dumps(record))
                if fault == "uid":
                    real_fstat = os.fstat
                    lease_ino = (root / "lease").stat().st_ino
                    def foreign_uid(fd):
                        info = real_fstat(fd)
                        if info.st_ino == lease_ino:
                            fields = {k: getattr(info, k) for k in dir(info) if k.startswith("st_")}
                            fields["st_uid"] += 1
                            return SimpleNamespace(**fields)
                        return info
                    with patch.object(linux.os, "fstat", side_effect=foreign_uid):
                        self.assertIsNone(io.lease_age())
                else:
                    with self.assertRaises(g.GuardRefusal):
                        io.check()

    def test_ready_and_admit_absent_during_staging_then_complete(self):
        for target in ("ready", "admit"):
            io = self.make()
            data = "identity-complete\n"
            write = io.files._write
            def staging(fd, text):
                with self.assertRaises(FileNotFoundError):
                    io.files.read(target)
                write(fd, text)
                with self.assertRaises(FileNotFoundError):
                    io.files.read(target)
            with patch.object(io.files, "_write", side_effect=staging):
                io.files.create(target, data)
            self.assertEqual(io.files.read(target), data)
            self.assertEqual((Path(io.root) / target).stat().st_nlink, 1)
            self.assertFalse((Path(io.root) / ("." + target + "-next")).exists())

    def test_link_claim_reader_waits_until_single_link(self):
        io = self.make()
        reader_files = linux.PrivateFiles(io.root)
        self.addCleanup(reader_files.close)
        linked, contended = threading.Event(), threading.Event()
        results, errors = [], []
        main = threading.get_ident()
        real_link, real_flock = os.link, fcntl.flock
        def reader():
            try:
                self.assertTrue(linked.wait(2))
                results.append(reader_files.read("ready"))
            except BaseException as exc:
                errors.append(exc)
        worker = threading.Thread(target=reader)
        def flock(fd, flags):
            try:
                return real_flock(fd, flags)
            except BlockingIOError:
                if threading.get_ident() != main:
                    contended.set()
                raise
        def link(*args, **kwargs):
            real_link(*args, **kwargs)
            self.assertEqual((Path(io.root) / "ready").stat().st_nlink, 2)
            linked.set()
            self.assertTrue(contended.wait(2))
        with patch.object(linux.os, "link", side_effect=link), patch.object(linux.fcntl, "flock", side_effect=flock):
            worker.start()
            try:
                io.files.create("ready", "complete-ready")
            finally:
                worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, ["complete-ready"])

    def test_existing_ready_or_staging_never_overwritten(self):
        for fault in ("target", "symlink", "staging"):
            io = self.make()
            root = Path(io.root)
            path = root / (".ready-next" if fault == "staging" else "ready")
            if fault == "symlink":
                path.symlink_to("absent-foreign")
            else:
                path.write_text("foreign")
                path.chmod(0o600)
            with self.assertRaises(FileExistsError):
                io.files.create("ready", "replacement")
            self.assertTrue(path.is_symlink()) if fault == "symlink" else self.assertEqual(path.read_text(), "foreign")
            if fault != "staging":
                self.assertFalse((root / ".ready-next").exists())

    def test_staging_cleanup_requires_positive_identity_and_safe_shape(self):
        for fault in ("own", "replaced", "hardlinked", "symlink", "mode"):
            io = self.make()
            root = Path(io.root)
            staging = root / ".ready-next"
            write = io.files._write
            def fail(fd, data):
                write(fd, data)
                if fault == "replaced":
                    staging.rename(root / "retained-original")
                    staging.write_text("foreign")
                elif fault == "hardlinked":
                    os.link(staging, root / "other")
                elif fault == "symlink":
                    staging.rename(root / "retained-original")
                    staging.symlink_to("retained-original")
                elif fault == "mode":
                    staging.chmod(0o644)
                raise OSError("injected")
            with patch.object(io.files, "_write", side_effect=fail), self.assertRaises(OSError):
                io.files.create("ready", "record")
            self.assertFalse((root / "ready").exists())
            self.assertEqual(staging.exists(), fault != "own")

    def test_claim_changed_staging_is_preserved_not_unlinked(self):
        io = self.make()
        root = Path(io.root)
        staging = root / ".ready-next"
        real_link = os.link
        def replace_stage(*args, **kwargs):
            real_link(*args, **kwargs)
            staging.rename(root / "retained")
            staging.write_text("foreign")
            staging.chmod(0o600)
        with patch.object(linux.os, "link", side_effect=replace_stage), self.assertRaises(g.GuardRefusal):
            io.files.create("ready", "original")
        self.assertEqual(staging.read_text(), "foreign")
        with self.assertRaises(g.GuardRefusal):
            io.files.read("ready")  # Unknown two-link claim is not tolerated.

    def test_controller_refuses_malformed_ready_without_waiting_or_renewing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp).resolve())
            files = linux.PrivateFiles(root)
            try:
                files.create("ready", "mismatched-identity")
            finally:
                files.close()
            args = SimpleNamespace(run_id=lease_tests.RUN, checkout="discover", source_commit="a" * 40,
                                   archive_sha256="b" * 64, archive="/fake", baseline=[])
            child = SimpleNamespace(pid=42, poll=lambda: None)
            with patch.object(linux, "prepare_run_root", return_value=root), \
                    patch.object(linux, "identity", return_value=123), \
                    patch.object(linux.subprocess, "Popen", return_value=child), \
                    patch.object(linux.PrivateFiles, "publish_lease") as renew, \
                    patch.object(linux.time, "sleep") as sleep:
                with self.assertRaisesRegex(g.GuardRefusal, "ready identity mismatch"):
                    linux.controller(args)
            renew.assert_not_called()
            sleep.assert_not_called()

    def test_stuck_publication_lock_has_finite_acquisition_bound(self):
        io = self.make()
        other = linux.PrivateFiles(io.root)
        self.addCleanup(other.close)
        with other._publication_lock(exclusive=True), patch.object(linux.time, "sleep") as sleep:
            with self.assertRaises(BlockingIOError):
                io.files.read("lease")
            self.assertEqual(sleep.call_count, 19)
        self.assertEqual(io.lease_age(), 1)


if __name__ == "__main__":
    unittest.main()
