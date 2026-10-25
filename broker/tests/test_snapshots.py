"""Temporary WAL snapshot/restore rehearsals; no service or real authority."""
import hashlib
import os
import tempfile
import unittest
import sqlite3
import time
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from broker import request_lifecycle as life
from broker import brokerctl
from broker.audit import AuditLog
from broker.identity import authenticate, hash_token
from broker.store import Store
from .support import make_ctx, seed_caller


class Snapshots(unittest.TestCase):
    def test_operator_commands_parse_and_remain_offline(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "source.db"
            store = Store(str(source))
            seed_caller(store, allow=["echo.say"])
            store.close()
            snapshot = Path(d) / "backup.db"
            restored = Path(d) / "restored.db"
            commands = [
                ["backup", "--db", str(source), "--destination", str(snapshot)],
                ["prune-payloads", "--db", str(source)],
                ["reconcile-offline", "--db", str(source), "--confirm-offline"],
                ["restore-new", "--snapshot", str(snapshot), "--destination", str(restored), "--confirm-offline"],
            ]
            for args in commands:
                with patch("sys.argv", ["brokerctl"] + args), redirect_stdout(io.StringIO()) as output:
                    brokerctl.main()
                self.assertIsInstance(json.loads(output.getvalue()), dict)
            state = Store(str(restored))
            try:
                self.assertIsNone(authenticate(state, "Bearer token-for-hermes"))
            finally:
                state.close()

    def test_publish_race_never_overwrites_competing_destination(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(str(Path(d) / "source.db"))
            destination = Path(d) / "racing.db"
            original_link = os.link
            def racing_link(source, target, **kwargs):
                destination.write_bytes(b"COMPETING FILE")
                destination.chmod(0o600)
                return original_link(source, target, **kwargs)
            try:
                with patch("broker.store.os.link", side_effect=racing_link), self.assertRaises(FileExistsError):
                    store.backup_to(destination)
                self.assertEqual(destination.read_bytes(), b"COMPETING FILE")
                self.assertEqual(list(Path(d).glob(".broker-snapshot-*")), [])
            finally:
                store.close()

    def test_newer_snapshot_refused_and_no_destination_published(self):
        with tempfile.TemporaryDirectory() as d:
            snapshot = Path(d) / "future.db"
            conn = sqlite3.connect(snapshot)
            conn.execute("PRAGMA user_version=99")
            conn.close()
            snapshot.chmod(0o600)
            before = snapshot.read_bytes()
            destination = Path(d) / "new.db"
            with self.assertRaises(ValueError):
                Store.restore_new(snapshot, destination, confirmed_offline=True)
            self.assertFalse(destination.exists())
            self.assertEqual(snapshot.read_bytes(), before)
            self.assertEqual(list(Path(d).glob(".broker-snapshot-*")), [])

    def test_populated_wal_backup_restore_new_revokes_authority_and_never_replays(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(catalog={"echo": {"say": "read", "review": "write"}})
            ctx.store.close()
            source = Path(d) / "source.db"
            ctx.store = Store(str(source))
            ctx.audit = AuditLog(ctx.store, sink=None)
            try:
                token = seed_caller(ctx.store, allow=["echo.say"], review=["echo.review"])
                caller = authenticate(ctx.store, f"Bearer {token}")
                completed = life.submit(ctx, caller, "echo", "say", {"fake": "value"}, "a", idempotency_key="done")
                pruned = life.submit(ctx, caller, "echo", "say", {"fake": "old"}, "old", idempotency_key="pruned")
                ctx.store._conn.execute("UPDATE requests SET updated_at=? WHERE id=?", (time.time() - 8*86400, pruned.request_id))
                ctx.store._conn.commit()
                self.assertEqual(ctx.store.prune_payloads(), 1)
                pending = life.submit(ctx, caller, "echo", "review", {"fake": "sensitive"}, "b", idempotency_key="pending")
                op = ctx.registry.lookup("echo", "say")
                active, _, _ = ctx.store.reserve_action(caller, "c", "echo", "say", {}, None, op.generation, "active")
                self.assertTrue(ctx.store.claim_received(active["id"], op.generation, caller, active["request_digest"]))
                self.assertGreater(Path(str(source) + "-wal").stat().st_size, 0)
                namespace = ctx.store.installation_id
                snapshot = Path(d) / "snapshots" / "backup.db"
                ctx.store.backup_to(snapshot)
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                self.assertEqual(snapshot.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(snapshot.stat().st_nlink, 1)
                snapshot_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()
            finally:
                ctx.store.close()  # operator-exclusive restore: original writers stopped
            restored = Path(d) / "restored" / "new.db"
            with self.assertRaises(ValueError):
                Store.restore_new(snapshot, restored)
            self.assertFalse(restored.exists())
            self.assertFalse(restored.parent.exists())
            Store.restore_new(snapshot, restored, confirmed_offline=True)
            self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(), snapshot_hash)
            ctx.store = Store(str(restored))
            ctx.audit = AuditLog(ctx.store, sink=None)
            try:
                self.assertIsNone(authenticate(ctx.store, f"Bearer {token}"))
                self.assertEqual(ctx.store.policy_for(caller.id), {})
                self.assertNotEqual(ctx.store.installation_id, namespace)
                self.assertEqual(ctx.store.request(pending.request_id)["status"], "expired")
                self.assertEqual(ctx.store.approval_for_request(pending.request_id)["status"], "cancelled")
                self.assertIsNone(ctx.store.request(pending.request_id)["action_json"])
                self.assertEqual(ctx.store.request(active["id"])["status"], "unknown")
                self.assertEqual(ctx.store.request(completed.request_id)["result_json"], '{"echoed": {"fake": "value"}}')
                # Explicit new authority after review, never inherited on restore.
                ctx.store.add_token(caller.id, hash_token("new-fake-token"))
                ctx.store.set_policy(caller.id, {"tools": {"echo": {"say": "allow", "review": "review"}}})
                renewed = authenticate(ctx.store, "Bearer new-fake-token")
                self.assertEqual(life.submit(ctx, renewed, "echo", "say", {}, "d", idempotency_key="active").status, life.UNKNOWN)
                self.assertEqual(life.submit(ctx, renewed, "echo", "review", {"fake": "sensitive"}, "e", idempotency_key="pending").status, life.EXPIRED)
                repeat = life.submit(ctx, renewed, "echo", "say", {"fake": "value"}, "f", idempotency_key="done")
                self.assertEqual((repeat.request_id, repeat.result), (completed.request_id, completed.result))
                self.assertEqual(life.submit(ctx, renewed, "echo", "say", {"fake": "old"}, "g", idempotency_key="pruned").status, life.RESULT_EXPIRED)
                self.assertEqual(life.submit(ctx, renewed, "echo", "say", {"fake": "new"}, "h", idempotency_key="pruned").status, life.CONFLICT)
                self.assertEqual(len(ctx.runtime.calls), 2)  # original completed effects only
            finally:
                ctx.store.close()

    def test_existing_file_symlink_hardlink_and_unsafe_destinations_refused_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(str(Path(d) / "source.db"))
            try:
                snapshot = Path(d) / "snapshot.db"
                store.backup_to(snapshot)
                target = Path(d) / "existing.db"
                target.write_bytes(b"DO NOT CHANGE")
                target.chmod(0o640)
                symlink = Path(d) / "linked.db"
                symlink.symlink_to(target)
                hardlink = Path(d) / "hardlinked.db"
                os.link(target, hardlink)
                for destination in (target, symlink, hardlink):
                    before = target.read_bytes(), target.stat().st_mode, target.stat().st_mtime_ns
                    with self.assertRaises(FileExistsError):
                        store.backup_to(destination)
                    with self.assertRaises(FileExistsError):
                        Store.restore_new(snapshot, destination, confirmed_offline=True)
                    self.assertEqual((target.read_bytes(), target.stat().st_mode, target.stat().st_mtime_ns), before)
                unsafe = Path(d) / "shared"
                unsafe.mkdir(mode=0o755)
                unsafe.chmod(0o755)  # fixture must remain unsafe even under umask077
                self.assertEqual(unsafe.stat().st_mode & 0o777, 0o755)
                with self.assertRaises(ValueError):
                    store.backup_to(unsafe / "new.db")
                with self.assertRaises(ValueError):
                    Store.restore_new(snapshot, unsafe / "new.db", confirmed_offline=True)
                self.assertEqual(unsafe.stat().st_mode & 0o777, 0o755)
                self.assertFalse((unsafe / "new.db").exists())
                writable = Path(d) / "writable"
                writable.mkdir()
                writable.chmod(0o777)
                with self.assertRaises(ValueError):
                    store.backup_to(writable / "missing" / "new.db")
                self.assertFalse((writable / "missing").exists())
                self.assertEqual(list(Path(d).glob(".broker-snapshot-*")), [])
            finally:
                store.close()
