"""SQLite persistence for the broker: the store behind every module.

The broker holds one long-lived connection (``check_same_thread=False``; the dev
server is single-threaded). The admin web app opens its own short-lived
connections to the same file. WAL mode plus a busy timeout (set in ``__init__``)
let those coexist safely: many readers and a single writer at a time. Tests pass
``":memory:"`` (WAL is skipped there).

Tables: callers, tokens (hashed), caller_policies, requests, approvals, audit_events.
Arguments/private action bindings exist while received/pending/executing and are
cleared at terminal states. Results are manually prunable after seven days.
Caller/key/payload-digest tombstones stay to forbid replay; values never enter audit.
"""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
import tempfile
from urllib.parse import quote
import sqlite3
import time
from pathlib import Path

from .identity import Caller

SCHEMA = """
CREATE TABLE IF NOT EXISTS broker_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS callers (
    id         INTEGER PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    created_at REAL NOT NULL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    caller_id  INTEGER NOT NULL REFERENCES callers(id),
    created_at REAL NOT NULL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS caller_policies (
    caller_id   INTEGER PRIMARY KEY REFERENCES callers(id),
    policy_json TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id             INTEGER PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    caller_id      INTEGER NOT NULL REFERENCES callers(id),
    tool           TEXT NOT NULL,
    op             TEXT NOT NULL,
    status         TEXT NOT NULL,
    arguments_json TEXT,            -- kept only while pending approval, then cleared
    result_json    TEXT,            -- the tool result, once completed
    error          TEXT,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id          INTEGER PRIMARY KEY,
    request_id  INTEGER NOT NULL REFERENCES requests(id),
    surface_ref TEXT NOT NULL,
    status      TEXT NOT NULL,      -- pending / approved / rejected / expired / cancelled
    expires_at  REAL NOT NULL,
    approver    TEXT,
    note        TEXT,
    decided_at  TEXT,               -- ISO 8601 from the surface (when the human answered)
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    id             INTEGER PRIMARY KEY,
    at             REAL NOT NULL,
    component      TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    correlation_id TEXT,
    request_id     INTEGER,
    details_json   TEXT NOT NULL
);
"""


def default_db_path() -> str:
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return str(Path(state) / "toolstack" / "broker" / "broker.sqlite3")


def _private_parent(path, create=True):
    parent_path = Path(path).parent
    for ancestor in parent_path.resolve().parents:
        try:
            info = ancestor.stat()
        except FileNotFoundError:
            continue
        sticky_system_tmp = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky_system_tmp):
            raise ValueError("database parent has an unsafe writable ancestor")
    if create:
        parent_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = parent_path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077):
        raise ValueError("database parent must be an owned private directory (0700)")
    return parent_path


class Store:
    def __init__(self, db_path: str | None = None) -> None:
        path = db_path or default_db_path()
        if path != ":memory:":
            _private_parent(path)
            # Precreate privately so SQLite's WAL/SHM inherit 0600, independent
            # of ambient umask. Reject links; same-owner attackers are not isolated.
            for candidate in (path, path + "-wal", path + "-shm", path + "-journal"):
                if candidate != path and not os.path.lexists(candidate):
                    continue
                fd = os.open(candidate, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                        raise ValueError("database state must be a regular file owned by this user")
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        # WAL lets the broker's long-lived connection and the admin app's
        # short-lived connections share this file (one writer + many readers)
        # without "database is locked"; busy_timeout serializes the rare write
        # collision. WAL does not apply to an in-memory DB (used in tests).
        self._conn.execute("PRAGMA busy_timeout = 5000")
        try:
            # Serialize schema inspection and DDL across broker/admin startup.
            # executescript implicitly commits, so execute each static statement.
            self._conn.execute("BEGIN IMMEDIATE")
            if self._conn.execute("PRAGMA user_version").fetchone()[0] > 3:
                raise ValueError("database schema is newer than this broker supports")
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    self._conn.execute(statement)
            columns = {r[1] for r in self._conn.execute("PRAGMA table_info(requests)")}
            for name in ("operation_generation", "policy_binding", "action_json", "request_digest", "idempotency_key", "payload_digest", "pruned_at"):
                if name not in columns:
                    kind = "REAL" if name == "pruned_at" else "TEXT"
                    self._conn.execute(f"ALTER TABLE requests ADD COLUMN {name} {kind}")
            approval_columns = {r[1] for r in self._conn.execute("PRAGMA table_info(approvals)")}
            if "request_digest" not in approval_columns:
                self._conn.execute("ALTER TABLE approvals ADD COLUMN request_digest TEXT")
            self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS requests_caller_key ON requests(caller_id,idempotency_key) WHERE idempotency_key IS NOT NULL")
            self._conn.execute("INSERT OR IGNORE INTO broker_metadata(key,value) VALUES ('installation_uuid',?)", (str(uuid.uuid4()),))
            self._conn.execute("PRAGMA user_version = 3")
            self._conn.commit()
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
        except BaseException:
            self._conn.rollback()
            self._conn.close()
            raise

    # --- callers & tokens ---------------------------------------------------

    def set_catalog_receipt(self, receipt: dict | None) -> None:
        with self._conn:
            self._conn.execute("INSERT OR REPLACE INTO broker_metadata(key,value) VALUES (?,?)",
                               ("catalog_receipt", json.dumps(receipt)))

    def catalog_receipt(self) -> dict | None:
        row = self._conn.execute("SELECT value FROM broker_metadata WHERE key=?",
                                 ("catalog_receipt",)).fetchone()
        return json.loads(row[0]) if row else None

    @property
    def installation_id(self) -> str:
        value = self._conn.execute("SELECT value FROM broker_metadata WHERE key='installation_uuid'").fetchone()[0]
        return str(uuid.UUID(value))

    def add_caller(self, name: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO callers (name, created_at) VALUES (?, ?)", (name, time.time())
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def revoke_caller(self, name: str) -> None:
        self._conn.execute(
            "UPDATE callers SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL",
            (time.time(), name),
        )
        self._conn.commit()

    def add_token(self, caller_id: int, token_hash: str) -> None:
        self._conn.execute(
            "INSERT INTO tokens (token_hash, caller_id, created_at) VALUES (?, ?, ?)",
            (token_hash, caller_id, time.time()),
        )
        self._conn.commit()

    def revoke_token(self, token_hash: str) -> None:
        self._conn.execute(
            "UPDATE tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (time.time(), token_hash),
        )
        self._conn.commit()

    def revoke_tokens_for_caller(self, caller_id: int, except_hash: str | None = None) -> int:
        """Revoke every active token for a caller, optionally sparing one hash. Used to
        rotate a caller down to a single active token. Returns how many were revoked."""
        sql = "UPDATE tokens SET revoked_at = ? WHERE caller_id = ? AND revoked_at IS NULL"
        params: list = [time.time(), caller_id]
        if except_hash is not None:
            sql += " AND token_hash != ?"
            params.append(except_hash)
        cur = self._conn.execute(sql, params)
        self._conn.commit()
        return cur.rowcount

    def caller_by_token_hash(self, token_hash: str) -> Caller | None:
        """Resolve a live caller from a token hash. Revoked tokens or revoked
        callers return None, so revocation takes effect on the next request."""
        row = self._conn.execute(
            """
            SELECT c.id AS id, c.name AS name
            FROM tokens t JOIN callers c ON c.id = t.caller_id
            WHERE t.token_hash = ? AND t.revoked_at IS NULL AND c.revoked_at IS NULL
            """,
            (token_hash,),
        ).fetchone()
        return Caller(id=row["id"], name=row["name"], token_hash=token_hash) if row else None

    # --- policy -------------------------------------------------------------

    def set_policy(self, caller_id: int, policy: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO caller_policies (caller_id, policy_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(caller_id) DO UPDATE SET policy_json = excluded.policy_json,
                                                 updated_at = excluded.updated_at
            """,
            (caller_id, json.dumps(policy), time.time()),
        )
        self._conn.execute("UPDATE approvals SET status='cancelled' WHERE status='pending' AND request_id IN (SELECT id FROM requests WHERE caller_id=? AND status='pending_approval')", (caller_id,))
        self._conn.execute("UPDATE requests SET status='denied', error='approval_invalidated', arguments_json=NULL, action_json=NULL,updated_at=? WHERE caller_id=? AND status='pending_approval'", (time.time(), caller_id))
        self._conn.commit()

    def policy_for(self, caller_id: int) -> dict:
        row = self._conn.execute(
            "SELECT policy_json FROM caller_policies WHERE caller_id = ?", (caller_id,)
        ).fetchone()
        return json.loads(row["policy_json"]) if row else {}  # no policy -> deny all

    # --- requests -----------------------------------------------------------

    def create_request(
        self, correlation_id: str, caller_id: int, tool: str, op: str, status: str
    ) -> int:
        now = time.time()
        cur = self._conn.execute(
            """
            INSERT INTO requests (correlation_id, caller_id, tool, op, status,
                                  created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (correlation_id, caller_id, tool, op, status, now, now),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def request(self, request_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()

    def update_request(self, request_id: int, **fields) -> None:
        """Update whitelisted request columns. Column names come from a fixed
        allowlist (never user input), so the f-string is safe."""
        if fields.get("status") in {"completed", "denied", "expired", "failed", "unknown", "result_expired", "not_found", "invalid"}:
            fields["action_json"] = None
            fields["arguments_json"] = None
        allowed = ("status", "arguments_json", "result_json", "error", "operation_generation", "policy_binding", "action_json", "request_digest")
        cols = [c for c in fields if c in allowed]
        if not cols:
            return
        assignments = ", ".join(f"{c} = ?" for c in cols)
        values = [fields[c] for c in cols] + [time.time(), request_id]
        self._conn.execute(
            f"UPDATE requests SET {assignments}, updated_at = ? WHERE id = ?", values
        )
        self._conn.commit()

    def caller_name(self, caller_id: int) -> str | None:
        row = self._conn.execute(
            "SELECT name FROM callers WHERE id = ?", (caller_id,)
        ).fetchone()
        return row["name"] if row else None

    def _live(self, caller_id, caller=None):
        row = self._conn.execute("SELECT revoked_at FROM callers WHERE id=?", (caller_id,)).fetchone()
        if row is None or row[0] is not None or (caller is not None and caller.id != caller_id):
            return False
        if caller is not None and caller.token_hash is not None:
            return self._conn.execute("SELECT 1 FROM tokens WHERE caller_id=? AND token_hash=? AND revoked_at IS NULL",
                                      (caller_id, caller.token_hash)).fetchone() is not None
        return self.active_token_count(caller_id) > 0

    @staticmethod
    def _bound(req, generation):
        from .approval_summary import bound_request, canonical
        try:
            action = json.loads(req["action_json"] or "null")
            if not isinstance(action, dict):
                return False
            expected, digest = bound_request(req["caller_id"], req["tool"], req["op"], generation,
                                             action.get("arguments"), action.get("reason"), action.get("nonce"))
            return (canonical(action) == expected and digest == req["request_digest"]
                    and canonical(action.get("arguments")) == canonical(json.loads(req["arguments_json"] or "null")))
        except (ValueError, TypeError):
            return False

    def authorized_request(self, caller, request_id):
        """Read receipt and current authority in one snapshot; no network work."""
        from .policy import decide, DENY
        self._conn.execute("BEGIN")
        try:
            req = self.request(request_id)
            allowed = (req is not None and req["caller_id"] == caller.id and self._live(caller.id, caller)
                       and decide(self.policy_for(caller.id), req["tool"], req["op"]) != DENY)
            self._conn.commit()
            return req if allowed else None
        except BaseException:
            self._conn.rollback()
            raise

    def reserve_action(self, caller, correlation_id, tool, op, arguments, reason, generation, key=None):
        """Return (request, created, conflict); only creator may advance received.

        Private payload digest excludes generation: matching retries after a
        catalog reload still refer to the original receipt, never a new effect.
        """
        import hashlib
        from .approval_summary import canonical, bound_request
        from .policy import decide, DENY
        self.validate_idempotency_key(key)
        payload = canonical({"tool": tool, "op": op, "arguments": arguments, "reason": reason})
        digest = hashlib.sha256(payload.encode()).hexdigest()
        action, binding = bound_request(caller.id, tool, op, generation, arguments, reason)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not self._live(caller.id, caller):
                raise PermissionError("authority revoked")
            policy = self.policy_for(caller.id)
            prior = self._conn.execute("SELECT * FROM requests WHERE caller_id=? AND idempotency_key=?", (caller.id, key)).fetchone() if key is not None else None
            if prior is not None:
                if decide(policy, prior["tool"], prior["op"]) == DENY:
                    raise PermissionError("authority revoked")
                self._conn.commit()
                return prior, False, prior["payload_digest"] != digest
            now = time.time()
            cur = self._conn.execute("INSERT INTO requests(correlation_id,caller_id,tool,op,status,created_at,updated_at,arguments_json,operation_generation,policy_binding,action_json,request_digest,idempotency_key,payload_digest) VALUES (?,?,?,?,'received',?,?,?,?,?,?,?,?,?)",
                (correlation_id, caller.id, tool, op, now, now, canonical(arguments), generation,
                 json.dumps(policy, sort_keys=True), action, binding, key, digest))
            req = self.request(cur.lastrowid)
            self._conn.commit()
            return req, True, False
        except BaseException:
            self._conn.rollback()
            raise

    @staticmethod
    def validate_idempotency_key(key):
        if key is not None and (not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", key)):
            raise ValueError("invalid idempotency key")
        return key

    def claim_received(self, request_id, generation, caller, expected_digest):
        from .policy import decide, ALLOW
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            req = self.request(request_id)
            valid = (req is not None and req["status"] == "received"
                     and self._live(req["caller_id"], caller) and generation
                     and req["operation_generation"] == generation
                     and req["request_digest"] == expected_digest and self._bound(req, generation))
            if valid:
                policy = self.policy_for(req["caller_id"])
                valid = (json.dumps(policy, sort_keys=True) == req["policy_binding"]
                         and decide(policy, req["tool"], req["op"]) == ALLOW)
            if valid:
                self._conn.execute("UPDATE requests SET status='executing', updated_at=? WHERE id=? AND status='received'", (time.time(), request_id))
            elif req is not None and req["status"] == "received":
                self._conn.execute("UPDATE requests SET status='denied', error='authority_changed', arguments_json=NULL,action_json=NULL,updated_at=? WHERE id=?", (time.time(), request_id))
            self._conn.commit()
            return bool(valid)
        except BaseException:
            self._conn.rollback()
            raise

    def claim_approval(self, request_id, generation, state, now, caller=None) -> bool:
        """Commit point: revocation/cancellation wins until this transaction claims.

        No network I/O inside the write transaction. Once running, cancellation
        cannot promise to undo a tool effect. Never replay running rows on restart.
        """
        from .policy import decide, REVIEW
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            req = self.request(request_id)
            app = self.approval_for_request(request_id)
            valid = (req is not None and app is not None
                     and req["status"] == "pending_approval" and app["status"] == "pending"
                     and app["expires_at"] > now
                     and self._live(req["caller_id"], caller)
                     and generation and req["operation_generation"] == generation
                     and req["request_digest"] and req["request_digest"] == app["request_digest"])
            if valid:
                valid = self._bound(req, generation)
            if valid:
                policy = self.policy_for(req["caller_id"])
                valid = (req["policy_binding"] == json.dumps(policy, sort_keys=True)
                         and decide(policy, req["tool"], req["op"]) == REVIEW)
            if not valid:
                # Never overwrite a concurrent terminal/cancelled transition.
                if req and req["status"] == "pending_approval":
                    expired = app is not None and app["status"] == "pending" and app["expires_at"] <= now
                    self._conn.execute("UPDATE requests SET status=?, error=?, arguments_json=NULL, action_json=NULL, updated_at=? WHERE id=?",
                                       ("expired" if expired else "denied", None if expired else "approval_invalidated", now, request_id))
                    self._conn.execute("UPDATE approvals SET status=? WHERE request_id=? AND status='pending'",
                                       ("expired" if expired else "cancelled", request_id))
                self._conn.commit()
                return False
            self._conn.execute("UPDATE requests SET status='executing', updated_at=? WHERE id=?", (now, request_id))
            self._conn.execute("UPDATE approvals SET status='approved', approver=?, note=?, decided_at=? WHERE id=?",
                               (state.approver, state.note, state.decided_at, app["id"]))
            self._conn.commit()
            return True
        except BaseException:
            self._conn.rollback()
            raise

    def finish_pending(self, request_id, status, approval_status, *, error=None,
                       state=None, now=None, deadline_only=False) -> bool:
        """Conditionally finish both rows; stale polls/sweeps cannot undo a claim.

        Used by all pending terminal paths, including out-of-process revocation.
        The approved/running commit point wins over later cancellation attempts.
        """
        now = time.time() if now is None else now
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            req = self.request(request_id)
            app = self.approval_for_request(request_id)
            if (req is None or app is None or req["status"] != "pending_approval"
                    or app["status"] != "pending"
                    or (deadline_only and app["expires_at"] > now)):
                self._conn.commit()
                return False
            # Broker deadline wins over any delayed human rejection/cancellation.
            if now >= app["expires_at"]:
                status, approval_status, error = "expired", "expired", None
            elif (self._conn.execute("SELECT revoked_at FROM callers WHERE id=?", (req["caller_id"],)).fetchone()[0] is not None
                  or self.active_token_count(req["caller_id"]) == 0):
                status, approval_status, error = "expired", "cancelled", None
            self._conn.execute("UPDATE requests SET status=?, error=?, arguments_json=NULL, action_json=NULL, updated_at=? WHERE id=?",
                               (status, error, now, request_id))
            self._conn.execute("UPDATE approvals SET status=?, approver=?, note=?, decided_at=? WHERE id=?",
                               (approval_status, state.approver if state else None,
                                state.note if state else None, state.decided_at if state else None, app["id"]))
            self._conn.commit()
            return True
        except BaseException:
            self._conn.rollback()
            raise

    def reconcile_offline(self, *, confirmed_offline=False):
        """Explicit operator assertion all brokers/writers stopped; never replay."""
        if not confirmed_offline:
            raise ValueError("stop all writers and explicitly confirm offline reconciliation")
        with self._conn:
            cur = self._conn.execute("UPDATE requests SET status='unknown',error='offline_reconciled',arguments_json=NULL,action_json=NULL,result_json=NULL,updated_at=? WHERE status IN ('received','executing','running')", (time.time(),))
        return cur.rowcount

    def prune_payloads(self, now=None):
        """Manual seven-day pruning; immutable caller/key/digest tombstones stay."""
        now = time.time() if now is None else now
        with self._conn:
            self._conn.execute("UPDATE approvals SET note=NULL WHERE request_id IN (SELECT id FROM requests WHERE updated_at < ? AND pruned_at IS NULL AND status IN ('completed','denied','expired','failed','unknown','result_expired','not_found','invalid'))", (now - 7 * 86400,))
            cur = self._conn.execute("UPDATE requests SET status=CASE WHEN status='completed' THEN 'result_expired' ELSE status END,arguments_json=NULL,action_json=NULL,result_json=NULL,pruned_at=? WHERE updated_at < ? AND pruned_at IS NULL AND status IN ('completed','denied','expired','failed','unknown','result_expired','not_found','invalid')", (now, now - 7 * 86400))
        return cur.rowcount

    def backup_to(self, destination):
        """SQLite snapshot includes committed WAL; new private destination ONLY."""
        return self._snapshot_new(self._conn, destination)

    @staticmethod
    def _snapshot_new(source, destination, transform=None):
        destination = str(destination)
        parent = _private_parent(destination)
        if os.path.lexists(destination):
            raise FileExistsError("destination already exists; never overwrite state")
        fd, stage = tempfile.mkstemp(prefix=".broker-snapshot-", dir=parent)
        os.fchmod(fd, 0o600)
        os.close(fd)
        try:
            target = sqlite3.connect(stage)
            try:
                deadline = time.monotonic() + 30
                def progress(status, remaining, total):
                    if time.monotonic() > deadline:
                        raise TimeoutError("SQLite snapshot deadline exceeded")
                source.backup(target, pages=128, progress=progress, sleep=0.01)
                target.execute("PRAGMA journal_mode=DELETE")
                target.commit()
            finally:
                target.close()
            if transform is not None:
                transform(stage)
            fd = os.open(stage, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            # Atomic no-clobber publication. An existing/link/hardlink/racing
            # destination is refused by the kernel, never truncated or chmodded.
            os.link(stage, destination, follow_symlinks=False)
            return destination
        finally:
            for suffix in ("", "-wal", "-shm", "-journal"):
                Path(stage + suffix).unlink(missing_ok=True)  # only our unique stage

    @classmethod
    def restore_new(cls, snapshot, destination, *, confirmed_offline=False):
        """Operator-exclusive restore to NEW destination; no execution or replay.

        Caller must stop all writers. This is an explicit operator assertion,
        not guessed PID ownership or isolation against arbitrary same-owner code.
        """
        if not confirmed_offline:
            raise ValueError("stop all writers and explicitly confirm offline restore")
        _private_parent(destination)
        if os.path.lexists(destination):
            raise FileExistsError("restore destination exists; never overwrite state")
        _private_parent(snapshot, create=False)
        info = Path(snapshot).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError("snapshot must be a private owned regular file, not a link")
        def sanitize(stage):
            store = cls(stage)
            try:
                now = time.time()
                store._conn.execute("BEGIN IMMEDIATE")
                store._conn.execute("UPDATE approvals SET status='cancelled',note=NULL WHERE status='pending'")
                store._conn.execute("UPDATE requests SET status='expired',error='restore_cancelled',arguments_json=NULL,action_json=NULL,result_json=NULL,updated_at=? WHERE status='pending_approval'", (now,))
                store._conn.execute("UPDATE requests SET status='unknown',error='restore_unknown',arguments_json=NULL,action_json=NULL,result_json=NULL,updated_at=? WHERE status IN ('received','executing','running')", (now,))
                store._conn.execute("UPDATE tokens SET revoked_at=? WHERE revoked_at IS NULL", (now,))
                store._conn.execute("UPDATE caller_policies SET policy_json='{}',updated_at=?", (now,))
                store._conn.execute("UPDATE broker_metadata SET value=? WHERE key='installation_uuid'", (str(uuid.uuid4()),))
                store._conn.commit()
                store.append_audit(now, "admin", "restored_offline", "ok", None, None,
                                   {"tokens_invalidated": True, "policies_cleared": True, "replayed": 0})
                store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                store._conn.execute("PRAGMA journal_mode=DELETE")
            finally:
                store.close()
        source = sqlite3.connect(f"file:{quote(str(Path(snapshot).absolute()), safe='/')}?mode=ro", uri=True)
        try:
            return cls._snapshot_new(source, destination, transform=sanitize)
        finally:
            source.close()

    # --- approvals ----------------------------------------------------------

    def create_approval(self, request_id: int, surface_ref: str, expires_at: float, request_digest=None) -> int:
        cur = self._conn.execute(
            "INSERT INTO approvals (request_id, surface_ref, status, expires_at, created_at, request_digest) "
            "VALUES (?, ?, 'pending', ?, ?, ?)",
            (request_id, surface_ref, expires_at, time.time(), request_digest),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def approval_for_request(self, request_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM approvals WHERE request_id = ?", (request_id,)
        ).fetchone()

    def pending_approvals_for_caller(self, caller_id: int) -> list[sqlite3.Row]:
        """Pending approvals (with their request's tool/op/correlation) owned by a
        caller, the worklist for cancelling on caller/last-token revocation."""
        return self._conn.execute(
            """
            SELECT a.id AS id, a.surface_ref AS surface_ref, a.request_id AS request_id,
                   r.tool AS tool, r.op AS op, r.correlation_id AS correlation_id
            FROM approvals a JOIN requests r ON r.id = a.request_id
            WHERE r.caller_id = ? AND a.status = 'pending'
            """,
            (caller_id,),
        ).fetchall()

    def expired_pending_approvals(self, now: float) -> list[sqlite3.Row]:
        """Pending approvals past their broker deadline, the lazy sweep's worklist.
        (Same row shape as :meth:`pending_approvals_for_caller`.)"""
        return self._conn.execute(
            """
            SELECT a.id AS id, a.surface_ref AS surface_ref, a.request_id AS request_id,
                   r.tool AS tool, r.op AS op, r.correlation_id AS correlation_id
            FROM approvals a JOIN requests r ON r.id = a.request_id
            WHERE a.status = 'pending' AND a.expires_at <= ?
            """,
            (now,),
        ).fetchall()

    def update_approval(self, approval_id: int, **fields) -> None:
        allowed = ("status", "approver", "note", "decided_at")
        cols = [c for c in fields if c in allowed]
        if not cols:
            return
        assignments = ", ".join(f"{c} = ?" for c in cols)
        self._conn.execute(
            f"UPDATE approvals SET {assignments} WHERE id = ?",
            [fields[c] for c in cols] + [approval_id],
        )
        self._conn.commit()

    # --- audit --------------------------------------------------------------

    def append_audit(
        self,
        at: float,
        component: str,
        event_type: str,
        outcome: str,
        correlation_id: str,
        request_id: int | None,
        details: dict,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO audit_events (at, component, event_type, outcome,
                                      correlation_id, request_id, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (at, component, event_type, outcome, correlation_id, request_id,
             json.dumps(details)),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def audit_events(self, request_id=None, correlation_id=None) -> list[dict]:
        """Chronological audit events, optionally filtered to one request or
        correlation id (the spine of the four audit questions)."""
        clauses, params = [], []
        if request_id is not None:
            clauses.append("request_id = ?")
            params.append(request_id)
        if correlation_id is not None:
            clauses.append("correlation_id = ?")
            params.append(correlation_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM audit_events{where} ORDER BY id", params
        ).fetchall()
        return [self._audit_row(r) for r in rows]

    def recent_audit(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._audit_row(r) for r in reversed(rows)]

    def clear_audit(self) -> None:
        self._conn.execute("DELETE FROM audit_events")
        self._conn.commit()

    @staticmethod
    def _audit_row(row) -> dict:
        event = dict(row)
        event["details"] = json.loads(event.pop("details_json"))
        return event

    # --- operator queries (brokerctl) ---------------------------------------

    def caller_by_name(self, name: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM callers WHERE name = ?", (name,)
        ).fetchone()

    def list_callers(self, include_revoked: bool = False) -> list[sqlite3.Row]:
        where = "" if include_revoked else " WHERE revoked_at IS NULL"
        return self._conn.execute(
            f"SELECT * FROM callers{where} ORDER BY id"
        ).fetchall()

    def list_tokens(self, include_revoked: bool = False) -> list[sqlite3.Row]:
        where = "" if include_revoked else " WHERE t.revoked_at IS NULL"
        return self._conn.execute(
            "SELECT t.token_hash AS token_hash, c.name AS caller, t.created_at AS created_at, "
            f"t.revoked_at AS revoked_at FROM tokens t JOIN callers c ON c.id = t.caller_id{where} "
            "ORDER BY t.created_at"
        ).fetchall()

    def revoke_token_by_prefix(self, prefix: str) -> int:
        self._validate_token_prefix(prefix)
        cur = self._conn.execute(
            "UPDATE tokens SET revoked_at = ? WHERE token_hash LIKE ? AND revoked_at IS NULL",
            (time.time(), prefix + "%"),
        )
        self._conn.commit()
        return cur.rowcount

    def caller_ids_for_token_prefix(self, prefix: str) -> list[int]:
        """Distinct caller ids owning any token matching ``prefix`` (revoked or not).
        Used after a token revocation to find which callers may now be tokenless."""
        self._validate_token_prefix(prefix)
        rows = self._conn.execute(
            "SELECT DISTINCT caller_id FROM tokens WHERE token_hash LIKE ?", (prefix + "%",)
        ).fetchall()
        return [r["caller_id"] for r in rows]

    @staticmethod
    def _validate_token_prefix(prefix: str) -> None:
        if not isinstance(prefix, str) or not re.fullmatch(r"[0-9a-f]{12,64}", prefix):
            raise ValueError("token prefix must be 12–64 lowercase hexadecimal characters")

    def active_token_count(self, caller_id: int) -> int:
        """How many non-revoked tokens a caller still has."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM tokens WHERE caller_id = ? AND revoked_at IS NULL",
            (caller_id,),
        ).fetchone()
        return int(row["n"])

    def list_requests(self, status: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
        if status:
            return self._conn.execute(
                "SELECT * FROM requests WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def close(self) -> None:
        self._conn.close()
