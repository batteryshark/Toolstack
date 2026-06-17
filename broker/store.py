"""SQLite persistence for the broker — the store behind every module.

The broker holds one long-lived connection (``check_same_thread=False``; the dev
server is single-threaded). The admin web app opens its own short-lived
connections to the same file. WAL mode plus a busy timeout (set in ``__init__``)
let those coexist safely — many readers and a single writer at a time. Tests pass
``":memory:"`` (WAL is skipped there).

Tables: callers, tokens (hashed), caller_policies, requests, approvals, audit_events.
A request's arguments/results are stored only transiently — arguments while it is
pending approval (needed to run it after approval), the result on completion — and
arguments are cleared at any terminal state. They are never written to audit.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from .identity import Caller

SCHEMA = """
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
    decided_at  REAL,
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


class Store:
    def __init__(self, db_path: str | None = None) -> None:
        path = db_path or default_db_path()
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        # WAL lets the broker's long-lived connection and the admin app's
        # short-lived connections share this file (one writer + many readers)
        # without "database is locked"; busy_timeout serializes the rare write
        # collision. WAL does not apply to an in-memory DB (used in tests).
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # --- callers & tokens ---------------------------------------------------

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
        return Caller(id=row["id"], name=row["name"]) if row else None

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
        allowed = ("status", "arguments_json", "result_json", "error")
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

    # --- approvals ----------------------------------------------------------

    def create_approval(self, request_id: int, surface_ref: str, expires_at: float) -> int:
        cur = self._conn.execute(
            "INSERT INTO approvals (request_id, surface_ref, status, expires_at, created_at) "
            "VALUES (?, ?, 'pending', ?, ?)",
            (request_id, surface_ref, expires_at, time.time()),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def approval_for_request(self, request_id: int) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM approvals WHERE request_id = ?", (request_id,)
        ).fetchone()

    def pending_approvals_for_caller(self, caller_id: int) -> list[sqlite3.Row]:
        """Pending approvals (with their request's tool/op/correlation) owned by a
        caller — the worklist for cancelling on caller/last-token revocation."""
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
        """Pending approvals past their broker deadline — the lazy sweep's worklist.
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
        cur = self._conn.execute(
            "UPDATE tokens SET revoked_at = ? WHERE token_hash LIKE ? AND revoked_at IS NULL",
            (time.time(), prefix + "%"),
        )
        self._conn.commit()
        return cur.rowcount

    def caller_ids_for_token_prefix(self, prefix: str) -> list[int]:
        """Distinct caller ids owning any token matching ``prefix`` (revoked or not).
        Used after a token revocation to find which callers may now be tokenless."""
        rows = self._conn.execute(
            "SELECT DISTINCT caller_id FROM tokens WHERE token_hash LIKE ?", (prefix + "%",)
        ).fetchall()
        return [r["caller_id"] for r in rows]

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
