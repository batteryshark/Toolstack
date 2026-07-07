"""brokerctl: the operator CLI for the broker.

Manage callers, policies, and tokens; inspect requests and audit. The mutations
themselves live in :mod:`broker.operations` (shared with the admin web app), so
this module is a thin CLI shell over them; mutating actions are recorded as
``admin.*`` audit events there. Per the trust model the operator works on the
broker host with direct DB access, so there is no networked admin surface to
secure.

    brokerctl create-caller --name hermes --allow echo.say --review echo.skip
    brokerctl list-callers
    brokerctl set-policy --name hermes --allow echo.say
    brokerctl show-policy --name hermes
    brokerctl issue-token --name hermes
    brokerctl revoke-token --prefix 1a2b3c
    brokerctl revoke-caller --name hermes
    brokerctl sweep
    brokerctl list-requests [--status pending_approval]
    brokerctl audit [--request-id N | --correlation-id C | --limit 50]
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
from pathlib import Path

from . import operations, request_lifecycle
from .audit import AuditLog, stderr_sink
from .context import BrokerContext
from .store import Store
from .surface_nod import NodSurface


def _store(args) -> Store:
    return Store(args.db)  # Store(None) -> default XDG path


def _state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "toolstack"


def _pidfile_path() -> Path:
    return _state_dir() / "broker.pid"


def _is_broker(pid: int) -> bool:
    try:
        out = subprocess.run(["ps", "-p", str(pid), "-o", "args="],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    try:
        args = shlex.split(out.stdout)
    except ValueError:
        return False
    return any(tok == "-m" and args[i + 1] == "broker.server" for i, tok in enumerate(args[:-1]))


def create_caller(args) -> None:
    store = _store(args)
    try:
        token = operations.create_caller(store, args.name, args.allow, args.review, args.operator)
    finally:
        store.close()
    print(f"caller '{args.name}' created.")
    print("token (shown once, store it now):")
    print(token)


def list_callers(args) -> None:
    store = _store(args)
    try:
        for c in store.list_callers(include_revoked=args.include_revoked):
            print(f"{c['id']}\t{c['name']}\t{'revoked' if c['revoked_at'] else 'active'}")
    finally:
        store.close()


def revoke_caller(args) -> None:
    store = _store(args)
    try:
        cancelled = operations.revoke_caller(store, args.name, args.operator,
                                             surface=NodSurface.from_env())
    except LookupError as exc:
        raise SystemExit(str(exc))
    finally:
        store.close()
    suffix = f" ({cancelled} pending approval(s) cancelled)" if cancelled else ""
    print(f"caller '{args.name}' revoked.{suffix}")


def show_policy(args) -> None:
    store = _store(args)
    try:
        caller = operations.require_caller(store, args.name)
        print(json.dumps(store.policy_for(caller["id"]), indent=2))
    except LookupError as exc:
        raise SystemExit(str(exc))
    finally:
        store.close()


def set_policy(args) -> None:
    store = _store(args)
    try:
        operations.set_policy(store, args.name, args.allow, args.review, args.operator,
                              deny=args.deny)
    except LookupError as exc:
        raise SystemExit(str(exc))
    finally:
        store.close()
    print(f"policy for '{args.name}' updated.")


def issue_token(args) -> None:
    store = _store(args)
    try:
        token = operations.issue_token(store, args.name, args.operator)
    except LookupError as exc:
        raise SystemExit(str(exc))
    finally:
        store.close()
    print("token (shown once, store it now):")
    print(token)


def list_tokens(args) -> None:
    store = _store(args)
    try:
        for t in store.list_tokens(include_revoked=args.include_revoked):
            print(f"{t['token_hash'][:12]}...\t{t['caller']}\t{'revoked' if t['revoked_at'] else 'active'}")
    finally:
        store.close()


def revoke_token(args) -> None:
    store = _store(args)
    try:
        count = operations.revoke_token(store, args.prefix, args.operator,
                                        surface=NodSurface.from_env())
    finally:
        store.close()
    print(f"revoked {count} token(s) matching '{args.prefix}'.")


def sweep(args) -> None:
    """Expire pending approvals past their broker deadline (lazy GC, since the broker
    runs no background worker). Withdraws each from nod if TOOLSTACK_NOD_* is set."""
    store = _store(args)
    try:
        ctx = BrokerContext(store=store, registry=None, runtime=None,
                            audit=AuditLog(store, sink=stderr_sink),
                            surface=NodSurface.from_env())
        count = request_lifecycle.sweep_expired(ctx)
    finally:
        store.close()
    print(f"swept {count} expired approval(s).")


def list_requests(args) -> None:
    store = _store(args)
    try:
        for r in store.list_requests(status=args.status, limit=args.limit):
            print(f"{r['id']}\t{r['tool']}.{r['op']}\t{r['status']}")
    finally:
        store.close()


def audit(args) -> None:
    store = _store(args)
    try:
        if args.request_id is not None:
            events = store.audit_events(request_id=args.request_id)
        elif args.correlation_id:
            events = store.audit_events(correlation_id=args.correlation_id)
        else:
            events = store.recent_audit(limit=args.limit)
        for e in events:
            print(f"{e['component']}.{e['event_type']}\t{e['outcome']}\treq={e['request_id']}\t{json.dumps(e['details'])}")
    finally:
        store.close()


def reload(args) -> None:
    path = Path(args.pidfile) if args.pidfile else _pidfile_path()
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read broker pidfile {path}: {exc}")
    if not _is_broker(pid):
        raise SystemExit(f"refusing to signal pid {pid}: it is not broker.server")
    try:
        os.kill(pid, signal.SIGHUP)
    except OSError as exc:
        raise SystemExit(f"failed to signal broker pid {pid}: {exc}")
    print(f"reloaded broker registry (pid {pid}).")


def main() -> None:
    parser = argparse.ArgumentParser(prog="brokerctl")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", help="database path (default: $TOOLSTACK_BROKER_DB or XDG state dir)")
    operator = argparse.ArgumentParser(add_help=False)
    operator.add_argument("--operator", default="operator", help="operator id for the audit trail")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("create-caller", parents=[common, operator])
    p.add_argument("--name", required=True)
    p.add_argument("--allow", action="append", metavar="TOOL.OP")
    p.add_argument("--review", action="append", metavar="TOOL.OP")
    p.set_defaults(func=create_caller)

    p = sub.add_parser("list-callers", parents=[common])
    p.add_argument("--include-revoked", action="store_true")
    p.set_defaults(func=list_callers)

    p = sub.add_parser("revoke-caller", parents=[common, operator])
    p.add_argument("--name", required=True)
    p.set_defaults(func=revoke_caller)

    p = sub.add_parser("show-policy", parents=[common])
    p.add_argument("--name", required=True)
    p.set_defaults(func=show_policy)

    p = sub.add_parser("set-policy", parents=[common, operator])
    p.add_argument("--name", required=True)
    p.add_argument("--allow", action="append", metavar="TOOL.OP")
    p.add_argument("--review", action="append", metavar="TOOL.OP")
    p.add_argument("--deny", action="append", metavar="TOOL.OP")
    p.set_defaults(func=set_policy)

    p = sub.add_parser("issue-token", parents=[common, operator])
    p.add_argument("--name", required=True)
    p.set_defaults(func=issue_token)

    p = sub.add_parser("list-tokens", parents=[common])
    p.add_argument("--include-revoked", action="store_true")
    p.set_defaults(func=list_tokens)

    p = sub.add_parser("revoke-token", parents=[common, operator])
    p.add_argument("--prefix", required=True, help="token hash prefix (see list-tokens)")
    p.set_defaults(func=revoke_token)

    p = sub.add_parser("sweep", parents=[common],
                       help="expire pending approvals past their deadline (lazy GC)")
    p.set_defaults(func=sweep)

    p = sub.add_parser("list-requests", parents=[common])
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=list_requests)

    p = sub.add_parser("audit", parents=[common])
    p.add_argument("--request-id", type=int)
    p.add_argument("--correlation-id")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=audit)

    p = sub.add_parser("reload", help="send SIGHUP to the running broker to reload the registry")
    p.add_argument("--pidfile", help="broker pidfile (default: XDG state toolstack/broker.pid)")
    p.set_defaults(func=reload)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
