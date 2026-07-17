"""Toolyard lifecycle CLI.

    python3 -m toolyard.cli up [id]   --root tools --secrets secrets.toml [--backend process|docker]
    python3 -m toolyard.cli down [id]
    python3 -m toolyard.cli ls

Which tools are running is kept in a small JSON state file so `down`/`ls` work
across invocations.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path

from .config import discover
from .runner import RunningTool, get_runner
from .secrets import get_backend


def _state_path() -> Path:
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(state) / "toolstack" / "toolyard" / "state.json"


def _load_state() -> dict:
    path = _state_path()
    return json.loads(path.read_text()) if path.exists() else {}


def _save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, path)   # atomic: a torn write can't orphan the running tools' records


def cmd_up(args) -> None:
    root = args.root or os.environ.get("TOOLSTACK_TOOLS_ROOT") or "tools"
    secrets_file = args.secrets or os.environ.get("TOOLSTACK_SECRETS_FILE") or "secrets.toml"
    defs = {d.id: d for d in discover(root)}
    targets = [args.id] if args.id else list(defs)
    runner = get_runner(args.backend)
    state = _load_state()
    for tool_id in targets:
        if tool_id not in defs:
            raise SystemExit(f"unknown tool: {tool_id}")
        if tool_id in state:
            print(f"{tool_id}: already running")
            continue
        tool_def = defs[tool_id]
        # Per tool, not once for the batch: each tool resolves under its own machine
        # identity, so one tool's start can never read another's secrets. A tool with no
        # secrets needs no backend at all (every resolve() is empty for it anyway).
        secrets = {}
        if tool_def.secrets:
            backend = get_backend(args.secret_backend, secrets_file=secrets_file,
                                  tool_def=tool_def)
            secrets = backend.resolve(tool_def)
        running = runner.start(
            tool_def, secrets,
            secret_backend=args.secret_backend, secrets_file=secrets_file)
        state[tool_id] = asdict(running)
        print(f"{tool_id}: started ({running.backend}) on 127.0.0.1:{running.port}")
    _save_state(state)


def cmd_down(args) -> None:
    state = _load_state()
    targets = [args.id] if args.id else list(state)
    for tool_id in targets:
        if tool_id not in state:
            print(f"{tool_id}: not running")
            continue
        running = RunningTool(**state[tool_id])
        get_runner(running.backend).stop(running)
        del state[tool_id]
        print(f"{tool_id}: stopped")
    _save_state(state)


def cmd_reload(args) -> None:
    cmd_down(args)
    cmd_up(args)


def cmd_ls(args) -> None:
    state = _load_state()
    if not state:
        print("no tools running")
        return
    for tool_id, record in state.items():
        running = RunningTool(**record)
        alive = "alive" if get_runner(running.backend).is_alive(running) else "dead"
        print(f"{tool_id}\t{running.backend}\t127.0.0.1:{running.port}\t{alive}")


def _vault_file(args) -> str:
    from .secrets import _default_vault_file
    return args.file or os.environ.get("TOOLSTACK_VAULT_FILE") or _default_vault_file()


def _vault_passphrase(confirm: bool = False) -> str:
    """Passphrase for a vault CLI command: from $TOOLSTACK_VAULT_PASSPHRASE, else prompt
    (no echo). `confirm` double-prompts for the init flow."""
    env = os.environ.get("TOOLSTACK_VAULT_PASSPHRASE")
    if env:
        return env
    import getpass
    pw = getpass.getpass("vault passphrase: ")
    if not pw:
        raise SystemExit("passphrase must not be empty")
    if confirm and pw != getpass.getpass("confirm passphrase: "):
        raise SystemExit("passphrases do not match")
    return pw


def cmd_vault_init(args) -> None:
    from .secrets import VaultBackend
    path = _vault_file(args)
    try:
        VaultBackend.init(path, _vault_passphrase(confirm=True))
    except FileExistsError as exc:
        raise SystemExit(str(exc))
    print(f"vault created at {path}")


def cmd_vault_set(args) -> None:
    import sys
    from .secrets import VaultBackend
    path = _vault_file(args)
    passphrase = _vault_passphrase()
    # value never on argv (shell history / ps): prompt with no echo on a tty, else read stdin
    if sys.stdin.isatty():
        import getpass
        value = getpass.getpass(f"value for {args.tool}.{args.field}: ")
    else:
        value = sys.stdin.readline().rstrip("\n")
    try:
        VaultBackend(path, passphrase).set_secret(args.tool, args.field, value)
    except (FileNotFoundError, RuntimeError) as exc:
        raise SystemExit(str(exc))
    print(f"set {args.tool}.{args.field}")


def main() -> None:
    logging.basicConfig(level=os.environ.get("TOOLSTACK_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="toolyard")
    sub = parser.add_subparsers(required=True)

    up = sub.add_parser("up", help="resolve secrets and start one or all tools")
    up.add_argument("id", nargs="?")
    up.add_argument("--root", help="tools root (default: $TOOLSTACK_TOOLS_ROOT or 'tools')")
    up.add_argument("--secrets", help="dev secrets TOML (default: $TOOLSTACK_SECRETS_FILE or 'secrets.toml')")
    up.add_argument("--backend", choices=["process", "docker"],
                    default=os.environ.get("TOOLSTACK_RUNNER", "process"))
    up.add_argument("--secret-backend", choices=["file", "vault", "infisical"],
                    default=os.environ.get("TOOLSTACK_SECRET_BACKEND", "file"),
                    help="secret backend (default: $TOOLSTACK_SECRET_BACKEND or 'file')")
    up.set_defaults(func=cmd_up)

    down = sub.add_parser("down", help="stop one or all tools")
    down.add_argument("id", nargs="?")
    down.set_defaults(func=cmd_down)

    reload_p = sub.add_parser("reload", help="restart one or all tools")
    reload_p.add_argument("id", nargs="?")
    reload_p.add_argument("--root", help="tools root (default: $TOOLSTACK_TOOLS_ROOT or 'tools')")
    reload_p.add_argument("--secrets", help="dev secrets TOML (default: $TOOLSTACK_SECRETS_FILE or 'secrets.toml')")
    reload_p.add_argument("--backend", choices=["process", "docker"],
                          default=os.environ.get("TOOLSTACK_RUNNER", "process"))
    reload_p.add_argument("--secret-backend", choices=["file", "vault", "infisical"],
                          default=os.environ.get("TOOLSTACK_SECRET_BACKEND", "file"),
                          help="secret backend (default: $TOOLSTACK_SECRET_BACKEND or 'file')")
    reload_p.set_defaults(func=cmd_reload)

    ls = sub.add_parser("ls", help="list running tools")
    ls.set_defaults(func=cmd_ls)

    vinit = sub.add_parser("vault-init", help="create a new empty encrypted secrets vault")
    vinit.add_argument("--file", help="vault path (default: $TOOLSTACK_VAULT_FILE or "
                                      "~/.config/toolstack/vault.json)")
    vinit.set_defaults(func=cmd_vault_init)

    vset = sub.add_parser("vault-set", help="set a secret field in the vault "
                                            "(value read from stdin, or prompted)")
    vset.add_argument("tool", help="tool id (the [section] in the vault)")
    vset.add_argument("field", help="backend field name (the KEY under the tool)")
    vset.add_argument("--file", help="vault path (default: $TOOLSTACK_VAULT_FILE or "
                                     "~/.config/toolstack/vault.json)")
    vset.set_defaults(func=cmd_vault_set)

    args = parser.parse_args()
    try:
        args.func(args)
    except ValueError as exc:
        # a malformed toolyard.toml (e.g. a missing/invalid port) -> a clean one-line
        # message and a non-zero exit, not a traceback.
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
