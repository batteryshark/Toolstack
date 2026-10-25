"""SPS CLI. Production entrypoint: `python3 -m sps.cli serve`.

Subcommands:
  - (default) serve: run the SPS server using /etc/toolstack/sps.env
  - init:    generate a starter sps.env + self-signed cert/key + CA bundle;
            idempotent (refuses to overwrite an existing config).
  - vault-set / vault-get: operator provisioning against the localfile plugin.

The serve subcommand blocks (HTTPServer.serve_forever) until SIGTERM.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from . import audit, config as cfgmod
from .plugins import loader as plugin_loader
from .server import AppContext, build_server
from .store import ToolRegistrationStore


def init_runtime_paths(config: str | Path, *, state_dir: str | Path | None = None,
                       audit_log: str | Path | None = None) -> tuple[Path, Path]:
    """Pure bootstrap path selection: (vault file, audit log).

    Production config separates read-only configuration from mutable state;
    arbitrary config locations stay self-contained unless explicitly overridden.
    """
    config = Path(config)
    production = config == Path("/etc/toolstack/sps.env")
    state = Path(state_dir) if state_dir is not None else (
        Path("/var/lib/toolstack") if production else config.parent)
    audit_path = Path(audit_log) if audit_log is not None else (
        Path("/var/log/toolstack/sps.audit") if production else config.parent / "sps-audit.jsonl")
    return state / "sps.vault.json", audit_path


def _mkdir_private(path: Path) -> None:
    """Create missing directories privately; never chmod shared existing parents."""
    if not path.exists():
        _mkdir_private(path.parent)
        path.mkdir(mode=0o700, exist_ok=True)


# Where SPS writes its boot identity so long-running tools can detect a restart
# and re-register. Overridable for tests (TOOLSTACK_SPS_BOOT_ID_PATH).
_DEFAULT_BOOT_ID_PATH = (
    Path(os.environ.get("XDG_STATE_HOME") or "/var/lib")
    / "toolstack"
    / "sps.boot_id"
)


def _write_boot_id(path: Path, boot_id: str | None = None) -> str:
    """Write a boot_id atomically (write-temp + os.replace). Generates a fresh
    random id if none is supplied. Returns the id. SPS regenerates this on every
    startup; the admin watchdog polls the file and re-registers running tools
    when it changes."""
    if boot_id is None:
        boot_id = secrets.token_hex(16)
    from .paths import atomic_write
    atomic_write(path, (boot_id + "\n").encode("utf-8"), public=True)
    return boot_id


def maybe_generate_tls_material(cert_path: str, key_path: str, ca_path: str, subj: str) -> bool:
    """Idempotent: returns False if all three files exist (nothing to do),
    True if OpenSSL was run to produce them. The CA path is generated as the
    self-signed cert in dev; production replaces with a real CA file.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path) and os.path.exists(ca_path):
        return False
    # Self-signed cert generated for both server and CA-verify (dev/single-host).
    # `-addext subjectAltName=IP:127.0.0.1,DNS:localhost` is required: Python's
    # ssl module rejects CN-only certs for hostname/IP verification (RFC 6125).
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_path, "-out", cert_path,
        "-days", "365", "-subj", subj,
        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
    ]
    subprocess.run(cmd, check=True, capture_output=True, umask=0o077)
    # Copy the cert as the CA bundle (self-signed == own CA in dev).
    if not os.path.exists(ca_path):
        fd = os.open(ca_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with open(cert_path, "rb") as f, os.fdopen(fd, "wb") as g:
            g.write(f.read())
    return True


def _cmd_serve(args) -> None:
    """Run the SPS server. Mode-0600 re-check fails closed."""
    cfg_path = args.config
    cfg = cfgmod.load_config(cfg_path)  # raises ConfigModeError or FileNotFoundError
    import ssl as _ssl
    if not cfg.sp_tls_cert or not cfg.sp_tls_key:
        raise ValueError("SPS requires TLS certificate and key")
    ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=cfg.sp_tls_cert, keyfile=cfg.sp_tls_key)
    plugin = plugin_loader.load_plugin(cfg)
    plugin.connect()
    audit_log_path = cfg.sp_audit_log or "/var/log/toolstack/sps.audit"
    audit_log = audit.AuditLogger(audit_log_path)
    boot_id = secrets.token_hex(16)
    ctx = AppContext(
        config=cfg,
        store=ToolRegistrationStore(),
        audit=audit_log,
        plugin=plugin,
        boot_id=boot_id,
    )
    server = build_server(ctx, host=cfg.sp_host, port=cfg.sp_port, ssl_ctx=ssl_ctx)
    # Announce a fresh boot_id so the toolyard watchdog (admin side) can detect
    # this restart and re-register every running tool. Without this, SPS's
    # in-memory tool pool starts empty on every startup and any tool that was
    # already running gets "Not found" until it's manually bounced.
    boot_id_path = Path(
        os.environ.get("TOOLSTACK_SPS_BOOT_ID_PATH") or _DEFAULT_BOOT_ID_PATH
    )
    _write_boot_id(boot_id_path, boot_id)
    print(
        f"sps: listening on https://{cfg.sp_host}:{cfg.sp_port} "
        f"(plugin={cfg.sp_plugin}, audit={audit_log_path}, boot_id={boot_id[:8]}...)",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _cmd_regen_tls(args) -> None:
    """Regenerate the self-signed TLS cert/key/CA bundle. Existing sps.env is
    preserved (SP_SECRET unchanged). Idempotent: rerun is a no-op. Operators
    who replaced the self-signed cert with one from a real CA should not run
    this -- it will overwrite their cert."""
    import shutil
    cfg_path = args.config
    base_dir = os.path.dirname(cfg_path) or "."
    cert = os.path.join(base_dir, "sps.crt")
    key = os.path.join(base_dir, "sps.key")
    ca = os.path.join(base_dir, "sps-ca.crt")
    if shutil.which("openssl") is None:
        print("openssl is required for `sps regen-tls`", file=sys.stderr)
        sys.exit(3)
    for p in (cert, key, ca):
        if os.path.exists(p):
            os.remove(p)
    maybe_generate_tls_material(cert, key, ca, "/CN=127.0.0.1")
    if os.geteuid() == 0:
        # Match sps.env's mode-0600 posture; the key is the sensitive half.
        os.chmod(key, 0o600)
    print(f"regenerated {cert}, {key}, {ca} (SP_SECRET and sps.env unchanged)")


def _cmd_init_vault(args) -> None:
    """Create the localfile vault file at the path sps.env points at, using
    $SP_VAULT_PASSPHRASE (or $SP_VAULT_PASSPHRASE_FILE) for the encryption key.
    Idempotent: refuses to overwrite an existing vault file (the operator
    always wins; pass --force to re-init, which destroys all stored secrets)."""
    import getpass
    cfg = cfgmod.load_config(args.config)
    if cfg.sp_plugin != "localfile" or cfg.localfile is None:
        raise SystemExit("sps init-vault requires SP_PLUGIN=localfile")
    passphrase = os.environ.get("SP_VAULT_PASSPHRASE")
    file_path = os.environ.get("SP_VAULT_PASSPHRASE_FILE")
    if file_path:
        from .paths import read_private
        passphrase = read_private(file_path).strip()
    elif not passphrase and sys.stdin.isatty():
        passphrase = getpass.getpass("vault passphrase: ")
    elif not passphrase:
        passphrase = sys.stdin.readline().rstrip("\n")
    if not passphrase:
        raise SystemExit("vault passphrase not provided (set SP_VAULT_PASSPHRASE or stdin it)")
    from .plugins.localfile import _Vault
    vault_file = cfg.localfile.vault_file
    if Path(vault_file).exists() and not args.force:
        raise SystemExit(
            f"vault already exists at {vault_file}; pass --force to re-init "
            "(this destroys all stored secrets)"
        )
    if Path(vault_file).exists() and args.force:
        Path(vault_file).unlink()
    _Vault.init(vault_file, passphrase=passphrase)
    os.chmod(vault_file, 0o600)
    print(f"initialized vault at {vault_file} (mode 0600)")


def _cmd_init(args) -> None:
    """Generate a starter sps.env + cert/key/CA. Idempotent on the env file."""
    import shutil
    cfg_path = args.config
    if os.path.lexists(cfg_path):
        print(f"{cfg_path}: already exists; not overwriting", file=sys.stderr)
        sys.exit(2)
    if shutil.which("openssl") is None:
        print("openssl is required for `sps init`", file=sys.stderr)
        sys.exit(3)
    base_dir = os.path.dirname(cfg_path) or "."
    vault_file, audit_log = init_runtime_paths(
        cfg_path, state_dir=getattr(args, "state_dir", None),
        audit_log=getattr(args, "audit_log", None))
    for directory in (Path(base_dir), vault_file.parent, audit_log.parent):
        _mkdir_private(directory)
    cert = os.path.join(base_dir, "sps.crt")
    key = os.path.join(base_dir, "sps.key")
    ca = os.path.join(base_dir, "sps-ca.crt")
    maybe_generate_tls_material(cert, key, ca, "/CN=127.0.0.1")

    # SP_SECRET: 32 random bytes -> 64 hex chars (way above the 32-char lower
    # bound). SP_PLUGIN defaults to localfile for the dev path.
    secret = os.urandom(32).hex()
    content = (
        'SP_HOST = "127.0.0.1"\n'
        'SP_PORT = "8743"\n'
        f'SP_TLS_CERT = {json.dumps(cert)}\n'
        f'SP_TLS_KEY = {json.dumps(key)}\n'
        f'SP_TLS_CA = {json.dumps(ca)}\n'
        f'SP_SECRET = "{secret}"\n'
        f'SP_AUDIT_LOG = {json.dumps(str(audit_log))}\n'
        'SP_PLUGIN = "localfile"\n'
        '\n'
        '[localfile]\n'
        f'VAULT_FILE = {json.dumps(str(vault_file))}\n'
    )
    # Exclusive creation prevents a concurrent init (or dangling symlink) from
    # overwriting existing configuration. Sensitive bytes are private at birth.
    fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(cfg_path, 0o600)
    # When the chosen plugin is localfile, `vault-set` / `vault-get` need the actual
    # vault file to exist. If the operator passed SP_VAULT_PASSPHRASE in env, generate
    # the empty vault now (idempotent: skip if one already exists). Otherwise print a
    # hint about how to set the passphrase before first vault-set.
    vault_msg = ""
    if "SP_PLUGIN = \"localfile\"" in content:
        passphrase = os.environ.get("SP_VAULT_PASSPHRASE")
        if passphrase:
            try:
                from .plugins.localfile import _Vault
                _Vault.init(vault_file, passphrase=passphrase)
                vault_msg = f"; vault initialized at {vault_file}"
            except FileExistsError:
                vault_msg = f"; vault at {vault_file} (kept existing)"
        else:
            vault_msg = (
                f"\n  vault not created (no $SP_VAULT_PASSPHRASE in env); set it then "
                f"`python3 -m sps.cli init-vault --config {cfg_path}`"
            )
    print(f"wrote {cfg_path} (mode 0600); SP_SECRET generated; cert at {cert}; CA at {ca}{vault_msg}")


def _cmd_vault_set(args) -> None:
    """Operator provisioning against the localfile plugin."""
    cfg = cfgmod.load_config(args.config)
    if cfg.sp_plugin != "localfile" or cfg.localfile is None:
        raise SystemExit("sps vault-set requires SP_PLUGIN=localfile")
    import getpass
    if sys.stdin.isatty():
        value = getpass.getpass(f"value for {args.tool}.{args.field}: ")
    else:
        value = sys.stdin.readline().rstrip("\n")
    passphrase = os.environ.get("SP_VAULT_PASSPHRASE")
    if not passphrase:
        raise SystemExit("SP_VAULT_PASSPHRASE not set in env")
    from .plugins.localfile import _Vault
    _Vault(cfg.localfile.vault_file, passphrase).set(args.tool, args.field, value)
    print(f"set {args.tool}.{args.field}")


def _cmd_vault_get(args) -> None:
    """Operator introspection: length-only (never the value)."""
    cfg = cfgmod.load_config(args.config)
    if cfg.sp_plugin != "localfile" or cfg.localfile is None:
        raise SystemExit("sps vault-get requires SP_PLUGIN=localfile")
    passphrase = os.environ.get("SP_VAULT_PASSPHRASE")
    if not passphrase:
        raise SystemExit("SP_VAULT_PASSPHRASE not set in env")
    from .plugins.localfile import _Vault
    backend = _Vault(cfg.localfile.vault_file, passphrase)
    print("set" if backend.has(args.tool, args.field) else "unset")


def main() -> None:
    parser = argparse.ArgumentParser(prog="sps")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="write a starter sps.env (cert + key + CA)")
    p_init.add_argument("--config", default="/etc/toolstack/sps.env")
    p_init.add_argument("--state-dir", help="directory for sps.vault.json (default: /var/lib/toolstack for production config, otherwise beside config)")
    p_init.add_argument("--audit-log", help="audit log file (default: /var/log/toolstack/sps.audit for production config, otherwise beside config)")
    p_init.set_defaults(func=_cmd_init)
    p_iv = sub.add_parser("init-vault", help="create the localfile vault file (separate from init)")
    p_iv.add_argument("--config", default="/etc/toolstack/sps.env")
    p_iv.add_argument("--force", action="store_true",
                      help="re-initialize an existing vault (destroys all stored secrets)")
    p_iv.set_defaults(func=_cmd_init_vault)
    p_regen = sub.add_parser("regen-tls", help="regenerate the TLS cert/key/CA (sps.env kept)")
    p_regen.add_argument("--config", default="/etc/toolstack/sps.env")
    p_regen.set_defaults(func=_cmd_regen_tls)
    p_serve = sub.add_parser("serve", help="run the SPS server")
    p_serve.add_argument("--config", default="/etc/toolstack/sps.env")
    p_serve.set_defaults(func=_cmd_serve)
    p_vset = sub.add_parser("vault-set", help="set a secret in the localfile vault")
    p_vset.add_argument("--config", default="/etc/toolstack/sps.env")
    p_vset.add_argument("tool")
    p_vset.add_argument("field")
    p_vset.set_defaults(func=_cmd_vault_set)
    p_vget = sub.add_parser("vault-get", help="check whether a vault entry exists")
    p_vget.add_argument("--config", default="/etc/toolstack/sps.env")
    p_vget.add_argument("tool")
    p_vget.add_argument("field")
    p_vget.set_defaults(func=_cmd_vault_get)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
