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
import os
import subprocess
import sys

from . import audit, config as cfgmod
from .plugins import loader as plugin_loader
from .server import AppContext, build_server
from .store import ToolRegistrationStore


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
    subprocess.run(cmd, check=True, capture_output=True)
    # Copy the cert as the CA bundle (self-signed == own CA in dev).
    if not os.path.exists(ca_path):
        with open(cert_path, "rb") as f, open(ca_path, "wb") as g:
            g.write(f.read())
    return True


def _cmd_serve(args) -> None:
    """Run the SPS server. Mode-0600 re-check fails closed."""
    cfg_path = args.config
    cfg = cfgmod.load_config(cfg_path)  # raises ConfigModeError or FileNotFoundError
    plugin = plugin_loader.load_plugin(cfg)
    plugin.connect()
    audit_log_path = cfg.sp_audit_log or "/var/log/toolstack/sps.audit"
    audit_log = audit.AuditLogger(audit_log_path)
    ctx = AppContext(
        config=cfg,
        store=ToolRegistrationStore(),
        audit=audit_log,
        plugin=plugin,
    )
    import ssl as _ssl
    ssl_ctx = None
    if cfg.sp_tls_cert and cfg.sp_tls_key and os.path.exists(cfg.sp_tls_cert) and os.path.exists(cfg.sp_tls_key):
        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=cfg.sp_tls_cert, keyfile=cfg.sp_tls_key)
    server = build_server(ctx, host=cfg.sp_host, port=cfg.sp_port, ssl_ctx=ssl_ctx)
    print(
        f"sps: listening on https://{cfg.sp_host}:{cfg.sp_port} "
        f"(plugin={cfg.sp_plugin}, audit={audit_log_path})",
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


def _cmd_init(args) -> None:
    """Generate a starter sps.env + cert/key/CA. Idempotent on the env file."""
    import shutil
    cfg_path = args.config
    if os.path.exists(cfg_path):
        print(f"{cfg_path}: already exists; not overwriting", file=sys.stderr)
        sys.exit(2)
    if shutil.which("openssl") is None:
        print("openssl is required for `sps init`", file=sys.stderr)
        sys.exit(3)
    base_dir = os.path.dirname(cfg_path) or "."
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
        f'SP_TLS_CERT = "{cert}"\n'
        f'SP_TLS_KEY = "{key}"\n'
        f'SP_TLS_CA = "{ca}"\n'
        f'SP_SECRET = "{secret}"\n'
        'SP_AUDIT_LOG = "/var/log/toolstack/sps.audit"\n'
        'SP_PLUGIN = "localfile"\n'
        '\n'
        '[localfile]\n'
        'VAULT_FILE = "/var/lib/toolstack/sps.vault.json"\n'
    )
    with open(cfg_path, "w") as f:
        f.write(content)
    os.chmod(cfg_path, 0o600)
    print(f"wrote {cfg_path} (mode 0600); SP_SECRET generated; cert at {cert}; CA at {ca}")


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
    p_init.set_defaults(func=_cmd_init)
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
