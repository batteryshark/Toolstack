#!/bin/sh
# First-run onboarding, then serve the admin. Everything below is idempotent; state
# persists on the /data volume, so a restart re-uses the password and vault already set.
set -e

mkdir -p "$XDG_CONFIG_HOME" "$XDG_STATE_HOME"

# Read secrets from the environment INSIDE python (never interpolate them into the shell),
# so a password/passphrase containing quotes or $ can't break or leak.
python - <<'PY'
import os, sys
from admin import auth, settings

# Reject the shipped .env.example placeholders, so a box can never go live with a guessable
# secret because someone copied .env.example and forgot to edit it.
_PLACEHOLDERS = {"change-me", "change-me-too", "changeme", "change_me", "password", "secret"}

# 1) Admin login password. The admin refuses to serve without one (no default creds).
if settings.read_password_hash() is None:
    pw = os.environ.get("TOOLSTACK_ADMIN_PASSWORD") or ""
    if not pw:
        sys.exit("[entrypoint] no admin password set. Put TOOLSTACK_ADMIN_PASSWORD in your "
                 ".env, or run `python -m admin set-password` against the /data volume.")
    if pw.strip().lower() in _PLACEHOLDERS:
        sys.exit("[entrypoint] TOOLSTACK_ADMIN_PASSWORD is still the example placeholder. "
                 "Set a real password in your .env before starting.")
    settings.write_password_hash(auth.hash_password(pw))
    print("[entrypoint] admin password set from TOOLSTACK_ADMIN_PASSWORD")
else:
    print("[entrypoint] admin password already set; leaving it")

# 2) Encrypted vault: create it once if that backend is selected and a passphrase is given.
if os.environ.get("TOOLSTACK_SECRET_BACKEND") == "vault" and os.environ.get("TOOLSTACK_VAULT_PASSPHRASE"):
    if os.environ["TOOLSTACK_VAULT_PASSPHRASE"].strip().lower() in _PLACEHOLDERS:
        sys.exit("[entrypoint] TOOLSTACK_VAULT_PASSPHRASE is still the example placeholder. "
                 "Set a real passphrase in your .env before starting.")
    from pathlib import Path
    from toolyard import secrets as ts
    vault = os.environ.get("TOOLSTACK_VAULT_FILE") or ts._default_vault_file()
    if not Path(vault).exists():
        ts.VaultBackend.init(vault, os.environ["TOOLSTACK_VAULT_PASSPHRASE"])
        print(f"[entrypoint] encrypted vault created at {vault}")
    else:
        print("[entrypoint] vault already exists; leaving it")
PY

# The broker is started from the admin UI (Start broker), so it's the admin's managed
# child. Just serve the control panel; bind host comes from TOOLSTACK_ADMIN_HOST. The
# container-internal port is fixed at 8780 (remap the HOST side in compose if you need a
# different host port: "127.0.0.1:<host>:8780").
exec python -m admin serve --port 8780
