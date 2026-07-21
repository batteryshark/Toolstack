#!/usr/bin/env bash
# One-command native (systemd) install of Toolstack on a single host.
#
#   sudo deploy/install.sh                 # service account defaults to "toolstack"
#   sudo TOOLSTACK_USER=svc deploy/install.sh
#
# It creates the service account, builds the admin virtualenv (with the package, so
# brokerctl/toolstack/toolyard are on hand), pins the state dir, sets the admin password,
# and installs + enables the systemd unit. It chowns the checkout to the service user, so
# run it from where the deployment should live (e.g. /opt/toolstack), not a personal clone.
#
# This gives a working basic install (process runner + file secret backend). For the docker
# runner, the encrypted vault, or Infisical, fill in /etc/toolstack/admin.env afterwards
# (see deploy/README.md) and restart the service.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo deploy/install.sh" >&2; exit 1; }

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="${TOOLSTACK_USER:-toolstack}"
UNIT="/etc/systemd/system/toolstack-admin.service"
VENV_PY="$REPO_ROOT/admin/.venv/bin/python"
VENV_PIP="$REPO_ROOT/admin/.venv/bin/pip"
# admin is run from the checkout root (it is not a pip-distributed package), so every admin
# invocation below cd's there first, matching the unit's WorkingDirectory.
run_admin() { sudo -u "$SERVICE_USER" env XDG_CONFIG_HOME=/var/lib XDG_STATE_HOME=/var/lib \
                  sh -c "cd '$REPO_ROOT' && $1"; }

echo "==> Toolstack install  (checkout: $REPO_ROOT, service user: $SERVICE_USER)"

# 1. Service account
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "==> Creating system user '$SERVICE_USER'"
    useradd --system --user-group --shell /usr/sbin/nologin --home-dir "$REPO_ROOT" "$SERVICE_USER"
fi
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"

# 2. Let the service user own the checkout: it reads the code and git-clones imported tools
#    into the tools dir under it.
echo "==> chown -R $SERVICE_USER:$SERVICE_GROUP $REPO_ROOT"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$REPO_ROOT"

# 3. Admin virtualenv: the package (brokerctl/toolstack/toolyard) + vault extra + admin deps
if [ ! -x "$VENV_PY" ]; then
    echo "==> Creating admin virtualenv"
    sudo -u "$SERVICE_USER" python3 -m venv "$REPO_ROOT/admin/.venv"
fi
echo "==> Installing the package + admin dependencies"
sudo -u "$SERVICE_USER" sh -c "cd '$REPO_ROOT' && '$VENV_PIP' install --quiet -e '.[vault]' -r admin/requirements.txt"

# 4. State + log dirs (the unit's StateDirectory/ReadWritePaths keep them; pre-create
#    so set-password + the SPS audit logger land right instead of crashing on first write)
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 700 /var/lib/toolstack
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 750 /var/log/toolstack

# 5. Admin password (the panel fails closed without one)
if run_admin "'$VENV_PY' -c 'from admin import settings; raise SystemExit(0 if settings.read_password_hash() else 1)'"; then
    echo "==> Admin password already set; leaving it"
else
    echo "==> Set the admin login password:"
    run_admin "'$VENV_PY' -m admin set-password"
fi

# 6. systemd units: fill the templates' install root + service account, install both
echo "==> Installing $UNIT"
sed -e "s|/opt/toolstack|$REPO_ROOT|g" \
    -e "s|^User=toolstack|User=$SERVICE_USER|" \
    -e "s|^Group=toolstack|Group=$SERVICE_GROUP|" \
    "$REPO_ROOT/deploy/toolstack-admin.service" > "$UNIT"

SPS_UNIT="/etc/systemd/system/toolstack-sps.service"
echo "==> Installing $SPS_UNIT"
sed -e "s|/opt/toolstack|$REPO_ROOT|g" \
    -e "s|^User=toolstack|User=$SERVICE_USER|" \
    -e "s|^Group=toolstack|Group=$SERVICE_GROUP|" \
    "$REPO_ROOT/deploy/toolstack-sps.service" > "$SPS_UNIT"

systemctl daemon-reload
systemctl enable --now toolstack-admin
if [ -f /etc/toolstack/sps.env ]; then
    # Env file already exists (operator provisioned it): take ownership so the
    # service user can read it, then start. (New installs: run `python3 -m sps.cli init`
    # to bootstrap sps.env, then systemctl start toolstack-sps.)
    chown "$SERVICE_USER:$SERVICE_GROUP" /etc/toolstack/sps.env
    chmod 600 /etc/toolstack/sps.env
    systemctl enable --now toolstack-sps
else
    echo "==> /etc/toolstack/sps.env not found; enabling toolstack-sps unit without autostart."
    echo "    Run:  sudo -u $SERVICE_USER python3 -m sps.cli init --config /etc/toolstack/sps.env"
    echo "    then: sudo systemctl start toolstack-sps"
    systemctl enable toolstack-sps
fi

cat <<EOF

Toolstack is installed and running.
  Panel:   http://127.0.0.1:8780   (reach it over a TLS tunnel; never bind a public interface)
  SPS:     tcp://127.0.0.1:8743 (TLS; tools register here on startup)
  Status:  systemctl status toolstack-admin toolstack-sps
  Logs:    journalctl -u toolstack-admin -f
            journalctl -u toolstack-sps -f
            tail -f /var/log/toolstack/sps.audit    (SPS secret-access audit log)

  Provision an agent (its bearer token prints once):
    sudo -u $SERVICE_USER env XDG_CONFIG_HOME=/var/lib XDG_STATE_HOME=/var/lib \\
        $REPO_ROOT/admin/.venv/bin/brokerctl create-caller --name my-agent --allow echo_api.echo

  Docker runner / encrypted vault / Infisical: fill in /etc/toolstack/admin.env, then
  'systemctl restart toolstack-admin'. For the SPS plugin (Infisical / Vault / localfile),
  fill in /etc/toolstack/sps.env and 'systemctl restart toolstack-sps'. See deploy/README.md.
EOF
