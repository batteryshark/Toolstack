#!/usr/bin/env python3
"""Offline SPS bootstrap; never starts a server or provisions a secret value."""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', default='/etc/toolstack/sps.env')
    p.add_argument('--state-dir', default='/var/lib/toolstack')
    p.add_argument('--log-dir', default='/var/log/toolstack')
    args = p.parse_args()
    os.umask(0o077)
    config = Path(args.config).resolve()
    state = Path(args.state_dir).resolve()
    logs = Path(args.log_dir).resolve()
    if config.exists():
        p.error('config exists; refusing to overwrite')
    for directory in (config.parent, state, logs):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    env = dict(os.environ)
    env.pop('SP_VAULT_PASSPHRASE', None)
    env.pop('SP_VAULT_PASSPHRASE_FILE', None)
    subprocess.run([sys.executable, '-m', 'sps.cli', 'init', '--config', str(config),
                    '--state-dir', str(state), '--audit-log', str(logs / 'sps.audit')],
                   env=env, check=True)
    config.chmod(0o600)
    print('Bootstrap complete; set ownership and provision the vault offline before starting SPS.')


if __name__ == '__main__':
    main()
