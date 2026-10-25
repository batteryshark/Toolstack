#!/usr/bin/env python3
"""Run the opt-in real-release integration fixture with a scrubbed environment."""
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEMP = Path('/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode')

if __name__ == '__main__':
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='toolstack-e2e-', dir=TEMP) as directory:
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': directory,
               'TMPDIR': directory, 'PYTHONPATH': str(ROOT),
               'TOOLSTACK_E2E_ROOT': directory, 'PYTHONUNBUFFERED': '1',
               'PYTHONNOUSERSITE': '1',
               **{key: str(Path(directory) / key.lower()) for key in
                  ('XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR')}}
        child = subprocess.Popen([sys.executable, str(ROOT / 'tests/integration/vertical_slice.py')],
                                 cwd=ROOT, env=env)
        try:
            code = child.wait(timeout=270)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            # Let the fixture's finally stop independently grouped services before
            # TemporaryDirectory removes their files. Never broad-kill a session.
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            code = child.wait(timeout=30)
        raise SystemExit(code)
