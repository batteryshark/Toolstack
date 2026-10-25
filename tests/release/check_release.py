"""One wheel build + isolated Python 3.11 installation, no source-path imports.

Run with Python 3.11+ and uv available. No services, Docker, providers or real secrets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def child_environment(parent, base):
    """Pure allowlist: never inherit application config or credential settings."""
    allowed = ('PATH', 'TMPDIR', 'SYSTEMROOT', 'WINDIR', 'LANG', 'LC_ALL',
               'LC_CTYPE', 'UV_CACHE_DIR', 'UV_PYTHON_INSTALL_DIR')
    env = {key: parent[key] for key in allowed if key in parent}
    env.update(HOME=str(base), XDG_CONFIG_HOME=str(base / 'config'),
               XDG_STATE_HOME=str(base / 'state'), XDG_CACHE_HOME=str(base / 'cache'),
               XDG_DATA_HOME=str(base / 'data'), XDG_RUNTIME_DIR=str(base / 'runtime'),
               PYTHONNOUSERSITE='1', TOOLSTACK_SPS_SKIP='1',
               UV_CONCURRENT_BUILDS='1', UV_CONCURRENT_INSTALLS='1')
    return env


def run(*args, cwd=ROOT, env=None):
    subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, help='retain successful wheel and proof JSON')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='toolstack-release-') as tmp:
        base = Path(tmp)
        env = child_environment(os.environ, base)
        for key in ('XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME',
                    'XDG_DATA_HOME', 'XDG_RUNTIME_DIR'):
            Path(env[key]).mkdir(mode=0o700)
        run('uv', 'build', '--python', '3.11', '--wheel', '--out-dir', base / 'dist', env=env)
        wheel, = (base / 'dist').glob('*.whl')
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            for package in ('admin', 'admin/views', 'broker', 'client', 'toolyard',
                            'sps', 'sps/plugins', 'toolstack_forwarder'):
                for source in (ROOT / package).glob('*.py'):
                    assert f'{package}/{source.name}' in names, source
            assert 'client/SKILL.md' in names
            assert 'admin/views/assets.py' in names  # UI CSS/JS are Python constants
            assert not any('/tests/' in n or '.env' in n or '__pycache__' in n for n in names)
            entrypoints = next(n for n in names if n.endswith('.dist-info/entry_points.txt'))
            assert 'admin = admin.__main__:main' in archive.read(entrypoints).decode()
        run('uv', 'venv', '--python', '3.11', base / 'venv', env=env)
        python = base / 'venv/bin/python'
        run('uv', 'pip', 'install', '--python', python, wheel,
            '-r', ROOT / 'admin/requirements.txt', '-c', ROOT / 'admin/requirements-lock.txt', env=env)
        script = '''
import importlib, pathlib, sys
assert sys.version_info[:2] == (3, 11), sys.version
for name in ('admin', 'admin.views.assets', 'admin.server', 'broker', 'client',
             'toolyard', 'sps', 'sps.plugins.localfile', 'toolstack_forwarder.__main__'):
    module = importlib.import_module(name)
    assert pathlib.Path(module.__file__).is_relative_to(sys.prefix), module.__file__
from admin.server import create_app
from admin import auth, settings
settings.write_password_hash(auth.hash_password('fake-release-password-only'))
assert create_app().routes
from sps.plugins.localfile import _Vault
vault = pathlib.Path.home() / 'fake.vault'
_Vault.init(str(vault), passphrase='fake-release-only')
v = _Vault(str(vault), 'fake-release-only')
v.set('demo', 'API_KEY', 'fake-only')
assert v.has('demo', 'API_KEY')
print('Python 3.11 installed wheel imports/admin app/localfile smoke OK')
'''
        run(python, '-I', '-c', script, cwd=base, env=env)
        for command in ('admin', 'sps', 'brokerctl', 'toolstack', 'toolyard'):
            run(base / 'venv/bin' / command, '--help', cwd=base, env=env)
        # Forwarder has no argparse/help mode: absent config must fail before networking.
        result = subprocess.run([str(base / 'venv/bin/toolstack-forwarder')], cwd=base,
                                env=env, capture_output=True, text=True)
        assert result.returncode != 0 and 'toolyard.toml' in result.stderr, result.stderr
        run('uv', 'pip', 'check', '--python', python, cwd=base, env=env)
        if args.artifact_dir:
            args.artifact_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(wheel, args.artifact_dir / wheel.name)
            report = {
                'source_revision': subprocess.check_output(
                    ['git', 'rev-parse', 'HEAD'], cwd=ROOT, env=env, text=True).strip(),
                'python': subprocess.check_output([str(python), '--version'], env=env, text=True).strip(),
                'wheel': wheel.name,
                'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
                'checks': ['wheel contents and entrypoint', 'isolated clean dependency install',
                           'installed-path imports with -I', 'admin app factory',
                           'fake localfile vault write/presence', 'CLI help',
                           'forwarder missing-config rejection', 'uv pip check'],
                'result': 'passed',
                'scope': 'Packaging smoke only; no listeners, providers, services or full E2E',
            }
            (args.artifact_dir / 'proof.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Release packaging checks passed')


if __name__ == '__main__':
    main()
