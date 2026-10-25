"""Fake-only manual acceptance backend. Default/prepare never create a listener."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import os
import plistlib
import pwd
import shutil
import signal
import stat
import subprocess
from pathlib import Path
import socket
import sys
import threading
import time
import uuid
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
TEMP = Path('/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode')
PASSWORD = 'FAKE-live-ui-only-password'
APP_HASH = '28cf9127f93d4ffd30fe7d91d120b862d4e2fc1c3a845b50210bd6a369b18600'


def environment(root: Path) -> dict[str, str]:
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(root / 'home'),
            'XDG_CONFIG_HOME': str(root / 'config'),
            'XDG_STATE_HOME': str(root / 'state'), 'TMPDIR': str(root / 'tmp'),
            'PYTHONPATH': str(SOURCE), 'PYTHONDONTWRITEBYTECODE': '1',
            'TOOLSTACK_SPS_SKIP': '1', 'TOOLSTACK_SPS_ENV': str(root / 'absent.env')}


def validate_root(value: str) -> Path:
    root = Path(value)
    if not root.is_absolute() or root.parent != TEMP or not root.name.startswith('toolstack-live-ui-'):
        raise ValueError(f'root must be a new toolstack-live-ui-* direct child of {TEMP}')
    if root.exists() or root.is_symlink():
        raise ValueError('root must be absent; refusing adoption')
    for parent in (TEMP, *TEMP.parents):
        if parent.is_symlink():
            raise ValueError('symlink ancestor refused')
    return root


def runtime_report() -> dict:
    found = {}
    for name in ('fastapi', 'uvicorn', 'pywebview', 'pyobjc-core', 'pyobjc-framework-Cocoa', 'pyobjc-framework-WebKit'):
        try:
            found[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            found[name] = 'MISSING'
    return found


def bootstrap(root: Path):
    from admin import auth, settings, broker_config
    from broker import operations
    from broker.store import Store
    for name in ('home', 'config', 'state', 'tmp', 'tools', 'external'):
        (root / name).mkdir(mode=0o700)
    # Declarations only: nothing executable and no broker or tool is started.
    for name, folder in [('fake-zero', root / 'tools' / 'fake-zero'),
                         ('fake-read', root / 'tools' / 'fake-read'),
                         ('fake-external', root / 'external')]:
        folder.mkdir(mode=0o700, exist_ok=True)
        text = f'id="{name}"\ntype="api"\n[entrypoint]\nport=1\n'
        if name == 'fake-read':
            text += '\n[[operations]]\nname="read"\nrisk="read"\ndescription="FAKE declaration only"\n'
        (folder / 'toolyard.toml').write_text(text)
    broker_config.save(broker_config.BrokerRunConfig(
        port=0, db_path=str(root / 'fake.sqlite'), tools_root=str(root / 'tools'),
        tool_dirs=[str(root / 'external')]))
    settings.write_password_hash(auth.hash_password(PASSWORD))
    store = Store(str(root / 'fake.sqlite'))
    try:
        for name in ('FAKE-policy', 'FAKE-rotate', 'FAKE-revoke'):
            operations.create_caller(store, name, ['fake-read.read'], [], 'FAKE-bootstrap')
        store.set_catalog_receipt(None)
    finally:
        store.close()


def check_stop(stop):
    if stop is not None and stop.is_set():
        raise InterruptedError('fixture stop requested; admission closed')


@contextmanager
def stop_handlers():
    stop = threading.Event()
    previous = {}
    def handler(signum, frame):
        stop.set()
    try:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            previous[sig] = signal.signal(sig, handler)
        yield stop
    finally:
        for sig, old in previous.items():
            signal.signal(sig, old)


def native_copy(app: Path, root: Path, identity: str, env: dict, stop=None):
    """Called only after future admission; never edit the original artifact."""
    if not identity.startswith('Apple Development:'):
        raise ValueError('explicit existing Apple Development identity required')
    if app.is_symlink() or not app.is_dir():
        raise ValueError('app must be a real directory')
    app = app.resolve()
    for item in app.rglob('*'):
        mode = item.lstat().st_mode
        if stat.S_ISLNK(mode):
            if not item.resolve().is_relative_to(app):
                raise ValueError('external bundle link')
        elif not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError('special bundle file')
    def command(*args):
        check_stop(stop)
        command_env = dict(env)
        owner_home = pwd.getpwuid(os.getuid()).pw_dir
        if not owner_home or not Path(owner_home).is_absolute() or owner_home == '/':
            raise ValueError('OS account owner home must be an absolute non-root path')
        command_env['HOME'] = owner_home
        return subprocess.run(['/usr/bin/codesign', *args], check=True, timeout=30,
                              env=command_env, capture_output=True, text=True)
    command('--verify', '--deep', '--strict', str(app))
    signature = command('-dv', '--verbose=4', str(app))
    if f'Authority={identity}' not in signature.stderr.splitlines():
        raise ValueError('original signing identity mismatch')
    binary = app / 'Contents/MacOS/ToolstackApp'
    if hashlib.sha256(binary.read_bytes()).hexdigest() != APP_HASH:
        raise ValueError('original executable hash mismatch')
    copy = root / 'Fixture.app'
    check_stop(stop)
    shutil.copytree(app, copy, symlinks=True)
    info = copy / 'Contents/Info.plist'
    if info.is_symlink():
        raise ValueError('Info.plist must not be a link')
    data = plistlib.loads(info.read_bytes())
    identifier = 'com.toolstack.operator.fixture.' + uuid.uuid4().hex
    data['CFBundleIdentifier'] = identifier
    info.write_bytes(plistlib.dumps(data))
    command('--force', '--deep', '--sign', identity, '--timestamp=none', str(copy))
    command('--verify', '--deep', '--strict', str(copy))
    return copy / 'Contents/MacOS/ToolstackApp', identifier


def native_url(url):
    return url + '#toolstack-fixture-' + uuid.uuid4().hex


def launch(argv, env, children, identity, record, stop=None):
    check_stop(stop)
    proc = subprocess.Popen(argv, env=env, cwd=SOURCE)
    child = {'proc': proc, 'pid': proc.pid, 'identity': None}
    children.append(child)
    if type(proc.pid) is int and proc.pid > 1:
        child['identity'] = identity(proc.pid)
    record()  # persist ownership before any subsequent action
    if child['identity'] is None:
        raise RuntimeError('child identity unavailable; cleanup uncertain')


def stop_child(child, identity):
    proc = child['proc']
    if proc.poll() is not None:
        proc.wait(timeout=5)
        return 'reaped'
    def current():
        return (type(child['pid']) is int and child['pid'] > 1
                and type(proc.pid) is int and proc.pid == child['pid']
                and child['identity'] is not None and identity(child['pid']) == child['identity'])
    if not current():
        return 'uncertain: identity mismatch; not signalled'
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if not current():
            return 'uncertain: identity changed before kill'
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return 'uncertain: kill wait expired'
    return 'reaped'


def wait_ready(server, thread, errors, seconds=10, stop=None):
    check_stop(stop)
    deadline = time.monotonic() + seconds
    while not server.started:
        check_stop(stop)
        if errors or not thread.is_alive() or time.monotonic() >= deadline:
            raise RuntimeError('backend readiness failed; no app launch')
        time.sleep(.02)
    if errors or not thread.is_alive():
        raise RuntimeError('backend exited during readiness')


def serve(root: Path, native_app=None, sign_identity=None, desktop=False):
    with stop_handlers() as stop:
        try:
            _serve(root, native_app, sign_identity, desktop, stop)
        except InterruptedError:
            pass  # controlled stop; owned cleanup already ran


def _serve(root, native_app, sign_identity, desktop, stop):
    check_stop(stop)
    os.umask(0o077)
    # Exclusive mkdir; never follow/adopt a pre-existing root.
    root.mkdir(mode=0o700)
    os.environ.clear()
    os.environ.update(environment(root))
    sys.path.insert(0, str(SOURCE))
    bootstrap(root)
    from admin.server import create_app
    from toolyard.runner import _process_identity
    import uvicorn
    # Suppress only automatic reconciliation, not routes/auth/product responses.
    with patch('admin.server.start_reconciler_thread', return_value=None):
        app = create_app()
    with socket.socket() as sock:
        check_stop(stop)
        sock.bind(('127.0.0.1', 0))
        url = f'http://127.0.0.1:{sock.getsockname()[1]}'
        record = {'url': url, 'pid': os.getpid(), 'identity': _process_identity(os.getpid()),
                  'budget_seconds': 1200, 'fake_password': PASSWORD, 'runtime': runtime_report()}
        children, errors = [], []
        def save():
            record['children'] = [{k: v for k, v in child.items() if k != 'proc'} for child in children]
            (root / 'fixture.json').write_text(json.dumps(record, indent=2))
        save()
        server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', log_level='warning',
                                              timeout_graceful_shutdown=5))
        def run():
            try:
                server.run(sockets=[sock])
            except BaseException as exc:
                errors.append(repr(exc))
        thread = threading.Thread(target=run, daemon=True)
        try:
            check_stop(stop)
            thread.start()
            deadline = time.monotonic() + 1200
            print(json.dumps(record), flush=True)
            wait_ready(server, thread, errors, stop=stop)
            if native_app:
                check_stop(stop)
                binary, identifier = native_copy(Path(native_app), root, sign_identity, environment(root), stop)
                account = native_url(url)
                record['native'] = {'original': str(native_app), 'original_sha256': APP_HASH,
                                    'copy': str(binary), 'bundle_id': identifier, 'account_url': account}
                save()
                wait_ready(server, thread, errors, stop=stop)
                launch([str(binary), '-ToolstackAdminURL', account],
                       {**environment(root), 'TOOLSTACK_ADMIN_URL': account}, children, _process_identity, save, stop)
            if desktop:
                wait_ready(server, thread, errors, stop=stop)
                launch([sys.executable, '-m', 'desktop'],
                       {**environment(root), 'TOOLSTACK_ADMIN_URL': url}, children, _process_identity, save, stop)
            while thread.is_alive() and time.monotonic() < deadline and not stop.is_set():
                stop.wait(.1)
            if errors or not thread.is_alive():
                raise RuntimeError(f'backend exited unexpectedly: {errors}')
        finally:
            for child in reversed(children):
                try:
                    child['cleanup'] = stop_child(child, _process_identity)
                except Exception as exc:
                    child['cleanup'] = 'uncertain: ' + repr(exc)
            server.should_exit = True
            if thread.ident is not None:
                thread.join(7)
            record.update(backend_stopped=not thread.is_alive(), backend_errors=errors,
                          cleanup_uncertain=thread.is_alive() or bool(errors) or
                          any(c.get('cleanup') != 'reaped' for c in children))
            save()
            (root / 'stopped.json').write_text(json.dumps(record, indent=2))
            if record['cleanup_uncertain']:
                raise RuntimeError('fixture cleanup uncertain; see private fixture/stopped records')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--prepare', action='store_true', help='report only; creates nothing')
    mode.add_argument('--serve', action='store_true', help='future parent/chief hands admission ONLY')
    parser.add_argument('--root', help='absent approved-temp child; required for serve')
    parser.add_argument('--native-app', help='existing verified original; future private copy only')
    parser.add_argument('--sign-identity', help='explicit existing Apple Development identity')
    parser.add_argument('--desktop', action='store_true', help='future owned pywebview launch')
    args = parser.parse_args(argv)
    if (args.native_app or args.sign_identity or args.desktop) and not args.serve:
        parser.error('app flags require --serve')
    if bool(args.native_app) != bool(args.sign_identity):
        parser.error('--native-app and --sign-identity are required together')
    if not args.serve:
        print(json.dumps({'status': 'OFF', 'runtime': runtime_report(),
                          'apps_launched': False, 'listener': False}, indent=2))
        return
    if not args.root:
        parser.error('--serve requires --root')
    serve(validate_root(args.root), args.native_app, args.sign_identity, args.desktop)


if __name__ == '__main__':
    main()
