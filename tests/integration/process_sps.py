"""Finite fake-data process/SPS release proof; requires an explicitly owned root."""
from __future__ import annotations
import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request
import urllib.error
import uuid


def private_root(raw):
    path = Path(raw)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute normalized root required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('parent must be owned mode 0700')
        os.mkdir(path.name, 0o700, dir_fd=fd)
    finally:
        os.close(fd)
    return path


def tool(raw):
    root = Path(raw)
    assert root.is_absolute() and str(root) == os.environ.get('HOME')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in root.parts[1:]:
            assert part not in ('.', '..')
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
        markerfd = os.open('fixture.marker', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(markerfd) as stream:
            mi = os.fstat(stream.fileno())
            assert stat.S_ISREG(mi.st_mode) and mi.st_uid == os.getuid() and stat.S_IMODE(mi.st_mode) == 0o600
            assert json.load(stream) == {'device': info.st_dev, 'inode': info.st_ino}
    finally:
        os.close(fd)
    assert os.environ.get('TOOLSTACK_SPS_HOST') == '127.0.0.1'
    assert os.environ.get('TOOLSTACK_TOOL_CONFIG') == str(root / 'external/slice/toolyard.toml')
    assert os.environ.get('TOOLSTACK_SPS_CA') == str(root / 'sps.crt')
    for path in (root / 'external', root / 'external/slice', root / 'external/slice/toolyard.toml', root / 'sps.crt'):
        assert not path.is_symlink() and path.stat().st_uid == os.getuid()
    import hmac
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from sps.tool_sdk import SecretClient
    assert os.environ.get('TOOLSTACK_SPS_VERIFY') in ('1', 'true')
    sdk = SecretClient.from_env('slice')
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if not hmac.compare_digest(self.headers.get('X-Toolstack-Secret', ''), os.environ['TOOLSTACK_CHANNEL_SECRET']):
                self.send_response(401)
                self.end_headers()
                return
            value = sdk.refresh('proof')
            data = json.dumps({'string': isinstance(value, str), 'gate': isinstance(value, str) and value.startswith('FAKE-SLICE-')}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    HTTPServer(('127.0.0.1', int(os.environ['TOOLSTACK_PORT'])), Handler).serve_forever()


def main(root):
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from sps.client import SPSClient, AuthError, NotFound
    from sps.plugins.localfile import _Vault
    from toolyard.cli import state_lock, _save_state
    from toolyard.config import load
    from toolyard.runner import ProcessRunner, _process_identity, _boot_id, reregister_all_with_sps_detailed
    from admin.sps_watchdog import SPSWatchdog
    from types import SimpleNamespace
    assert cryptography.__version__ == '50.0.2'
    os.umask(0o077)
    temp = private_root(root)
    # Resolve import roots from installed modules, never from the script location.
    import sps, toolyard, admin
    sources = list(dict.fromkeys(str(Path(m.__file__).resolve().parent.parent) for m in (sps, toolyard, admin)))
    info = temp.stat()
    (temp / 'fixture.marker').write_text(json.dumps({'device': info.st_dev, 'inode': info.st_ino}))
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(temp), 'TMPDIR': str(temp), 'TMP': str(temp), 'TEMP': str(temp),
           'PYTHONPATH': os.pathsep.join(sources), 'PYTHONNOUSERSITE': '1', 'PYTHONUNBUFFERED': '1'}
    for name in ('CONFIG', 'STATE', 'DATA', 'CACHE', 'RUNTIME'):
        p = temp / name.lower()
        p.mkdir(mode=0o700)
        env['XDG_' + name + '_HOME' if name != 'RUNTIME' else 'XDG_RUNTIME_DIR'] = str(p)
    os.environ.clear()
    os.environ.update(env)
    evidence = {'platform': platform.platform(), 'python': platform.python_version(), 'cryptography': cryptography.__version__, 'checks': [], 'processes': [], 'cleanup': 'unknown', 'status': 'FAIL'}
    children = []
    running = None
    runner = ProcessRunner()
    sensitive = []
    spawned = []
    stage = 'preflight'
    def check(name, condition=True):
        if not condition:
            raise AssertionError(name)
        evidence['checks'].append(name)
    def start(label):
        with open(temp / (label + '.log'), 'ab') as log:
            p = subprocess.Popen([sys.executable, '-m', 'sps.cli', 'serve', '--config', str(config)], env={**env, 'SP_VAULT_PASSPHRASE': password, 'TOOLSTACK_SPS_BOOT_ID_PATH': str(temp / 'boot')}, cwd=temp, stdout=log, stderr=log, start_new_session=True)
        children.append((p, _process_identity(p.pid)))
        evidence['processes'].append({'label': label, 'pid': p.pid, 'identity': children[-1][1]})
        return p
    def stop(p, identity):
        if p.poll() is None:
            assert p.pid > 1 and identity and _process_identity(p.pid) == identity
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                assert _process_identity(p.pid) == identity
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=3)
        p.wait(timeout=1)
    def ready(fn):
        deadline = time.monotonic() + 10
        while True:
            try:
                return fn()
            except (OSError, RuntimeError, ValueError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('readiness deadline') from None
                time.sleep(.05)
    def interrupt(*args):
        raise KeyboardInterrupt()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, interrupt)
    signal.alarm(100)
    try:
        check('host boot identity preflight', bool(_boot_id()))
        def port():
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                return s.getsockname()[1]
        sp, tp = port(), port()
        evidence['ports'] = {'sps': sp, 'tool': tp}
        def certificate(prefix):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'localhost')])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False).sign(key, hashes.SHA256()))
            ca = temp / (prefix + '.crt')
            ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            kp = temp / (prefix + '.key')
            kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            return str(ca), str(kp)
        ca, key = certificate('sps')
        badca, _ = certificate('unknown')
        secret, password, fake, changed = [prefix + uuid.uuid4().hex for prefix in ('FAKE-SP-', 'FAKE-PASSWORD-', 'FAKE-SLICE-', 'FAKE-OTHER-')]
        sensitive.extend([secret, password, fake, changed])
        vaultfile = temp / 'vault.json'
        _Vault.init(vaultfile, password)
        vault = _Vault(vaultfile, password)
        vault.set('slice', 'PROOF', fake)
        config = temp / 'sps.env'
        config.write_text('\n'.join(f'{k} = {json.dumps(v)}' for k, v in {'SP_HOST': '127.0.0.1', 'SP_PORT': str(sp), 'SP_SECRET': secret, 'SP_TLS_CERT': ca, 'SP_TLS_KEY': key, 'SP_TLS_CA': ca, 'SP_AUDIT_LOG': str(temp / 'sps.audit'), 'SP_PLUGIN': 'localfile'}.items()) + '\n[localfile]\nVAULT_FILE = ' + json.dumps(str(vaultfile)) + '\n')
        stage = 'initial SPS'
        sps = start('sps')
        registrar = SPSClient('127.0.0.1', sp, sp_secret=secret, ca_file=ca, timeout=2)
        boot = ready(registrar.ping)['boot_id']
        check('verified TLS ping')
        try:
            SPSClient('127.0.0.1', sp, sp_secret=secret, ca_file=badca, timeout=2).ping()
        except Exception as exc:
            check('unknown CA rejected', str(exc) == 'SSLCertVerificationError')
        else:
            raise AssertionError('unknown CA accepted')
        toolpath = temp / 'external' / 'slice'
        toolpath.mkdir(parents=True)
        (temp / 'tools').mkdir()
        manifest = toolpath / 'toolyard.toml'
        command = shlex.join([sys.executable, str(Path(__file__).resolve()), 'tool', str(temp)])
        manifest.write_text(f'id = "slice"\ntype = "api"\n[entrypoint]\nport = {tp}\ncommand = {json.dumps(command)}\n[[operations]]\nname = "check"\nrisk = "read"\n[[secrets]]\nname = "proof"\nfield = "PROOF"\n')
        os.environ.update({'TOOLSTACK_SPS_ENV': str(config), 'TOOLSTACK_SPS_VERIFY': 'true', 'TOOLSTACK_TOOLYARD_CHANNEL_STATE': str(temp / 'channels.json')})
        stage = 'runner start'
        # Transparent observation of the real spawn; arguments and environment
        # are neither retained nor modified. Restore even on partial failure.
        original_spawn = os.posix_spawn
        def observed_spawn(*args, **kwargs):
            pid = original_spawn(*args, **kwargs)
            record = {'label': 'runner spawn', 'pid': pid, 'identity': _process_identity(pid), 'boot': _boot_id()}
            spawned.append(record)
            evidence['processes'].append(record)
            return pid
        try:
            os.posix_spawn = observed_spawn
            with state_lock():
                running = runner.start(load(manifest))
                _save_state({'slice': asdict(running)})
        finally:
            os.posix_spawn = original_spawn
        stage = 'channel checks'
        sensitive.extend([running.e_secret, running.channel_secret])
        evidence['processes'].append({'label': 'tool', 'pid': int(running.handle), 'identity': running.process_identity, 'boot': running.boot_id})
        check('independent credentials', running.e_secret != running.channel_secret)
        publication = (temp / 'channels.json').read_text()
        check('channel publication excludes SPS credentials', secret not in publication and running.e_secret not in publication)
        def request(credential):
            req = urllib.request.Request(f'http://127.0.0.1:{tp}/check', data=b'{}', headers={'X-Toolstack-Secret': credential})
            with urllib.request.urlopen(req, timeout=3) as response:
                return json.load(response)
        check('SDK refresh string and safe boolean', ready(lambda: request(running.channel_secret)) == {'string': True, 'gate': True})
        try:
            request(running.e_secret)
        except urllib.error.HTTPError as exc:
            check('SPS credential rejected by channel', exc.code == 401)
            exc.close()
        else:
            raise AssertionError('cross-use accepted')
        try:
            SPSClient('127.0.0.1', sp, esecret=running.channel_secret, ca_file=ca, timeout=2).get_secrets('slice')
        except AuthError:
            check('channel credential rejected by SPS')
        else:
            raise AssertionError('cross-use accepted')
        stage = 'restart and recovery'
        stop(*children[0])
        sps = start('sps-restart')
        newboot = ready(registrar.ping)['boot_id']
        evidence['boots'] = [boot, newboot]
        check('restart new boot', boot != newboot)
        client = SPSClient('127.0.0.1', sp, esecret=running.e_secret, ca_file=ca, timeout=2)
        try:
            client.get_secrets('slice')
        except (AuthError, NotFound):
            check('registrations lost')
        else:
            raise AssertionError('registration survived')
        attempts = []
        def recover(**kwargs):
            attempts.append(newboot)
            if len(attempts) == 1:
                hidden = manifest.with_suffix('.hidden')
                manifest.rename(hidden)
                try:
                    result = reregister_all_with_sps_detailed(**kwargs)
                finally:
                    hidden.rename(manifest)
                check('actual first recovery incomplete', not result.complete)
                return result
            result = reregister_all_with_sps_detailed(**kwargs)
            check('actual second recovery complete', result.complete and result.count == 1)
            return result
        watchdog = SPSWatchdog(config=SimpleNamespace(tools_root=str(temp / 'tools'), tool_dirs=[str(toolpath)]), probe=lambda: registrar.ping()['boot_id'], re_register_fn=recover, sps_env_path=str(config))
        watchdog._check_once()
        check('incomplete boot unacknowledged', watchdog._last_seen is None)
        watchdog._check_once()
        check('same boot retry', attempts == [newboot, newboot] and watchdog._last_seen == newboot)
        check('new TLS retrieval', client.get_secret('slice', 'proof') == fake)
        vault.set('slice', 'PROOF', changed)
        check('persisted change affects next SDK refresh', request(running.channel_secret) == {'string': True, 'gate': False})
        check('same live tool identity', runner.is_alive(running) and _process_identity(int(running.handle)) == running.process_identity)
        check('vault encrypted', all(v.encode() not in vaultfile.read_bytes() for v in (fake, changed)))
        evidence['status'] = 'PASS'
    except BaseException as exc:
        evidence['failure_type'] = type(exc).__name__
        evidence['failure_stage'] = stage
    finally:
        signal.alarm(0)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        clean = True
        if running:
            try:
                runner.stop(running)
                deadline = time.monotonic() + 4
                while True:
                    try:
                        pid, _ = os.waitpid(int(running.handle), os.WNOHANG)
                    except ChildProcessError:
                        break
                    if pid:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('tool reap deadline')
                    time.sleep(.05)
                with state_lock():
                    _save_state({})
            except BaseException:
                clean = False
        for record in spawned:
            try:
                pid, identity = record['pid'], record['identity']
                assert pid > 1 and identity and record['boot'] == _boot_id()
                current = _process_identity(pid)
                if current is not None:
                    assert current == identity
                    os.kill(pid, signal.SIGTERM)
                deadline = time.monotonic() + 3
                killed = False
                while True:
                    try:
                        reaped, _ = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        assert _process_identity(pid) is None
                        break
                    if reaped:
                        break
                    if time.monotonic() >= deadline:
                        if killed:
                            raise RuntimeError('partial child reap deadline')
                        assert _process_identity(pid) == identity
                        os.kill(pid, signal.SIGKILL)
                        killed = True
                        deadline = time.monotonic() + 3
                    time.sleep(.05)
                record['cleanup'] = 'reaped and absent'
                assert _process_identity(pid) is None
            except BaseException:
                clean = False
        for child, identity in reversed(children):
            try:
                stop(child, identity)
            except BaseException:
                clean = False
        logs = list(temp.rglob('*.log')) + list(temp.rglob('*.audit'))
        if running:
            logs.append(Path(running.log_path))
        try:
            check('logs and audit exclude all fake values and credentials', all(value not in p.read_text() for p in logs for value in sensitive))
        except BaseException:
            evidence['status'] = 'FAIL'
        evidence['cleanup'] = 'reaped' if clean else 'unknown'
        if not clean:
            evidence['status'] = 'FAIL'
        (temp / 'result.json').write_text(json.dumps(evidence, indent=2))
        print(json.dumps(evidence))
    return 0 if evidence['status'] == 'PASS' else 1


if __name__ == '__main__':
    def early_interrupt(*args):
        raise KeyboardInterrupt()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, early_interrupt)
    if len(sys.argv) == 3 and sys.argv[1] == 'tool':
        tool(sys.argv[2])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--root', required=True)
        args = parser.parse_args()
        try:
            code = main(args.root)
        except BaseException as exc:
            print(json.dumps({'status': 'FAIL', 'failure_stage': 'setup-or-reporting', 'failure_type': type(exc).__name__, 'cleanup': 'unknown; inspect private evidence'}))
            code = 1
        finally:
            signal.alarm(0)
        sys.exit(code)
