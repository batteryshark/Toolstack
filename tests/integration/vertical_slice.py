"""Real local vertical slice. Not a host-isolation or deployment acceptance test.

Only published Nod is downloaded; every runtime request is literal loopback.
All children inherit a constructed environment, never the invoking shell's.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import socket
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
URL = 'https://github.com/batteryshark/nod/releases/download/v1.0.1/nod-server-v1.0.1-aarch64-apple-darwin.tar.gz'
DIGEST = '43cf90c0043759f3ace7beb13c76878ada19efed9f9dbced536cf674556d4bf0'
APPROVED = Path('/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def api(base, path, token='', body=None, method=None):
    assert base.startswith('http://127.0.0.1:')
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(base + path, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method=method)
    with urllib.request.urlopen(req, timeout=3) as response:
        return json.loads(response.read() or b'null')


def ready(fn, processes):
    deadline = time.monotonic() + 12
    last = None
    while time.monotonic() < deadline:
        assert all(p.poll() is None for p in processes), 'owned service exited during readiness'
        try:
            return fn()
        except (OSError, ValueError, RuntimeError) as exc:
            last = exc
            time.sleep(.05)  # bounded service readiness only, not agent/model polling
    raise RuntimeError('readiness deadline') from last


def fixture_tool():
    import hmac
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from sps.tool_sdk import SecretClient
    sdk = SecretClient.from_env('slice')

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            expected = os.environ['TOOLSTACK_CHANNEL_SECRET']
            authorized = hmac.compare_digest(self.headers.get('X-Toolstack-Secret', ''), expected)
            if not authorized:
                self.send_response(401)
                self.end_headers()
                return
            # Fetch anew over verified TLS each invocation, not merely a startup cache.
            value = sdk.refresh('proof')
            with open(Path(os.environ['HOME']) / 'effects', 'a') as effect:
                effect.write('effect\n')
            # Secret affects a safe boolean; neither value nor reversible encoding is returned.
            result = {'secret_gate': value.startswith('FAKE-SLICE-'), 'operation': self.path.rsplit('/', 1)[-1]}
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    HTTPServer(('127.0.0.1', int(os.environ['TOOLSTACK_PORT'])), Handler).serve_forever()


def main():
    import cryptography
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from broker.identity import hash_token
    from broker.store import Store
    from sps.cli import maybe_generate_tls_material
    from sps.client import SPSClient, AuthError, NotFound
    from sps.plugins.localfile import _Vault
    from toolyard.cli import state_lock, _save_state
    from toolyard.config import load
    from toolyard.runner import ProcessRunner, _process_identity, reregister_all_with_sps_detailed
    from admin.sps_watchdog import SPSWatchdog
    from types import SimpleNamespace

    temp = Path(os.environ['TOOLSTACK_E2E_ROOT']).resolve()
    assert temp.is_relative_to(APPROVED) and temp != APPROVED
    assert cryptography.__version__ == '50.0.2'
    os.umask(0o077)
    base_env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(temp),
                'TMPDIR': str(temp), 'PYTHONPATH': str(ROOT), 'PYTHONUNBUFFERED': '1',
                'PYTHONNOUSERSITE': '1',
                **{name: str(temp / name.lower()) for name in
                   ('XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR')}}
    for name, value in base_env.items():
        if name.startswith('XDG_'):
            Path(value).mkdir(mode=0o700, exist_ok=True)
    os.environ.clear()
    os.environ.update(base_env)
    processes = []
    evidence = {'nod_release': 'v1.0.1', 'archive_sha256': DIGEST,
                'python': sys.version.split()[0], 'cryptography': cryptography.__version__,
                'checks': [], 'processes': []}
    runner = ProcessRunner()
    running = None
    admin = None
    operator = None
    supervised = None

    def check(name, condition=True):
        assert condition, name
        evidence['checks'].append(name)

    def start(label, argv, extra=None):
        log = open(temp / (label + '.log'), 'ab')
        try:
            proc = subprocess.Popen(argv, cwd=ROOT, env={**base_env, **(extra or {})},
                                    stdout=log, stderr=log, start_new_session=True)
        finally:
            log.close()
        identity = _process_identity(proc.pid)
        assert identity is not None
        processes.append((proc, identity, label))
        evidence['processes'].append({'label': label, 'pid': proc.pid, 'identity': identity})
        return proc

    def stop(proc):
        record = next(x for x in processes if x[0] is proc)
        if proc.poll() is None:
            assert proc.pid > 1 and _process_identity(proc.pid) == record[1]
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                assert _process_identity(proc.pid) == record[1]
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=3)

    def cli(*args, success=True):
        result = subprocess.run([sys.executable, '-m', 'client.toolstack', *args],
                                env={**base_env, 'TOOLSTACK_URL': broker_url,
                                     'TOOLSTACK_TOKEN': agent_token}, cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == (0 if success else 1), 'CLI unexpected exit (output withheld)'
        check('CLI output contains no fake secret', fake not in result.stdout + result.stderr)
        return json.loads(result.stdout)

    def interrupted(signum, frame):
        raise KeyboardInterrupt('fixture interrupted; cleaning owned processes')

    signal.signal(signal.SIGTERM, interrupted)
    try:
        # HTTPS public artifact only; do not consult installed Nod or existing data.
        archive = temp / 'nod.tar.gz'
        with urllib.request.urlopen(URL, timeout=45) as response:
            blob = response.read(64 * 1024 * 1024 + 1)
        assert len(blob) <= 64 * 1024 * 1024
        assert hashlib.sha256(blob).hexdigest() == DIGEST
        archive.write_bytes(blob)
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                assert not path.is_absolute() and '..' not in path.parts
                assert member.isfile() or member.isdir(), 'links/special archive members refused'
                assert member.size <= 64 * 1024 * 1024, 'oversize archive member'
            assert sum(m.size for m in members) <= 128 * 1024 * 1024
            tar.extractall(temp / 'release', filter='data')
        binary, = list((temp / 'release').rglob('nod-server'))
        binary.chmod(0o700)
        evidence['nod_binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        np, sp, tp, bp = (free_port() for _ in range(4))
        nod_url = f'http://127.0.0.1:{np}'
        broker_url = f'http://127.0.0.1:{bp}'
        evidence['ports'] = {'nod': np, 'sps_tls': sp, 'tool': tp, 'broker': bp}
        admin_token = 'FAKE-nod-admin-' + uuid.uuid4().hex
        nod = start('nod', [str(binary)], {'NOD_BIND': f'127.0.0.1:{np}',
                    'NOD_ADMIN_TOKEN': admin_token, 'NOD_DATABASE_URL': f'sqlite://{temp}/nod.sqlite',
                    'NOD_DATA_DIR': str(temp / 'nod-data'), 'NOD_CALLBACK_ALLOWED_ORIGINS': ''})
        ready(lambda: api(nod_url, '/health'), [nod])
        api(nod_url, '/api/v1/admin/users', admin_token, {'id': 'fake-user', 'name': 'Fake local user'})
        api(nod_url, '/api/v1/admin/channels', admin_token, {'id': 'slice', 'name': 'Fake slice'})
        code = api(nod_url, '/api/v1/admin/users/fake-user/enrollment-codes', admin_token,
                   {'expires_in_seconds': 600})['code']
        issuer = api(nod_url, '/api/v1/admin/issuer-tokens', admin_token,
                     {'name': 'fake-issuer', 'scopes': ['requests:write', 'requests:read']})['token']
        key = ec.generate_private_key(ec.SECP256R1())
        b64 = lambda value: base64.urlsafe_b64encode(value).decode().rstrip('=')
        public = b64(key.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint))
        enrolled = api(nod_url, '/api/v1/enroll', body={'code': code, 'device_name': 'FAKE software device',
                       'platform': 'linux', 'signing_key': {'key_id': 'fake-key',
                       'algorithm': 'p256_ecdsa_sha256', 'public_key': public}})
        device_token, device_id = enrolled['token'], enrolled['device_id']
        api(nod_url, '/api/v1/devices/me/subscriptions/slice', device_token,
            {'subscribed': True}, 'PUT')

        cert, keyfile, ca = (str(temp / name) for name in ('sps.crt', 'sps.key', 'ca.crt'))
        maybe_generate_tls_material(cert, keyfile, ca, '/CN=localhost')
        config = temp / 'sps.env'
        vaultfile = temp / 'vault.json'
        sp_secret = 'FAKE-SP-' + uuid.uuid4().hex
        passphrase = 'FAKE-PASSPHRASE-' + uuid.uuid4().hex
        fake = 'FAKE-SLICE-' + uuid.uuid4().hex
        _Vault.init(vaultfile, passphrase)
        vault = _Vault(vaultfile, passphrase)
        vault.set('slice', 'PROOF', fake)
        config.write_text('\n'.join(f'{k} = {json.dumps(v)}' for k, v in {
            'SP_HOST': '127.0.0.1', 'SP_PORT': str(sp), 'SP_SECRET': sp_secret,
            'SP_TLS_CERT': cert, 'SP_TLS_KEY': keyfile, 'SP_TLS_CA': ca,
            'SP_AUDIT_LOG': str(temp / 'sps.audit'), 'SP_PLUGIN': 'localfile'}.items())
            + f'\n[localfile]\nVAULT_FILE = {json.dumps(str(vaultfile))}\n')
        config.chmod(0o600)
        sps_env = {'SP_VAULT_PASSPHRASE': passphrase,
                   'TOOLSTACK_SPS_BOOT_ID_PATH': str(temp / 'sps.boot')}
        sps = start('sps', [sys.executable, '-m', 'sps.cli', 'serve', '--config', str(config)], sps_env)
        registrar = SPSClient('127.0.0.1', sp, sp_secret=sp_secret, ca_file=ca, timeout=2)
        boot = ready(registrar.ping, [sps])['boot_id']
        check('verified TLS ping')
        toolpath = temp / 'external/slice'
        toolpath.mkdir(parents=True)
        manifest = toolpath / 'toolyard.toml'
        manifest.write_text(f'''id = "slice"
type = "api"
[entrypoint]
port = {tp}
command = "{sys.executable} {Path(__file__).resolve()} tool"
[[operations]]
name = "check"
risk = "read"
approval_fields = ["/destination", "/credential"]
[[operations]]
name = "blocked"
risk = "read"
[[secrets]]
name = "proof"
field = "PROOF"
''')
        runner_env = {'TOOLSTACK_SPS_ENV': str(config), 'TOOLSTACK_SPS_VERIFY': 'true',
                      'TOOLSTACK_TOOLYARD_CHANNEL_STATE': str(temp / 'channels.json')}
        os.environ.update(runner_env)
        with state_lock():
            running = runner.start(load(manifest))
            _save_state({'slice': asdict(running)})
        evidence['processes'].append({'label': 'runner-tool', 'pid': int(running.handle),
                                      'identity': running.process_identity})
        check('independent credentials', running.e_secret != running.channel_secret)
        channels = (temp / 'channels.json').read_text()
        check('channel-only publication', running.e_secret not in channels and sp_secret not in channels)
        try:
            SPSClient('127.0.0.1', sp, esecret=running.channel_secret, ca_file=ca).get_secrets('slice')
        except AuthError:
            check('channel credential rejected by SPS')
        else:
            raise AssertionError('channel credential authenticated SPS')
        request = urllib.request.Request(f'http://127.0.0.1:{tp}/v1/actions/check', data=b'{}',
                                          headers={'X-Toolstack-Secret': running.e_secret})
        try:
            urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as exc:
            check('SPS credential rejected by tool channel', exc.code == 401)
            exc.close()
        else:
            raise AssertionError('SPS key authenticated tool channel')

        db = str(temp / 'broker.sqlite')
        agent_token = 'FAKE-agent-' + uuid.uuid4().hex
        store = Store(db)
        caller = store.add_caller('fake-agent')
        store.add_token(caller, hash_token(agent_token))
        policy = {'tools': {'slice': {'check': 'review', 'blocked': 'deny', 'refresh': 'deny'}}}
        store.set_policy(caller, policy)
        store.close()
        # The real admin owns broker creation from the beginning; never adopt a PID.
        from admin import auth, settings, broker_config
        (temp / 'tools').mkdir()
        password = 'FAKE-operator-' + uuid.uuid4().hex
        settings.write_password_hash(auth.hash_password(password))
        settings.rotate_session_secret()
        broker_config.save(broker_config.BrokerRunConfig(
            port=bp, db_path=db, tools_root=str(temp / 'tools'),
            tool_dirs=[str(toolpath)], nod_url=nod_url, nod_token=issuer,
            nod_channel='slice', rate_limit=0))
        ap = free_port()
        admin_url = f'http://127.0.0.1:{ap}'
        evidence['ports']['admin'] = ap
        admin_env = {**runner_env, 'TOOLSTACK_BROKER_HOST': '127.0.0.1'}

        def admin_start(label):
            child = start(label, [sys.executable, '-m', 'admin', 'serve', '--port', str(ap)], admin_env)
            ready(lambda: urllib.request.urlopen(admin_url + '/login', timeout=2).close(), [child])
            token = api(admin_url, '/api/login', body={'password': password})['token']
            return child, token

        def broker_start():
            nonlocal supervised
            status = api(admin_url, '/api/broker/start', operator, {})
            supervised = (status['pid'], _process_identity(status['pid']))
            assert status['healthy'] and supervised[1] is not None
            evidence['processes'].append({'label': 'admin-owned-broker', 'pid': supervised[0], 'identity': supervised[1]})

        def broker_stop():
            nonlocal supervised
            assert supervised and _process_identity(supervised[0]) == supervised[1]
            status = api(admin_url, '/api/broker/stop', operator, {})
            check('admin API stops and reaps owned broker', not status['running'] and _process_identity(supervised[0]) is None)
            supervised = None

        admin, operator = admin_start('admin')
        saved = api(admin_url, '/api/config', operator, {'approval_ttl': 420})
        check('JSON config save preserves external tool_dirs', saved['tool_dirs'] == [str(toolpath)])
        import httpx
        import re
        with httpx.Client(base_url=admin_url, trust_env=False, timeout=5) as web:
            web.cookies.set('toolstack_admin_session', operator)
            page = web.get('/config')
            csrf = re.search(r"name=['\"]_csrf['\"] value=['\"]([^'\"]+)", page.text).group(1)
            response = web.post('/config', data={'_csrf': csrf, 'approval_ttl': '421'})
            check('authenticated HTML config save', response.status_code == 200)
        check('HTML config preserves external tool_dirs', api(admin_url, '/api/config', operator)['tool_dirs'] == [str(toolpath)])
        broker_start()
        denied = cli('call', 'slice.blocked', '{}', success=False)
        check('explicit deny policy', denied['status'] == 'denied')
        denied = cli('call', 'slice.refresh', '{}', success=False)
        check('explicit refresh deny', denied['status'] == 'denied')
        private = 'FAKE-private-' + uuid.uuid4().hex
        reason = 'FAKE-reason-' + uuid.uuid4().hex
        arguments = json.dumps({'destination': 'safe-fixture-destination', 'credential': private, 'unselected': 'omitted-fixture'})
        call = ('call', 'slice.check', arguments, '--reason', reason, '--idempotency-key', 'fixture-review-1')
        pending = cli(*call)
        check('review remains pending', pending['status'] == 'pending_approval')
        request_id = pending['request_id']
        retry = cli(*call)
        check('matching preapproval retry reuses receipt', retry['request_id'] == request_id and retry['reused'])
        conflict = cli('call', 'slice.check', '{"different":true}', '--idempotency-key', 'fixture-review-1', success=False)
        check('mismatching key payload conflicts', conflict.get('status') == 'conflict')
        req = urllib.request.Request(broker_url + '/v1/actions/slice.check', data=b'{"arguments":{"different":true}}',
            headers={'Authorization': 'Bearer ' + agent_token, 'Content-Type': 'application/json', 'Idempotency-Key': 'fixture-review-1'})
        try:
            urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError as exc:
            check('mismatching payload HTTP 409', exc.code == 409)
            exc.close()
        else:
            raise AssertionError('conflicting payload accepted')
        listed = api(nod_url, '/api/v1/requests', device_token)['requests']
        nod_request, = listed
        card = json.dumps(nod_request)
        check('card omits private credential and reason', private not in card and reason not in card)
        check('card preserves safe destination and visible omissions', 'safe-fixture-destination' in card and 'Fields outside configured pointers are omitted.' in card and '[MASKED]' in card)
        check('no preapproval tool effect', not (temp / 'effects').exists())
        ref = nod_request['id']
        check('published Nod issued exact approval option pairs',
              {(o['id'], o['kind']) for o in nod_request['options']} == {('approve', 'approve'), ('reject', 'reject_with_text')})
        digest = nod_request.get('signing', {}).get('request_digest') or nod_request['request_digest']
        nonce = str(uuid.uuid4())
        signed_at = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        text = 'FAKE local software approval'
        payload = '\n'.join(['nod-decision-v1', f'request_id:{ref}', f'request_digest:{digest}',
                   'option_id:approve', 'option_kind:approve', 'user_id:fake-user',
                   f'device_id:{device_id}', 'key_id:fake-key', f'nonce:{nonce}',
                   f'signed_at:{signed_at}', f'text_sha256:{hashlib.sha256(text.encode()).hexdigest()}', ''])
        signature = b64(key.sign(payload.encode(), ec.ECDSA(hashes.SHA256())))
        resolved = api(nod_url, f'/api/v1/requests/{ref}/options/approve', device_token,
                       {'text': text, 'signature': {'key_id': 'fake-key',
                        'algorithm': 'p256_ecdsa_sha256', 'nonce': nonce, 'signed_at': signed_at,
                        'request_digest': digest, 'signature': signature}})
        check('real Nod verified software P256 decision',
              resolved['request']['decision']['signature']['verified'] is True)
        result = cli('wait', str(request_id), '--timeout', '3')
        check('agent poll executes real secret-dependent tool',
               result['status'] == 'ok' and result['result']['secret_gate'] is True)
        retry = cli(*call)
        check('matching postapproval retry reuses result', retry['request_id'] == request_id and retry['result'] == result['result'] and retry['reused'])
        check('retry causes exactly one effect', (temp / 'effects').read_text() == 'effect\n')
        check('retry creates no extra Nod card', len(api(nod_url, '/api/v1/requests', device_token)['requests']) == 1)

        # Stop through the owning HTTP service before restarting that service.
        broker_stop()
        stop(admin)

        # Restart SPS: registry is deliberately lost, vault stays encrypted on disk.
        stop(sps)
        sps = start('sps-restart', [sys.executable, '-m', 'sps.cli', 'serve', '--config', str(config)], sps_env)
        new_boot = ready(registrar.ping, [sps])['boot_id']
        check('SPS restart new boot', boot != new_boot)
        toolclient = SPSClient('127.0.0.1', sp, esecret=running.e_secret, ca_file=ca)
        try:
            toolclient.get_secrets('slice')
        except (AuthError, NotFound):
            check('restart clears registrations')
        else:
            raise AssertionError('registration survived restart')
        attempts = []

        def recover(**kwargs):
            # Controlled actual registration failure: withhold the owned manifest
            # for exactly the first pass, rather than forging a recovery result.
            attempts.append(new_boot)
            if len(attempts) == 1:
                hidden = manifest.with_suffix('.hidden')
                manifest.rename(hidden)
                try:
                    result = reregister_all_with_sps_detailed(**kwargs)
                finally:
                    hidden.rename(manifest)
                check('actual recovery first pass incomplete', not result.complete)
                return result
            result = reregister_all_with_sps_detailed(**kwargs)
            check('actual recovery second pass complete', result.complete and result.count == 1)
            return result

        watchdog = SPSWatchdog(config=SimpleNamespace(tools_root=str(temp / 'tools'), tool_dirs=[str(toolpath)]),
                               probe=lambda: registrar.ping()['boot_id'], re_register_fn=recover,
                               sps_env_path=str(config))
        watchdog._check_once()
        check('failed boot not acknowledged', watchdog._last_seen is None)
        watchdog._check_once()
        check('same boot retries once', attempts == [new_boot, new_boot] and watchdog._last_seen == new_boot)
        check('recovered real TLS secret retrieval', toolclient.get_secret('slice', 'proof') == fake)
        # Change persisted vault data: safe result must change on the next SDK refresh.
        vault.set('slice', 'PROOF', 'FAKE-OTHER-' + uuid.uuid4().hex)
        from broker.runtime import HttpRuntime
        from broker.registry import Registry
        op = Registry.from_sources(str(temp / 'tools'), [str(toolpath)]).lookup('slice', 'check')
        safe = HttpRuntime(tool_secret=lambda _: running.channel_secret).execute(op, {}, 9001, 'fixture')
        check('vault value affects tool result without echo', safe['secret_gate'] is False)
        check('local vault encrypted', fake.encode() not in vaultfile.read_bytes())
        admin, operator = admin_start('admin-restart')
        persisted = api(admin_url, '/api/config', operator)
        check('actual admin restart reads persisted config', persisted['approval_ttl'] == 421 and persisted['tool_dirs'] == [str(toolpath)])
        check('admin restart retains live tool identity', runner.is_alive(running))
        check('admin restart retains persisted policy/grants', api(admin_url, '/api/callers/fake-agent/policy', operator)['policy'] == policy)
        check('external tool recoverable through admin API', any(t['id'] == 'slice' for t in api(admin_url, '/api/tools', operator)['tools']))
        broker_start()
        check('policy persists after broker restart', cli('call', 'slice.blocked', '{}', success=False)['status'] == 'denied')
        for path in [settings.state_dir() / 'broker.log', temp / 'admin.log', temp / 'admin-restart.log', temp / 'sps.audit',
                     Path(running.log_path)]:
            check('no fake secret in ' + path.name, fake not in path.read_text())
        import sqlite3
        with sqlite3.connect(db) as connection:
            dump = '\n'.join(connection.iterdump())
        check('no fake value in broker database including audit/results', fake not in dump)
        audit = json.dumps(api(admin_url, '/api/audit', operator)['audit'])
        check('audit omits private credential and reason', private not in audit and reason not in audit)
        broker_stop()
        evidence['outcome'] = 'PASS'
    finally:
        cleanup_errors = []
        if supervised is not None:
            try:
                broker_stop()
            except BaseException as exc:
                cleanup_errors.append(type(exc).__name__ + ': admin-owned-broker')
                # Independent fallback if the HTTP control plane itself failed.
                # Stop/reap the known admin parent, then signal only the recorded
                # broker identity; its orphan is reaped by the OS, not waitpid here.
                try:
                    if admin is not None:
                        stop(admin)
                    pid, identity = supervised
                    for sig in (signal.SIGTERM, signal.SIGKILL):
                        current = _process_identity(pid)
                        if current is None:
                            break
                        assert current == identity, 'broker PID identity changed; refusing signal'
                        os.killpg(pid, sig)
                        deadline = time.monotonic() + 3
                        while _process_identity(pid) == identity and time.monotonic() < deadline:
                            time.sleep(.05)  # bounded teardown, never agent polling
                    assert _process_identity(pid) is None, 'owned broker exit unconfirmed'
                except BaseException as fallback:
                    cleanup_errors.append(type(fallback).__name__ + ': broker fallback')
        try:
            if running is not None:
                runner.stop(running)
                check('runner tool stopped', not runner.is_alive(running))
        except BaseException as exc:
            cleanup_errors.append(type(exc).__name__ + ': runner-tool')
        for proc, identity, label in reversed(processes):
            try:
                stop(proc)
                assert proc.poll() is not None
            except BaseException as exc:
                cleanup_errors.append(type(exc).__name__ + ': ' + label)
        evidence['teardown'] = ('all owned processes stopped; temporary files removed by launcher'
                                if not cleanup_errors else cleanup_errors)
        print(json.dumps(evidence, indent=2), flush=True)
        assert not cleanup_errors, cleanup_errors


if __name__ == '__main__':
    if sys.argv[1:] == ['tool']:
        fixture_tool()
    else:
        main()
