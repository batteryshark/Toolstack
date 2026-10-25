"""Bounded installed-wheel acceptance with explicitly fake Nod. Import inert."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import uuid
import hmac
import signal
import socket
import subprocess
import time
import shlex
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import asdict

WHEEL_SHA256 = '177b2ced1cd0500da68fd228284f50b74f2c941571ba0db8d606bc18617207c5'
MODULES = ('admin', 'broker', 'client', 'sps', 'toolyard', 'toolstack_forwarder')
RUN_BUDGET_SECONDS = 240
CLEANUP_BUDGET_SECONDS = 30
MAX_BODY = 1024 * 1024


class BoundaryError(RuntimeError):
    """A boundary could not be proved. Messages contain no supplied values."""


class BudgetExpired(BaseException):
    """Must bypass per-resource cleanup error handling."""


def private_root(path: Path) -> Path:
    """Create exactly one absent child, refusing symlinks in every ancestor.

    Canonical absolute paths are intentional: macOS /var aliases must be expanded
    by the parent before invocation. An existing private directory is not reused.
    """
    if not path.is_absolute() or '..' in path.parts:
        raise BoundaryError('absolute canonical root required')
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise BoundaryError('unsafe root ancestor')
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise BoundaryError('parent must be owned and private')
    # mkdir supplies no-clobber semantics, including dangling leaf symlinks.
    path.mkdir(mode=0o700)
    return path


def private_json(path: Path, value: dict) -> None:
    """Exclusive creation; never follow or replace a pre-existing evidence file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def environment(root: Path) -> dict[str, str]:
    """Construct from literals, never by copying parent credentials or proxies."""
    return {
        'HOME': str(root), 'TMPDIR': str(root / 'tmp'),
        'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
        'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHONUNBUFFERED': '1',
        **{key: str(root / key.lower()) for key in (
            'XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_DATA_HOME',
            'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR')},
    }


def installed_origins(prefix: Path, source: Path, finder=None) -> dict:
    finder = finder or importlib.util.find_spec
    prefix, source = prefix.resolve(), source.resolve()
    result = {}
    for name in MODULES:
        spec = finder(name)
        if spec is None or not spec.origin:
            raise BoundaryError('missing concrete installed module')
        origin = Path(spec.origin).resolve()
        if not origin.is_relative_to(prefix) or origin.is_relative_to(source):
            raise BoundaryError('module outside installed prefix')
        for entry in spec.submodule_search_locations or ():
            location = Path(entry).resolve()
            if not location.is_relative_to(prefix) or location.is_relative_to(source):
                raise BoundaryError('package search path outside installed prefix')
        result[name] = {'origin': str(origin),
                        'sha256': hashlib.sha256(origin.read_bytes()).hexdigest()}
    return result


def may_signal(pid, recorded_identity, recorded_boot, current_identity, current_boot):
    """Unknown identity is never absence and never permission to signal."""
    return (isinstance(pid, int) and not isinstance(pid, bool) and pid > 1
            and recorded_identity is not None and recorded_boot is not None
            and current_identity is not None and current_boot is not None
            and recorded_identity == current_identity and recorded_boot == current_boot)


def body_length(raw: str) -> int:
    if not raw or not raw.isascii() or not raw.isdecimal():
        raise BoundaryError('invalid body length')
    if len(raw) > 7:
        raise BoundaryError('oversize body')
    length = int(raw)
    if length > MAX_BODY:
        raise BoundaryError('oversize body')
    return length


def api(base, path, token='', body=None, key=None):
    if not base.startswith('http://127.0.0.1:'):
        raise BoundaryError('nonloopback HTTP refused')
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if key:
        headers['Idempotency-Key'] = key
    request = urllib.request.Request(base + path, headers=headers,
        data=None if body is None else json.dumps(body).encode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            raise BoundaryError('oversize response')
        return json.loads(data or b'null')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise BoundaryError('redirect refused')


def ready(fn, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = fn()
            if result:
                return result
        except (OSError, ValueError, RuntimeError):
            pass
        time.sleep(.05)
    raise BoundaryError('readiness deadline')


def decision(ref, approved):
    return {'request_id': ref, 'status': 'resolved' if approved else 'pending',
            'decision': {'option_id': 'approve', 'option_kind': 'approve',
                         'actor_user_id': 'explicit-fake-fixture'} if approved else None}


class FixtureHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *args):
        pass

    def respond(self, code, data):
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, post):
        server = self.server
        expected = server.credential
        actual = self.headers.get('Authorization' if server.kind == 'nod' else 'X-Toolstack-Secret', '')
        if server.kind == 'nod':
            expected = 'Bearer ' + expected
        if not hmac.compare_digest(actual, expected):
            return self.respond(401, {})
        try:
            if self.headers.get('Transfer-Encoding'):
                raise BoundaryError('transfer encoding refused')
            payload = None
            if post:
                length = body_length(self.headers.get('Content-Length', ''))
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise BoundaryError('short body')
                payload = json.loads(raw)
            if server.kind == 'tool':
                if not post or self.path != '/v1/actions/check':
                    return self.respond(404, {})
                value = server.sdk.refresh('proof')
                effects = server.root / 'effects'
                count = int(effects.read_text()) if effects.exists() else 0
                if count >= 4:
                    raise BoundaryError('effect bound')
                effects.write_text(str(count + 1))
                return self.respond(200, {'secret_gate': value.startswith('FAKE-SLICE-'), 'operation': 'check'})
            if post and self.path == '/api/v1/requests':
                key = payload['dedupe_key']
                if key in server.cards and server.cards[key][1] != payload:
                    return self.respond(409, {})
                if key not in server.cards:
                    if len(server.cards) >= 4:
                        raise BoundaryError('card bound')
                    server.cards[key] = (uuid.uuid4().hex, payload)
                    private_json(server.root / ('card-' + str(len(server.cards)) + '.json'), payload)
                    if len(server.cards) == 1:
                        private_json(server.root / 'nod-reference.json', {'request_id': server.cards[key][0]})
                return self.respond(200, {'request_id': server.cards[key][0]})
            for ref, _ in server.cards.values():
                if not post and self.path == '/api/v1/requests/' + ref + '/decision':
                    control = server.root / 'approve.json'
                    approved = False
                    if control.exists():
                        value = json.loads(control.read_text())
                        approved = hmac.compare_digest(value.get('credential', ''), server.control) and value.get('request_id') == ref
                    return self.respond(200, decision(ref, approved))
            self.respond(404, {})
        except (ValueError, KeyError, OSError, BoundaryError):
            self.respond(400, {})


def fixture(kind):
    root = Path(os.environ['HOME'])
    marker = json.loads((root / 'marker.json').read_text())
    if marker['kind'] != 'installed-stack':
        raise BoundaryError('fixture marker missing')
    signal.alarm(RUN_BUDGET_SECONDS + CLEANUP_BUDGET_SECONDS)
    server = HTTPServer(('127.0.0.1', 0 if kind == 'nod' else int(os.environ['TOOLSTACK_PORT'])), FixtureHandler)
    server.kind, server.root = kind, root
    if kind == 'nod':
        config = json.loads((root / 'fixture.json').read_text())
        server.credential, server.control = config['issuer'], config['control']
        server.cards = {}
        private_json(root / 'nod-ready.json', {'port': server.server_port})
    else:
        from sps.tool_sdk import SecretClient
        server.sdk = SecretClient.from_env('slice')
        server.credential = os.environ['TOOLSTACK_CHANNEL_SECRET']
    try:
        server.serve_forever(poll_interval=.1)
    finally:
        server.server_close()


def interrupted(signum, frame):
    if signum == signal.SIGALRM:
        raise BudgetExpired()
    raise BoundaryError('bounded run interrupted')


def absent(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def parse_processes(text):
    rows = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            raise BoundaryError('process inventory malformed')
        try:
            argv = shlex.split(parts[2])
        except ValueError:
            argv = []  # unrelated opaque command; never eligible for adoption
        rows[int(parts[0])] = (int(parts[1]), argv)
    return rows


def process_inventory():
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,args='],
                            capture_output=True, text=True, timeout=2)
    if result.returncode:
        raise BoundaryError('process inventory failed')
    return parse_processes(result.stdout)


def reconcile_broker(intent, state, rows, identity, boot, executable):
    """Pure adoption gate. Missing state is uncertainty, never inferred absence."""
    parent = intent['admin']
    if not may_signal(parent['pid'], parent['identity'], parent['boot'],
                      identity(parent['pid']), boot):
        raise BoundaryError('broker reconciliation parent unknown')
    if not isinstance(state, dict) or state.get('port') != intent['port']:
        raise BoundaryError('broker reconciliation state unknown')
    pid = state.get('pid')
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        raise BoundaryError('broker reconciliation pid invalid')
    row = rows.get(pid)
    if row != (parent['pid'], [executable, '-m', 'broker.server']):
        raise BoundaryError('broker reconciliation ownership unknown')
    birth = identity(pid)
    if birth is None or boot != parent['boot']:
        raise BoundaryError('broker reconciliation birth unknown')
    return pid, birth


def start_once(intent, persist, post):
    """Persist before exactly one POST; a lost reply propagates for reconciliation."""
    persist(intent)
    return post()


def stop_once(stop_api, is_absent, persist_absence):
    result = stop_api()
    if result.get('running') is not False or not is_absent():
        raise BoundaryError('broker stop unconfirmed')
    persist_absence()


def acceptance(root, origins, wheel):
    from toolyard.runner import ProcessRunner, _process_identity, _boot_id
    from toolyard.cli import state_lock, _save_state
    from toolyard.config import load
    from sps.cli import maybe_generate_tls_material
    from sps.plugins.localfile import _Vault
    from sps.client import SPSClient
    from broker.store import Store
    from broker.identity import hash_token
    from admin import auth, settings, broker_config

    evidence = {'outcome': 'FAIL', 'phase': 'setup', 'wheel_sha256_parent_attestation': wheel,
                'installed_origins': origins, 'checks': [], 'processes': [], 'ports': {}, 'cleanup': []}
    records = []
    running = None
    supervised = None
    admin = None
    operator = None
    intent = None
    retain_admin = False
    runner = ProcessRunner()
    boot = _boot_id()
    env = environment(root)
    for key, value in env.items():
        if key.startswith('XDG_') or key == 'TMPDIR':
            Path(value).mkdir(mode=0o700)
    os.environ.clear()
    os.environ.update(env)
    os.chdir(root)

    def check(name, condition):
        if not condition:
            evidence['failed_check'] = name[:160]
            raise BoundaryError(name)
        evidence['checks'].append(name)

    def record(label, pid, proc=None, identity=None):
        entry = {'label': label, 'pid': int(pid), 'identity': identity or _process_identity(pid), 'boot': boot}
        records.append((entry, proc))
        evidence['processes'].append(entry)
        private_json(root / ('process-' + str(len(records)) + '.json'), entry)
        check('known birth and boot: ' + label, entry['pid'] > 1 and entry['identity'] is not None and boot is not None)
        return entry

    def start(label, argv, extra=None):
        with open(root / (label + '.log'), 'xb') as log:
            proc = subprocess.Popen(argv, cwd=root, env={**env, **(extra or {})}, stdout=log, stderr=log, start_new_session=True)
        entry = record(label, proc.pid, proc)
        return entry, proc

    def stop(entry, proc=None):
        if proc is not None and proc.poll() is not None:
            return
        if absent(entry['pid']):
            if proc is not None:
                proc.wait(timeout=.2)
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if not may_signal(entry['pid'], entry['identity'], entry['boot'], _process_identity(entry['pid']), _boot_id()):
                raise BoundaryError('unknown identity cleanup refused')
            os.kill(entry['pid'], sig)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if proc is not None:
                    proc.poll()
                else:
                    try:
                        os.waitpid(entry['pid'], os.WNOHANG)
                    except ChildProcessError:
                        pass
                if absent(entry['pid']):
                    return
                time.sleep(.05)
        raise BoundaryError('exit unconfirmed')

    def port(label):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            value = sock.getsockname()[1]
        evidence['ports'][label] = value
        return value

    def broker_stop():
        nonlocal supervised, intent
        if supervised is not None:
            check('broker identity before API stop', may_signal(supervised['pid'], supervised['identity'], supervised['boot'], _process_identity(supervised['pid']), _boot_id()))
            stop_once(lambda: api(admin_url, '/api/broker/stop', operator, {}),
                      lambda: absent(supervised['pid']),
                      lambda: private_json(root / ('broker-stop-' + str(len(records)) + '.json'), {'absent': True}))
            check('broker stopped and reaped', True)
            supervised = None
            intent = None

    def broker_start():
        nonlocal supervised, intent
        state_path = settings.state_dir() / 'broker.state.json'
        check('broker state absent before start', not state_path.exists())
        intent = {'port': bp, 'admin': dict(admin[0]), 'state_path': str(state_path)}
        result = start_once(intent,
            lambda value: private_json(root / ('broker-intent-' + str(len(records)) + '.json'), value),
            lambda: api(admin_url, '/api/broker/start', operator, {}))
        supervised = record('admin-owned-broker', result['pid'])
        check('broker healthy', result['healthy'])

    def admin_start(label):
        child = start(label, [sys.executable, '-I', '-m', 'admin', 'serve', '--port', str(ap)], runner_env)
        token = ready(lambda: api(admin_url, '/api/login', body={'password': password}).get('token'))
        return child, token

    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)}
    signal.alarm(RUN_BUDGET_SECONDS)
    try:
        issuer, control = ('FAKE-' + uuid.uuid4().hex for _ in range(2))
        private_json(root / 'fixture.json', {'issuer': issuer, 'control': control})
        helper = str(Path(__file__).resolve())
        start('fake-nod', [sys.executable, '-I', helper, '--fake-nod'])
        nod_port = ready(lambda: json.loads((root / 'nod-ready.json').read_text())['port'])
        evidence['ports']['nod'] = nod_port
        nod_url = f'http://127.0.0.1:{nod_port}'
        sp, tp, bp, ap = (port(name) for name in ('sps', 'tool', 'broker', 'admin'))
        broker_url, admin_url = f'http://127.0.0.1:{bp}', f'http://127.0.0.1:{ap}'
        cert, keyfile, ca = (str(root / name) for name in ('sps.crt', 'sps.key', 'ca.crt'))
        maybe_generate_tls_material(cert, keyfile, ca, '/CN=localhost')
        sp_secret, passphrase = ('FAKE-' + uuid.uuid4().hex for _ in range(2))
        fake = 'FAKE-SLICE-' + uuid.uuid4().hex
        vaultfile = root / 'vault.json'
        _Vault.init(vaultfile, passphrase)
        _Vault(vaultfile, passphrase).set('slice', 'PROOF', fake)
        config = root / 'sps.env'
        config.write_text('\n'.join(f'{k} = {json.dumps(v)}' for k, v in {
            'SP_HOST': '127.0.0.1', 'SP_PORT': str(sp), 'SP_SECRET': sp_secret,
            'SP_TLS_CERT': cert, 'SP_TLS_KEY': keyfile, 'SP_TLS_CA': ca,
            'SP_AUDIT_LOG': str(root / 'sps.audit'), 'SP_PLUGIN': 'localfile'}.items())
            + '\n[localfile]\nVAULT_FILE = ' + json.dumps(str(vaultfile)) + '\n')
        start('sps', [sys.executable, '-I', '-m', 'sps.cli', 'serve', '--config', str(config)],
              {'SP_VAULT_PASSPHRASE': passphrase, 'TOOLSTACK_SPS_BOOT_ID_PATH': str(root / 'sps.boot')})
        registrar = SPSClient('127.0.0.1', sp, sp_secret=sp_secret, ca_file=ca, timeout=2)
        check('SPS verified TLS boot', bool(ready(registrar.ping)['boot_id']))
        toolpath = root / 'external' / 'slice'
        toolpath.mkdir(parents=True)
        command = shlex.quote(sys.executable) + ' -I ' + shlex.quote(helper) + ' --tool'
        manifest = toolpath / 'toolyard.toml'
        manifest.write_text('id = "slice"\ntype = "api"\n[entrypoint]\nport = ' + str(tp)
            + '\ncommand = ' + json.dumps(command) + '\n[[operations]]\nname = "check"\nrisk = "read"\napproval_fields = ["/destination", "/credential"]\n[[operations]]\nname = "blocked"\nrisk = "read"\n[[secrets]]\nname = "proof"\nfield = "PROOF"\n')
        runner_env = {'TOOLSTACK_SPS_ENV': str(config), 'TOOLSTACK_SPS_VERIFY': 'true',
                      'TOOLSTACK_TOOLYARD_CHANNEL_STATE': str(root / 'channels.json'), 'TOOLSTACK_BROKER_HOST': '127.0.0.1'}
        os.environ.update(runner_env)
        with state_lock():
            try:
                running = runner.start(load(manifest))
            except BaseException as error:
                partial = getattr(error, 'running', None)
                if partial is not None and partial.handle:
                    running = partial
                    record('partial-runner-tool', partial.handle, identity=partial.process_identity)
                raise
            record('runner-tool', running.handle, identity=running.process_identity)
            _save_state({'slice': asdict(running)})
        check('independent credentials', running.e_secret != running.channel_secret)
        check('tool ready', ready(lambda: api(f'http://127.0.0.1:{tp}', '/missing') == {}))
        db = str(root / 'broker.sqlite')
        agent_token = 'FAKE-' + uuid.uuid4().hex
        store = Store(db)
        caller = store.add_caller('fake-agent')
        store.add_token(caller, hash_token(agent_token))
        policy = {'tools': {'slice': {'check': 'review', 'blocked': 'deny'}}}
        store.set_policy(caller, policy)
        store.close()
        (root / 'tools').mkdir()
        password = 'FAKE-' + uuid.uuid4().hex
        settings.write_password_hash(auth.hash_password(password))
        settings.rotate_session_secret()
        broker_config.save(broker_config.BrokerRunConfig(port=bp, db_path=db, tools_root=str(root / 'tools'),
            tool_dirs=[str(toolpath)], nod_url=nod_url, nod_token=issuer, nod_channel='slice', rate_limit=0))
        admin, operator = admin_start('admin')
        saved = api(admin_url, '/api/config', operator, {'approval_ttl': 420})
        check('config save preserves external tools', saved['tool_dirs'] == [str(toolpath)])
        broker_start()
        evidence['phase'] = 'review'
        private, reason = ('FAKE-private-' + uuid.uuid4().hex for _ in range(2))
        body = {'arguments': {'destination': 'safe-fixture', 'credential': private}, 'reason': reason}
        def call():
            return api(broker_url, '/v1/actions/slice.check', agent_token, body, 'installed-proof-1')
        pending = call()
        request_id = pending['request_id']
        check('review pending', pending['status'] == 'pending_approval')
        retry = call()
        check('pending receipt deduplicated', retry['request_id'] == request_id and retry['reused'])
        check('no preapproval effect', not (root / 'effects').exists())
        card = json.loads((root / 'card-1.json').read_text())
        check('exact approval options', {(o['id'], o['kind']) for o in card['options']} == {('approve', 'approve'), ('reject', 'reject_with_text')})
        fields = {f['label']: f['value'] for f in card['fields']}
        check('full digest and generation', len(fields['Full request SHA-256']) == 64 and bool(fields['Operation generation']))
        check('private action omitted', private not in json.dumps(card) and reason not in json.dumps(card))
        # The broker receipt records the opaque surface reference in its store;
        # the fixture publishes a control-only reference file on creation.
        ref = json.loads((root / 'nod-reference.json').read_text())['request_id']
        private_json(root / 'approve.json', {'credential': control, 'request_id': ref})
        result = ready(lambda: (r if (r := api(broker_url, '/v1/requests/' + str(request_id), agent_token))['status'] == 'ok' else None))
        check('real TLS secret gates tool result', result['result']['secret_gate'] is True)
        retry = call()
        check('completed receipt deduplicated', retry['reused'] and retry['request_id'] == request_id and retry['result'] == result['result'])
        check('exactly one effect and card', (root / 'effects').read_text() == '1' and not (root / 'card-2.json').exists())
        broker_stop()
        stop(*admin)
        evidence['phase'] = 'restart'
        admin, operator = admin_start('admin-restart')
        persisted = api(admin_url, '/api/config', operator)
        check('admin config recovered', persisted['approval_ttl'] == 420 and persisted['tool_dirs'] == [str(toolpath)])
        check('live tool recovered', runner.is_alive(running))
        check('policy recovered', api(admin_url, '/api/callers/fake-agent/policy', operator)['policy'] == policy)
        broker_start()
        retry = call()
        check('token and completed receipt recovered', retry['reused'] and retry['request_id'] == request_id and retry['result'] == result['result'])
        denied = api(broker_url, '/v1/actions/slice.blocked', agent_token, {'arguments': {}})
        check('deny policy survives restart', denied['status'] == 'denied')
        check('restart causes no replay', (root / 'effects').read_text() == '1')
        broker_stop()
        evidence['outcome'] = 'PASS'
    except BaseException as error:
        evidence['failure_stage'] = evidence['phase']
        evidence['failuretype'] = type(error).__name__
    finally:
        evidence['last_flow_stage'] = evidence['phase']
        evidence['phase'] = 'cleanup'
        signal.alarm(CLEANUP_BUDGET_SECONDS)
        # Ignore further user interrupts during the finite teardown, retain alarm.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            if intent is not None and supervised is None:
                try:
                    state = json.loads(Path(intent['state_path']).read_text())
                    pid, birth = reconcile_broker(intent, state, process_inventory(),
                                                 _process_identity, _boot_id(), sys.executable)
                    supervised = record('reconciled-broker', pid, identity=birth)
                except Exception as error:
                    retain_admin = True
                    evidence['outcome'] = 'FAIL'
                    evidence['cleanup'].append({'label': 'broker-reconcile', 'failuretype': type(error).__name__})
            if supervised is not None:
                try:
                    broker_stop()
                except Exception:
                    try:
                        stop(supervised)
                        check('fallback broker absent', absent(supervised['pid']))
                        private_json(root / 'broker-fallback-absence.json', {'absent': True})
                        intent = None
                    except Exception as error:
                        retain_admin = True
                        evidence['cleanup'].append({'label': 'broker-fallback', 'failuretype': type(error).__name__})
            if running is not None:
                try:
                    check('tool identity before runner stop', may_signal(int(running.handle), running.process_identity, running.boot_id, _process_identity(running.handle), _boot_id()))
                    runner.stop(running)
                except Exception as error:
                    evidence['cleanup'].append({'label': 'runner-stop', 'failuretype': type(error).__name__})
            for entry, proc in reversed(records):
                try:
                    if retain_admin and admin is not None and entry['pid'] == admin[0]['pid']:
                        raise BoundaryError('admin retained for unresolved broker ownership')
                    stop(entry, proc)
                    evidence['cleanup'].append({'label': entry['label'], 'absent': absent(entry['pid'])})
                except Exception as error:
                    evidence['cleanup'].append({'label': entry['label'], 'failuretype': type(error).__name__})
            for value in evidence['ports'].values():
                with socket.socket() as sock:
                    sock.settimeout(.2)
                    check('owned listener gone', sock.connect_ex(('127.0.0.1', value)) != 0)
            check('all recorded identities absent', all(absent(entry['pid']) for entry, _ in records))
            check('cleanup complete', all(item.get('absent') is True for item in evidence['cleanup']))
        except BaseException as error:
            evidence['outcome'] = 'FAIL'
            evidence['cleanup_failuretype'] = type(error).__name__
        finally:
            signal.alarm(0)
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
            evidence['phase'] = 'finished'
            evidence['loaded_package_modules'] = {}
            for name, module in tuple(sys.modules.items()):
                if name.split('.')[0] not in MODULES or not getattr(module, '__file__', None):
                    continue
                origin = Path(module.__file__).resolve()
                if not origin.is_relative_to(Path(sys.prefix).resolve()):
                    evidence['outcome'] = 'FAIL'
                    evidence['provenance_failure'] = True
                    continue
                evidence['loaded_package_modules'][name] = {'origin': str(origin), 'sha256': hashlib.sha256(origin.read_bytes()).hexdigest()}
            private_json(root / 'evidence.json', evidence)
    return 0 if evidence['outcome'] == 'PASS' else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--wheel-sha256', required=True, choices=[WHEEL_SHA256])
    parser.add_argument('--run', required=True, choices=['single'])
    args = parser.parse_args(argv)
    if not sys.flags.isolated or sys.prefix == sys.base_prefix:
        raise BoundaryError('isolated fresh virtual environment required')
    # An argument pin is a parent attestation, not proof of wheel bytes. The
    # parent must hash its retained wheel before installing it into the venv.
    origins = installed_origins(Path(sys.prefix), Path(__file__).resolve().parents[2])
    root = private_root(args.root)
    os.umask(0o077)
    private_json(root / 'marker.json', {'run_id': uuid.uuid4().hex, 'kind': 'installed-stack'})
    return acceptance(root, origins, args.wheel_sha256)


if __name__ == '__main__':
    try:
        if sys.argv[1:] in (['--fake-nod'], ['--tool']):
            fixture('nod' if sys.argv[1] == '--fake-nod' else 'tool')
        else:
            raise SystemExit(main())
    except Exception as error:
        print('installed-stack: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
