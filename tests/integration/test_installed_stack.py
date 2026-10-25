"""Pure boundary tests: no listeners, network, or subprocess creation."""
import importlib.util
import os
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('installed_stack', Path(__file__).with_name('installed_stack.py'))
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class Boundaries(unittest.TestCase):
    def test_import_is_inert(self):
        with patch('subprocess.Popen', side_effect=AssertionError('spawn')), patch('socket.socket', side_effect=AssertionError('socket')):
            spec.loader.exec_module(subject)

    def test_environment_allowlist(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'secret', 'TOKEN': 'secret'}):
            env = subject.environment(Path('/private/example'))
        self.assertNotIn('TOKEN', env)
        self.assertNotIn('HTTPS_PROXY', env)
        self.assertNotIn('PYTHONPATH', env)
        self.assertTrue(all(v.startswith('/private/example') for k, v in env.items() if k.startswith('XDG_')))

    def test_root_no_clobber_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = subject.private_root(parent / 'proof')
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                subject.private_root(root)
            (parent / 'link').symlink_to(root)
            with self.assertRaises(subject.BoundaryError):
                subject.private_root(parent / 'link' / 'child')

    def test_evidence_exclusive_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence'
            subject.private_json(path, {'outcome': 'INCOMPLETE'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                subject.private_json(path, {})

    def test_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            origin = root / 'module.py'
            origin.write_text('# fixture\n')
            finder = lambda _: SimpleNamespace(origin=str(origin), submodule_search_locations=[])
            self.assertEqual(len(subject.installed_origins(root, root / 'source', finder)), 6)
            with self.assertRaises(subject.BoundaryError):
                subject.installed_origins(root / 'venv', root, finder)

    def test_unknown_identity_refuses_signal(self):
        self.assertTrue(subject.may_signal(42, 'birth', 'boot', 'birth', 'boot'))
        for args in [(42, None, 'boot', None, 'boot'), (1, 'a', 'b', 'a', 'b'),
                     (42, 'a', 'b', 'other', 'b'), (42, 'a', None, 'a', None)]:
            self.assertFalse(subject.may_signal(*args))

    def test_body_bounds(self):
        self.assertEqual(subject.body_length(str(subject.MAX_BODY)), subject.MAX_BODY)
        for raw in ['-1', '+1', ' 1', '1048577', '9' * 100, '１']:
            with self.assertRaises(subject.BoundaryError):
                subject.body_length(raw)

    def test_budget(self):
        self.assertLessEqual(subject.RUN_BUDGET_SECONDS, 240)
        self.assertLessEqual(subject.CLEANUP_BUDGET_SECONDS, 30)

    def test_fake_decision_mapping(self):
        self.assertEqual(subject.decision('opaque', False)['status'], 'pending')
        resolved = subject.decision('opaque', True)
        self.assertEqual(resolved['request_id'], 'opaque')
        self.assertEqual(resolved['decision']['option_kind'], 'approve')

    def test_fake_http_without_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = SimpleNamespace(kind='nod', root=root, credential='fake-issuer', control='separate-control', cards={})
            def request(path, payload=None, token='fake-issuer'):
                handler = object.__new__(subject.FixtureHandler)
                handler.server, handler.path = server, path
                raw = json.dumps(payload).encode() if payload is not None else b''
                handler.headers = {'Authorization': 'Bearer ' + token, 'Content-Length': str(len(raw))}
                handler.rfile = io.BytesIO(raw)
                result = []
                handler.respond = lambda code, data: result.append((code, data))
                handler.dispatch(payload is not None)
                return result[0]
            payload = {'dedupe_key': 'fixture', 'options': []}
            self.assertEqual(request('/api/v1/requests', payload, 'wrong')[0], 401)
            code, result = request('/api/v1/requests', payload)
            ref = result['request_id']
            self.assertEqual(code, 200)
            self.assertEqual(request('/api/v1/requests', payload)[1], result)
            self.assertEqual(len(server.cards), 1)
            endpoint = '/api/v1/requests/' + ref + '/decision'
            self.assertEqual(request(endpoint)[1]['status'], 'pending')
            control = root / 'approve.json'
            control.write_text(json.dumps({'credential': 'fake-issuer', 'request_id': ref}))
            self.assertEqual(request(endpoint)[1]['status'], 'pending')
            control.write_text(json.dumps({'credential': 'separate-control', 'request_id': ref}))
            self.assertEqual(request(endpoint)[1]['status'], 'resolved')
            self.assertEqual(request('/api/v1/requests', {'dedupe_key': 'fixture', 'changed': True})[0], 409)

    def test_absence_is_positive(self):
        with patch.object(subject.os, 'kill', side_effect=ProcessLookupError):
            self.assertTrue(subject.absent(42))
        with patch.object(subject.os, 'kill', return_value=None):
            self.assertFalse(subject.absent(42))
        with patch.object(subject.os, 'kill', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                subject.absent(42)

    def test_interrupt_and_deadline(self):
        with self.assertRaises(subject.BudgetExpired):
            subject.interrupted(subject.signal.SIGALRM, None)
        with self.assertRaises(subject.BoundaryError):
            subject.interrupted(15, None)
        with patch.object(subject.time, 'monotonic', side_effect=[0, 13]):
            with self.assertRaises(subject.BoundaryError):
                subject.ready(lambda: None)

    def test_lost_start_once_and_reconcile(self):
        intent = {'admin': {'pid': 42, 'identity': 'admin-birth', 'boot': 'boot'}, 'port': 12345}
        events = []
        def lost():
            events.append('POST')
            raise TimeoutError()
        with self.assertRaises(TimeoutError):
            subject.start_once(intent, lambda _: events.append('persist'), lost)
        self.assertEqual(events, ['persist', 'POST'])
        rows = subject.parse_processes('43 42 /venv/bin/python -m broker.server\n')
        identities = {42: 'admin-birth', 43: 'broker-birth'}
        result = subject.reconcile_broker(intent, {'pid': 43, 'port': 12345}, rows,
                                          identities.get, 'boot', '/venv/bin/python')
        self.assertEqual(result, (43, 'broker-birth'))
        stopped = []
        subject.stop_once(lambda: stopped.append('stop') or {'running': False},
                          lambda: True, lambda: stopped.append('clear'))
        self.assertEqual(stopped, ['stop', 'clear'])
        with self.assertRaises(subject.BoundaryError):
            subject.stop_once(lambda: {'running': False}, lambda: False,
                              lambda: self.fail('cleared before absence'))
        with self.assertRaises(subject.BudgetExpired):
            subject.stop_once(lambda: subject.interrupted(subject.signal.SIGALRM, None),
                              lambda: True, lambda: self.fail('deadline swallowed'))
        for changed in [None, {'pid': 43, 'port': 9}]:
            with self.assertRaises(subject.BoundaryError):
                subject.reconcile_broker(intent, changed, rows, identities.get, 'boot', '/venv/bin/python')
        for bad_rows, identity in [({43: (99, rows[43][1])}, identities.get),
                                    (rows, lambda pid: identities.get(pid) if pid == 42 else None),
                                    ({43: (42, ['/foreign/python', '-m', 'broker.server'])}, identities.get)]:
            with patch.object(subject.os, 'kill', side_effect=AssertionError('signal refused')):
                with self.assertRaises(subject.BoundaryError):
                    subject.reconcile_broker(intent, {'pid': 43, 'port': 12345}, bad_rows, identity, 'boot', '/venv/bin/python')


if __name__ == '__main__':
    unittest.main()
