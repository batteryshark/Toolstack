"""Pure fakes: no sockets, signing, app launches or GUI imports."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, MagicMock, patch

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('live_ui_fixture.py'))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class FixtureTests(unittest.TestCase):
    def test_off_and_flags(self):
        with patch.object(f, 'serve') as serve, patch('builtins.print'):
            f.main([])
            f.main(['--prepare'])
            for args in (['--desktop'], ['--prepare', '--native-app', 'a'],
                         ['--serve', '--native-app', 'a']):
                with self.assertRaises(SystemExit):
                    f.main(args)
            serve.assert_not_called()

    def test_unique_account_and_environment(self):
        a, b = f.native_url('http://127.0.0.1:123'), f.native_url('http://127.0.0.1:123')
        self.assertNotEqual(a, b)
        self.assertEqual(a.split('#')[0], 'http://127.0.0.1:123')
        with patch.dict(f.os.environ, {'REAL_TOKEN': 'never'}, clear=True):
            self.assertNotIn('REAL_TOKEN', f.environment(Path('/fake')))

    def test_reuse_not_signalled(self):
        p = Mock(pid=42)
        p.poll.return_value = None
        self.assertIn('uncertain', f.stop_child({'proc': p, 'pid': 42, 'identity': 'old'}, lambda _: 'new'))
        p.terminate.assert_not_called()
        p.kill.assert_not_called()

    def test_finite_cleanup(self):
        p = Mock(pid=42)
        p.poll.return_value = None
        p.wait.side_effect = [subprocess.TimeoutExpired('fake', 5), 0]
        self.assertEqual(f.stop_child({'proc': p, 'pid': 42, 'identity': 'same'}, lambda _: 'same'), 'reaped')
        p.terminate.assert_called_once()
        p.kill.assert_called_once()
        self.assertEqual([c.kwargs for c in p.wait.call_args_list], [{'timeout': 5}, {'timeout': 5}])

    def test_failed_readiness(self):
        with self.assertRaises(RuntimeError):
            f.wait_ready(Mock(started=False), Mock(is_alive=lambda: False), ['failed'])
        with self.assertRaises(RuntimeError):
            f.wait_ready(Mock(started=True), Mock(is_alive=lambda: True), ['failed'])

    def test_unsafe_pids_and_unknown_identity(self):
        for pid, actual, start in [(1, 1, 's'), (0, 0, 's'), (-1, -1, 's'),
                                   ('42', 42, 's'), (True, 42, 's'),
                                   (42, 43, 's'), (42, 42, None)]:
            p = Mock(pid=actual)
            p.poll.return_value = None
            self.assertIn('uncertain', f.stop_child({'proc': p, 'pid': pid, 'identity': start}, lambda _: 's'))
            p.terminate.assert_not_called()
            p.kill.assert_not_called()

    def test_signal_stop_closes_admission_and_cleans_thread(self):
        for sig in (f.signal.SIGTERM, f.signal.SIGHUP):
            handlers = {}
            def install(number, handler):
                handlers[number] = handler
                return 'previous'
            server = Mock(started=True)
            thread = Mock(ident=42)
            thread.is_alive.return_value = False
            root = MagicMock()
            child = Mock(pid=42)
            child.poll.return_value = None
            modules = {'admin': MagicMock(), 'admin.server': MagicMock(),
                       'toolyard.runner': MagicMock(), 'uvicorn': MagicMock()}
            modules['uvicorn'].Server.return_value = server
            modules['toolyard.runner']._process_identity.return_value = 'start'
            def ready(*args, **kwargs):
                handlers[sig](sig, None)  # fake invocation, never an actual OS signal
            with patch.dict(f.sys.modules, modules), patch.dict(f.os.environ), \
                 patch.object(f.sys, 'path', list(f.sys.path)), \
                 patch.object(f.os, 'umask'), patch.object(f, 'bootstrap'), \
                 patch.object(f, 'environment', return_value={}), \
                 patch.object(f, 'runtime_report', return_value={}), \
                 patch.object(f.socket, 'socket', return_value=MagicMock()), \
                 patch.object(f.threading, 'Thread', return_value=thread), \
                 patch.object(f.signal, 'signal', side_effect=install), \
                 patch.object(f, 'wait_ready', side_effect=ready), \
                 patch.object(f.subprocess, 'Popen') as popen, \
                 patch.object(f, 'native_copy') as copy, patch('builtins.print'):
                f.serve(root, 'fake.app', 'Apple Development: FAKE')
            copy.assert_not_called()
            popen.assert_not_called()
            self.assertTrue(server.should_exit)
            thread.join.assert_called_once_with(7)
            self.assertTrue(all(value == 'previous' for value in handlers.values()))

    def test_launch_records_before_return(self):
        children = []
        p = Mock(pid=42)
        with patch.object(f.subprocess, 'Popen', return_value=p):
            f.launch(['fake'], {}, children, lambda _: 'start', lambda: self.assertEqual(children[0]['identity'], 'start'))

    def test_controlled_stop_unknown_cleanup_propagates(self):
        root = MagicMock()
        server = Mock(started=True)
        thread = Mock(ident=42)
        thread.is_alive.return_value = False
        children = [{'proc': Mock(pid=pid), 'pid': pid, 'identity': 'start'}
                    for pid in (42, 43)]
        modules = {'admin': MagicMock(), 'admin.server': MagicMock(),
                   'toolyard.runner': MagicMock(), 'uvicorn': MagicMock()}
        modules['uvicorn'].Server.return_value = server
        modules['toolyard.runner']._process_identity.return_value = 'start'
        def stopped_launch(argv, env, owned, identity, record, stop):
            owned.extend(children)
            stop.set()
            raise InterruptedError('controlled stop')
        with patch.dict(f.sys.modules, modules), patch.dict(f.os.environ), \
             patch.object(f.sys, 'path', list(f.sys.path)), \
             patch.object(f.os, 'umask'), patch.object(f, 'bootstrap'), \
             patch.object(f, 'environment', return_value={}), \
             patch.object(f, 'runtime_report', return_value={}), \
             patch.object(f.socket, 'socket', return_value=MagicMock()), \
             patch.object(f.threading, 'Thread', return_value=thread), \
             patch.object(f.signal, 'signal'), patch.object(f, 'wait_ready'), \
             patch.object(f, 'launch', side_effect=stopped_launch), \
             patch.object(f, 'stop_child', side_effect=['uncertain: unknown identity', 'reaped']) as cleanup, \
             patch('builtins.print'):
            with self.assertRaisesRegex(RuntimeError, 'cleanup uncertain'):
                f.serve(root, desktop=True)
        self.assertEqual(cleanup.call_count, 2)
        self.assertEqual([call.args[0]['pid'] for call in cleanup.call_args_list], [43, 42])
        thread.join.assert_called_once_with(7)
        self.assertTrue(server.should_exit)
        records = root.__truediv__.return_value.write_text.call_args_list
        self.assertTrue(f.json.loads(records[-1].args[0])['cleanup_uncertain'])
        self.assertIn(unittest.mock.call('stopped.json'), root.__truediv__.call_args_list)

    def test_stop_after_spawn_records_then_cleanup(self):
        for sig in (f.signal.SIGTERM, f.signal.SIGHUP):
            handlers = {}
            def install(number, handler):
                handlers[number] = handler
                return None
            p = Mock(pid=42)
            p.poll.return_value = None
            children = []
            with patch.object(f.signal, 'signal', side_effect=install), \
                 patch.object(f.subprocess, 'Popen', return_value=p) as popen:
                with f.stop_handlers() as stop:
                    try:
                        f.launch(['fake'], {}, children, lambda _: 'start',
                                 lambda: handlers[sig](sig, None), stop)
                        with self.assertRaises(InterruptedError):
                            f.launch(['second'], {}, children, lambda _: 'start', Mock(), stop)
                    finally:
                        for child in children:
                            self.assertEqual(f.stop_child(child, lambda _: 'start'), 'reaped')
                popen.assert_called_once()
            p.terminate.assert_called_once()
            p.wait.assert_called_once_with(timeout=5)

    def test_native_hash_gate_rejects_old_and_wrong_hash(self):
        self.assertEqual(f.APP_HASH, '28cf9127f93d4ffd30fe7d91d120b862d4e2fc1c3a845b50210bd6a369b18600')
        for digest in ('9092236f5acec2deb7f83377cba9ea3c57551a4b585f95fb72de4cf829bca15b', '0' * 64):
            with self.subTest(digest=digest), \
                 patch.object(Path, 'is_symlink', return_value=False), \
                 patch.object(Path, 'is_dir', return_value=True), \
                 patch.object(Path, 'resolve', lambda p: p), \
                 patch.object(Path, 'rglob', return_value=[]), \
                 patch.object(Path, 'read_bytes', return_value=b'fake'), \
                 patch.object(Path, 'write_bytes') as write, \
                 patch.object(f.hashlib, 'sha256', return_value=Mock(hexdigest=lambda: digest)), \
                 patch.object(f.shutil, 'copytree') as copy, \
                 patch.object(f.subprocess, 'run', return_value=Mock(stderr='Authority=Apple Development: FAKE\n')) as command:
                with self.assertRaisesRegex(ValueError, 'original executable hash mismatch'):
                    f.native_copy(Path('/fake/Original.app'), Path('/fake/root'), 'Apple Development: FAKE', {})
                copy.assert_not_called()
                write.assert_not_called()
                self.assertEqual([call.args[0][1] for call in command.call_args_list], ['--verify', '-dv'])

    def test_native_copy_order_and_metadata(self):
        app, root = Path('/fake/Original.app'), Path('/fake/root')
        events = []
        env = f.environment(root)
        original_env = dict(env)
        def command(argv, **kwargs):
            self.assertEqual(argv[0], '/usr/bin/codesign')
            self.assertEqual(kwargs['env'], {**original_env, 'HOME': '/fake/owner'})
            self.assertNotIn('FAKE_SECRET', kwargs['env'])
            events.append(argv)
            return Mock(stderr='Authority=Apple Development: FAKE\n')
        with patch.object(Path, 'is_symlink', return_value=False), \
             patch.object(Path, 'is_dir', return_value=True), \
             patch.object(Path, 'resolve', lambda p: p), \
             patch.object(Path, 'rglob', return_value=[]), \
             patch.object(Path, 'read_bytes', return_value=b'fake'), \
             patch.object(Path, 'write_bytes') as write, \
             patch.object(f.hashlib, 'sha256', return_value=Mock(hexdigest=lambda: f.APP_HASH)), \
             patch.object(f.plistlib, 'loads', return_value={'CFBundleIdentifier': 'original'}), \
             patch.object(f.shutil, 'copytree', side_effect=lambda *a, **k: events.append('copy')), \
             patch.object(f.subprocess, 'run', side_effect=command), \
             patch.object(f.pwd, 'getpwuid', return_value=Mock(pw_dir='/fake/owner')), \
             patch.dict(f.os.environ, {'FAKE_SECRET': 'never'}, clear=True):
            binary, identifier = f.native_copy(app, root, 'Apple Development: FAKE', env)
            self.assertEqual(env, original_env)
            with patch.object(f.subprocess, 'Popen', return_value=Mock(pid=42)) as popen:
                f.launch(['fake'], env, [], lambda _: 'start', Mock())
                self.assertIs(popen.call_args.kwargs['env'], env)
                self.assertEqual(popen.call_args.kwargs['env'], original_env)
        self.assertEqual(events[0][1:4], ['--verify', '--deep', '--strict'])
        self.assertEqual(events[2], 'copy')
        self.assertIn('--timestamp=none', events[3])
        self.assertEqual(events[4][1], '--verify')
        self.assertTrue(identifier.startswith('com.toolstack.operator.fixture.'))
        self.assertTrue(binary.is_relative_to(root))
        self.assertIn(identifier.encode(), write.call_args.args[0])

    def test_invalid_owner_home_stops_before_codesign(self):
        for home in ('', 'relative', '/'):
            with self.subTest(home=home), \
                 patch.object(Path, 'is_symlink', return_value=False), \
                 patch.object(Path, 'is_dir', return_value=True), \
                 patch.object(Path, 'resolve', lambda p: p), \
                 patch.object(Path, 'rglob', return_value=[]), \
                 patch.object(f.pwd, 'getpwuid', return_value=Mock(pw_dir=home)), \
                 patch.object(f.subprocess, 'run') as command, \
                 patch.object(f.shutil, 'copytree') as copy:
                with self.assertRaisesRegex(ValueError, 'OS account owner home'):
                    f.native_copy(Path('/fake/Original.app'), Path('/fake/root'),
                                  'Apple Development: FAKE', {})
                command.assert_not_called()
                copy.assert_not_called()


if __name__ == '__main__':
    unittest.main()
