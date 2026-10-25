"""Cleanup controller qualification: fake VM/child and disposable fake artifacts."""
import copy
import dataclasses
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from contextlib import redirect_stdout
from unittest.mock import patch

import vm_proof_cleanup as c
import vm_proof_guard as g
import vm_proof_payload as p
from vm_proof_adapter import StopLatch, run_guard
from test_vm_proof_adapter import FakeIO
from test_vm_proof_linux import Child

NEW = 'vmproof-20261024T220000Z-01234567'


def config():
    return g.GuardConfig(NEW, tuple(g.BaselineContainer(n, 'healthy') for n in
                                   ['nod', *['service' + str(i) for i in range(15)]]))


def snapshot():
    jobs, evidence, containers = [], [], []
    for kind in p.CONTAINER_KINDS:
        if kind in p.KINDS:
            evidence.append({'step': 'build-' + kind, 'result': {
                'image': c.IMAGES[p.KINDS.index(kind)], 'tag': p.tag_for(c.OLD_RUN, kind), 'label': c.OLD_RUN}})
        cid = format(len(containers) + 1, '064x')
        containers.append(cid)
        evidence.extend([{'step': 'create-' + kind, 'result': {'container': cid}},
                         {'step': 'start-' + kind, 'result': {}}])
    for row in evidence:
        jobs.append({'key': row['step'], 'pid': 100, 'identity': {'pid': 100, 'start': 50, 'boot': 'a' * 36},
                     'exitcode': 0})
    evidence.append({'step': 'extract-offline-units', 'result': {'commit': c.COMMIT, 'sha256': c.DIGEST}})
    reasons = ['image-users-unknown:' + image for image in c.IMAGES]
    return {'config': dict(dataclasses.asdict(config()), run_id=c.OLD_RUN),
            'state': {'owned_resize': True, 'owned_start': True, 'shutdown_sent': True, 'children': [],
                      'containers': [], 'images': [], 'stop': 'proof-complete',
                      'baseline_vm130': {'status': 'stopped', 'memory_mib': 8192, 'cores': 2, 'onboot': 0},
                      'proof': {'pending': None, 'sync_inflight': None, 'inventory_stage': None,
                                'inventory_failure': None, 'complete': True, 'root_attempted': True,
                                'leftovers': reasons, 'images': list(c.IMAGES), 'marker': dict(c.MARKER),
                                'root': str(p.root_for(c.OLD_RUN)), 'commit': c.COMMIT, 'sha256': c.DIGEST,
                                'jobs': jobs, 'containers': containers}},
            'result': {'ask_parent': True, 'phase': 'monitor', 'reasons': ['proof-complete', *reasons],
                       'restored': False, 'proof_complete': True},
            'proof-evidence': evidence, 'controller': {'pid': 999991, 'start': 100},
            'lease': {'pid': 999991, 'start': 100, 'run': c.OLD_RUN, 'monotonic': 1},
            'pid': c.OLD_RUN + '\n999992 200\n'}


class Records(unittest.TestCase):
    def test_absent_control_root_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = str(Path(tmp).resolve())
            first = c.prepare_run_root(parent, NEW)
            with self.assertRaises((g.GuardRefusal, OSError)):
                c.prepare_run_root(parent, NEW)
            self.assertTrue(Path(first).is_dir())

    def test_valid_fixed_snapshot_and_distinct_control(self):
        self.assertEqual(c.validate(snapshot(), NEW), (999991, 999992))
        with self.assertRaises(g.GuardRefusal):
            c.validate(snapshot(), c.OLD_RUN)

    def test_unknown_inflight_and_identity_drift_refused(self):
        mutations = [
            ('state.children', [123]), ('state.shutdown_sent', False),
            ('state.proof.pending', {'pid': None}), ('state.proof.sync_inflight', 'remove'),
            ('state.proof.jobs', []), ('state.proof.marker.ino', 99),
            ('state.proof.marker.run', NEW), ('state.proof.images', []),
            ('state.proof.complete', False), ('state.proof.leftovers', []),
            ('state.proof.inventory_failure', {}), ('state.proof.root', '/foreign'),
            ('state.baseline_vm130.memory_mib', 4096), ('result.proof_complete', False),
            ('result.reasons', ['owned-child-exit-unconfirmed']), ('config.run_id', NEW),
            ('lease.run', NEW), ('controller.start', None), ('pid', 'bad'),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                data = snapshot()
                target = data
                keys = path.split('.')
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises((g.GuardRefusal, TypeError, KeyError, ValueError)):
                    c.validate(data, NEW)

    def test_image_evidence_drift_refused(self):
        for field, value in [('image', c.IMAGES[1]), ('tag', 'foreign:latest'), ('label', NEW)]:
            data = snapshot()
            data['proof-evidence'][0]['result'][field] = value
            with self.assertRaises(g.GuardRefusal):
                c.validate(data, NEW)

    def private(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        os.chmod(root, 0o700)
        files = c.linux.PrivateFiles(str(root))
        for key, value in snapshot().items():
            files.create(key, value if key == 'pid' else json.dumps(value))
        files.close()
        return root

    def test_private_snapshot_and_no_mutation(self):
        root = self.private()
        before = {f.name: f.read_bytes() for f in root.iterdir()}
        with patch.object(c, 'OLD_ROOT', str(root)):
            self.assertEqual(c.load_prior(NEW)['state']['proof']['marker'], c.MARKER)
        self.assertEqual(before, {f.name: f.read_bytes() for f in root.iterdir()})

    def test_private_records_refuse_links_modes_missing_malformed(self):
        for problem in ('symlink', 'hardlink', 'mode', 'missing', 'malformed', 'rootmode'):
            with self.subTest(problem=problem):
                root = self.private()
                target = root / 'state'
                if problem == 'symlink':
                    target.rename(root / 'saved')
                    target.symlink_to(root / 'saved')
                elif problem == 'hardlink':
                    os.link(target, root / 'saved')
                elif problem == 'mode':
                    target.chmod(0o644)
                elif problem == 'missing':
                    target.unlink()
                elif problem == 'rootmode':
                    root.chmod(0o755)
                else:
                    target.write_text('{')
                with patch.object(c, 'OLD_ROOT', str(root)):
                    with self.assertRaises((g.GuardRefusal, OSError, ValueError)):
                        c.load_prior(NEW)

    def test_live_or_unknown_prior_helper_refused(self):
        root = self.private()
        original = os.stat
        for outcome in (object(), PermissionError()):
            def observe(path, *a, **kw):
                if str(path).startswith('/proc/'):
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
                return original(path, *a, **kw)
            with patch.object(c, 'OLD_ROOT', str(root)), patch.object(c.os, 'stat', side_effect=observe):
                with self.assertRaises((g.GuardRefusal, PermissionError)):
                    c.load_prior(NEW)

    def test_default_and_dry_run_have_no_host_or_snapshot_access(self):
        with patch.object(c.linux, 'host_gate', side_effect=AssertionError), \
                patch.object(c, 'load_prior', side_effect=AssertionError), redirect_stdout(io.StringIO()):
            self.assertEqual(c.cli([]), 0)
            self.assertEqual(c.cli(['controller', '--execute', '--dry-run']), 0)


class CleanupFake(FakeIO):
    def __init__(self):
        super().__init__()
        self.config = config()
        self.latch = StopLatch()
        self.clock = lambda: 0
        self.deadline = 2400
        self.cleanup = False
        self.cleanup_deadline = None
        self.proof_cleanup_deadline = None
        self.admit = NEW
        self.prod = '\n'.join(b.name + '\tUp (healthy)' for b in self.config.baseline)
        self.proof = c.CleanupProof(self, snapshot())
        self.fault = None
        self.saved = []

    records = c.CleanupIO.records
    metadata_proof = c.CleanupIO.metadata_proof

    def checkpoint(self):
        self.saved.append(copy.deepcopy(self.proof.state()))

    def begin_cleanup(self):
        self.latch.trip('cleanup')
        self.cleanup = True
        self.cleanup_deadline = 300

    def _guest(self, inner):
        if inner[:2] == ('python3', '-c'):
            self.assert_fixed(inner)
            action = inner[4]
            if self.fault == action:
                return g.Completed(1, '')
            return g.Completed(0, json.dumps(c.MARKER if action == 'cleanup-check'
                                            else {'removed': str(p.root_for(c.OLD_RUN))}))
        if inner[:2] == ('docker', 'ps'):
            return g.Completed(1 if self.fault == 'users-unknown' else 0,
                               'f' * 64 if self.fault == 'users-foreign' else '')
        if inner[:3] == ('docker', 'image', 'inspect'):
            image = inner[-1]
            tags = [p.tag_for(c.OLD_RUN, p.KINDS[c.IMAGES.index(image)])]
            if self.fault == 'shared':
                tags.append('foreign:latest')
            return g.Completed(0, '\t'.join((image, json.dumps(tags), json.dumps({g.LABEL_KEY: c.OLD_RUN}))))
        if inner[:3] == ('docker', 'image', 'rm'):
            return g.Completed(1 if self.fault == 'rm' else 0, '')
        raise AssertionError(inner)

    def assert_fixed(self, inner):
        assert inner[2] == c.GUEST_CODE and inner[3] == c.OLD_RUN
        assert inner[4] in ('cleanup-check', 'cleanup-remove')
        assert inner[5:] == (str(c.MARKER['dev']), str(c.MARKER['ino']))


class Lifecycle(unittest.TestCase):
    def test_actual_cleanup_binding_fake_pipes_and_stderr_refusal(self):
        for warning in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                calls = []
                def spawn(argv, **kwargs):
                    inner = argv[7:]
                    calls.append(inner)
                    if inner[:2] == ('python3', '-c'):
                        result = c.MARKER if inner[4] == 'cleanup-check' else {'removed': str(p.root_for(c.OLD_RUN))}
                        text = json.dumps(result)
                    elif inner[:3] == ('docker', 'image', 'inspect'):
                        image = inner[-1]
                        text = '\t'.join((image, json.dumps([p.tag_for(c.OLD_RUN, p.KINDS[c.IMAGES.index(image)])]),
                                          json.dumps({g.LABEL_KEY: c.OLD_RUN})))
                    else:
                        text = ''
                    error = 'warning' if warning and inner[:2] == ('docker', 'ps') else ''
                    return Child(json.dumps({'exited': 1, 'exitcode': 0, 'out-data': text, 'err-data': error}).encode())
                real = c.CleanupIO(str(Path(tmp).resolve()), config(), StopLatch(), snapshot(),
                                   popen=spawn, observe=lambda pid: 123, clock=lambda: 0)
                try:
                    real.owned_start = True
                    real.proof.ready = True
                    real.begin_cleanup()
                    reasons = real.proof.cleanup()
                    self.assertEqual(bool(reasons), warning)
                    self.assertEqual(real.proof.completed, not warning)
                    self.assertEqual(len(calls), 2 if warning else 11)
                    self.assertEqual(real.active, {})
                    self.assertFalse(real.unresolved_child)
                finally:
                    real.close()

    def test_cleanup_binding_inherits_psi_grace_sustained_and_memory_floor(self):
        for field in ('avg10', 'avg60', 'memory'):
            with tempfile.TemporaryDirectory() as tmp:
                now = [0]
                real = c.CleanupIO(str(Path(tmp).resolve()), config(), StopLatch(), snapshot(), clock=lambda: now[0])
                try:
                    real.lease_age = lambda: 0
                    real.pressure_state.begin_boot(0)
                    def read(path):
                        if path == '/proc/meminfo':
                            return 'MemAvailable: %d kB' % (1 if field == 'memory' else 8000000)
                        return ('some avg10=0 avg60=0 avg300=0 total=0\n'
                                'full avg10=%d avg60=%d avg300=0 total=0' %
                                (3 if field == 'avg10' else 0, 2 if field == 'avg60' else 0))
                    real.read = read
                    if field == 'memory':
                        with self.assertRaises(g.GuardRefusal):
                            real.check()
                    else:
                        now[0] = 89
                        real.check()
                        now[0] = 90
                        if field == 'avg60':
                            with self.assertRaises(g.GuardRefusal):
                                real.check()
                        else:
                            real.check()
                            now[0] = 119
                            real.check()
                            now[0] = 120
                            with self.assertRaises(g.GuardRefusal):
                                real.check()
                    self.assertTrue(real.latch.closed())
                finally:
                    real.close()

    def run_fake(self, fake):
        return run_guard(fake, fake.config, fake.latch, fake.clock, lambda s: None, max_ticks=4)

    def test_one_boot_old_targets_new_rollback_and_no_proof_calls(self):
        fake = CleanupFake()
        result = self.run_fake(fake)
        self.assertTrue(result.restored)
        self.assertFalse(result.ask_parent)
        self.assertTrue(fake.proof.completed)
        self.assertEqual(fake.records(), g.ProofRecords(NEW, (), ()))
        self.assertEqual(fake.proof.removed, list(c.IMAGES))
        self.assertEqual(fake.calls.count(('qm', 'start', '130')), 1)
        self.assertLess(fake.calls.index(('qm', 'set', '130', '--memory', '4096')),
                        fake.calls.index(('qm', 'start', '130')))
        self.assertLess(fake.calls.index(('qm', 'shutdown', '130', '--timeout', '90')),
                        fake.calls.index(('qm', 'set', '130', '--memory', '8192')))
        self.assertEqual((fake.vm130, fake.memory), ('stopped', 8192))
        self.assertNotIn('proof-complete', result.reasons)
        for command in fake.calls:
            if command[:4] == ('qm', 'guest', 'exec', '130') and command != g.agent_ready_argv():
                inner = command[7:]
                self.assertTrue(inner[:2] == ('python3', '-c') or inner[:2] == ('docker', 'ps')
                                or inner[:3] in (('docker', 'image', 'inspect'), ('docker', 'image', 'rm')))
            self.assertFalse(command[:3] in (('qm', 'set', '100'), ('qm', 'start', '100'), ('qm', 'shutdown', '100')))

    def test_doubt_stops_guest_sequence_and_still_shuts_down(self):
        for fault in ('cleanup-check', 'users-unknown', 'users-foreign', 'shared', 'rm', 'cleanup-remove'):
            with self.subTest(fault=fault):
                fake = CleanupFake()
                fake.fault = fault
                result = self.run_fake(fake)
                self.assertTrue(result.ask_parent)
                self.assertFalse(fake.proof.completed)
                self.assertEqual((fake.vm130, fake.memory), ('stopped', 8192))
                calls = [cmd for cmd in fake.calls if cmd[:4] == ('qm', 'guest', 'exec', '130')]
                if fault != 'cleanup-remove':
                    self.assertNotIn(fake.proof.root_command('cleanup-remove'), calls)
                before = len(fake.calls)
                self.assertTrue(fake.proof.cleanup())
                self.assertEqual(len(fake.calls), before)

    def test_prod_unknown_or_stale_lease_cannot_boot(self):
        for name, value in [('prod', ''), ('nod', '{}'), ('lease', 91), ('vm130', 'running'), ('memory', 6000)]:
            fake = CleanupFake()
            setattr(fake, name, value)
            self.run_fake(fake)
            self.assertNotIn(('qm', 'start', '130'), fake.calls)
            self.assertFalse(fake.proof.attempted)

    def test_memory_trip_after_start_skips_targets_but_restores(self):
        fake = CleanupFake()
        fake.low_after_start = True
        self.run_fake(fake)
        self.assertFalse(fake.proof.attempted)
        self.assertEqual((fake.vm130, fake.memory), ('stopped', 8192))

    def test_normal_guard_mismatch_check_unchanged(self):
        with self.assertRaises(g.GuardRefusal):
            g.rollback(None, config(), g.ProofRecords(c.OLD_RUN, (), ()))

    def test_cleanup_io_denies_normal_metadata_and_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp).resolve())
            real = c.CleanupIO(root, config(), StopLatch(), snapshot(), popen=lambda *a, **kw: self.fail('spawn'))
            try:
                real.owned_start = True
                for command in (g.unit_list_argv(), g.listen_argv(), g.process_meta_argv(),
                                g._guest('130', '30', ('docker', 'create', 'image'))):
                    with self.assertRaises(g.GuardRefusal):
                        real.allowed(command)
                self.assertEqual(real.records(), g.ProofRecords(NEW, (), ()))
            finally:
                real.close()


class AnchoredRoot(unittest.TestCase):
    def test_marker_change_during_scan_refuses_before_deletion(self):
        root, marker = self.fixture()
        original = os.listdir
        changed = [False]
        def mutate(fd):
            if not changed[0]:
                changed[0] = True
                (root / 'owner').write_text('{}')
            return original(fd)
        with patch.object(p.os, 'listdir', side_effect=mutate):
            with self.assertRaises(ValueError):
                self.call(root, marker)
        self.assertTrue((root / 'src' / 'fake').exists())

    def test_foreign_owner_device_and_nested_mount_refused(self):
        for field in ('uid', 'dev', 'mount'):
            root, marker = self.fixture()
            original = os.stat
            def observed(name, *a, **kw):
                info = original(name, *a, **kw)
                if name == 'fake' and kw.get('dir_fd') is not None and field != 'mount':
                    values = list(info)
                    values[4 if field == 'uid' else 2] += 1
                    return os.stat_result(values)
                return info
            target = (root / 'src' / 'fake').stat().st_ino
            def mount(fd):
                return 'foreign' if field == 'mount' and os.fstat(fd).st_ino == target else 'same'
            with patch.object(p.os, 'stat', side_effect=observed), patch.object(p, 'cleanup_mount', side_effect=mount):
                with self.assertRaises(ValueError):
                    p.cleanup_root(root, c.OLD_RUN, marker['dev'], marker['ino'], remove=True)
            self.assertTrue((root / 'src' / 'fake').exists())

    def test_file_replacement_between_scan_and_delete_is_retained(self):
        root, marker = self.fixture()
        original = os.unlink
        swapped = [False]
        def unlink(name, *a, **kw):
            if not swapped[0]:
                swapped[0] = True
                (root / 'payload.tar').rename(root.parent / 'saved-tar')
                (root / 'payload.tar').write_text('replacement must survive')
            return original(name, *a, **kw)
        with patch.object(p.os, 'unlink', side_effect=unlink):
            with self.assertRaises(ValueError):
                self.call(root, marker)
        self.assertEqual((root / 'payload.tar').read_text(), 'replacement must survive')

    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        parent = Path(temp.name).resolve()
        root = parent / 'owned'
        root.mkdir(mode=0o700)
        marker = {'run': c.OLD_RUN, 'dev': root.stat().st_dev, 'ino': root.stat().st_ino}
        for name in ('owner', 'payload-meta', 'payload.tar'):
            p.private_write(root / name, json.dumps(marker).encode() if name == 'owner' else b'fake')
        for name in ('src', 'home', 'tmp', 'config', 'state', 'cache', 'data', 'runtime', 'docker-config', 'jobs'):
            (root / name).mkdir()
        (root / 'src' / 'fake').write_text('fake artifact')
        return root, marker

    def call(self, root, marker, remove=True):
        with patch.object(p, 'cleanup_mount', return_value='fake-mount'):
            return p.cleanup_root(root, c.OLD_RUN, marker['dev'], marker['ino'], remove=remove)

    def test_valid_check_then_fd_relative_remove(self):
        root, marker = self.fixture()
        self.assertEqual(self.call(root, marker, False), marker)
        self.assertTrue(root.exists())
        self.assertEqual(self.call(root, marker), {'removed': str(root)})
        self.assertFalse(root.exists())

    def test_wrong_marker_inode_unexpected_entry_symlink_hardlink_special(self):
        for problem in ('marker', 'inode', 'extra', 'symlink', 'hardlink', 'fifo', 'owner-mode'):
            with self.subTest(problem=problem):
                root, marker = self.fixture()
                outside = root.parent / 'protected'
                outside.write_text('untouched')
                if problem == 'marker':
                    (root / 'owner').write_text('{}')
                elif problem == 'inode':
                    marker['ino'] += 1
                elif problem == 'extra':
                    (root / 'unexpected').write_text('retain')
                elif problem == 'symlink':
                    (root / 'src' / 'link').symlink_to(outside)
                elif problem == 'hardlink':
                    os.link(outside, root / 'src' / 'link')
                elif problem == 'fifo':
                    os.mkfifo(root / 'src' / 'fifo')
                else:
                    (root / 'owner').chmod(0o644)
                with self.assertRaises((ValueError, OSError)):
                    self.call(root, marker)
                self.assertTrue(root.exists())
                self.assertEqual(outside.read_text(), 'untouched')

    def test_mount_and_root_identity_swap_refused(self):
        root, marker = self.fixture()
        with patch.object(p, 'cleanup_mount', side_effect=['root', 'foreign']):
            with self.assertRaises(ValueError):
                p.cleanup_root(root, c.OLD_RUN, marker['dev'], marker['ino'], remove=True)
        original = p.os.listdir
        changed = [False]
        def swap(fd):
            result = original(fd)
            if not changed[0]:
                changed[0] = True
                root.rename(root.parent / 'old')
                root.mkdir(mode=0o700)
                (root / 'protected').write_text('untouched')
            return result
        with patch.object(p.os, 'listdir', side_effect=swap):
            with self.assertRaises(ValueError):
                self.call(root, marker)
        self.assertEqual((root / 'protected').read_text(), 'untouched')
        self.assertTrue((root.parent / 'old' / 'src' / 'fake').exists())


class Supervision(unittest.TestCase):
    def run_case(self, *, ready=True, mismatch=False, identity=True, exit_after=2, wait_timeout=False,
                 stopped=False, identity_drift=False):
        now = [0]
        class Files:
            writes = []
            leases = []
            def read(self, name):
                if not ready:
                    raise FileNotFoundError()
                return 'wrong' if mismatch else f'{NEW}\n42 100\n'
            def create(self, name, text):
                self.writes.append((name, text))
            def publish_lease(self, record):
                self.leases.append(record)
        class Child:
            pid = 42
            waited = False
            def poll(self):
                return 0 if now[0] >= exit_after else None
            def wait(self, timeout):
                self.waited = True
                assert timeout == 400
                if wait_timeout:
                    raise subprocess.TimeoutExpired('fake', timeout)
                return 0
        files, child = Files(), Child()
        def sleep(seconds):
            now[0] += seconds
        code = c.supervise(child, files, NEW, {'pid': 1, 'start': 1},
                           observe=lambda pid: (101 if identity_drift and now[0] else 100) if identity else None,
                           clock=lambda: now[0], sleep=sleep, stopped=lambda: stopped)
        return code, child, files

    def test_success_positive_reap(self):
        code, child, files = self.run_case()
        self.assertEqual(code, 0)
        self.assertTrue(child.waited)
        self.assertEqual(files.writes, [('admit', NEW)])

    def test_lease_deadline_still_waits_cleanup(self):
        code, child, files = self.run_case(exit_after=99999)
        self.assertTrue(child.waited)
        self.assertTrue(all(row['monotonic'] < 2400 for row in files.leases))
        self.assertEqual(code, 0)  # controller separately verifies the durable result

    def test_unknown_identity_ready_race_and_timeout_never_complete(self):
        for kwargs in ({'identity': False}, {'mismatch': True}, {'ready': False},
                       {'exit_after': 99999, 'wait_timeout': True}):
            code, child, files = self.run_case(**kwargs)
            self.assertEqual(code, 2)
            self.assertTrue(child.waited)
            if not kwargs.get('wait_timeout'):
                self.assertEqual(files.writes, [])

    def test_signal_and_reused_guard_identity_close_lease_and_reap(self):
        for kwargs in ({'stopped': True}, {'identity_drift': True, 'exit_after': 10}):
            code, child, files = self.run_case(**kwargs)
            self.assertEqual(code, 2)
            self.assertTrue(child.waited)
            self.assertLessEqual(len(files.leases), 1)

    def test_controller_snapshots_before_spawn_and_checks_final_result(self):
        for complete in (True, False):
            with tempfile.TemporaryDirectory() as tmp:
                root = str(Path(tmp).resolve())
                data = snapshot()
                data['config']['baseline'] = list(data['config']['baseline'])
                order = []
                def prior(run):
                    order.append('snapshot')
                    return data
                def prepare(parent, run):
                    order.append('root')
                    return root
                def spawn(cmd, **kw):
                    order.append('spawn')
                    self.assertNotIn('--archive', cmd)
                    self.assertNotIn('--checkout', cmd)
                    self.assertIn(NEW, cmd)
                    self.assertEqual(Path(cmd[1]).name, 'vm_proof_cleanup.py')
                    return object()
                def supervise(child, files, *a, **kw):
                    self.assertEqual(json.loads(files.read('inventory')), json.loads(json.dumps(data)))
                    files.create('result', json.dumps({'cleanup_complete': complete, 'restored': True, 'ask_parent': False}))
                    files.create('state', json.dumps({'children': []}))
                    return 0
                args = SimpleNamespace(run_id=NEW, baseline=[b.name + ':healthy' for b in config().baseline])
                with patch.object(c, 'load_prior', side_effect=prior), patch.object(c, 'prepare_run_root', side_effect=prepare), \
                        patch.object(c.linux, 'identity', return_value=100), patch.object(c.subprocess, 'Popen', side_effect=spawn), \
                        patch.object(c, 'supervise', side_effect=supervise):
                    if complete:
                        self.assertEqual(c.controller(args, config()), 0)
                    else:
                        with self.assertRaises(g.GuardRefusal):
                            c.controller(args, config())
                self.assertEqual(order, ['snapshot', 'root', 'spawn'])


if __name__ == '__main__':
    unittest.main()
