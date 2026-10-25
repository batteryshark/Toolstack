"""One fixed prior-proof cleanup; inert by default. Parent live admission required."""
import argparse
import dataclasses
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import vm_proof_guard as g
import vm_proof_linux as linux
import vm_proof_payload as payload
from vm_proof_adapter import StopLatch, prepare_run_root, run_guard, timeout_for
from vm_proof_driver import GUEST_CODE

OLD_RUN = 'vmproof-20261024T182625Z-2b3a3e9a'
OLD_ROOT = '/var/tmp/' + OLD_RUN
MARKER = {'run': OLD_RUN, 'dev': 2049, 'ino': 2097223}
IMAGES = (
    'sha256:fb8e78e8c31cdc5fb7a8ca893d58a56358efe152145e8433ff23e5837418c9c3',
    'sha256:bc4444aff2d536d62ca0ef3ec113dda922db2abe4c17724bfb1c805fbdda582d',
    'sha256:b9e50c2fafe2ba9da97191f9c1120c8bf1b2d91096141bbefe9822a18f375cf4',
)
COMMIT = '78ea9049a3370688b721e7ff3bda31a8b3f184c3'
DIGEST = '70aa41ab2f4fc04aece1661b773af93b29458a8d82a3048cacb29a13aa4350a4'
RECORDS = ('config', 'state', 'result', 'proof-evidence', 'controller', 'lease', 'pid')


def require(ok, reason):
    if not ok:
        raise g.GuardRefusal(reason)


def validate(snapshot, control):
    """No CLI targets. The old approved identity is corroborated by owned records."""
    g.require_run_id(control)
    require(control != OLD_RUN, 'new control run required')
    require(set(snapshot) == set(RECORDS), 'snapshot record set')
    config, state, result = (snapshot[k] for k in ('config', 'state', 'result'))
    proof = state['proof']
    reasons = ['image-users-unknown:' + image for image in IMAGES]
    require(config['run_id'] == OLD_RUN and len(config['baseline']) == 16,
            'prior config identity/baseline')
    require(set(config) == {'run_id', 'baseline', 'window_seconds', 'lease_stale_seconds'}
            and config['window_seconds'] == g.WINDOW_SECONDS
            and config['lease_stale_seconds'] == g.LEASE_STALE_SECONDS, 'prior guard limits')
    require(state['owned_resize'] is True and state['owned_start'] is True
            and state['shutdown_sent'] is True and state['children'] == []
            and state['containers'] == [] and state['images'] == []
            and state['stop'] == 'proof-complete'
            and state['baseline_vm130'] == {'status': 'stopped', 'memory_mib': 8192, 'cores': 2, 'onboot': 0},
            'prior transition not fenced')
    require(result == {'ask_parent': True, 'phase': 'monitor', 'reasons': ['proof-complete', *reasons],
                       'restored': False, 'proof_complete': True}, 'prior result not recognized')
    require(proof['pending'] is None and proof['sync_inflight'] is None
            and proof['inventory_stage'] is None and proof['inventory_failure'] is None
            and proof['complete'] is True and proof['root_attempted'] is True
            and proof['leftovers'] == reasons and proof['images'] == list(IMAGES)
            and proof['marker'] == MARKER and proof['root'] == str(payload.root_for(OLD_RUN))
            and proof['commit'] == COMMIT and proof['sha256'] == DIGEST,
            'prior proof identity/inflight unknown')
    expected_jobs = {action + '-' + kind for action in ('create', 'start')
                     for kind in (*payload.KINDS, 'process-sps', 'serve')}
    expected_jobs |= {'build-' + kind for kind in payload.KINDS}
    jobs = proof['jobs']
    require(len(jobs) == len(expected_jobs) and {j['key'] for j in jobs} == expected_jobs,
            'prior jobs incomplete')
    for job in jobs:
        ident = job['identity']
        require(type(job['pid']) is int and job['pid'] > 1 and type(job['exitcode']) is int and job['exitcode'] == 0
                and ident['pid'] == job['pid'] and type(ident['start']) is int and ident['start'] > 0
                and isinstance(ident['boot'], str) and len(ident['boot']) == 36,
                'prior job identity/outcome unknown')
    evidence = snapshot['proof-evidence']
    require(len(evidence) == len(expected_jobs) + 1 and
            {e['step'] for e in evidence} == expected_jobs | {'extract-offline-units'}, 'evidence steps')
    rows = {e['step']: e['result'] for e in evidence}
    require(rows['extract-offline-units']['commit'] == COMMIT and
            rows['extract-offline-units']['sha256'] == DIGEST, 'source evidence identity')
    for kind, image in zip(payload.KINDS, IMAGES):
        require(rows['build-' + kind] == {'image': image, 'tag': payload.tag_for(OLD_RUN, kind),
                                        'label': OLD_RUN}, 'image evidence identity')
    containers = [rows['create-' + kind]['container'] for kind in (*payload.KINDS, 'process-sps', 'serve')]
    require(proof['containers'] == containers and len(set(containers)) == 5
            and all(g.canonical_container_id(c) for c in containers), 'container records')
    owner, lease = snapshot['controller'], snapshot['lease']
    require(set(owner) == {'pid', 'start'} and all(type(v) is int and v > 1 for v in owner.values()),
            'prior controller identity')
    require(lease['run'] == OLD_RUN and all(lease[k] == owner[k] for k in owner)
            and g._finite_nonnegative(lease['monotonic']), 'prior lease identity')
    lines = snapshot['pid'].splitlines()
    require(len(lines) == 2 and lines[0] == OLD_RUN, 'prior guard identity')
    guard = tuple(map(int, lines[1].split()))
    require(len(guard) == 2 and all(v > 1 for v in guard), 'prior guard identity')
    return (owner['pid'], guard[0])


def load_prior(control):
    files = linux.PrivateFiles(OLD_ROOT)
    try:
        snapshot = {}
        for name in RECORDS:
            text = files._read(name, snapshot=True)
            snapshot[name] = text if name == 'pid' else json.loads(text)
        for pid in validate(snapshot, control):
            # Only ENOENT proves absence; permission/errors/reused/live PID refuse.
            try:
                os.stat('/proc/' + str(pid))
            except FileNotFoundError:
                continue
            raise g.GuardRefusal('prior helper not positively absent')
        again = linux.open_directory(OLD_ROOT)
        try:
            require((os.fstat(again).st_dev, os.fstat(again).st_ino) ==
                    (os.fstat(files.fd).st_dev, os.fstat(files.fd).st_ino), 'prior root changed')
        finally:
            os.close(again)
        return snapshot
    finally:
        files.close()


class CleanupProof:
    """Old target authority only; never supplies physical VM rollback records."""
    root_attempted = True

    def __init__(self, io, snapshot):
        validate(snapshot, io.config.run_id)
        self.io = io
        self.expected = None
        self.ready = self.attempted = self.completed = False
        self.leftovers = []
        self.removed = []

    def state(self):
        return {'mode': 'cleanup-only', 'target_run': OLD_RUN, 'marker': MARKER,
                'images': list(IMAGES), 'removed': self.removed, 'complete': self.completed,
                'attempted': self.attempted, 'ready': self.ready, 'leftovers': self.leftovers}

    def root_command(self, action):
        require(action in ('cleanup-check', 'cleanup-remove'), 'fixed cleanup action')
        return ('qm', 'guest', 'exec', '130', '--timeout', '30', '--', 'python3', '-c',
                GUEST_CODE, OLD_RUN, action, str(MARKER['dev']), str(MARKER['ino']))

    def permit(self, argv, data):
        return (data is None and tuple(argv) == self.expected and self.io.owned_start
                and self.io.cleanup and self.io.latch.closed())

    def emit(self, argv):
        argv = tuple(argv)
        require(self.io.clock() < self.io.proof_cleanup_deadline, 'cleanup target budget')
        if argv not in (self.root_command('cleanup-check'), self.root_command('cleanup-remove')):
            g.rollback_command_allowed(argv, OLD_RUN)
            require(argv[7:] in {
                inner for image in IMAGES for inner in (
                    ('docker', 'ps', '-a', '--no-trunc', '--filter', 'ancestor=' + image, '--format', '{{.ID}}'),
                    ('docker', 'image', 'inspect', '--format', g.IMAGE_INSPECT_FORMAT, image),
                    ('docker', 'image', 'rm', image))}, 'not a fixed cleanup command')
        with self.io.latch.lock:
            require(self.expected is None, 'concurrent cleanup')
            self.expected = argv
            try:
                return self.io.run(argv, timeout_for(argv))
            finally:
                self.expected = None

    def cleanup(self):
        require(self.io.cleanup and self.io.latch.closed(), 'cleanup admission open')
        if not self.ready or self.attempted:
            return ['cleanup-not-admitted-or-already-attempted']
        self.attempted = True
        self.io.checkpoint()
        self.io.proof_cleanup_deadline = min(self.io.cleanup_deadline, self.io.clock() + 45)
        try:
            checked = self.emit(self.root_command('cleanup-check'))
            require(checked.code == 0 and json.loads(checked.stdout) == MARKER, 'root preflight unknown')
            for image in IMAGES:
                reasons = []
                g._remove_image(self.emit, OLD_RUN, image, reasons)
                require(not reasons, ';'.join(reasons))
                self.removed.append(image)
                self.io.checkpoint()
            removed = self.emit(self.root_command('cleanup-remove'))
            require(removed.code == 0 and json.loads(removed.stdout) ==
                    {'removed': str(payload.root_for(OLD_RUN))}, 'root removal unconfirmed')
            self.completed = True
        except g.GuardRefusal as exc:
            self.leftovers.append(str(exc))
        except Exception:
            # No retries and no more guest effects; physical rollback still runs.
            self.leftovers.append('cleanup-refused-or-unknown: retained artifacts; no retry')
        finally:
            self.io.proof_cleanup_deadline = None
            self.io.checkpoint()
        return self.leftovers


class CleanupIO(linux.LinuxSubprocessIO):
    def __init__(self, root, config, latch, snapshot, **kwargs):
        validate(snapshot, config.run_id)
        super().__init__(root, config, latch, 'discover', **kwargs)
        self.proof = CleanupProof(self, snapshot)

    def records(self):
        return g.ProofRecords(self.config.run_id, (), ())

    def metadata_proof(self, latch):
        sample, shape = linux._fresh(self, self.config, 2400 - (self.deadline - self.clock()))
        require(not g.assess(sample, self.config).rollback and
                (shape.status, shape.memory_mib, shape.cores, shape.onboot) == ('running', 4096, 2, 0),
                'cleanup health/shape')
        latch.before_effect()
        self.proof.ready = True
        # Avoid the normal adapter's proof-complete label.
        latch.trip('cleanup-only-ready')
        self.checkpoint()

    def allowed(self, argv, input_data=None):
        # Narrow the inherited metadata allowlist, never broaden it.
        if argv[:3] == ('qm', 'guest', 'exec') and argv[3] == '130':
            if argv != g.agent_ready_argv() and not self.proof.permit(argv, input_data):
                raise g.GuardRefusal('cleanup-only guest command refused')
        return super().allowed(argv, input_data)


def supervise(child, files, run, owner, *, observe=linux.identity, clock=time.monotonic,
              sleep=time.sleep, stopped=lambda: False):
    """Stop renewing at 40 min; reap the exact Popen child through cleanup bound."""
    valid = False
    admitted = False
    deadline = clock() + 2400
    try:
        start = observe(child.pid)
        valid = start is not None
        while valid and child.poll() is None and clock() < deadline:
            require(not stopped(), 'controller signal')
            require(observe(child.pid) == start, 'guard identity changed')
            if not admitted:
                try:
                    require(files.read('ready') == f'{run}\n{child.pid} {start}\n', 'ready identity mismatch')
                    files.create('admit', run)
                    admitted = True
                except FileNotFoundError:
                    pass
            files.publish_lease(dict(owner, run=run, monotonic=clock()))
            sleep(2)
    except (Exception, KeyboardInterrupt):
        valid = False
    # No signal to an unknown/reused PID. Lease expiry <=90 + cleanup <=300.
    try:
        code = child.wait(timeout=400)
    except subprocess.TimeoutExpired:
        return 2  # explicitly uncertain; never report completion
    return code if valid and admitted and not stopped() else 2


def controller(args, config):
    snapshot = load_prior(args.run_id)  # before creating a new root or spawning
    require(snapshot['config']['baseline'] == [dataclasses.asdict(b) for b in config.baseline],
            'baseline differs from prior approved set')
    root = prepare_run_root('/var/tmp', args.run_id)
    files = linux.PrivateFiles(root)
    stopped = [False]
    handlers = {}
    try:
        start = linux.identity(os.getpid())
        require(start is not None, 'controller identity unknown')
        owner = {'pid': os.getpid(), 'start': start}
        files.create('inventory', json.dumps(snapshot))
        files.create('controller', json.dumps(owner))
        files.create('lease', json.dumps(dict(owner, run=args.run_id, monotonic=time.monotonic())))
        cmd = [sys.executable, str(Path(__file__).resolve()), 'guard', '--execute', '--live', '--run-id', args.run_id]
        for entry in args.baseline:
            cmd += ['--baseline', entry]
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[sig] = signal.signal(sig, lambda signum, frame: stopped.__setitem__(0, True))
        require(not stopped[0], 'controller signal before spawn')
        child = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'HOME': root})
        code = supervise(child, files, args.run_id, owner, stopped=lambda: stopped[0])
        if code:
            return code
        result = json.loads(files.read('result'))
        state = json.loads(files.read('state'))
        require(result['cleanup_complete'] is True and result['restored'] is True
                and result['ask_parent'] is False and state['children'] == [], 'cleanup result incomplete')
        return 0
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        files.close()


def cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', choices=('controller', 'guard'))
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--run-id')
    parser.add_argument('--baseline', action='append', default=[])
    args = parser.parse_args(argv)
    if args.dry_run or not args.execute:
        print('dry-run: cleanup-only; fixed prior run ' + OLD_RUN + '; no commands or writes')
        return 0
    try:
        require(args.live and args.mode and args.run_id, 'explicit mode/live/new run required')
        g.require_run_id(args.run_id)
        require(args.run_id != OLD_RUN, 'new control run required')
        config = linux.baseline_config(args)
        require(len(config.baseline) == 16, 'all 16 production baseline entries required')
        linux.host_gate()
        if args.mode == 'controller':
            return controller(args, config)
        root = '/var/tmp/' + args.run_id
        files = linux.PrivateFiles(root)
        try:
            snapshot = json.loads(files.read('inventory'))
        finally:
            files.close()
        require(snapshot['config']['baseline'] == [dataclasses.asdict(b) for b in config.baseline], 'baseline mismatch')
        latch = StopLatch()
        io = CleanupIO(root, config, latch, snapshot)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, lambda signum, frame: latch.trip('signal'))
        try:
            result = run_guard(io, config, latch, time.monotonic, time.sleep)
            complete = io.proof.completed and not io.active and not io.unresolved_child
            if not complete:
                result = dataclasses.replace(result, ask_parent=True, restored=False,
                                             reasons=(*result.reasons, 'cleanup-incomplete-or-child-unknown'))
            io.checkpoint()
            io.files.create('result', json.dumps(dict(dataclasses.asdict(result), mode='cleanup-only',
                                                    target_run=OLD_RUN, cleanup_complete=complete)))
            return 0 if complete and result.restored and not result.ask_parent else 1
        finally:
            io.close()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, g.GuardRefusal):
        print('cleanup refused/uncertain; inspect private records; no retry', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
