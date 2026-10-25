"""Local signing command contracts only; never invoke real Apple tools."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / 'macapp/packaging'
IDENTITY = 'Apple Development: FAKE Identity (FAKE123)'


class LocalSigning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='local-sign-contract-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.app = self.root / 'Fake Operator.app'
        (self.app / 'Contents').mkdir(parents=True)
        self.log = self.root / 'argv.json'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        # No shell/real codesign fallback: this is the only command named codesign.
        import sys
        stub = self.bin / 'codesign'
        stub.write_text(f'#!{sys.executable}\n'
                        'import json, os, sys\n'
                        'with open(os.environ["ARGV_LOG"], "w") as f: json.dump(sys.argv[1:], f)\n'
                        'sys.exit(int(os.environ.get("FAKE_EXIT", "0")))\n')
        stub.chmod(0o700)
        for command in ('security', 'xcrun', 'spctl', 'swift', 'curl', 'ditto'):
            trap = self.bin / command
            trap.write_text('#!/bin/bash\nexit 99\n')
            trap.chmod(0o700)
        self.env = {'PATH': f'{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin',
                    'HOME': str(self.root), 'TMPDIR': str(self.root),
                    'ARGV_LOG': str(self.log)}

    def run_script(self, name, *args, env=None):
        return subprocess.run(['/bin/bash', str(PACKAGING / name), *map(str, args)],
                              cwd=self.root, env=env or self.env,
                              capture_output=True, text=True, timeout=5)

    def test_explicit_identity_and_spaces_exact_argv(self):
        result = self.run_script('sign-local.sh', '--identity', IDENTITY, '--app', self.app)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.log.read_text()),
                         ['--force', '--sign', IDENTITY, '--timestamp=none', str(self.app)])

    def test_environment_identity_and_argument_override(self):
        env = dict(self.env, TOOLSTACK_LOCAL_SIGN_IDENTITY=IDENTITY)
        self.assertEqual(self.run_script('sign-local.sh', '--app', self.app, env=env).returncode, 0)
        self.assertEqual(self.run_script('sign-local.sh', '--identity', IDENTITY,
                                        '--app', self.app, env=dict(env, TOOLSTACK_LOCAL_SIGN_IDENTITY='-')).returncode, 0)

    def test_verification_independent_strict_deep(self):
        result = self.run_script('verify-local.sh', self.app)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.log.read_text()),
                         ['--verify', '--deep', '--strict', '--verbose=2', str(self.app)])

    def test_failures_propagate_without_fallback(self):
        for name, args in (('sign-local.sh', ('--identity', IDENTITY, '--app', self.app)),
                           ('verify-local.sh', (self.app,))):
            with self.subTest(name=name):
                result = self.run_script(name, *args, env=dict(self.env, FAKE_EXIT='42'))
                self.assertEqual(result.returncode, 42)

    def test_missing_invalid_inputs_never_call_codesign(self):
        cases = [('sign-local.sh', ['--app', self.app]),
                 ('sign-local.sh', ['--identity', '-','--app', self.app]),
                 ('sign-local.sh', ['--identity', 'Developer ID Application: FAKE','--app', self.app]),
                 ('sign-local.sh', ['--identity', IDENTITY,'--app', self.root / 'missing.app']),
                 ('sign-local.sh', ['--identity']),
                 ('sign-local.sh', ['--build']),
                 ('verify-local.sh', [self.root / 'missing.app']),
                 ('verify-local.sh', [self.app, self.app])]
        for name, args in cases:
            with self.subTest(name=name, args=args):
                self.assertNotEqual(self.run_script(name, *args).returncode, 0)
                self.assertFalse(self.log.exists())

    def test_no_private_sources_or_distribution_commands(self):
        # Inspect only the new scripts, never open any private credential files.
        for name in ('sign-local.sh', 'verify-local.sh'):
            source = (PACKAGING / name).read_text()
            for forbidden in ('signing.env', 'secrets.env', 'notarytool', 'spctl',
                              'security ', 'xcrun ', 'swift ', 'source ', 'eval ',
                              'sign-and-notarize.sh', '--options runtime'):
                self.assertNotIn(forbidden, source)
            self.assertNotRegex(source, r'(?m)^\s*\.\s')


if __name__ == '__main__':
    unittest.main()
