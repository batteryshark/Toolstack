"""Cheap source-contract checks; no daemon or installed service access."""
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DeploymentContracts(unittest.TestCase):
    def test_offline_bootstrap_writable_paths(self):
        with tempfile.TemporaryDirectory(prefix='toolstack-bootstrap-') as tmp:
            root = Path(tmp).resolve()  # macOS /var aliases /private/var
            config = root / 'etc/sps.env'
            subprocess.run([sys.executable, str(ROOT / 'deploy/bootstrap-sps.py'),
                            '--config', str(config), '--state-dir', str(root / 'state'),
                            '--log-dir', str(root / 'log')], cwd=ROOT, check=True,
                           capture_output=True, text=True, timeout=30)
            data = tomllib.loads(config.read_text())
            self.assertEqual(data['localfile']['VAULT_FILE'], str(root / 'state/sps.vault.json'))
            self.assertEqual(data['SP_AUDIT_LOG'], str(root / 'log/sps.audit'))
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            self.assertFalse((root / 'state/sps.vault.json').exists())

    def test_wheel_entrypoint_and_packages(self):
        project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
        self.assertEqual(project['project']['scripts']['admin'], 'admin.__main__:main')
        self.assertIn('admin.views', project['tool']['setuptools']['packages'])

    def test_all_installers_consume_same_export(self):
        for path in ('deploy/install.sh', 'deploy/redeploy-toolstack', 'deploy/docker/Dockerfile'):
            source = (ROOT / path).read_text()
            self.assertIn('admin/requirements.txt', source)
            self.assertIn('admin/requirements-lock.txt', source)

    def test_private_units_and_no_toml_environmentfile(self):
        for component in ('admin', 'sps'):
            source = (ROOT / f'deploy/toolstack-{component}.service').read_text()
            for setting in ('UMask=0077', 'StateDirectoryMode=0700', 'NoNewPrivileges=true'):
                self.assertIn(setting, source)
        sps = (ROOT / 'deploy/toolstack-sps.service').read_text()
        self.assertNotIn('EnvironmentFile=-/etc/toolstack/sps.env', sps)

    def test_docker_contents_and_command(self):
        source = (ROOT / 'deploy/docker/Dockerfile').read_text()
        self.assertIn('COPY sps/ sps/', source)
        self.assertIn('COPY toolstack_forwarder/ toolstack_forwarder/', source)
        self.assertNotIn('"--host"', source)
        self.assertIn('profiles: [experimental]', (ROOT / 'deploy/docker/docker-compose.yml').read_text())


if __name__ == '__main__':
    unittest.main()
