"""Pure release child-environment checks: no imports of Toolstack or subprocesses."""
from pathlib import Path
import unittest

from check_release import child_environment


class ChildEnvironment(unittest.TestCase):
    def test_rejects_credentials_and_application_configuration(self):
        parent = {key: 'must-not-inherit' for key in (
            'SP_SECRET', 'SP_VAULT_PASSPHRASE', 'SP_VAULT_PASSPHRASE_FILE',
            'SP_CONFIG', 'TOOLSTACK_SPS_ENV', 'TOOLSTACK_E_SECRET',
            'TOOLSTACK_CHANNEL_SECRET', 'TOOLSTACK_TOOLYARD_STATE',
            'SPS_CONFIG', 'AWS_SECRET_ACCESS_KEY', 'VAULT_TOKEN',
            'INFISICAL_TOKEN', 'UV_INDEX_URL', 'HTTPS_PROXY',
            'PYTHONPATH', 'PYTHONHOME', 'UNEXPECTED_FUTURE_SETTING')}
        original = parent.copy()
        env = child_environment(parent, Path('/fake/private/release'))
        self.assertTrue(set(parent).isdisjoint(env))
        self.assertEqual(parent, original)
        self.assertEqual(env['TOOLSTACK_SPS_SKIP'], '1')

    def test_preserves_only_explicit_runtime_paths(self):
        parent = {key: '/fake/' + key for key in (
            'PATH', 'TMPDIR', 'UV_CACHE_DIR', 'UV_PYTHON_INSTALL_DIR')}
        env = child_environment(parent, Path('/fake/private/release'))
        for key, value in parent.items():
            self.assertEqual(env[key], value)

    def test_home_and_all_xdg_paths_are_temporary_from_start(self):
        base = Path('/fake/private/release')
        parent = {key: '/real/operator' for key in (
            'HOME', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME',
            'XDG_DATA_HOME', 'XDG_RUNTIME_DIR')}
        env = child_environment(parent, base)
        self.assertEqual(env['HOME'], str(base))
        for key in parent.keys() - {'HOME'}:
            self.assertTrue(Path(env[key]).is_relative_to(base))
        self.assertEqual(env['PYTHONNOUSERSITE'], '1')
        self.assertEqual(env['UV_CONCURRENT_BUILDS'], '1')
        self.assertEqual(env['UV_CONCURRENT_INSTALLS'], '1')


if __name__ == '__main__':
    unittest.main()
