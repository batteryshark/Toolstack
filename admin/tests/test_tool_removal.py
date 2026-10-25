import tempfile
import unittest
from pathlib import Path
from unittest import mock

from admin.broker_config import BrokerRunConfig
from admin.tool_removal import remove_tool


class ToolRemoval(unittest.TestCase):
    def test_external_unregister_retains_files_and_other_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            external = root/'external'
            external.mkdir()
            manifest = external/'toolyard.toml'
            content = 'id="external"\ntype="api"\n[entrypoint]\nport=43211\n'
            manifest.write_text(content)
            config = BrokerRunConfig(db_path=str(root/'fake.db'), tools_root=str(root/'managed'),
                                      tool_dirs=[str(external), str(root/'other')])
            with mock.patch('admin.tool_removal.toolyard_ops.stop') as stop, \
                 mock.patch('admin.tool_removal.operator_audit.save_config') as save:
                result = remove_tool(config, 'external', 'fake-admin')
            self.assertEqual(result, {'removed': 'external', 'deleted': False})
            self.assertEqual(manifest.read_text(), content)
            self.assertEqual(save.call_args.args[1].tool_dirs, [str(root/'other')])
            self.assertEqual(config.tool_dirs, [str(external), str(root/'other')])
            stop.assert_called_once_with('external')

    def test_unknown_ownership_refuses_before_effect(self):
        config = BrokerRunConfig(tools_root='/fake/managed', tool_dirs=[])
        with mock.patch('admin.tool_removal.toolyard_ops.list_tools', return_value=[
            {'id': 'unknown', 'path': '/fake/elsewhere'}]), \
             mock.patch('admin.tool_removal.toolyard_ops.remove') as remove:
            with self.assertRaisesRegex(ValueError, 'Ownership unknown for unknown'):
                remove_tool(config, 'unknown', 'fake-admin')
            remove.assert_not_called()
