import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from admin.broker_config import BrokerRunConfig
from admin.catalog_observation import observe_catalog
from broker.server import build_server


class CatalogObservation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.folder = root / 'tools' / 'fake'
        self.folder.mkdir(parents=True)
        self.manifest = self.folder / 'toolyard.toml'
        self.text = 'id="fake"\ntype="api"\n[entrypoint]\nport=43210\n[[operations]]\nname="read"\nrisk="read"\n'
        self.manifest.write_text(self.text)
        self.server = build_server(port=0, host='127.0.0.1', db_path=str(root/'test.db'),
                                  tools_root=str(self.folder.parent), surface=mock.Mock())
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.close)
        self.config = BrokerRunConfig(db_path=str(root/'test.db'), tools_root=str(self.folder.parent),
                                      port=self.server.server_address[1])

    def close(self):
        self.server.shutdown()
        self.thread.join(3)
        self.server.server_close()
        self.server.ctx.store.close()

    def health(self):
        with urllib.request.urlopen(f'http://127.0.0.1:{self.config.port}/v1/health', timeout=2) as r:
            return json.load(r)

    def test_actual_load_edit_reload_and_failed_reload(self):
        first = self.health()['catalog_observation_id']
        self.assertEqual(observe_catalog(self.config)['status'], 'verified')
        self.manifest.write_text(self.text.replace('risk="read"', 'risk="write"'))
        self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})
        self.server.reload_registry()
        self.assertNotEqual(self.health()['catalog_observation_id'], first)
        self.assertEqual(observe_catalog(self.config)['status'], 'verified')
        self.manifest.write_text('invalid = [')
        with self.assertRaises(ValueError):
            self.server.reload_registry()
        self.assertNotIn('catalog_observation_id', self.health())
        self.manifest.write_text(self.text)
        self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})

    def test_cached_listing_does_not_prove_membership_after_reload(self):
        from admin.toolyard_ops import list_tools
        from admin.views.tools import tools_view
        cached = list_tools(self.config.tools_root)
        self.assertEqual(observe_catalog(self.config)['tool_ids'], ['fake'])
        self.manifest.unlink()
        self.server.reload_registry()
        empty = observe_catalog(self.config)
        self.assertEqual(empty['status'], 'verified')
        self.assertEqual(empty['tool_ids'], [])
        html = tools_view(user='fake',csrf='fake',tools=cached,tools_root=self.config.tools_root,catalog=empty)
        self.assertNotIn('Catalog verified', html)
        self.assertIn('Registration unknown', html)
        self.manifest.write_text(self.text.replace('id="fake"','id="other"'))
        self.server.reload_registry()
        self.assertEqual(observe_catalog(self.config)['tool_ids'], ['other'])
        self.manifest.write_text('id="fake"\ntype="api"\n[entrypoint]\nport=43210\n')
        self.server.reload_registry()
        zero_ops = observe_catalog(self.config)
        self.assertEqual(zero_ops['tool_ids'], ['fake'])
        self.assertEqual(self.server.ctx.registry.list_ops(), [])
        self.assertIn('Catalog verified', tools_view(user='fake',csrf='fake',tools=cached,tools_root=self.config.tools_root,catalog=zero_ops))

    def test_cached_row_rejects_legacy_and_malformed_membership(self):
        from admin.catalog_observation import target_verified
        from admin.toolyard_ops import list_tools
        from admin.views.tools import tools_view
        cached = list_tools(self.config.tools_root)
        for ids in (None, 'fake', {}, [None], ['fake', 3], [], ['other']):
            self.assertFalse(target_verified({'status':'verified','tool_ids':ids}, 'fake'))
            html = tools_view(user='fake',csrf='fake',tools=cached,tools_root=self.config.tools_root,
                              catalog={'status':'verified','tool_ids':ids})
            self.assertNotIn('Catalog verified', html)
        self.assertFalse(target_verified({'status':'verified'}, 'fake'))
        self.assertTrue(target_verified({'status':'verified','tool_ids':['fake']}, 'fake'))

    def test_missing_mismatched_receipt_and_sources(self):
        receipt = self.server.ctx.store.catalog_receipt()
        for value in (None, {**receipt, 'observation_id': 'old-broker'}):
            self.server.ctx.store.set_catalog_receipt(value)
            self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})
        self.server.ctx.store.set_catalog_receipt(receipt)
        self.config.tool_dirs = [str(self.folder)]
        self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})
        self.config.tool_dirs = []
        self.config.tools_root = str(self.folder)
        self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})

    def test_health_only_exposes_random_identity(self):
        health = self.health()
        self.assertEqual(set(health), {'status', 'catalog_observation_id'})
        encoded = json.dumps(health)
        self.assertNotIn('fake', encoded)
        self.assertNotIn(self.temp.name, encoded)
        self.assertNotIn(self.server.ctx.store.catalog_receipt()['fingerprint'], encoded)
        with mock.patch('admin.catalog_observation.urllib.request.urlopen', side_effect=OSError):
            self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})

    def test_previous_process_receipt_cannot_certify_new_load(self):
        old = self.server.ctx.store.catalog_receipt()
        self.server.reload_registry()
        self.server.ctx.store.set_catalog_receipt(old)
        self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})

    def test_old_live_broker_and_concurrent_admin_reads(self):
        from concurrent.futures import ThreadPoolExecutor
        from dataclasses import replace
        second = build_server(port=0, host='127.0.0.1', db_path=self.config.db_path,
                              tools_root=self.config.tools_root, surface=mock.Mock())
        thread = threading.Thread(target=second.serve_forever)
        thread.start()
        try:
            # The old listener is still healthy, but no longer owns the private receipt.
            self.assertEqual(observe_catalog(self.config), {'status': 'unknown'})
            current = replace(self.config, port=second.server_address[1])
            with ThreadPoolExecutor(max_workers=3) as pool:
                observations = list(pool.map(observe_catalog, [current]*3))
            self.assertTrue(all(o['status'] == 'verified' for o in observations))
        finally:
            second.shutdown()
            thread.join(3)
            second.server_close()
            second.ctx.store.close()

    def test_secret_block_content_does_not_enter_private_fingerprint(self):
        from broker.registry import Registry
        self.manifest.write_text(self.text + '\n[[secrets]]\nname="fake_key"\nfield="FAKE_ONE"\n')
        one = Registry.from_sources(self.config.tools_root).observation_fingerprint(self.config.tools_root)
        self.manifest.write_text(self.text + '\n[[secrets]]\nname="fake_key"\nfield="FAKE_TWO"\n')
        two = Registry.from_sources(self.config.tools_root).observation_fingerprint(self.config.tools_root)
        self.assertEqual(one, two)
