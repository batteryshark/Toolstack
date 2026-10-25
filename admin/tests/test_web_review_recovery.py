"""Fake-only policy boundary regressions, using the existing isolated app fixture."""
import unittest
from pathlib import Path
from unittest import mock

from admin.tests import test_app
from admin.views.callers import caller_tools_view


class WebRecovery(unittest.TestCase):
    setUp = test_app.AdminApp.setUp
    _restore_env = test_app.AdminApp._restore_env
    _store = test_app.AdminApp._store
    _login = test_app.AdminApp._login

    def prepare(self, policy):
        self._login()
        self.csrf = test_app._csrf(self.client.get('/').text)
        self.client.post('/callers', data={'name': 'writer', '_csrf': self.csrf})
        self.store = self._store()
        self.caller = self.store.caller_by_name('writer')['id']
        self.store.set_policy(self.caller, policy)

    def post(self, fields, json=True):
        return self.client.post('/callers/writer/policy',
            headers={'Accept': 'application/json'} if json else {},
            data={'_csrf': self.csrf, **fields}, follow_redirects=False)

    def test_disabled_since_load_rejected_without_effect(self):
        self.prepare({'enabled': ['echo'], 'tools': {'echo': {'say': 'deny'}}})
        self.client.get('/callers/writer/policy')
        self.store.set_policy(self.caller, {'enabled': [], 'tools': {}})
        with mock.patch('admin.server.operations.set_policy') as effect:
            response = self.post({'op__echo__say': 'allow'})
        self.assertEqual(response.json()['outcome'], 'rejected')
        effect.assert_not_called()
        self.assertEqual(self.store.policy_for(self.caller)['tools'], {})

    def test_exact_double_underscore_and_unseen_grants(self):
        self.prepare({'enabled': ['fake__tool', 'offline'], 'tools': {
            'fake__tool': {'read': 'deny', 'hidden': 'review'}, 'offline': {'read': 'allow'}}})
        tool = Path(self.tmp, 'tools', 'fake__tool')
        tool.mkdir()
        (tool / 'toolyard.toml').write_text('id = "fake__tool"\ntype = "api"\n[entrypoint]\nport = 4602\n[[operations]]\nname = "read"\nrisk = "read"\n')
        response = self.post({'op__fake__tool__read': 'allow'})
        self.assertEqual(response.json()['outcome'], 'saved')
        policy = self.store.policy_for(self.caller)['tools']
        self.assertEqual(policy['fake__tool']['read'], 'allow')
        self.assertNotIn('fake', policy)
        self.assertEqual(policy['fake__tool']['hidden'], 'review')
        self.assertEqual(policy['offline']['read'], 'allow')

    def test_collision_and_noncatalog_rejected(self):
        self.prepare({'enabled': ['fake', 'fake__tool'], 'tools': {}})
        catalog = {'fake': [{'op': 'tool__read'}], 'fake__tool': [{'op': 'read'}]}
        ops = [dict(op, tool=tool) for tool, entries in catalog.items() for op in entries]
        with mock.patch('admin.server.Registry.from_sources') as registry, mock.patch('admin.server.operations.set_policy') as effect:
            registry.return_value.list_ops.return_value = ops
            for field in ('op__fake__tool__read', 'op__fake__missing'):
                self.assertEqual(self.post({field: 'allow'}).json()['outcome'], 'rejected')
        effect.assert_not_called()

    def test_csrf_html_retains_safe_posted_values(self):
        self.prepare({'enabled': ['echo'], 'tools': {'echo': {'say': 'deny'}}})
        response = self.post({'_csrf': 'invalid-fake', 'op__echo__say': 'review'}, json=False)
        self.assertEqual(response.status_code, 403)
        self.assertIn('Save rejected', response.text)
        self.assertIn("value='review' selected", response.text)
        self.assertEqual(self.store.policy_for(self.caller)['tools']['echo']['say'], 'deny')

    def test_scope_html_retains_only_valid_edits_and_gates_save(self):
        self.prepare({'enabled': ['echo'], 'tools': {'echo': {'say': 'deny'}}})
        response = self.post({'op__echo__say': 'review', 'op__gone__write': 'allow'}, json=False)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Operation set changed', response.text)
        self.assertIn("value='review' selected", response.text)
        self.assertNotIn('op__gone__write', response.text)
        self.assertIn("type='submit' disabled", response.text)

    def test_auth_redirect_precedes_effect(self):
        self.prepare({'enabled': ['echo'], 'tools': {}})
        self.client.cookies.clear()
        with mock.patch('admin.server.operations.set_policy') as effect:
            response = self.post({'op__echo__say': 'allow'})
        self.assertEqual(response.headers['location'], '/login')
        effect.assert_not_called()

    def test_html_invalid_effect_rejected_without_inventing_grants(self):
        self.prepare({'enabled': ['echo'], 'tools': {'echo': {'say': 'deny'}}})
        response = self.post({'op__echo__say': 'bogus'}, json=False)
        self.assertEqual(response.status_code, 400)
        self.assertIn('Save rejected', response.text)
        self.assertIn("value='deny' selected", response.text)
        self.assertEqual(self.store.policy_for(self.caller)['tools']['echo']['say'], 'deny')

    def test_html_after_effect_failure_stays_unknown_and_gated(self):
        self.prepare({'enabled': ['echo'], 'tools': {'echo': {'say': 'deny'}}})
        with mock.patch('admin.server.operations.set_policy', side_effect=RuntimeError('fake failure')):
            response = self.post({'op__echo__say': 'review'}, json=False)
        self.assertEqual(response.status_code, 503)
        self.assertIn('Save outcome unknown', response.text)
        self.assertIn("value='review' selected", response.text)
        self.assertIn("type='submit' disabled", response.text)

    def test_checkbox_name_escaped(self):
        html = caller_tools_view(user='fake', csrf='fake', caller="writer'", all_tools=[('fake<tool', [])], enabled=[])
        self.assertIn("aria-label='Enable fake&lt;tool for writer&#x27;'", html)
