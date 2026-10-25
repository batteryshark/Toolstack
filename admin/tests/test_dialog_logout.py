"""Shared web/desktop dialog and sign-out regressions; private fake app settings."""
import re
import unittest
from unittest import mock

from admin.server import SESSION_COOKIE
from admin.tests import test_app
from admin.views.assets import _CSS, _JS


class DialogAssets(unittest.TestCase):
    def test_both_dialogs_group_actions_with_focus_outline_clearance(self):
        self.assertIn("actions.append(cancel,proceed);dialog.append(actions)", _JS)
        self.assertIn("actions.append(stay,discard);d.append(actions)", _JS)
        self.assertEqual(_JS.count("actions.className='actions'"), 2)
        self.assertIn('dialog .actions{justify-content:flex-end;gap:20px;}', _CSS)
        self.assertIn('.actions,.row{display:flex;', _CSS)
        self.assertIn('outline:3px solid #0d6efd;outline-offset:3px;', _CSS)
        self.assertIn("cancel.autofocus=true", _JS)
        self.assertIn("stay.autofocus=true", _JS)


class SignOut(unittest.TestCase):
    _restore_env = test_app.AdminApp._restore_env
    _login = test_app.AdminApp._login

    def setUp(self):
        with mock.patch('admin.server.SPSLink.from_env', return_value=None), \
             mock.patch('admin.server.start_reconciler_thread'):
            test_app.AdminApp.setUp(self)
        self.addCleanup(self.client.close)

    def test_signout_form_clears_session_and_get_logout_is_not_an_action(self):
        # desktop/app.py loads this same admin URL without a separate logout handler.
        self._login()
        cookie = self.client.cookies.get(SESSION_COOKIE)
        self.assertTrue(cookie)
        response = self.client.get('/logout', follow_redirects=False)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method Not Allowed'})
        self.assertEqual(response.headers['allow'], 'POST')
        self.assertEqual(self.client.cookies.get(SESSION_COOKIE), cookie)
        dashboard = self.client.get('/', follow_redirects=False)
        self.assertEqual(dashboard.status_code, 200)
        form = re.search(r"<form method='post' action='/logout'>(.*?)</form>", dashboard.text).group(1)
        self.assertIn('Sign out', form)
        response = self.client.post('/logout', data={'_csrf': test_app._csrf(form)}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/login')
        self.assertIn('Max-Age=0', response.headers['set-cookie'])
        self.assertIsNone(self.client.cookies.get(SESSION_COOKIE))
        response = self.client.get('/', follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers['location'], '/login')
        self.assertEqual(self.client.get('/login').status_code, 200)
        self.assertEqual(self.client.get('/logout').status_code, 405)
        self.assertEqual(self.client.get('/', follow_redirects=False).headers['location'], '/login')
