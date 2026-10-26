"""Pure generated-markup contract; WebKit fixtures exercise the actual handlers."""
import unittest
from html.parser import HTMLParser

from admin.views.dashboard import _callers_section
from admin.views.layout import page


class Tags(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class CallerRowActivationTests(unittest.TestCase):
    def test_rows_keep_named_keyboard_path_and_existing_destination(self):
        for revoked in (None, 1):
            html = _callers_section([dict(name='writer-demo', revoked_at=revoked)], 'fake')
            tags = Tags(html).tags
            row = next(attrs for tag, attrs in tags if tag == 'tr' and 'data-caller-policy' in attrs)
            self.assertEqual(row['tabindex'], '0')
            self.assertEqual(row['aria-label'], 'Open caller settings for writer-demo')
            link = next(attrs for tag, attrs in tags if 'data-policy-link' in attrs)
            self.assertEqual(link['href'], '/callers/writer-demo/settings')
            self.assertEqual(sum(tag == 'button' for tag, _ in tags), 3)

    def test_empty_and_escaped_names(self):
        self.assertNotIn('data-caller-policy', _callers_section([], 'fake'))
        html = _callers_section([dict(name="a'<>\"", revoked_at=None)], 'fake')
        rows = [attrs for tag, attrs in Tags(html).tags if 'data-caller-policy' in attrs]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['aria-label'], "Open caller settings for a'<>\"")

    def test_generated_script_guards_nested_actions_and_repeat(self):
        html = page('Callers', _callers_section([], 'fake'), user=None)
        self.assertIn("row.addEventListener('dblclick'", html)
        self.assertIn("event.target.closest('a,button,input,select,textarea,form,summary", html)
        self.assertIn("event.key==='Enter' && event.target===row && !event.repeat", html)
        self.assertIn("row.querySelector('[data-policy-link]').click()", html)
