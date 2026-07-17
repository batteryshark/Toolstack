"""plugins/base: harness ABC + incomplete-subclass enforcement."""
import unittest

from sps.plugins.base import SPSSecretsPlugin


class _Good(SPSSecretsPlugin):
    def connect(self):
        return self

    def get_secret(self, field, item):
        return "v"

    def write_secret(self, field, item, value):
        return None


class _MissingGet(SPSSecretsPlugin):
    def connect(self):
        return self

    def write_secret(self, field, item, value):
        return None


class _MissingWrite(SPSSecretsPlugin):
    def connect(self):
        return self

    def get_secret(self, field, item):
        return "v"


class _MissingConnect(SPSSecretsPlugin):
    def get_secret(self, field, item):
        return "v"

    def write_secret(self, field, item, value):
        return None


class Harness(unittest.TestCase):
    def test_complete_plugin_instantiates(self):
        p = _Good()
        self.assertEqual(p.connect(), p)
        self.assertEqual(p.get_secret("f", "i"), "v")
        p.write_secret("f", "i", "x")

    def test_missing_get_secret_raises(self):
        with self.assertRaises(TypeError):
            _MissingGet()

    def test_missing_write_secret_raises(self):
        with self.assertRaises(TypeError):
            _MissingWrite()

    def test_missing_connect_raises(self):
        with self.assertRaises(TypeError):
            _MissingConnect()
