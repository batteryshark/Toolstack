import importlib
import os
import unittest
import urllib.request
from unittest.mock import patch
from toolstack_forwarder import outbound


class ProxyPolicy(unittest.TestCase):
    def test_ambient_proxies_are_not_installed(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://fake.invalid:1", "HTTPS_PROXY": "http://fake.invalid:1"}):
            importlib.reload(outbound)
            self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
                                 for h in outbound._OPENER.handlers))
