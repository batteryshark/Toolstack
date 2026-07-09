"""SandboxPolicy contract and native-backend dispatch.

No OS sandbox is built here; this pins the backend-neutral policy shape and the
platform -> backend mapping that the coming Seatbelt (macOS) and bubblewrap (Linux)
runners build against, so the seam is fixed before either backend exists.
"""

import dataclasses
import unittest

from toolyard.runner import DockerRunner, ProcessRunner, SeatbeltRunner, get_runner, native_backend
from toolyard.sandbox import EgressPolicy, ResourceCaps, SandboxPolicy


class SandboxPolicyTest(unittest.TestCase):
    def test_default_is_deny_all_no_caps(self):
        p = SandboxPolicy()
        self.assertEqual(p.egress.allow, ())
        self.assertTrue(p.egress.denies_all)
        self.assertIsNone(p.resources.memory_mb)
        self.assertIsNone(p.resources.cpu)
        self.assertIsNone(p.resources.pids)

    def test_egress_allowlist(self):
        e = EgressPolicy(allow=("api.example.com",))
        self.assertFalse(e.denies_all)
        self.assertIn("api.example.com", e.allow)

    def test_caps_reject_nonpositive(self):
        for kwargs in ({"memory_mb": 0}, {"pids": -1}, {"cpu": 0}, {"cpu": -0.5}):
            with self.assertRaises(ValueError):
                ResourceCaps(**kwargs)

    def test_caps_accept_values(self):
        c = ResourceCaps(memory_mb=512, cpu=1.5, pids=64)
        self.assertEqual((c.memory_mb, c.cpu, c.pids), (512, 1.5, 64))

    def test_policy_is_frozen(self):
        p = SandboxPolicy()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            p.egress = EgressPolicy()  # type: ignore[misc]


class NativeBackendTest(unittest.TestCase):
    def test_platform_mapping(self):
        self.assertEqual(native_backend("darwin"), "seatbelt")
        self.assertEqual(native_backend("linux"), "bwrap")
        self.assertEqual(native_backend("linux2"), "bwrap")

    def test_unsupported_platform(self):
        with self.assertRaises(RuntimeError):
            native_backend("win32")


class GetRunnerTest(unittest.TestCase):
    def test_known_backends(self):
        self.assertIsInstance(get_runner("process"), ProcessRunner)
        self.assertIsInstance(get_runner("docker"), DockerRunner)

    def test_seatbelt_backend_returns_runner(self):
        # The class exists on every platform; it only *works* on macOS (sandbox-exec).
        self.assertIsInstance(get_runner("seatbelt"), SeatbeltRunner)

    def test_bwrap_not_yet_implemented(self):
        with self.assertRaises(NotImplementedError):
            get_runner("bwrap")

    def test_sandbox_resolves_to_this_hosts_native_backend(self):
        if native_backend() == "seatbelt":
            self.assertIsInstance(get_runner("sandbox"), SeatbeltRunner)
        else:  # linux -> bwrap, not built yet
            with self.assertRaises(NotImplementedError):
                get_runner("sandbox")

    def test_unknown_backend(self):
        with self.assertRaises(ValueError):
            get_runner("bogus")


if __name__ == "__main__":
    unittest.main()
