"""Unit tests for the admin login brute-force throttle."""

import unittest
from unittest import mock

from admin.loginguard import LoginGuard


class LoginGuardTests(unittest.TestCase):
    def test_locks_after_max_per_ip(self):
        g = LoginGuard(max_per_ip=3, lockout=100, global_max=1000)
        for _ in range(3):
            self.assertEqual(g.retry_after("ip-a"), 0.0)  # allowed right up to the limit
            g.record_failure("ip-a")
        self.assertGreater(g.retry_after("ip-a"), 0.0)     # the next attempt is locked out

    def test_other_ip_unaffected_by_a_peers_failures(self):
        g = LoginGuard(max_per_ip=3, lockout=100, global_max=1000)
        for _ in range(3):
            g.record_failure("ip-a")
        self.assertEqual(g.retry_after("ip-b"), 0.0)

    def test_success_clears_the_lock(self):
        g = LoginGuard(max_per_ip=3, lockout=100, global_max=1000)
        for _ in range(3):
            g.record_failure("ip-a")
        self.assertGreater(g.retry_after("ip-a"), 0.0)
        g.record_success("ip-a")
        self.assertEqual(g.retry_after("ip-a"), 0.0)

    def test_global_cap_throttles_a_fresh_ip(self):
        # A spread-out attack (each IP under the per-IP limit) still trips the global ceiling.
        g = LoginGuard(max_per_ip=1000, lockout=100, global_max=5, global_window=100)
        for i in range(5):
            g.record_failure(f"ip-{i}")
        self.assertGreater(g.retry_after("ip-fresh"), 0.0)

    def test_lock_expires_after_the_window(self):
        g = LoginGuard(max_per_ip=2, lockout=100, global_max=1000)
        with mock.patch("admin.loginguard.time.time", return_value=1000.0):
            g.record_failure("ip-a")
            g.record_failure("ip-a")
            self.assertGreater(g.retry_after("ip-a"), 0.0)
        with mock.patch("admin.loginguard.time.time", return_value=1101.0):  # past the lockout
            self.assertEqual(g.retry_after("ip-a"), 0.0)


if __name__ == "__main__":
    unittest.main()
