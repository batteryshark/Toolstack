"""Per-caller fixed-window rate limiter."""

import unittest

from broker.ratelimit import RateLimiter


class Limit(unittest.TestCase):
    def test_allows_up_to_limit_then_denies(self):
        rl = RateLimiter(2)
        self.assertTrue(rl.allow("c", now=1000))
        self.assertTrue(rl.allow("c", now=1001))
        self.assertFalse(rl.allow("c", now=1002))

    def test_window_resets(self):
        rl = RateLimiter(1)
        self.assertTrue(rl.allow("c", now=1000))
        self.assertFalse(rl.allow("c", now=1030))
        self.assertTrue(rl.allow("c", now=1061))  # > 60s -> new window

    def test_is_per_caller(self):
        rl = RateLimiter(1)
        self.assertTrue(rl.allow("a", now=1000))
        self.assertTrue(rl.allow("b", now=1000))
        self.assertFalse(rl.allow("a", now=1000))

    def test_zero_disables(self):
        rl = RateLimiter(0)
        self.assertTrue(all(rl.allow("c", now=1000) for _ in range(100)))


if __name__ == "__main__":
    unittest.main()
