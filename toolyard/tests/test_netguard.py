"""Pure-logic tests for the privileged netguard helper: tool-id validation, nft table naming,
and the generated ruleset. These run on any platform (no root, nft, or cgroups needed); the
end-to-end confinement is covered by the Bwrap* tests in test_runner.py on a Linux host."""

import unittest

from toolyard import netguard


class ToolIdTest(unittest.TestCase):
    def test_accepts_normal_ids(self):
        for ok in ("echo", "rest_demo", "a", "tool-1", "x" * 64):
            self.assertEqual(netguard._tool_id(ok), ok)

    def test_rejects_bad_ids(self):
        for bad in ("", "-lead", "_lead", "UPPER", "has space", "semi;colon", "../escape", "x" * 65):
            with self.assertRaises(SystemExit):
                netguard._tool_id(bad)

    def test_table_name_is_nft_safe(self):
        # hyphens are legal in a tool id / cgroup dir but not in an nft identifier
        self.assertEqual(netguard._table("tool-1"), "toolyard_tool_1")
        self.assertEqual(netguard._table("echo"), "toolyard_echo")


class RulesetTest(unittest.TestCase):
    def test_deny_all_has_no_outbound_accept(self):
        rs = netguard._ruleset("echo", None)
        self.assertIn("ct state established,related accept", rs)   # may still serve the broker
        self.assertNotIn("tcp dport", rs)                          # but no new outbound anywhere
        self.assertIn("meta nfproto ipv4 drop", rs)
        self.assertIn("meta nfproto ipv6 drop", rs)

    def test_allowlist_permits_only_the_proxy_port(self):
        rs = netguard._ruleset("echo", 6123)
        self.assertIn("ip daddr 127.0.0.1 tcp dport 6123 accept", rs)
        self.assertIn("meta nfproto ipv4 drop", rs)               # everything else still drops

    def test_rule_is_scoped_to_the_tools_cgroup(self):
        rs = netguard._ruleset("echo", None)
        self.assertIn('socket cgroupv2 level 2 "toolyard/echo"', rs)
        self.assertIn("table inet toolyard_echo", rs)

    def test_drop_rules_follow_the_accepts(self):
        # order matters: established + proxy accepts must precede the catch-all drops
        rs = netguard._ruleset("echo", 6123)
        self.assertLess(rs.index("dport 6123 accept"), rs.index("nfproto ipv4 drop"))


class ArgParsingTest(unittest.TestCase):
    def test_run_requires_a_command_tail(self):
        with self.assertRaises(SystemExit):
            netguard.main(["run", "--tool", "echo"])

    def test_run_rejects_bad_proxy_port(self):
        with self.assertRaises(SystemExit):
            netguard.main(["run", "--tool", "echo", "--proxy-port", "70000", "--", "/bin/true"])

    def test_invalid_tool_id_is_rejected(self):
        with self.assertRaises(SystemExit):
            netguard.main(["teardown", "--tool", "../etc"])


if __name__ == "__main__":
    unittest.main()
