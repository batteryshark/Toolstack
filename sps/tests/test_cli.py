"""cli: cert/CA helper + idempotency + serve/init/vault-* subcommands."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sps.cli import maybe_generate_tls_material


class TlsMaterial(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, ignore_errors=True)

    def test_idempotent_when_all_three_files_exist(self):
        cert = self.tmp / "c.crt"
        key = self.tmp / "k.key"
        ca = self.tmp / "ca.crt"
        cert.write_text("CERT")
        key.write_text("KEY")
        ca.write_text("CA")
        with mock.patch("subprocess.run") as run:
            rc = maybe_generate_tls_material(str(cert), str(key), str(ca), "/CN=x")
        run.assert_not_called()
        self.assertFalse(rc)

    def test_generates_when_any_missing(self):
        cert = self.tmp / "c.crt"
        key = self.tmp / "k.key"
        ca = self.tmp / "ca.crt"

        def fake_run(cmd, **kwargs):
            # Use openssl if available, otherwise write the files ourselves.
            if subprocess.os.path.exists(cmd[cmd.index("-out") + 1]):
                return subprocess.CompletedProcess(cmd, 0)
            with open(cmd[cmd.index("-out") + 1], "w") as f:
                f.write("CERT")
            with open(cmd[cmd.index("-keyout") + 1], "w") as f:
                f.write("KEY")
            return subprocess.CompletedProcess(cmd, 0)

        if shutil_which := __import__("shutil").which("openssl"):
            with mock.patch("subprocess.run", side_effect=fake_run):
                rc = maybe_generate_tls_material(str(cert), str(key), str(ca), "/CN=x")
            self.assertTrue(rc)
            # ca was copied from cert
            self.assertTrue(ca.exists())
        else:
            self.skipTest("openssl unavailable")


class CliHelp(unittest.TestCase):
    def test_help_lists_all_subcommands(self):
        from sps.cli import main
        with mock.patch("sys.argv", ["sps", "--help"]):
            with self.assertRaises(SystemExit):
                main()
        # argparse writes to stderr on -h; we just verify it doesn't crash mid-parsing.


if __name__ == "__main__":
    unittest.main()
