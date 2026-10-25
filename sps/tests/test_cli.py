"""cli: cert/CA helper + idempotency + serve/init/vault-* subcommands."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sps.cli import maybe_generate_tls_material
from sps.cli import init_runtime_paths, main
from sps.config import load_config


class Bootstrap(unittest.TestCase):
    def test_production_and_temporary_path_selection_is_pure(self):
        # No filesystem operations: production paths must never be created here.
        self.assertEqual(init_runtime_paths("/etc/toolstack/sps.env"), (
            Path("/var/lib/toolstack/sps.vault.json"), Path("/var/log/toolstack/sps.audit")))
        self.assertEqual(init_runtime_paths("/temporary/config/sps.env"), (
            Path("/temporary/config/sps.vault.json"), Path("/temporary/config/sps-audit.jsonl")))
        self.assertEqual(init_runtime_paths("local.env"), (
            Path("sps.vault.json"), Path("sps-audit.jsonl")))
        for config in ("/etc/toolstack/sps.env", "/temporary/config/sps.env"):
            self.assertEqual(init_runtime_paths(config, state_dir="/explicit/state", audit_log="/explicit/log/audit"), (
                Path("/explicit/state/sps.vault.json"), Path("/explicit/log/audit")))
        self.assertEqual(init_runtime_paths("/etc/toolstack/sps.env", state_dir="/explicit/state")[1],
                         Path("/var/log/toolstack/sps.audit"))
        self.assertEqual(init_runtime_paths("/temporary/config/sps.env", audit_log="/explicit/audit")[0],
                         Path("/temporary/config/sps.vault.json"))

    def _init(self, config, *options, passphrase=None):
        # Never inherit credential environment; only fake test passphrases.
        env = {} if passphrase is None else {"SP_VAULT_PASSPHRASE": passphrase}
        def fake_tls(cert, key, ca, subject):
            for path in (cert, key, ca):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as output:
                    output.write("fake TLS fixture")
        import contextlib, io
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("shutil.which", return_value="fake-openssl"), \
                mock.patch("sps.cli.maybe_generate_tls_material", side_effect=fake_tls), \
                mock.patch("sys.argv", ["sps", "init", "--config", str(config), *map(str, options)]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            main()

    def test_explicit_paths_private_creation_and_kept_existing_vault(self):
        from sps.plugins.localfile import _Vault
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "config" / "sps.env"
            state = root / "state"
            audit = root / "logs" / "audit.jsonl"
            state.mkdir(mode=0o700)
            vault = _Vault.init(state / "sps.vault.json", "fake-pass")
            vault.set("fake-tool", "field", "fake-value")
            before = (state / "sps.vault.json").read_bytes()
            self._init(config, "--state-dir", state, "--audit-log", audit, passphrase="fake-pass")
            cfg = load_config(config)
            self.assertEqual(cfg.localfile.vault_file, str(state / "sps.vault.json"))
            self.assertEqual(cfg.sp_audit_log, str(audit))
            self.assertEqual((state / "sps.vault.json").read_bytes(), before)
            for directory in (config.parent, state, audit.parent):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            for file in (config, state / "sps.vault.json", config.parent / "sps.key"):
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            config_before = config.read_bytes()
            with self.assertRaises(SystemExit) as error:
                self._init(config, "--state-dir", root / "unused")
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(config.read_bytes(), config_before)
            self.assertFalse((root / "unused").exists())

    def test_temp_config_defaults_stay_adjacent_and_initialize_private_vault(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "nested" / 'quoted"config' / "sps.env"
            self._init(config, passphrase="fake-pass")
            cfg = load_config(config)
            self.assertEqual(cfg.localfile.vault_file, str(config.parent / "sps.vault.json"))
            self.assertEqual(cfg.sp_audit_log, str(config.parent / "sps-audit.jsonl"))
            self.assertEqual(Path(cfg.localfile.vault_file).stat().st_mode & 0o777, 0o600)
            self.assertEqual(config.parent.parent.stat().st_mode & 0o777, 0o700)

    def test_dangling_config_symlink_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "sps.env"
            target = Path(temp) / "missing"
            config.symlink_to(target)
            with self.assertRaises(SystemExit):
                self._init(config)
            self.assertTrue(config.is_symlink())
            self.assertFalse(target.exists())


class InitVaultPassphrase(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.key = self.root / "fake-passphrase"
        self.key.write_text(" fake-file-passphrase\n")
        self.key.chmod(0o600)
        self.vault = self.root / "fake-vault"
        self.args = SimpleNamespace(config="fake-config", force=True)
        self.cfg = SimpleNamespace(sp_plugin="localfile",
                                   localfile=SimpleNamespace(vault_file=str(self.vault)))

    def invoke(self, env):
        from sps.cli import _cmd_init_vault
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("sps.cli.cfgmod.load_config", return_value=self.cfg):
            _cmd_init_vault(self.args)

    def test_valid_file_wins_over_direct_environment(self):
        # Stop after selection, before any vault creation or KDF.
        with mock.patch("sps.plugins.localfile._Vault.init", side_effect=RuntimeError("selected")) as init:
            with self.assertRaisesRegex(RuntimeError, "selected"):
                self.invoke({"SP_VAULT_PASSPHRASE_FILE": str(self.key),
                             "SP_VAULT_PASSPHRASE": "fake-direct-passphrase"})
        init.assert_called_once_with(str(self.vault), passphrase="fake-file-passphrase")

    def test_unsafe_file_never_reads_or_changes_vault_even_with_force(self):
        for kind in ("0644", "symlink", "hardlink", "fifo", "linked-parent", "missing", "empty"):
            with self.subTest(kind=kind):
                directory = self.root / kind
                directory.mkdir(mode=0o700)
                key = directory / "key"
                if kind == "symlink":
                    key.symlink_to(self.key)
                elif kind == "hardlink":
                    os.link(self.key, key)
                elif kind == "fifo":
                    os.mkfifo(key, 0o600)
                elif kind == "linked-parent":
                    directory.rmdir()
                    directory.symlink_to(self.root, target_is_directory=True)
                    key = directory / self.key.name
                elif kind != "missing":
                    key.write_text("" if kind == "empty" else "fake-secret")
                    key.chmod(0o644 if kind == "0644" else 0o600)
                before = key.lstat() if kind != "missing" else None
                for existing in (False, True):
                    if existing:
                        self.vault.write_bytes(b"fake-existing-vault")
                        self.vault.chmod(0o600)
                    with mock.patch("sps.plugins.localfile._Vault.init") as init, \
                            mock.patch("sps.paths.os.fdopen", wraps=os.fdopen) as reader:
                        with self.assertRaises((PermissionError, FileNotFoundError, SystemExit)) as error:
                            self.invoke({"SP_VAULT_PASSPHRASE_FILE": str(key),
                                         "SP_VAULT_PASSPHRASE": "fake-direct"})
                        init.assert_not_called()
                        if kind != "empty":
                            reader.assert_not_called()
                        else:
                            self.assertEqual(str(error.exception),
                                             "vault passphrase not provided (set SP_VAULT_PASSPHRASE or stdin it)")
                    if existing:
                        self.assertEqual(self.vault.read_bytes(), b"fake-existing-vault")
                        self.assertEqual(self.vault.stat().st_mode & 0o777, 0o600)
                        self.vault.unlink()
                    else:
                        self.assertFalse(self.vault.exists())
                    if before:
                        self.assertEqual(key.lstat().st_mode, before.st_mode)
                if kind == "hardlink":
                    key.unlink()

    def test_direct_environment_and_interactive_fallbacks(self):
        for env, tty, expected in (({"SP_VAULT_PASSPHRASE": "fake-direct"}, True, "fake-direct"),
                                   ({}, True, "fake-prompt"), ({}, False, "fake-stdin")):
            with self.subTest(env=env, tty=tty), \
                    mock.patch("sys.stdin.isatty", return_value=tty), \
                    mock.patch("sys.stdin.readline", return_value="fake-stdin\n"), \
                    mock.patch("getpass.getpass", return_value="fake-prompt"), \
                    mock.patch("sps.plugins.localfile._Vault.init", side_effect=RuntimeError("selected")) as init:
                with self.assertRaisesRegex(RuntimeError, "selected"):
                    self.invoke(env)
                init.assert_called_once_with(str(self.vault), passphrase=expected)


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
        import io, contextlib
        from sps.cli import main
        # argparse prints the full help to stdout when invoked with --help; capture
        # it so the help text doesn't pollute the unittest output.
        buf = io.StringIO()
        with mock.patch("sys.argv", ["sps", "--help"]):
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as cm:
                    main()
        self.assertEqual(cm.exception.code, 0)
        for sub in ("init", "init-vault", "regen-tls", "serve", "vault-set", "vault-get"):
            self.assertIn(sub, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
