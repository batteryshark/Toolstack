"""Fake-only seam regressions for the bounded admin repair tranche."""
import errno
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from admin import broker_config, manifest_files, secret_values, tool_sources
from admin.server import _config_from_form
from admin.sps_watchdog import SPSWatchdog
from admin.sps_watchdog import recover_with_runner


class ConfigMerge(unittest.TestCase):
    def test_html_and_json_share_preserving_merge(self):
        current = broker_config.BrokerRunConfig(tool_dirs=["/fake/external"], nod_token="fake")
        for merge in (_config_from_form, broker_config.merge_update):
            result = merge({"port": "9000", "nod_token": ""}, current) if merge is _config_from_form else merge(current, {"port": "9000", "nod_token": ""})
            self.assertEqual(result.tool_dirs, current.tool_dirs)
            self.assertEqual(result.nod_token, "fake")
            self.assertEqual(result.port, 9000)

    def test_invalid_input_is_not_silently_saved(self):
        for data in ({"port": True}, {"port": 2.5}, {"port": "oops"},
                     {"port": 0}, {"approval_ttl": 0}, {"rate_limit": -1},
                     {"nod_url": None}, {"nod_url": "http://example.com"}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                broker_config.merge_update(broker_config.BrokerRunConfig(), data)

    def test_secret_inspection_is_unknown(self):
        self.assertIsNone(secret_values.provisioned_fields("fake", ["FAKE"]))


class Recovery(unittest.TestCase):
    def test_adapter_uses_detailed_runner_contract(self):
        result = SimpleNamespace(complete=False)
        with mock.patch("toolyard.runner.reregister_all_with_sps_detailed", create=True,
                        return_value=result) as recover:
            self.assertIs(recover_with_runner(tools_root="fake"), result)
            recover.assert_called_once_with(tools_root="fake")

    def test_same_boot_retries_until_explicit_completion(self):
        for first in (OSError("fake failure"), 1, SimpleNamespace(complete=False)):
            recover = mock.Mock(side_effect=[first, SimpleNamespace(complete=True)])
            watchdog = SPSWatchdog(config=broker_config.BrokerRunConfig(),
                                   probe=lambda: "same", re_register_fn=recover,
                                   sps_env_path="/fake/unused")
            watchdog._check_once()
            self.assertIsNone(watchdog._last_seen)
            watchdog._check_once()
            watchdog._check_once()
            self.assertEqual(recover.call_count, 2)


class ManifestSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.tool = self.root / "tool"
        self.tool.mkdir()
        self.outside = self.root / "outside"
        self.outside.write_text("unchanged")

    def test_linked_manifest_rejected_on_ingestion_and_write(self):
        (self.tool / "toolyard.toml").symlink_to(self.outside)
        with self.assertRaises(ValueError):
            tool_sources.add_from_path(str(self.tool), str(self.root / "managed"))
        with self.assertRaises(ValueError):
            manifest_files.write(self.tool, "replacement")
        self.assertEqual(self.outside.read_text(), "unchanged")

    def test_linked_directory_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.tool, target_is_directory=True)
        with mock.patch("admin.manifest_files.os.close", wraps=os.close) as close:
            with self.assertRaises(ValueError):
                manifest_files.write(alias, "replacement")
        self.assertTrue(close.called)
        for call in close.call_args_list:
            with self.assertRaises(OSError) as closed:
                os.fstat(call.args[0])
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_hardlinked_manifest_rejected(self):
        os.link(self.outside, self.tool / "toolyard.toml")
        with self.assertRaises(ValueError):
            manifest_files.write(self.tool, "replacement")
        self.assertEqual(self.outside.read_text(), "unchanged")

    def test_failed_atomic_replace_preserves_original(self):
        target = self.tool / "toolyard.toml"
        target.write_text("original")
        for operation in ("replace", "fsync"):
            for code in (errno.ENOSPC, errno.EACCES, errno.EIO):
                failure = OSError(code, "fake")
                with self.subTest(operation=operation, code=code), mock.patch(
                        "admin.manifest_files.os." + operation, side_effect=failure):
                    with self.assertRaises(OSError) as caught:
                        manifest_files.write(self.tool, "replacement")
                    self.assertIs(caught.exception, failure)
                self.assertEqual(target.read_text(), "original")
                self.assertEqual(list(self.tool.iterdir()), [target])

    def test_directory_body_errors_propagate_and_close_fd(self):
        for code in (errno.ENOSPC, errno.EACCES, errno.EIO):
            failure = OSError(code, "fake caller body")
            with self.subTest(code=code), self.assertRaises(OSError) as caught:
                with manifest_files.directory(self.tool) as fd:
                    os.fstat(fd)
                    raise failure
            self.assertIs(caught.exception, failure)
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_directory_success_closes_fd(self):
        with manifest_files.directory(self.tool) as fd:
            os.fstat(fd)
        with self.assertRaises(OSError) as closed:
            os.fstat(fd)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_atomic_write_private_file(self):
        manifest_files.write(self.tool, "new")
        self.assertEqual(manifest_files.read(self.tool), b"new")
        self.assertEqual((self.tool / "toolyard.toml").stat().st_mode & 0o777, 0o600)
