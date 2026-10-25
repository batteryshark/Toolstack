"""Nonvisual approval metadata adapter and shared registry contract."""
import copy
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from admin import manifest_files, tool_authoring as author
from admin.tests.test_tool_authoring import FULL, REST_FULL
from admin.views import assets
from broker.approval_summary import validate_fields
from broker.registry import Registry


class ApprovalFields(unittest.TestCase):
    def data(self, kind, fields=None, present=True):
        data = copy.deepcopy(REST_FULL if kind == "rest" else FULL)
        data["type"] = kind
        if present:
            data["operations"][0]["approval_fields"] = fields
        return data

    def test_roundtrip_registry_all_transports(self):
        for kind in ("api", "mcp", "rest"):
            for present, fields in ((False, None), (True, []),
                                    (True, ["/", "/escaped~1key/~0", "/items/0/name", "/ spaced "]),
                                    (True, ["/" + "x" * 255]),
                                    (True, [f"/k{i}" for i in range(32)])):
                with self.subTest(kind=kind, present=present, fields=fields), tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp)
                    data = author.from_json(json.dumps(self.data(kind, fields, present)))
                    self.assertEqual(author.validate(data), [])
                    author.write(directory, data, runner="process")
                    parsed = tomllib.loads(manifest_files.read(directory).decode())
                    loaded = author.read(directory)
                    for op in (data["operations"][0], parsed["operations"][0], loaded["operations"][0]):
                        self.assertEqual("approval_fields" in op, present)
                        if present:
                            self.assertEqual(op["approval_fields"], fields)
                    registry = Registry.from_sources(tool_dirs=[directory])
                    name = data["operations"][0]["name"]
                    expected = fields if present else []
                    self.assertEqual(registry.lookup(data["id"], name).approval_fields, tuple(expected))
                    self.assertEqual(registry.describe(data["id"], name)["approval_fields"], expected)
                    if kind == "rest":
                        self.assertIs(loaded["operations"][1]["redact_response_body"], False)
                        self.assertIs(loaded["operations"][1]["redact_response_headers"], False)
                        self.assertEqual(loaded["operations"][1]["secret_update_rules"], data["operations"][1]["secret_update_rules"])

    def test_invalid_raw_values_refused_without_publication(self):
        invalid = [None, "PRIVATE_SENTINEL", {}, 1, True, ("/a",),
                   [1], [None], [{}], ["/a", "/a"], [""], ["no/slash"],
                   [" /a"], ["/bad~"], ["/bad~2"], ["/" + "x" * 256],
                   [f"/k{i}" for i in range(33)]]
        for kind in ("api", "mcp", "rest"):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                author.write(directory, author.normalize(self.data(kind, [], True)), runner="process")
                before = manifest_files.read(directory)
                for fields in invalid:
                    with self.subTest(kind=kind, value_type=type(fields).__name__):
                        data = author.normalize(self.data(kind, fields))
                        self.assertIs(data["operations"][0]["approval_fields"], fields)
                        with self.assertRaises(ValueError):
                            validate_fields(fields)
                        self.assertEqual(author.validate(data), [
                            "approval_fields must be <=32 unique non-root RFC6901 pointers (<=256 characters)"])
                        with patch.object(manifest_files, "write") as publish:
                            with self.assertRaises(ValueError) as error:
                                author.write(directory, data, runner="process")
                            publish.assert_not_called()
                        self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))
                        self.assertEqual(manifest_files.read(directory), before)
                        with self.assertRaises(ValueError):
                            author.to_toml(data)

    def test_shared_validator_is_imported(self):
        self.assertIs(author.validate_fields, validate_fields)

    def test_existing_editor_preserves_presence_nonvisually(self):
        # No existing JS execution route in admin/tests. These are source contract
        # checks, NOT live-form/browser proof; no new browser/harness is introduced.
        source = Path(assets.__file__).read_text()
        card = source.split("function opCard(o, open){", 1)[1].split("function serializeOp(card){", 1)[0]
        serializer = source.split("function serializeOp(card){", 1)[1].split("function secRow(s){", 1)[0]
        self.assertIn("hasOwnProperty.call(o, 'approval_fields')", card)
        self.assertIn("card._approval_fields = o.approval_fields", card)
        self.assertIn("hasOwnProperty.call(card, '_approval_fields')", serializer)
        self.assertIn("operation.approval_fields = card._approval_fields", serializer)
        self.assertIn("return operation;", serializer)
        self.assertNotIn("approval_fields", card.split("card.querySelector('.op-name').value", 1)[0])
