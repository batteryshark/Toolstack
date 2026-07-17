"""store: in-memory TOOL_REGISTRATION pool, no persistence."""
import unittest

from sps.store import Registration, ToolRegistrationStore


class Store(unittest.TestCase):
    def test_register_and_get(self):
        s = ToolRegistrationStore()
        rec = Registration(
            esecret="abc",
            secret_entries=(
                {"name": "api_key", "field": "API_KEY", "item": None, "writable": False},
            ),
        )
        s.register("echo", rec)
        self.assertEqual(s.get("echo").esecret, "abc")  # type: ignore[union-attr]
        self.assertEqual(
            s.get("echo").secret_entries[0]["name"],  # type: ignore[union-attr]
            "api_key",
        )

    def test_unregister_removes(self):
        s = ToolRegistrationStore()
        s.register("echo", Registration(esecret="abc", secret_entries=()))
        s.unregister("echo")
        self.assertIsNone(s.get("echo"))

    def test_unregister_nonexistent_is_noop(self):
        s = ToolRegistrationStore()
        s.unregister("ghost")  # must not raise
        self.assertIsNone(s.get("ghost"))

    def test_reregister_overwrites(self):
        s = ToolRegistrationStore()
        s.register("echo", Registration(esecret="old", secret_entries=()))
        s.register("echo", Registration(esecret="new", secret_entries=()))
        self.assertEqual(s.get("echo").esecret, "new")  # type: ignore[union-attr]

    def test_is_in_memory_only(self):
        # Contract: nothing on disk. The store has no save/load methods.
        s = ToolRegistrationStore()
        self.assertFalse(hasattr(s, "save"))
        self.assertFalse(hasattr(s, "load"))
        self.assertFalse(hasattr(s, "_path"))
        self.assertFalse(hasattr(s, "_persist"))

    def test_ids_isolated_per_store(self):
        a = ToolRegistrationStore()
        b = ToolRegistrationStore()
        a.register("echo", Registration(esecret="a", secret_entries=()))
        self.assertEqual(a.ids(), ("echo",))
        self.assertEqual(b.ids(), ())
