"""Fake-command tests for VM source inventory. No checkout or host is changed."""

from pathlib import Path
import unittest

from vm_proof_inventory import (
    STAGE2_STEPS,
    TESTED_ARCHIVE_SHA256,
    TESTED_COMMIT,
    UNEXECUTED_GATES,
    CheckoutInventory,
    InventoryRefusal,
    accept_archive_sha256,
    archive_command,
    in_place_commands,
    inventory_commands,
    inventory_from,
    metadata_only,
    parse_unit,
    removal_command,
    temp_checkout_commands,
    update_route,
)

ROOT = Path(__file__).resolve().parents[2]
PROOF = "/var/tmp/toolstack-vm-proof/vmproof-20261024T150000Z-a1b2c3d4"
DEST = PROOF + "/src"
PREEXISTING = "/opt/toolstack"
HEAD = "a" * 40


def known(paths=()):
    return CheckoutInventory(PREEXISTING, True, HEAD, "main", paths)


class InventoryStrategy(unittest.TestCase):
    def test_inventory_commands_are_status_and_hash_only(self):
        commands = inventory_commands(PREEXISTING)
        self.assertTrue(metadata_only(commands))
        joined = " ".join(" ".join(item) for item in commands)
        self.assertIn("rev-parse HEAD", joined)
        self.assertIn("--porcelain=v1", joined)
        self.assertNotIn("diff", joined)
        self.assertNotIn(".env", joined)

    def test_dirty_checkout_is_preserved_even_if_parent_approves_overwrite(self):
        inventory = inventory_from(PREEXISTING, HEAD, "main", " M deploy/docker/.env\n?? secrets.toml\n", True)
        self.assertEqual(inventory.dirty_paths, ("deploy/docker/.env", "secrets.toml"))
        route = update_route(inventory, rollback_bundle_saved=True, parent_approved_inplace=True)
        self.assertEqual(route.kind, "temp-checkout")
        self.assertEqual(route.reason, "dirty-preserve")
        with self.assertRaises(InventoryRefusal):
            in_place_commands(route, PREEXISTING, PROOF + "/old.bundle", TESTED_COMMIT)

    def test_unknown_checkout_refuses_update(self):
        inventory = inventory_from(PREEXISTING, None, None, "", False)
        route = update_route(inventory, rollback_bundle_saved=True, parent_approved_inplace=True)
        self.assertEqual(route.kind, "refuse")
        self.assertFalse(inventory.known)

    def test_clean_default_is_temp_checkout_until_rollback_and_approval(self):
        clean = known()
        default = update_route(clean, rollback_bundle_saved=True, parent_approved_inplace=False)
        self.assertEqual(default.reason, "temp-extract-only")
        missing = update_route(clean, rollback_bundle_saved=False, parent_approved_inplace=True)
        self.assertEqual(missing.reason, "rollback-not-recorded")
        approved = update_route(clean, rollback_bundle_saved=True, parent_approved_inplace=True)
        self.assertEqual(approved.kind, "temp-checkout")

    def test_temp_checkout_and_removal_cannot_touch_preexisting_tree(self):
        commands = temp_checkout_commands(PROOF + "/tested.tar", DEST, PROOF, PREEXISTING)
        self.assertEqual(commands[1][:3], ("tar", "-xf", PROOF + "/tested.tar"))
        self.assertNotIn("reset", " ".join(" ".join(item) for item in commands))
        self.assertNotIn("clean", " ".join(" ".join(item) for item in commands))
        self.assertTrue(accept_archive_sha256(TESTED_ARCHIVE_SHA256 + "  tested.tar\n"))
        self.assertFalse(accept_archive_sha256(HEAD))
        with self.assertRaises(InventoryRefusal):
            temp_checkout_commands(PROOF + "/tested.tar", PREEXISTING, PROOF, PREEXISTING)
        with self.assertRaises(InventoryRefusal):
            removal_command(PREEXISTING, PROOF, PREEXISTING)
        with self.assertRaises(InventoryRefusal):
            removal_command(PROOF, PROOF, PREEXISTING)
        self.assertEqual(removal_command(DEST, PROOF, PREEXISTING), ("rm", "-rf", DEST))

    def test_archive_is_exact_commit_and_not_a_branch_history(self):
        command = archive_command(PREEXISTING, PROOF + "/tested.tar", TESTED_COMMIT)
        self.assertEqual(command[:4], ("git", "-C", PREEXISTING, "archive"))
        self.assertIn("--format=tar", command)
        self.assertNotIn("push", command)
        self.assertNotIn("--all", command)
        self.assertEqual(TESTED_ARCHIVE_SHA256, "817da51460438e431c301d0691bb2165df85dcb519e614cdecd2f22aa0729764")
        with self.assertRaises(InventoryRefusal):
            archive_command(PREEXISTING, PROOF + "/tested.tar", "5ec463b")

    def test_in_place_update_is_refused(self):
        route = update_route(known(), rollback_bundle_saved=True, parent_approved_inplace=True)
        with self.assertRaises(InventoryRefusal):
            in_place_commands(route, PREEXISTING, PROOF + "/tested.tar", TESTED_COMMIT)
        self.assertEqual(TESTED_COMMIT, "5ec463bc53c051255d6126e0e87329fad2207096")


class UnitAndStageBoundary(unittest.TestCase):
    def test_sps_and_admin_templates_keep_writable_paths_without_install(self):
        sps = parse_unit((ROOT / "deploy/toolstack-sps.service").read_text())
        admin = parse_unit((ROOT / "deploy/toolstack-admin.service").read_text())
        self.assertEqual(sps.read_write, ("/var/lib/toolstack", "/var/log/toolstack"))
        self.assertEqual(sps.state_directory, "toolstack")
        self.assertEqual(sps.logs_directory, "toolstack")
        self.assertEqual(sps.xdg_state, "/var/lib")
        self.assertEqual(sps.xdg_config, "/var/lib")
        self.assertTrue(sps.no_new_privileges)
        self.assertNotIn("-/etc/toolstack/sps.env", sps.environment_files)
        self.assertIn("-/etc/toolstack/sps-runtime.env", sps.environment_files)
        self.assertFalse(sps.mentions_docker_socket)
        self.assertFalse(sps.mentions_sudo)
        self.assertEqual(admin.runner, "process")
        self.assertEqual(admin.read_write, ("/opt/toolstack",))
        self.assertTrue(admin.no_new_privileges)
        self.assertFalse(admin.mentions_docker_socket)
        self.assertFalse(admin.mentions_sudo)

    def test_stage2_order_and_unexecuted_installation_gates(self):
        self.assertLess(STAGE2_STEPS.index("start-guard-before-resize"), STAGE2_STEPS.index("qm-set-4096-while-stopped"))
        self.assertLess(STAGE2_STEPS.index("inventory-status-hash-paths"), STAGE2_STEPS.index("archive-tested-commit"))
        self.assertLess(
            STAGE2_STEPS.index("one-heavy-onebox-build"),
            STAGE2_STEPS.index("owned-cleanup-graceful-shutdown-restore-8192"),
        )
        self.assertIn("deploy/install.sh", UNEXECUTED_GATES)
        self.assertIn("Docker+SPS runner certification", UNEXECUTED_GATES)
        self.assertIn("process SPS TLS/restart/recovery on this VM", UNEXECUTED_GATES)
        self.assertNotIn("systemctl", " ".join(STAGE2_STEPS))


if __name__ == "__main__":
    unittest.main()
