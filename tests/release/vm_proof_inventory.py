"""Stage-1 inventory for the VM Toolstack copy. No checkout is modified.

Status, commit hashes, and path names only. Patch text, secrets, and .env
files are never requested. A dirty preexisting checkout is preserved. The
default update is a separate temporary checkout of the tested commit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Historical stage-1 fixture only. Live Source.load takes explicit commit/SHA.
TESTED_COMMIT = "5ec463bc53c051255d6126e0e87329fad2207096"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
# sha256 of `git archive --format=tar` of TESTED_COMMIT. Tracked tree only.
TESTED_ARCHIVE_SHA256 = "817da51460438e431c301d0691bb2165df85dcb519e614cdecd2f22aa0729764"

UNEXECUTED_GATES = (
    "deploy/install.sh",
    "systemctl enable",
    "systemctl start",
    "useradd",
    "docker compose up",
    "Docker+SPS runner certification",
    "process SPS TLS/restart/recovery on this VM",
    "qm stop or poweroff",
    "memory restore while a guest is running",
    "mutation of VM 100 or any other guest",
)

STAGE2_STEPS = (
    "resample-baseline",
    "refuse-start-unless-stopped-8192-and-headroom",
    "start-guard-before-resize",
    "qm-set-4096-while-stopped",
    "qm-start-130",
    "wait-guest-agent-or-rollback",
    "list-units-ports-process-metadata",
    "inventory-status-hash-paths",
    "archive-tested-commit",
    "one-heavy-onebox-build",
    "image-content-and-fake-admin-start",
    "echo-builds-only-if-gate-open",
    "offline-unit-parse",
    "owned-cleanup-graceful-shutdown-restore-8192",
    "confirm-nod-and-stop",
)


class InventoryRefusal(Exception):
    """An update or removal that would touch owner work or escape the proof root."""


@dataclass(frozen=True)
class CheckoutInventory:
    path: str
    known: bool
    head: str | None
    branch: str | None
    dirty_paths: tuple[str, ...]


@dataclass(frozen=True)
class UpdateRoute:
    kind: str
    reason: str


@dataclass(frozen=True)
class UnitContract:
    read_write: tuple[str, ...]
    state_directory: str | None
    logs_directory: str | None
    xdg_state: str | None
    xdg_config: str | None
    no_new_privileges: bool
    environment_files: tuple[str, ...]
    runner: str | None
    mentions_docker_socket: bool
    mentions_sudo: bool


def inventory_commands(path: str) -> tuple[tuple[str, ...], ...]:
    _absolute(path)
    git = ("git", "-C", path)
    return (
        git + ("rev-parse", "--show-toplevel"),
        git + ("rev-parse", "HEAD"),
        git + ("rev-parse", "--abbrev-ref", "HEAD"),
        git + ("status", "--porcelain=v1", "-uall"),
        git + ("submodule", "status"),
    )


def metadata_only(commands: tuple[tuple[str, ...], ...]) -> bool:
    forbidden = {"diff", "show", "clean", "reset", "checkout", "stash", "apply", "am", "cat"}
    for argv in commands:
        if any(part in forbidden for part in argv):
            return False
        if any(part.endswith(".env") or part == ".env" for part in argv):
            return False
    return True


def parse_porcelain(text: str) -> tuple[str, ...]:
    paths = []
    for line in text.splitlines():
        if len(line) < 4:
            continue
        paths.append(line[3:])
    return tuple(paths)


def inventory_from(path: str, head: str | None, branch: str | None, porcelain: str, inside: bool) -> CheckoutInventory:
    if not inside or head is None or not COMMIT_RE.fullmatch(head):
        return CheckoutInventory(path, False, None, None, ())
    return CheckoutInventory(path, True, head, branch, parse_porcelain(porcelain))


def update_route(
    inventory: CheckoutInventory,
    *,
    rollback_bundle_saved: bool,
    parent_approved_inplace: bool,
) -> UpdateRoute:
    if not inventory.known:
        return UpdateRoute("refuse", "unknown-checkout")
    if inventory.dirty_paths:
        return UpdateRoute("temp-checkout", "dirty-preserve")
    if not rollback_bundle_saved and parent_approved_inplace:
        return UpdateRoute("refuse", "rollback-not-recorded")
    return UpdateRoute("temp-checkout", "temp-extract-only")


def archive_command(source: str, archive_path: str, commit: str) -> tuple[str, ...]:
    """Tracked tree of the exact commit. No branch history and no untracked files."""
    if not COMMIT_RE.fullmatch(commit):
        raise InventoryRefusal("archive requires an explicit full commit")
    _absolute(source)
    _absolute(archive_path)
    if not archive_path.endswith(".tar") or archive_path.endswith("/.tar"):
        raise InventoryRefusal("archive path must name a tar file")
    return ("git", "-C", source, "archive", "--format=tar", f"--output={archive_path}", commit)


def archive_checksum_command(archive_path: str) -> tuple[str, ...]:
    _absolute(archive_path)
    return ("sha256sum", "--", archive_path)


def accept_archive_sha256(hex_text: str) -> bool:
    return hex_text.strip().split()[0] == TESTED_ARCHIVE_SHA256


def temp_checkout_commands(
    archive: str,
    dest: str,
    proof_root: str,
    preexisting: str,
) -> tuple[tuple[str, ...], ...]:
    _contained(dest, proof_root)
    if _overlaps(dest, preexisting):
        raise InventoryRefusal("temp checkout overlaps the preexisting checkout")
    if not archive.endswith(".tar"):
        raise InventoryRefusal("temp checkout source is not the tested tar")
    return (
        ("mkdir", "-m", "0700", dest),
        ("tar", "-xf", archive, "-C", dest),
    )


def in_place_commands(
    route: UpdateRoute,
    checkout: str,
    bundle: str,
    commit: str,
) -> tuple[tuple[str, ...], ...]:
    del route, checkout, bundle, commit
    raise InventoryRefusal("preexisting checkout is not an update target; extract the tested tar")


def removal_command(path: str, proof_root: str, preexisting: str) -> tuple[str, ...]:
    _contained(path, proof_root)
    if _overlaps(path, preexisting):
        raise InventoryRefusal("refusing to remove a preexisting checkout")
    return ("rm", "-rf", path)


def accept_clone_head(head: str) -> bool:
    return head.strip() == TESTED_COMMIT


def parse_unit(text: str) -> UnitContract:
    read_write: list[str] = []
    environment_files: list[str] = []
    operative: list[str] = []
    state = logs = xdg_state = xdg_config = runner = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        operative.append(line)
        if line.startswith("ReadWritePaths="):
            read_write.extend(line.split("=", 1)[1].split())
        elif line.startswith("StateDirectory="):
            state = line.split("=", 1)[1]
        elif line.startswith("LogsDirectory="):
            logs = line.split("=", 1)[1]
        elif line.startswith("EnvironmentFile="):
            environment_files.append(line.split("=", 1)[1])
        elif line.startswith("Environment="):
            value = line.split("=", 1)[1]
            if value.startswith("XDG_STATE_HOME="):
                xdg_state = value.split("=", 1)[1]
            elif value.startswith("XDG_CONFIG_HOME="):
                xdg_config = value.split("=", 1)[1]
            elif value.startswith("TOOLSTACK_RUNNER="):
                runner = value.split("=", 1)[1]
    body = "\n".join(operative).lower()
    return UnitContract(
        tuple(read_write), state, logs, xdg_state, xdg_config,
        "NoNewPrivileges=true" in operative, tuple(environment_files), runner,
        "docker.sock" in body, "sudo" in body,
    )


def _absolute(path: str) -> None:
    if not path.startswith("/") or ".." in path.split("/"):
        raise InventoryRefusal("path is not absolute")


def _parts(path: str) -> tuple[str, ...]:
    _absolute(path)
    return tuple(part for part in path.split("/") if part)


def _contained(path: str, root: str) -> None:
    child = _parts(path)
    parent = _parts(root)
    if child[:len(parent)] != parent or len(child) <= len(parent):
        raise InventoryRefusal("path escapes the proof root")


def _overlaps(left: str, right: str) -> bool:
    a = _parts(left)
    b = _parts(right)
    return a == b or a[:len(b)] == b or b[:len(a)] == a
