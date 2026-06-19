"""Operator provisioning of secret VALUES — the local-vault path only.

The control plane normally never touches secret values: they live in the backend, off the panel
(see admin.tool_authoring / admin.toolyard_ops). The local encrypted vault is the deliberate
exception for the laptop deployment — there's no separate secret manager, so the operator fills it
here. Values are WRITE-ONLY through this module: set, never read back, never logged. Other backends
(file / infisical) are managed out-of-band, so this refuses them.
"""

from __future__ import annotations

from toolyard.secrets import VaultBackend

from . import settings


def is_settable() -> bool:
    """True only when the active backend is the local vault (the one we can safely write to here)."""
    return settings.secret_backend() == "vault"


def _vault() -> VaultBackend:
    if not is_settable():
        raise ValueError(
            f"setting secret values here is only supported for the local 'vault' backend "
            f"(the active backend is '{settings.secret_backend()}'); set those values where that "
            f"backend is managed")
    return VaultBackend.from_env()   # reads $TOOLSTACK_VAULT_FILE + passphrase from the env


def set_value(tool_id: str, field: str, value: str) -> None:
    """Provision ``tool_id.field`` in the vault. Raises ValueError if the backend isn't the vault,
    or the vault can't be opened (missing/empty passphrase, wrong passphrase, missing extra)."""
    _vault().set_secret(tool_id, field, value)


def provisioned_fields(tool_id: str, declared: list[str]) -> list[str]:
    """Which of the tool's ``declared`` secret fields currently have a value (vault only). Returns
    the field NAMES that are set — never the values. Empty list when the backend isn't the vault."""
    if not is_settable():
        return []
    vault = VaultBackend.from_env()
    return [field for field in declared if vault.has_secret(tool_id, field)]
