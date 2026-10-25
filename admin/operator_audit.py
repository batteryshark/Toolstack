"""Bounded metadata only. The host operator can delete this local audit."""
from dataclasses import asdict

from broker import operations
from . import broker_config
from .store_access import open_store


class AppliedAuditError(RuntimeError):
    """The requested change happened but its completion audit did not."""


def save_config(current, updated, user):
    # Field names are a fixed schema: never record tokens, paths or URL values.
    before, after = asdict(current), asdict(updated)
    fields = [key for key in before if before[key] != after[key]]
    with open_store(current) as store:
        operations.record_admin_event(store, user, "config_change_requested", {"fields": fields})
        broker_config.save(updated)
        try:
            operations.record_admin_event(store, user, "config_changed", {"fields": fields})
        except Exception:
            raise AppliedAuditError("Configuration saved but completion audit failed; verify before retrying") from None


def clear_audit(config, user):
    # Both authenticated adapters require administrator authority. Deletion is
    # intentional, not a security erasure or independent evidence guarantee.
    with open_store(config) as store:
        store.clear_audit()
        try:
            operations.record_admin_event(store, user, "audit_cleared", {"authority": "host_admin"})
        except Exception:
            raise AppliedAuditError("Audit cleared but deletion marker failed; verify before retrying") from None
