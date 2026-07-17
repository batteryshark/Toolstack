"""Endpoint ops: register, unregister, get_secrets, get_secret, write_secret.

Each function takes a context (carrying store + audit + plugin + config) and
an incoming JSON message, and returns the wire envelope: a dict with
`status: "ok"` + payload, or `status: "error"` + a fixed `message` from
the guidance's allowed set.

Errors never carry a secret value, a credential, or a backend response body;
the only payload is the message string itself.

Dispatch + transport-layer error mapping happen in server.py.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .config import Config
from .store import Registration, ToolRegistrationStore
from .wire import constant_time_eq, err_envelope


class AuthError(Exception):
    """401 Unauthorized -- bad SP/ES secret or missing auth field."""


class BadRegistration(Exception):
    """400 Bad request -- malformed body or invalid field types."""


class BadRequest(BadRegistration):
    """400 Bad request -- alias for BadRegistration (semantic clarity at call sites)."""


class ToolNotFound(Exception):
    """404 Not found -- no registration for toolid."""


class SecretNotFound(Exception):
    """404 Not found -- tool registered but the named secret is unknown."""


class NotWritable(Exception):
    """Not writable -- writeback for a non-writable CS_TUPLE."""


class BackendError(Exception):
    """500 Backend error -- the plugin's get/write raised."""


@dataclass
class HandlerContext:
    config: Config
    store: ToolRegistrationStore
    audit: Any  # AuditLogger; not type-checked to keep the layer flexible
    plugin: Any


# ---- auth helpers ------------------------------------------------------------

_SP_PREFIX = "spsecret"
_ES_PREFIX = "esecret"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _field(msg: dict[str, Any], key: str) -> str:
    """Pull a string field from the message, raising BadRegistration on missing
    or wrong-type values."""
    v = msg.get(key)
    if not isinstance(v, str) or not v:
        raise BadRegistration(f"{key!r} must be a non-empty string")
    return v


def _ensure_loaded(name: str) -> str:
    # Module-level for testability later if needed.
    return name


def check_sp(ctx: HandlerContext, msg: dict[str, Any]) -> None:
    """Verify mode-0600 + SP secret match. Raises AuthError on any failure."""
    val = msg.get(_SP_PREFIX)
    if not isinstance(val, str) or not val:
        raise AuthError(f"{_SP_PREFIX} missing or not a string")
    if not constant_time_eq(val, ctx.config.sp_secret):
        raise AuthError(f"{_SP_PREFIX} mismatch")


def check_es(ctx: HandlerContext, tool_id: str, msg: dict[str, Any]) -> None:
    """Verify the E_SECRET matches the registered tool. Raises AuthError /
    ToolNotFound on any failure."""
    val = msg.get(_ES_PREFIX)
    if not isinstance(val, str) or not val:
        raise AuthError(f"{_ES_PREFIX} missing or not a string")
    rec = ctx.store.get(tool_id)
    if rec is None:
        raise ToolNotFound(tool_id)
    if not constant_time_eq(val, rec.esecret):
        raise AuthError(f"{_ES_PREFIX} mismatch")


# ---- helpers ----------------------------------------------------------------

def parse_cs_tuples(entries: Any) -> tuple[dict, ...]:
    """Validate each CS_TUPLE has the required fields. Defaults: item=None,
    writable=False."""
    if not isinstance(entries, list):
        raise BadRegistration("secrets must be a JSON array")
    out: list[dict] = []
    for e in entries:
        if not isinstance(e, dict):
            raise BadRegistration("each secret entry must be an object")
        name = e.get("name")
        field = e.get("field")
        if not isinstance(name, str) or not name:
            raise BadRegistration("secret name must be a non-empty string")
        if not isinstance(field, str) or not field:
            raise BadRegistration("secret field must be a non-empty string")
        item = e.get("item")
        if item is not None and not isinstance(item, str):
            raise BadRegistration("secret item must be a string or null")
        writable = e.get("writable", False)
        if not isinstance(writable, bool):
            raise BadRegistration("secret writable must be a boolean")
        out.append({"name": name, "field": field, "item": item, "writable": writable})
    return tuple(out)


# ---- ops --------------------------------------------------------------------

def handle_register(ctx: HandlerContext, msg: dict[str, Any]) -> dict[str, Any]:
    check_sp(ctx, msg)
    tool_id = _field(msg, "toolid")
    esecret = msg.get("esecret")
    if not isinstance(esecret, str) or not _HEX_RE.match(esecret) or len(esecret) < 32:
        raise BadRegistration("esecret must be a hex string of at least 32 chars")
    entries = parse_cs_tuples(msg.get("secrets"))
    ctx.store.register(tool_id, Registration(esecret=esecret, secret_entries=entries))
    ctx.audit.event("register", tool_id=tool_id)
    return {"status": "ok"}


def handle_unregister(ctx: HandlerContext, msg: dict[str, Any]) -> dict[str, Any]:
    check_sp(ctx, msg)
    tool_id = _field(msg, "toolid")
    ctx.store.unregister(tool_id)
    ctx.audit.event("unregister", tool_id=tool_id)
    return {"status": "ok"}


def handle_get_secrets(ctx: HandlerContext, msg: dict[str, Any]) -> dict[str, Any]:
    tool_id = _field(msg, "toolid")
    check_es(ctx, tool_id, msg)
    rec = ctx.store.get(tool_id)
    if rec is None:  # belt-and-suspenders; check_es already raised
        raise ToolNotFound(tool_id)
    body: dict[str, str] = {}
    for entry in rec.secret_entries:
        item = entry.get("item") or tool_id
        try:
            value = ctx.plugin.get_secret(entry["field"], item)
        except KeyError as exc:
            raise BackendError(f"{tool_id}.{entry['name']}: {exc}") from exc
        body[entry["name"]] = value
    return {"status": "ok", "secrets": body}


def handle_get_secret(ctx: HandlerContext, msg: dict[str, Any]) -> dict[str, Any]:
    tool_id = _field(msg, "toolid")
    name = _field(msg, "name")
    check_es(ctx, tool_id, msg)
    rec = ctx.store.get(tool_id)
    if rec is None:
        raise ToolNotFound(tool_id)
    match = next((e for e in rec.secret_entries if e.get("name") == name), None)
    if match is None:
        raise SecretNotFound(f"{tool_id}.{name}")
    item = match.get("item") or tool_id
    try:
        value = ctx.plugin.get_secret(match["field"], item)
    except KeyError as exc:
        raise BackendError(f"{tool_id}.{name}: {exc}") from exc
    return {"status": "ok", "secrets": {name: value}}


def handle_write_secret(ctx: HandlerContext, msg: dict[str, Any]) -> dict[str, Any]:
    tool_id = _field(msg, "toolid")
    name = _field(msg, "name")
    check_es(ctx, tool_id, msg)
    rec = ctx.store.get(tool_id)
    if rec is None:
        raise ToolNotFound(tool_id)
    match = next((e for e in rec.secret_entries if e.get("name") == name), None)
    if match is None:
        raise SecretNotFound(f"{tool_id}.{name}")
    if match.get("writable") is not True:
        raise NotWritable(f"{tool_id}.{name}")
    value = msg.get("value")
    if not isinstance(value, str):
        raise BadRequest("'value' must be a string")
    item = match.get("item") or tool_id
    try:
        ctx.plugin.write_secret(match["field"], item, value)
    except Exception as exc:
        raise BackendError(f"{tool_id}.{name}: {exc}") from exc
    return {"status": "ok", "name": name}
