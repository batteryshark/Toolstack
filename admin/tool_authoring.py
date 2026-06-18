"""Author and edit a tool's ``toolyard.toml`` from the panel.

Per the chosen scope this writes the **manifest only** — the operator supplies the
tool's code (a process ``command`` / ``app.py``) or a Docker ``image``. The form
sends a normalized tool definition (assembled by the editor's JS into one JSON
field, so there is no hand-typed TOML and no quoting risk); this module validates
it, serializes idiomatic TOML, and reads it back for editing.

Secret **declarations** (name + backend field) are authored here; secret **values**
are not — those stay in the on-disk secrets file, off the control plane.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

RISKS = ("low", "medium", "high")
ARG_TYPES = ("string", "number", "integer", "boolean", "object", "array")

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")   # no dots (tool.op routing) or slashes
_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")             # operation / argument names
_SECRET_RE = re.compile(r"^[A-Za-z0-9_.-]+$")         # also used as a filename
_VAULT_RE = re.compile(r"^[A-Za-z0-9 _.-]+$")         # Infisical project name/slug/id
_ITEM_RE = re.compile(r"^[A-Za-z0-9_./-]+$")          # Infisical secret path (may have /)


def from_json(raw: str) -> dict:
    """Parse the editor's hidden JSON field into a normalized tool dict."""
    return normalize(json.loads(raw))


def normalize(data: dict) -> dict:
    """Coerce a raw tool dict to clean types and drop blank rows, so validation and
    serialization can assume a tidy shape."""
    def s(x) -> str:
        return str(x if x is not None else "").strip()

    operations = []
    for o in data.get("operations") or []:
        name = s(o.get("name"))
        if not name:
            continue
        args = []
        for a in o.get("args") or []:
            an = s(a.get("name"))
            if not an:
                continue
            args.append({
                "name": an,
                "type": s(a.get("type")) or "string",
                "required": bool(a.get("required")),
                "description": s(a.get("description")),
            })
        operations.append({
            "name": name,
            "risk": s(o.get("risk")) or "low",
            "description": s(o.get("description")),
            "args": args,
        })

    secrets = []
    for sec in data.get("secrets") or []:
        nm = s(sec.get("name"))
        if not nm:
            continue
        # vault/item are the Infisical coordinates (blank -> backend defaults: vault from
        # $TOOLSTACK_INFISICAL_VAULT, item from the tool id). Ignored by the file backend.
        secrets.append({
            "name": nm,
            "field": s(sec.get("field")),
            "vault": s(sec.get("vault")),
            "item": s(sec.get("item")),
            "writable": bool(sec.get("writable")),
        })

    try:
        port = int(data.get("port"))
    except (TypeError, ValueError):
        port = None  # flagged by validate

    return {
        "id": s(data.get("id")),
        "type": s(data.get("type")) or "rest",
        "command": s(data.get("command")),
        "image": s(data.get("image")),
        "port": port,
        "operations": operations,
        "secrets": secrets,
    }


def validate(data: dict) -> list[str]:
    """Return a list of human-readable problems (empty == valid). Uniqueness of the
    id across other tools is the caller's job (it needs the registry)."""
    errors: list[str] = []
    if not _ID_RE.match(data["id"]):
        errors.append("id must start alphanumeric and contain only letters, digits, _ or - (no dots)")
    if data["type"] != "rest":
        errors.append('type must be "rest"')
    if not data["command"] and not data["image"]:
        errors.append("provide an entrypoint command (process backend) or image (docker backend)")
    if not isinstance(data["port"], int) or not (1 <= data["port"] <= 65535):
        errors.append("port must be an integer between 1 and 65535")
    if not data["operations"]:
        errors.append("add at least one operation")
    seen = set()
    for o in data["operations"]:
        if not _NAME_RE.match(o["name"]):
            errors.append(f"operation name '{o['name']}' may contain only letters, digits and _")
        if o["name"] in seen:
            errors.append(f"duplicate operation '{o['name']}'")
        seen.add(o["name"])
        if o["risk"] not in RISKS:
            errors.append(f"operation '{o['name']}' risk must be one of {', '.join(RISKS)}")
        for a in o["args"]:
            if not _NAME_RE.match(a["name"]):
                errors.append(f"argument '{a['name']}' in '{o['name']}' may contain only letters, digits and _")
    for sec in data["secrets"]:
        if not _SECRET_RE.match(sec["name"]):
            errors.append(f"secret name '{sec['name']}' has invalid characters")
        if not sec["field"]:
            errors.append(f"secret '{sec['name']}' needs a backend field")
        if sec.get("vault") and not _VAULT_RE.match(sec["vault"]):
            errors.append(f"secret '{sec['name']}' vault has invalid characters")
        if sec.get("item") and not _ITEM_RE.match(sec["item"]):
            errors.append(f"secret '{sec['name']}' item has invalid characters")
    return errors


def _s(value) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _arg_inline(arg: dict) -> str:
    parts = [f"name = {_s(arg['name'])}",
             f"type = {_s(arg.get('type', 'string'))}",
             f"required = {str(bool(arg.get('required'))).lower()}"]
    if arg.get("description"):
        parts.append(f"description = {_s(arg['description'])}")
    return "{ " + ", ".join(parts) + " }"


def to_toml(data: dict) -> str:
    """Serialize a normalized tool dict to idiomatic toolyard.toml."""
    out = [f"id = {_s(data['id'])}", f"type = {_s(data['type'])}", "", "[entrypoint]"]
    if data["command"]:
        out.append(f"command = {_s(data['command'])}")
    if data["image"]:
        out.append(f"image = {_s(data['image'])}")
    out.append(f"port = {data['port']}")
    for o in data["operations"]:
        out += ["", "[[operations]]", f"name = {_s(o['name'])}", f"risk = {_s(o['risk'])}"]
        if o["description"]:
            out.append(f"description = {_s(o['description'])}")
        if o["args"]:
            out.append("args = [ " + ", ".join(_arg_inline(a) for a in o["args"]) + " ]")
    for sec in data["secrets"]:
        out += ["", "[[secrets]]", f"name = {_s(sec['name'])}", f"field = {_s(sec['field'])}"]
        if sec.get("vault"):
            out.append(f"vault = {_s(sec['vault'])}")
        if sec.get("item"):
            out.append(f"item = {_s(sec['item'])}")
        if sec["writable"]:
            out.append("writable = true")
    return "\n".join(out) + "\n"


def read(dir_path: str | Path) -> dict:
    """Load an existing tool's toolyard.toml into the editor's dict shape."""
    with open(Path(dir_path) / "toolyard.toml", "rb") as f:
        data = tomllib.load(f)
    entry = data.get("entrypoint", {})
    return normalize({
        "id": data.get("id", ""),
        "type": data.get("type", "rest"),
        "command": entry.get("command", ""),
        "image": entry.get("image", ""),
        "port": entry.get("port"),
        "operations": data.get("operations", []),
        "secrets": data.get("secrets", []),
    })


def write(dir_path: str | Path, data: dict) -> Path:
    """Validate and write ``<dir_path>/toolyard.toml``. Raises ValueError on invalid
    input or a missing directory; only ever writes a file named toolyard.toml."""
    errors = validate(data)
    if errors:
        raise ValueError("; ".join(errors))
    path = Path(dir_path)
    if not path.is_dir():
        raise ValueError(f"not an existing directory: {dir_path}")
    target = path / "toolyard.toml"
    target.write_text(to_toml(data), encoding="utf-8")
    return target
