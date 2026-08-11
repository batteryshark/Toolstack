"""Load and validate a rest tool's ``toolyard.toml``.

The forwarder is runtime-authoritative for rest-specific fields. Broker and
toolyard phases will do their own shallow validation, but this loader keeps the
process fail-closed if a hand-written TOML is malformed.
"""

from __future__ import annotations

import re
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """The rest forwarder configuration is invalid."""


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*\Z")
_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]+\Z")
_TEMPLATE_VAR = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PATH_PRINTABLE = frozenset(chr(c) for c in range(0x21, 0x7F))
_QUERY_PRINTABLE = _PATH_PRINTABLE | {" ", "'"}

VERBS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
BODY_KINDS = frozenset({"none", "text", "binary"})
RULE_RESPONSE_TYPES = frozenset({"json", "xml", "form", "plaintext"})


@dataclass(frozen=True)
class SecretDecl:
    name: str
    field: str
    writable: bool = False


@dataclass(frozen=True)
class SecretUpdateRule:
    secret_name: str
    response_type: str
    extract_path: str
    match_status: str


@dataclass(frozen=True)
class Operation:
    name: str
    risk: str
    description: str
    verb: str
    path: str
    allowed_headers: frozenset[str]
    body_kind: str
    body_content_type: str | None
    body_substitution: bool
    redact_response_body: bool = False
    redact_response_headers: bool = False
    secret_update_rules: tuple[SecretUpdateRule, ...] = ()


@dataclass(frozen=True)
class RestConfig:
    tool_id: str
    port: int | None
    base_url: str
    operations: dict[str, Operation]
    secrets: dict[str, SecretDecl]


def load_config(toml_path: str | Path) -> RestConfig:
    path = Path(toml_path)
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    if not isinstance(data, dict):
        raise _err(path, "root", "must be a TOML table")

    tool_id = data.get("id")
    if not (isinstance(tool_id, str) and _ID_RE.match(tool_id)):
        raise _err(path, "id", f"invalid tool id {tool_id!r}")
    if data.get("type") != "rest":
        raise _err(path, "type", "forwarder config must declare type = \"rest\"")

    entry = data.get("entrypoint", {})
    if not isinstance(entry, dict):
        raise _err(path, "entrypoint", "must be a table")
    port = entry.get("port")
    if port is not None and not (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535):
        raise _err(path, "entrypoint.port", f"must be an integer 1-65535, got {port!r}")

    base_url = _string(data, "base_url", path)
    _validate_base_url(path, base_url)

    secrets = _load_secrets(path, data.get("secrets", []))
    operations = _load_operations(path, data.get("operations", []), secrets)
    if not operations:
        raise _err(path, "operations", "rest tools must declare at least one operation")

    return RestConfig(tool_id=tool_id, port=port, base_url=base_url.rstrip("/"), operations=operations, secrets=secrets)


def _load_secrets(path: Path, raw: Any) -> dict[str, SecretDecl]:
    if not isinstance(raw, list):
        raise _err(path, "secrets", "must be an array of tables")
    secrets: dict[str, SecretDecl] = {}
    for idx, item in enumerate(raw):
        field = f"secrets[{idx}]"
        if not isinstance(item, dict):
            raise _err(path, field, "must be a table")
        name = _string(item, "name", path, field)
        if not _SECRET_RE.match(name):
            raise _err(path, f"{field}.name", "must match [A-Za-z0-9_-]+")
        if name in secrets:
            raise _err(path, f"{field}.name", f"duplicate secret {name!r}")
        secret_field = _string(item, "field", path, field)
        writable = item.get("writable", False)
        if not isinstance(writable, bool):
            raise _err(path, f"{field}.writable", "must be a boolean")
        secrets[name] = SecretDecl(name=name, field=secret_field, writable=writable)
    return secrets


def _load_operations(path: Path, raw: Any, secrets: dict[str, SecretDecl]) -> dict[str, Operation]:
    if not isinstance(raw, list):
        raise _err(path, "operations", "must be an array of tables")
    operations: dict[str, Operation] = {}
    writable = {name for name, spec in secrets.items() if spec.writable}
    for idx, item in enumerate(raw):
        field = f"operations[{idx}]"
        if not isinstance(item, dict):
            raise _err(path, field, "must be a table")
        name = _string(item, "name", path, field)
        if not _ID_RE.match(name):
            raise _err(path, f"{field}.name", "must match [A-Za-z0-9][A-Za-z0-9_-]*")
        if name in operations:
            raise _err(path, f"{field}.name", f"duplicate operation {name!r}")

        verb = _string(item, "verb", path, field).upper()
        if verb not in VERBS:
            raise _err(path, f"{field}.verb", f"must be one of {', '.join(sorted(VERBS))}")
        op_path = _string(item, "path", path, field)
        _validate_path_template(path, f"{field}.path", op_path)

        allowed_headers = item.get("allowed_headers", [])
        if not isinstance(allowed_headers, list) or not all(isinstance(h, str) for h in allowed_headers):
            raise _err(path, f"{field}.allowed_headers", "must be a list of strings")
        allowed = set()
        for h in allowed_headers:
            if not _HEADER_RE.match(h):
                raise _err(path, f"{field}.allowed_headers", f"invalid header name {h!r}")
            allowed.add(h.lower())

        body_kind = item.get("body_kind")
        if body_kind is None:
            body_kind = "none" if verb in {"GET", "DELETE"} else "text"
        if body_kind not in BODY_KINDS:
            raise _err(path, f"{field}.body_kind", "must be none, text, or binary")

        body_content_type = item.get("body_content_type")
        if body_content_type is not None and not isinstance(body_content_type, str):
            raise _err(path, f"{field}.body_content_type", "must be a string")
        if body_kind == "none":
            body_content_type = None
        elif not body_content_type:
            body_content_type = "application/json" if body_kind == "text" else "application/octet-stream"

        body_substitution = item.get("body_substitution")
        if body_substitution is None:
            body_substitution = body_kind == "text"
        if not isinstance(body_substitution, bool):
            raise _err(path, f"{field}.body_substitution", "must be a boolean")
        if body_kind == "binary":
            body_substitution = False
        if body_kind == "none":
            body_substitution = False

        redact_body = item.get("redact_response_body", False)
        if not isinstance(redact_body, bool):
            raise _err(path, f"{field}.redact_response_body", "must be a boolean")
        redact_headers = item.get("redact_response_headers", False)
        if not isinstance(redact_headers, bool):
            raise _err(path, f"{field}.redact_response_headers", "must be a boolean")

        rules = _load_rules(path, field, item.get("secret_update_rules", []), writable)
        operations[name] = Operation(
            name=name,
            risk=item.get("risk", "unknown") if isinstance(item.get("risk", "unknown"), str) else "unknown",
            description=item.get("description", "") if isinstance(item.get("description", ""), str) else "",
            verb=verb,
            path=op_path,
            allowed_headers=frozenset(allowed),
            body_kind=body_kind,
            body_content_type=body_content_type,
            body_substitution=body_substitution,
            redact_response_body=redact_body,
            redact_response_headers=redact_headers,
            secret_update_rules=rules,
        )
    return operations


def _load_rules(path: Path, op_field: str, raw: Any, writable: set[str]) -> tuple[SecretUpdateRule, ...]:
    if not isinstance(raw, list):
        raise _err(path, f"{op_field}.secret_update_rules", "must be a list")
    rules: list[SecretUpdateRule] = []
    for idx, item in enumerate(raw):
        field = f"{op_field}.secret_update_rules[{idx}]"
        if not isinstance(item, dict):
            raise _err(path, field, "must be a table")
        secret_name = _string(item, "secret_name", path, field)
        if secret_name not in writable:
            raise _err(path, f"{field}.secret_name", f"secret {secret_name!r} is not declared writable")
        response_type = _string(item, "response_type", path, field)
        if response_type not in RULE_RESPONSE_TYPES:
            raise _err(path, f"{field}.response_type", "must be json, xml, form, or plaintext")
        rules.append(
            SecretUpdateRule(
                secret_name=secret_name,
                response_type=response_type,
                extract_path=_string(item, "extract_path", path, field),
                match_status=_string(item, "match_status", path, field),
            )
        )
    return tuple(rules)


def _validate_base_url(path: Path, value: str) -> None:
    split = urllib.parse.urlsplit(value)
    if split.scheme not in {"http", "https"}:
        raise _err(path, "base_url", "must use http or https")
    if not split.hostname:
        raise _err(path, "base_url", "must include a host")
    if split.username is not None or split.password is not None:
        raise _err(path, "base_url", "must not embed credentials")
    if split.query or split.fragment:
        raise _err(path, "base_url", "must not include a query or fragment")


def _validate_path_template(path: Path, field: str, value: str) -> None:
    path_part, _, query_part = value.partition("?")
    if not path_part.startswith("/") or path_part.startswith("//"):
        raise _err(path, field, "must start with a single /")
    if "#" in value:
        raise _err(path, field, "must not include fragment text")
    if any(c not in _PATH_PRINTABLE for c in path_part):
        raise _err(path, field, "path portion must be printable ASCII without spaces")
    if any(c not in _QUERY_PRINTABLE for c in query_part):
        raise _err(path, field, "query portion must be printable ASCII with spaces and single quotes allowed")
    stripped = _TEMPLATE_VAR.sub("", value)
    if "{" in stripped or "}" in stripped:
        raise _err(path, field, "only single-segment {name} path variables are supported")


def _string(data: dict[str, Any], key: str, path: Path, prefix: str | None = None) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise _err(path, f"{prefix + '.' if prefix else ''}{key}", "must be a non-empty string")
    return value


def _err(path: Path, field: str, msg: str) -> ConfigError:
    return ConfigError(f"{path}: {field}: {msg}")
