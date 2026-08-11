"""Build outbound HTTP requests from a rest operation and broker envelope."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from sps.tool_sdk import SecretClient
from .config import Operation, RestConfig


class RequestBuildError(ValueError):
    """The broker envelope cannot be turned into the configured outbound request."""

    def __init__(self, code: str, detail: str = "", **fields) -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code
        self.fields = fields

    def envelope(self) -> dict:
        obj = {"error": self.code}
        if self.detail:
            obj["detail"] = self.detail
        obj.update(self.fields)
        return obj


@dataclass(frozen=True)
class OutboundRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None


_TEMPLATE_VAR = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SECRET_REF = re.compile(r"\{\{secret:([A-Za-z0-9_-]+)\}\}")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*\Z")
_FORBIDDEN_PATH_VARIABLE_CHARS = set("/\\")
_PATH_VALUE_CHARS = frozenset(chr(c) for c in range(0x21, 0x7F))
_QUERY_VALUE_CHARS = _PATH_VALUE_CHARS | {" ", "'"}


def build_request(config: RestConfig, op_name: str, arguments: dict,
                  secrets: SecretClient, max_body: int) -> OutboundRequest:
    if not isinstance(arguments, dict):
        raise RequestBuildError("invalid_arguments", "arguments must be an object")
    op = config.operations.get(op_name)
    if op is None:
        raise RequestBuildError("unknown_op", "unknown rest operation", op=op_name)
    path = _hydrate_path(op, arguments)
    url = _join_url(config.base_url, path)
    headers = _build_headers(op, arguments, secrets)
    body = _build_body(op, arguments, secrets, max_body)
    if body is not None and op.body_content_type:
        headers["Content-Type"] = op.body_content_type
    return OutboundRequest(method=op.verb, url=url, headers=headers, body=body)


def read_secret(secrets: SecretClient, name: str) -> str:
    try:
        return secrets.get(name)
    except KeyError:
        raise RequestBuildError(
            "missing_secret", "configured secret is unavailable", secret=name
        )


def _hydrate_path(op: Operation, arguments: dict) -> str:
    variables = arguments.get("variables", {})
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        raise RequestBuildError("invalid_variables", "variables must be an object")

    query_at = op.path.find("?")

    if query_at < 0:
        path_prefix = op.path
        path_fill = _make_path_fill(variables, query_at=-1)
        return _TEMPLATE_VAR.sub(path_fill, path_prefix)

    path_prefix = op.path[:query_at]
    query_suffix = op.path[query_at:]

    path_fill = _make_path_fill(variables, query_at=query_at)
    rendered_prefix = _TEMPLATE_VAR.sub(path_fill, path_prefix)

    rendered_query = _hydrate_query(query_suffix, variables)
    if rendered_query:
        return rendered_prefix + "?" + rendered_query
    return rendered_prefix


def _make_path_fill(variables: dict, query_at: int):
    def fill(match: re.Match[str]) -> str:
        name = match.group(1)
        value = variables.get(name)
        if not isinstance(value, str):
            raise RequestBuildError("missing_variable", f"missing path variable {name!r}", name=name)
        if query_at >= 0 and match.start() > query_at:
            return urllib.parse.quote(_validate_query_variable(name, value), safe="")
        return urllib.parse.quote(_validate_path_variable(name, value), safe="")
    return fill


def _hydrate_query(query_suffix: str, variables: dict) -> str:
    pairs: list[str] = []
    for pair in query_suffix[1:].split("&"):
        if not pair:
            continue
        referenced = _TEMPLATE_VAR.findall(pair)
        if not referenced:
            pairs.append(pair)
            continue
        missing = [name for name in referenced if name not in variables]
        if missing:
            continue
        for name in referenced:
            value = variables[name]
            if not isinstance(value, str):
                raise RequestBuildError(
                    "missing_variable", f"missing query variable {name!r}", name=name,
                )
        def fill(match: re.Match[str], _variables=variables) -> str:
            name = match.group(1)
            return urllib.parse.quote(_validate_query_variable(name, _variables[name]), safe="")
        pairs.append(_TEMPLATE_VAR.sub(fill, pair))
    return "&".join(pairs)


def _validate_variable_common(name: str, raw: str, context: str) -> str:
    value = raw.strip()
    if not value:
        raise RequestBuildError("invalid_variable", f"{context} variable is empty", name=name)
    if len(value.encode("utf-8")) > 4096:
        raise RequestBuildError("invalid_variable", f"{context} variable exceeds 4096 bytes", name=name)
    if any(ord(c) > 0x7f for c in value):
        raise RequestBuildError("invalid_variable", f"{context} variable must be ASCII", name=name)
    return value


def _validate_path_variable(name: str, raw: str) -> str:
    value = _validate_variable_common(name, raw, "path")
    if any(c not in _PATH_VALUE_CHARS for c in value):
        raise RequestBuildError("invalid_variable", "path variable contains whitespace or control characters", name=name)
    if any(c in _FORBIDDEN_PATH_VARIABLE_CHARS for c in value):
        raise RequestBuildError("invalid_variable", "path variable contains a forbidden character", name=name)
    if ".." in value:
        raise RequestBuildError("invalid_variable", "path variable contains '..'", name=name)
    decoded = urllib.parse.unquote(value)
    if any(c not in _PATH_VALUE_CHARS for c in decoded):
        raise RequestBuildError("invalid_variable", "path variable contains an encoded forbidden character", name=name)
    if any(c in _FORBIDDEN_PATH_VARIABLE_CHARS for c in decoded):
        raise RequestBuildError("invalid_variable", "path variable contains an encoded forbidden character", name=name)
    if ".." in decoded:
        raise RequestBuildError("invalid_variable", "path variable contains '..'", name=name)
    return value


def _validate_query_variable(name: str, raw: str) -> str:
    value = _validate_variable_common(name, raw, "query")
    if any(c not in _QUERY_VALUE_CHARS for c in value):
        raise RequestBuildError("invalid_variable", "query variable contains a control character", name=name)
    return value


def _join_url(base_url: str, path: str) -> str:
    base = urllib.parse.urlsplit(base_url)
    rel = urllib.parse.urlsplit(path)
    base_path = base.path.rstrip("/")
    full_path = (base_path + rel.path) if base_path else rel.path
    return urllib.parse.urlunsplit((base.scheme, base.netloc, full_path, rel.query, ""))


def _build_headers(op: Operation, arguments: dict, secrets: SecretClient) -> dict[str, str]:
    raw = arguments.get("headers", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise RequestBuildError("invalid_headers", "headers must be an object")
    headers: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not _HEADER_NAME.match(name):
            raise RequestBuildError("invalid_header", "header name is invalid", name=str(name))
        if name.lower() not in op.allowed_headers:
            raise RequestBuildError("header_not_allowed", "header is not allowed for this operation", name=name)
        if not isinstance(value, str):
            raise RequestBuildError("invalid_header", "header value must be a string", name=name)
        substituted = _substitute_secrets(value, secrets)
        if any(ord(c) < 0x20 or ord(c) == 0x7f for c in substituted):
            raise RequestBuildError("invalid_header", "header value contains a control character", name=name)
        headers[name] = substituted
    return headers


def _build_body(op: Operation, arguments: dict, secrets: SecretClient, max_body: int) -> bytes | None:
    present = "body" in arguments
    body = arguments.get("body")
    if op.body_kind == "none":
        if present:
            raise RequestBuildError("body_not_allowed", "this operation does not accept a body")
        return None
    if not isinstance(body, str):
        raise RequestBuildError("missing_body", "this operation requires body as a string")
    if op.body_kind == "text":
        if op.body_substitution:
            body = _substitute_secrets(body, secrets)
        data = body.encode("utf-8")
    else:
        try:
            data = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            raise RequestBuildError("invalid_body", "binary body must be base64")
    if len(data) > max_body:
        raise RequestBuildError("body_too_large", "body exceeds configured limit", limit_bytes=max_body)
    return data


def _substitute_secrets(text: str, secrets: SecretClient) -> str:
    def fill(match: re.Match[str]) -> str:
        return read_secret(secrets, match.group(1))

    out = _SECRET_REF.sub(fill, text)
    if "{{secret:" in out:
        raise RequestBuildError("invalid_secret_ref", "secret reference must be {{secret:NAME}}")
    return out
