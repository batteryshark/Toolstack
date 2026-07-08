"""Generate a Toolstack ``rest`` tool from an OpenAPI / Swagger spec.

The importer emits the current REST forwarder contract: top-level ``base_url``,
``type = "rest"``, ``python3 -m toolstack_forwarder``, and named operations with
``verb`` / ``path``. It intentionally does not generate a bespoke proxy.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit

_HTTP_METHODS = ("get", "post", "put", "patch", "delete")
_NON_NAME = re.compile(r"[^A-Za-z0-9_]+")
_TEMPLATE_VAR = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_VERB_RISK = {"GET": "read", "POST": "write", "PUT": "write", "PATCH": "write", "DELETE": "destructive"}


def _q(value: object) -> str:
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return f'"{text}"'


def _inline(d: dict) -> str:
    parts = []
    for key, value in d.items():
        if isinstance(value, bool):
            parts.append(f"{key} = {str(value).lower()}")
        elif isinstance(value, str):
            parts.append(f"{key} = {_q(value)}")
        else:
            parts.append(f"{key} = {value}")
    return "{ " + ", ".join(parts) + " }"


def _resolve_ref(spec: dict, node):
    if isinstance(node, dict) and isinstance(node.get("$ref"), str) and node["$ref"].startswith("#/"):
        target = spec
        for part in node["$ref"][2:].split("/"):
            target = target.get(part, {}) if isinstance(target, dict) else {}
        return target if isinstance(target, dict) else node
    return node


def op_name(method: str, path: str, operation: dict, used: set) -> str:
    raw = operation.get("operationId") or f"{method}_{path}"
    name = _NON_NAME.sub("_", str(raw)).strip("_")
    if not name or name[0].isdigit():
        name = f"{method}_{name}".strip("_")
    base, n = name, 2
    while name in used:
        name = f"{base}_{n}"
        n += 1
    used.add(name)
    return name


def base_url(spec: dict) -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url", ""))
        for var, meta in (servers[0].get("variables") or {}).items():
            url = url.replace("{" + var + "}", str((meta or {}).get("default", "")))
        if url:
            return _strip_query_fragment(url)
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        return _strip_query_fragment(f"{scheme}://{host}{spec.get('basePath', '')}")
    return ""


def _strip_query_fragment(url: str) -> str:
    split = urlsplit(url)
    return urlunsplit((split.scheme, split.netloc, split.path.rstrip("/"), "", ""))


def _path_params(spec: dict, path_item: dict, operation: dict) -> list[dict]:
    raw = list(path_item.get("parameters", []) or []) + list(operation.get("parameters", []) or [])
    out, seen = [], set()
    for param in raw:
        param = _resolve_ref(spec, param)
        if not isinstance(param, dict) or param.get("in") != "path" or "name" not in param:
            continue
        name = str(param["name"])
        if name in seen:
            continue
        seen.add(name)
        schema = _resolve_ref(spec, param.get("schema", {})) if isinstance(param.get("schema"), dict) else {}
        out.append({
            "name": name,
            "type": str(schema.get("type") or param.get("type") or "string"),
            "required": True,
            "description": str(param.get("description") or "")[:200],
        })
    return out


def _auth(spec: dict) -> tuple[list[dict], list[dict]]:
    """Return (header_templates, secret_declarations) for usable header auth schemes."""
    schemes = ((spec.get("components") or {}).get("securitySchemes")
               or spec.get("securityDefinitions") or {})
    for scheme in schemes.values():
        scheme = scheme or {}
        kind = scheme.get("type")
        if kind == "http" and str(scheme.get("scheme", "")).lower() == "bearer":
            return ([{"name": "Authorization", "value": "Bearer {{secret:api_token}}"}],
                    [{"name": "api_token", "field": "API_TOKEN"}])
        if kind == "oauth2":
            return ([{"name": "Authorization", "value": "Bearer {{secret:access_token}}"}],
                    [{"name": "access_token", "field": "ACCESS_TOKEN"}])
        if kind == "apiKey" and scheme.get("in") == "header":
            header = str(scheme.get("name", "X-API-Key"))
            return ([{"name": header, "value": "{{secret:api_key}}"}],
                    [{"name": "api_key", "field": "API_KEY"}])
    return ([], [])


def _body(operation: dict, method: str) -> tuple[str, str]:
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return ("none", "")
    content = request_body.get("content")
    if not isinstance(content, dict) or not content:
        return ("text", "text/plain")
    if "application/json" in content:
        return ("text", "application/json")
    if "application/octet-stream" in content:
        return ("binary", "application/octet-stream")
    content_type = next(iter(content.keys()))
    return ("text", str(content_type))


def _rest_args(path: str, allowed_headers: list[str], body_kind: str) -> list[dict]:
    variables = sorted(set(_TEMPLATE_VAR.findall(path)))
    args = []
    if variables:
        args.append({
            "name": "variables",
            "type": "object",
            "required": True,
            "description": "Path variables: " + ", ".join(variables),
        })
    if allowed_headers:
        args.append({
            "name": "headers",
            "type": "object",
            "required": False,
            "description": "Allowed headers: " + ", ".join(allowed_headers),
        })
    if body_kind != "none":
        args.append({
            "name": "body",
            "type": "string",
            "required": True,
            "description": "UTF-8 body" if body_kind == "text" else "base64 body",
        })
    return args


def build_operations(spec: dict) -> list[dict]:
    header_templates, _ = _auth(spec)
    allowed_headers = [h["name"] for h in header_templates]
    used: set = set()
    ops = []
    for path in sorted((spec.get("paths") or {}).keys()):
        path_item = spec["paths"][path] or {}
        if not isinstance(path_item, dict):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            verb = method.upper()
            body_kind, body_content_type = _body(operation, method)
            ops.append({
                "name": op_name(method, path, operation, used),
                "verb": verb,
                "path": path,
                "risk": _VERB_RISK[verb],
                "description": str(operation.get("summary") or operation.get("description") or "")[:200],
                "allowed_headers": allowed_headers,
                "body_kind": body_kind,
                "body_content_type": body_content_type,
                "args": _rest_args(path, allowed_headers, body_kind),
                "path_params": _path_params(spec, path_item, operation),
            })
    return ops


def parse_spec(spec: dict) -> dict:
    header_templates, secrets = _auth(spec)
    return {
        "base_url": base_url(spec),
        "auth_headers": header_templates,
        "secrets": secrets,
        "operations": build_operations(spec),
    }


def build_toolyard_toml(spec: dict, *, tool_id: str, port: int) -> str:
    parsed = parse_spec(spec)
    info = spec.get("info") or {}
    desc = str(info.get("title") or tool_id)
    if info.get("version"):
        desc += f" - {info['version']}"

    lines = [
        "# Generated from an OpenAPI spec by toolyard.openapi_import.",
        f"id = {_q(tool_id)}",
        'type = "rest"',
        f"description = {_q(desc)}",
        f"base_url = {_q(parsed['base_url'] or 'https://api.example.com')}",
        "",
        "[entrypoint]",
        'command = "python3 -m toolstack_forwarder"',
        f"port = {port}",
        "",
    ]
    for op in parsed["operations"]:
        lines += [
            "[[operations]]",
            f"name = {_q(op['name'])}",
            f"verb = {_q(op['verb'])}",
            f"path = {_q(op['path'])}",
            f"risk = {_q(op['risk'])}",
        ]
        if op["description"]:
            lines.append(f"description = {_q(op['description'])}")
        if op["args"]:
            lines.append("args = [ " + ", ".join(_inline(a) for a in op["args"]) + " ]")
        if op["allowed_headers"]:
            lines.append("allowed_headers = [ " + ", ".join(_q(h) for h in op["allowed_headers"]) + " ]")
        lines.append(f"body_kind = {_q(op['body_kind'])}")
        if op["body_content_type"]:
            lines.append(f"body_content_type = {_q(op['body_content_type'])}")
        lines.append("")

    seen = set()
    for secret in parsed["secrets"]:
        if secret["name"] in seen:
            continue
        seen.add(secret["name"])
        lines += [
            "[[secrets]]",
            f"name = {_q(secret['name'])}",
            f"field = {_q(secret['field'])}",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="toolyard.openapi_import",
                                     description="Generate a Toolstack rest tool from an OpenAPI JSON spec.")
    parser.add_argument("spec", help="path to the OpenAPI / Swagger JSON spec")
    parser.add_argument("--id", required=True, help="tool id")
    parser.add_argument("--port", type=int, required=True, help="loopback port for the forwarder")
    parser.add_argument("-o", "--out", help="write here instead of stdout")
    args = parser.parse_args(argv)

    with open(args.spec, "rb") as fh:
        spec = json.load(fh)
    if not isinstance(spec, dict):
        print("openapi_import: the spec must be a JSON object", file=sys.stderr)
        return 2
    text = build_toolyard_toml(spec, tool_id=args.id, port=args.port)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
