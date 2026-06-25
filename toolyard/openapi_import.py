"""Generate a Toolstack ``rest`` tool (a ``toolyard.toml``) from an OpenAPI / Swagger spec.

Each path + method in the spec becomes a NAMED rest op: ``name`` = the operationId, ``verb`` =
the method, ``path`` = the spec's path template. OpenAPI already spells path parameters as
``{name}``, which is exactly the syntax the broker fills (broker/runtime.resolve_rest_path), so a
spec maps onto named ops with no translation. Point this at a documented API and you get a
policy-gated tool whose ops are named, scoped, and ready to grant by name, with the generic
proxy (toolyard.http_proxy) injecting the credential and pinning every route to the base URL.

    python3 -m toolyard.openapi_import graph-openapi.json --id graph --port 4640 > graph/toolyard.toml

The auth block is scaffolded from the spec's security scheme (bearer / apiKey / oauth2) with a
placeholder secret you wire to your backend; everything else is derived. Stdlib only (the stdlib
has no TOML *writer*, so the document is emitted by hand).
"""

from __future__ import annotations

import argparse
import json
import re
import sys

_HTTP_METHODS = ("get", "post", "put", "patch", "delete")
_NON_NAME = re.compile(r"[^A-Za-z0-9_]+")


def _q(s: object) -> str:
    """A TOML basic string with the needed escapes."""
    text = str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ")
    return f'"{text}"'


def _inline(d: dict) -> str:
    """A TOML inline table ``{ k = v, ... }`` for the small flat dicts we emit (args, inject)."""
    parts = []
    for k, v in d.items():
        if isinstance(v, bool):
            parts.append(f"{k} = {str(v).lower()}")
        elif isinstance(v, str):
            parts.append(f"{k} = {_q(v)}")
        else:
            parts.append(f"{k} = {v}")
    return "{ " + ", ".join(parts) + " }"


def _resolve_ref(spec: dict, node):
    """Shallow single-hop ``$ref`` resolution into the spec (covers ``#/components/parameters/*``
    and ``#/parameters/*``, the common shapes). A non-ref or unresolvable ref is returned as-is."""
    if isinstance(node, dict) and isinstance(node.get("$ref"), str) and node["$ref"].startswith("#/"):
        target = spec
        for part in node["$ref"][2:].split("/"):
            target = target.get(part, {}) if isinstance(target, dict) else {}
        return target if isinstance(target, dict) else node
    return node


def op_name(method: str, path: str, operation: dict, used: set) -> str:
    """A safe, unique op name. Prefer the operationId; else synthesize from the method + path.
    Sanitised to ``[A-Za-z0-9_]`` (no dots/spaces, which would break ``tool.op`` policy routing or
    collide with the verb-glob form) and de-duplicated against ``used``."""
    raw = operation.get("operationId") or f"{method}_{path}"
    name = _NON_NAME.sub("_", raw).strip("_")
    if not name or name[0].isdigit():
        name = f"{method}_{name}".strip("_")
    base, n = name, 2
    while name in used:
        name = f"{base}_{n}"
        n += 1
    used.add(name)
    return name


def base_url(spec: dict) -> str:
    """Derive the base URL: OpenAPI 3 ``servers[0].url`` (server-variable defaults filled), else
    Swagger 2 ``scheme://host + basePath``. Empty if the spec declares neither."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url", ""))
        for var, meta in (servers[0].get("variables") or {}).items():
            url = url.replace("{" + var + "}", str((meta or {}).get("default", "")))
        if url:
            return url
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{host}{spec.get('basePath', '')}"
    return ""


def _params(spec: dict, path_item: dict, operation: dict) -> list:
    """The path + query parameters for an op, as arg descriptors (path-item-level and
    operation-level merged, ``$ref``s resolved). Header/cookie params are skipped: they aren't
    part of the route or the query passthrough."""
    out, seen = [], set()
    raw = list(path_item.get("parameters", []) or []) + list(operation.get("parameters", []) or [])
    for p in raw:
        p = _resolve_ref(spec, p)
        if not isinstance(p, dict) or "name" not in p or p.get("in") not in ("path", "query"):
            continue
        if p["name"] in seen:
            continue
        seen.add(p["name"])
        schema = _resolve_ref(spec, p.get("schema", {})) if isinstance(p.get("schema"), dict) else {}
        out.append({
            "name": str(p["name"]),
            "type": str(schema.get("type") or p.get("type") or "string"),  # swagger2 types live on the param
            "required": bool(p.get("required", p.get("in") == "path")),     # path params are always required
            "description": str(p.get("description") or "")[:200],
        })
    return out


def _auth(spec: dict):
    """Scaffold ``(inject, secrets)`` from the first usable security scheme (bearer / apiKey /
    oauth2). The secret is a placeholder the operator wires to their backend; the value is never
    in the spec. Empty lists if no scheme is declared (the proxy then injects nothing)."""
    schemes = ((spec.get("components") or {}).get("securitySchemes")
               or spec.get("securityDefinitions") or {})
    for s in schemes.values():
        s = s or {}
        kind = s.get("type")
        if kind == "http" and str(s.get("scheme", "")).lower() == "bearer":
            return ([{"into": "header", "name": "Authorization", "value": "Bearer ${secret:api_token}"}],
                    [{"name": "api_token", "field": "API_TOKEN"}])
        if kind == "oauth2":  # a token that expires: see http_proxy rotation to reup it in place
            return ([{"into": "header", "name": "Authorization", "value": "Bearer ${secret:access_token}"}],
                    [{"name": "access_token", "field": "ACCESS_TOKEN"}])
        if kind == "apiKey" and s.get("in") in ("header", "query"):
            return ([{"into": s["in"], "name": str(s.get("name", "X-API-Key")), "value": "${secret:api_key}"}],
                    [{"name": "api_key", "field": "API_KEY"}])
    return ([], [])


def build_operations(spec: dict) -> list:
    """Every path+method in the spec as a named-op descriptor (name, verb, path, description, args).
    Deterministic order (sorted by path then method) for stable output."""
    used: set = set()
    ops = []
    for path in sorted((spec.get("paths") or {}).keys()):
        path_item = spec["paths"][path] or {}
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            ops.append({
                "name": op_name(method, path, operation, used),
                "verb": method.upper(),
                "path": path,
                "description": str(operation.get("summary") or operation.get("description") or "")[:200],
                "args": _params(spec, path_item, operation),
            })
    return ops


def parse_spec(spec: dict) -> dict:
    """Parse a spec into the pieces a UI needs to offer a SELECTABLE import: the base_url, the
    auth inject + secret scaffold, and the full operation list. The caller (the admin panel) lets
    the operator pick a subset of `operations` rather than importing the whole spec."""
    inject, secrets = _auth(spec)
    return {
        "base_url": base_url(spec),
        "inject": inject,
        "secrets": secrets,
        "operations": build_operations(spec),
    }


def build_toolyard_toml(spec: dict, *, tool_id: str, port: int) -> str:
    """Render a complete ``toolyard.toml`` for a rest tool fronting this spec through the proxy."""
    inject, secrets = _auth(spec)
    ops = build_operations(spec)
    base = base_url(spec)
    info = spec.get("info") or {}
    desc = str(info.get("title") or tool_id) + (f" - {info.get('version')}" if info.get("version") else "")

    lines = [
        f"# Generated from an OpenAPI spec by toolyard.openapi_import. Each operation is a NAMED",
        f"# rest op (the broker fills its path template); grant them by name in policy.",
        f"id = {_q(tool_id)}",
        'type = "rest"',
        f"description = {_q(desc)}",
        "",
        "[entrypoint]",
        'command = "python3 -m toolyard.http_proxy"   # the bundled proxy; you write no tool code',
        f"port = {port}",
        "",
        "[proxy]",
        f"base_url = {_q(base)}" if base else '# base_url = "https://api.example.com"   # spec had no server; set this',
    ]
    if inject:
        lines.append("inject = [")
        lines += [f"    {_inline(i)}," for i in inject]
        lines.append("]")
    else:
        lines.append("# inject = [ { into = \"header\", name = \"Authorization\", value = \"Bearer ${secret:token}\" } ]")
    lines.append("")

    for o in ops:
        lines.append("[[operations]]")
        lines.append(f"name = {_q(o['name'])}")
        lines.append(f"verb = {_q(o['verb'])}")
        lines.append(f"path = {_q(o['path'])}")
        if o["description"]:
            lines.append(f"description = {_q(o['description'])}")
        if o["args"]:
            lines.append("args = [")
            lines += [f"    {_inline(a)}," for a in o["args"]]
            lines.append("]")
        lines.append("")

    for s in secrets:
        lines.append("[[secrets]]")
        lines.append(f"name = {_q(s['name'])}")
        lines.append(f"field = {_q(s['field'])}   # resolved from YOUR backend into the proxy, never the broker")
        lines.append("")
    if not secrets:
        lines.append("# [[secrets]]  # add the credential the proxy should inject (see [proxy] inject)")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="toolyard.openapi_import",
                                     description="Generate a Toolstack rest tool from an OpenAPI/Swagger spec.")
    parser.add_argument("spec", help="path to the OpenAPI / Swagger JSON spec")
    parser.add_argument("--id", required=True, help="tool id (letters, digits, _ or -, no dots)")
    parser.add_argument("--port", type=int, required=True, help="loopback port for the proxy")
    parser.add_argument("-o", "--out", help="write here instead of stdout")
    args = parser.parse_args(argv)

    with open(args.spec, "rb") as fh:
        spec = json.load(fh)
    if not isinstance(spec, dict):
        print("openapi_import: the spec must be a JSON object", file=sys.stderr)
        return 2
    toml_text = build_toolyard_toml(spec, tool_id=args.id, port=args.port)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(toml_text)
    else:
        sys.stdout.write(toml_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
