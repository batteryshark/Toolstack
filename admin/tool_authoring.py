"""Author and edit a tool's ``toolyard.toml`` from the panel.

Per the chosen scope this writes the **manifest only**: the operator supplies the
tool's code (a process ``command`` / ``app.py``) or a Docker ``image``. The form
sends a normalized tool definition (assembled by the editor's JS into one JSON
field, so there is no hand-typed TOML and no quoting risk); this module validates
it, serializes idiomatic TOML, and reads it back for editing.

Secret **declarations** (name + backend field) are authored here; secret **values**
are not; those stay in the on-disk secrets file, off the control plane.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

# The risk taxonomy: read / write / destructive. (One vocabulary, no low/medium/high.)
RISK_CHOICES = ("read", "write", "destructive")
RISKS = RISK_CHOICES
ARG_TYPES = ("string", "number", "integer", "boolean", "object", "array")
# Tool transports the panel can author. "api" POSTs /v1/actions/<op>; "mcp" is a
# streamable-HTTP MCP server the broker calls via tools/call; "rest" is backed by
# the generic toolstack_forwarder process.
TOOL_TYPES = ("api", "mcp", "rest")
REST_VERBS = ("GET", "POST", "PUT", "PATCH", "DELETE")
REST_VERB_RISK = {
    "GET": "read",
    "POST": "write",
    "PUT": "write",
    "PATCH": "write",
    "DELETE": "destructive",
}
REST_BODY_KINDS = ("none", "text", "binary")
RULE_RESPONSE_TYPES = ("json", "xml", "form", "plaintext")
FORWARDER_COMMAND = "python3 -m toolstack_forwarder"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")   # no dots (tool.op routing) or slashes
_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")             # operation / argument names
_SECRET_RE = re.compile(r"^[A-Za-z0-9_.-]+$")         # also used as a filename
_ITEM_RE = re.compile(r"^[A-Za-z0-9_./-]+$")          # Infisical secret path (may have /)
_HEADER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_TEMPLATE_VAR = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def from_json(raw: str) -> dict:
    """Parse the editor's hidden JSON field into a normalized tool dict."""
    return normalize(json.loads(raw))


def normalize(data: dict) -> dict:
    """Coerce a raw tool dict to clean types and drop blank rows, so validation and
    serialization can assume a tidy shape."""
    def s(x) -> str:
        return str(x if x is not None else "").strip()

    tool_id = s(data.get("id"))
    tool_type = s(data.get("type")) or "api"
    operations = []
    for o in data.get("operations") or []:
        name = s(o.get("name"))
        if not name:
            continue
        if tool_type == "rest":
            verb = s(o.get("verb")).upper() or "GET"
            body_kind = s(o.get("body_kind")) or ("none" if verb in {"GET", "DELETE"} else "text")
            allowed_headers = [s(h) for h in (o.get("allowed_headers") or []) if s(h)]
            path_template = s(o.get("path"))
            operations.append({
                "name": name,
                "risk": REST_VERB_RISK.get(verb, "write"),
                "description": s(o.get("description")),
                "verb": verb,
                "path": path_template,
                "allowed_headers": allowed_headers,
                "body_kind": body_kind,
                "body_content_type": s(o.get("body_content_type")),
                "body_substitution": bool(o.get("body_substitution", body_kind == "text")),
                "redact_response_body": bool(o.get("redact_response_body")),
                "redact_response_headers": bool(o.get("redact_response_headers")),
                "secret_update_rules": _norm_secret_update_rules(o.get("secret_update_rules")),
                "args": _rest_envelope_args(path_template, allowed_headers, body_kind),
            })
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
            "risk": s(o.get("risk")) or "read",
            "description": s(o.get("description")),
            "args": args,
        })

    secrets = []
    for sec in data.get("secrets") or []:
        nm = s(sec.get("name"))
        if not nm:
            continue
        # item is the Infisical secret path (blank -> tool id). Ignored by the file backend.
        secrets.append({
            "name": nm,
            "field": s(sec.get("field")),
            "item": s(sec.get("item")),
            "writable": bool(sec.get("writable")),
        })
    try:
        port = int(data.get("port"))
    except (TypeError, ValueError):
        port = None  # flagged by validate

    command = s(data.get("command"))
    if tool_type == "rest" and not command:
        command = FORWARDER_COMMAND

    return {
        "id": tool_id,
        "type": tool_type,
        "description": s(data.get("description")),
        "base_url": s(data.get("base_url")),
        "command": command,
        "image": s(data.get("image")),
        "port": port,
        "operations": operations,
        "secrets": secrets,
    }


def _norm_args(raw) -> list[dict]:
    def s(x) -> str:
        return str(x if x is not None else "").strip()

    args = []
    for a in raw or []:
        an = s(a.get("name"))
        if not an:
            continue
        args.append({
            "name": an,
            "type": s(a.get("type")) or "string",
            "required": bool(a.get("required")),
            "description": s(a.get("description")),
        })
    return args


def _norm_secret_update_rules(raw) -> list[dict]:
    def s(x) -> str:
        return str(x if x is not None else "").strip()

    rules = []
    for r in raw or []:
        name = s(r.get("secret_name"))
        if not name:
            continue
        rules.append({
            "secret_name": name,
            "response_type": s(r.get("response_type")) or "json",
            "extract_path": s(r.get("extract_path")),
            "match_status": s(r.get("match_status")) or "2xx",
        })
    return rules


def _rest_envelope_args(path_template: str, allowed_headers: list[str], body_kind: str) -> list[dict]:
    variables = sorted(set(_TEMPLATE_VAR.findall(path_template or "")))
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


def validate(data: dict) -> list[str]:
    """Return a list of human-readable problems (empty == valid). Uniqueness of the
    id across other tools is the caller's job (it needs the registry)."""
    errors: list[str] = []
    if not _ID_RE.match(data["id"]):
        errors.append("id must start alphanumeric and contain only letters, digits, _ or - (no dots)")
    elif len(data["id"]) > 64:
        # the id is used as a directory name (tools_root/<id>); keep it well under filesystem limits
        errors.append("id must be at most 64 characters")
    if data["type"] not in TOOL_TYPES:
        errors.append(f'type must be one of {", ".join(TOOL_TYPES)}')
    if data["type"] == "rest":
        base_url = data.get("base_url", "")
        split = urlsplit(base_url)
        if split.scheme not in ("http", "https") or not split.hostname:
            errors.append("rest base_url must be an absolute http(s) URL with a host")
        elif split.username is not None or split.password is not None:
            errors.append("rest base_url must not embed credentials")
        elif split.query or split.fragment:
            errors.append("rest base_url must not include a query or fragment")
    # An entrypoint may be a process command, a docker image, or neither: a docker tool
    # that builds the Dockerfile in its own directory. Since that last case depends on the
    # directory (which validate can't see), write() enforces the "must have *some*
    # entrypoint" rule where it has the path.
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
        if data["type"] == "rest":
            verb = o.get("verb")
            if verb not in REST_VERBS:
                errors.append(f"rest operation '{o['name']}' verb must be one of {', '.join(REST_VERBS)}")
            path_template = o.get("path")
            path_part = path_template.partition("?")[0] if isinstance(path_template, str) else path_template
            if not isinstance(path_template, str) or not path_part.startswith("/") or path_part.startswith("//"):
                errors.append(f"rest operation '{o['name']}' path must start with a single '/'")
            elif "#" in path_template:
                errors.append(f"rest operation '{o['name']}' path must not include fragment text")
            elif any(not (0x21 <= ord(c) <= 0x7e) for c in path_template):
                errors.append(f"rest operation '{o['name']}' path must be printable ASCII without spaces")
            if o.get("body_kind") not in REST_BODY_KINDS:
                errors.append(f"rest operation '{o['name']}' body_kind must be one of {', '.join(REST_BODY_KINDS)}")
            for h in o.get("allowed_headers", []):
                if not _HEADER_RE.match(h):
                    errors.append(f"rest operation '{o['name']}' allowed header '{h}' has invalid characters")
        for a in o["args"]:
            if not _NAME_RE.match(a["name"]):
                errors.append(f"argument '{a['name']}' in '{o['name']}' may contain only letters, digits and _")
    writable = {sec["name"] for sec in data["secrets"] if sec.get("writable")}
    for sec in data["secrets"]:
        if not _SECRET_RE.match(sec["name"]):
            errors.append(f"secret name '{sec['name']}' has invalid characters")
        if not sec["field"]:
            errors.append(f"secret '{sec['name']}' needs a backend field")
        if sec.get("item") and not _ITEM_RE.match(sec["item"]):
            errors.append(f"secret '{sec['name']}' path has invalid characters")
    if data["type"] == "rest":
        for o in data["operations"]:
            for rule in o.get("secret_update_rules", []):
                if rule.get("secret_name") not in writable:
                    errors.append(
                        f"rest operation '{o['name']}' secret_update_rule targets non-writable "
                        f"secret '{rule.get('secret_name')}'"
                    )
                if rule.get("response_type") not in RULE_RESPONSE_TYPES:
                    errors.append(
                        f"rest operation '{o['name']}' secret_update_rule response_type must be one of "
                        f"{', '.join(RULE_RESPONSE_TYPES)}"
                    )
                if not rule.get("extract_path"):
                    errors.append(f"rest operation '{o['name']}' secret_update_rule needs an extract_path")
                if not rule.get("match_status"):
                    errors.append(f"rest operation '{o['name']}' secret_update_rule needs a match_status")
    return errors


def _s(value) -> str:
    # TOML basic strings can't contain a literal newline/tab; escape control chars too so a
    # multi-line description (or op description) round-trips instead of producing broken TOML.
    text = (str(value).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))
    return '"' + text + '"'


def _arg_inline(arg: dict) -> str:
    parts = [f"name = {_s(arg['name'])}",
             f"type = {_s(arg.get('type', 'string'))}",
             f"required = {str(bool(arg.get('required'))).lower()}"]
    if arg.get("description"):
        parts.append(f"description = {_s(arg['description'])}")
    return "{ " + ", ".join(parts) + " }"


def _rule_inline(rule: dict) -> str:
    parts = [
        f"secret_name = {_s(rule['secret_name'])}",
        f"response_type = {_s(rule.get('response_type', 'json'))}",
        f"extract_path = {_s(rule.get('extract_path', ''))}",
        f"match_status = {_s(rule.get('match_status', '2xx'))}",
    ]
    return "{ " + ", ".join(parts) + " }"


def entrypoint_error(data: dict, dir_path: str | Path, runner: str | None = None) -> str | None:
    """Whether the tool has a usable entrypoint for the active toolyard runner: the one
    validity rule that depends on the directory (and on which runner will start the tool).
    Returns an error string or None.

    - **docker** runner: it ignores ``command`` and runs an ``image`` or builds the
      directory's ``Dockerfile``. A command-only tool builds nothing and 502s on first
      start, so require an ``image`` or a ``Dockerfile``.
    - **process** runner: it needs a ``command``.

    ``runner`` defaults to the deployment's active runner (``settings.tool_runner_backend``),
    so a save in a docker deployment is checked against docker. Kept out of :func:`validate`
    (which is pure) so ``write`` and the add-from-source flows apply it where they have the
    directory."""
    if data["type"] == "rest":
        # REST tools run the bundled generic forwarder. The docker runner has a stock-python
        # fallback for it, so there may be no tool-owned image or Dockerfile.
        return None
    if runner is None:
        from . import settings
        runner = settings.tool_runner_backend()
    if runner == "docker":
        if not data["image"] and not (Path(dir_path) / "Dockerfile").exists():
            return ("the docker runner needs an image or a Dockerfile in the tool directory "
                    "(a process command alone won't run under docker)")
    elif not data["command"]:
        return "the process runner needs an entrypoint command"
    return None


def to_toml(data: dict) -> str:
    """Serialize a normalized tool dict to idiomatic toolyard.toml."""
    out = [f"id = {_s(data['id'])}", f"type = {_s(data['type'])}"]
    if data.get("description"):
        out.append(f"description = {_s(data['description'])}")
    if data["type"] == "rest":
        out.append(f"base_url = {_s(data.get('base_url', ''))}")
    out += ["", "[entrypoint]"]
    if data["command"]:
        out.append(f"command = {_s(data['command'])}")
    if data["image"]:
        out.append(f"image = {_s(data['image'])}")
    out.append(f"port = {data['port']}")
    for o in data["operations"]:
        out += ["", "[[operations]]", f"name = {_s(o['name'])}"]
        if data["type"] == "rest":
            out.append(f"verb = {_s(o['verb'])}")
            out.append(f"path = {_s(o['path'])}")
        out.append(f"risk = {_s(o['risk'])}")
        if o["description"]:
            out.append(f"description = {_s(o['description'])}")
        if o["args"]:
            out.append("args = [ " + ", ".join(_arg_inline(a) for a in o["args"]) + " ]")
        if data["type"] == "rest":
            if o.get("allowed_headers"):
                out.append("allowed_headers = [ " + ", ".join(_s(h) for h in o["allowed_headers"]) + " ]")
            out.append(f"body_kind = {_s(o.get('body_kind', 'none'))}")
            if o.get("body_content_type"):
                out.append(f"body_content_type = {_s(o['body_content_type'])}")
            if bool(o.get("body_substitution", o.get("body_kind") == "text")) != (o.get("body_kind") == "text"):
                out.append(f"body_substitution = {str(bool(o.get('body_substitution'))).lower()}")
            if o.get("redact_response_body"):
                out.append("redact_response_body = true")
            if o.get("redact_response_headers"):
                out.append("redact_response_headers = true")
            if o.get("secret_update_rules"):
                out.append("secret_update_rules = [ " + ", ".join(
                    _rule_inline(r) for r in o["secret_update_rules"]) + " ]")
    for sec in data["secrets"]:
        out += ["", "[[secrets]]", f"name = {_s(sec['name'])}", f"field = {_s(sec['field'])}"]
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
        "type": data.get("type", "api"),
        "description": data.get("description", ""),
        "base_url": data.get("base_url", ""),
        "command": entry.get("command", ""),
        "image": entry.get("image", ""),
        "port": entry.get("port"),
        "operations": data.get("operations", []),
        "secrets": data.get("secrets", []),
    })


def write(dir_path: str | Path, data: dict, runner: str | None = None) -> Path:
    """Validate and write ``<dir_path>/toolyard.toml``. Raises ValueError on invalid
    input, a missing directory, or an entrypoint the ``runner`` can't start; only ever
    writes a file named toolyard.toml. ``runner`` defaults to the deployment's runner."""
    errors = validate(data)
    if errors:
        raise ValueError("; ".join(errors))
    path = Path(dir_path)
    if not path.is_dir():
        raise ValueError(f"not an existing directory: {dir_path}")
    ep_err = entrypoint_error(data, path, runner)
    if ep_err:
        raise ValueError(ep_err)
    target = path / "toolyard.toml"
    target.write_text(to_toml(data), encoding="utf-8")
    return target
