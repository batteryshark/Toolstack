"""JSON operator API (under ``/api``) for native / automation clients.

The HTML panel and this API share the SAME operations (``broker.operations`` / ``supervisor`` /
``broker_config`` / the store) — this is just a JSON face with **bearer-token** auth instead of a
session cookie + CSRF. ``POST /api/login {password}`` returns the same signed-session value the
cookie uses; clients send it back as ``Authorization: Bearer <token>`` and a dependency runs
``auth.verify_session``. No CSRF is needed (a header token is not auto-sent cross-site). Loopback
only, like the rest of the admin.

Split out of ``server.create_app`` so the JSON surface stays separate from the HTML server.
Covers the full operator surface: auth, broker status/control, callers/policies/tokens, tools
(add/author/update + secret declarations), secret values, and the request + audit log.
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, HTTPException, Request

from broker import operations
from broker.registry import Registry

from . import (auth, broker_config, secret_values, settings, supervisor,
               tool_authoring, tool_sources, toolyard_ops)
from .store_access import open_store

# broker lifecycle action -> the admin.* audit event it records (shared with the HTML handler)
_BROKER_EVENTS = {"start": "broker_started", "stop": "broker_stopped", "restart": "broker_restarted"}


log = logging.getLogger(__name__)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def audit_login_failure(ip: str, username: str) -> None:
    """Record a denied ``admin.login_failed`` audit event — IP + attempted username, NEVER the
    submitted password. Best-effort (auditing must not change the login response); the login
    throttle bounds how many of these an attacker can drive. Shared by /login and /api/login."""
    try:
        with open_store(broker_config.load()) as store:
            # Cap the attacker-controlled username: the login surface is unauthenticated and the
            # request body is uncapped, so an unbounded username would be a disk-write amplifier.
            operations.record_admin_denied(store, "login_failed",
                                           {"ip": ip, "username": username[:256]})
    except Exception as exc:
        log.warning("could not audit login failure from %s: %s", ip, exc)


def _rows(rows) -> list[dict]:
    """sqlite3.Row list -> JSON-serializable dicts."""
    return [dict(r) for r in rows]


def _str_list(value, field: str) -> list[str]:
    """Coerce a JSON field to a list[str], or 400. None -> []."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise HTTPException(status_code=400, detail=f"{field} must be a list of strings")
    return value


async def _json_object(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="expected a JSON object body")
    return body


def add_api_routes(app: FastAPI, secret: str, guard) -> None:
    """Register the ``/api/*`` JSON routes on the admin app. ``secret`` is the session-signing
    secret (same one the cookie uses), so a token minted here is interchangeable with the panel's.
    ``guard`` is the shared :class:`loginguard.LoginGuard` so /api/login and /login throttle as one."""

    def require_user(request: Request) -> str:
        authz = request.headers.get("authorization", "")
        token = authz[7:].strip() if authz[:7].lower() == "bearer " else ""
        user = auth.verify_session(token, secret)
        if not user:
            raise HTTPException(status_code=401, detail="unauthorized")
        return user

    @app.post("/api/login")
    async def api_login(request: Request):
        ip = client_ip(request)
        wait = guard.retry_after(ip)
        if wait > 0:  # locked out — reject before checking the password
            raise HTTPException(status_code=429, detail="too many failed attempts",
                                headers={"Retry-After": str(int(wait) + 1)})
        data = await _json_object(request)
        username = data.get("username") or settings.admin_username()
        password = data.get("password", "")
        stored = settings.read_password_hash()
        if username != settings.admin_username() or not stored or not auth.verify_password(password, stored):
            guard.record_failure(ip)
            audit_login_failure(ip, username)
            # same fail-closed message for bad user OR bad password — don't reveal which
            raise HTTPException(status_code=401, detail="invalid credentials")
        guard.record_success(ip)
        token = auth.sign_session(username, secret, settings.session_ttl_seconds())
        return {"token": token, "username": username}

    @app.get("/api/broker")
    async def api_broker_status(user: str = Depends(require_user)):
        return supervisor.status()

    @app.post("/api/broker/{action}")
    async def api_broker_action(action: str, user: str = Depends(require_user)):
        if action not in _BROKER_EVENTS:
            raise HTTPException(status_code=400, detail=f"unknown broker action: {action}")
        config = broker_config.load()
        try:
            result = supervisor.stop() if action == "stop" else getattr(supervisor, action)(config)
        except Exception as exc:  # a failed spawn is a 502, not a 500
            raise HTTPException(status_code=502, detail=f"broker {action} failed: {exc}")
        with open_store(config) as store:
            operations.record_admin_event(store, user, _BROKER_EVENTS[action], {})
        if isinstance(result, dict) and result.get("error"):  # started but never went healthy
            raise HTTPException(status_code=502, detail=f"broker {action}: {result['error']}")
        return supervisor.status()

    # --- callers / policy / tokens -------------------------------------------
    @app.get("/api/callers")
    async def api_callers(user: str = Depends(require_user)):
        with open_store(broker_config.load()) as store:
            return {"callers": _rows(store.list_callers(include_revoked=True)),
                    "tokens": _rows(store.list_tokens(include_revoked=False))}

    @app.post("/api/callers")
    async def api_create_caller(request: Request, user: str = Depends(require_user)):
        data = await _json_object(request)
        name = (data.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        allow, review = _str_list(data.get("allow"), "allow"), _str_list(data.get("review"), "review")
        with open_store(broker_config.load()) as store:
            if store.caller_by_name(name) is not None:
                raise HTTPException(status_code=409, detail=f"caller already exists: {name}")
            token = operations.create_caller(store, name, allow, review, user)
        return {"name": name, "token": token}  # token shown once

    @app.post("/api/callers/{name}/revoke")
    async def api_revoke_caller(name: str, user: str = Depends(require_user)):
        config = broker_config.load()
        with open_store(config) as store:
            try:
                # surface=build_surface() so cancelled approval cards are also withdrawn from
                # nod, matching the HTML panel (store-marking is the disarm guarantee regardless).
                cancelled = operations.revoke_caller(store, name, user, surface=config.build_surface())
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
        return {"name": name, "cancelled_approvals": cancelled}

    @app.post("/api/callers/{name}/rotate-token")
    async def api_rotate_token(name: str, user: str = Depends(require_user)):
        with open_store(broker_config.load()) as store:
            try:
                token = operations.rotate_token(store, name, user)
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
        return {"name": name, "token": token}  # the caller's single active token, shown once

    @app.post("/api/tokens/revoke")
    async def api_revoke_token(request: Request, user: str = Depends(require_user)):
        data = await _json_object(request)
        prefix = (data.get("prefix") or "").strip()
        if not prefix:
            raise HTTPException(status_code=400, detail="prefix is required (an empty prefix is refused)")
        config = broker_config.load()
        with open_store(config) as store:
            revoked = operations.revoke_token(store, prefix, user, surface=config.build_surface())
        return {"prefix": prefix, "revoked": revoked}

    @app.get("/api/callers/{name}/policy")
    async def api_get_policy(name: str, user: str = Depends(require_user)):
        with open_store(broker_config.load()) as store:
            try:
                caller = operations.require_caller(store, name)
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            policy = store.policy_for(caller["id"])
        return {"name": name, "policy": policy, "enabled": operations.enabled_tools(policy)}

    @app.put("/api/callers/{name}/policy")
    async def api_set_policy(name: str, request: Request, user: str = Depends(require_user)):
        data = await _json_object(request)
        allow, review = _str_list(data.get("allow"), "allow"), _str_list(data.get("review"), "review")
        deny = _str_list(data.get("deny"), "deny")
        # A path-aware client (the macapp policy editor) renders + manages rest path rules and
        # sends the full picture, so it may intentionally drop rules; it declares itself with
        # this flag. A path-blind client that omits it is refused if it would flatten path rules.
        manages_path = bool(data.get("manages_path_rules"))
        with open_store(broker_config.load()) as store:
            try:
                if not manages_path:
                    dropped = operations.coarse_update_drops_scope(store, name, allow, review, deny)
                    if dropped:
                        raise HTTPException(
                            status_code=409,
                            detail="caller has path-scoped rules this client can't manage; edit "
                                   "them with a path-aware client or brokerctl. Would drop: "
                                   + ", ".join(sorted(dropped)))
                operations.set_policy(store, name, allow, review, user, deny=deny)
                policy = store.policy_for(operations.require_caller(store, name)["id"])
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
        return {"name": name, "policy": policy, "enabled": operations.enabled_tools(policy)}

    @app.put("/api/callers/{name}/tools")
    async def api_set_enabled_tools(name: str, request: Request, user: str = Depends(require_user)):
        data = await _json_object(request)
        enabled = _str_list(data.get("enabled"), "enabled")
        with open_store(broker_config.load()) as store:
            try:
                operations.set_enabled_tools(store, name, enabled, user)
            except LookupError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
        return {"name": name, "enabled": enabled}

    # --- observe / discover ---------------------------------------------------
    @app.get("/api/audit")
    async def api_audit(user: str = Depends(require_user), limit: int = 50):
        limit = max(1, min(limit, 500))
        with open_store(broker_config.load()) as store:
            return {"audit": store.recent_audit(limit=limit),
                    "requests": _rows(store.list_requests(limit=limit))}

    @app.get("/api/tools")
    async def api_tools(user: str = Depends(require_user)):
        config = broker_config.load()
        try:
            tools = toolyard_ops.list_tools(config.tools_root, config.tool_dirs)
        except Exception as exc:  # a single bad toolyard.toml -> an error field, not a 500
            return {"tools": [], "error": f"could not read tools: {exc}"}
        # attach each tool's ops (op/risk/description) so a client can build a policy editor
        ops_by_tool: dict[str, list] = {}
        try:
            for op in Registry.from_sources(config.tools_root, config.tool_dirs).list_ops():
                ops_by_tool.setdefault(op["tool"], []).append(
                    {"op": op["op"], "risk": op["risk"], "description": op["description"]})
        except Exception as exc:
            log.warning("could not read tool ops for the policy editor: %s", exc)
            # tools still listed (without ops) if the registry can't be read
        # attach each tool's secret DECLARATIONS (name/field/writable/vault/item) for display.
        # The broker registry ignores [[secrets]], but the admin (control plane) may show them —
        # these are declarations, never values.
        try:
            defs = toolyard_ops._all_defs(config.tools_root, config.tool_dirs)
        except Exception as exc:
            log.warning("could not read tool secret declarations: %s", exc)
            defs = {}
        for tool in tools:
            tool["ops"] = ops_by_tool.get(tool["id"], [])
            td = defs.get(tool["id"])
            tool["description"] = td.description if td else ""
            tool["secrets"] = [
                {"name": s.name, "field": s.field, "writable": s.writable, "vault": s.vault, "item": s.item}
                for s in (td.secrets if td else ())
            ]
            tool["source"] = tool_sources.read_source(tool["path"])  # sidecar (path/github) or null
        return {"tools": tools}

    @app.post("/api/tools")
    async def api_add_tool(request: Request, user: str = Depends(require_user)):
        """Add a tool by COPYING it into the broker's tools dir (where it's auto-discovered). The
        source is either a local folder (``source``) or a git repo (``repo`` + optional ``subdir`` /
        ``ref``). It must contain a toolyard.toml; otherwise 422 so the client can offer to author a
        manifest (a separate flow). A cloned repo is third-party code — copied in, never started here.
        Restart the broker to register the new tool."""
        data = await _json_object(request)
        repo = (data.get("repo") or "").strip()
        source = (data.get("source") or "").strip()
        manifest = data.get("manifest")
        if not repo and not source:
            raise HTTPException(status_code=400, detail="provide a source (folder path) or repo (git URL)")
        if manifest is not None and not isinstance(manifest, dict):
            raise HTTPException(status_code=400, detail="manifest must be an object")
        config = broker_config.load()
        try:
            existing = [t["id"] for t in toolyard_ops.list_tools(config.tools_root, config.tool_dirs)]
        except Exception:
            existing = []  # can't confirm uniqueness while some tool fails to load; _ingest still guards the dir
        try:
            if repo:
                tool = tool_sources.add_from_github(
                    repo, config.tools_root, existing,
                    subdir=data.get("subdir", ""), ref=data.get("ref", ""))
            elif manifest is not None:
                # author-from-code-only: copy the folder + write the supplied manifest (no toolyard.toml needed)
                tool = tool_sources.add_with_manifest(source, config.tools_root, existing, manifest)
            else:
                tool = tool_sources.add_from_path(source, config.tools_root, existing)
        except tool_sources.NoManifest:
            raise HTTPException(status_code=422, detail="no toolyard.toml at that location — author one to add it")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_created", {"tool": tool["id"], "dir": tool["path"]})
        return tool

    @app.post("/api/tools/{tool_id}")
    async def api_edit_tool(tool_id: str, request: Request, user: str = Depends(require_user)):
        """Edit a tool's description and/or secret DECLARATIONS, preserving its operations and
        entrypoint. Mirrors the HTML panel's tool editor (admin.tool_authoring), but scoped to the
        two fields the native app edits. Secret *values* are never touched (they stay in the backend).
        """
        data = await _json_object(request)
        config = broker_config.load()
        try:
            tools = toolyard_ops.list_tools(config.tools_root, config.tool_dirs)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not read tools: {exc}")
        by_id = {t["id"]: t for t in tools}
        if tool_id not in by_id:
            raise HTTPException(status_code=404, detail=f"no such tool: {tool_id}")
        dir_path = by_id[tool_id]["path"]
        try:
            tool = tool_authoring.read(dir_path)  # full current def (ops/entrypoint/secrets/description)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not read tool: {exc}")
        # Only these two fields are editable here; id/command/image/port/operations come from
        # `read()` (disk) and are intentionally NOT overridable from the body — a tool can't be
        # repointed at other code via this endpoint.
        if "description" in data:
            if not isinstance(data["description"], str):
                raise HTTPException(status_code=400, detail="description must be a string")
            tool["description"] = data["description"]
        if "secrets" in data:
            if not isinstance(data["secrets"], list):
                raise HTTPException(status_code=400, detail="secrets must be a list")
            tool["secrets"] = data["secrets"]  # replace: sending `secrets` overwrites all declarations; omit to keep
        tool = tool_authoring.normalize(tool)
        errors = tool_authoring.validate(tool)
        if errors:
            raise HTTPException(status_code=400, detail="; ".join(errors))
        try:
            tool_authoring.write(dir_path, tool)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_edited", {"tool": tool_id, "dir": dir_path})
        return {"id": tool["id"], "description": tool["description"], "secrets": tool["secrets"]}

    @app.post("/api/tools/{tool_id}/update")
    async def api_update_tool_source(tool_id: str, user: str = Depends(require_user)):
        """Re-pull a tool from its recorded source (the local folder or git repo it was added from),
        keeping the operator's description + secret declarations. Only works for tools added through
        TSR (those with a ``.tsr-source.json``). Restart the broker if the entrypoint/ops changed."""
        config = broker_config.load()
        try:
            tools = toolyard_ops.list_tools(config.tools_root, config.tool_dirs)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not read tools: {exc}")
        by_id = {t["id"]: t for t in tools}
        if tool_id not in by_id:
            raise HTTPException(status_code=404, detail=f"no such tool: {tool_id}")
        try:
            tool = tool_sources.update(by_id[tool_id]["path"])
        except tool_sources.NoManifest:
            raise HTTPException(status_code=422, detail="the tool's source no longer has a toolyard.toml")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_updated", {"tool": tool_id, "dir": tool["path"]})
        return tool

    def _declared_fields(config, tool_id: str) -> list[str]:
        """The secret FIELDS a tool declares (or None if there's no such tool)."""
        try:
            defs = toolyard_ops._all_defs(config.tools_root, config.tool_dirs)
        except Exception as exc:
            log.warning("could not read tool secret declarations: %s", exc)
            defs = {}
        td = defs.get(tool_id)
        return None if td is None else [s.field for s in td.secrets]

    @app.get("/api/tools/{tool_id}/secrets")
    async def api_tool_secret_status(tool_id: str, user: str = Depends(require_user)):
        """Which of a tool's declared secret fields currently have a value, and whether the operator
        can set them here. Provisioning is supported only for the local 'vault' backend; values are
        NEVER returned — only set/unset status."""
        config = broker_config.load()
        declared = _declared_fields(config, tool_id)
        if declared is None:
            raise HTTPException(status_code=404, detail=f"no such tool: {tool_id}")
        try:
            provisioned = secret_values.provisioned_fields(tool_id, declared)
        except Exception as exc:  # vault locked/misconfigured — report it without leaking specifics
            raise HTTPException(status_code=400, detail=f"could not read the vault: {exc}")
        return {"backend": settings.secret_backend(),
                "settable": secret_values.is_settable(),
                "fields": declared,
                "provisioned": provisioned}

    @app.post("/api/tools/{tool_id}/secrets")
    async def api_set_tool_secret(tool_id: str, request: Request, user: str = Depends(require_user)):
        """Provision a secret VALUE for a tool (local vault only). The value is write-only — it's
        stored in the vault, never returned, and the audit event records only tool+field. Restricted
        to fields the tool actually declares."""
        data = await _json_object(request)
        field = (data.get("field") or "").strip()
        value = data.get("value")
        if not field:
            raise HTTPException(status_code=400, detail="field is required")
        # reject an all-whitespace value (a likely paste/typo) but store whatever's given VERBATIM —
        # stripping could corrupt a secret that legitimately has surrounding whitespace.
        if not isinstance(value, str) or value.strip() == "":
            raise HTTPException(status_code=400, detail="value must be a non-empty string")
        config = broker_config.load()
        declared = _declared_fields(config, tool_id)
        if declared is None:
            raise HTTPException(status_code=404, detail=f"no such tool: {tool_id}")
        if field not in declared:
            raise HTTPException(status_code=400,
                                detail=f"tool '{tool_id}' declares no secret with field '{field}'")
        try:
            secret_values.set_value(tool_id, field, value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not write to the vault: {exc}")
        with open_store(config) as store:  # NB: never log the value, only tool + field
            operations.record_admin_event(store, user, "secret_set", {"tool": tool_id, "field": field})
        return {"field": field, "set": True}

    # Per-tool lifecycle. Declared AFTER the literal /update and /secrets routes so those match
    # first; this catches start | stop | restart. Mirrors the HTML panel's /toolyard/tools/{id}/{action}.
    _TOOL_EVENTS = {"start": "tool_started", "stop": "tool_stopped", "restart": "tool_restarted"}

    @app.post("/api/tools/{tool_id}/{action}")
    async def api_tool_action(tool_id: str, action: str, user: str = Depends(require_user)):
        """Start / stop / restart a tool via the toolyard. Returns the tool's refreshed run state."""
        if action not in _TOOL_EVENTS:
            raise HTTPException(status_code=400, detail=f"unknown tool action: {action}")
        config = broker_config.load()
        try:
            tools = toolyard_ops.list_tools(config.tools_root, config.tool_dirs)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not read tools: {exc}")
        if tool_id not in {t["id"] for t in tools}:
            raise HTTPException(status_code=404, detail=f"no such tool: {tool_id}")
        try:
            if action == "stop":
                toolyard_ops.stop(tool_id)
            else:
                getattr(toolyard_ops, action)(
                    tool_id, config.tools_root, config.tool_dirs,
                    settings.tool_secrets_file(), settings.tool_runner_backend())
        except Exception as exc:  # a failed spawn/build is a 502, not a 500
            raise HTTPException(status_code=502, detail=f"tool {action} failed: {exc}")
        with open_store(config) as store:
            operations.record_admin_event(store, user, _TOOL_EVENTS[action], {"tool": tool_id})
        updated = next((t for t in toolyard_ops.list_tools(config.tools_root, config.tool_dirs)
                        if t["id"] == tool_id), {"id": tool_id})
        return updated

    @app.get("/api/config")
    async def api_config(user: str = Depends(require_user)):
        return broker_config.load().masked()  # masked: never returns the nod token

    @app.post("/api/config")
    async def api_set_config(request: Request, user: str = Depends(require_user)):
        data = await _json_object(request)
        current = broker_config.load()

        def _int(key: str, default: int) -> int:
            if key not in data:
                return default
            try:
                return int(data[key])
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} must be an integer")

        port = _int("port", current.port)
        approval_ttl = _int("approval_ttl", current.approval_ttl)
        rate_limit = _int("rate_limit", current.rate_limit)
        if not 1 <= port <= 65535:
            raise HTTPException(status_code=400, detail="port must be 1..65535")
        if approval_ttl < 1:
            raise HTTPException(status_code=400, detail="approval_ttl must be >= 1")
        if rate_limit < 0:
            raise HTTPException(status_code=400, detail="rate_limit must be >= 0")
        # nod token is write-only: keep the stored value unless a new non-empty one is given.
        nod_token = (data.get("nod_token") or "").strip() or current.nod_token
        updated = broker_config.BrokerRunConfig(
            port=port,
            db_path=current.db_path,  # not editable here — changing it would orphan the DB
            tools_root=(data.get("tools_root") or current.tools_root).strip() or current.tools_root,
            nod_url=data.get("nod_url", current.nod_url).strip(),
            nod_token=nod_token,
            nod_channel=data.get("nod_channel", current.nod_channel).strip(),
            approval_ttl=approval_ttl,
            rate_limit=rate_limit,
            tool_dirs=current.tool_dirs,
        )
        try:
            broker_config.validate_nod_url(updated.nod_url)  # SSRF guard (carries the nod token)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        broker_config.save(updated)  # the operator restarts the broker to apply (like the HTML panel)
        return updated.masked()

    @app.get("/api/secret-backend")
    async def api_secret_backend(user: str = Depends(require_user)):
        return settings.secret_backend_info()
