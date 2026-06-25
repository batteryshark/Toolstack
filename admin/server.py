"""The admin web app (FastAPI). Server-rendered HTML, loopback-only.

Every route except the login pages requires a valid signed-session cookie; every
state-changing POST also verifies a session-bound CSRF token. Data mutations go
through :mod:`broker.operations` (shared with ``brokerctl``, so one audit trail);
the broker process is driven through :mod:`admin.supervisor`. Secrets are never
rendered back: the nod token is write-only, and tool secret values are not handled
here at all.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from broker import operations
from broker.registry import Registry

from . import (api, auth, broker_config, loginguard, settings, supervisor,
               tool_authoring, tool_sources, toolyard_ops, views)
from .store_access import open_store

log = logging.getLogger(__name__)

SESSION_COOKIE = "toolstack_admin_session"


def create_app() -> FastAPI:
    # Fail closed: no admin login configured means no app (no default credentials).
    if settings.read_password_hash() is None:
        raise RuntimeError("no admin password set; run: python3 -m admin set-password")
    secret = settings.load_or_create_session_secret()
    guard = loginguard.LoginGuard()  # shared by /login and /api/login
    app = FastAPI(title="Toolstack Admin", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(sqlite3.OperationalError)
    async def _operational_error(request: Request, exc: sqlite3.OperationalError):
        # The admin opens short-lived connections; under sustained write contention with the
        # broker one can still exceed the store's busy_timeout. Answer "busy, retry" (a 503,
        # not an opaque 500) so the operator (or the API client) knows it's transient. A
        # NON-lock OperationalError (a schema/SQL bug) is a real 500: don't mask it as "busy".
        text = str(exc).lower()
        busy = "lock" in text or "busy" in text
        status, msg = (503, "Database is busy; please retry in a moment.") if busy \
            else (500, "Internal database error.")
        log.warning("sqlite OperationalError on %s (%s): %s", request.url.path,
                    "busy" if busy else "fatal", exc)
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": msg}, status_code=status)
        return HTMLResponse(f"<!doctype html><title>Error</title><h1>{status}</h1><p>{msg}</p>",
                            status_code=status)

    # --- small request helpers ------------------------------------------------
    def session_value(request: Request) -> str | None:
        return request.cookies.get(SESSION_COOKIE)

    def current_user(request: Request) -> str | None:
        return auth.verify_session(session_value(request), secret)

    def csrf_for(request: Request) -> str:
        sv = session_value(request)
        return auth.csrf_token(sv, secret) if sv else ""

    async def read_form(request: Request) -> dict[str, str]:
        # Parse urlencoded bodies ourselves (no python-multipart dependency), as
        # the old panel did. Every form field here is single-valued.
        raw = (await request.body()).decode("utf-8")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: v[-1] if v else "" for k, v in parsed.items()}

    def csrf_ok(request: Request, data: dict) -> bool:
        return auth.verify_csrf(data.get("_csrf"), session_value(request), secret)

    def redirect(path: str = "/") -> RedirectResponse:
        return RedirectResponse(path, status_code=303)

    def render_dashboard(request: Request, user: str, *, banner=None, error=None) -> HTMLResponse:
        config = broker_config.load()
        with open_store(config) as store:
            callers = store.list_callers(include_revoked=True)
            tokens = store.list_tokens(include_revoked=False)  # active only; log shows revocations
            requests = store.list_requests(limit=50)   # a wider window so the row filter has substance
            audit = store.recent_audit(limit=50)
            caller_names = {c["id"]: c["name"] for c in callers}
        return HTMLResponse(views.dashboard_view(
            user=user, csrf=csrf_for(request),
            broker=supervisor.status(), log_tail=supervisor.log_tail(),
            config=config.masked(),
            callers=callers, tokens=tokens, requests=requests, audit=audit,
            caller_names=caller_names, banner=banner, error=error,
        ))

    def ops_by_tool(config) -> dict:
        try:
            ops = Registry.from_sources(config.tools_root, config.tool_dirs).list_ops()
        except (OSError, ValueError, KeyError):
            ops = []
        grouped: dict[str, list] = {}
        for op in ops:
            grouped.setdefault(op["tool"], []).append(op)
        return grouped

    def safe_list_tools(config):
        """``(tools, error)``: list the tools, or ``([], "Could not read tools: ...")`` if
        any toolyard.toml fails to load (e.g. a hand-edited tool with a bad/missing port,
        which `toolyard.config.load` now rejects). Every tool route goes through this so a
        single bad tool degrades to an error banner instead of a 500."""
        try:
            return toolyard_ops.list_tools(config.tools_root, config.tool_dirs), None
        except Exception as exc:
            return [], f"Could not read tools: {exc}"

    # --- auth -----------------------------------------------------------------
    @app.get("/login")
    async def login_page(request: Request):
        if current_user(request):
            return redirect("/")
        return HTMLResponse(views.login_view())

    @app.post("/login")
    async def login(request: Request):
        ip = api.client_ip(request)
        wait = guard.retry_after(ip)
        if wait > 0:  # locked out: reject before touching the password (no timing leak)
            resp = HTMLResponse(views.login_view(
                error="Too many failed attempts. Try again later."), status_code=429)
            resp.headers["Retry-After"] = str(int(wait) + 1)
            return resp
        data = await read_form(request)
        username = data.get("username", "")
        password = data.get("password", "")
        stored = settings.read_password_hash()
        if username != settings.admin_username() or stored is None or not auth.verify_password(password, stored):
            guard.record_failure(ip)
            api.audit_login_failure(ip, username)
            return HTMLResponse(views.login_view(error="Invalid username or password"), status_code=401)
        guard.record_success(ip)
        resp = redirect("/")
        resp.set_cookie(
            SESSION_COOKIE,
            auth.sign_session(username, secret, settings.session_ttl_seconds()),
            # Secure only when reached over TLS (TOOLSTACK_ADMIN_SECURE_COOKIE=1); loopback http
            # and the container's http-behind-publish would otherwise drop the cookie.
            httponly=True, samesite="strict", secure=settings.cookie_secure(),
        )
        return resp

    @app.post("/logout")
    async def logout(request: Request):
        data = await read_form(request)
        if not csrf_ok(request, data):
            return redirect("/")
        resp = redirect("/login")
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    # --- dashboard ------------------------------------------------------------
    @app.get("/")
    async def dashboard(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        return render_dashboard(request, user)

    # --- broker supervision ---------------------------------------------------
    @app.post("/broker/{action}")
    async def broker_action(request: Request, action: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        config = broker_config.load()
        events = {"start": "broker_started", "stop": "broker_stopped", "restart": "broker_restarted"}
        if action not in events:
            return render_dashboard(request, user, error="Unknown broker action.")
        try:
            result = supervisor.stop() if action == "stop" else getattr(supervisor, action)(config)
        except Exception as exc:  # surface a failed spawn rather than 500
            return render_dashboard(request, user, error=f"Broker {action} failed: {exc}")
        with open_store(config) as store:
            operations.record_admin_event(store, user, events[action], {})
        if isinstance(result, dict) and result.get("error"):  # started but never went healthy
            return render_dashboard(request, user, error=f"Broker {action}: {result['error']}")
        return redirect("/")

    # --- run config -----------------------------------------------------------
    @app.get("/config")
    async def config_page(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        return HTMLResponse(views.config_view(user=user, csrf=csrf_for(request), config=broker_config.load()))

    @app.post("/config")
    async def save_config(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return HTMLResponse(views.config_view(
                user=user, csrf=csrf_for(request), config=broker_config.load(),
                error="Invalid CSRF token."))
        try:
            updated = _config_from_form(data, broker_config.load())
            broker_config.validate_nod_url(updated.nod_url)  # SSRF guard (carries the nod token)
        except ValueError as exc:
            return HTMLResponse(views.config_view(
                user=user, csrf=csrf_for(request), config=broker_config.load(),
                error=f"Invalid config: {exc}"))
        broker_config.save(updated)
        return render_dashboard(request, user,
                                banner="Saved broker config. Restart the broker to apply changes.")

    # --- callers & tokens -----------------------------------------------------
    @app.post("/callers")
    async def create_caller(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        name = data.get("name", "").strip()
        if not name:
            return render_dashboard(request, user, error="Caller name is required.")
        config = broker_config.load()
        try:
            with open_store(config) as store:
                token = operations.create_caller(store, name, None, None, user)
        except Exception as exc:
            return render_dashboard(request, user, error=f"Could not create caller: {exc}")
        banner = views.token_reveal_banner(
            f"Created caller <code>{views.esc(name)}</code>. Save this token now; "
            "it is shown once and cannot be retrieved later:", token)
        return render_dashboard(request, user, banner=banner)

    @app.post("/callers/refresh-token")
    async def refresh_token(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        name = data.get("name", "")
        config = broker_config.load()
        try:
            with open_store(config) as store:
                token = operations.rotate_token(store, name, user)
        except LookupError as exc:
            return render_dashboard(request, user, error=str(exc))
        banner = views.token_reveal_banner(
            f"Rotated token for <code>{views.esc(name)}</code>. Its previous token is now "
            "revoked. New token, shown once and cannot be retrieved later:", token)
        return render_dashboard(request, user, banner=banner)

    @app.post("/callers/revoke")
    async def revoke_caller(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        config = broker_config.load()
        try:
            with open_store(config) as store:
                operations.revoke_caller(store, data.get("name", ""), user,
                                         surface=config.build_surface())
        except LookupError as exc:
            return render_dashboard(request, user, error=str(exc))
        return redirect("/")

    @app.post("/tokens/revoke")
    async def revoke_token(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        config = broker_config.load()
        with open_store(config) as store:
            operations.revoke_token(store, data.get("prefix", ""), user,
                                    surface=config.build_surface())
        return redirect("/")

    # --- policy ---------------------------------------------------------------
    @app.get("/callers/{name}/policy")
    async def edit_policy(request: Request, name: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        config = broker_config.load()
        try:
            with open_store(config) as store:
                caller = operations.require_caller(store, name)
                current = store.policy_for(caller["id"])
        except LookupError as exc:
            return render_dashboard(request, user, error=str(exc))
        all_ops = ops_by_tool(config)
        enabled = operations.enabled_tools(current)
        shown = {t: ops for t, ops in all_ops.items() if t in enabled}
        return HTMLResponse(views.policy_view(
            user=user, csrf=csrf_for(request), caller=name,
            ops_by_tool=shown, current=current, has_tools=bool(all_ops)))

    @app.post("/callers/{name}/policy")
    async def save_policy(request: Request, name: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        if not csrf_ok(request, data):
            try:
                with open_store(config) as store:
                    current = store.policy_for(operations.require_caller(store, name)["id"])
            except LookupError:
                current = {}
            all_ops = ops_by_tool(config)
            shown = {t: ops for t, ops in all_ops.items() if t in operations.enabled_tools(current)}
            return HTMLResponse(views.policy_view(
                user=user, csrf=csrf_for(request), caller=name,
                ops_by_tool=shown, current=current, has_tools=bool(all_ops),
                error="Invalid CSRF token."))
        allow, review, deny = [], [], []
        for key, value in data.items():
            if key.startswith("op__"):  # api/mcp: one effect per op; deny == omitted
                _, tool, op = key.split("__", 2)
                spec = f"{tool}.{op}"
                if value == "allow":
                    allow.append(spec)
                elif value == "review":
                    review.append(spec)
            elif key.startswith("rest_rules__"):  # rest: a JSON array of {verb, pattern, effect}
                tool = key[len("rest_rules__"):]
                try:
                    rules = json.loads(value) if value else []
                except (json.JSONDecodeError, TypeError):
                    rules = []
                for rule in rules if isinstance(rules, list) else []:
                    if not isinstance(rule, dict):
                        continue
                    verb = str(rule.get("verb", "")).strip()
                    if not verb:
                        continue
                    pattern = str(rule.get("pattern", "")).strip()
                    spec = f"{tool}.{verb}" if not pattern else f"{tool}.{verb} {pattern}"
                    bucket = {"allow": allow, "review": review, "deny": deny}.get(rule.get("effect"))
                    if bucket is not None:
                        bucket.append(spec)
        try:
            with open_store(config) as store:
                operations.set_policy(store, name, allow, review, user, deny=deny)
        except LookupError as exc:
            return render_dashboard(request, user, error=str(exc))
        return redirect(f"/callers/{name}/policy")

    @app.get("/callers/{name}/tools")
    async def edit_caller_tools(request: Request, name: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        config = broker_config.load()
        try:
            with open_store(config) as store:
                caller = operations.require_caller(store, name)
                current = store.policy_for(caller["id"])
        except LookupError as exc:
            return render_dashboard(request, user, error=str(exc))
        all_tools = sorted(ops_by_tool(config).items())
        return HTMLResponse(views.caller_tools_view(
            user=user, csrf=csrf_for(request), caller=name,
            all_tools=all_tools, enabled=set(operations.enabled_tools(current))))

    @app.post("/callers/{name}/tools")
    async def save_caller_tools(request: Request, name: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        enabled = [k[len("tool__"):] for k, v in data.items()
                   if k.startswith("tool__") and v == "on"]
        try:
            with open_store(config) as store:
                operations.set_enabled_tools(store, name, enabled, user)
        except LookupError as exc:
            return render_dashboard(request, user, error=str(exc))
        return redirect(f"/callers/{name}/policy")

    # --- tools (toolyard control) ---------------------------------------------
    @app.get("/tools")
    async def tools_page(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        config = broker_config.load()
        tools, error = safe_list_tools(config)
        for t in tools:  # attach the source sidecar so updatable tools get an Update button
            t["source"] = tool_sources.read_source(t["path"])
        return HTMLResponse(views.tools_view(
            user=user, csrf=csrf_for(request), tools=tools,
            tools_root=config.tools_root, error=error))

    @app.post("/toolyard/tools/{tool_id}/{action}")
    async def toolyard_action(request: Request, tool_id: str, action: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        events = {"start": "tool_started", "stop": "tool_stopped", "restart": "tool_restarted"}

        def tools_error(msg: str) -> HTMLResponse:
            tools, _ = safe_list_tools(config)
            return HTMLResponse(views.tools_view(
                user=user, csrf=csrf_for(request), tools=tools,
                tools_root=config.tools_root, error=msg))

        if not csrf_ok(request, data):
            return tools_error("Invalid CSRF token.")
        if action not in events:
            return redirect("/tools")
        try:
            if action == "stop":
                toolyard_ops.stop(tool_id)
            else:
                getattr(toolyard_ops, action)(
                    tool_id, config.tools_root, config.tool_dirs,
                    settings.tool_secrets_file(), settings.tool_runner_backend())
            with open_store(config) as store:
                operations.record_admin_event(store, user, events[action], {"tool": tool_id})
        except Exception as exc:
            return tools_error(f"Tool {action} failed: {exc}")
        return redirect("/tools")

    # --- tool authoring (write/edit toolyard.toml) ----------------------------
    @app.get("/tools/new")
    async def new_tool_page(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        return HTMLResponse(views.tool_editor_view(
            user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="new", tool={}, dir_value=""))

    @app.post("/tools/new")
    async def create_tool(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        dir_path = (data.get("dir") or "").strip()
        tool = _tool_from_form(data)
        if not csrf_ok(request, data):
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="new", tool=tool,
                dir_value=dir_path, error="Invalid CSRF token."))
        errors = list(tool_authoring.validate(tool))
        if not os.path.isabs(dir_path):
            errors.append("tool directory must be an absolute path")
        elif not Path(dir_path).is_dir():
            errors.append(f"directory does not exist: {dir_path}")
        existing, list_err = safe_list_tools(config)
        if list_err:
            errors.append(list_err)  # can't confirm uniqueness while a tool fails to load
        elif tool["id"] in {t["id"] for t in existing}:
            errors.append(f"a tool named '{tool['id']}' already exists")
        if errors:
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="new", tool=tool,
                dir_value=dir_path, error="; ".join(errors)))
        try:
            # write() runs the entrypoint check that validate() can't (it needs the directory and
            # the runner); surface its ValueError as a form error, not an opaque 500.
            tool_authoring.write(dir_path, tool)
        except ValueError as exc:
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="new", tool=tool,
                dir_value=dir_path, error=str(exc)))
        norm_dir = str(Path(dir_path))  # normalize so the later removable check matches
        if norm_dir not in config.tool_dirs:
            config.tool_dirs = [*config.tool_dirs, norm_dir]
            broker_config.save(config)
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_created", {"tool": tool["id"], "dir": norm_dir})
        return render_dashboard(request, user, banner=(
            f"Created tool {views.esc(tool['id'])}. Restart the broker to register it, "
            "then grant a caller access in its policy."))

    @app.get("/tools/{tool_id}/edit")
    async def edit_tool_page(request: Request, tool_id: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        config = broker_config.load()
        tools_list, list_err = safe_list_tools(config)
        if list_err:
            return render_dashboard(request, user, error=list_err)
        tools = {t["id"]: t for t in tools_list}
        if tool_id not in tools:
            return render_dashboard(request, user, error=f"no such tool: {tool_id}")
        dir_path = tools[tool_id]["path"]
        try:
            tool = tool_authoring.read(dir_path)
        except Exception as exc:
            return render_dashboard(request, user, error=f"could not read tool: {exc}")
        return HTMLResponse(views.tool_editor_view(
            user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="edit", tool=tool, dir_value=dir_path))

    @app.post("/tools/{tool_id}/edit")
    async def save_tool(request: Request, tool_id: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        # Derive the directory from the tool itself (not the posted field), so the
        # write always targets the tool being edited.
        tools_list, list_err = safe_list_tools(config)
        if list_err:
            return render_dashboard(request, user, error=list_err)
        tools = {t["id"]: t for t in tools_list}
        if tool_id not in tools:
            return render_dashboard(request, user, error=f"no such tool: {tool_id}")
        dir_path = tools[tool_id]["path"]
        tool = _tool_from_form(data)
        if not csrf_ok(request, data):
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="edit", tool=tool,
                dir_value=dir_path, error="Invalid CSRF token."))
        errors = tool_authoring.validate(tool)
        if errors:
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="edit", tool=tool,
                dir_value=dir_path, error="; ".join(errors)))
        try:
            # write() runs the entrypoint check that validate() can't; surface its ValueError as a
            # form error, not an opaque 500.
            tool_authoring.write(dir_path, tool)
        except ValueError as exc:
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), backend=settings.secret_backend_info(), mode="edit", tool=tool,
                dir_value=dir_path, error=str(exc)))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_edited", {"tool": tool["id"], "dir": dir_path})
        return render_dashboard(request, user, banner=(
            f"Saved tool {views.esc(tool['id'])}. Restart the broker if its entrypoint or "
            "operations changed."))

    @app.post("/tools/{tool_id}/remove")
    async def remove_tool(request: Request, tool_id: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        config = broker_config.load()
        tools_list, list_err = safe_list_tools(config)
        if list_err:
            return render_dashboard(request, user, error=list_err)
        tools = {t["id"]: t for t in tools_list}
        if tool_id not in tools:
            return render_dashboard(request, user, error=f"no such tool: {tool_id}")
        path = str(Path(tools[tool_id]["path"]))
        is_external = path in {str(Path(p)) for p in config.tool_dirs}
        try:
            if is_external:
                # An operator-owned folder registered via tool_dirs: unregister it, leave the files.
                toolyard_ops.stop(tool_id)  # stop if running (no-op otherwise)
                config.tool_dirs = [p for p in config.tool_dirs if str(Path(p)) != path]
                broker_config.save(config)
                banner = (f"Unregistered tool <code>{views.esc(tool_id)}</code> (its files were "
                          "left on disk). Restart the broker to apply.")
            else:
                # A TSR-managed tool under the tools root: stop it and delete its folder.
                toolyard_ops.remove(tool_id, config.tools_root, config.tool_dirs)
                banner = (f"Removed tool <code>{views.esc(tool_id)}</code> (deleted its folder). "
                          "Restart the broker to apply.")
        except (LookupError, ValueError) as exc:
            return render_dashboard(request, user, error=str(exc))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_removed",
                                          {"tool": tool_id, "dir": path, "deleted": not is_external})
        return render_dashboard(request, user, banner=banner)

    # --- add / update a tool from its source (folder or git) ------------------
    @app.get("/tools/add")
    async def add_tool_source_page(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        return HTMLResponse(views.tool_add_view(user=user, csrf=csrf_for(request)))

    @app.post("/tools/add-source")
    async def add_tool_source(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        src_val, repo_val = (data.get("source") or "").strip(), (data.get("repo") or "").strip()

        def again(error: str) -> HTMLResponse:
            return HTMLResponse(views.tool_add_view(
                user=user, csrf=csrf_for(request), source_value=src_val, repo_value=repo_val, error=error))

        if not csrf_ok(request, data):
            return again("Invalid CSRF token.")
        config = broker_config.load()
        existing, list_err = safe_list_tools(config)
        existing_ids = [] if list_err else [t["id"] for t in existing]
        try:
            if data.get("kind") == "github":
                tool = tool_sources.add_from_github(
                    repo_val, config.tools_root, existing_ids,
                    subdir=(data.get("subdir") or "").strip(), ref=(data.get("ref") or "").strip())
            else:
                tool = tool_sources.add_from_path(src_val, config.tools_root, existing_ids)
        except tool_sources.NoManifest:
            return again("No toolyard.toml at that location; use “Author a tool” to create one.")
        except ValueError as exc:
            return again(str(exc))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_created", {"tool": tool["id"], "dir": tool["path"]})
        return render_dashboard(request, user, banner=(
            f"Added tool {views.esc(tool['id'])} from its source. Restart the broker to register it, "
            "then grant a caller access in its policy."))

    @app.post("/tools/{tool_id}/update-source")
    async def update_tool_source(request: Request, tool_id: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        config = broker_config.load()
        tools_list, list_err = safe_list_tools(config)
        if list_err:
            return render_dashboard(request, user, error=list_err)
        tools = {t["id"]: t for t in tools_list}
        if tool_id not in tools:
            return render_dashboard(request, user, error=f"no such tool: {tool_id}")
        try:
            tool = tool_sources.update(tools[tool_id]["path"])
        except tool_sources.NoManifest:
            return render_dashboard(request, user, error="the tool's source no longer has a toolyard.toml")
        except ValueError as exc:
            return render_dashboard(request, user, error=str(exc))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_updated", {"tool": tool_id, "dir": tool["path"]})
        return render_dashboard(request, user, banner=(
            f"Updated tool {views.esc(tool_id)} from its source. Restart the broker if its entrypoint "
            "or operations changed."))

    # JSON operator API (bearer-token auth) for native / automation clients: same ops,
    # JSON face. See admin/api.py (T-029).
    api.add_api_routes(app, secret, guard)
    return app


def _tool_from_form(data: dict) -> dict:
    """Parse the editor's hidden tool_json field into a normalized tool dict, or an
    empty normalized dict if it is missing/garbage (validation then reports why)."""
    try:
        return tool_authoring.from_json(data.get("tool_json") or "{}")
    except Exception:
        return tool_authoring.normalize({})


def _config_from_form(data: dict, current) -> "broker_config.BrokerRunConfig":
    def _int(key: str, default: int) -> int:
        raw = data.get(key, "").strip()
        try:
            return int(raw) if raw else default
        except ValueError:
            return default

    # nod token is write-only: keep the stored value unless a new one is provided.
    nod_token = data.get("nod_token", "") or current.nod_token
    return broker_config.BrokerRunConfig(
        port=_int("port", current.port),
        db_path=data.get("db_path", "").strip() or current.db_path,
        tools_root=data.get("tools_root", "").strip() or current.tools_root,
        nod_url=data.get("nod_url", current.nod_url).strip(),
        nod_token=nod_token,
        nod_channel=data.get("nod_channel", current.nod_channel).strip(),
        approval_ttl=_int("approval_ttl", current.approval_ttl),
        rate_limit=_int("rate_limit", current.rate_limit),
    )
