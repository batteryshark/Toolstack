"""The admin web app (FastAPI). Server-rendered HTML, loopback-only.

Every route except the login pages requires a valid signed-session cookie; every
state-changing POST also verifies a session-bound CSRF token. Data mutations go
through :mod:`broker.operations` (shared with ``brokerctl``, so one audit trail);
the broker process is driven through :mod:`admin.supervisor`. Secrets are never
rendered back: the nod token is write-only, and tool secret values are not handled
here at all.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from broker import operations
from broker.registry import Registry

from . import auth, broker_config, settings, supervisor, tool_authoring, toolyard_ops, views
from .store_access import open_store

SESSION_COOKIE = "toolstack_admin_session"


def create_app() -> FastAPI:
    # Fail closed: no admin login configured means no app (no default credentials).
    if settings.read_password_hash() is None:
        raise RuntimeError("no admin password set — run: python3 -m admin set-password")
    secret = settings.load_or_create_session_secret()
    app = FastAPI(title="Toolstack Admin", docs_url=None, redoc_url=None, openapi_url=None)

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
            tokens = store.list_tokens(include_revoked=True)
            requests = store.list_requests(limit=25)
            audit = store.recent_audit(limit=25)
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
            ops = Registry.from_tools_root(config.tools_root).list_ops()
        except (OSError, ValueError, KeyError):
            ops = []
        grouped: dict[str, list] = {}
        for op in ops:
            grouped.setdefault(op["tool"], []).append(op)
        return grouped

    # --- auth -----------------------------------------------------------------
    @app.get("/login")
    async def login_page(request: Request):
        if current_user(request):
            return redirect("/")
        return HTMLResponse(views.login_view())

    @app.post("/login")
    async def login(request: Request):
        data = await read_form(request)
        username = data.get("username", "")
        password = data.get("password", "")
        stored = settings.read_password_hash()
        if username != settings.admin_username() or stored is None or not auth.verify_password(password, stored):
            return HTMLResponse(views.login_view(error="Invalid username or password"), status_code=401)
        resp = redirect("/")
        resp.set_cookie(
            SESSION_COOKIE,
            auth.sign_session(username, secret, settings.session_ttl_seconds()),
            httponly=True, samesite="strict", secure=False,  # loopback http; tunnel for remote
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
            getattr(supervisor, action)(config) if action != "stop" else supervisor.stop()
        except Exception as exc:  # surface a failed spawn rather than 500
            return render_dashboard(request, user, error=f"Broker {action} failed: {exc}")
        with open_store(config) as store:
            operations.record_admin_event(store, user, events[action], {})
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
        broker_config.save(_config_from_form(data, broker_config.load()))
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
        banner = (f"Created caller {views.esc(name)}. Save this token now — it is shown once: "
                  f"<code>{views.esc(token)}</code>")
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
                token = operations.issue_token(store, name, user)
        except LookupError as exc:
            return render_dashboard(request, user, error=str(exc))
        banner = (f"New token for {views.esc(name)} — shown once: <code>{views.esc(token)}</code>")
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
                operations.revoke_caller(store, data.get("name", ""), user)
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
            operations.revoke_token(store, data.get("prefix", ""), user)
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
        return HTMLResponse(views.policy_view(
            user=user, csrf=csrf_for(request), caller=name,
            ops_by_tool=ops_by_tool(config), current=current))

    @app.post("/callers/{name}/policy")
    async def save_policy(request: Request, name: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        if not csrf_ok(request, data):
            return HTMLResponse(views.policy_view(
                user=user, csrf=csrf_for(request), caller=name,
                ops_by_tool=ops_by_tool(config), current={}, error="Invalid CSRF token."))
        allow, review = [], []
        for key, value in data.items():
            if not key.startswith("op__"):
                continue
            _, tool, op = key.split("__", 2)
            spec = f"{tool}.{op}"
            if value == "allow":
                allow.append(spec)
            elif value == "review":
                review.append(spec)
        try:
            with open_store(config) as store:
                operations.set_policy(store, name, allow, review, user)
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
        try:
            tools, error = toolyard_ops.list_tools(config.tools_root, config.tool_dirs), None
        except Exception as exc:
            tools, error = [], f"Could not read tools: {exc}"
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
            try:
                tools = toolyard_ops.list_tools(config.tools_root, config.tool_dirs)
            except Exception:
                tools = []
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
            user=user, csrf=csrf_for(request), mode="new", tool={}, dir_value=""))

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
                user=user, csrf=csrf_for(request), mode="new", tool=tool,
                dir_value=dir_path, error="Invalid CSRF token."))
        errors = list(tool_authoring.validate(tool))
        if not os.path.isabs(dir_path):
            errors.append("tool directory must be an absolute path")
        elif not Path(dir_path).is_dir():
            errors.append(f"directory does not exist: {dir_path}")
        if tool["id"] in {t["id"] for t in toolyard_ops.list_tools(config.tools_root, config.tool_dirs)}:
            errors.append(f"a tool named '{tool['id']}' already exists")
        if errors:
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), mode="new", tool=tool,
                dir_value=dir_path, error="; ".join(errors)))
        tool_authoring.write(dir_path, tool)
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
        tools = {t["id"]: t for t in toolyard_ops.list_tools(config.tools_root, config.tool_dirs)}
        if tool_id not in tools:
            return render_dashboard(request, user, error=f"no such tool: {tool_id}")
        dir_path = tools[tool_id]["path"]
        try:
            tool = tool_authoring.read(dir_path)
        except Exception as exc:
            return render_dashboard(request, user, error=f"could not read tool: {exc}")
        return HTMLResponse(views.tool_editor_view(
            user=user, csrf=csrf_for(request), mode="edit", tool=tool, dir_value=dir_path))

    @app.post("/tools/{tool_id}/edit")
    async def save_tool(request: Request, tool_id: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        # Derive the directory from the tool itself (not the posted field), so the
        # write always targets the tool being edited.
        tools = {t["id"]: t for t in toolyard_ops.list_tools(config.tools_root, config.tool_dirs)}
        if tool_id not in tools:
            return render_dashboard(request, user, error=f"no such tool: {tool_id}")
        dir_path = tools[tool_id]["path"]
        tool = _tool_from_form(data)
        if not csrf_ok(request, data):
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), mode="edit", tool=tool,
                dir_value=dir_path, error="Invalid CSRF token."))
        errors = tool_authoring.validate(tool)
        if errors:
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), mode="edit", tool=tool,
                dir_value=dir_path, error="; ".join(errors)))
        tool_authoring.write(dir_path, tool)
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
        tools = {t["id"]: t for t in toolyard_ops.list_tools(config.tools_root, config.tool_dirs)}
        if tool_id not in tools:
            return render_dashboard(request, user, error=f"no such tool: {tool_id}")
        toolyard_ops.stop(tool_id)  # stop it if running (no-op otherwise)
        path = str(Path(tools[tool_id]["path"]))
        if path not in {str(Path(p)) for p in config.tool_dirs}:
            return render_dashboard(request, user, error=(
                f"{tool_id} lives in the tools root — remove its folder from "
                f"{config.tools_root} to delete it."))
        config.tool_dirs = [p for p in config.tool_dirs if str(Path(p)) != path]
        broker_config.save(config)
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_removed", {"tool": tool_id, "dir": path})
        return render_dashboard(request, user, banner=(
            f"Unregistered tool {views.esc(tool_id)} (its files were left on disk). "
            "Restart the broker to apply."))

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
