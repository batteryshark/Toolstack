"""The admin web app (FastAPI). Server-rendered HTML, loopback-only.

Every route except the login pages requires a valid signed-session cookie; every
state-changing POST also verifies a session-bound CSRF token. Data mutations go
through :mod:`broker.operations` (shared with ``brokerctl``, so one audit trail);
the broker process is driven through :mod:`admin.supervisor`. Secrets are never
rendered back: the nod token is write-only, and tool secret values are not handled
here at all.
"""

from __future__ import annotations

import logging
import json
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from broker import operations
from broker.registry import Registry
from toolyard import openapi_import

from . import (api, auth, broker_config, loginguard, settings, supervisor,
               tool_authoring, tool_sources, toolyard_ops, views)
from .reconciler import RECONCILE_LOCK, start_reconciler_thread
from .sps_link import SPSLink
from .store_access import open_store
from . import operator_audit
from .blocking import work
from .policy_edits import merge_grants, merge_enabled, operation_fields, retained_draft

log = logging.getLogger(__name__)

SESSION_COOKIE = "toolstack_admin_session"


def create_app() -> FastAPI:
    # Fail closed: no admin login configured means no app (no default credentials).
    if settings.read_password_hash() is None:
        raise RuntimeError("no admin password set; run: python3 -m admin set-password")
    secret = settings.load_or_create_session_secret()
    guard = loginguard.LoginGuard()  # shared by /login and /api/login
    app = FastAPI(title="Toolstack Admin", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def session_generation(request: Request, call_next):
        # Snapshot once per request; never use the startup key after reset.
        # Missing/unreadable key fails closed, rather than recreating authority.
        try:
            key = settings.session_secret_file().read_text(encoding="utf-8").strip()
            if not key:
                raise ValueError("empty session generation")
        except (OSError, ValueError):
            return JSONResponse({"detail": "Session authority unavailable"}, status_code=503)
        request.state.session_secret = key
        return await call_next(request)

    # --- SPS restart watchdog + startup reconciliation -------------------------
    # SPS is in-memory only (see sps/store.py). If SPS bounces (crash, library
    # upgrade, manual restart) every running tool loses its registration. The
    # watchdog detects that from a live boot_id ping and re-registers the tools
    # that are still alive.
    from .sps_watchdog import SPSWatchdog, recover_with_runner

    _initial_cfg = broker_config.load()
    _sps_env_path = settings.sps_env_path() or "/etc/toolstack/sps.env"

    # One live link serves both readiness gating (reconciler) and restart
    # detection (watchdog). None in dev / no-secrets mode.
    _sps_link = SPSLink.from_env(_sps_env_path)
    app.state.sps_link = _sps_link
    _sps_configured = (
        os.environ.get("TOOLSTACK_SPS_SKIP") != "1" and os.path.exists(_sps_env_path)
    )

    if _sps_link is not None:
        _watchdog = SPSWatchdog(
            config=_initial_cfg,
            probe=_sps_link.boot_id,
            re_register_fn=recover_with_runner,
            sps_env_path=_sps_env_path,
            lock=RECONCILE_LOCK,
        )
        _watchdog.start()
        app.state.sps_watchdog = _watchdog

        @app.on_event("shutdown")
        def _stop_watchdog() -> None:
            _watchdog.stop()

    # Restart forwarders that state.json says should be running. The reconciler
    # gates on SPS readiness itself. If SPS is configured but no usable link was
    # built, do NOT reconcile -- fail closed and surface the misconfiguration.
    if _sps_configured and _sps_link is None:
        app.state.reconciler = None
        log.error("SPS is configured at %s but no usable link was built; "
                  "skipping tool reconciliation", _sps_env_path)
    else:
        app.state.reconciler = start_reconciler_thread(_initial_cfg, _sps_link)

    @app.exception_handler(operator_audit.AppliedAuditError)
    async def _applied_audit_error(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": str(exc), "action_applied": True,
                                 "audit_complete": False}, status_code=503)
        return HTMLResponse(f"<p>{views.esc(str(exc))}</p>", status_code=503)

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
        return auth.verify_session(session_value(request), request.state.session_secret)

    def csrf_for(request: Request) -> str:
        sv = session_value(request)
        return auth.csrf_token(sv, request.state.session_secret) if sv else ""

    async def read_form(request: Request) -> dict[str, str]:
        # Parse urlencoded bodies ourselves (no python-multipart dependency), as
        # the old panel did. Every form field here is single-valued.
        raw = (await request.body()).decode("utf-8")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: v[-1] if v else "" for k, v in parsed.items()}

    def csrf_ok(request: Request, data: dict) -> bool:
        return auth.verify_csrf(data.get("_csrf"), session_value(request), request.state.session_secret)

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
            auth.sign_session(username, request.state.session_secret, settings.session_ttl_seconds()),
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
        target = data.get('catalog_target')

        async def registration_result(error=None):
            from .catalog_observation import observe_catalog
            catalog = await work.run(observe_catalog, config)
            tools, list_error = safe_list_tools(config)
            from .catalog_observation import target_verified
            verified = target_verified(catalog, target)
            message = f"{views.esc(target)} · " + ('Catalog registration verified.' if verified else 'Registration unknown. Refresh state before deciding whether to restart again.')
            return HTMLResponse(views.tools_view(user=user, csrf=csrf_for(request), tools=tools,
                tools_root=config.tools_root, catalog=catalog, broker_port=config.port,
                banner=message if verified else None, error=error or list_error or (None if verified else message),
                mutation_outcome='unknown' if error or not verified else None))
        if action not in events:
            return render_dashboard(request, user, error="Unknown broker action.")
        try:
            result = await work.run(supervisor.stop) if action == "stop" else await work.run(getattr(supervisor, action), config)
        except Exception as exc:  # surface a failed spawn rather than 500
            if target:
                return await registration_result(f"Broker restart outcome unknown for {target}. Refresh state; no retry was sent.")
            response = render_dashboard(request, user, error=f"Broker {action} outcome unknown. Refresh state before another action.")
            response.headers['X-Toolstack-Mutation-Outcome'] = 'unknown'
            return response
        with open_store(config) as store:
            operations.record_admin_event(store, user, events[action], {})
        if isinstance(result, dict) and result.get("error"):  # started but never went healthy
            if target:
                return await registration_result(f"Broker restart did not establish readiness for {target}. Refresh state.")
            return render_dashboard(request, user, error=f"Broker {action}: {result['error']}")
        if target:
            return await registration_result()
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
            current = broker_config.load()
            updated = _config_from_form(data, current)
            broker_config.validate_nod_url(updated.nod_url)  # SSRF guard (carries the nod token)
        except ValueError as exc:
            return HTMLResponse(views.config_view(
                user=user, csrf=csrf_for(request), config=broker_config.load(),
                error=f"Invalid config: {exc}"))
        operator_audit.save_config(current, updated, user)
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

    @app.post("/audit/clear")
    async def clear_audit(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        if not csrf_ok(request, data):
            return render_dashboard(request, user, error="Invalid CSRF token.")
        operator_audit.clear_audit(broker_config.load(), user)
        return redirect("/#audit")

    # --- policy ---------------------------------------------------------------
    def policy_recovery(request, user, name, data, message, status):
        try:
            config = broker_config.load()
            with open_store(config) as store:
                current = store.policy_for(operations.require_caller(store, name)["id"])
                catalog = ops_by_tool(config)
                field_map = operation_fields(current, catalog)
            scope_changed = any(k.startswith('op__') and not field_map.get(k) for k in data)
            shown = {t: ops for t, ops in catalog.items() if t in operations.enabled_tools(current)}
            if scope_changed:
                message += " Operation set changed. Load the current policy page; only still-editable draft values are shown."
            return HTMLResponse(views.policy_view(
                user=user, csrf=csrf_for(request), caller=name, ops_by_tool=shown,
                current=retained_draft(current, data, field_map), loaded=not scope_changed and status != 503,
                error=message), status_code=status)
        except (LookupError, OSError, ValueError, sqlite3.Error):
            return HTMLResponse(views.policy_view(
                user=user, csrf=csrf_for(request), caller=name, ops_by_tool={}, current={},
                loaded=False, error=message + " Draft could not be displayed. Return to the previous page to keep your inputs."), status_code=status)

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
        except (LookupError, OSError, sqlite3.Error):
            return HTMLResponse(views.policy_view(
                user=user, csrf=csrf_for(request), caller=name, ops_by_tool={},
                current={}, loaded=False, error="Policy could not be loaded. Retry load."), status_code=503)
        try:
            all_ops = ops_by_tool(config)
        except (OSError, ValueError):
            return HTMLResponse(views.policy_view(
                user=user, csrf=csrf_for(request), caller=name, ops_by_tool={},
                current={}, loaded=False, error="Tool catalog could not be loaded. Retry load."), status_code=503)
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
        wants_receipt = request.headers.get("accept") == "application/json"
        if not csrf_ok(request, data):
            if wants_receipt:
                return JSONResponse({"outcome": "rejected", "error": "Session check failed. Reload policy before saving."}, status_code=403)
            return policy_recovery(request, user, name, data,
                "Save rejected. Invalid CSRF token. Valid editable draft values retained; review before saving.", 403)
        effect_started = False
        try:
            with open_store(config) as store:
                current = store.policy_for(operations.require_caller(store, name)["id"])
                field_map = operation_fields(current, ops_by_tool(config))
                allow, review, deny = merge_grants(current, data, field_map)
                effect_started = True
                operations.set_policy(store, name, allow, review, user, deny=deny)
        except Exception as exc:
            rejected = not effect_started and isinstance(exc, (LookupError, ValueError))
            if wants_receipt:
                return JSONResponse({"outcome": "rejected" if rejected else "unknown",
                    "error": "Policy not saved. Operation set or effects may have changed. Reload to compare before saving." if rejected else
                             "Save outcome unknown. Reload to compare before retrying."}, status_code=400 if rejected else 503)
            return policy_recovery(request, user, name, data,
                "Save rejected. Valid editable draft values retained; review the current operation set and effects." if rejected else
                "Save outcome unknown. Draft retained where still editable. Reload policy to compare before retrying.",
                400 if rejected else 503)
        if wants_receipt:
            return JSONResponse({"outcome": "saved", "target": name})
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
                current = store.policy_for(operations.require_caller(store, name)["id"])
                enabled = merge_enabled(current, ops_by_tool(config), enabled)
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
        from .catalog_observation import observe_catalog
        catalog = await work.run(observe_catalog, config)
        selected = request.query_params.get('tool')
        if selected:
            tools = [t for t in tools if t['id'] == selected]
        return HTMLResponse(views.tools_view(
            user=user, csrf=csrf_for(request), tools=tools,
            tools_root=config.tools_root, error=error, catalog=catalog, broker_port=config.port, focused=bool(selected)))

    @app.post("/toolyard/tools/{tool_id}/{action}")
    async def toolyard_action(request: Request, tool_id: str, action: str):
        user = current_user(request)
        if not user:
            return redirect("/login")
        data = await read_form(request)
        config = broker_config.load()
        events = {"start": "tool_started", "stop": "tool_stopped", "restart": "tool_restarted"}

        def tools_error(msg: str, unknown=False) -> HTMLResponse:
            tools, _ = safe_list_tools(config)
            return HTMLResponse(views.tools_view(
                user=user, csrf=csrf_for(request), tools=[t for t in tools if t['id'] == tool_id],
                tools_root=config.tools_root, error=msg, focused=True, broker_port=config.port,
                mutation_outcome='unknown' if unknown else None))

        if not csrf_ok(request, data):
            return tools_error("Invalid CSRF token.")
        if action not in events:
            return redirect("/tools")
        try:
            if action == "stop":
                await work.run(toolyard_ops.stop, tool_id)
            else:
                await work.run(getattr(toolyard_ops, action),
                    tool_id, config.tools_root, config.tool_dirs,
                    settings.tool_runner_backend())
            with open_store(config) as store:
                operations.record_admin_event(store, user, events[action], {"tool": tool_id})
        except Exception:
            return tools_error(f"{tool_id} · {action} outcome unknown. Refresh state before another action; nothing was replayed.", unknown=True)
        return redirect(f"/tools?tool={quote(tool_id, safe='')}")

    # --- tool authoring (write/edit toolyard.toml) ----------------------------
    @app.get("/tools/new")
    async def new_tool_page(request: Request):
        user = current_user(request)
        if not user:
            return redirect("/login")
        return HTMLResponse(views.tool_editor_view(
            user=user, csrf=csrf_for(request), backend=settings.sps_info(), mode="new", tool={}, dir_value=""))

    @app.post("/tools/parse-openapi")
    async def parse_openapi(request: Request):
        user = current_user(request)
        if not user:
            return JSONResponse({"error": "auth"}, status_code=401)
        data = await read_form(request)
        if not csrf_ok(request, data):
            return JSONResponse({"error": "invalid CSRF token"}, status_code=400)
        try:
            spec = _parse_openapi_text(data.get("spec") or "")
            return JSONResponse(openapi_import.parse_spec(spec))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except Exception as exc:
            log.warning("could not parse OpenAPI spec: %s", exc)
            return JSONResponse({"error": f"could not parse spec: {type(exc).__name__}"}, status_code=400)

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
                user=user, csrf=csrf_for(request), backend=settings.sps_info(), mode="new", tool=tool,
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
                user=user, csrf=csrf_for(request), backend=settings.sps_info(), mode="new", tool=tool,
                dir_value=dir_path, error="; ".join(errors)))
        tool_authoring.write(dir_path, tool)
        norm_dir = str(Path(dir_path))  # normalize so the later removable check matches
        if norm_dir not in config.tool_dirs:
            previous = replace(config)
            config.tool_dirs = [*config.tool_dirs, norm_dir]
            operator_audit.save_config(previous, config, user)
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
            user=user, csrf=csrf_for(request), backend=settings.sps_info(), mode="edit", tool=tool, dir_value=dir_path))

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
                user=user, csrf=csrf_for(request), backend=settings.sps_info(), mode="edit", tool=tool,
                dir_value=dir_path, error="Invalid CSRF token."))
        errors = tool_authoring.validate(tool)
        if errors:
            return HTMLResponse(views.tool_editor_view(
                user=user, csrf=csrf_for(request), backend=settings.sps_info(), mode="edit", tool=tool,
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
        from .tool_removal import remove_tool as remove_owned_tool
        try:
            result = await work.run(remove_owned_tool, config, tool_id, user)
            effect = "deleted its managed folder" if result['deleted'] else "files retained on disk"
            label = "Removed tool" if result['deleted'] else "Unregistered tool"
            banner = f"{label} <code>{views.esc(tool_id)}</code> · {effect}. Restart the broker to apply."
        except (LookupError, ValueError) as exc:
            return render_dashboard(request, user, error=str(exc))
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
                tool = await work.run(tool_sources.add_from_github,
                    repo_val, config.tools_root, existing_ids,
                    subdir=(data.get("subdir") or "").strip(), ref=(data.get("ref") or "").strip())
            else:
                tool = await work.run(tool_sources.add_from_path, src_val, config.tools_root, existing_ids)
        except tool_sources.NoManifest:
            return again("No toolyard.toml at that location; use “Author a tool” to create one.")
        except ValueError as exc:
            return again(str(exc))
        with open_store(config) as store:
            operations.record_admin_event(store, user, "tool_created", {"tool": tool["id"], "dir": tool["path"]})
        tools, error = safe_list_tools(config)
        return HTMLResponse(views.tools_view(user=user, csrf=csrf_for(request),
            tools=[t for t in tools if t['id'] == tool['id']], tools_root=config.tools_root,
            broker_port=config.port, error=error, focused=True,
            banner=f"Added {views.esc(tool['id'])}. Start executes this trusted local tool. Catalog registration and caller grants remain separate decisions."))

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
            tool = await work.run(tool_sources.update, tools[tool_id]["path"])
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


def _parse_openapi_text(raw: str) -> dict:
    text = (raw or "").strip()
    if not text:
        raise ValueError("the spec is empty")
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError:
            raise ValueError("the spec is not valid JSON; install PyYAML for YAML")
        try:
            spec = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"the spec is not valid JSON or YAML: {exc}")
    if not isinstance(spec, dict):
        raise ValueError("the spec must be a JSON or YAML object")
    return spec


def _config_from_form(data: dict, current) -> "broker_config.BrokerRunConfig":
    return broker_config.merge_update(current, data)
