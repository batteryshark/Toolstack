"""JSON operator API (under ``/api``) for native / automation clients.

The HTML panel and this API share the SAME operations (``broker.operations`` / ``supervisor`` /
``broker_config`` / the store) — this is just a JSON face with **bearer-token** auth instead of a
session cookie + CSRF. ``POST /api/login {password}`` returns the same signed-session value the
cookie uses; clients send it back as ``Authorization: Bearer <token>`` and a dependency runs
``auth.verify_session``. No CSRF is needed (a header token is not auto-sent cross-site). Loopback
only, like the rest of the admin.

Split out of ``server.create_app`` so the JSON surface can grow (callers / policies / tools /
secrets / audit) without bloating the HTML server. **Phase 1 (T-029):** auth + broker status/
control; the remaining operator endpoints land as the native app ([[T-030]]) needs them.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request

from broker import operations

from . import auth, broker_config, settings, supervisor
from .store_access import open_store

# broker lifecycle action -> the admin.* audit event it records (shared with the HTML handler)
_BROKER_EVENTS = {"start": "broker_started", "stop": "broker_stopped", "restart": "broker_restarted"}


async def _json_object(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="expected a JSON object body")
    return body


def add_api_routes(app: FastAPI, secret: str) -> None:
    """Register the ``/api/*`` JSON routes on the admin app. ``secret`` is the session-signing
    secret (same one the cookie uses), so a token minted here is interchangeable with the panel's."""

    def require_user(request: Request) -> str:
        authz = request.headers.get("authorization", "")
        token = authz[7:].strip() if authz[:7].lower() == "bearer " else ""
        user = auth.verify_session(token, secret)
        if not user:
            raise HTTPException(status_code=401, detail="unauthorized")
        return user

    @app.post("/api/login")
    async def api_login(request: Request):
        data = await _json_object(request)
        username = data.get("username") or settings.admin_username()
        password = data.get("password", "")
        stored = settings.read_password_hash()
        if username != settings.admin_username() or not stored or not auth.verify_password(password, stored):
            # same fail-closed message for bad user OR bad password — don't reveal which
            raise HTTPException(status_code=401, detail="invalid credentials")
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
            supervisor.stop() if action == "stop" else getattr(supervisor, action)(config)
        except Exception as exc:  # a failed spawn is a 502, not a 500
            raise HTTPException(status_code=502, detail=f"broker {action} failed: {exc}")
        with open_store(config) as store:
            operations.record_admin_event(store, user, _BROKER_EVENTS[action], {})
        return supervisor.status()
