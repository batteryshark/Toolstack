"""NodSurface — the reference approval-surface adapter, talking to nod over HTTP.

    open   -> POST {base}/api/v1/requests              (issuer token)
    poll   -> GET  {base}/api/v1/requests/{id}/decision
    cancel -> POST {base}/api/v1/requests/{id}/cancel   (best effort)

It maps an OperationCard to nod's CreateDecisionRequest (no raw args/secrets;
push text redacted) and nod's decision back to a normalized SurfaceState. The
broker owns approval truth — `poll` is authoritative; nod is the messenger.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import approval
from .approval import OperationCard, SurfaceState


class NodSurface:
    def __init__(self, base_url, issuer_token, *, channel="default",
                 callback_url=None, timeout=15.0):
        self._base = base_url.rstrip("/")
        self._token = issuer_token
        self._channel = channel
        self._callback_url = callback_url
        self._timeout = timeout

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"{self._base}{path}", data=data, method=method,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self._token}"},
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    def open(self, card: OperationCard) -> str:
        payload = {
            "channel_id": self._channel,
            "title": card.title,
            "summary": f"{card.tool}.{card.op} · risk {card.risk}",
            "fields": [
                {"label": "Caller", "value": card.caller},
                {"label": "Tool", "value": card.tool},
                {"label": "Operation", "value": card.op},
                {"label": "Risk", "value": card.risk},
                {"label": "Policy", "value": card.reason},
            ],
            "options": [
                {"id": "approve", "label": "Approve", "kind": "approve"},
                {"id": "reject", "label": "Reject", "kind": "reject_with_text",
                 "destructive": True},
            ],
            "dedupe_key": str(card.request_id),  # retry-safe open
            "notification": {"redact": True},  # nothing sensitive on a lock screen
        }
        if card.justification:
            payload["body_markdown"] = f"**Agent's reason:** {card.justification}"
        if self._callback_url:
            payload["callback_url"] = self._callback_url
        result = self._call("POST", "/api/v1/requests", payload)
        return str(result["request_id"])

    def poll(self, ref: str) -> SurfaceState:
        try:
            data = self._call("GET", f"/api/v1/requests/{ref}/decision")
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 404:
                return SurfaceState(approval.EXPIRED)  # gone -> treat as expired
            raise RuntimeError(f"nod poll failed: HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"nod unreachable: {exc.reason}")
        return _to_state(data)

    def cancel(self, ref: str) -> None:
        try:
            self._call("POST", f"/api/v1/requests/{ref}/cancel")
        except Exception:
            pass  # best effort; the broker has already recorded the local outcome


def _to_state(data: dict) -> SurfaceState:
    status = data.get("status", "pending")
    if status == "expired":
        return SurfaceState(approval.EXPIRED)
    if status in ("cancelled", "canceled"):
        return SurfaceState(approval.CANCELLED)
    decision = data.get("decision")
    if not decision:
        return SurfaceState(approval.PENDING)
    kind = (decision.get("option_kind") or "").lower()
    approver = decision.get("actor_user_id")
    note = decision.get("text")
    if kind.startswith("approve"):
        return SurfaceState(approval.APPROVED, approver, note)
    if kind.startswith("reject"):
        return SurfaceState(approval.REJECTED, approver, note)
    return SurfaceState(approval.PENDING)  # dismiss / other -> not an approval
