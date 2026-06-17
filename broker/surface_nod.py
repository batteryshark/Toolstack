"""NodSurface — the reference approval-surface adapter, talking to nod over HTTP.

    open   -> POST {base}/api/v1/requests              (issuer token, requests:write)
    poll   -> GET  {base}/api/v1/requests/{id}/decision (issuer token, requests:read)
    cancel -> POST {base}/api/v1/requests/{id}/cancel   (issuer token; best effort)

It maps an OperationCard to nod's CreateDecisionRequest (no raw args/secrets;
push text redacted) and nod's decision back to a normalized SurfaceState. The
broker owns approval truth — `poll` is authoritative; nod is the messenger.

Contract pinned against nod v1.0.1 (github.com/batteryshark/nod @ 01d535d),
verified endpoint-by-endpoint against that source and live-probed against a
running instance. Do not change a request field or response key below without
re-checking it against nod's `nod-proto` crate — the request body is strict.

  open  request body  -> nod CreateDecisionRequest (`#[serde(deny_unknown_fields)]`,
      so an unknown/typo'd field is rejected, not dropped). Fields used here:
      channel_id, title, summary, body_markdown?, fields[{label,value}],
      options[{id,label,kind,destructive?}], dedupe_key, notification{redact}.
      `dedupe_key` makes open() retry-safe (same key -> same request). We do NOT
      send nod's `callback_url`: resolution is poll-only by design (`poll` is
      authoritative), and nod posts callbacks unauthenticated, so a broker receiver
      would let anyone forge an approval. See docs/approval-surface-adapter.md.
  open  response      -> {request_id: str, deduped: bool, request: {...}}.
      We read request_id; `deduped` is available if a caller wants to detect a
      dedupe hit. nod ignores unknown *response* fields, so it is forward-compatible.
  poll  response      -> RequestDecisionView:
      {request_id, status, decision|null, decisions[], decision_resolution,
       recipients[], pending_recipients[], request_digest, timed_out?}.
      status      ∈ {pending, resolved, expired, cancelled}  (snake_case).
      decision    -> {option_id, option_kind, option_label, text?, actor_user_id?,
                      actor_device_id?, signature?, resolved_at}.
      option_kind ∈ {approve, approve_with_text, reject, reject_with_text,
                      dismiss, open, custom}  (snake_case). We map approve* ->
      APPROVED, reject* -> REJECTED, everything else -> not-an-approval (PENDING).
  cancel              -> only the creating issuer token may cancel its request
      (else 403); best effort, since the broker has already recorded the outcome.

  Efficiency note: nod also serves GET .../{id}/wait?timeout_seconds=N (1..60),
  a long-poll that returns the same RequestDecisionView as soon as a decision
  lands. The broker currently uses the instant `/decision` read in its own poll
  loop; switching to `/wait` would cut request churn (left as a future change so
  this adapter stays a thin, stateless mapper).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import approval
from .approval import OperationCard, SurfaceState


class NodSurface:
    def __init__(self, base_url, issuer_token, *, channel="default", timeout=15.0):
        self._base = base_url.rstrip("/")
        self._token = issuer_token
        self._channel = channel
        self._timeout = timeout

    @classmethod
    def from_env(cls) -> "NodSurface | None":
        """Build from TOOLSTACK_NOD_URL / _TOKEN / _CHANNEL, or None if URL+token
        aren't both set. Lets the broker, brokerctl, and the admin app construct the
        same surface client — the latter two revoke out of the broker process and
        build their own to withdraw cancelled approvals from nod."""
        url = os.environ.get("TOOLSTACK_NOD_URL")
        token = os.environ.get("TOOLSTACK_NOD_TOKEN")
        if not (url and token):
            return None
        return cls(url, token, channel=os.environ.get("TOOLSTACK_NOD_CHANNEL", "default"))

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
    decided_at = decision.get("resolved_at")  # nod's decision time (ISO 8601) -> decided_at
    if kind.startswith("approve"):
        return SurfaceState(approval.APPROVED, approver, note, decided_at)
    if kind.startswith("reject"):
        return SurfaceState(approval.REJECTED, approver, note, decided_at)
    return SurfaceState(approval.PENDING)  # dismiss / other -> not an approval
