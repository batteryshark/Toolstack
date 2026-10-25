"""NodSurface: the reference approval-surface adapter, talking to nod over HTTP.

    open   -> POST {base}/api/v1/requests              (issuer token, requests:write)
    poll   -> GET  {base}/api/v1/requests/{id}/decision (issuer token, requests:read)
    cancel -> POST {base}/api/v1/requests/{id}/cancel   (issuer token; best effort)

It maps an OperationCard to nod's CreateDecisionRequest (allowlisted structural
summary, not a secret-free guarantee) and nod's decision back to SurfaceState. The
broker owns approval truth: `poll` is authoritative; nod is the messenger.

Contract pinned against nod v1.0.1 (github.com/batteryshark/nod @ 01d535d),
verified endpoint-by-endpoint against that source and live-probed against a
running instance. Do not change a request field or response key below without
re-checking it against nod's `nod-proto` crate; the request body is strict.

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
                       dismiss, open, custom} (snake_case). Only the exact issued
       pairs (approve, approve), (reject, reject_with_text), in resolved state,
       become APPROVED/REJECTED. Every returned request identifier must match.
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
import math
import os
import re
import uuid
import urllib.error
import urllib.parse
import urllib.request

from . import approval
from .approval import OperationCard, SurfaceState
from .bounds import DeadlineHTTPHandler, DeadlineHTTPSHandler, operation_bounds, read_response


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                     DeadlineHTTPHandler(), DeadlineHTTPSHandler())


def _reference(ref):
    if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", ref):
        raise ValueError("invalid Nod request identifier")
    return ref


def _matching_ids(value, ref):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "request_id" and child != ref:
                return False
            if key == "request" and isinstance(child, dict) and "id" in child and child["id"] != ref:
                return False
            if not _matching_ids(child, ref):
                return False
    elif isinstance(value, list):
        return all(_matching_ids(child, ref) for child in value)
    return True


class NodSurface:
    def __init__(self, base_url, issuer_token, *, channel="default", timeout=15.0):
        try:
            if not isinstance(base_url, str) or any(c.isspace() or ord(c) < 32 for c in base_url):
                raise ValueError
            url = urllib.parse.urlsplit(base_url)
            if (url.scheme not in {"http", "https"} or not url.hostname
                    or url.username is not None or url.password is not None
                    or "?" in base_url or "#" in base_url or "\\" in base_url):
                raise ValueError
            if url.port is not None and not 0 < url.port <= 65535:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("invalid Nod base URL") from None
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("Nod timeout must be finite and within (0,60] seconds")
        self._base = base_url.rstrip("/")
        self._token = issuer_token
        self._channel = channel
        self._timeout = timeout

    @classmethod
    def from_env(cls) -> "NodSurface | None":
        """Build from TOOLSTACK_NOD_URL / _TOKEN / _CHANNEL, or None if URL+token
        aren't both set. Lets the broker, brokerctl, and the admin app construct the
        same surface client; the latter two revoke out of the broker process and
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
        with operation_bounds(self._timeout, 1024 * 1024):
            try:
                with _OPENER.open(req, timeout=self._timeout) as resp:
                    raw = read_response(resp)
            except urllib.error.HTTPError as exc:
                exc.close()
                raise
        result = json.loads(raw) if raw else {}
        if not isinstance(result, dict):
            raise ValueError("invalid Nod response")
        return result

    def open(self, card: OperationCard) -> str:
        namespace = str(uuid.UUID(card.installation_id)) if card.installation_id else None
        if namespace is None:
            raise ValueError("persistent installation identity required")
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
            ] + ([{"label": "Endpoint", "value": card.endpoint}] if card.endpoint else []),
            "options": [
                {"id": "approve", "label": "Approve", "kind": "approve"},
                {"id": "reject", "label": "Reject", "kind": "reject_with_text",
                 "destructive": True},
            ],
            "dedupe_key": f"toolstack:{namespace}:{card.request_id}",
            "notification": {"redact": True},  # nothing sensitive on a lock screen
        }
        md = []
        # Free-text reason is never a trusted summary, even if pattern-redacted.
        # Structural presentation is produced by the broker's allowlist path.
        if card.request_digest:
            payload["fields"].append({"label": "Full request SHA-256", "value": card.request_digest})
        if card.operation_generation:
            payload["fields"].append({"label": "Operation generation", "value": card.operation_generation})
        if card.details:
            md.append(f"**Allowlisted summary (not the complete request):**\n```json\n{card.details}\n```")
        if md:
            payload["body_markdown"] = "\n\n".join(md)
        result = self._call("POST", "/api/v1/requests", payload)
        ref = _reference(result.get("request_id"))
        if not _matching_ids(result, ref):
            raise ValueError("Nod returned mismatched request identifiers")
        return ref

    def poll(self, ref: str) -> SurfaceState:
        _reference(ref)
        try:
            data = self._call("GET", f"/api/v1/requests/{ref}/decision")
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 404:
                return SurfaceState(approval.EXPIRED)  # gone -> treat as expired
            raise RuntimeError(f"nod poll failed: HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"nod unreachable: {exc.reason}")
        if not isinstance(data, dict) or data.get("request_id") != ref or not _matching_ids(data, ref):
            raise ValueError("Nod returned mismatched request identifiers")
        return _to_state(data)

    def cancel(self, ref: str) -> None:
        try:
            _reference(ref)
            self._call("POST", f"/api/v1/requests/{ref}/cancel")
        except Exception:
            pass  # best effort; the broker has already recorded the local outcome


def _to_state(data: dict) -> SurfaceState:
    status = data.get("status", "pending")
    if status == "expired":
        return SurfaceState(approval.EXPIRED)
    if status == "cancelled":
        return SurfaceState(approval.CANCELLED)
    decision = data.get("decision")
    if status != "resolved" or not isinstance(decision, dict):
        return SurfaceState(approval.PENDING)
    pair = (decision.get("option_id"), decision.get("option_kind"))
    approver = decision.get("actor_user_id")
    note = decision.get("text")
    decided_at = decision.get("resolved_at")  # nod's decision time (ISO 8601) -> decided_at
    if pair == ("approve", "approve"):
        return SurfaceState(approval.APPROVED, approver, note, decided_at)
    if pair == ("reject", "reject_with_text"):
        return SurfaceState(approval.REJECTED, approver, note, decided_at)
    return SurfaceState(approval.PENDING)  # dismiss / other -> not an approval
