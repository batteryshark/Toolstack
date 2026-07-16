"""The dashboard: broker control, callers, tokens, requests, and audit."""

from __future__ import annotations

import json
import time

from .components import _alerts
from .layout import _csrf_field, esc, page


def _broker_section(broker: dict, log_tail: str, config: dict, csrf: str) -> str:
    if broker["running"]:
        healthy = broker["healthy"]
        cls, word = ("ok", "healthy") if healthy else ("bad", "unhealthy")
        status = (f"<span class='pill {cls}'>running · {word}</span> "
                  f"<span class='muted'>pid {esc(broker['pid'])} · port {esc(broker['port'])}</span>")
    else:
        status = "<span class='pill muted'>stopped</span>"

    def btn(action: str, label: str, disabled: bool) -> str:
        d = " disabled" if disabled else ""
        return (f"<form method='post' action='/broker/{action}' class='inline-form'>"
                f"{_csrf_field(csrf)}<button type='submit'{d}>{esc(label)}</button></form>")

    running = broker["running"]
    controls = (btn("start", "Start", running)
                + btn("stop", "Stop", not running)
                + btn("restart", "Restart", not running))
    cfg_rows = "".join(f"<tr><td>{esc(k)}</td><td><code>{esc(v)}</code></td></tr>"
                       for k, v in config.items())
    log_body = log_tail if log_tail else "No broker log yet."
    log_html = f"<details><summary>Broker log</summary><pre>{esc(log_body)}</pre></details>"
    return (
        "<section><h2>Broker</h2>"
        f"<p>{status}</p>"
        f"<div class='actions'>{controls}</div>"
        f"{log_html}"
        "<h3>Run config</h3>"
        f"<table>{cfg_rows}</table>"
        "<p class='actions'><a class='button' href='/config'>Edit config</a>"
        "<a class='button' href='/tools'>Manage tools</a></p>"
        "</section>"
    )


def token_reveal_banner(lead: str, token: str) -> str:
    """A one-time token reveal for the dashboard banner: a lead line plus a readonly,
    click-to-select field and a Copy button. ``lead`` is caller-supplied HTML; ``token``
    is URL-safe (so it is safe inline in the JS string and, via esc, in HTML)."""
    return (
        f"{lead}"
        "<div class='row' style='margin-top:10px'>"
        f"<input class='token-field' readonly value='{esc(token)}' onclick='this.select()' "
        "style='flex:1;min-width:340px;font-family:ui-monospace,Menlo,Consolas,monospace'>"
        f"<button type='button' onclick=\"navigator.clipboard.writeText('{esc(token)}');"
        "this.textContent='Copied!'\">Copy</button>"
        "</div>"
    )


def _callers_section(callers, csrf: str) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{esc(c['name'])}</td>"
        f"<td>{'revoked' if c['revoked_at'] else 'active'}</td>"
        "<td class='actions'>"
        f"<a class='button' href='/callers/{esc(c['name'])}/policy'>Policy</a>"
        f"<a class='button' href='/callers/{esc(c['name'])}/tools'>Tools</a>"
        f"<form method='post' action='/callers/refresh-token' class='inline-form' "
        "onsubmit=\"return confirm('Rotate this caller\\'s token? Its current token stops "
        "working immediately and a new one is shown once.')\">"
        f"{_csrf_field(csrf)}"
        f"<input type='hidden' name='name' value='{esc(c['name'])}'><button type='submit'>Refresh token</button></form>"
        f"<form method='post' action='/callers/revoke' class='inline-form'>{_csrf_field(csrf)}"
        f"<input type='hidden' name='name' value='{esc(c['name'])}'><button type='submit'>Revoke</button></form>"
        "</td></tr>"
        for c in callers
    ) or "<tr><td colspan='3' class='muted'>No callers yet.</td></tr>"
    create = (
        "<form method='post' action='/callers' class='toolbar'>"
        f"{_csrf_field(csrf)}<input name='name' placeholder='caller name' required>"
        "<button type='submit'>Create caller</button></form>"
    )
    return (f"<section><h2>Callers</h2>{create}"
            "<table><thead><tr><th>Name</th><th>Status</th><th>Actions</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")


def _tokens_section(tokens, csrf: str) -> str:
    # Active tokens only; revocations and rotations are recorded in the Audit log.
    rows = "".join(
        "<tr>"
        f"<td><code>{esc(t['token_hash'][:12])}...</code></td>"
        f"<td>{esc(t['caller'])}</td>"
        "<td>"
        f"<form method='post' action='/tokens/revoke' class='inline-form'>{_csrf_field(csrf)}"
        f"<input type='hidden' name='prefix' value='{esc(t['token_hash'][:12])}'>"
        "<button type='submit'>Revoke</button></form></td>"
        "</tr>"
        for t in tokens
    ) or "<tr><td colspan='3' class='muted'>No active tokens.</td></tr>"
    return ("<section><h2>Active tokens</h2>"
            "<p class='muted'>Only active tokens are listed. Revoked and rotated tokens "
            "appear in the Audit log.</p>"
            "<table><thead><tr><th>Hash prefix</th><th>Caller</th><th></th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")


def _filterbar(table_id: str, placeholder: str, key_label: str, keys) -> str:
    """A text filter (matches the row text) + an optional dropdown (matches each row's data-key),
    wired to filterTable() in the page JS. ``keys`` are the distinct outcomes/statuses present."""
    options = "".join(f"<option value='{esc(k)}'>{esc(k)}</option>" for k in keys)
    return ("<div class='filterbar'>"
            f"<input type='search' data-filter-for='{table_id}' placeholder='{esc(placeholder)}'>"
            f"<select data-filter-sel='{table_id}'><option value=''>{esc(key_label)}</option>"
            f"{options}</select></div>")


def _requests_section(requests, caller_names) -> str:
    rows = "".join(
        f"<tr data-row data-key=\"{esc(r['status'])}\">"
        f"<td>{esc(r['id'])}</td>"
        f"<td>{esc(caller_names.get(r['caller_id'], r['caller_id']))}</td>"
        f"<td>{esc(r['tool'])}.{esc(r['op'])}</td>"
        f"<td>{esc(r['status'])}</td>"
        "</tr>"
        for r in requests
    ) or "<tr><td colspan='4' class='muted'>No requests yet.</td></tr>"
    bar = _filterbar("requests-table", "Filter by caller / tool...", "All statuses",
                     sorted({r["status"] for r in requests}))
    return ("<section><h2>Recent requests</h2>" + bar +
            "<table id='requests-table'><thead><tr><th>#</th><th>Caller</th><th>Operation</th><th>Status</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")


def _fmt_at(ts) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError, OSError):
        return ""


def _audit_section(events, csrf: str) -> str:
    latest = max((e["id"] for e in events), default=None)
    rows = "".join(
        f"<tr data-row data-key=\"{esc(e['outcome'])}\" class=\"{'audit-latest' if e['id'] == latest else ''}\">"
        f"<td>{esc(_fmt_at(e.get('at')))}</td>"
        f"<td>{esc(e['component'])}.{esc(e['event_type'])}</td>"
        f"<td>{esc(e['outcome'])}</td>"
        f"<td>{esc(e['request_id'] if e['request_id'] is not None else '')}</td>"
        f"<td><code>{esc(json.dumps(e['details']))}</code></td>"
        "</tr>"
        for e in events
    ) or "<tr><td colspan='5' class='muted'>No audit events yet.</td></tr>"
    bar = _filterbar("audit-table", "Filter by caller / tool / event...", "All outcomes",
                     sorted({e["outcome"] for e in events}))
    clear = ("<form method='post' action='/audit/clear' class='inline-form' "
             "onsubmit=\"return confirm('Clear the audit log?')\">"
             f"{_csrf_field(csrf)}<button type='submit'>Clear audit</button></form>")
    return ("<section><div class='toolbar'><h2>Audit</h2>" + clear + "</div>" + bar +
            "<table id='audit-table'><thead><tr><th>Time</th><th>Event</th><th>Outcome</th><th>Req</th><th>Details</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")


def dashboard_view(*, user, csrf, broker, log_tail, config, callers, tokens,
                   requests, audit, caller_names, banner=None, error=None) -> str:
    panels = [
        ("broker", "Broker", _broker_section(broker, log_tail, config, csrf)),
        ("callers", "Callers", _callers_section(callers, csrf)),
        ("tokens", "Tokens", _tokens_section(tokens, csrf)),
        ("requests", "Requests", _requests_section(requests, caller_names)),
        ("audit", "Audit", _audit_section(audit, csrf)),
    ]
    bar = "".join(
        f"<button class='tab-button{' active' if i == 0 else ''}' type='button' "
        f"data-tab='{key}'>{esc(label)}</button>"
        for i, (key, label, _) in enumerate(panels))
    # The first panel renders visible and the rest hidden, so the page is usable before
    # (or without) JS; showTab() then honours any URL hash on load.
    body = (
        _alerts(banner, error)
        + f"<nav class='tabs'>{bar}</nav>"
        + "".join(f"<div class='tab-panel{'' if i == 0 else ' hidden'}' data-tab-panel='{key}'>"
                  f"{content}</div>"
                  for i, (key, _, content) in enumerate(panels))
    )
    return page("Dashboard", body, user=user, csrf=csrf, nav="dashboard")
