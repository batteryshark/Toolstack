"""Server-rendered HTML for the admin app.

Plain f-strings + ``html.escape`` (the same approach as the old broker-panel) — no
template engine to learn, and every dynamic value is escaped at the point of
interpolation. Static CSS/JS are plain string constants (not f-strings) so their
braces need no escaping. Every form carries a CSRF token via :func:`_csrf_field`.

These functions only build strings; the server layer decides status codes and
wraps them in responses.
"""

from __future__ import annotations

import html
import json
from typing import Any

_CSS = """
:root{color-scheme:light;--bg:#f6f7f9;--ink:#18202a;--muted:#697483;--line:#d9dee7;--panel:#fff;--accent:#0d6efd;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;background:#172033;color:#fff;}
header h1{font-size:18px;margin:0;font-weight:650;}
main{max-width:1100px;margin:0 auto;padding:22px;}
section{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px;}
h2{font-size:16px;margin:0 0 12px;}
h3{font-size:14px;margin:16px 0 8px;color:var(--muted);}
button,input,select{font:inherit;min-height:34px;border-radius:6px;border:1px solid var(--line);padding:6px 9px;background:#fff;}
button{background:#f3f5f8;cursor:pointer;}
button[type=submit],button:not([type]){background:var(--accent);border-color:var(--accent);color:#fff;}
button:disabled{opacity:.5;cursor:not-allowed;}
a.button{display:inline-flex;align-items:center;min-height:34px;border-radius:6px;border:1px solid var(--line);padding:6px 9px;background:#f3f5f8;color:var(--ink);text-decoration:none;}
table{width:100%;border-collapse:collapse;}
td,th{border-top:1px solid var(--line);padding:8px;text-align:left;vertical-align:middle;}
code{background:#eef1f5;padding:2px 5px;border-radius:5px;overflow-wrap:anywhere;}
pre{background:#0d1117;color:#e6edf3;padding:12px;border-radius:6px;overflow:auto;max-height:240px;font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;}
.toolbar,.inline-form,header form,.actions,.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.banner{background:#e9f8ef;border:1px solid #a9dfbc;padding:12px;border-radius:8px;margin-bottom:16px;}
.error{background:#fff0f0;border:1px solid #efb3b3;padding:12px;border-radius:8px;color:#8c1f1f;margin-bottom:16px;}
.muted{color:var(--muted);}
.login{max-width:380px;margin:60px auto;display:grid;gap:12px;}
.login label{display:grid;gap:6px;}
.field{display:grid;gap:6px;margin-bottom:12px;max-width:520px;}
.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;}
.pill.ok{background:#e9f8ef;color:#1c7a3f;}
.pill.bad{background:#ffe8e8;color:#8c1f1f;}
.pill.muted{background:#eef1f5;color:#697483;}
.risk{display:inline-block;border-radius:999px;padding:2px 8px;font-size:12px;background:#eef1f5;color:#333;}
.risk.low,.risk.read{background:#e8f5ff;color:#185d8f;}
.risk.medium,.risk.write{background:#fff6df;color:#7a5100;}
.risk.high,.risk.destructive{background:#ffe8e8;color:#8c1f1f;}
.card{border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0;background:#fbfcfe;}
.argrow,.secrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0;}
.argrow input,.secrow input{min-width:120px;}
"""

_JS = """
function setAll(effect){document.querySelectorAll('select[name^="op__"]').forEach(function(s){s.value=effect;});}
function setTool(tool,effect){document.querySelectorAll('select[name^="op__'+tool+'__"]').forEach(function(s){s.value=effect;});}
"""

# Tool editor: builds repeating operation/argument/secret rows from real widgets,
# pre-fills from window.TOOL_INITIAL, and serializes everything into the hidden
# tool_json field on submit — so the operator never types TOML or JSON by hand.
_TOOL_EDITOR_JS = """
(function(){
  var ARG_TYPES = ["string","number","integer","boolean","object","array"];
  function mk(html){var t=document.createElement('template');t.innerHTML=html.trim();return t.content.firstChild;}
  function opts(values, sel){return values.map(function(v){return '<option'+(v===sel?' selected':'')+'>'+v+'</option>';}).join('');}

  function argRow(a){
    a = a||{};
    var row = mk('<div class="argrow"><input class="arg-name" placeholder="arg name">'
      + '<select class="arg-type">'+opts(ARG_TYPES, a.type||'string')+'</select>'
      + '<label><input type="checkbox" class="arg-req"> required</label>'
      + '<input class="arg-desc" placeholder="description">'
      + '<button type="button" class="rm">remove</button></div>');
    row.querySelector('.arg-name').value = a.name||'';
    row.querySelector('.arg-req').checked = !!a.required;
    row.querySelector('.arg-desc').value = a.description||'';
    row.querySelector('.rm').onclick = function(){row.remove();};
    return row;
  }
  function opCard(o){
    o = o||{};
    var card = mk('<div class="card opcard"><div class="row">'
      + '<input class="op-name" placeholder="operation name">'
      + '<select class="op-risk">'+opts(["low","medium","high"], o.risk||'low')+'</select>'
      + '<input class="op-desc" placeholder="description">'
      + '<button type="button" class="rm">remove op</button></div>'
      + '<div class="args"></div><button type="button" class="add-arg">add argument</button></div>');
    card.querySelector('.op-name').value = o.name||'';
    card.querySelector('.op-desc').value = o.description||'';
    var args = card.querySelector('.args');
    (o.args||[]).forEach(function(a){args.appendChild(argRow(a));});
    card.querySelector('.add-arg').onclick = function(){args.appendChild(argRow());};
    card.querySelector('.rm').onclick = function(){card.remove();};
    return card;
  }
  function secRow(s){
    s = s||{};
    var row = mk('<div class="secrow"><input class="sec-name" placeholder="name (file the tool reads)">'
      + '<input class="sec-field" placeholder="backend field">'
      + '<label><input type="checkbox" class="sec-writable"> writable</label>'
      + '<button type="button" class="rm">remove</button></div>');
    row.querySelector('.sec-name').value = s.name||'';
    row.querySelector('.sec-field').value = s.field||'';
    row.querySelector('.sec-writable').checked = !!s.writable;
    row.querySelector('.rm').onclick = function(){row.remove();};
    return row;
  }

  var initial = window.TOOL_INITIAL || {};
  document.getElementById('f_id').value = initial.id||'';
  document.getElementById('f_command').value = initial.command||'';
  document.getElementById('f_image').value = initial.image||'';
  document.getElementById('f_port').value = initial.port||'';
  var ops = document.getElementById('ops');
  (initial.operations && initial.operations.length ? initial.operations : [{}]).forEach(function(o){ops.appendChild(opCard(o));});
  var secs = document.getElementById('secrets');
  (initial.secrets||[]).forEach(function(s){secs.appendChild(secRow(s));});
  document.getElementById('add-op').onclick = function(){ops.appendChild(opCard());};
  document.getElementById('add-secret').onclick = function(){secs.appendChild(secRow());};

  document.getElementById('tool-form').addEventListener('submit', function(){
    var tool = {
      id: document.getElementById('f_id').value,
      type: 'rest',
      command: document.getElementById('f_command').value,
      image: document.getElementById('f_image').value,
      port: document.getElementById('f_port').value,
      operations: [].map.call(ops.querySelectorAll('.opcard'), function(card){
        return {name: card.querySelector('.op-name').value,
                risk: card.querySelector('.op-risk').value,
                description: card.querySelector('.op-desc').value,
                args: [].map.call(card.querySelectorAll('.argrow'), function(r){
                  return {name: r.querySelector('.arg-name').value,
                          type: r.querySelector('.arg-type').value,
                          required: r.querySelector('.arg-req').checked,
                          description: r.querySelector('.arg-desc').value};
                })};
      }),
      secrets: [].map.call(secs.querySelectorAll('.secrow'), function(r){
        return {name: r.querySelector('.sec-name').value,
                field: r.querySelector('.sec-field').value,
                writable: r.querySelector('.sec-writable').checked};
      })
    };
    document.getElementById('tool_json').value = JSON.stringify(tool);
  });
})();
"""


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="_csrf" value="{esc(csrf)}">'


def page(title: str, body: str, *, user: str | None, csrf: str = "") -> str:
    nav = (
        f"<form method='post' action='/logout'>{_csrf_field(csrf)}"
        f"<span class='muted'>{esc(user)}</span> <button>Sign out</button></form>"
        if user else ""
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{esc(title)} · Toolstack Admin</title>"
        f"<style>{_CSS}</style><script>{_JS}</script></head>"
        f"<body><header><h1>Toolstack Admin</h1>{nav}</header>"
        f"<main>{body}</main></body></html>"
    )


def login_view(*, error: str | None = None) -> str:
    msg = f"<div class='error'>{esc(error)}</div>" if error else ""
    body = f"""
<form method="post" action="/login" class="login">
  {msg}
  <label>Username <input name="username" autocomplete="username" required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>"""
    return page("Sign in", body, user=None)


def _alerts(banner: str | None, error: str | None) -> str:
    out = ""
    if banner:
        out += f"<div class='banner'>{banner}</div>"  # banner is pre-escaped by the caller
    if error:
        out += f"<div class='error'>{esc(error)}</div>"
    return out


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
    log_html = (f"<details><summary>Broker log</summary><pre>{esc(log_tail)}</pre></details>"
                if log_tail else "")
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


def _callers_section(callers, csrf: str) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{esc(c['name'])}</td>"
        f"<td>{'revoked' if c['revoked_at'] else 'active'}</td>"
        "<td class='actions'>"
        f"<a class='button' href='/callers/{esc(c['name'])}/policy'>Policy</a>"
        f"<form method='post' action='/callers/refresh-token' class='inline-form'>{_csrf_field(csrf)}"
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
    rows = "".join(
        "<tr>"
        f"<td><code>{esc(t['token_hash'][:12])}…</code></td>"
        f"<td>{esc(t['caller'])}</td>"
        f"<td>{'revoked' if t['revoked_at'] else 'active'}</td>"
        "<td>"
        f"<form method='post' action='/tokens/revoke' class='inline-form'>{_csrf_field(csrf)}"
        f"<input type='hidden' name='prefix' value='{esc(t['token_hash'][:12])}'>"
        "<button type='submit'>Revoke</button></form></td>"
        "</tr>"
        for t in tokens
    ) or "<tr><td colspan='4' class='muted'>No tokens yet.</td></tr>"
    return ("<section><h2>Tokens</h2>"
            "<table><thead><tr><th>Hash prefix</th><th>Caller</th><th>Status</th><th></th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")


def _requests_section(requests, caller_names) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{esc(r['id'])}</td>"
        f"<td>{esc(caller_names.get(r['caller_id'], r['caller_id']))}</td>"
        f"<td>{esc(r['tool'])}.{esc(r['op'])}</td>"
        f"<td>{esc(r['status'])}</td>"
        "</tr>"
        for r in requests
    ) or "<tr><td colspan='4' class='muted'>No requests yet.</td></tr>"
    return ("<section><h2>Recent requests</h2>"
            "<table><thead><tr><th>#</th><th>Caller</th><th>Operation</th><th>Status</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")


def _audit_section(events) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{esc(e['component'])}.{esc(e['event_type'])}</td>"
        f"<td>{esc(e['outcome'])}</td>"
        f"<td>{esc(e['request_id'] if e['request_id'] is not None else '')}</td>"
        f"<td><code>{esc(json.dumps(e['details']))}</code></td>"
        "</tr>"
        for e in events
    ) or "<tr><td colspan='4' class='muted'>No audit events yet.</td></tr>"
    return ("<section><h2>Audit</h2>"
            "<table><thead><tr><th>Event</th><th>Outcome</th><th>Req</th><th>Details</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>")


def dashboard_view(*, user, csrf, broker, log_tail, config, callers, tokens,
                   requests, audit, caller_names, banner=None, error=None) -> str:
    body = (
        _alerts(banner, error)
        + _broker_section(broker, log_tail, config, csrf)
        + _callers_section(callers, csrf)
        + _tokens_section(tokens, csrf)
        + _requests_section(requests, caller_names)
        + _audit_section(audit)
    )
    return page("Dashboard", body, user=user, csrf=csrf)


def config_view(*, user, csrf, config, error=None) -> str:
    err = f"<div class='error'>{esc(error)}</div>" if error else ""

    def field(name, label, value, *, kind="text", placeholder="") -> str:
        ph = f" placeholder='{esc(placeholder)}'" if placeholder else ""
        return (f"<label class='field'>{esc(label)}"
                f"<input name='{esc(name)}' type='{kind}' value='{esc(value)}'{ph}></label>")

    nod_set = "set" if config.nod_token else "not set"
    body = (
        f"{err}<section><h2>Broker run config</h2>"
        "<form method='post' action='/config'>"
        f"{_csrf_field(csrf)}"
        f"{field('port', 'Broker port', config.port)}"
        f"{field('db_path', 'Database path', config.db_path)}"
        f"{field('tools_root', 'Tools root', config.tools_root)}"
        f"{field('nod_url', 'nod URL', config.nod_url)}"
        f"<label class='field'>nod token (currently {esc(nod_set)})"
        f"<input name='nod_token' type='password' placeholder='(unchanged — leave blank to keep)'></label>"
        f"{field('nod_callback_url', 'nod callback URL', config.nod_callback_url)}"
        f"{field('nod_channel', 'nod channel', config.nod_channel, placeholder='default')}"
        f"{field('approval_ttl', 'Approval TTL (seconds)', config.approval_ttl)}"
        f"{field('rate_limit', 'Rate limit (per caller/min, 0=off)', config.rate_limit)}"
        "<div class='actions'><button type='submit'>Save config</button>"
        "<a class='button' href='/'>Back</a></div>"
        "<p class='muted'>Saving does not restart the broker — restart it from the dashboard to apply changes.</p>"
        "</form></section>"
    )
    return page("Config", body, user=user, csrf=csrf)


def tools_view(*, user, csrf, tools, tools_root, banner=None, error=None) -> str:
    def action(tool_id, act, label, disabled):
        d = " disabled" if disabled else ""
        return (f"<form method='post' action='/toolyard/tools/{esc(tool_id)}/{act}' class='inline-form'>"
                f"{_csrf_field(csrf)}<button type='submit'{d}>{esc(label)}</button></form>")

    rows = ""
    for t in tools:
        if t["running"]:
            state = ("running" if t["alive"] else "running?")
            cls = "ok" if t["alive"] else "bad"
        else:
            state, cls = "stopped", "muted"
        running = t["running"]
        remove = ""
        if t.get("removable"):
            remove = (
                f"<form method='post' action='/tools/{esc(t['id'])}/remove' class='inline-form' "
                "onsubmit=\"return confirm('Unregister this tool? Its files stay on disk.')\">"
                f"{_csrf_field(csrf)}<button type='submit'>Remove</button></form>"
            )
        rows += (
            "<tr>"
            f"<td><strong>{esc(t['id'])}</strong></td>"
            f"<td>{esc(t['port'])}</td>"
            f"<td><span class='pill {cls}'>{esc(state)}</span></td>"
            f"<td><code>{esc(t.get('path', ''))}</code></td>"
            "<td class='actions'>"
            f"<a class='button' href='/tools/{esc(t['id'])}/edit'>Edit</a>"
            f"{action(t['id'], 'start', 'Start', running)}"
            f"{action(t['id'], 'stop', 'Stop', not running)}"
            f"{action(t['id'], 'restart', 'Restart', not running)}"
            f"{remove}"
            "</td></tr>"
        )
    rows = rows or "<tr><td colspan='5' class='muted'>No tools defined yet.</td></tr>"
    body = (
        _alerts(banner, error)
        + "<section><div class='row'><a class='button' href='/'>Back</a>"
        f"<h2>Tools</h2><span class='muted'>root: <code>{esc(tools_root)}</code></span>"
        "<a class='button' href='/tools/new'>Add tool</a></div>"
        "<table><thead><tr><th>Tool</th><th>Port</th><th>State</th><th>Directory</th><th>Actions</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "<p class='muted'>Starting a tool resolves its secrets and runs it. A newly added or "
        "edited tool is only registered after the broker is restarted (its registry is read at startup).</p>"
        "</section>"
    )
    return page("Tools", body, user=user, csrf=csrf)


def policy_view(*, user, csrf, caller, ops_by_tool, current, error=None) -> str:
    err = f"<div class='error'>{esc(error)}</div>" if error else ""
    tool_policies = current.get("tools", {})
    sections = [
        f"{err}<form method='post' action='/callers/{esc(caller)}/policy'>",
        _csrf_field(csrf),
        "<section class='row'>"
        f"<a class='button' href='/'>Back</a>"
        f"<strong>Policy for {esc(caller)}</strong>"
        "<button type='button' onclick=\"setAll('allow')\">Allow all</button>"
        "<button type='button' onclick=\"setAll('review')\">Review all</button>"
        "<button type='button' onclick=\"setAll('deny')\">Deny all</button>"
        "<button type='submit'>Save policy</button>"
        "</section>",
    ]
    if not ops_by_tool:
        sections.append("<section><p class='muted'>No tools found in the configured tools "
                        "root. Start the broker with a valid tools root to manage policy.</p></section>")
    for tool, ops in sorted(ops_by_tool.items()):
        current_ops = tool_policies.get(tool, {})
        op_rows = []
        for op in ops:
            name = op["op"]
            effect = current_ops.get(name, "deny")
            select = (f"<select name='op__{esc(tool)}__{esc(name)}'>"
                      + "".join(
                          f"<option value='{v}'{' selected' if effect == v else ''}>{v.title()}</option>"
                          for v in ("allow", "review", "deny"))
                      + "</select>")
            op_rows.append(
                "<tr>"
                f"<td>{esc(name)}</td>"
                f"<td><span class='risk {esc(op['risk'])}'>{esc(op['risk'])}</span></td>"
                f"<td>{esc(op.get('description', ''))}</td>"
                f"<td>{select}</td>"
                "</tr>"
            )
        sections.append(
            "<section><div class='row'>"
            f"<h2>{esc(tool)}</h2>"
            f"<button type='button' onclick=\"setTool('{esc(tool)}','allow')\">Allow all</button>"
            f"<button type='button' onclick=\"setTool('{esc(tool)}','review')\">Review all</button>"
            f"<button type='button' onclick=\"setTool('{esc(tool)}','deny')\">Deny all</button>"
            "</div>"
            "<table><thead><tr><th>Operation</th><th>Risk</th><th>Description</th><th>Effect</th></tr></thead>"
            f"<tbody>{''.join(op_rows)}</tbody></table></section>"
        )
    sections.append("</form>")
    return page(f"Policy · {caller}", "".join(sections), user=user, csrf=csrf)


def tool_editor_view(*, user, csrf, mode, tool, dir_value="", error=None) -> str:
    """The Add/Edit tool form. ``mode`` is "new" or "edit"; ``tool`` pre-fills the
    fields (empty dict for a blank new tool). The repeating operation/secret rows
    are built and serialized by the editor JS into the hidden tool_json field."""
    err = f"<div class='error'>{esc(error)}</div>" if error else ""
    action = "/tools/new" if mode == "new" else f"/tools/{esc(tool.get('id', ''))}/edit"
    if mode == "new":
        dir_field = ("<label class='field'>Tool directory (absolute path on the server)"
                     f"<input name='dir' value='{esc(dir_value)}' placeholder='/srv/tools/weather' required>"
                     "</label><p class='muted'>The directory must already exist and hold your tool's "
                     "code (for a process tool) — the panel writes only <code>toolyard.toml</code> into it.</p>")
        id_attr = ""
    else:
        dir_field = (f"<input type='hidden' name='dir' value='{esc(dir_value)}'>"
                     f"<p class='muted'>Directory: <code>{esc(dir_value)}</code></p>")
        id_attr = " readonly"  # renaming a tool would orphan its caller policies
    initial = json.dumps(tool).replace("</", "<\\/")  # safe to embed in <script>
    body = (
        f"{err}<section><div class='row'><a class='button' href='/tools'>Back</a>"
        f"<h2>{'Add tool' if mode == 'new' else 'Edit tool: ' + esc(tool.get('id', ''))}</h2></div>"
        f"<form id='tool-form' method='post' action='{action}'>"
        f"{_csrf_field(csrf)}{dir_field}"
        f"<label class='field'>id <input id='f_id' placeholder='weather'{id_attr} required></label>"
        "<label class='field'>entrypoint command (process backend)"
        "<input id='f_command' placeholder='python3 app.py'></label>"
        "<label class='field'>image (docker backend, optional)"
        "<input id='f_image' placeholder='ghcr.io/owner/tool:tag'></label>"
        "<label class='field'>port <input id='f_port' type='number' placeholder='4700' required></label>"
        "<h3>Operations</h3><div id='ops'></div>"
        "<button type='button' id='add-op'>Add operation</button>"
        "<h3>Secrets <span class='muted'>— declarations only; values stay in your secrets file</span></h3>"
        "<div id='secrets'></div><button type='button' id='add-secret'>Add secret</button>"
        "<input type='hidden' name='tool_json' id='tool_json'>"
        "<div class='actions'><button type='submit'>Save tool</button>"
        "<a class='button' href='/tools'>Cancel</a></div></form>"
        "<p class='muted'>Saving writes <code>toolyard.toml</code> to the directory and registers it. "
        "Restart the broker (dashboard) to pick it up, then grant a caller access in its policy.</p>"
        "</section>"
        f"<script>window.TOOL_INITIAL = {initial};</script>"
        f"<script>{_TOOL_EDITOR_JS}</script>"
    )
    return page("Add tool" if mode == "new" else "Edit tool", body, user=user, csrf=csrf)
