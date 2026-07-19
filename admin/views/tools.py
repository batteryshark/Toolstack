"""Tool management: the tool list, add-from-source, and the author/edit form."""

from __future__ import annotations

import json

from .assets import _TOOL_EDITOR_JS
from .components import _alerts
from .layout import _csrf_field, esc, page


def _secret_backend_note(sps: dict | None) -> str:
    """A muted line telling the operator where secrets resolve from, so they can see at a
    glance which SPS plugin the tool's secrets live in."""
    if not sps:
        return ""
    plugin = sps.get("plugin", "")
    if plugin in ("infisical", "hashicorp_vault", "localfile"):
        host = esc(sps.get("host", ""))
        port = sps.get("port", "")
        return (f"<p class='muted'>SPS plugin: <strong>{esc(plugin)}</strong> "
                f"(<code>{host}:{port}</code>). Each tool pulls its secrets from SPS at boot via "
                "the per-tool E_SECRET the runner mints at start.</p>")
    return ""


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
        update = ""
        src = t.get("source")
        if src:
            origin = esc(src.get("url") or src.get("source") or src.get("type", "source"))
            update = (
                f"<form method='post' action='/tools/{esc(t['id'])}/update-source' class='inline-form' "
                f"onsubmit=\"return confirm('Re-pull {esc(t['id'])} from its source? Your description and "
                "secret declarations are kept.')\">"
                f"{_csrf_field(csrf)}<button type='submit' title='source: {origin}'>Update</button></form>"
            )
        # An external (tool_dirs) tool is unregistered (files left on disk); a managed tool under
        # the tools root is deleted. Show the action for both, with the matching verb + warning.
        if t.get("removable"):
            confirm, label = "Unregister this tool? Its files stay on disk.", "Unregister"
        else:
            confirm, label = "Remove this tool? This deletes its folder and cannot be undone.", "Remove"
        remove = (
            f"<form method='post' action='/tools/{esc(t['id'])}/remove' class='inline-form' "
            f"onsubmit=\"return confirm('{confirm}')\">"
            f"{_csrf_field(csrf)}<button type='submit'>{label}</button></form>"
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
            f"{update}"
            f"{remove}"
            "</td></tr>"
        )
    rows = rows or "<tr><td colspan='5' class='muted'>No tools defined yet.</td></tr>"
    body = (
        _alerts(banner, error)
        + "<section><div class='row'><a class='button' href='/'>Back</a>"
        f"<h2>Tools</h2><span class='muted'>root: <code>{esc(tools_root)}</code></span>"
        "<a class='button' href='/tools/new'>Author a tool</a>"
        "<a class='button' href='/tools/add'>Add from source</a></div>"
        "<table><thead><tr><th>Tool</th><th>Port</th><th>State</th><th>Directory</th><th>Actions</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "<p class='muted'>Starting a tool resolves its secrets and runs it. A newly added or "
        "edited tool is only registered after the broker is restarted (its registry is read at startup).</p>"
        "</section>"
    )
    return page("Tools", body, user=user, csrf=csrf, nav="tools")


def tool_add_view(*, user, csrf, source_value="", repo_value="", error=None) -> str:
    """Add an existing tool (one that already has a ``toolyard.toml``) by copying it from a local
    folder or cloning it from git into the tools root, recording its source for later Update."""
    err = f"<div class='error'>{esc(error)}</div>" if error else ""
    body = (
        f"{err}"
        "<section><div class='row'><a class='button' href='/tools'>Back</a>"
        "<h2>Add a tool from a source</h2></div>"
        "<p class='muted'>Copy a tool that already has a <code>toolyard.toml</code> into the tools "
        "root, so the broker auto-discovers it. Its source is recorded so you can <strong>Update</strong> "
        "(re-pull) it later. To hand-author a manifest instead, use "
        "<a href='/tools/new'>Author a tool</a>.</p>"

        "<h3>From a local folder</h3>"
        f"<form method='post' action='/tools/add-source'>{_csrf_field(csrf)}"
        "<input type='hidden' name='kind' value='path'>"
        "<label class='field'>Folder path <span class='muted'>(absolute, on the server)</span>"
        f"<input name='source' value='{esc(source_value)}' placeholder='/srv/tools/weather' required></label>"
        "<div class='actions'><button type='submit'>Add from folder</button></div></form>"

        "<h3>From a Git repository</h3>"
        f"<form method='post' action='/tools/add-source'>{_csrf_field(csrf)}"
        "<input type='hidden' name='kind' value='github'>"
        "<label class='field'>Repository URL"
        f"<input name='repo' value='{esc(repo_value)}' placeholder='https://github.com/owner/repo' required></label>"
        "<label class='field'>Subdirectory <span class='muted'>(optional: if the tool lives in a subfolder)</span>"
        "<input name='subdir' placeholder='tools/weather'></label>"
        "<label class='field'>Ref <span class='muted'>(optional: branch, tag, or commit)</span>"
        "<input name='ref' placeholder='main'></label>"
        "<div class='actions'><button type='submit'>Clone and add</button></div></form>"
        "<p class='muted'>Cloned code is copied in, never executed by the panel. Restart the broker to "
        "register the new tool.</p>"
        "</section>"
    )
    return page("Add tool", body, user=user, csrf=csrf, nav="tools")


def tool_editor_view(*, user, csrf, mode, tool, dir_value="", backend=None, error=None) -> str:
    """The Add/Edit tool form. ``mode`` is "new" or "edit"; ``tool`` pre-fills the
    fields (empty dict for a blank new tool). The repeating operation/secret rows
    are built and serialized by the editor JS into the hidden tool_json field.
    ``backend`` is a display-only summary of the active secret backend."""
    err = f"<div class='error'>{esc(error)}</div>" if error else ""
    action = "/tools/new" if mode == "new" else f"/tools/{esc(tool.get('id', ''))}/edit"
    if mode == "new":
        dir_field = ("<label class='field'>Tool directory (absolute path on the server)"
                     f"<input name='dir' value='{esc(dir_value)}' placeholder='/srv/tools/weather' required>"
                     "</label><p class='muted'>The directory must already exist and hold your tool's "
                     "code (for a process tool); the panel writes only <code>toolyard.toml</code> into it.</p>")
        id_attr = ""
    else:
        dir_field = (f"<input type='hidden' name='dir' value='{esc(dir_value)}'>"
                     f"<p class='muted'>Directory: <code>{esc(dir_value)}</code></p>")
        id_attr = " readonly"  # renaming a tool would orphan its caller policies
    initial = json.dumps(tool).replace("</", "<\\/")  # safe to embed in <script>
    importer = ""
    if mode == "new":
        importer = (
            "<details id='import-openapi'><summary>Import OpenAPI</summary>"
            "<p class='muted'>Paste a JSON OpenAPI/Swagger spec; YAML works when PyYAML is installed.</p>"
            "<textarea id='oai-spec' rows='8' placeholder='{\"openapi\":\"3.0.0\",...}'></textarea>"
            "<div class='actions'><button type='button' id='oai-parse'>Parse spec</button></div>"
            "<div id='oai-error' class='error' hidden></div>"
            "<div id='oai-results' hidden><p id='oai-base' class='muted'></p>"
            "<div id='oai-ops'></div>"
            "<button type='button' id='oai-add'>Use selected operations</button></div>"
            "</details>"
        )
    body = (
        f"{err}<section><div class='row'><a class='button' href='/tools'>Back</a>"
        f"<h2>{'Add tool' if mode == 'new' else 'Edit tool: ' + esc(tool.get('id', ''))}</h2></div>"
        f"{importer}"
        f"<form id='tool-form' method='post' action='{action}'>"
        f"{_csrf_field(csrf)}{dir_field}"
        f"<label class='field'>id <input id='f_id' placeholder='weather'{id_attr} required></label>"
        "<label class='field'>transport <span class='muted'>(api = POST /v1/actions; "
        "mcp = streamable-HTTP MCP server; rest = generic forwarder)</span>"
        "<select id='f_type'></select></label>"
        "<label class='field'>description <span class='muted'>(optional)</span>"
        "<textarea id='f_description' rows='2' placeholder='what this tool does'></textarea></label>"
        "<div id='rest-fields' hidden>"
        "<label class='field'>base URL <span class='muted'>(REST upstream)</span>"
        "<input id='f_base_url' placeholder='https://api.example.com/v1'></label>"
        "</div>"
        "<label class='field'>entrypoint command <span class='muted'>(process backend)</span>"
        "<input id='f_command' placeholder='python3 app.py'></label>"
        "<label class='field'>image <span class='muted'>(docker backend)</span>"
        "<input id='f_image' placeholder='ghcr.io/owner/tool:tag'></label>"
        "<p class='muted'>Leave both blank for a docker tool that builds the "
        "<code>Dockerfile</code> in its own directory.</p>"
        "<label class='field'>port <input id='f_port' type='number' placeholder='4700' required></label>"
        "<div class='row'><h3>Operations</h3>"
        "<button type='button' id='ops-expand' class='linkish'>Expand all</button>"
        "<button type='button' id='ops-collapse' class='linkish'>Collapse all</button></div>"
        "<div id='ops'></div>"
        "<button type='button' id='add-op'>Add operation</button>"
        "<h3>Secrets <span class='muted'>(declarations only; values stay in the secret backend)</span></h3>"
        f"{_secret_backend_note(backend)}"
        "<div class='sechead'>"
        "<span>Name <span class='muted'>(file the tool reads)</span></span>"
        "<span>Field <span class='muted'>(backend key)</span></span>"
        "<span>Path <span class='muted'>(Infisical)</span></span>"
        "<span class='colcenter'>Writable</span><span></span></div>"
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
    return page("Add tool" if mode == "new" else "Edit tool", body, user=user, csrf=csrf, nav="tools")
