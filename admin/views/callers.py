"""Per-caller tool enablement and the per-operation policy editor."""

from __future__ import annotations

from .layout import _csrf_field, esc, page


def caller_tools_view(*, user, csrf, caller, all_tools, enabled, error=None) -> str:
    err = f"<div class='error'>{esc(error)}</div>" if error else ""
    rows = "".join(
        "<tr>"
        f"<td><input type='checkbox' name='tool__{esc(tool)}'"
        f"{' checked' if tool in enabled else ''}></td>"
        f"<td>{esc(tool)}</td>"
        f"<td class='muted'>{len(ops)} operation{'' if len(ops) == 1 else 's'}</td>"
        "</tr>"
        for tool, ops in all_tools
    ) or "<tr><td colspan='3' class='muted'>No tools registered on the broker.</td></tr>"
    body = (
        f"{err}<form method='post' action='/callers/{esc(caller)}/tools'>"
        f"{_csrf_field(csrf)}"
        "<section class='row'>"
        "<a class='button' href='/'>Back</a>"
        f"<strong>Tools for {esc(caller)}</strong>"
        f"<a class='button' href='/callers/{esc(caller)}/policy'>Edit policy</a>"
        "<button type='submit'>Save tools</button>"
        "</section>"
        "<section><p class='muted'>Enabling a tool lets you grant its operations on the "
        "policy page. Disabling a tool revokes the caller's access (its granted operations "
        "are cleared).</p>"
        "<table><thead><tr><th>Enabled</th><th>Tool</th><th>Operations</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></section>"
        "</form>"
    )
    return page(f"Tools · {caller}", body, user=user, csrf=csrf)


def policy_view(*, user, csrf, caller, ops_by_tool, current, has_tools=True, error=None) -> str:
    err = f"<div class='error'>{esc(error)}</div>" if error else ""
    tool_policies = current.get("tools", {})
    sections = [
        f"{err}<form id='policy-form' method='post' action='/callers/{esc(caller)}/policy'>",
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
        if has_tools:
            msg = ("No tools enabled for this caller yet. "
                   f"<a href='/callers/{esc(caller)}/tools'>Enable tools</a> first, "
                   "then set per-operation policy here.")
        else:
            msg = ("No tools found in the configured tools root. Start the broker with a "
                   "valid tools root to manage policy.")
        sections.append(f"<section><p class='muted'>{msg}</p></section>")
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
