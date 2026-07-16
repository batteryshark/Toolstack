"""The broker run-config editor."""

from __future__ import annotations

from .layout import _csrf_field, esc, page


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
        f"<input name='nod_token' type='password' placeholder='(unchanged, leave blank to keep)'></label>"
        f"{field('nod_channel', 'nod channel', config.nod_channel, placeholder='default')}"
        f"{field('approval_ttl', 'Approval TTL (seconds)', config.approval_ttl)}"
        f"{field('rate_limit', 'Rate limit (per caller/min, 0=off)', config.rate_limit)}"
        "<div class='actions'><button type='submit'>Save config</button>"
        "<a class='button' href='/'>Back</a></div>"
        "<p class='muted'>Saving does not restart the broker; restart it from the dashboard to apply changes.</p>"
        "</form></section>"
    )
    return page("Config", body, user=user, csrf=csrf, nav="config")
