"""Page shell and the escaping/CSRF primitives every view builds on."""

from __future__ import annotations

import html
from typing import Any

from .assets import _CSS, _JS


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="_csrf" value="{esc(csrf)}">'


_NAV_LINKS = (("/", "Dashboard", "dashboard"),
              ("/tools", "Tools", "tools"),
              ("/config", "Config", "config"))


def page(title: str, body: str, *, user: str | None, csrf: str = "", nav: str = "") -> str:
    if user:
        links = "".join(
            f"<a href='{href}'{' class=\"active\"' if nav == key else ''}>{esc(label)}</a>"
            for href, label, key in _NAV_LINKS)
        header = (
            f"<div class='brand'><h1>Toolstack Admin</h1><nav class='appnav'>{links}</nav></div>"
            f"<form method='post' action='/logout'>{_csrf_field(csrf)}"
            f"<span class='muted'>{esc(user)}</span> <button>Sign out</button></form>"
        )
    else:
        header = "<h1>Toolstack Admin</h1>"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{esc(title)} · Toolstack Admin</title>"
        f"<style>{_CSS}</style><script>{_JS}</script></head>"
        f"<body><header>{header}</header>"
        f"<main>{body}</main></body></html>"
    )
