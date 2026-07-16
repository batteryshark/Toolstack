"""Small HTML fragments shared across more than one view."""

from __future__ import annotations

from .layout import esc


def _alerts(banner: str | None, error: str | None) -> str:
    out = ""
    if banner:
        out += f"<div class='banner'>{banner}</div>"  # banner is pre-escaped by the caller
    if error:
        out += f"<div class='error'>{esc(error)}</div>"
    return out
