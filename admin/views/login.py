"""The sign-in page."""

from __future__ import annotations

from .layout import esc, page


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
