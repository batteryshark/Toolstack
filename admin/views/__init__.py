"""Server-rendered HTML for the admin app.

Plain f-strings + ``html.escape`` (the same approach as the old broker-panel), with no
template engine to learn, and every dynamic value is escaped at the point of
interpolation. Static CSS/JS are plain string constants (not f-strings) so their
braces need no escaping. Every form carries a CSRF token via ``_csrf_field``.

These functions only build strings; the server layer decides status codes and
wraps them in responses.

Split by screen: :mod:`layout` (page shell + esc/CSRF), :mod:`components` (shared
fragments), :mod:`assets` (CSS/JS), and one module per screen (:mod:`login`,
:mod:`dashboard`, :mod:`config`, :mod:`tools`, :mod:`callers`). This module re-exports
the public surface, so callers keep importing ``views.<name>`` unchanged.
"""

from .callers import caller_tools_view, policy_view
from .config import config_view
from .dashboard import dashboard_view, token_reveal_banner
from .layout import esc, page
from .login import login_view
from .tools import tool_add_view, tool_editor_view, tools_view

__all__ = [
    "caller_tools_view",
    "config_view",
    "dashboard_view",
    "esc",
    "login_view",
    "page",
    "policy_view",
    "token_reveal_banner",
    "tool_add_view",
    "tool_editor_view",
    "tools_view",
]
