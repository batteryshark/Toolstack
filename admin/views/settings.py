"""Unified caller settings surface; shared by the browser and desktop shell."""
import json

from .layout import esc, page


def settings_view(*, user, csrf, caller, state):
    if state is None:
        return page("Caller settings", f"<section role='alert'>Settings unavailable · {esc(caller)}. "
                    "Your drafts have not been changed. <a href=''>Retry load</a></section>", user=user, csrf=csrf)
    payload = json.dumps(state).replace("<", "\\u003c")
    return page("Caller settings", "<p><a href='/'>Back to callers</a></p>"
                f"<script type='application/json' id='caller-settings-state'>{payload}</script>", user=user, csrf=csrf)
