# Operator-approved secret declarations

The tools page shows secret names and backend items beside Start, never values.
Start and Restart ask for confirmation: a started tool runs with this host's
credentials, so only start tools you trust. Cancel is the default web action.

Source updates always retain the local secret declarations, including an empty
list. The update result includes `secret_declarations_changed` and a
`secret_declarations` object containing `kept` and `upstream` lists. The web
update banner warns when they differ. Review and save an explicit Edit to adopt
changes; upstream declarations never become grants merely by updating code.

Authoring and import reject a nonempty secret `item` different from the tool id
unless the operator checks the explicit confirmation. JSON clients send
`confirm_secret_items: true` alongside the request, outside the manifest.
An empty item retains the default of the tool id.

Each process Start records declarations and the SHA-256 manifest digest in
private toolyard state. SPS recovery and automatic process reconciliation use
that snapshot even if the manifest changes on disk. An explicit operator Edit
updates the recorded declarations; Start/Restart adopts the current manifest.
Older running records without snapshots require an operator stop/start rather
than having grants inferred from disk during recovery.

Admin and runner read only `SP_HOST`, `SP_PORT`, `SP_TLS_CA`, and `SP_SECRET`
from the top-level SPS TOML env file, which must remain a regular mode-0600 file.
Provider tables are not decoded. A registration-only env file can therefore be
used via `TOOLSTACK_SPS_ENV`; provider configuration remains SPS's responsibility.
TLS verification is enabled by default. `TOOLSTACK_SPS_VERIFY=0` is refused
unless `TOOLSTACK_SPS_DEV=1` is also set explicitly for trusted development.
This does not change `TOOLSTACK_SPS_SKIP=1`, which skips SPS entirely.
