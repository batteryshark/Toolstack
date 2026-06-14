---
name: toolstack
description: Call tools through the Toolstack broker. Use whenever you need to take an action that runs behind the broker (anything reachable as a <tool>.<op>) — discover what you can call, call it, and handle approval-gated operations. One generic client for all tools; tool schemas are fetched on demand to stay token-light.
---

# toolstack

You reach tools only through the broker — never the tools directly. One CLI covers
every tool. Schemas are fetched on demand, so don't pre-load tool docs.

Config (already set in the environment): `TOOLSTACK_URL`, and `TOOLSTACK_TOKEN` or
`TOOLSTACK_TOKEN_FILE` (your caller's bearer token). Run `toolstack` = `python3 -m client.toolstack`.

## Workflow

1. **Discover** only when you don't already know the op:
   ```bash
   toolstack tools                 # the ops you're allowed to call: tool.op  effect  risk  description
   toolstack describe media.skip   # that op's args, on demand
   ```
2. **Call** it. Pass the JSON arguments object **shell-safely** — via a quoted
   heredoc (handles quotes, newlines, `$`, backticks with no escaping) or
   `--args-file`. Use inline JSON only for trivial args.
   ```bash
   toolstack call media.play <<'JSON'
   {"note": "any 'quotes', \"quotes\", $vars, and
   multi-line text — passed literally, no escaping"}
   JSON

   toolstack call media.play --args-file args.json   # large/awkward data (write the file first)
   toolstack call media.play '{"track":"x"}'         # trivial args only
   ```
   Output is the broker's JSON. `effect` from `tools` tells you what to expect:
   - `allow` → runs now, returns `{"status":"ok","result":...}`.
   - `review` → returns `{"status":"pending_approval","request_id":N}`; a human must decide.
3. **Wait** on a review op (or pass `--wait` to `call`):
   ```bash
   toolstack wait N
   ```
   Resolves to `ok` (with `result`), `denied`, or `expired`. On a decision it includes
   the human's `approver` and `note` — read the note.

## Comments / reasons — be sparse and reactive

A `--reason` is shown to the human who approves; it is NOT for routine calls.

- **Allowed ops:** never pass `--reason` (no human is reading it — wasted tokens).
- **Review ops:** pass one short `--reason` explaining the intent.
- **After a rejection:** read the approver's `note`. If you retry, pass a `--reason`
  that *responds to that note*. Retry at most once; if denied again, stop and report
  the note to the user. Do not resubmit repeatedly with new comments.

## Rules

- Don't call raw broker endpoints; use this CLI.
- For any argument value with quotes, newlines, or special characters, use the
  heredoc or `--args-file` — never hand-build a quoted JSON string on the command line.
- Don't guess args — `describe` first if unsure.
- A non-zero exit means denied/expired/failed/unavailable; read the JSON for why.
- `429` means you're calling too fast — slow down, don't loop.

## Per-domain skills (optional)

Some tools ship a richer skill with domain workflows; prefer it when present. It
still calls the broker through this same client underneath.
