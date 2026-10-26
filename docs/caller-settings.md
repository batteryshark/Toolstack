# Caller settings

Open a caller's **Settings** action, double-click its row or select it and press Return.
Web and desktop use a modal popup; the Mac app uses a native sheet. Both tabs share one
draft and one **Save changes** button.

- **Enabled tools:** switch on a whole tool to enable all its functions. Expand its
  group to exclude individual functions. Enabling is not an Allow grant.
- **Policy:** choose Deny, Review (ask for human approval) or Allow per function.
  Disabled functions retain their policy choices but cannot execute.
- Search tools and functions, or use **Enabled only** and **Needs review**. With any
  search/filter active, **All matches / None matches** act only on the visible matches
  in that tool. Without filters, **All / None** act on the whole tool. Neither grants Allow.

Both tabs, filters and edits are kept on this device across app/window closure. Drafts
are scoped to the server installation, operator and caller identity, not just the caller
name. No bearer tokens, passwords, CSRF values or workload secrets are stored in drafts.
Browser private mode or clearing website data removes browser drafts. The desktop shell
uses persistent website storage; the Mac app keeps owner-only files in Application Support.
If storage fails, the editor warns you to keep the window open or save before quitting.

Cancel/Escape with edits offers Stay (the safe default), Keep draft and close, or explicit
Discard. Closing the app does not apply a draft. Saving commits both tabs and invalidates
pending approvals in the same SQLite transaction.

## Changed elsewhere and unknown saves

Settings and catalog revisions are checked on Save and observed while the editor is open.
A stale or unavailable observation pauses Save without replacing your draft. **Compare
latest** shows your draft beside the saved state. Only the explicit **Keep my edits on
latest** action rebases your edits; changes you did not edit are retained from the latest
state. You still choose Save afterward. If the server/caller identity changed or functions
disappeared, the old draft is kept and cannot be silently applied to another target.

A timeout or missing/mismatched receipt is **Save outcome unknown**, not proof of failure.
No write is replayed. Compare before deciding whether another save is needed. Interrupted
saves stay blocked after relaunch. Discarding a draft does not undo a write already applied.

## API compatibility

`GET /api/callers/{name}/settings` returns the catalog, policy, installation/caller identity
and revision. `PUT` takes that revision plus catalog-scoped `enabled`, `disabled_functions`
and `tools` maps and commits both tabs together. A stale revision returns 409 without a write.
Unseen tools, functions and policy metadata are preserved, not replaced by the visible form.
The authenticated HTML endpoint uses the same mutation with cookie/CSRF protection.

The older policy/tools routes and CLI remain available. Legacy policies keep their previous
semantics until saved as combined settings. Combined settings use explicit enablement and
function exclusions as execution gates; policy-only updates preserve these gates. To grant
a disabled function, enable it as well as setting its policy. Older tools updates still
drop policies for disabled tools; use combined settings to retain choices while disabling.
