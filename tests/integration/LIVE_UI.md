# LIVE acceptance — KEEP OFF

Code/setup only. Parent HIGH accepted the pin code/tests at 42e37b3 after independent
12 pure tests PASS (0.012s, toolstack-fixture-parent.4x7z39) and actual binary hash
match. Parent sends READY plus the unchanged eight plain steps to chief
`toolstack-live-ui-hands-20261024`; chief alone handles the principal's ONE card.
Never launch the fixture until chief confirms the principal is ready. No
fixture/app/window/listener has been started by this repair worker.

The first admitted parent attempt stopped at COPY re-signing before native or
desktop launch: private HOME prevented lookup of the existing authorized identity.
Parent reports successful cleanup (children empty, backend stopped, no errors or
cleanup uncertainty; independently absent PID/listener and unchanged original).
This was not a principal rejection or a three-surface/manual result. No permission
prompt was observed by the agent, which had no screen-control tools; this does not
establish that no prompt ever appeared. The principal must report ANY prompt to
chief immediately: stop and clean up, with no bypass. Parent will test actual
private COPY signing and verification with apps OFF, then request new chief READY
confirmation. No automatic fixture/app/listener relaunch is authorized.

`python tests/integration/live_ui_fixture.py --prepare` reports installed metadata
without importing GUI modules or creating files. Default and help are also inert.
Future admitted backend command: `python tests/integration/live_ui_fixture.py --serve
--root /private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode/toolstack-live-ui-UNIQUE`.
Use a private interpreter with admin pinned requirements. Backend stops after 20
minutes or Ctrl-C. It leaves its private root for evidence; no automatic deletion.
SPS_SKIP=1 is fake-fixture development mode, **not isolation**. Do not start broker,
tools, add real configuration, or invoke providers/Nod from this fixture.

Future app launch requires explicit `--serve --native-app APP --sign-identity
'Apple Development: EXISTING IDENTITY'` and/or `--desktop`. Before later launching, the helper verifies strict
deep signature and executable SHA256
`28cf9127f93d4ffd30fe7d91d120b862d4e2fc1c3a845b50210bd6a369b18600` for
`Contents/MacOS/ToolstackApp` in the current artifact:
`/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode/toolstack-release-artifacts-parent.PLguZR/source/macapp/build/Toolstack Operator.app`.
This development-signed release-build artifact was built from production source
`78ea9049a3370688b721e7ff3bda31a8b3f184c3`. Parent reports signing with existing
Apple Development identity (name and team withheld), followed by a
separate strict deep verification PASS (valid on disk/designated requirement).
The executable hash was independently read and confirmed for this pin repair;
signature verification was not repeated here. Original artifact remains OFF,
unlaunched, uninstalled and not notarized. This test/doc-only repair changes no
production wheel/native bytes and does not claim a new signed build or a Linux
full-archive qualification of the repair commit.

Parent's actual Linux fourth run at source 78 reported `proof_complete:true`
(onebox/API/MCP Docker Linux and 19 process SPS checks; admin HTTP 200), but the
overall run exited 1 with `restored:false`: three image-user observations remain
unknown, so images and the owned guest proof root were retained. Chief's matching
answer to `toolstack-linux-proof-cleanup-20261024` accepts the fourth Linux functional
witness (Docker/start, all 19 SPS checks, admin HTTP 200). Cleanup remains INCOMPLETE;
it is not itself a release gate, but must be reported before final acceptance.
VM130 stays STOPPED, 8192 MiB / 2 CPUs / onboot=0; production remains healthy.
Parent reports the ONE cleanup-only attempt c1ViDD finished exit 1 at unknown-root
preflight before any images, with removed=[]; all three images and the old root
remain retained. No retry or another boot is authorized. Independent parent checks
confirmed VM130 STOPPED, 8192 MiB / 2 CPUs / onboot=0 and production healthy.
Fixture stays OFF until
chief confirms principal readiness; neither hands nor cleanup PASS is claimed.
Scope remains 68 IDs / Plan 3 of 5 / 0 rejections / one-PR acceptance.

The helper rejects external bundle links/special files, copies the verified original
under the owned root, changes only the COPY bundle identifier to unique
`com.toolstack.operator.fixture.<uuid>`, signs locally with that same explicit
existing identity and `--timestamp=none`, then separately verifies. The original
artifact is unchanged; this is an ephemeral test copy, not a release deliverable.
It records the original hash, copy identifier/path and unique account URL.
Native URL includes `#toolstack-fixture-<uuid>` (HTTP drops the fragment), passed
both through constructed environment and `-ToolstackAdminURL`. Isolated bundle
preferences and unique fake account avoid real preferences/account reads.
Never use open/AppleScript. Helper owns Popen handles and records PID/start
identity using `toolyard.runner._process_identity`; terminate/wait 5s/kill/wait 5s
only identity-matching owned children. For desktop it uses the private interpreter
`-m desktop` with plain fixture URL after bounded backend readiness. No real credential
environment may be inherited. Require a newly allocated fake URL; never enter an
existing real server URL. Only that URL's fake Keychain item may be created and
removed by signout/current API; never enumerate/export/delete other items.

App/backend environments retain private HOME, XDG and TMP settings. Only
`/usr/bin/codesign` commands receive a copy of that allowlisted environment with
HOME set from `pwd.getpwuid(os.getuid()).pw_dir`, solely to locate the existing
authorized signing identity. No ambient environment, credentials or arbitrary
HOME/keychain override is inherited; native/desktop launch environments stay private.

## Manual checklist (eight steps)

1. After admission, record browser/webview plain fake URL and native unique fragment URL/isolated copy identifier; login on all three using admin / FAKE-live-ui-only-password; record versions and observed surface.
2. Tab/Shift-Tab every control: visible focus, logical order, no trap. Inspect actual web 38px/native 32px minimum hit geometry; do not infer full accessibility compliance.
3. Edit FAKE-policy draft, navigate/retry as supported, verify preservation and fresh-comparison unknown state. Record running-intent and stale-comparison cases not run when unavailable without production hooks.
4. Open confirmations; Escape and default Cancel must dismiss without mutation. Check policy/token/tool state before and after.
5. Rotate FAKE-rotate, revoke FAKE-revoke, remove fake-zero and fake-external: verify named target, confirmation and effects; external declaration removal must preserve its directory.
6. Manually toggle VoiceOver as needed; inspect names, roles, order, current state and announcements on all surfaces. Restore manual toggle; no persistent global setting changes.
7. Check native and webview focus transitions and titlebar Close; record window closure separately from process exit (native may retain menu process, then Quit owned process). Exercise startup Retry/Close only with parent-owned bounded failure setup; otherwise mark not run.
8. Sign out each surface, clean only URL-scoped fake login items, Quit owned apps, stop fixture and verify owned PID identities/listener quiescence; preserve manual results and remove only owned root when evidence is retained.

## Observation record (fill manually, never synthesize)

For each step and each surface: `surface | step | pass/fail/not-run | observed
behavior | evidence | PID/start identity | notes`. Initial state: every step NOT RUN.
No synthetic CGEvent/XCTest result counts as manual acceptance.
Runtime metadata verified without GUI imports using approved temp
`toolstack-live-ui-runtime.m7oo4s/venv/bin/python`: Python 3.11.17 (parent),
FastAPI 0.137.1, uvicorn 0.49.0, pywebview 6.2.1, Cocoa/WebKit/pyobjc-core 12.2.2.
Parent exact pins/logs are adjacent to that venv. Current gaps: admitted bounded
HTTP smoke, running-intent and startup-retry reproduction,
all live observations. Failed server thread or uncertain cleanup is never PASS.
No claim is made that shared WebKit XPC processes exit. Default desktop startup
failure/retry behavior is product-owned and must be observed manually later.

Scoped TERM/HUP/INT handlers close admission and route through owned cleanup;
previous handlers are restored. Stop is checked before copy/sign/launch and
during readiness/wait. Cleanup refuses malformed PID, PID <=1, handle mismatch
or unknown/reused start identity. A failed evidence save occurs only after all
owned child cleanup attempts and backend join; uncertainty remains reportable.
