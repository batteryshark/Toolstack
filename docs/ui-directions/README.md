# Toolstack operator — three design directions

**Current: revision 02, chief feedback applied.** Start with [`overview.html`](overview.html), the self-contained three-direction comparison for the chief’s eventual single card, then open [`gallery.html`](gallery.html). No card is sent by this pack. Current screenshots are all under `captures/`; iteration 01 and its superseded evidence are archived in `iterations/01-superseded.zip`. Principal rejections remain **0**.

**Recommendation to chief: 01 · Clear desk.** It retains Toolstack’s navy navigation, blue action color and light form canvas, while making authority and state legible. It is the least disruptive reference for the web, thin desktop shell and native Mac adaptation. This is a recommendation, not a selection.

Open **`gallery.html`** directly; no server, build or dependencies are needed. It is self-contained, with direction, surface, flow and frame selectors. The controls browse designs only; application controls are drawings. Default view is desktop-size, with optional fit-to-width. Hash links preserve a particular frame, for example `gallery.html#b-mac-recover-0`.

## Delivered

- Three directions, each across **admin web, desktop webview shell, and native Mac**.
- Each surface has three primary flows with three frames each: **81 standalone 1440 × 900 SVGs**, all embedded in the gallery.
- Nine representative 1440 × 900 PNGs in `captures/`: a web policy draft, a shell broker-registration confirmation and a native crash screen for **each** direction.
- `acceptance.md`: source/mockup review, projected task paths, limitations and acceptance gates.
- `evidence/`: bundled Norman collector output for each existing surface and the mockups; offscreen rendering results; structural verification.
- `build_gallery.py`: deterministic stdlib design-artifact generator. `capture.py`: optional existing-Chrome offscreen evidence, with a disposable isolated profile. Neither imports or starts Toolstack.

## Directions

### 01 · Clear desk — continuity first

The navy web top bar and light documents remain the visual anchor. The compact form owns the action; caller/tool/operation sit in a header line. Native Mac uses a unified titlebar, tab selection, compact controls and right-aligned actions. The shell uses the web composition exactly.

**Merit:** lower relearning cost and the smallest navigation change. **Tradeoff:** less persistent collection context, with longer document-style screens. **Best fit:** the first bounded reliability uplift.

### 02 · Operator workbench — context first

A persistent navy web rail and collection column keep the selected entity beside the form. The native adaptation uses light source-list sidebars and a unified titlebar; pale blue selection carries identity without competing with the primary action. The shell remains the web workbench.

**Merit:** useful for repeated work across callers/tools without forgetting the selected target. **Tradeoff:** more horizontal space and scanning; this is a larger information-architecture change. The rail is a proposed view organization, not a new backend capability.

### 03 · Guided ledger — sequence first

Retain navy navigation and a pale blue stage rail with labels only. The compact scope line follows the current task. Add, start, register and grant remain separate decisions. Native Mac adapts progression to a light source list and grouped task editor.

**Merit:** strongest first-use explanation of authority transitions. **Tradeoff:** stage navigation can burden experienced operators; stage labels must reflect current facts, not optimistic completion. Avoid adding automation or orchestration to support this design.

## Source basis and assumptions

Read the requested review sections 3–6 in the accepted 24 Oct 2026 Toolstack review (private document), and actual CSS/SwiftUI in the registered checkout. Branch `uplift/ui-design`, source commit `06df1b15c0c8ac996ec8ce4851e674199b124393`.

- `admin/views/assets.py:6–38,58–67`: exact base palette `#0d6efd`, `#172033`, `#f6f7f9`, `#18202a`, white panels, light borders. Mockups darken secondary text to `#526173`; blue remains identity/action, not health.
- `admin/views/layout.py:19–21`: Dashboard / Tools / Config web navigation.
- `admin/views/tools.py:35–41,71–88,94–125`: record vs liveness, start recovery, copying a local folder, separate broker restart for registration.
- `admin/toolyard_ops.py:48–90`: available observations and stale-record recovery path. No invented health endpoint or atomic “install/start/grant” operation.
- `desktop/app.py:54–103,106–126`: ownership-sensitive lifecycle, startup error visibility gap, same web surface.
- `macapp/Sources/ToolstackApp/ToolstackApp.swift:143–165,206–255,344–355,448–598`: tabs, caller actions, misleading running indicator, policy load/save/dismiss behavior.
- `admin/views/tools.py:149–159` and native `ToolstackKit/ApiClient.swift:120–122`: OpenAPI exists; native authoring signifier is proposed, gated on contract repair.

Assumptions: one trusted local admin, existing caller and tool, fake identifiers and paths, a running broker for the add-flow example. “Disabled tool” means disabled **for this caller**, not a stopped process. The admin host path remains explicitly labeled even in the Mac app: a Mac file picker must not imply it can upload a folder to a remote admin. No real secrets, account files or live status were accessed. User-supplied flows are the priority tasks; there is no usage telemetry.

## Non-negotiable behavior for any selected direction

1. **Load gate:** loading/failed policy load cannot enable Save. Failure offers Retry, not an empty editable policy. Preserve all other enabled tools/grants. Never infer empty from missing data.
2. **Drafts:** retain the draft and target on rejected save. Failed navigation/save must not dismiss the editor. Leaving with unsaved edits requires Stay / Discard draft for the named target, with Stay the safe default. On returning, show “Resume policy draft · writer-demo”. Crash/relaunch persistence is unimplemented and cannot be promised without a storage decision and tests; do not persist secrets into browser storage.
3. **Mutation outcomes:** an acknowledged rejection is failed; a lost response is unknown. On unknown save, retain the draft and reload to compare before retrying. The gallery’s rejected-save fixture is distinct from its lost-restart-response fixture.
4. **States:** record present + process absent → Failed / not alive; process present alone → Alive / health unknown; observation unavailable → Unknown with last-known context; explicit negative health observation → Unhealthy; explicit successful health observation → Healthy with observation time and scope. Current tool listing establishes liveness only. Green Healthy must stay unavailable without that evidence. Secret availability is Unknown, not Absent.
5. **Authority:** admin edits caller grants; broker decides action authorization; SPS governs tool secret access. Enabling is followed by explicit operation policy, not Allow all. No stronger isolation or “broker cannot fetch secrets” promise is made.
6. **Registration:** adding copies; starting executes trusted code and triggers runner/SPS lifecycle; broker restart reloads the catalog. Confirm the named broker, warn of interruption, then verify registration. Failure retains the stage; never equate a click or process start with successful catalog registration.
7. **Confirmations:** name target and effect for caller revoke, token rotation, managed-folder removal, broker restart and tool restart. Example: “Rotate token for writer-demo? Existing token stops working; update clients using this caller.” Buttons: Cancel / Rotate writer-demo token. Revoke names the caller and pending approvals it cancels. External-folder unregister must say files stay; managed-folder removal must say files are deleted. Do not put destructive actions beside the normal Save action.
8. **Requests:** inspection/filtering of requests and outcomes only; no audit-delete affordance. Local audit is not described as tamper-proof. A lost tool result must not be labeled safe to retry or automatically replayed. Any future retention management is separately scoped, never smuggled into Requests.
9. **Native authoring:** visible `Author a tool → Import OpenAPI…`. Parsing produces a reviewable draft; no automatic execution or caller grant. Contract repair and native decoder tests precede enabling this entry in the real app.
10. **Shell startup:** separate startup error surface with admin URL, observed failure and Retry / Close; point to diagnostics without claiming the password is definitely missing. Closing stops only a shell-owned admin, never a pre-existing one. The shell owns no parallel policy system.

## Usable now / left

**Usable now:** a portable gallery for review, inspectable vector frames, representative offscreen captures, concise recommendation and bounded behavior requirements.

**Left:** chief presents one selection card; principal chooses a direction; authorized construction and cross-surface contract/state repairs; live keyboard, focus, contrast, VoiceOver, resizing, draft persistence, startup and failure-recovery checks. None is a hidden implementation task in this design handoff.

**Pending effects:** none on the running product. No product implementation, services, architecture, providers, credentials, external posts or cards. Revision-02 milestone is an owned-docs-only local commit, with explicit requested identity; no push. Native session cwd stays at `/Users/batteryshark/Projects/workstack/toolstack`; every source-tool cwd/path used the registered `.worktrees/ui-design` checkout. Principal rejections **0**; at **2**, stop the project. Questions return to parent `ses_e933928afffeKukrMplyUQvz07`, not chief/principal.
