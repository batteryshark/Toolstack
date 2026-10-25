# Revision 02 acceptance — design handoff only

Origin `toolstack-ui-directions-20261024`. Chief review, not principal rejection; count **0**. Original evidence is historical in `iterations/01-superseded.zip`. Current `visuals/`, `captures/`, gallery and overview are revision 02. Norman/Norman-audit remain explicitly selected; Nod `PROJECT.md:30–39` governs compact action-first composition. The pre-redesign ranked audit is in `lead/revision-02-source-audit.md`.

## Chief feedback addressed generator-wide

- Eyebrows, scope teaching text, draft philosophy, stage philosophy and both footers removed from all 81 frames. Mockup label appears only in the titlebar.
- Caller/tool/operation folded into a compact header line. No empty Authority scope inspector.
- No permanent health-unknown sentence. No green health inferred from process records. Actionable process failure and **restart outcome unknown** remain explicit.
- One filled-blue primary action per frame; policy value selection and navigation use pale selection states, not primary styling. Named targets, interruption warnings and no-replay confirmation remain.
- Native frames have a unified native titlebar, light source lists/tabs, compact 32px controls and right-aligned dialog actions. Web/shell controls are 38px. These are SVG native-layout proposals, not compiled SwiftUI controls.
- `walkthrough.md` records the five Norman questions, primary action, source-counted cost, first/hundredth/interruption for **each of 81 views**.

## Geometry evidence: real render bounds, not XML proof

`check_geometry.py` loads all 81 SVGs in existing isolated headless Chrome. It calls `getBBox()` for every text, control, container and decoration and records the rectangles in `evidence/geometry.json`.

Rules: every element fits the 1440×900 viewport and its declared parent; all non-ancestor pairs must be disjoint. **Only explicit ancestor/descendant containment is an allowed intentional overlay** (label in button, row text in row, content in panel). No exemption for rails, footers, text or native chrome. A 0.5px edge tolerance excludes touching borders; stroke/antialias pixels are not pixel-segmented. Injected original-style root footer crossing the B rail is rejected by the same checker.

Result: **81 frames, zero unallowed overlaps or parent/viewport overflows; footer regression detected.** This verifies actual installed-font geometry for these static drawings, not product responsive layout or accessibility. Fixed desktop canvas uses horizontal scrolling at smaller gallery widths; laptop reflow is not certified.

## Full-size visual review: all nine current captures

Each file was opened as a 1440×900 image and inspected, not merely generated:

- `a-web-grant-1.png`: scope line and error/action group legible; no inspector/footers.
- `a-shell-add-2.png`: named broker, interruption warning and one primary; same web layout.
- `a-mac-recover-0.png`: native tabs, compact right-aligned actions; record/failure distinct.
- `b-web-grant-1.png`: collection and policy columns fit; no rail-bottom intrusion.
- `b-shell-add-2.png`: selection retained; warning and actions fit detail pane.
- `b-mac-recover-0.png`: native source lists; no footer overlap; failure precedes recovery.
- `c-web-grant-1.png`: stages contain labels only; error and selected policy legible.
- `c-shell-add-2.png`: registration stage, broker target and interruption warning fit.
- `c-mac-recover-0.png`: native stage source list and compact actions; no passive health prose.

No clipping/overlap observed in these nine images. No claim of measured usability, native execution, real health, startup behavior, focus/VoiceOver or draft durability. Remaining frames have geometry coverage, not individual screenshot inspection. Gallery hash-route execution and JavaScript syntax are separate checks. Bundled Norman collector output is in `evidence/revision-02-mockups.json`; it cannot judge SVG interaction or SwiftUI behavior.

## Remaining ranked gates

- **S3 trap:** failed-load Save lock, preserved other grants and native load contract still need authorized source repair. [`macapp/Sources/ToolstackApp/ToolstackApp.swift:521–530,590–598`]
- **S3 amnesia:** failure/unknown must retain the editor and draft; these pictures cannot establish persistence. [`macapp/Sources/ToolstackApp/ToolstackApp.swift:533–540`]
- **S3 mute:** actual native record/liveness decoding remains a source repair. [`macapp/Sources/ToolstackApp/ToolstackApp.swift:344–355`]
- **S2 orphan:** visible native OpenAPI entry remains gated on contract repair. [`macapp/Sources/ToolstackKit/ApiClient.swift:120–122`]
- **S2 mute:** shell startup visibility and ownership-sensitive close behavior need live checks. [`desktop/app.py:106–123`]

Design handoff usable; product acceptance pending. No failed approach required escalation. Simplest route remains static SVG + self-contained HTML; one geometry/capture milestone using installed headless Chrome, no services.

net: -0 controls, -0 steps, +1 signifier needed.

Conservative product implementation ledger; the native OpenAPI signifier is already drawn, not implemented.
