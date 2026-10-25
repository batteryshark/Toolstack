# Evidence index — revision 02

- `geometry.json`: all 81 current frames, every rendered element rectangle, explicit parent hierarchy, zero violations, detected synthetic footer regression.
- `geometry-renderer.log`: existing headless Chrome diagnostics; successful geometry completion is recorded separately.
- `verification.json`: current static checks and SHA-256 fingerprints of all nine visually inspected PNGs.
- `render-results.json`: current nine PNG render results and gallery hash-route check.
- `gallery-dom.html`: current offscreen gallery DOM, not a running Toolstack page.
- `screens.json`: current SVGs used as geometry input.
- `revision-02-mockups.json`: current bundled Norman collector facts; static scanner is not visual proof.
- `admin.json`, `desktop.json`, `macapp.json`: original source collector results at unchanged source baseline `06df1b1`; still source-only, not new live checks.

Earlier mockup/capture evidence lives only in `../iterations/01-superseded.zip`. No image in current `../captures/` is an iteration-01 capture. macOS display-link/task-policy warnings in headless logs did not prevent generation; they are not evidence of product rendering faults.
