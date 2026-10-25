# Local development packaging

The approved path is **LOCAL Apple Development signing**, not distribution.
The approved Clear desk UI is built. A parent local build, Apple Development signing
and separate strict/deep verification passed; see [bounded evidence](../../docs/mac-local-signing.md).
An existing approved identity is required on the machine performing the recipe.
Current evidence binds the product to `78ea904` (unchanged at `8e4bb2e`). The
isolated-copy fixture's codesign-only HOME repair also passed real signing and
separate verification while OFF; this does not establish live app acceptance.
See the linked evidence for the first failed hands attempt and fresh readiness gate.

From `macapp/`, build the existing bundle with
`bash packaging/build-app.sh` (output: `build/Toolstack Operator.app`). Then use an
explicit, already-existing approved identity; no identity discovery or account setup
is performed by these scripts:

```sh
bash packaging/sign-local.sh --identity 'Apple Development: APPROVED EXISTING IDENTITY' --app 'build/Toolstack Operator.app'
bash packaging/verify-local.sh 'build/Toolstack Operator.app'
```

Alternatively set `TOOLSTACK_LOCAL_SIGN_IDENTITY` explicitly for `sign-local.sh`.
The app path defaults to `macapp/build/Toolstack Operator.app`, relative to the
script, not the caller's directory. Both scripts accept paths containing spaces.
Signing requires an existing bundle; it never builds. It uses
`codesign --force --sign IDENTITY --timestamp=none`, without hardened runtime,
ad-hoc fallback, secure timestamp or network submission. Verification is a
**separate command**, `codesign --verify --deep --strict --verbose=2 APP`;
run it and require success independently. Missing bundle/identity or failed
codesign exits nonzero. Sign success alone is not verification evidence.

Neither script sources `signing.env`, `secrets.env` or any credential file, invokes
notarytool/spctl, enumerates identities, nor changes certificates/accounts.
The signing tool itself uses the existing local keychain identity; these scripts
do not export its key. Stub tests are argv/failure contracts, not real signing proof.

Strict/deep verification proves signature consistency only: not functional behavior,
Keychain compatibility, notarization, Gatekeeper acceptance or distribution safety.
See [local evidence and remaining checks](../../docs/mac-local-signing.md).

## Historical distribution script — not the default

`sign-and-notarize.sh` is retained unchanged as historical distribution automation.
It **builds, sources private configuration, signs with Developer ID, submits to
Apple, staples and assesses Gatekeeper**. Do not execute or source it for this
release's local path. Its presence establishes no configured credentials,
distributable artifact or successful notarization. Developer ID, notary API keys,
account changes and distribution are out of scope.

Bundle identifier, version, Info.plist and icon assets are unchanged. The builder
generates the app icon from `AppIcon-source.png` and copies SwiftPM resources;
signature verification does not certify visual behavior or resource completeness.
