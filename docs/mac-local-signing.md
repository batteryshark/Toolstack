# Native Mac: development-signed local use

The approved Clear desk native app is implemented and built. Parent evidence records
75 passing native tests at `78ea904`, an actual release build,
signing with an existing approved Apple Development
identity, and a **separate** `codesign --verify --deep --strict` PASS.
The bundle identifier is `com.toolstack.operator`; production source remains
byte-identical at `8e4bb2e`. Original signed binary SHA-256:
`28cf9127f93d4ffd30fe7d91d120b862d4e2fc1c3a845b50210bd6a369b18600`.
Identity: an existing Apple Development certificate (name and team withheld);
development only, not notarization or distribution.

This establishes local signature consistency, not functional correctness or full
web parity. No app activation, installation, live Keychain proof, notarization,
Gatekeeper assessment or distribution acceptance is established.

For repeatable local use, follow the [packaging recipe](../macapp/packaging/README.md):
build the bundle, explicitly select an existing approved Apple Development identity,
sign, then independently verify. Signing does not build or verify; neither local
script sources credentials or submits to Apple. Stub tests prove command contracts,
not signatures. Retain build revision and verification evidence privately.

The first hands attempt failed at copy codesign with private HOME (identity not
found), before either app launched; it was fully cleaned, not a principal rejection.
The codesign-only OS-owner HOME repair passed actual fresh-copy signing and separate
strict/deep verification while OFF, plus 13 independent pure fixture checks.
Native/backend/desktop HOME, XDG and TMP remain private with an allowlisted
environment and no ambient credentials. The original artifact is unchanged.
Renewed readiness was sent to chief; fresh readiness confirmation remains pending.

Trusted keyboard/Tab/Escape, VoiceOver, focus, native window Close, named/default Cancel
and comprehensive hit-target acceptance remain open. Synthetic clicks/keys and
offscreen captures are not substitutes. Earlier backend/native wire evidence does
not establish these hands results. Same-user Mac development is not secret isolation; see the
[runtime boundary](runtime-matrix.md).
