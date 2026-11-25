# Release notes — bounded validation and open gates

The Linux installer and systemd deployment are untested.

An isolated installed-wheel check serves as this release's clean-install gate. That **one full-stack check PASSED** at helper source `7eac4f9`
with unchanged production `78ea904`: 42 harness checks, including lifecycle checks,
in 2.912s. A fresh Mac environment from the retained wheel exercised broker, verified
TLS SPS with encrypted localfile storage, admin, a ProcessRunnerSDK tool and fake
Nod approval. Admin restart recovered configuration, token and completed receipt;
denial persisted and retries produced one card/one effect without replay.
Installed origins and bytes matched the wheel; independent postchecks confirmed
owned children reaped/absent and listeners gone. The bounded clean-install check
passed.
Fake Nod is not real Nod integration, signature or human approval proof. No GUI
checks or optional SPS restart ran; this is not full-source or release acceptance.

This check does not run `deploy/install.sh`, systemd, account changes or installed
services. A real Linux installer test needs a disposable host.
Manual UI checks have not run. Final qualification, scans and release acceptance
remain open.

See the [runtime matrix](runtime-matrix.md) for the trusted-host boundary, accepted
Linux functional witness and cleanup limits, and the
[source-bound milestones](security-contracts.md#dependency-and-validation-evidence)
for product `78ea904`, helper baseline `8e4bb2e` and full-Python `791159c` evidence.
Same-account Mac use remains development-only, not secret isolation. No test count
waives the remaining gates or establishes Docker+SPS, privileged native or Seatbelt
support.
