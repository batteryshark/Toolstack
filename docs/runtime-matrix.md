# Supported runtime and evidence matrix

Production source boundary: **78ea904** (production bytes unchanged at **7eac4f9**;
later changes are test/release/fixture helpers, docs and handoffs). [Current security contracts](security-contracts.md)
record exact response/time/path limits, receipts/offline recovery and
[validation provenance](security-contracts.md#dependency-and-validation-evidence).
Local fake-data validation is not deployment or host-isolation certification.

Supported release boundary: a dedicated Toolstack VM with only Toolstack and trusted
tools under its OS account; agents are outside the host and reach only the broker.
Same-machine/same-account agents (including Mac local use) are development-only,
not secret isolation. Separate enforced accounts/filesystem boundaries are future
hardening, not implemented release guarantees.

| Combination | Status | Boundary / remaining evidence |
| --- | --- | --- |
| Local process runner + SPS | Verified local fake-data Mac development recipe; trusted tools only | Published Nod 1.0.1, verified TLS, localfile, CLI/admin and restart/recovery exercised; shared uid is not host isolation |
| Linux systemd + process + SPS | Deployment templates provided; live deployment not tested here | Private state, umask 0077, verified TLS; no privileged helper |
| Linux native sandbox / mutable privileged helper | Disabled / unsupported | Never grant sudo to service-writable Python or interpreter |
| Docker runner + SPS | Unsupported | Recipe image smoke/build/start does not prove SPS connectivity, lifecycle, isolation or recovery |
| Seatbelt + SPS | Unsupported | Network policy/lifecycle unproven |
| One-box Docker compose | Bounded Linux build/create/start proven; experimental SPS deployment | Real onebox and echo API/MCP images exercised at `78ea904`; no automatic SPS supervisor; not Docker+SPS lifecycle/isolation/recovery proof |
| Native Mac app | Local release build and separate Apple Development signature verification passed | 75 native tests at `78ea904`; live interaction/Keychain acceptance open; no full web parity or distribution readiness |
| Fresh retained-wheel Mac full stack, `7eac4f9` / production `78ea904` | PASS: 42 harness checks including lifecycle, 2.912s; installed origins/bytes verified; admin restart/persisted recovery and independent owned cleanup pass | Bounded clean-install check achieved; fake Nod only, no GUI or SPS restart; not Linux installer/systemd or release acceptance |

Release checks exercise Python 3.11 runtime, wheel contents and isolated wheel
imports/CLIs. They are not full integration, sandbox or provider certification.
See the [source-bound milestone table](security-contracts.md#dependency-and-validation-evidence)
for full tracked Python, package, native and offscreen evidence. The historical
589-check run included a stale health assertion failure; it is not the current
qualification or a pending 589-check repair gate. Older counts are not added to
current milestones. Synthetic events do not certify trusted keyboard/Tab/Escape,
VoiceOver, focus, Close, default Cancel or hit targets.

The fourth Linux witness at `78ea904` passed all 19 real process/SPS checks and
admin HTTP 200 alongside real Docker build/create/start. Chief accepted this
**functional witness only**. Composite cleanup failed: five owned containers were
removed, three proof images and the proof root retained. The sole authorized
cleanup-only retry failed safely at root preflight before removal; all residue
remained. The test VM was independently stopped/restored and production health
confirmed. Both permissions are consumed; no further boots/retries are authorized.
The existing host checkout was never edited; no installer, systemd or account
changes occurred. The separate retained-wheel check above closes the bounded
clean-install check, not installed-service deployment validation.
The Linux installer and systemd deployment are untested.

The single approved release retains all 68 obligations, plan 3/5 and zero principal
rejections. Live hands, final exact qualification, scans, PR and chief/principal acceptance remain open;
test counts waive none of these gates.

Process memory contains plaintext secrets in SPS and authorized workloads. Neither
TLS, encryption at rest, nor mode 0600 protects against the host administrator or
same-user trusted processes. Revocation cannot erase already cached values.
