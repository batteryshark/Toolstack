# Toolstack

Brokered actions for agents: callers receive scoped action permissions, while
authorized tools retrieve workload credentials through SPS. Web admin controls
callers, policies and trusted tools. The broker and SPS make separate decisions.

**Supported release boundary: a dedicated Toolstack VM containing only Toolstack
and trusted tools under its OS account. Agents stay outside that host and reach
only the broker.** No VM setup is performed by these source changes. Same-machine
or same-account agents (including on a Mac) are local/development use only and
do not isolate secrets. Process mode is not hostile-code isolation. Secrets
exist as plaintext in endpoint memory and can be returned by tool responses.
Private files and TLS do not isolate processes sharing the same unrestricted uid.

- [Runtime support matrix](docs/runtime-matrix.md)
- [Integrated security contracts and remaining release gates](docs/security-contracts.md)
- [Deployment and offline SPS provisioning](deploy/README.md)
- [Fake-config walkthrough](docs/walkthrough.md)
- [SPS architecture](docs/sps.md)
- [Local Mac signing gate](docs/mac-local-signing.md)
- [Release notes and pending validation](docs/release-notes.md)

The Linux installer and systemd deployment are untested.
The isolated retained-wheel full-stack check on this Mac **passed**, including admin
restart/persisted recovery and independently verified owned cleanup. This closes
the bounded clean-install check, using fake state and fake Nod, not real Nod,
signature or human approval proof. No GUI checks ran. See the release notes for
its scope. Manual hands checks have not run and remain OFF pending fresh
principal go through chief; no release acceptance is implied.

Python 3.11+ is required. Build with `uv build`; the wheel includes admin, broker,
client, toolyard, SPS/plugins and forwarder. Admin dependencies and localfile crypto
are optional extras (`.[admin,vault]`). Full deployment dependencies are resolved in
`uv.lock` and exported to `admin/requirements-lock.txt`; deployment scripts consume
that export consistently as requirements and constraints.

Run `uv run --no-project --python 3.11 python tests/release/check_release.py` for
isolated packaging verification. Release workflow checks/builds only: no tags,
publishing, GHCR, signing or release creation. Full fake-secret E2E is a separate
integration gate. Docker/Seatbelt with SPS and mutable Linux privileged helpers
are unsupported. Source build/sign scripts do not establish distribution readiness.
