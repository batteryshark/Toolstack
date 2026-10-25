# Experimental image scaffold — NOT supported SPS deployment

Dockerfile now copies SPS and the forwarder, installs the complete pinned deployment
export, and invokes the packaged `admin serve --port 8780` (no unsupported --host
argument). This has not been built or started with a Docker daemon in this lane.

Compose is opt-in under the `experimental` profile. It does not supervise SPS and
does not provide proven runner registration/recovery. Do not use it for the supported
release. See [runtime matrix](../../docs/runtime-matrix.md) and native deployment.
The image's process runner does not isolate hostile tools.

Before any future Docker/SPS support claim, prove: SPS lifecycle, TLS server name/CA
matching the reachable service, explicit runner config and passphrase wiring, private
state/log volumes, offline vault provisioning, separate broker channel credentials,
restart/recovery and negative credential tests. Do not mount a Docker socket or
publish SPS publicly. Docker network egress is not loopback isolation.

`TOOLSTACK_ADMIN_PASSWORD` is not a password bootstrap mechanism: the actual admin
requires `admin set-password` with persistent XDG config before serving. Example
env carries no real password. No default credentials are supplied.
