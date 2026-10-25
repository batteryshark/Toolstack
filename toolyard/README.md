# Toolyard

The **execution boundary**. It reads `toolyard.toml`, resolves each tool's secrets,
and starts the tool so the broker can forward approved calls to it on
`127.0.0.1:<port>`. The broker is never on the secret path. See [../plan.md](../plan.md).

Zero dependencies: stdlib only (TOML via `tomllib`).

## A tool definition (`toolyard.toml`)

One file per tool, the single source of truth shared with the broker. The broker
reads only `id` / `type` / `[[operations]]` and the entrypoint `port`; the toolyard
additionally reads `[entrypoint]` and `[[secrets]]`.

An operation's `risk` is **descriptive metadata** shown during discovery; it does
**not** decide whether a call needs approval. That is the per-caller **policy**
(`allow` / `review` / `deny`), set by an operator with `brokerctl`. And a tool is not
callable by anyone until a caller policy grants it (`brokerctl create-caller --allow
<tool>.<op>` / `--review <tool>.<op>`).

```toml
id = "echo"
type = "api"

[entrypoint]
command = "python3 app.py"   # process backend (dev/CI)
port = 4601
# image = "ghcr.io/..."      # docker backend (production); built from Dockerfile if absent

[[operations]]
name = "say"
risk = "read"

[[secrets]]
name = "api_key"             # the tool reads $TOOLSTACK_SECRETS_DIR/api_key
field = "API_KEY"            # looked up in the secret backend
```

A tool's `type` is one of `api` / `mcp` / `rest`; see [../tools/README.md](../tools/README.md)
for choosing one. Samples live in [../tools/](../tools/).

REST tools add top-level `base_url` and per-operation `verb` / `path`. When
`[entrypoint].command` is omitted for a REST tool, the toolyard defaults it to
`python3 -m toolstack_forwarder`. Under the docker runner, a REST tool without an
explicit image uses a generic stock-Python container with the repo mounted
read-only to run that bundled forwarder. Broker-to-tool `X-Toolstack-Secret`
works uniformly for api / mcp / rest when a shared `broker_secret` is provisioned;
REST tools do not need a per-tool channel secret.

To scaffold a REST manifest from an OpenAPI JSON spec:

```bash
python3 -m toolyard.openapi_import openapi.json --id graph --port 4640 > tools/graph/toolyard.toml
```

The importer emits named operations for the generic forwarder contract. The admin
panel also exposes the parser and accepts YAML when `PyYAML` is installed.

## Secrets

The toolyard resolves a tool's declared secrets through a pluggable backend and
hands the values to the tool, never to the broker.

- **Dev (shipped):** `FileBackend` reads a local TOML file shaped as
  `[<tool_id>]  FIELD = "value"`. Copy [../secrets.example.toml](../secrets.example.toml)
  to `secrets.toml` (gitignored) and fill it in.
- **Local encrypted (shipped, opt-in):** `VaultBackend` keeps secrets in an scrypt+AEAD
  encrypted file unlocked by `$TOOLSTACK_VAULT_PASSPHRASE` (`pip install '.[vault]'`).
- **Production (shipped):** `InfisicalBackend` resolves each secret from Infisical
  over its HTTP API (stdlib only, no added dependency). A `[[secrets]]` entry adds
  `item` (secret path; defaults to the tool id) next to `field` (the secret key).
  The Infisical project/vault comes only from `TOOLSTACK_INFISICAL_VAULT`.
  Toolstack authenticates once with the deployment's machine identity
  (`TOOLSTACK_INFISICAL_CLIENT_ID` / `_CLIENT_SECRET`, or the unprefixed Infisical
  names). Configure with `TOOLSTACK_INFISICAL_HOST` / `_ENVIRONMENT` / `_VAULT`.
- **Backend selection:** `get_backend(name)` picks `file` (default), `vault`, or `infisical`;
  the CLI exposes `--secret-backend` and honors `$TOOLSTACK_SECRET_BACKEND`.
- SOPS can follow behind the same `resolve()` interface.

## Runners

- **`process`** (default): trusted subprocesses retrieve workload values through
  SPS using a scoped capability, separate from the API channel key. No isolation.
- **`docker`**: experimental no-SPS lifecycle only, publishing to host loopback.
  Docker+SPS and secret-bearing tool combinations are refused.
- **`sandbox`** selects **`seatbelt`** on macOS (network-only development backend,
  no SPS support) or **`bwrap`** on Linux (**disabled**). Do not authorize mutable
  Python application code through sudo. Legacy Linux-native records produce an
  operator-cleanup error rather than invoking an unsafe helper.

### Current supported boundary

Process mode is **trusted tools only**. Private state is mode 0600 in a 0700
directory, but unrestricted same-owner processes can still read it; this is not
OS isolation. The independent `TOOLSTACK_CHANNEL_SECRET` authenticates tool API
requests and is never an SPS credential. Tools refuse missing channel credentials.
The broker reads only `TOOLSTACK_TOOLYARD_CHANNEL_STATE` (default `channels.json`
beside private `state.json`), shaped as `toolid -> {channel_secret: value}`.
Runner private state retains `e_secret`; do not give the broker that file.
Docker and Seatbelt with SPS are refused pending complete lifecycle validation.

Process tools declaring secrets refuse startup when SPS configuration is absent.
`TOOLSTACK_SPS_SKIP=1` is an explicit, logged **trusted-process development/test**
opt-out only; it does not enable secret-bearing Docker/Seatbelt/Bwrap tools.
Invalid configured SPS settings raise a configuration error, not a secretless fallback.

The egress proxy shares one 30-second socket deadline across request ingress,
upstream send/headers/streamed body and CONNECT (5-second socket inactivity,
1 MiB request, 4 MiB response/tunnel, 16 admitted handlers). Synchronous OS DNS
is a trusted-host dependency and cannot be preempted: a resolver can retain an
admitted handler until it returns. Late resolution is refused before connection;
a late connection is closed before sending any request bytes. No hard real-time
full-operation bound is claimed. Deadline aborts and partial responses **do not
roll back upstream effects**. No resolver service or unbounded worker pool is used.
Writeback operations must explicitly choose body and header response visibility;
writeback alone does not redact a returned secret.

The approved release boundary is a dedicated Toolstack VM with trusted tools
sharing its account and agents outside using only the broker. Mac same-host/
same-account use is development-only, not secret isolation. Enforced per-tool
accounts/filesystems are future hardening, not this release's promise.

`TOOLSTACK_TOOLYARD_STATE` overrides the private state path; absent a channel
override, both broker and runner use its sibling `channels.json`. Existing
destination directories must already be owner-private; linked, foreign-owned,
or broadly accessible destinations are refused without chmod. Use canonical
directory paths. Child environment is allowlisted to runtime plumbing; provider
and registration-master credentials are not inherited. Workload-specific values
should come through SPS, not ambient environment.

Bundled echo Dockerfiles require repository-root build context, for example
`docker build -f tools/echo_api/Dockerfile .` (substitute `echo_mcp` as needed).
The Docker runner selects that context for bundled echo tools; custom tool
Dockerfiles retain tool-directory context. Echo images copy their manifests and
SDK source. This is a source packaging repair, not a validated Docker+SPS recipe;
no image build or daemon check was performed.

## CLI

```bash
# start one tool (or all, if no id) with the process backend
python3 -m toolyard.cli up echo

# or the docker backend (builds the tool's Dockerfile)
# Docker is experimental and refuses SPS/secret-bearing combinations.

python3 -m toolyard.cli ls
python3 -m toolyard.cli down echo
python3 -m toolyard.cli reload echo
```

Defaults: `--root` = `$TOOLSTACK_TOOLS_ROOT` or `tools`; `--backend` = `$TOOLSTACK_RUNNER` or
`process`.

## End to end with the broker

```bash
python3 -m toolyard.cli up echo                               # configured SPS
python3 -m broker.brokerctl create-caller --name hermes --allow echo.say
TOOLSTACK_TOOLS_ROOT=tools python3 -m broker.server            # broker reads the registry
# then POST /v1/actions/echo.say to the broker with the caller's token
```

## Test it

```bash
python3 -m unittest discover -s toolyard/tests -t .
# Native and Docker integration checks are opt-in; neither was run for this tranche.
```

## Writable secrets

A tool that rotates a credential (e.g. an OAuth token) writes it back through a Unix
socket the toolyard mounts into the container at `/run/toolyard/secrets.sock`
(message-contracts §4). For any tool declaring a `writable = true` secret, the runner
starts a small **write-proxy** on the host (it holds the backend; only the socket is
exposed to the container), enforces the tool's writable allowlist, and patches exactly
the declared `(item, field)`. The proxy is killed and its socket removed on
stop. No backend credential is ever mounted in the container.

## Modules

- `config.py`: parse `toolyard.toml` into a `ToolDef`.
- `secrets.py`: secret backends (`FileBackend`, `VaultBackend`, `InfisicalBackend`; `get_backend()`).
- `runner.py`: `ProcessRunner` and `DockerRunner` (`get_runner(backend)`).
- `write_proxy.py`: the writable-secret socket server (message-contracts §4).
- `openapi_import.py`: stdlib OpenAPI/Swagger JSON importer for REST manifests.
- `cli.py`: `up` / `down` / `ls`, with a small JSON state file.
- `toolstack_forwarder`: the generic REST forwarder process used by `type = "rest"` tools.

## Security notes

- A tool never holds a broker token or a secret-backend credential.
- The broker never receives a secret value (verified in the tests).
- Writable secrets go host-side through the write-proxy; the container only ever sees
  the socket, never a backend credential.
- Hardening to add: inject secrets into a container **tmpfs** at start so they never
  touch host disk (the process/docker backends write to a `0700` dir removed on stop).
