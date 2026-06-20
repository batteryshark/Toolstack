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

A tool's `type` is one of `api` / `mcp` / `rest`, the three transports; see
[../tools/README.md](../tools/README.md) for choosing one. A sample of each lives in
[../tools/](../tools/).

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
  `vault` (Infisical project) and `item` (secret path; defaults to the tool id) next
  to `field` (the secret key). Each tool authenticates with its own machine identity
  read from `<credentials_dir>/<item>.env`. Configure with `TOOLSTACK_INFISICAL_HOST`
  / `_ENVIRONMENT` / `_CREDENTIALS_DIR` / `_VAULT`.
- **Backend selection:** `get_backend(name)` picks `file` (default), `vault`, or `infisical`;
  the CLI exposes `--secret-backend` and honors `$TOOLSTACK_SECRET_BACKEND`.
- SOPS can follow behind the same `resolve()` interface.

## Runners

- **`process`** (default, zero infra): runs the tool as a local subprocess with its
  secrets in a private `0700` dir pointed to by `$TOOLSTACK_SECRETS_DIR`. Binds
  loopback only.
- **`docker`**: runs the tool in a container with its secrets mounted at
  `/run/secrets`, publishing the port to host loopback (`-p 127.0.0.1:...`).

## CLI

```bash
# start one tool (or all, if no id) with the process backend
python3 -m toolyard.cli up echo --secrets secrets.toml

# or the docker backend (builds the tool's Dockerfile)
python3 -m toolyard.cli up echo --secrets secrets.toml --backend docker

python3 -m toolyard.cli ls
python3 -m toolyard.cli down echo
```

Defaults: `--root` = `$TOOLSTACK_TOOLS_ROOT` or `tools`; `--secrets` =
`$TOOLSTACK_SECRETS_FILE` or `secrets.toml`; `--backend` = `$TOOLSTACK_RUNNER` or
`process`.

## End to end with the broker

```bash
cp secrets.example.toml secrets.toml
python3 -m toolyard.cli up echo --secrets secrets.toml          # start the tool
python3 -m broker.brokerctl create-caller --name hermes --allow echo.say
TOOLSTACK_TOOLS_ROOT=tools python3 -m broker.server            # broker reads the registry
# then POST /v1/actions/echo.say to the broker with the caller's token
```

## Test it

```bash
python3 -m unittest discover -s toolyard/tests -t .
TOOLSTACK_TEST_DOCKER=1 python3 -m unittest toolyard.tests.test_runner  # include docker e2e
```

## Writable secrets

A tool that rotates a credential (e.g. an OAuth token) writes it back through a Unix
socket the toolyard mounts into the container at `/run/toolyard/secrets.sock`
(message-contracts §4). For any tool declaring a `writable = true` secret, the runner
starts a small **write-proxy** on the host (it holds the backend; only the socket is
exposed to the container), enforces the tool's writable allowlist, and patches exactly
the declared `(vault, item, field)`. The proxy is killed and its socket removed on
stop. No backend credential is ever mounted in the container.

## Modules

- `config.py`: parse `toolyard.toml` into a `ToolDef`.
- `secrets.py`: secret backends (`FileBackend`, `VaultBackend`, `InfisicalBackend`; `get_backend()`).
- `runner.py`: `ProcessRunner` and `DockerRunner` (`get_runner(backend)`).
- `write_proxy.py`: the writable-secret socket server (message-contracts §4).
- `cli.py`: `up` / `down` / `ls`, with a small JSON state file.

## Security notes

- A tool never holds a broker token or a secret-backend credential.
- The broker never receives a secret value (verified in the tests).
- Writable secrets go host-side through the write-proxy; the container only ever sees
  the socket, never a backend credential.
- Hardening to add: inject secrets into a container **tmpfs** at start so they never
  touch host disk (the process/docker backends write to a `0700` dir removed on stop).
