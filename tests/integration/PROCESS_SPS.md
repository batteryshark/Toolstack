# Finite process/SPS proof

Run with Python 3.11 and cryptography **50.0.2**, with the installed toolstack
dependencies. No download, Nod, broker, provider, Docker driver, or VM helper is
part of this fixture. With no `--root` it has no effects.

Private child invocation is `tool ROOT`, emitted only by the fixture manifest.
It validates an owned 0700 root, a private regular marker bound to its device
and inode, HOME, manifest and CA placement, loopback SPS host, and verified TLS
before creating the SDK. Bare `tool` is rejected. The constructed PATH includes
`/usr/sbin:/sbin` for native boot identity tools; boot identity must be available
before any service spawn. A narrow transparent posix_spawn observer records the
real runner child PID/start/boot, allowing partial-start cleanup to be checked.
It changes neither spawn arguments nor product behavior.

The root must be an absent absolute path below a caller-owned 0700 directory.
Ancestors are traversed with no-follow directory descriptors. All generated
configuration, fake encrypted vault, credentials, logs, and state are private
under that root. Preserve the root on failure; it contains fake credentials and
must remain private. Only `result.json` is intended for sharing.

Container owner entry argv (inside the already installed image):

```
python /proof/process_sps.py --root /data/process-sps
```

Mount this script read-only at `/proof/process_sps.py`; `/data` must be owned by
the invoking container user, mode 0700, with `process-sps` absent. Installed
`sps`, `admin`, and `toolyard` imports must be available (for source in `/app`,
invoke with `PYTHONPATH=/app`). The fixture derives child import roots from those
modules. Network NONE is compatible with its literal loopback traffic.

The 100-second work alarm leads to bounded owned-child cleanup. SPS restarts
exactly once. ProcessRunner owns the tool spawn/process group; SPS children use
new sessions. Result records checks, boot/start identities, ports, PIDs, versions,
and cleanup status. A failed assertion preserves completed checks and failure
type without exception text that could contain credentials. No automatic effect
replay occurs; only readiness is retried. Root evidence remains for its owner to
remove after review.

Scope: Linux process userland inside a throwaway container, **not** bare-host
systemd installation, account/isolation acceptance, or production providers.
Installation and final Linux execution gates remain separate.
