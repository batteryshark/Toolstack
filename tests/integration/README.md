# Local real-release vertical slice

Run from this checkout with the already-cached Python 3.11.17 environment:

```sh
env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
 HOME=/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode \
 TMPDIR=/private/var/folders/pz/lrml3ths3mg3mf4bb75rmcvc0000gn/T/opencode \
 UV_CACHE_DIR=/Users/batteryshark/.cache/uv UV_PYTHON_DOWNLOADS=never \
 /Users/batteryshark/.local/bin/uv run --offline --no-project \
 --python /Users/batteryshark/.local/share/uv/python/cpython-3.11.17-macos-aarch64-none/bin/python3.11 \
 --with cryptography==50.0.2 --with fastapi==0.137.1 --with uvicorn==0.49.0 \
 --with PyYAML==6.0.3 --with httpx==0.28.1 python scripts/check-vertical-slice.py
```

This is intentionally opt-in (not unittest discovery): it downloads the public
Nod v1.0.1 Apple Silicon macOS release, verifies the pinned archive SHA-256 and
rejects links, special members, absolute/traversal archive paths before extraction.
It never invokes an installed Nod. It requires network access only for that
published artifact; runtime calls use dynamic literal loopback ports.

The launcher creates one private temporary directory under the approved OpenCode
temporary root and constructs a fresh child environment. The fixture clears its
own environment too. Certificates, fake SPS config/passphrase, encrypted vault,
fake tokens, private runner state, channels.json, logs and Nod data stay there.
No APNs configuration or push tokens are supplied. The enrolled software P-256
device is synthetic; Nod itself is not faked. The tool is a test-owned HTTP
fixture using the real SecretClient with certificate verification enabled.

The result prints nonsecret process IDs/start identities, ports, digests and
checks. Every owned long-lived process has an identity-checked bounded teardown;
the launcher removes temporary data after fixture exit. Expected warning: the
first restart-recovery pass withholds the fixture manifest, so real registration
is incomplete; restoring it allows the same-boot watchdog retry to complete.
No model polling or automatic action replay is involved.

Scope: Mac **development fixture only**, trusted same-owner process runner, not
host isolation. The supported target is dedicated-VM trusted tools with external
agents; no VM, installation or deployment is tested here. Broker restart and
persisted policy are covered. Full admin HTTP/login restart and persisted admin
configuration are now covered through a real admin child, fake-password login,
authenticated JSON and HTML config saves, API-owned broker start/stop, admin
stop/restart and fresh login. An external tool directory must survive both saves
and restart; policies/grants and tool discoverability persist. The broker is
stopped/reaped through its owning admin before admin restart; this does not test
adoption of an orphan broker. The running fixture tool keeps its identity.
The explicit watchdog failure/retry phase runs while admin is stopped to prevent
background recovery races. Real admin startup also uses its ordinary watchdog.

The first review call uses a stable CLI idempotency key. Matching retries before
and after approval reuse the same receipt/result, one card and one effect;
mismatch is HTTP 409 and nonzero CLI. Card checks preserve an allowlisted safe
destination, mask a fake credential, visibly omit other fields and exclude the
private reason; audit excludes both private markers. Unknown outcomes are not
interpreted as proof of absent effects. This fixture does not induce a transport
loss, restore a backup, or test pruning. The launcher budget is 270 seconds plus
30 seconds for interrupted cleanup. All XDG paths and umask077 are explicit.
