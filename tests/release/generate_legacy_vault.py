"""Run with uv run --no-project --with cryptography==45.0.7 python this-file.

Creates only a fake regression fixture, using the production constructor/KDF.
"""
import sys
import tempfile
from pathlib import Path

import cryptography

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sps.plugins.localfile import _Vault

assert cryptography.__version__ == "45.0.7", cryptography.__version__
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "vault.json"
    vault = _Vault.init(path, "fake-compatibility-passphrase")
    vault.set("fake-tool", "token", "fake-old-value")
    vault.set("fake-tool", "retained", "fake-retained")
    Path(__file__).with_name("vault-45.0.7.json").write_bytes(path.read_bytes())
print(sys.version, cryptography.__version__)
