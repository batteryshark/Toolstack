"""Read only the registration client's top-level SPS settings."""
from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass, field


class ConfigModeError(ValueError):
    pass


@dataclass(frozen=True)
class RegistrationConfig:
    sp_host: str
    sp_port: int
    sp_secret: str = field(repr=False)
    sp_tls_ca: str = ""


def _statements(stream):
    """Frame TOML statements without decoding values we do not need."""
    buf = ""
    quote = None
    depth = 0
    for line in stream:
        buf += line
        i = 0
        while i < len(line):
            c = line[i]
            if quote:
                if quote.startswith('"') and c == "\\":
                    i += 2
                    continue
                if line.startswith(quote, i):
                    i += len(quote)
                    quote = None
                    continue
            elif c == "#":
                break
            elif c in "\"'":
                quote = c * 3 if line.startswith(c * 3, i) else c
                i += len(quote)
                continue
            elif c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
            i += 1
        if quote is None and depth == 0:
            yield buf
            buf = ""
    if buf.strip():
        raise ValueError("incomplete SPS configuration statement")


def load_registration_config(path):
    allowed = {"SP_HOST", "SP_PORT", "SP_TLS_CA", "SP_SECRET"}
    data = {}
    with open(path, "r", encoding="utf-8") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
            raise ConfigModeError("SPS configuration must be a regular mode 0600 file")
        for statement in _statements(stream):
            text = statement.strip()
            if text.startswith("["):
                break
            if not text or text.startswith("#"):
                continue
            key = text.split("=", 1)[0].strip().strip("\"'")
            if key not in allowed:
                continue
            try:
                value = tomllib.loads(text)
            except ValueError:
                raise ValueError("invalid SPS registration setting") from None
            if set(value) != {key} or key in data:
                raise ValueError("invalid or duplicate SPS registration setting")
            data.update(value)
    for key in ("SP_HOST", "SP_PORT", "SP_SECRET"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise ValueError(f"missing SPS registration setting {key}")
    if not isinstance(data.get("SP_TLS_CA", ""), str):
        raise ValueError("invalid SP_TLS_CA")
    return RegistrationConfig(data["SP_HOST"], int(data["SP_PORT"]),
                              data["SP_SECRET"], data.get("SP_TLS_CA", ""))


def parse_verify(value):
    from sps.config import parse_bool
    verify = parse_bool(value, name="TOOLSTACK_SPS_VERIFY")
    if not verify and os.environ.get("TOOLSTACK_SPS_DEV") != "1":
        raise ValueError("TOOLSTACK_SPS_VERIFY=0 requires TOOLSTACK_SPS_DEV=1")
    return verify
