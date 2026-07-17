"""Load exactly one plugin at startup, per the guidance.

Selection is from `Config.sp_plugin`. The matching `[plugin]` block must be
non-None; we do not silently fall back. A missing block fails closed.
"""
from __future__ import annotations

from ..config import Config
from .base import SPSSecretsPlugin


def load_plugin(cfg: Config) -> SPSSecretsPlugin:
    name = cfg.sp_plugin
    if name == "infisical":
        if cfg.infisical is None:
            raise ValueError("SP_PLUGIN=infisical but [infisical] block missing")
        from .infisical import InfisicalPlugin
        return InfisicalPlugin(cfg.infisical)
    if name == "hashicorp_vault":
        if cfg.vault is None:
            raise ValueError(
                "SP_PLUGIN=hashicorp_vault but [hashicorp_vault] block missing"
            )
        from .hashicorp_vault import HashicorpVaultPlugin
        return HashicorpVaultPlugin(cfg.vault)
    if name == "localfile":
        if cfg.localfile is None:
            raise ValueError("SP_PLUGIN=localfile but [localfile] block missing")
        from .localfile import LocalFilePlugin
        return LocalFilePlugin(cfg.localfile)
    raise ValueError(f"unknown SP_PLUGIN {name!r}")
