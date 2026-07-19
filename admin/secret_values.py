"""Operator provisioning of secret VALUES: the SPS path.

The control plane normally never touches secret values: they live in the
backend, off the panel (see admin.tool_authoring / admin.toolyard_ops).
This module is for the operator-facing "set a value" UI. With Phase 5
the value is set through the SPS over its TLS/TCP wire protocol (the
``vault-set`` op); we use sps.client.SPSClient with the runner's SP_SECRET
authentication so only the admin host -- which is already trusted to
hold the SPS config -- can do this. The backend plugin does the actual
storage (whatever the operator configured at SPS startup).
"""
from __future__ import annotations

import os

from sps.client import SPSClient
from sps.config import load_config

_DEFAULT_ENV = "/etc/toolstack/sps.env"


def _client() -> SPSClient:
    """Build an SPSClient from the standard sps.env. Raises if missing or
    mode-0600 violation; the SPS config loader fails closed on both."""
    path = os.environ.get("TOOLSTACK_SPS_ENV", _DEFAULT_ENV)
    cfg = load_config(path)
    verify = os.environ.get("TOOLSTACK_SPS_VERIFY", "1") == "1"
    return SPSClient(
        host=os.environ.get("TOOLSTACK_SPS_HOST", cfg.sp_host),
        port=int(os.environ.get("TOOLSTACK_SPS_PORT", str(cfg.sp_port))),
        sp_secret=cfg.sp_secret,
        ca_file=cfg.sp_tls_ca,
        verify=verify,
    )


def set_value(tool_id: str, field: str, value: str) -> None:
    """Provision ``tool_id.field`` through SPS. The wire call goes
    ``write_secret``; the backend plugin (the operator's choice at
    SPS startup) does the actual storage."""
    _client().write_secret(tool_id, field, value, esecret=_client_spsecret_proxy_for_write())


def _client_spsecret_proxy_for_write() -> str:
    """Operator-write uses SP_SECRET (the runner-side credential). The runner
    is the only authorized registrar; we are not, so this raises -- forcing
    operator provisioning through `python3 -m sps.cli vault-set`, which
    uses SP_SECRET directly. The reason: keeping the panel out of the
    auth path makes "set a secret" a controlled, host-level action."""
    raise RuntimeError(
        "admin.secret_values.set_value is not callable from the panel: "
        "operator provisioning must use 'python3 -m sps.cli vault-set' "
        "(which authenticates against SP_SECRET directly, not the panel)."
    )
