"""Authenticated control-plane verification of a private loaded catalog receipt."""
import json
import urllib.request

from broker.registry import Registry
from .store_access import open_store


def observe_catalog(config):
    unknown = {"status": "unknown"}
    try:
        # The public endpoint carries only a random observation id, never a digest.
        with urllib.request.urlopen(f"http://127.0.0.1:{config.port}/v1/health", timeout=1) as response:
            if response.status != 200:
                return unknown
            health = json.loads(response.read(8192))
        observation = health.get("catalog_observation_id")
        if health.get("status") != "ok" or not isinstance(observation, str) or not observation:
            return unknown
        with open_store(config) as store:
            receipt = store.catalog_receipt()
        current = Registry.from_sources(config.tools_root, config.tool_dirs)
        if not isinstance(receipt, dict) or receipt.get("observation_id") != observation:
            return unknown
        if receipt.get("fingerprint") != current.observation_fingerprint(config.tools_root, config.tool_dirs):
            return unknown
        # A restart/reload racing the private read cannot certify the previous receipt.
        with urllib.request.urlopen(f"http://127.0.0.1:{config.port}/v1/health", timeout=1) as response:
            latest = json.loads(response.read(8192))
            if response.status != 200 or latest.get('status') != 'ok' or latest.get('catalog_observation_id') != observation:
                return unknown
        return {"status": "verified", "observation_id": observation, "tool_ids": current.tool_ids()}
    except Exception:
        return unknown


def target_verified(catalog, target):
    """Legacy/global verdicts cannot establish membership of a separately cached row."""
    if not isinstance(catalog, dict) or catalog.get('status') != 'verified':
        return False
    ids = catalog.get('tool_ids')
    return (isinstance(ids, list) and all(isinstance(item, str) and item for item in ids)
            and target in ids)
