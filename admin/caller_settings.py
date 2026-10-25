"""One settings snapshot and atomic mutation shared by HTML and native clients."""
import copy
import hashlib
import json

from broker import operations
from broker.registry import Registry


class ChangedElsewhere(ValueError):
    pass


def snapshot(store, config, name):
    caller = operations.require_caller(store, name)
    if caller["revoked_at"] is not None:
        raise LookupError("Caller is revoked")
    catalog = {}
    registry = Registry.from_sources(config.tools_root, config.tool_dirs)
    for tool in registry.tool_ids():
        catalog[tool] = []
    for op in registry.list_ops():
        catalog[op["tool"]].append({key: op[key] for key in ("op", "risk", "description")})
    policy = store.policy_for(caller["id"])
    installation = store.installation_id
    material = [installation, caller["id"], policy, catalog]
    revision = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"name": name, "caller_id": caller["id"], "installation": installation, "revision": revision,
            "policy": policy, "enabled": operations.enabled_tools(policy), "catalog": catalog}


def apply(store, config, name, data, operator):
    current = snapshot(store, config, name)
    if data.get("revision") != current["revision"]:
        raise ChangedElsewhere("Changed elsewhere. Compare latest before saving.")
    catalog = current["catalog"]
    enabled = data.get("enabled")
    disabled = data.get("disabled_functions")
    tools = data.get("tools")
    if not isinstance(enabled, list) or not all(isinstance(t, str) and t in catalog for t in enabled):
        raise ValueError("Invalid enabled tools")
    if not isinstance(disabled, dict) or not isinstance(tools, dict):
        raise ValueError("Invalid function settings")
    # Send precisely the observed catalog. Never replace authority the editor could not see.
    if set(disabled) != set(catalog) or set(tools) != set(catalog):
        raise ChangedElsewhere("Function set changed. Compare latest before saving.")
    after = copy.deepcopy(current["policy"])
    after["enabled"] = sorted(set(current["enabled"]) - set(catalog) | set(enabled))
    after.setdefault("tools", {})
    after.setdefault("disabled_functions", {})
    for tool, rows in catalog.items():
        names = {op["op"] for op in rows}
        excluded, effects = disabled[tool], tools[tool]
        if (not isinstance(excluded, list) or not all(isinstance(op, str) and op in names for op in excluded)
                or not isinstance(effects, dict) or set(effects) != names
                or any(v not in ("allow", "review", "deny") for v in effects.values())):
            raise ValueError("Invalid function settings")
        old_excluded = set(after["disabled_functions"].get(tool, [])) - names
        after["disabled_functions"][tool] = sorted(old_excluded | set(excluded))
        after["tools"].setdefault(tool, {}).update(effects)
    caller = operations.require_caller(store, name)
    if not store.compare_and_set_policy(caller["id"], current["policy"], after, operator):
        raise ChangedElsewhere("Changed elsewhere. Compare latest before saving.")
    # Receipt is tied to the exact committed policy, not a later writer's snapshot.
    return {"outcome": "saved", "name": name, "policy": after}
