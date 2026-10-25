"""Merge the web editor's explicit edits without replacing unseen authority."""


def operation_fields(current, catalog):
    """Exact web field identities, restricted to currently enabled operations."""
    from broker.operations import enabled_tools

    result = {}
    for tool in enabled_tools(current):
        for operation in catalog.get(tool, []):
            op = operation['op']
            key = f'op__{tool}__{op}'
            target = (tool, op)
            if key in result and result[key] != target:
                result[key] = None  # Ambiguous encoding must never pick a target.
            else:
                result[key] = target
    return result


def retained_draft(current, fields, field_map):
    """Keep only valid, unambiguous posted values on a safe current scope."""
    draft = dict(current, tools={t: dict(ops) for t, ops in current.get('tools', {}).items()})
    for key, effect in fields.items():
        target = field_map.get(key)
        if target and effect in ('allow', 'review', 'deny'):
            tool, op = target
            draft['tools'].setdefault(tool, {})[op] = effect
    return draft


def merge_grants(current, fields, field_map=None):
    grants = {f"{tool}.{op}": effect
              for tool, ops in current.get("tools", {}).items()
              for op, effect in ops.items()}
    for key, effect in fields.items():
        if not key.startswith("op__"):
            continue
        parts = key.split("__", 2)
        if len(parts) != 3 or effect not in ("allow", "review", "deny"):
            raise ValueError("Invalid operation policy")
        if field_map is not None:
            target = field_map.get(key)
            if not target:
                raise ValueError("Operation set changed. Load the current policy page before saving.")
            tool, op = target
        else:
            tool, op = parts[1:]
        grants[f"{tool}.{op}"] = effect
    return tuple([key for key, value in grants.items() if value == effect]
                 for effect in ("allow", "review", "deny"))


def merge_enabled(current, available, selected):
    # Tools absent from the catalog cannot be unchecked in the editor.
    prior = list(dict.fromkeys(current.get("enabled", []) + list(current.get("tools", {}))))
    return list(dict.fromkeys([t for t in prior if t not in available] + selected))
