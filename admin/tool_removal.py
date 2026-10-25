"""One ownership-sensitive remove operation for HTML and JSON adapters."""
from dataclasses import replace
from pathlib import Path

from broker import operations
from . import toolyard_ops, operator_audit
from .store_access import open_store


def remove_tool(config, tool_id, user):
    try:
        tools = {t['id']: t for t in toolyard_ops.list_tools(config.tools_root, config.tool_dirs)}
    except (OSError, ValueError):
        raise ValueError(f'Could not read tools. Check tool manifests before removing {tool_id}.') from None
    if tool_id not in tools:
        raise LookupError(f'no such tool: {tool_id}')
    path = Path(tools[tool_id]['path']).resolve()
    matches = [p for p in config.tool_dirs if Path(p).resolve() == path]
    if matches:
        toolyard_ops.stop(tool_id)
        updated = replace(config, tool_dirs=[p for p in config.tool_dirs if Path(p).resolve() != path])
        operator_audit.save_config(config, updated, user)
        deleted = False
    else:
        if not config.tools_root or path.parent != Path(config.tools_root).resolve():
            raise ValueError(f'Ownership unknown for {tool_id}; folder was not removed')
        toolyard_ops.remove(tool_id, config.tools_root, config.tool_dirs)
        deleted = True
    with open_store(config) as store:
        operations.record_admin_event(store, user, 'tool_removed', {'tool': tool_id, 'deleted': deleted})
    return {'removed': tool_id, 'deleted': deleted}
