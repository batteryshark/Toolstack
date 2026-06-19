"""Bring a tool's directory INTO the deployment's managed tools dir.

The native app and Docker deployments can't reference arbitrary host paths at run time, so
"adding" a tool COPIES its folder into the broker's ``tools_root`` (where it is auto-discovered).
A small ``.tsr-source.json`` sidecar records where it came from (a local path now; a git repo in
a later slice) so the tool can be re-synced later ("Update").

Secret *values* are never involved here — only the tool's files and its manifest. The manifest
must already exist in the source folder; authoring one for a code-only folder is a separate flow.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from toolyard.config import load as load_tool

from . import tool_authoring

SIDECAR = ".tsr-source.json"
# Don't drag a source's VCS/build cruft (or a stale sidecar) into the managed copy.
_IGNORE = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", SIDECAR)


class NoManifest(Exception):
    """The source folder has no toolyard.toml — it's code, not yet a tool. The caller decides
    whether to author a manifest for it (a separate flow) rather than treating this as an error."""


def _resolved_dir(source: str) -> Path:
    src = Path(source).expanduser()
    if not src.is_dir():
        raise ValueError(f"not a directory: {source}")
    return src


def add_from_path(source: str, tools_root: str, existing_ids=()) -> dict:
    """Copy a ready tool folder (one containing toolyard.toml) into ``tools_root/<id>`` and record
    its source. Returns ``{id, type, description, path}``. Raises ``NoManifest`` if the folder has
    no manifest, or ``ValueError`` on a bad source / id clash / unwritable destination."""
    src = _resolved_dir(source)
    if not (src / "toolyard.toml").exists():
        raise NoManifest(str(src))
    if not tools_root:
        raise ValueError("no tools_root is configured")
    root = Path(tools_root)
    if src.resolve() == root.resolve() or root.resolve() in src.resolve().parents:
        # otherwise discover() could list both the source and the copy as the same tool
        raise ValueError("source folder is inside the tools dir; choose a folder outside it")
    tool = tool_authoring.read(src)            # normalized dict (id/description/ops/secrets/…)
    # validate() rejects a broken tool at add time (not at broker start) AND bounds the id to a
    # safe single path component (no separators, length-capped) — that's what makes `root / id` safe.
    errors = tool_authoring.validate(tool)
    if errors:
        raise ValueError("; ".join(errors))
    tool_id = tool["id"]
    if tool_id in set(existing_ids):
        raise ValueError(f"a tool named '{tool_id}' already exists")
    dest = root / tool_id
    if dest.exists():
        raise ValueError(f"a folder named '{tool_id}' already exists in the tools dir")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        # symlinks=True copies links verbatim rather than dereferencing them, so a link in the
        # source can't materialize outside-file CONTENT into the managed (possibly synced) tools dir.
        shutil.copytree(src, dest, ignore=_IGNORE, symlinks=True)
    except shutil.Error as exc:
        shutil.rmtree(dest, ignore_errors=True)   # don't leave a half-copied dir that wedges retries
        raise ValueError("could not copy all of the tool's files") from exc
    except OSError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError(f"could not copy the tool's files: {exc.strerror or 'I/O error'}") from exc
    write_source(dest, {"type": "path", "source": str(src.resolve())})
    td = load_tool(dest / "toolyard.toml")
    return {"id": td.id, "type": td.type, "description": td.description, "path": str(dest)}


def write_source(tool_dir: str | Path, meta: dict) -> None:
    """Record where a managed tool came from, for a later re-sync ("Update")."""
    (Path(tool_dir) / SIDECAR).write_text(json.dumps(meta, indent=2), encoding="utf-8")


def read_source(tool_dir: str | Path) -> dict | None:
    """The recorded source for a managed tool, or None if it wasn't added through here."""
    path = Path(tool_dir) / SIDECAR
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
