"""Bring a tool's directory INTO the deployment's managed tools dir.

The native app and Docker deployments can't reference arbitrary host paths at run time, so
"adding" a tool COPIES its folder into the broker's ``tools_root`` (where it is auto-discovered).
A small ``.tsr-source.json`` sidecar records where it came from (a local path or a git repo) so
the tool can be re-synced later ("Update").

Secret *values* are never involved here — only the tool's files and its manifest. The manifest
must already exist in the source folder; authoring one for a code-only folder is a separate flow.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from toolyard.config import load as load_tool

from . import tool_authoring

SIDECAR = ".tsr-source.json"
# Don't drag a source's VCS/build cruft (or a stale sidecar) into the managed copy.
_IGNORE = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", SIDECAR)
# Only real fetch transports — NOT file://, ext::, fd:: (which can run commands) or a leading '-'.
_GIT_URL_RE = re.compile(r"^(https?://|git@|ssh://)")


class NoManifest(Exception):
    """The source folder has no toolyard.toml — it's code, not yet a tool. The caller decides
    whether to author a manifest for it (a separate flow) rather than treating this as an error."""


def _resolved_dir(source: str) -> Path:
    src = Path(source).expanduser()
    if not src.is_dir():
        # The path is resolved on the ADMIN's machine. A Docker/remote admin only sees its own
        # filesystem (e.g. /data), so a host folder picked on a laptop won't exist for it.
        raise ValueError(f"directory not found on the admin: {source} — a Docker or remote admin "
                         "sees only its own filesystem (e.g. /data), not this computer's folders")
    return src


def add_from_path(source: str, tools_root: str, existing_ids=()) -> dict:
    """Copy a ready tool folder (one containing toolyard.toml) into ``tools_root/<id>`` and record
    its source. Returns ``{id, type, description, path}``. Raises ``NoManifest`` if the folder has
    no manifest, or ``ValueError`` on a bad source / id clash / unwritable destination."""
    src = _resolved_dir(source)
    if not tools_root:
        raise ValueError("no tools_root is configured")
    root = Path(tools_root)
    if src.resolve() == root.resolve() or root.resolve() in src.resolve().parents:
        # otherwise discover() could list both the source and the copy as the same tool
        raise ValueError("source folder is inside the tools dir; choose a folder outside it")
    return _ingest(src, root, existing_ids, {"type": "path", "source": str(src.resolve())})


def add_from_github(repo: str, tools_root: str, existing_ids=(), *,
                    subdir: str = "", ref: str = "") -> dict:
    """Shallow-clone a git repo and copy its tool folder (the repo root, or ``subdir`` within it)
    into ``tools_root/<id>``, recording the repo for a later Update. Returns ``{id, type,
    description, path}``. Raises ``NoManifest`` (no toolyard.toml) or ``ValueError`` (bad URL /
    missing git / clone failure / id clash). NOTE: a cloned tool is THIRD-PARTY code — it is copied
    in but never executed here; the operator starts it explicitly and grants it policy."""
    url = (repo or "").strip()
    if not _GIT_URL_RE.match(url) or any(c.isspace() for c in url):
        # the scheme guard blocks file://, ext::, fd:: and a leading '-'; the no-whitespace rule
        # stops a second transport being smuggled in after a newline (the '--' below is the backstop).
        raise ValueError("repo must be a single https://, http://, git@ or ssh:// git URL")
    if not tools_root:
        raise ValueError("no tools_root is configured")
    if shutil.which("git") is None:
        raise ValueError("git is not installed on the admin's machine")
    sub = (subdir or "").strip().strip("/")
    if sub.startswith("..") or "/.." in sub or sub.startswith("/"):
        raise ValueError("subdir must be a relative path inside the repo")
    branch = (ref or "").strip()
    with tempfile.TemporaryDirectory(prefix="tsr-clone-") as tmp:
        clone = Path(tmp) / "repo"
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd += [f"--branch={branch}"]   # '=' binds the value, so a ref can't be read as a flag
        cmd += ["--", url, str(clone)]   # '--' so a URL like '--upload-pack=…' can't be read as a flag
        try:
            # No tty/credential/host-key prompts: fail fast instead of blocking a request.
            subprocess.run(cmd, capture_output=True, timeout=120, check=True,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                                "GIT_SSH_COMMAND": "ssh -oBatchMode=yes -oStrictHostKeyChecking=yes"})
        except subprocess.TimeoutExpired:
            raise ValueError("git clone timed out")
        except subprocess.CalledProcessError as exc:
            raise ValueError(f"git clone failed: {_clone_error(exc)}")
        tool_dir = (clone / sub) if sub else clone
        # belt-and-suspenders: a symlinked subdir could still resolve outside the clone
        if not tool_dir.resolve().is_relative_to(clone.resolve()):
            raise ValueError("subdir escapes the repository")
        if not tool_dir.is_dir():
            raise ValueError(f"subdir not found in the repo: {sub or '.'}")
        return _ingest(tool_dir, Path(tools_root), existing_ids,
                       {"type": "github", "url": url, "subdir": sub, "ref": branch})


def _clone_error(exc: subprocess.CalledProcessError) -> str:
    """A short reason from git's stderr (last line), bounded so we don't dump a wall of text."""
    raw = exc.stderr or b""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return (lines[-1].strip()[:200] if lines else f"exit {exc.returncode}")


def _ingest(tool_dir: Path, root: Path, existing_ids, meta: dict) -> dict:
    """Validate the tool at ``tool_dir`` and copy it into ``root/<id>`` with a source sidecar.
    Shared by add_from_path / add_from_github. Raises ``NoManifest`` / ``ValueError``."""
    if not (tool_dir / "toolyard.toml").exists():
        raise NoManifest(str(tool_dir))
    tool = tool_authoring.read(tool_dir)        # normalized dict (id/description/ops/secrets/…)
    # validate() rejects a broken tool now (not at broker start) AND bounds the id to a safe single
    # path component (no separators, length-capped) — that's what makes `root / id` safe.
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
        shutil.copytree(tool_dir, dest, ignore=_IGNORE, symlinks=True)
    except shutil.Error as exc:
        shutil.rmtree(dest, ignore_errors=True)   # don't leave a half-copied dir that wedges retries
        raise ValueError("could not copy all of the tool's files") from exc
    except OSError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError(f"could not copy the tool's files: {exc.strerror or 'I/O error'}") from exc
    write_source(dest, meta)
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
