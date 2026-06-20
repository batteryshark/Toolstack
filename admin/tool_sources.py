"""Bring a tool's directory INTO the deployment's managed tools dir.

The native app and Docker deployments can't reference arbitrary host paths at run time, so
"adding" a tool COPIES its folder into the broker's ``tools_root`` (where it is auto-discovered).
A small ``.tsr-source.json`` sidecar records where it came from (a local path or a git repo) so
the tool can be re-synced later ("Update").

Secret *values* are never involved here: only the tool's files and its manifest. The manifest
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
# Only real fetch transports: NOT file://, ext::, fd:: (which can run commands) or a leading '-'.
_GIT_URL_RE = re.compile(r"^(https?://|git@|ssh://)")


class NoManifest(Exception):
    """The source folder has no toolyard.toml: it's code, not yet a tool. The caller decides
    whether to author a manifest for it (a separate flow) rather than treating this as an error."""


def _resolved_dir(source: str) -> Path:
    src = Path(source).expanduser()
    if not src.is_dir():
        # The path is resolved on the ADMIN's machine. A Docker/remote admin only sees its own
        # filesystem (e.g. /data), so a host folder picked on a laptop won't exist for it.
        raise ValueError(f"directory not found on the admin: {source}; a Docker or remote admin "
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
    missing git / clone failure / id clash). NOTE: a cloned tool is THIRD-PARTY code; it is copied
    in but never executed here; the operator starts it explicitly and grants it policy."""
    if not tools_root:
        raise ValueError("no tools_root is configured")
    url = (repo or "").strip()
    sub = (subdir or "").strip().strip("/")
    branch = (ref or "").strip()
    with tempfile.TemporaryDirectory(prefix="tsr-clone-") as tmp:
        tool_dir = _clone_into(Path(tmp), url, branch, sub)
        return _ingest(tool_dir, Path(tools_root), existing_ids,
                       {"type": "github", "url": url, "subdir": sub, "ref": branch})


def _clone_into(tmp: Path, url: str, branch: str, sub: str) -> Path:
    """Shallow-clone ``url`` (at ``branch`` if given) into ``tmp/repo`` and return the tool dir
    (repo root, or ``sub`` within it). Validates the URL + subdir. Raises ``ValueError`` on a bad
    URL / missing git / clone failure / subdir escape. The caller owns ``tmp`` and must keep it
    alive until the tool is copied out. Shared by add_from_github and update()."""
    if not _GIT_URL_RE.match(url) or any(c.isspace() for c in url):
        # the scheme guard blocks file://, ext::, fd:: and a leading '-'; the no-whitespace rule
        # stops a second transport being smuggled in after a newline (the '--' below is the backstop).
        raise ValueError("repo must be a single https://, http://, git@ or ssh:// git URL")
    if shutil.which("git") is None:
        raise ValueError("git is not installed on the admin's machine")
    if sub.startswith("..") or "/.." in sub or sub.startswith("/"):
        raise ValueError("subdir must be a relative path inside the repo")
    clone = tmp / "repo"
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += [f"--branch={branch}"]   # '=' binds the value, so a ref can't be read as a flag
    cmd += ["--", url, str(clone)]   # '--' so a URL like '--upload-pack=...' can't be read as a flag
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
    return tool_dir


def update(dir_path: str | Path) -> dict:
    """Re-sync a managed tool from its recorded source (``.tsr-source.json``), KEEPING the operator's
    description + secret declarations while taking the source's operations/entrypoint. Returns
    ``{id, type, description, path}``. Raises ``NoManifest`` (source lost its manifest) or
    ``ValueError`` (not added via TSR / source gone / id changed / broken). A github source is
    re-cloned (third-party code, still never executed here)."""
    dest = Path(dir_path)
    source = read_source(dest)
    if not source:
        raise ValueError("this tool wasn't added through TSR (no recorded source); can't update it")
    tool_id = dest.name
    local = tool_authoring.read(dest)   # the operator's current description + secret declarations
    with tempfile.TemporaryDirectory(prefix="tsr-update-") as tmp:
        kind = source.get("type")
        if kind == "path":
            new_dir = Path(source.get("source", "")).expanduser()
            if not new_dir.is_dir():
                raise ValueError(f"the tool's source folder is gone: {new_dir}")
        elif kind == "github":
            new_dir = _clone_into(Path(tmp), (source.get("url") or "").strip(),
                                  (source.get("ref") or "").strip(),
                                  (source.get("subdir") or "").strip().strip("/"))
        else:
            raise ValueError(f"unknown source type: {kind!r}")
        if not (new_dir / "toolyard.toml").exists():
            raise NoManifest(str(new_dir))
        merged = tool_authoring.read(new_dir)   # upstream operations + entrypoint
        # the managed dir is named by id (_ingest: root/<id>), so this guards against the source
        # silently becoming a different tool under the same folder.
        if merged["id"] != tool_id:
            raise ValueError(f"the source now declares id '{merged['id']}', not '{tool_id}'; "
                             "remove the tool and add it again")
        # operator's wiring wins WHEN they set it; otherwise fall through to the source's (so a tool
        # the operator never customized still picks up upstream's new description / required secrets).
        merged["description"] = local["description"] or merged["description"]
        merged["secrets"] = local["secrets"] or merged["secrets"]
        errors = list(tool_authoring.validate(merged))
        ep = tool_authoring.entrypoint_error(merged, new_dir)
        if ep:
            errors.append(ep)
        if errors:
            raise ValueError("; ".join(errors))
        _swap_in_place(dest, new_dir, merged, source)
    td = load_tool(dest / "toolyard.toml")
    return {"id": td.id, "type": td.type, "description": td.description, "path": str(dest)}


def _swap_in_place(dest: Path, new_dir: Path, merged: dict, source: dict) -> None:
    """Replace ``dest``'s contents with ``new_dir``'s files + the merged manifest + the source
    sidecar, via a staged rename so a mid-operation failure leaves the original tool intact.

    Staging/backup live in ``<tools_root>/.tsr-staging/``: one level deeper than the tools, so the
    ``*/toolyard.toml`` discovery glob never sees them (a half-built or crash-orphaned copy can't be
    mistaken for, or shadow, a real tool), while staying on the same filesystem so ``os.replace`` is
    atomic (no cross-device rename)."""
    work = dest.parent / ".tsr-staging"
    shutil.rmtree(work, ignore_errors=True)   # clear any orphan from a previous crashed update
    work.mkdir(parents=True, exist_ok=True)
    staging = work / dest.name
    backup = work / (dest.name + ".old")
    try:
        shutil.copytree(new_dir, staging, ignore=_IGNORE, symlinks=True)
        tool_authoring.write(staging, merged)   # merged toolyard.toml (upstream ops + operator wiring)
        write_source(staging, source)           # keep the source record for the next Update
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
    os.replace(dest, backup)            # current aside (atomic, same filesystem)
    try:
        os.replace(staging, dest)       # new into place (atomic)
    except Exception:
        os.replace(backup, dest)        # restore the original on failure
        shutil.rmtree(work, ignore_errors=True)
        raise
    shutil.rmtree(work, ignore_errors=True)


def _clone_error(exc: subprocess.CalledProcessError) -> str:
    """A short reason from git's stderr (last line), bounded so we don't dump a wall of text.
    The common case (a private/missing repo the admin has no credentials for) gets a plain-English
    message instead of git's cryptic 'could not read Username ... terminal prompts disabled'."""
    raw = exc.stderr or b""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    low = text.lower()
    if ("could not read username" in low or "authentication failed" in low
            or "terminal prompts disabled" in low or "permission denied" in low):
        return ("repository not found or private; the admin has no git credentials for it "
                "(use a public repo, or configure credentials on the admin host)")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return (lines[-1].strip()[:200] if lines else f"exit {exc.returncode}")


def _ingest(tool_dir: Path, root: Path, existing_ids, meta: dict) -> dict:
    """Validate the tool at ``tool_dir`` and copy it into ``root/<id>`` with a source sidecar.
    Shared by add_from_path / add_from_github. Raises ``NoManifest`` / ``ValueError``."""
    if not (tool_dir / "toolyard.toml").exists():
        raise NoManifest(str(tool_dir))
    tool = tool_authoring.read(tool_dir)        # normalized dict (id/description/ops/secrets/...)
    # validate() rejects a broken tool now (not at broker start) AND bounds the id to a safe single
    # path component (no separators, length-capped): that's what makes `root / id` safe.
    errors = list(tool_authoring.validate(tool))
    ep = tool_authoring.entrypoint_error(tool, tool_dir)
    if ep:
        errors.append(ep)
    if errors:
        raise ValueError("; ".join(errors))
    tool_id = tool["id"]
    if tool_id in set(existing_ids):
        raise ValueError(f"a tool named '{tool_id}' already exists")
    dest = _copy_tool_dir(tool_dir, root, tool_id)
    write_source(dest, meta)
    td = load_tool(dest / "toolyard.toml")
    return {"id": td.id, "type": td.type, "description": td.description, "path": str(dest)}


def add_with_manifest(source: str, tools_root: str, existing_ids, manifest: dict) -> dict:
    """The 'point at code, author the tool in-app' flow: copy a folder that need NOT contain a
    toolyard.toml into ``tools_root/<id>`` and write the authored manifest into the copy. Returns
    ``{id, type, description, path}``. Raises ``ValueError`` on a bad source / invalid manifest / id
    clash. NO source sidecar is written: there's no upstream manifest to re-pull, so the tool isn't
    'updatable' (its id/ops are what you authored; description+secrets stay editable)."""
    src = _resolved_dir(source)
    if not tools_root:
        raise ValueError("no tools_root is configured")
    root = Path(tools_root)
    if src.resolve() == root.resolve() or root.resolve() in src.resolve().parents:
        raise ValueError("source folder is inside the tools dir; choose a folder outside it")
    tool = tool_authoring.normalize(manifest)
    errors = list(tool_authoring.validate(tool))   # also bounds the id to a safe single path component
    ep = tool_authoring.entrypoint_error(tool, src)
    if ep:
        errors.append(ep)
    if errors:
        raise ValueError("; ".join(errors))
    tool_id = tool["id"]
    if tool_id in set(existing_ids):
        raise ValueError(f"a tool named '{tool_id}' already exists")
    dest = _copy_tool_dir(src, root, tool_id)
    tool_authoring.write(dest, tool)   # write the authored toolyard.toml into the copied code
    td = load_tool(dest / "toolyard.toml")
    return {"id": td.id, "type": td.type, "description": td.description, "path": str(dest)}


def _copy_tool_dir(src: Path, root: Path, tool_id: str) -> Path:
    """Copy ``src`` into ``root/<tool_id>`` (rejecting a clash), rolling back a half-copy on failure.
    ``symlinks=True`` copies links verbatim rather than dereferencing them, so a link in the source
    can't materialize outside-file CONTENT into the managed (possibly synced) tools dir."""
    dest = root / tool_id
    if dest.exists():
        raise ValueError(f"a folder named '{tool_id}' already exists in the tools dir")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(src, dest, ignore=_IGNORE, symlinks=True)
    except shutil.Error as exc:
        shutil.rmtree(dest, ignore_errors=True)   # don't leave a half-copied dir that wedges retries
        raise ValueError("could not copy all of the tool's files") from exc
    except OSError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError(f"could not copy the tool's files: {exc.strerror or 'I/O error'}") from exc
    return dest


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
