"""Private SPS state paths on a trusted local filesystem.

No protection against a hostile same-account process changing directories.
Existing unsafe objects are refused, never repaired by chmod.
"""
import os
import stat
import tempfile
from pathlib import Path


def private_parent(path):
    parent = Path(os.path.abspath(path)).parent
    current = Path(parent.anchor)
    for component in parent.parts[1:]:
        current /= component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
            raise PermissionError("unsafe SPS directory")
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if info.st_mode & 0o022 and not sticky_root:
            raise PermissionError("unsafe SPS ancestor")
    info = parent.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PermissionError("unsafe SPS parent")
    return parent


def check_file(info, *, public=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.getuid() or info.st_mode & (0o022 if public else 0o077)):
        raise PermissionError("unsafe SPS file")


def validate(path, *, public=False):
    private_parent(path)
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return
    check_file(info, public=public)


def open_private(path, flags, *, public=False):
    validate(path, public=public)
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        check_file(os.fstat(fd), public=public)
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_private(path):
    with os.fdopen(open_private(path, os.O_RDONLY), "r", encoding="utf-8") as source:
        return source.read()


def atomic_write(path, data, *, public=False):
    path = Path(path)
    validate(path, public=public)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            if public:
                os.fchmod(output.fileno(), 0o644)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        validate(path, public=public)
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
