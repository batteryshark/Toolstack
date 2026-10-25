"""Non-following manifest access anchored to an opened directory."""
import os
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def directory(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            for part in Path(os.path.abspath(path)).parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
        except OSError as exc:
            raise ValueError("manifest directory must contain no links") from exc
        yield fd
    finally:
        os.close(fd)


def check(fd):
    try:
        info = os.stat("toolyard.toml", dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("manifest must be a regular, unlinked file")


def validate(path):
    with directory(path) as fd:
        check(fd)


def read(path):
    with directory(path) as fd:
        check(fd)
        file_fd = os.open("toolyard.toml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("manifest must be a regular, unlinked file")
            return stream.read()


def write(path, text):
    with directory(path) as fd:
        check(fd)
        name = ".manifest-" + uuid.uuid4().hex
        temp = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=fd)
        try:
            with os.fdopen(temp, "w", encoding="utf-8") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            check(fd)
            os.replace(name, "toolyard.toml", src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
