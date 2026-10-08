"""Bounded reads, private writes and keyed redaction. Linux only."""
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat

MAX_BYTES = 10 * 1024 * 1024
class SafeError(Exception):
    """Only static, non-sensitive messages belong in this exception."""


def fingerprint(key, value):
    if not isinstance(value, bytes):
        value = str(value).encode("utf-8")
    return "fp:" + hmac.new(key, value, hashlib.sha256).hexdigest()[:16]


def absolute(path):
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def directory_fd(path):
    """Walk from / using no-follow dirfds, preventing parent-symlink races."""
    path = absolute(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def bounded_read(path, home=None):
    path = absolute(path)
    if home is not None and not path.is_relative_to(absolute(home)):
        raise SafeError("outside home; not inspected")
    parent = directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise SafeError("not a single-link regular file; not inspected")
            if before.st_size > MAX_BYTES:
                raise SafeError("over 10 MB; not inspected")
            data = bytearray()
            while len(data) <= MAX_BYTES:
                block = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = os.fstat(fd)
            if len(data) > MAX_BYTES:
                raise SafeError("over 10 MB; not inspected")
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise SafeError("changed during read; not inspected")
            return bytes(data), before, os.fstat(parent)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def private_dir(path):
    path = absolute(path)
    # Parents are created private as well; pre-existing shared XDG parents are not changed.
    if not path.exists():
        if not path.parent.exists():
            private_dir(path.parent)
        parent = directory_fd(path.parent)
        try:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        finally:
            os.close(parent)
    fd = directory_fd(path)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SafeError("state directory must be owned by this user and mode 0700")
    finally:
        os.close(fd)


def write_private(path, data, replace=False):
    """Create 0600 from the first byte; report destinations never overwrite files."""
    path = absolute(path)
    data = data.encode("utf-8") if isinstance(data, str) else data
    parent = directory_fd(path.parent)
    temp = ".push-guard-sweep-" + secrets.token_hex(12)
    try:
        if replace:
            try:
                old = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                old = None
            if old and (not stat.S_ISREG(old.st_mode) or old.st_uid != os.getuid() or old.st_nlink != 1 or stat.S_IMODE(old.st_mode) != 0o600):
                raise SafeError("unsafe existing state file; refused replacement")
        name = temp if replace else path.name
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if replace:
                os.replace(temp, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            if replace:
                try:
                    os.unlink(temp, dir_fd=parent)
                except FileNotFoundError:
                    pass
    finally:
        os.close(parent)


class Store:
    def __init__(self, path):
        self.path = absolute(path)
        private_dir(self.path)
        try:
            self.key = self.read("fp.key", raw=True)
        except FileNotFoundError:
            if any((self.path / name).exists() for name in ("baseline.json", "last.json")):
                raise SafeError("fingerprint key missing; preserve state and restore the key")
            try:
                write_private(self.path / "fp.key", secrets.token_bytes(32))
            except FileExistsError:
                pass
            self.key = self.read("fp.key", raw=True)
        if len(self.key) != 32:
            raise SafeError("invalid fingerprint key")

    def read(self, name, default=None, raw=False):
        try:
            data, info, _ = bounded_read(self.path / name)
        except FileNotFoundError:
            if raw:
                raise
            return default
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise SafeError("state file must be owned by this user and mode 0600")
        return data if raw else json.loads(data)

    def save(self, name, value):
        data = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        if len(data.encode()) > MAX_BYTES:
            raise SafeError("state size limit exceeded")
        write_private(self.path / name, data, replace=True)


def read_error(exc):
    if isinstance(exc, SafeError):
        return str(exc)
    if isinstance(exc, OSError) and exc.errno in (errno.ELOOP, errno.ENOTDIR):
        return "symlink or non-directory component; not inspected"
    return "unreadable or invalid source; not inspected"
