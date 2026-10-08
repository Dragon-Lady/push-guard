"""Linux scan boundaries and one shared, bounded inspection deadline."""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import signal
import threading
import time

from .sweep_safety import SafeError, absolute, directory_fd


class BudgetExceeded(Exception):
    """Static reason only; partial inspection results must survive this stop."""
    def __init__(self, reason):
        self.reason = reason


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds
        self.phase_deadline = None

    def check(self):
        now = time.monotonic()
        if now >= self.deadline:
            raise BudgetExceeded('time_budget')
        if self.phase_deadline is not None and now >= self.phase_deadline[0]:
            raise BudgetExceeded(self.phase_deadline[1])

    @contextmanager
    def phase(self, seconds=None, reason='time_budget'):
        """Also interrupt long pattern matching in the single-threaded CLI.

        Library callers in other threads retain cooperative checkpoints. Do not
        replace another application's existing interval timer or alarm handler.
        """
        self.check()
        limit = self.deadline if seconds is None else min(self.deadline, time.monotonic() + seconds)
        reason = 'time_budget' if limit == self.deadline else reason
        previous_phase = self.phase_deadline
        self.phase_deadline = (limit, reason)
        armed = (threading.current_thread() is threading.main_thread()
                 and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0))
        if armed:
            old = signal.getsignal(signal.SIGALRM)
            def stop(signum, frame):
                raise BudgetExceeded(reason)
            signal.signal(signal.SIGALRM, stop)
            signal.setitimer(signal.ITIMER_REAL, max(0.001, limit - time.monotonic()))
        try:
            yield
        finally:
            self.phase_deadline = previous_phase
            if armed:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old)


class MountSkipped(SafeError):
    def __init__(self):
        super().__init__('filesystem boundary; not inspected')


def mount_records():
    # Kernel metadata, not scan-target content. Never invoke mount/findmnt/Git.
    with open('/proc/self/mountinfo', 'rb') as stream:
        data = stream.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise SafeError('mount metadata unavailable; not inspected')
    records = []
    for line in data.decode('utf-8', 'surrogateescape').splitlines():
        fields = line.split()
        divider = fields.index('-')
        if divider < 6 or len(fields) < divider + 4:
            raise ValueError('invalid mount metadata')
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        records.append((int(fields[0]), Path(point), fields[divider + 1]))
    if not records:
        raise ValueError('empty mount metadata')
    return records


def fd_mount_id(fd):
    # A bind mount can share st_dev: compare the descriptor's kernel mount ID.
    with open(f'/proc/self/fdinfo/{fd}', 'rb') as stream:
        data = stream.read(16385)
    if len(data) > 16384:
        raise SafeError('mount metadata unavailable; not inspected')
    for line in data.splitlines():
        if line.startswith(b'mnt_id:'):
            return int(line.split()[1])
    raise SafeError('mount metadata unavailable; not inspected')


class ScanFS:
    """Reject every mount below HOME, including same-device file bind mounts.

    Known mount points are rejected before stat/open/scandir. Open descriptors
    are checked again by device and mount ID before listing or reading, covering
    replacement by a bind mount after the mountinfo snapshot.
    """
    def __init__(self, home):
        self.home = absolute(home)
        self.blocked = set()
        self.seen_skips = set()
        self.unknown = False
        self.home_remote = False
        self.device = None
        self.mount_id = None
        try:
            records = mount_records()
            enclosing = [(mid, p, fs) for mid, p, fs in records if self.home.is_relative_to(p)]
            if not enclosing:
                raise ValueError('HOME mount missing')
            _, _, fs = max(enclosing, key=lambda record: len(record[1].parts))
            self.home_remote = fs.startswith(('fuse', 'nfs', 'cifs', 'smb', 'rclone', 'autofs', '9p'))
            self.blocked = {p for _, p, _ in records if p != self.home and p.is_relative_to(self.home)}
            if self.home_remote:
                self.blocked.add(self.home)
                return
            fd = directory_fd(self.home)
            try:
                self.device = os.fstat(fd).st_dev
                self.mount_id = fd_mount_id(fd)
            finally:
                os.close(fd)
        except (OSError, ValueError, SafeError):
            self.unknown = True

    def check_path(self, path):
        path = Path(path)
        if not path.is_absolute():
            path = absolute(path)
        if not path.is_relative_to(self.home):
            raise SafeError('outside HOME; not inspected')
        if self.unknown:
            raise SafeError('mount metadata unavailable; not inspected')
        for mount in self.blocked:
            if path.is_relative_to(mount):
                self.seen_skips.add(mount)
                raise MountSkipped()

    def check_stat(self, path, info):
        if info.st_dev != self.device:
            self.seen_skips.add(absolute(path))
            raise MountSkipped()

    def check_fd(self, path, fd):
        self.check_stat(path, os.fstat(fd))
        try:
            mount_id = fd_mount_id(fd)
        except (OSError, ValueError) as exc:
            raise SafeError('mount metadata unavailable; not inspected') from exc
        if mount_id != self.mount_id:
            self.seen_skips.add(absolute(path))
            raise MountSkipped()

    def directory(self, path):
        path = absolute(path)
        self.check_path(path)
        fd = directory_fd(self.home)
        try:
            self.check_fd(self.home, fd)
            walked = self.home
            for part in path.relative_to(self.home).parts:
                walked = walked / part
                self.check_path(walked)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                self.check_fd(walked, fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def child_directory(self, path, parent_fd):
        """Reuse the already-verified parent descriptor during recursive walks."""
        self.check_path(path)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            self.check_fd(path, fd)
            return fd
        except BaseException:
            os.close(fd)
            raise
