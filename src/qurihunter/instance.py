"""One interactive/watching qurihunter per home. A PID lock file refuses a second instance with a clear message; a process
scan additionally warns about instances that do not use the lock (an old version still running, another terminal)."""
from __future__ import annotations

import atexit
import json
import os

from datetime import datetime

import psutil

from . import dates
from .paths import home, instance_path


def _is_qurihunter(p: psutil.Process) -> bool:
    try:
        cmd = p.cmdline()
    except (psutil.Error, OSError):
        return False
    low = [os.path.basename(c) for c in cmd[:3]]
    if any(c in ("pytest", "py.test") for c in low) or "pytest" in " ".join(cmd[:3]):
        return False
    return any(c == "qurihunter" or c == "qurihunter.py" for c in low) or "qurihunter.cli" in " ".join(cmd[:4]) \
        or (len(cmd) > 2 and cmd[1] == "-m" and cmd[2].startswith("qurihunter"))


def _alive(pid: int) -> bool:
    try:
        return psutil.pid_exists(pid) and _is_qurihunter(psutil.Process(pid))
    except psutil.Error:
        return False


def _same_home(p: psutil.Process) -> bool:
    try:
        env = p.environ().get("QURIHUNTER_HOME")
    except (psutil.Error, OSError):
        return True  # cannot tell: assume it matters
    mine = os.environ.get("QURIHUNTER_HOME")
    return (env or "") == (mine or "")


def others() -> list[tuple[int, str]]:
    """Other qurihunter processes (pid, started) working on the same home, excluding this one and its relatives."""
    me = os.getpid()
    skip = {me}
    try:
        skip |= {p.pid for p in psutil.Process(me).parents()}
    except psutil.Error:
        pass
    out = []
    for p in psutil.process_iter(["pid"]):
        if p.pid in skip or not _is_qurihunter(p) or not _same_home(p):
            continue
        try:
            out.append((p.pid, dates.iso(datetime.fromtimestamp(p.create_time(), dates.UTC))))
        except psutil.Error:
            continue
    return out


def holder() -> dict | None:
    """The live instance holding the lock, if any (stale locks are ignored)."""
    p = instance_path()
    try:
        d = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    pid = int(d.get("pid", 0))
    return d if pid and pid != os.getpid() and _alive(pid) else None


def acquire(force: bool = False) -> tuple[bool, str]:
    h = holder()
    if h and not force:
        return False, (f"another qurihunter is already running against {home()} (pid {h['pid']}, started "
                       f"{h.get('started', '?')}). Close it first, or start with --force to ignore this check "
                       "(two instances can send duplicate alerts).")
    instance_path().write_text(json.dumps({"pid": os.getpid(), "started": dates.now_iso()}))
    atexit.register(release)
    return True, ""


def release() -> None:
    try:
        d = json.loads(instance_path().read_text())
        if int(d.get("pid", -1)) == os.getpid():
            instance_path().unlink()
    except (OSError, ValueError):
        pass


def warnings() -> list[str]:
    o = others()
    if not o:
        return []
    return [f"another qurihunter process is running on this home (pid {', '.join(str(p) for p, _ in o)}). If it is an old "
            "session it still runs OLD code - quit it. Two instances can send duplicate alerts."]
