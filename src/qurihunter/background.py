"""Foreground priority for the background workers. Workers (pending retry, reclassify) work in small batches, call
`checkpoint()` between items and stop to let a running foreground command go first; `/background pause|resume` is the
manual switch and `background_workers` the config switch."""
from __future__ import annotations

import contextlib
import threading
import time

from . import dblock

_lock = threading.Lock()
_state = {"paused": False, "fg": 0}
WORKERS: dict[str, dict] = {}  # name -> {alive, last_tick, job, error}
_sleep = time.sleep


@contextlib.contextmanager
def foreground():
    """Wrap a short foreground command: background workers yield while it runs."""
    with _lock:
        _state["fg"] += 1
    try:
        yield
    finally:
        dblock.flush()
        with _lock:
            _state["fg"] -= 1


def foreground_active() -> bool:
    return _state["fg"] > 0


def paused() -> bool:
    return _state["paused"]


def pause() -> None:
    _state["paused"] = True


def resume() -> None:
    _state["paused"] = False


def should_yield() -> bool:
    return _state["paused"] or _state["fg"] > 0


def checkpoint(max_wait: float = 600.0) -> bool:
    """Background threads only: wait (in small slices) while a foreground command runs or workers are paused.
    Returns False if the caller should stop its batch (paused / waited too long)."""
    if not dblock.is_background():
        return True
    dblock.flush()  # never wait or sleep with a transaction open
    end = time.monotonic() + max_wait
    while should_yield():
        if _state["paused"] or time.monotonic() > end:
            return False
        _sleep(0.2)
    return True


def note(name: str, **kw) -> None:
    WORKERS.setdefault(name, {"alive": True, "last_tick": None, "job": "", "error": ""}).update(kw)


def status_rows() -> list[tuple[str, dict]]:
    return sorted(WORKERS.items())
