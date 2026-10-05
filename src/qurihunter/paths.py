from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    p = Path(os.environ.get("QURIHUNTER_HOME", Path.home() / ".qurihunter"))
    p.mkdir(parents=True, exist_ok=True)
    try:
        p.chmod(0o700)
    except OSError:
        pass
    return p


def config_path() -> Path:
    return home() / "config.json"


def db_path() -> Path:
    return home() / "qurihunter.db"


def log_path() -> Path:
    return home() / "qurihunter.log"


def lock_path() -> Path:
    return home() / "scan.lock"


def instance_path() -> Path:
    return home() / "instance.lock"
