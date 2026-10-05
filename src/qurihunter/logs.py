from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from .paths import log_path

log = logging.getLogger("qurihunter")


def setup(verbose: bool = False) -> None:
    if log.handlers:
        return
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    h = RotatingFileHandler(log_path(), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(h)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
