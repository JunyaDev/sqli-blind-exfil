"""Tiny leveled logger.

We avoid the stdlib ``logging`` global state so multiple engine instances (and
tests) don't interfere. Verbosity maps: 0 quiet, 1 normal, 2 verbose, 3 debug.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import TextIO


class Logger:
    def __init__(self, verbosity: int = 1, stream: TextIO | None = None) -> None:
        self.verbosity = verbosity
        self.stream = stream or sys.stderr
        self._lock = threading.Lock()
        self._start = time.time()

    def _emit(self, level: int, tag: str, msg: str) -> None:
        if self.verbosity < level:
            return
        with self._lock:
            dt = time.time() - self._start
            self.stream.write(f"[{dt:8.3f}] {tag:5s} {msg}\n")
            self.stream.flush()

    def error(self, msg: str) -> None:
        self._emit(0, "ERROR", msg)

    def info(self, msg: str) -> None:
        self._emit(1, "INFO", msg)

    def verbose(self, msg: str) -> None:
        self._emit(2, "VERB", msg)

    def debug(self, msg: str) -> None:
        self._emit(3, "DEBUG", msg)
