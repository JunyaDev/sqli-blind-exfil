"""Terminal progress reporting.

Decoupled from the engine via a small callback object so output formatting can
change (or be silenced, or redirected to JSON lines) without touching search
logic.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional, TextIO


@dataclass
class ProgressState:
    target: str
    position: int
    known_prefix: str
    candidate: str
    oracle_result: str
    confidence: float
    requests_completed: int
    requests_failed: int
    est_total: Optional[int]

    @property
    def progress(self) -> str:
        if not self.est_total:
            return f"{len(self.known_prefix)} chars"
        pct = 100.0 * len(self.known_prefix) / max(1, self.est_total)
        return f"{len(self.known_prefix)}/{self.est_total} ({pct:.0f}%)"


class Reporter:
    def update(self, state: ProgressState) -> None:  # pragma: no cover - interface
        pass

    def result(self, target: str, value: str, complete: bool) -> None:  # pragma: no cover
        pass


class NullReporter(Reporter):
    pass


class TerminalReporter(Reporter):
    def __init__(self, stream: Optional[TextIO] = None, verbosity: int = 1) -> None:
        self.stream = stream or sys.stdout
        self.verbosity = verbosity

    def update(self, s: ProgressState) -> None:
        if self.verbosity < 1:
            return
        block = (
            f"Target: {s.target}\n"
            f"Position: {s.position}\n"
            f"Known prefix: {s.known_prefix}\n"
            f"Testing candidate: {s.candidate}\n"
            f"Prediction probability: {s.confidence:.2f}\n"
            f"Oracle: {s.oracle_result}\n"
            f"Requests: {s.requests_completed} ok / {s.requests_failed} failed\n"
            f"Progress: {s.progress}\n"
            f"Result: {s.known_prefix}\n"
            f"{'-' * 40}"
        )
        self.stream.write(block + "\n")
        self.stream.flush()

    def result(self, target: str, value: str, complete: bool) -> None:
        status = "COMPLETE" if complete else "PARTIAL"
        self.stream.write(f"\n=== {status} :: {target} = {value!r} ===\n")
        self.stream.flush()
