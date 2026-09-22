"""Test doubles: an in-memory oracle and a scripted HTTP client.

These let the engine, predictors and oracle retry logic be tested
deterministically without any network. The FakeOracle answers boolean
conditions by evaluating them against a known secret using the same condition
grammar the real mock target understands.
"""

from __future__ import annotations

import threading
from typing import Callable, Iterable, List, Optional, Set

from blindsqli.result_types import HttpResponse, OracleObservation, OracleResult
from mock_target import evaluate_condition


class FakeOracle:
    """Evaluates conditions against a secret; optionally returns UNKNOWN for a
    configured set of conditions, and can inject latency to exercise threading."""

    def __init__(
        self,
        secret: str,
        unknown_conditions: Optional[Iterable[str]] = None,
        delay: float = 0.0,
    ) -> None:
        self.secret = secret
        self.unknown: Set[str] = set(unknown_conditions or [])
        self.delay = delay
        self.requests_completed = 0
        self.requests_failed = 0
        self.asked: List[str] = []
        self._lock = threading.Lock()

    def ensure_classifier(self) -> None:
        return None

    def calibrate(self) -> None:
        return None

    def ask(self, condition: str) -> OracleObservation:
        if self.delay:
            import time
            time.sleep(self.delay)
        with self._lock:
            self.requests_completed += 1
            self.asked.append(condition)
        if condition in self.unknown:
            return OracleObservation(condition, OracleResult.UNKNOWN, 1)
        val = evaluate_condition(condition, self.secret)
        return OracleObservation(condition, OracleResult.TRUE if val else OracleResult.FALSE, 1)

    def test(self, condition: str) -> OracleResult:
        return self.ask(condition).result


class ScriptedHttpClient:
    """HTTP client stand-in. `behaviour` is a callable(value) -> HttpResponse or
    raises TimeoutError_/RequestError."""

    def __init__(self, behaviour: Callable[[str], HttpResponse]) -> None:
        self.behaviour = behaviour
        self.calls = 0

    def send(self, injected_value: str) -> HttpResponse:
        self.calls += 1
        return self.behaviour(injected_value)


def html(status: int, body: str, elapsed: float = 0.01) -> HttpResponse:
    return HttpResponse(status=status, body=body, length=len(body), headers={}, elapsed=elapsed)
