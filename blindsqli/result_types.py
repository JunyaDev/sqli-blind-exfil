"""Core result and verdict types shared across modules.

Keeping these in one dependency-free module means the classifier, oracle and
engine can all agree on vocabulary without importing each other.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Mapping, Optional


class OracleResult(enum.Enum):
    """Result of asking the boolean oracle a single yes/no question.

    Only TRUE and FALSE are *answers*. The other three are conditions the
    caller must never silently treat as FALSE (see reliability requirements).
    """

    TRUE = "TRUE"
    FALSE = "FALSE"
    REQUEST_ERROR = "REQUEST_ERROR"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"

    @property
    def is_definite(self) -> bool:
        return self in (OracleResult.TRUE, OracleResult.FALSE)


class Verdict(enum.Enum):
    """What the response classifier decided about a single HTTP response.

    ERROR  -> the target produced the type-conversion error (condition FALSE).
    OK     -> a normal, non-error response (condition TRUE).
    UNKNOWN-> the classifier could not tell; the oracle should retry.
    """

    OK = "OK"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass
class HttpResponse:
    """Immutable-ish snapshot of one HTTP response, used by the classifier."""

    status: int
    body: str
    length: int
    headers: Mapping[str, str]
    elapsed: float  # seconds
    url: str = ""

    @classmethod
    def from_requests(cls, resp, elapsed: float) -> "HttpResponse":
        body = resp.text or ""
        return cls(
            status=resp.status_code,
            body=body,
            length=len(body),
            headers={k.lower(): v for k, v in resp.headers.items()},
            elapsed=elapsed,
            url=str(resp.url),
        )


@dataclass
class ClassifierDecision:
    """A classifier verdict plus a human-readable explanation for diagnostics."""

    verdict: Verdict
    reason: str
    votes: dict = field(default_factory=dict)


@dataclass
class OracleObservation:
    """Everything the oracle learned answering one question. For logging."""

    condition: str
    result: OracleResult
    attempts: int
    decision: Optional[ClassifierDecision] = None
    response: Optional[HttpResponse] = None
    error: Optional[str] = None
