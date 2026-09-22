"""Response classifiers.

The classifier decides, for one HTTP response, whether the target produced its
error condition (=> the SQL condition was FALSE) or a normal response (=> TRUE).

Per the brief, HTTP status alone is not assumed sufficient. Classifiers can use
status, body signatures, body length, headers and timing, and can be composed.
An auto-calibrating classifier learns the true/false fingerprint from probes,
so you do not have to know the error format in advance.

Every classifier is independently replaceable: they share only the
``classify(response) -> ClassifierDecision`` contract.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence
from urllib.parse import quote

from .config import ClassifierConfig
from .result_types import ClassifierDecision, HttpResponse, Verdict


def strip_reflection(body: str, sent: Optional[str]) -> str:
    """Remove occurrences of the injected payload (and common encodings of it)
    from *body*.

    Many targets echo the submitted query/parameter back in the response, so a
    longer payload yields a longer body. That reflection would otherwise make
    body length track the payload length instead of the true/false signal,
    which breaks length-based classification. Removing it normalizes the body so
    only the genuine true/false difference remains.
    """
    if not sent:
        return body
    variants = [sent]
    try:
        variants.append(quote(sent))
        variants.append(quote(sent, safe=""))
    except Exception:  # pragma: no cover - defensive
        pass
    # HTML-escaped form (common when reflected into an HTML page)
    variants.append(
        sent.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;").replace("'", "&#39;")
    )
    for v in variants:
        if v:
            body = body.replace(v, "")
    return body


class BaseClassifier:
    def classify(self, response: HttpResponse, sent: Optional[str] = None) -> ClassifierDecision:  # pragma: no cover
        raise NotImplementedError


class StatusClassifier(BaseClassifier):
    def __init__(self, error_status: Sequence[int], ok_status: Sequence[int]) -> None:
        self.error_status = set(error_status)
        self.ok_status = set(ok_status)

    def classify(self, response: HttpResponse, sent=None) -> ClassifierDecision:
        if response.status in self.error_status:
            return ClassifierDecision(Verdict.ERROR, f"status {response.status} in error set")
        if response.status in self.ok_status:
            return ClassifierDecision(Verdict.OK, f"status {response.status} in ok set")
        return ClassifierDecision(Verdict.UNKNOWN, f"status {response.status} unclassified")


class SignatureClassifier(BaseClassifier):
    """Matches substrings/regexes in the body (and optionally headers)."""

    def __init__(
        self,
        error_body: Sequence[str] = (),
        ok_body: Sequence[str] = (),
        error_headers: Optional[dict] = None,
    ) -> None:
        self.error_body = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in error_body]
        self.ok_body = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in ok_body]
        self.error_headers = {k.lower(): re.compile(v, re.I) for k, v in (error_headers or {}).items()}

    def classify(self, response: HttpResponse, sent=None) -> ClassifierDecision:
        for rx in self.error_body:
            if rx.search(response.body):
                return ClassifierDecision(Verdict.ERROR, f"body matched error signature /{rx.pattern}/")
        for name, rx in self.error_headers.items():
            val = response.headers.get(name, "")
            if rx.search(val):
                return ClassifierDecision(Verdict.ERROR, f"header {name} matched /{rx.pattern}/")
        for rx in self.ok_body:
            if rx.search(response.body):
                return ClassifierDecision(Verdict.OK, f"body matched ok signature /{rx.pattern}/")
        return ClassifierDecision(Verdict.UNKNOWN, "no signature matched")


class LengthClassifier(BaseClassifier):
    """Bodies shorter than a threshold are treated as errors (or vice versa)."""

    def __init__(self, threshold: int, shorter_is_error: bool = True) -> None:
        self.threshold = threshold
        self.shorter_is_error = shorter_is_error

    def classify(self, response: HttpResponse, sent=None) -> ClassifierDecision:
        short = response.length < self.threshold
        is_error = short if self.shorter_is_error else not short
        verdict = Verdict.ERROR if is_error else Verdict.OK
        return ClassifierDecision(
            verdict, f"length {response.length} vs threshold {self.threshold}"
        )


class TimingClassifier(BaseClassifier):
    """Slower-than-threshold responses are treated as errors (time side channel)."""

    def __init__(self, threshold: float) -> None:
        self.threshold = threshold

    def classify(self, response: HttpResponse, sent=None) -> ClassifierDecision:
        if response.elapsed >= self.threshold:
            return ClassifierDecision(Verdict.ERROR, f"elapsed {response.elapsed:.3f}s >= {self.threshold}s")
        return ClassifierDecision(Verdict.OK, f"elapsed {response.elapsed:.3f}s < {self.threshold}s")


class CompositeClassifier(BaseClassifier):
    """Runs sub-classifiers in order; first definite (non-UNKNOWN) verdict wins.

    This lets you layer, e.g., a precise body signature first, then fall back to
    a length heuristic, then status.
    """

    def __init__(self, classifiers: Sequence[BaseClassifier], default: Verdict = Verdict.UNKNOWN) -> None:
        self.classifiers = list(classifiers)
        self.default = default

    def classify(self, response: HttpResponse, sent=None) -> ClassifierDecision:
        votes = {}
        for clf in self.classifiers:
            decision = clf.classify(response, sent)
            votes[type(clf).__name__] = decision.verdict.value
            if decision.verdict is not Verdict.UNKNOWN:
                decision.votes = votes
                return decision
        return ClassifierDecision(self.default, "no sub-classifier decided", votes)


class BaselineClassifier(BaseClassifier):
    """Auto-calibrated classifier.

    Given a known-OK sample and a known-ERROR sample (from calibration probes),
    it decides by nearest-fingerprint using status, then body length, then a
    diffed body signature. This is what runs when you don't hand-write rules.
    """

    def __init__(self, ok: HttpResponse, error: HttpResponse, length_tolerance: int = 0,
                 ok_sent: Optional[str] = None, error_sent: Optional[str] = None) -> None:
        self.ok = ok
        self.error = error
        self.length_tolerance = length_tolerance
        # Reflection-normalized bodies: strip each sample's own payload so the
        # calibrated lengths/markers reflect the true/false difference only, not
        # the length of the probe payload.
        self._ok_body = strip_reflection(ok.body, ok_sent)
        self._error_body = strip_reflection(error.body, error_sent)
        self._ok_len = len(self._ok_body)
        self._error_len = len(self._error_body)
        self._error_marker = self._diff_marker(self._error_body, self._ok_body)
        self._ok_marker = self._diff_marker(self._ok_body, self._error_body)

    @staticmethod
    def _diff_marker(a: str, b: str, span: int = 60) -> Optional[str]:
        """A short substring present in *a* but not *b*, if any."""
        # Find first line in a not present in b; cheap and effective for
        # error pages that add a stack-trace / message line.
        b_lines = set(b.splitlines())
        for line in a.splitlines():
            line = line.strip()
            if len(line) >= 4 and line not in b_lines and line in a:
                return line[:span]
        return None

    def classify(self, response: HttpResponse, sent: Optional[str] = None) -> ClassifierDecision:
        body = strip_reflection(response.body, sent)
        length = len(body)

        # 1) Distinct status codes are the strongest signal.
        if self.ok.status != self.error.status:
            if response.status == self.error.status:
                return ClassifierDecision(Verdict.ERROR, f"status matches calibrated error {self.error.status}")
            if response.status == self.ok.status:
                return ClassifierDecision(Verdict.OK, f"status matches calibrated ok {self.ok.status}")

        # 2) Distinctive body markers (on reflection-normalized bodies).
        if self._error_marker and self._error_marker in body:
            return ClassifierDecision(Verdict.ERROR, f"body contains calibrated error marker {self._error_marker!r}")
        if self._ok_marker and self._ok_marker in body:
            return ClassifierDecision(Verdict.OK, f"body contains calibrated ok marker {self._ok_marker!r}")

        # 3) Body length nearest-neighbour (reflection-normalized).
        d_ok = abs(length - self._ok_len)
        d_err = abs(length - self._error_len)
        if d_ok != d_err:
            if d_err < d_ok:
                return ClassifierDecision(Verdict.ERROR, f"normalized length {length} closer to error {self._error_len}")
            return ClassifierDecision(Verdict.OK, f"normalized length {length} closer to ok {self._ok_len}")

        return ClassifierDecision(Verdict.UNKNOWN, "response resembles neither calibrated sample")


def from_config(cfg: ClassifierConfig) -> Optional[BaseClassifier]:
    """Build a classifier from explicit config, or None if nothing configured
    (meaning: rely on auto-calibration)."""
    layers: List[BaseClassifier] = []
    if cfg.error_body_signatures or cfg.ok_body_signatures or cfg.error_header_signatures:
        layers.append(SignatureClassifier(cfg.error_body_signatures, cfg.ok_body_signatures, cfg.error_header_signatures))
    if cfg.error_status or cfg.ok_status:
        layers.append(StatusClassifier(cfg.error_status, cfg.ok_status))
    if cfg.length_threshold is not None:
        layers.append(LengthClassifier(cfg.length_threshold))
    if cfg.timing_threshold is not None:
        layers.append(TimingClassifier(cfg.timing_threshold))
    if not layers:
        return None
    return CompositeClassifier(layers)
