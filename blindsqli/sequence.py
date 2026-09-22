"""Sequence / pattern predictor.

Beyond single characters, this tracks whole discovered values and the shared
prefixes/substrings among them, so it can propose *multi-character* continuations
to verify in a single oracle call. Example: after discovering ``jun_users``,
``jun_roles``, ``jun_projects`` it recognises the recurring ``jun_`` prefix and,
when extraction of a new value reaches a matching point, proposes ``jun_`` (and
whole prior values) as sequence hypotheses.

It also provides a cost comparison: expected requests to verify a predicted
sequence vs. discovering those characters one at a time, so the engine can pick
the cheaper strategy.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import List, Sequence, Tuple


@dataclass
class SequenceHypothesis:
    sequence: str
    probability: float          # rough confidence in [0,1]
    source: str                 # why it was proposed (for logging)


class SequencePredictor:
    def __init__(self, min_prefix: int = 2, max_sequence: int = 24) -> None:
        self.min_prefix = min_prefix
        self.max_sequence = max_sequence
        self._values: List[str] = []
        self._prefix_counts: Counter = Counter()

    # ------------------------------------------------------------------ learn
    def learn_value(self, value: str) -> None:
        if not value:
            return
        self._values.append(value)
        # Count every prefix of length >= min_prefix; recurring ones surface.
        for length in range(self.min_prefix, len(value) + 1):
            self._prefix_counts[value[:length]] += 1

    def learn_corpus(self, values: Sequence[str]) -> None:
        for v in values:
            self.learn_value(v)

    # --------------------------------------------------------------- propose
    def propose(self, known_prefix: str, remaining_max: int) -> List[SequenceHypothesis]:
        """Propose sequence continuations for the value being extracted.

        Two families:
          1. *Completion*: a previously seen value whose start matches the known
             prefix -> propose the rest of it.
          2. *Recurring pattern*: a frequently-seen prefix that extends the
             known prefix -> propose the extending characters.
        """
        hyps: dict[str, SequenceHypothesis] = {}

        # 1) whole-value completions
        for value in self._values:
            if len(value) > len(known_prefix) and value.startswith(known_prefix):
                cont = value[len(known_prefix):]
                cont = cont[:remaining_max][: self.max_sequence]
                if cont:
                    prob = min(0.95, 0.5 + 0.1 * self._values.count(value))
                    self._add(hyps, cont, prob, f"completion of seen value {value!r}")

        # 2) recurring extending prefixes
        total = max(1, len(self._values))
        for prefix, count in self._prefix_counts.items():
            if count < 2:
                continue
            if len(prefix) > len(known_prefix) and prefix.startswith(known_prefix):
                cont = prefix[len(known_prefix):]
                cont = cont[:remaining_max][: self.max_sequence]
                if cont:
                    prob = min(0.9, count / total)
                    self._add(hyps, cont, prob, f"recurring pattern {prefix!r} (x{count})")

        return sorted(hyps.values(), key=lambda h: (len(h.sequence) * h.probability), reverse=True)

    @staticmethod
    def _add(store: dict, seq: str, prob: float, source: str) -> None:
        existing = store.get(seq)
        if existing is None or prob > existing.probability:
            store[seq] = SequenceHypothesis(seq, prob, source)

    # --------------------------------------------------------------- costing
    @staticmethod
    def expected_cost_char_by_char(n_chars: int, per_char_requests: float) -> float:
        """Expected requests to get *n_chars* one character at a time."""
        return n_chars * per_char_requests

    @staticmethod
    def expected_cost_sequence(hyp: SequenceHypothesis, per_char_requests: float) -> float:
        """Expected requests to verify a sequence, then fall back if it misses.

        A hit costs 1 request. A miss costs 1 request plus char-by-char of the
        same span. Weighted by the hypothesis probability.
        """
        n = len(hyp.sequence)
        hit = 1.0
        miss = 1.0 + n * per_char_requests
        return hyp.probability * hit + (1 - hyp.probability) * miss

    def worth_testing(self, hyp: SequenceHypothesis, per_char_requests: float) -> bool:
        cbc = self.expected_cost_char_by_char(len(hyp.sequence), per_char_requests)
        seq_cost = self.expected_cost_sequence(hyp, per_char_requests)
        return seq_cost < cbc
