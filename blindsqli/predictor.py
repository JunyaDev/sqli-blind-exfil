"""Adaptive character predictor.

A data-driven order-k Markov model with stupid-backoff. It learns transition
statistics from every value discovered so far (and from any completed characters
of the value currently being extracted), then ranks candidate next characters by
likelihood given the current known prefix.

Nothing is hard-coded to a particular vocabulary: the model starts from a light
uniform prior over the configured charset and is dominated by observed data as
soon as any exists. A small built-in seed corpus of common identifier shapes can
optionally warm it up.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Tuple

# Boundary marker prepended so the model can also learn "how values start".
BOS = "\x02"


class CharacterPredictor:
    def __init__(self, charset: str, order: int = 3, prior: float = 0.05) -> None:
        self.charset = charset
        self.charset_set = set(charset)
        self.order = max(1, order)
        self.prior = prior
        # counts[k][context][char] -> int, for context lengths 0..order
        self._counts: List[Dict[str, Dict[str, int]]] = [
            defaultdict(lambda: defaultdict(int)) for _ in range(self.order + 1)
        ]
        self._observed_chars: Dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ learn
    def learn_value(self, value: str) -> None:
        """Update the model with a fully-known value."""
        seq = BOS + value
        for i in range(1, len(seq)):
            ch = seq[i]
            if ch not in self.charset_set:
                continue
            self._observed_chars[ch] += 1
            for k in range(0, self.order + 1):
                if i - k < 0:
                    continue
                ctx = seq[i - k:i]
                self._counts[k][ctx][ch] += 1

    def learn_transition(self, prefix: str, ch: str) -> None:
        """Incrementally update from a single newly-discovered character."""
        if ch not in self.charset_set:
            return
        seq = BOS + prefix
        self._observed_chars[ch] += 1
        for k in range(0, self.order + 1):
            start = len(seq) - k
            if start < 0:
                continue
            ctx = seq[start:]
            self._counts[k][ctx][ch] += 1

    def learn_corpus(self, values: Iterable[str]) -> None:
        for v in values:
            self.learn_value(v)

    # ------------------------------------------------------------------- rank
    def _score(self, prefix: str, ch: str) -> float:
        """Stupid-backoff probability estimate for P(ch | prefix)."""
        seq = BOS + prefix
        weight = 1.0
        alpha = 0.4  # backoff discount
        for k in range(self.order, -1, -1):
            start = len(seq) - k
            if start < 0:
                continue
            ctx = seq[start:]
            ctx_counts = self._counts[k].get(ctx)
            if ctx_counts:
                total = sum(ctx_counts.values())
                c = ctx_counts.get(ch, 0)
                if c > 0:
                    return weight * (c / total)
            weight *= alpha
        # Global unigram frequency fallback, then uniform prior.
        total_obs = sum(self._observed_chars.values())
        if total_obs:
            freq = self._observed_chars.get(ch, 0) / total_obs
            return weight * (freq + self.prior / len(self.charset))
        return self.prior / len(self.charset)

    def rank(self, prefix: str, charset: Sequence[str] | None = None) -> List[Tuple[str, float]]:
        """Return candidate chars ranked by descending probability.

        Probabilities are normalised over the candidate set so callers can read
        them as confidences.
        """
        cs = list(charset) if charset is not None else list(self.charset)
        raw = [(ch, self._score(prefix, ch)) for ch in cs]
        total = sum(s for _, s in raw) or 1.0
        ranked = sorted(((ch, s / total) for ch, s in raw), key=lambda t: t[1], reverse=True)
        return ranked

    def probability(self, prefix: str, ch: str) -> float:
        for c, p in self.rank(prefix):
            if c == ch:
                return p
        return 0.0
