"""Persistent knowledge base of previously-extracted values.

A small JSON file (a deduplicated set of strings) that the tool can load before
a run and update after it. Two benefits:

  * **Faster re-extraction / cross-checking.** The loaded values seed the
    character and sequence predictors. Because the sequence predictor proposes a
    previously-seen value as a whole-string hypothesis, a value the tool already
    knows is confirmed in roughly a single oracle request instead of being
    rebuilt character by character -- i.e. the tool checks what it already
    extracted first.
  * **Uniqueness.** The file is kept as a set, so re-running never stores
    duplicates; the merged result is always the unique union.
"""

from __future__ import annotations

import json
import os
from typing import Iterable, List


def load_knowledge(path: str) -> List[str]:
    """Return the stored values, or [] if the file is absent/empty/invalid.

    Accepts either a bare JSON array or an object with a "values" array.
    """
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (ValueError, OSError):
        return []
    if isinstance(data, dict):
        data = data.get("values", [])
    if not isinstance(data, list):
        return []
    return [v for v in data if isinstance(v, str) and v]


def save_knowledge(path: str, values: Iterable[str]) -> List[str]:
    """Write the deduplicated, sorted union to *path* atomically. Returns it."""
    uniq = sorted({v for v in values if isinstance(v, str) and v})
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"values": uniq}, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    return uniq


def seed_predictors(char_predictor, seq_predictor, values: Iterable[str]) -> None:
    """Feed known values into the predictors so recurring data is cheap."""
    values = list(values)
    if char_predictor is not None:
        char_predictor.learn_corpus(values)
    if seq_predictor is not None:
        seq_predictor.learn_corpus(values)
