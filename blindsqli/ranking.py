"""Heuristic ranking of candidate locations.

There may be thousands of columns. Every blind confirmation costs a run of
oracle questions, so before spending them we *rank* columns by how likely they
are to hold a given keyword, and confirm the promising ones first. Ranking is
only a prioritisation: a high score is never a match. Every candidate must still
be confirmed through the boolean oracle (see :mod:`blindsqli.search`).

Signals combined per (keyword, column):
  * column-name similarity to the keyword and to the *kind* of value it looks
    like (an ``@`` makes ``email``-ish columns likely; digits+``-`` make
    ``invoice``/``code``-ish columns likely);
  * table-name and database/schema-name similarity;
  * data-type suitability (a text column beats an integer column for a string
    keyword);
  * learned patterns -- column/table names that have *already* produced
    confirmed matches are boosted, which is how recurring naming conventions
    (``users.username`` and ``accounts.username``) reinforce each other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Dict, Iterable, List, Optional, Tuple

from .metadata import ColumnRef

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Keyword "shape" -> column-name hints that commonly store that shape.
_SHAPE_HINTS = {
    "email": ["email", "mail", "e_mail", "contact"],
    "phone": ["phone", "tel", "mobile", "cell", "msisdn"],
    "money": ["price", "amount", "total", "cost", "balance", "invoice", "billing"],
    "code": ["code", "number", "no", "ref", "reference", "sku", "id", "invoice"],
    "name": ["name", "user", "login", "account", "customer", "contact", "title"],
    "secret": ["pass", "password", "pwd", "secret", "token", "key", "hash"],
}

# Textual SQL data types -- string keywords live in these, not in numerics.
_TEXT_TYPES = ("char", "text", "clob", "string", "enum", "json", "xml", "uniqueidentifier")
_NUMERIC_TYPES = ("int", "decimal", "numeric", "float", "double", "real", "money", "bit")


def tokenize(name: str) -> List[str]:
    """Split an identifier into lowercase word tokens (snake/camel/kebab)."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name or "")
    return _TOKEN_RE.findall(spaced.lower())


def _similarity(a: str, b: str) -> float:
    a, b = (a or "").lower(), (b or "").lower()
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    ratio = SequenceMatcher(None, a, b).ratio()
    if a in b or b in a:
        ratio = max(ratio, 0.75)
    return ratio


def _token_overlap(name: str, hints: Iterable[str]) -> float:
    toks = set(tokenize(name))
    if not toks:
        return 0.0
    best = 0.0
    for hint in hints:
        for htok in tokenize(hint):
            for tok in toks:
                if tok == htok or htok in tok or tok in htok:
                    best = max(best, 0.6 if tok == htok else 0.4)
    return best


def keyword_shapes(keyword: str) -> List[str]:
    """Classify a keyword into zero or more value *shapes* (see _SHAPE_HINTS)."""
    kw = keyword.strip()
    shapes: List[str] = []
    low = kw.lower()
    if "@" in kw and "." in kw:
        shapes.append("email")
    if re.fullmatch(r"[+()\-\s\d]{7,}", kw):
        shapes.append("phone")
    if re.search(r"\d", kw) and re.search(r"[-_/#]", kw):
        shapes.append("code")
    if re.fullmatch(r"[\$€£]?\d[\d,]*\.?\d*", kw):
        shapes.append("money")
    if any(w in low for w in ("pass", "secret", "token", "key")):
        shapes.append("secret")
    if re.fullmatch(r"[A-Za-z][\w.\- ]*", kw):
        shapes.append("name")
    return shapes or ["name"]


@dataclass
class PatternMemory:
    """Names that have produced confirmed matches, used to boost look-alikes.

    Every confirmed location feeds its column/table/schema tokens here; later
    candidates sharing those tokens are ranked higher. This is how the tool
    "detects repeated patterns" (recurring prefixes/suffixes, multilingual
    variants sharing a stem) without any hard-coded dictionary.
    """

    column_tokens: Dict[str, int] = field(default_factory=dict)
    table_tokens: Dict[str, int] = field(default_factory=dict)
    exact_columns: Dict[str, int] = field(default_factory=dict)

    def record(self, ref: ColumnRef) -> None:
        for tok in tokenize(ref.column):
            self.column_tokens[tok] = self.column_tokens.get(tok, 0) + 1
        for tok in tokenize(ref.table):
            self.table_tokens[tok] = self.table_tokens.get(tok, 0) + 1
        cn = ref.column.lower()
        self.exact_columns[cn] = self.exact_columns.get(cn, 0) + 1

    def boost(self, ref: ColumnRef) -> float:
        score = 0.0
        if ref.column.lower() in self.exact_columns:
            score += 0.5
        for tok in tokenize(ref.column):
            if tok in self.column_tokens:
                score += 0.15
        for tok in tokenize(ref.table):
            if tok in self.table_tokens:
                score += 0.05
        return min(score, 0.8)


@dataclass
class ScoredColumn:
    column: ColumnRef
    score: float
    reasons: List[str] = field(default_factory=list)


def _type_factor(keyword: str, data_type: Optional[str]) -> Tuple[float, str]:
    if not data_type:
        return 0.0, ""
    dt = data_type.lower()
    if any(t in dt for t in _TEXT_TYPES):
        return 0.1, "text column"
    if any(t in dt for t in _NUMERIC_TYPES):
        # a purely non-numeric keyword is unlikely in a numeric column
        if re.search(r"[^\d.,\-]", keyword):
            return -0.3, "numeric column vs text keyword"
        return 0.05, "numeric column matches numeric keyword"
    return 0.0, ""


def score_column(
    keyword: str,
    column: ColumnRef,
    patterns: Optional[PatternMemory] = None,
) -> ScoredColumn:
    """Score one column for one keyword. Higher is more promising (0..~1.5)."""
    reasons: List[str] = []
    score = 0.0

    name_sim = _similarity(keyword, column.column)
    if name_sim > 0.3:
        score += 0.4 * name_sim
        reasons.append(f"name~{name_sim:.2f}")

    shapes = keyword_shapes(keyword)
    hints = [h for s in shapes for h in _SHAPE_HINTS.get(s, [])]
    shape_hit = _token_overlap(column.column, hints)
    if shape_hit:
        score += shape_hit
        reasons.append(f"{'/'.join(shapes)}-like col")

    tbl_hit = _token_overlap(column.table, hints)
    if tbl_hit:
        score += 0.4 * tbl_hit
        reasons.append("table hint")

    tf, treason = _type_factor(keyword, column.data_type)
    if tf:
        score += tf
        if treason:
            reasons.append(treason)

    if patterns is not None:
        boost = patterns.boost(column)
        if boost:
            score += boost
            reasons.append(f"pattern+{boost:.2f}")

    # a tiny positive floor so unranked columns still get searched eventually
    score = max(score, 0.01)
    return ScoredColumn(column=column, score=round(score, 4), reasons=reasons)


def rank_columns(
    keyword: str,
    columns: Iterable[ColumnRef],
    patterns: Optional[PatternMemory] = None,
) -> List[ScoredColumn]:
    """Rank *columns* for *keyword*, most promising first (stable by location)."""
    scored = [score_column(keyword, c, patterns) for c in columns]
    scored.sort(key=lambda s: (-s.score, s.column.location))
    return scored
