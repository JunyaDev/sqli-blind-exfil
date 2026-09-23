"""Persistent search-result model.

For every candidate the keyword search evaluates, a :class:`KeywordMatch`
records where it looked and what the boolean oracle concluded. Results are kept
*per keyword* and never merged across keywords -- each keyword is an independent
investigation. A confirmed match carries enough location detail to hand straight
to targeted extraction.

Match status is a small ladder that mirrors the requested distinction between
"column appears relevant", "possible keyword match" and "confirmed match":

    CANDIDATE  -> ranked as relevant, not yet tested
    PROBABLE   -> heuristics strongly agree, or a partial signal
    CONFIRMED  -> the boolean oracle proved the value is present
    ABSENT     -> the oracle proved it is not here
"""

from __future__ import annotations

import enum
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .metadata import ColumnRef


class MatchStatus(enum.Enum):
    CANDIDATE = "CANDIDATE"
    PROBABLE = "PROBABLE"
    CONFIRMED = "CONFIRMED"
    ABSENT = "ABSENT"

    @property
    def is_positive(self) -> bool:
        return self in (MatchStatus.CONFIRMED, MatchStatus.PROBABLE)


@dataclass
class KeywordMatch:
    keyword: str
    database: Optional[str]
    schema: str
    table: str
    column: str
    status: MatchStatus = MatchStatus.CANDIDATE
    confidence: float = 0.0            # heuristic score at evaluation time
    match_type: str = "substring"      # substring | exact
    match_count: Optional[int] = None  # rows in this column that matched
    row_identifier: Optional[str] = None   # e.g. "id=42", when located
    where_clause: Optional[str] = None     # ready-to-use filter for extraction
    evidence: str = ""                 # short note on how it was decided
    discovered_at: float = field(default_factory=time.time)

    @property
    def location(self) -> str:
        db = f"{self.database}." if self.database else ""
        return f"{db}{self.schema}.{self.table}.{self.column}"

    @classmethod
    def from_ref(cls, keyword: str, ref: ColumnRef, **kw) -> "KeywordMatch":
        return cls(
            keyword=keyword, database=ref.database, schema=ref.schema,
            table=ref.table, column=ref.column, **kw,
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["location"] = self.location
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "KeywordMatch":
        data = dict(data)
        data.pop("location", None)
        status = data.pop("status", "CANDIDATE")
        obj = cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        obj.status = MatchStatus(status) if not isinstance(status, MatchStatus) else status
        return obj


class SearchResults:
    """All matches for a search, grouped by keyword and de-duplicated by
    (keyword, location, match_type). A later evaluation of the same cell
    upgrades the stored status rather than adding a duplicate row."""

    _RANK = {  # which status "wins" when the same cell is seen twice
        MatchStatus.ABSENT: 0,
        MatchStatus.CANDIDATE: 1,
        MatchStatus.PROBABLE: 2,
        MatchStatus.CONFIRMED: 3,
    }

    def __init__(self) -> None:
        self._by_key: Dict[tuple, KeywordMatch] = {}

    @staticmethod
    def _key(m: KeywordMatch) -> tuple:
        return (m.keyword, m.location, m.match_type)

    def record(self, match: KeywordMatch) -> KeywordMatch:
        key = self._key(match)
        prev = self._by_key.get(key)
        if prev is None or self._RANK[match.status] >= self._RANK[prev.status]:
            self._by_key[key] = match
            return match
        return prev

    def all(self) -> List[KeywordMatch]:
        return list(self._by_key.values())

    def for_keyword(self, keyword: str) -> List[KeywordMatch]:
        found = [m for m in self._by_key.values() if m.keyword == keyword]
        found.sort(key=lambda m: (-self._RANK[m.status], -m.confidence, m.location))
        return found

    def confirmed(self) -> List[KeywordMatch]:
        return [m for m in self._by_key.values() if m.status == MatchStatus.CONFIRMED]

    def keywords(self) -> List[str]:
        return sorted({m.keyword for m in self._by_key.values()})

    def summary(self) -> Dict[str, Dict[str, int]]:
        """Per-keyword counts by status, for a compact report."""
        out: Dict[str, Dict[str, int]] = {}
        for m in self._by_key.values():
            bucket = out.setdefault(m.keyword, {})
            bucket[m.status.value] = bucket.get(m.status.value, 0) + 1
        return out

    # ---- persistence ------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "generated_at": time.time(),
            "matches": [m.to_dict() for m in self._by_key.values()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SearchResults":
        obj = cls()
        for row in (data or {}).get("matches", []):
            obj.record(KeywordMatch.from_dict(row))
        return obj

    def save(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "SearchResults":
        if not path or not os.path.exists(path):
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return cls.from_dict(json.load(fh))
        except (ValueError, OSError):
            return cls()
