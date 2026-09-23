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


# ---------------------------------------------------------------------------
# Schema-aware oracle for the cross-scope value search.
#
# Models a small multi-database lab (databases -> tables -> columns -> rows) and
# answers the exact condition shapes the metadata discoverer and keyword search
# engine emit: COUNT(*) comparisons over sys.databases / INFORMATION_SCHEMA,
# name extraction via SUBSTRING/LEN, and value-match COUNT(* WHERE col matches).
# It lets the search stack be tested end-to-end without a network or a DBMS.
# ---------------------------------------------------------------------------

import re as _re

_NUM_CMP = _re.compile(r"(<=|>=|<|>|=)\s*(\d+)\s*$")
_INFO_DB = _re.compile(r"\[([^\]]+)\]\.INFORMATION_SCHEMA", _re.IGNORECASE)
_TABLE_NAME_EQ = _re.compile(r"TABLE_NAME\s*=\s*'((?:[^']|'')*)'", _re.IGNORECASE)
_OFFSET = _re.compile(r"OFFSET\s+(\d+)\s+ROWS", _re.IGNORECASE)
_TBL_WHERE_LIKE = _re.compile(
    r"WHERE\s+TABLE_NAME\s+LIKE\s*'((?:[^']|'')*)'", _re.IGNORECASE)
_BRACKET = _re.compile(r"\[([^\]]+)\]")
_MATCH_LIKE = _re.compile(r"LIKE\s*'%((?:[^']|'')*)%'\s*ESCAPE", _re.IGNORECASE)
_MATCH_EQ = _re.compile(r"\)\s*=\s*'((?:[^']|'')*)'", _re.IGNORECASE)


def _sql_unescape_like(s):
    s = s.replace("''", "'")
    return _re.sub(r"\\(.)", r"\1", s)


class SchemaOracle:
    """Answers boolean conditions against an in-memory multi-database schema.

    *schema* maps database name -> {table name -> {column name -> [row values]}}.
    *current_db* is what an unqualified INFORMATION_SCHEMA / table source means.
    """

    def __init__(self, schema, current_db=None):
        self.schema = schema
        self.current_db = current_db or next(iter(schema), "")
        self.requests_completed = 0
        self.requests_failed = 0
        self.asked = []
        self._lock = threading.Lock()

    def ensure_classifier(self):
        return None

    def calibrate(self):
        return None

    # -- rowset helpers -----------------------------------------------------
    def _db_names(self):
        return sorted(self.schema)

    def _table_names(self, db, like=None):
        names = sorted(self.schema.get(db, {}))
        if like is not None:
            rx = _like_to_regex(like)
            names = [n for n in names if rx.match(n)]
        return names

    def _column_names(self, db, table):
        return list(self.schema.get(db, {}).get(table, {}).keys())

    def _match_count(self, db, table, condition):
        cols = self.schema.get(db, {}).get(table, {})
        col_names = _BRACKET.findall(condition.split("WHERE", 1)[1]) if "WHERE" in condition.upper() else []
        col = col_names[0] if col_names else None
        rows = cols.get(col, [])
        case_sensitive = "BIN" in condition.upper()
        m = _MATCH_LIKE.search(condition)
        if m:
            needle = _sql_unescape_like(m.group(1))
            if case_sensitive:
                return sum(1 for v in rows if needle in v)
            return sum(1 for v in rows if needle.lower() in v.lower())
        m = _MATCH_EQ.search(condition)
        if m:
            needle = m.group(1).replace("''", "'")
            if case_sensitive:
                return sum(1 for v in rows if v == needle)
            return sum(1 for v in rows if v.lower() == needle.lower())
        return 0

    def _resolve_name(self, condition):
        up = condition.upper()
        off = _OFFSET.search(condition)
        idx = int(off.group(1)) if off else 0
        if "SYS.DATABASES" in up:
            names = self._db_names()
        elif "INFORMATION_SCHEMA.TABLES" in up:
            dbm = _INFO_DB.search(condition)
            db = dbm.group(1) if dbm else self.current_db
            like = None
            lm = _TBL_WHERE_LIKE.search(condition)
            if lm:
                like = lm.group(1)
            names = self._table_names(db, like=like)
        elif "INFORMATION_SCHEMA.COLUMNS" in up:
            dbm = _INFO_DB.search(condition)
            db = dbm.group(1) if dbm else self.current_db
            tm = _TABLE_NAME_EQ.search(condition)
            table = tm.group(1).replace("''", "'") if tm else ""
            names = self._column_names(db, table)
        else:
            names = []
        return names[idx] if 0 <= idx < len(names) else ""

    def _count(self, condition):
        up = condition.upper()
        if "SYS.DATABASES" in up:
            return len(self._db_names())
        if "INFORMATION_SCHEMA.TABLES" in up:
            dbm = _INFO_DB.search(condition)
            db = dbm.group(1) if dbm else self.current_db
            lm = _TBL_WHERE_LIKE.search(condition)
            return len(self._table_names(db, like=lm.group(1) if lm else None))
        if "INFORMATION_SCHEMA.COLUMNS" in up:
            dbm = _INFO_DB.search(condition)
            db = dbm.group(1) if dbm else self.current_db
            tm = _TABLE_NAME_EQ.search(condition)
            table = tm.group(1).replace("''", "'") if tm else ""
            return len(self._column_names(db, table))
        # value-match: FROM [db].[schema].[table] WHERE <col> matches
        brs = _BRACKET.findall(condition.split("WHERE", 1)[0])
        if len(brs) >= 3:
            db, _schema, table = brs[0], brs[1], brs[2]
        elif len(brs) == 2:
            db, table = self.current_db, brs[1]
        else:
            return 0
        return self._match_count(db, table, condition)

    # -- oracle interface ---------------------------------------------------
    def ask(self, condition):
        with self._lock:
            self.requests_completed += 1
            self.asked.append(condition)
        cmp = _NUM_CMP.search(condition)
        if "COUNT(*)" in condition.upper() and cmp:
            op, n = cmp.group(1), int(cmp.group(2))
            actual = self._count(condition)
            truth = {"<=": actual <= n, ">=": actual >= n, "<": actual < n,
                     ">": actual > n, "=": actual == n}[op]
            return OracleObservation(condition, OracleResult.TRUE if truth else OracleResult.FALSE, 1)
        name = self._resolve_name(condition)
        val = evaluate_condition(condition, name)
        return OracleObservation(condition, OracleResult.TRUE if val else OracleResult.FALSE, 1)

    def test(self, condition):
        return self.ask(condition).result
