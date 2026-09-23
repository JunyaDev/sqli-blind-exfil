"""Cross-scope keyword search engine.

Turns "I know several values but not where any of them live" into "here are the
confirmed locations of each value" -- without dumping everything. It:

  1. builds or reuses a shared :class:`~blindsqli.metadata.MetadataIndex`
     (discovery, done once and cached);
  2. for each keyword *independently*, ranks candidate columns by heuristic
     likelihood (:mod:`blindsqli.ranking`) so expensive work targets the
     promising ones first;
  3. confirms the top candidates through the boolean oracle with a single
     ``COUNT(* WHERE column matches keyword) > 0`` question each -- ranking only
     prioritises; the oracle is the sole source of truth;
  4. records every result per keyword (:mod:`blindsqli.results`) and feeds
     confirmations back into pattern memory so recurring naming conventions
     raise the priority of look-alike columns.

Independent confirmations run concurrently within a worker limit. Every query is
read-only; keywords are never combined into one query.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .dialect import SqlDialect
from .keywords import Keyword
from .logging_util import Logger
from .metadata import ColumnRef, MetadataIndex
from .ranking import PatternMemory, ScoredColumn, rank_columns
from .result_types import OracleResult
from .results import KeywordMatch, MatchStatus, SearchResults
from . import targets as targets_mod


@dataclass
class ScopeEstimate:
    """A pre-flight picture of how expensive a search could become."""

    keywords: int
    databases: int
    tables: int
    columns: int
    candidates_per_keyword: int
    confirm_requests: int
    level: str                    # LOW | MODERATE | HIGH | VERY HIGH
    suggestions: List[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            "Estimated search scope:",
            f"  Keywords:              {self.keywords:>8,}",
            f"  Databases:             {self.databases:>8,}",
            f"  Tables:                {self.tables:>8,}",
            f"  Columns (known):       {self.columns:>8,}",
            f"  Candidates/keyword:    {self.candidates_per_keyword:>8,}",
            f"  Confirmation requests: ~{self.confirm_requests:>7,}",
            f"  Cost level:            {self.level}",
        ]
        if self.suggestions:
            lines.append("  Suggested actions:")
            lines += [f"    - {s}" for s in self.suggestions]
        return "\n".join(lines)


def estimate_scope(index: MetadataIndex, keywords: int,
                   candidates_per_keyword: int,
                   databases: Optional[List[str]] = None) -> ScopeEstimate:
    """Estimate confirmation cost from the *known* schema and a candidate cap."""
    c = index.counts(databases)
    per_kw = min(candidates_per_keyword, c["columns"]) if c["columns"] else candidates_per_keyword
    confirm = keywords * per_kw
    if confirm <= 200:
        level = "LOW"
    elif confirm <= 2000:
        level = "MODERATE"
    elif confirm <= 20000:
        level = "HIGH"
    else:
        level = "VERY HIGH"
    suggestions: List[str] = []
    if level in ("HIGH", "VERY HIGH"):
        suggestions = [
            "Search metadata first (discover, then filter tables/columns)",
            "Lower --max-candidates so only the most likely columns are tested",
            "Restrict --databases to the ones in scope",
            "Filter tables with --table-like before searching",
        ]
    if not index.databases:
        suggestions.append("No metadata cached yet: run discovery first")
    return ScopeEstimate(
        keywords=keywords, databases=c["databases"], tables=c["tables"],
        columns=c["columns"], candidates_per_keyword=per_kw,
        confirm_requests=confirm, level=level, suggestions=suggestions,
    )


class KeywordSearchEngine:
    """Ranks, confirms and records keyword locations across the cached scope."""

    def __init__(self, engine, dialect: SqlDialect, index: MetadataIndex,
                 results: Optional[SearchResults] = None,
                 patterns: Optional[PatternMemory] = None,
                 logger: Optional[Logger] = None,
                 workers: int = 1) -> None:
        self.engine = engine
        self.oracle = engine.oracle
        self.dialect = dialect
        self.index = index
        self.results = results or SearchResults()
        self.patterns = patterns or PatternMemory()
        self.logger = logger or Logger(0)
        self.workers = max(1, workers)
        self._lock = threading.Lock()
        # seed pattern memory from any previously confirmed locations
        for m in self.results.confirmed():
            self.patterns.record(ColumnRef(m.database, m.schema, m.table, m.column))

    # -- confirmation -------------------------------------------------------
    def confirm(self, keyword: Keyword, ref: ColumnRef) -> bool:
        """Ask the oracle whether *keyword* occurs in *ref* (one boolean question)."""
        count_expr = targets_mod.column_match_count_expr(
            self.dialect, ref.database, ref.schema, ref.table, ref.column,
            keyword.value, exact=keyword.exact, case_sensitive=keyword.case_sensitive,
        )
        obs = self.oracle.ask(f"{count_expr} > 0")
        return obs.result == OracleResult.TRUE if obs.result.is_definite else None

    def count_matches(self, keyword: Keyword, ref: ColumnRef,
                      max_count: int = 4096) -> Optional[int]:
        """Exact number of rows in *ref* matching *keyword* (extra requests)."""
        count_expr = targets_mod.column_match_count_expr(
            self.dialect, ref.database, ref.schema, ref.table, ref.column,
            keyword.value, exact=keyword.exact, case_sensitive=keyword.case_sensitive,
        )
        return self.engine.discover_count(count_expr, max_count=max_count)

    def where_for(self, keyword: Keyword, column: str) -> str:
        """The WHERE predicate that isolates *keyword* in *column*, for
        handing to targeted row extraction (`enumerate --what rows --where`)."""
        return targets_mod.match_where(
            self.dialect, column, keyword.value,
            exact=keyword.exact, case_sensitive=keyword.case_sensitive,
        )

    # -- per-keyword search -------------------------------------------------
    def candidates_for(self, keyword: Keyword,
                       databases: Optional[List[str]] = None) -> List[ScoredColumn]:
        cols = list(self.index.iter_columns(databases))
        with self._lock:
            patterns = self.patterns
        return rank_columns(keyword.value, cols, patterns)

    def search_keyword(self, keyword: Keyword, databases: Optional[List[str]] = None,
                       max_candidates: int = 50, stop_after: Optional[int] = None,
                       count_rows: bool = False) -> List[KeywordMatch]:
        """Confirm the top-ranked candidates for one keyword. Returns its matches.

        *stop_after* stops once that many confirmed locations are found (None =
        test all candidates up to *max_candidates*).
        """
        ranked = self.candidates_for(keyword, databases)[:max_candidates]
        found = 0
        for sc in ranked:
            if self.engine.cancelled():
                break
            ref = sc.column
            verdict = self.confirm(keyword, ref)
            if verdict is None:
                status, evidence = MatchStatus.PROBABLE, "oracle undetermined; ranked candidate"
            elif verdict:
                status, evidence = MatchStatus.CONFIRMED, "COUNT(* WHERE match) > 0 is TRUE"
            else:
                status, evidence = MatchStatus.ABSENT, "COUNT(* WHERE match) > 0 is FALSE"
            match = KeywordMatch.from_ref(
                keyword.value, ref, status=status, confidence=sc.score,
                match_type=keyword.mode, evidence=evidence,
                where_clause=self.where_for(keyword, ref.column),
            )
            if status == MatchStatus.CONFIRMED:
                with self._lock:
                    self.patterns.record(ref)
                if count_rows:
                    match.match_count = self.count_matches(keyword, ref)
                found += 1
                self.logger.info(f"[{keyword.value}] CONFIRMED at {ref.location}")
            with self._lock:
                self.results.record(match)
            if stop_after is not None and found >= stop_after:
                break
        return self.results.for_keyword(keyword.value)

    # -- multi-keyword orchestration ---------------------------------------
    def search(self, keywords: List[Keyword], databases: Optional[List[str]] = None,
               max_candidates: int = 50, stop_after: Optional[int] = None,
               count_rows: bool = False,
               on_keyword_done: Optional[Callable[[str], None]] = None) -> SearchResults:
        """Search every keyword independently, concurrently within the worker limit.

        Each keyword keeps its own results; the shared metadata index and pattern
        memory mean the keywords cooperate on *cost* without their results ever
        being merged.
        """
        def run_one(kw: Keyword):
            self.search_keyword(kw, databases, max_candidates=max_candidates,
                                stop_after=stop_after, count_rows=count_rows)
            if on_keyword_done:
                on_keyword_done(kw.value)

        if self.workers == 1 or len(keywords) <= 1:
            for kw in keywords:
                if self.engine.cancelled():
                    break
                run_one(kw)
        else:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futs = [pool.submit(run_one, kw) for kw in keywords]
                for _ in as_completed(futs):
                    pass
        return self.results
