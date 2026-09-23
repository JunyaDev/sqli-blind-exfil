"""Metadata discovery, separated from data extraction.

Discovery enumerates schema (database, table and column *names*) through the
same boolean oracle the extractor uses, and records everything in a shared
:class:`~blindsqli.metadata.MetadataIndex`. It is deliberately distinct from
extraction: you discover and narrow the search space first, then extract only
what survives filtering. Results are cached in the index, so a second keyword
search reuses the first one's enumeration instead of repeating it.

All queries are read-only (``INFORMATION_SCHEMA`` / ``sys.databases`` and
``COUNT``/``OFFSET`` selects). Nothing here creates, alters or writes anything.
"""

from __future__ import annotations

from typing import List, Optional

from .dialect import SqlDialect
from .logging_util import Logger
from .metadata import ColumnMeta, MetadataIndex, TableMeta
from . import targets as targets_mod


class MetadataDiscoverer:
    """Fills a :class:`MetadataIndex` by blind enumeration, with caching."""

    def __init__(self, engine, dialect: SqlDialect, index: MetadataIndex,
                 logger: Optional[Logger] = None, max_count: int = 4096) -> None:
        self.engine = engine
        self.dialect = dialect
        self.index = index
        self.logger = logger or Logger(0)
        self.max_count = max_count

    # -- helpers ------------------------------------------------------------
    def _enumerate(self, count_expr: str, row_factory) -> List[str]:
        """Discover a count then extract each name; stop early on cancel."""
        total = self.engine.discover_count(count_expr, max_count=self.max_count)
        if total is None:
            return []
        names: List[str] = []
        for i in range(total):
            if self.engine.cancelled():
                break
            result = self.engine.extract(row_factory(i))
            if result.value and result.complete:
                names.append(result.value)
        return names

    # -- databases ----------------------------------------------------------
    def discover_databases(self, force: bool = False) -> List[str]:
        if self.index.databases_enumerated and not force and self.index.databases:
            return self.index.database_names()
        self.logger.info("discovering databases")
        names = self._enumerate(
            "(SELECT COUNT(*) FROM sys.databases)",
            lambda i: targets_mod.nth_database_name(self.dialect, offset=i),
        )
        for name in names:
            self.index.add_database(name)
        if force and not self.engine.cancelled():
            # evict databases that no longer exist (add_* is otherwise add-only)
            self.index.prune_databases(names)
        if not self.engine.cancelled():
            self.index.databases_enumerated = True
        return self.index.database_names()

    # -- tables -------------------------------------------------------------
    def discover_tables(self, database: Optional[str], where: Optional[str] = None,
                        force: bool = False) -> List[TableMeta]:
        db = self.index.add_database(database or "")
        if db.tables_enumerated and not force and where is None:
            return list(db.tables.values())
        self.logger.info(f"discovering tables in {database or 'current DB'}"
                         + (f" where {where}" if where else ""))
        names = self._enumerate(
            targets_mod.tables_count_expr(database, where=where),
            lambda i: targets_mod.first_table_name(
                self.dialect, offset=i, database=database, where=where),
        )
        tables = [self.index.add_table(database, n, schema="dbo") for n in names]
        if force and where is None and not self.engine.cancelled():
            db.prune_tables(names)
        if where is None and not self.engine.cancelled():
            db.tables_enumerated = True
        return tables

    # -- columns ------------------------------------------------------------
    def discover_columns(self, database: Optional[str], table: str, schema: str = "dbo",
                        where: Optional[str] = None, force: bool = False) -> List[ColumnMeta]:
        tbl = self.index.add_table(database, table, schema=schema)
        if tbl.columns_enumerated and not force and where is None:
            return list(tbl.columns.values())
        self.logger.info(f"discovering columns of {database or ''}{'.' if database else ''}"
                         f"{table}")
        names = self._enumerate(
            targets_mod.columns_count_expr(table, database=database, where=where),
            lambda i: targets_mod.first_column_name(
                self.dialect, table, offset=i, database=database, where=where),
        )
        cols = [tbl.add_column(n) for n in names]
        if force and where is None and not self.engine.cancelled():
            tbl.prune_columns(names)
        if where is None and not self.engine.cancelled():
            tbl.columns_enumerated = True
        return cols

    def discover_all_columns(self, databases: Optional[List[str]] = None,
                            table_where: Optional[str] = None) -> MetadataIndex:
        """Full read-only walk: databases -> tables -> columns, cached as it goes.

        This is the "build the metadata index once" step; the keyword engine then
        searches the index in memory instead of re-enumerating per keyword.
        """
        dbs = databases if databases is not None else self.discover_databases()
        for database in dbs:
            if self.engine.cancelled():
                break
            db_key = database or ""
            for tbl in self.discover_tables(db_key, where=table_where):
                if self.engine.cancelled():
                    break
                self.discover_columns(db_key, tbl.name, schema=tbl.schema)
        return self.index
