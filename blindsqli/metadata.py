"""Shared metadata index.

Blind enumeration is expensive: every database, table and column name costs a
run of oracle questions. The index caches what has already been discovered so
that (a) many keyword searches reuse one enumeration instead of repeating it,
and (b) a session can be saved and resumed. It is a plain, read-only picture of
the schema -- it never creates database objects; the only persistence is a
local JSON file the operator controls.

Shape::

    MetadataIndex
      database -> DatabaseMeta
                    schema.table -> TableMeta
                                      column -> ColumnMeta(data_type?)

Any level may be marked ``enumerated`` so callers can tell "this table has no
known columns yet" apart from "this table is known to have zero columns".
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional


@dataclass
class ColumnMeta:
    name: str
    data_type: Optional[str] = None


@dataclass
class TableMeta:
    schema: str
    name: str
    columns: Dict[str, ColumnMeta] = field(default_factory=dict)
    columns_enumerated: bool = False

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"

    def add_column(self, name: str, data_type: Optional[str] = None) -> ColumnMeta:
        col = self.columns.get(name)
        if col is None:
            col = ColumnMeta(name=name, data_type=data_type)
            self.columns[name] = col
        elif data_type and not col.data_type:
            col.data_type = data_type
        return col

    def prune_columns(self, keep_names: Iterable[str]) -> None:
        """Drop cached columns not in *keep_names* (for forced re-discovery)."""
        keep = set(keep_names)
        for name in [n for n in self.columns if n not in keep]:
            del self.columns[name]


@dataclass
class DatabaseMeta:
    name: str
    tables: Dict[str, TableMeta] = field(default_factory=dict)
    tables_enumerated: bool = False

    def add_table(self, name: str, schema: str = "dbo") -> TableMeta:
        key = f"{schema}.{name}"
        tbl = self.tables.get(key)
        if tbl is None:
            tbl = TableMeta(schema=schema, name=name)
            self.tables[key] = tbl
        return tbl

    def prune_tables(self, keep_names: Iterable[str]) -> None:
        """Drop cached tables whose name is not in *keep_names*."""
        keep = set(keep_names)
        for key in [k for k, t in self.tables.items() if t.name not in keep]:
            del self.tables[key]


@dataclass
class ColumnRef:
    """A fully-qualified column location, the unit the search engine ranks."""

    database: Optional[str]
    schema: str
    table: str
    column: str
    data_type: Optional[str] = None

    @property
    def location(self) -> str:
        db = f"{self.database}." if self.database else ""
        return f"{db}{self.schema}.{self.table}.{self.column}"

    def __str__(self) -> str:
        return self.location


class MetadataIndex:
    """In-memory cache of discovered schema, with JSON load/save."""

    def __init__(self) -> None:
        self.databases: Dict[str, DatabaseMeta] = {}
        self.databases_enumerated = False
        self.updated_at: float = time.time()

    # ---- mutation ---------------------------------------------------------
    def add_database(self, name: str) -> DatabaseMeta:
        db = self.databases.get(name)
        if db is None:
            db = DatabaseMeta(name=name)
            self.databases[name] = db
            self.updated_at = time.time()
        return db

    def add_table(self, database: Optional[str], name: str, schema: str = "dbo") -> TableMeta:
        db = self.add_database(database or "")
        self.updated_at = time.time()
        return db.add_table(name, schema=schema)

    def add_column(
        self,
        database: Optional[str],
        table: str,
        column: str,
        schema: str = "dbo",
        data_type: Optional[str] = None,
    ) -> ColumnMeta:
        tbl = self.add_table(database, table, schema=schema)
        self.updated_at = time.time()
        return tbl.add_column(column, data_type=data_type)

    def prune_databases(self, keep_names: Iterable[str]) -> None:
        """Drop cached databases not in *keep_names* (for forced re-discovery).

        The synthetic current-database placeholder ("") is always retained.
        """
        keep = set(keep_names) | {""}
        for name in [n for n in self.databases if n not in keep]:
            del self.databases[name]

    # ---- queries ----------------------------------------------------------
    def database_names(self) -> List[str]:
        return sorted(self.databases)

    def iter_tables(self, databases: Optional[Iterable[str]] = None) -> Iterator[tuple]:
        """Yield ``(database, TableMeta)`` pairs, optionally restricted."""
        wanted = set(databases) if databases is not None else None
        for db_name in sorted(self.databases):
            if wanted is not None and db_name not in wanted:
                continue
            db = self.databases[db_name]
            for key in sorted(db.tables):
                yield db_name or None, db.tables[key]

    def iter_columns(self, databases: Optional[Iterable[str]] = None) -> Iterator[ColumnRef]:
        """Yield every known column as a :class:`ColumnRef`."""
        for db_name, tbl in self.iter_tables(databases):
            for col_name in sorted(tbl.columns):
                col = tbl.columns[col_name]
                yield ColumnRef(
                    database=db_name, schema=tbl.schema, table=tbl.name,
                    column=col.name, data_type=col.data_type,
                )

    def counts(self, databases: Optional[Iterable[str]] = None) -> Dict[str, int]:
        """How much schema is currently known (for cost estimation/status)."""
        wanted = set(databases) if databases is not None else None
        dbs = [d for d in self.databases if wanted is None or d in wanted]
        tables = columns = 0
        for name in dbs:
            db = self.databases[name]
            tables += len(db.tables)
            for tbl in db.tables.values():
                columns += len(tbl.columns)
        return {"databases": len(dbs), "tables": tables, "columns": columns}

    # ---- persistence ------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "updated_at": self.updated_at,
            "databases_enumerated": self.databases_enumerated,
            "databases": {
                name: {
                    "tables_enumerated": db.tables_enumerated,
                    "tables": {
                        key: {
                            "schema": tbl.schema,
                            "name": tbl.name,
                            "columns_enumerated": tbl.columns_enumerated,
                            "columns": {
                                cn: {"data_type": c.data_type}
                                for cn, c in tbl.columns.items()
                            },
                        }
                        for key, tbl in db.tables.items()
                    },
                }
                for name, db in self.databases.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MetadataIndex":
        idx = cls()
        if not isinstance(data, dict):
            return idx
        idx.databases_enumerated = bool(data.get("databases_enumerated"))
        idx.updated_at = data.get("updated_at", time.time())
        for name, db_data in (data.get("databases") or {}).items():
            db = idx.add_database(name)
            db.tables_enumerated = bool(db_data.get("tables_enumerated"))
            for _key, tbl_data in (db_data.get("tables") or {}).items():
                if not isinstance(tbl_data, dict):
                    continue
                # Older/hand-edited files may omit "name"; recover it from the
                # "schema.name" key rather than raising KeyError.
                name = tbl_data.get("name")
                if name is None:
                    name = _key.split(".", 1)[1] if "." in _key else _key
                tbl = db.add_table(name, schema=tbl_data.get("schema", "dbo"))
                tbl.columns_enumerated = bool(tbl_data.get("columns_enumerated"))
                for cn, col_data in (tbl_data.get("columns") or {}).items():
                    tbl.add_column(cn, data_type=(col_data or {}).get("data_type"))
        return idx

    def save(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "MetadataIndex":
        if not path or not os.path.exists(path):
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return cls.from_dict(json.load(fh))
        except (ValueError, OSError, KeyError, TypeError):
            return cls()
