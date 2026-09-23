"""SQL dialects.

A dialect knows how to build the *boolean condition fragments* that the target
abstraction needs: substring extraction, length, ordering comparisons and LIKE
prefix matching, with correct literal escaping. Conditions are dialect-specific;
targets are not. Add a new database by adding a dialect, not by touching the
engine.
"""

from __future__ import annotations

from typing import Dict, Type


class SqlDialect:
    name = "generic"
    # Optional collation forced on character comparisons. Needed on engines
    # whose default collation is case-insensitive (e.g. SQL Server's
    # *_CI_AS), where 'A' = 'a' would otherwise corrupt both equality tests
    # and the ordinal binary search. None means "use the server default".
    collation = None
    # Collations used by the value-search matcher to force a chosen case
    # behaviour regardless of the target's default. None -> rely on the
    # server default (documented limitation for engines without named
    # collations here).
    cs_collation = None  # case-sensitive
    ci_collation = None  # case-insensitive

    # --- literal escaping ---------------------------------------------------
    def quote_str(self, value: str) -> str:
        """Return a safely single-quoted string literal (doubles embedded ')."""
        return "'" + value.replace("'", "''") + "'"

    def like_literal(self, prefix: str) -> str:
        """Quote *prefix* for a LIKE pattern, escaping wildcard metacharacters.

        Uses an explicit ESCAPE character so %, _ and the escape char itself are
        matched literally.
        """
        escaped = (
            prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        return "'" + escaped.replace("'", "''") + "%' ESCAPE '\\'"

    # --- expression helpers (override per dialect) --------------------------
    def substring(self, expr: str, pos: int, length: int) -> str:
        raise NotImplementedError

    def length(self, expr: str) -> str:
        raise NotImplementedError

    # --- condition builders (shared) ---------------------------------------
    def char_eq(self, expr: str, pos: int, ch: str) -> str:
        return f"{self.substring(expr, pos, 1)} = {self.quote_str(ch)}"

    def char_le(self, expr: str, pos: int, ch: str) -> str:
        return f"{self.substring(expr, pos, 1)} <= {self.quote_str(ch)}"

    def substr_eq(self, expr: str, pos: int, value: str) -> str:
        return f"{self.substring(expr, pos, len(value))} = {self.quote_str(value)}"

    def prefix_like(self, expr: str, prefix: str) -> str:
        return f"{expr} LIKE {self.like_literal(prefix)}"

    # --- value-search matchers ---------------------------------------------
    def _contains_literal(self, needle: str) -> str:
        """Quote *needle* as a substring LIKE pattern ('%needle%')."""
        escaped = (
            needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        return "'%" + escaped.replace("'", "''") + "%' ESCAPE '\\'"

    def _matched(self, expr: str, case_sensitive: bool) -> str:
        """Apply an explicit collation to *expr* for the chosen case behaviour."""
        coll = self.cs_collation if case_sensitive else self.ci_collation
        return f"({expr} COLLATE {coll})" if coll else expr

    def contains(self, expr: str, needle: str, case_sensitive: bool = False) -> str:
        """Condition: *expr* contains *needle* as a substring."""
        return f"{self._matched(expr, case_sensitive)} LIKE {self._contains_literal(needle)}"

    def value_eq(self, expr: str, value: str, case_sensitive: bool = False) -> str:
        """Condition: *expr* equals *value* exactly."""
        return f"{self._matched(expr, case_sensitive)} = {self.quote_str(value)}"

    def is_not_null(self, expr: str) -> str:
        """Condition: *expr* yields a non-NULL value (i.e. the row/value exists).

        A scalar subquery that selects nothing returns NULL, so this is the
        cheapest existence check: one boolean question tells extraction whether
        there is anything to recover before it iterates character by character.
        """
        return f"{expr} IS NOT NULL"

    def length_eq(self, expr: str, n: int) -> str:
        return f"{self.length(expr)} = {n}"

    def length_le(self, expr: str, n: int) -> str:
        return f"{self.length(expr)} <= {n}"

    def length_ge(self, expr: str, n: int) -> str:
        return f"{self.length(expr)} >= {n}"


class MSSQLDialect(SqlDialect):
    name = "mssql"
    # Force a binary (case-sensitive, code-point-ordered) collation so
    # comparisons are deterministic regardless of the database's default.
    collation = "Latin1_General_BIN"
    cs_collation = "Latin1_General_BIN"
    ci_collation = "Latin1_General_CI_AS"

    def substring(self, expr: str, pos: int, length: int) -> str:
        s = f"SUBSTRING({expr},{pos},{length})"
        return f"({s} COLLATE {self.collation})" if self.collation else s

    def length(self, expr: str) -> str:
        return f"LEN({expr})"


class MySQLDialect(SqlDialect):
    name = "mysql"

    def substring(self, expr: str, pos: int, length: int) -> str:
        return f"SUBSTRING({expr},{pos},{length})"

    def length(self, expr: str) -> str:
        return f"CHAR_LENGTH({expr})"


class PostgresDialect(SqlDialect):
    name = "postgres"

    def substring(self, expr: str, pos: int, length: int) -> str:
        return f"SUBSTRING({expr} FROM {pos} FOR {length})"

    def length(self, expr: str) -> str:
        return f"LENGTH({expr})"


_REGISTRY: Dict[str, Type[SqlDialect]] = {
    d.name: d for d in (MSSQLDialect, MySQLDialect, PostgresDialect)
}


def get_dialect(name: str) -> SqlDialect:
    try:
        return _REGISTRY[name.lower()]()
    except KeyError:
        raise ValueError(
            f"unknown dialect {name!r}; known: {sorted(_REGISTRY)}"
        ) from None


def register_dialect(cls: Type[SqlDialect]) -> None:
    _REGISTRY[cls.name.lower()] = cls
