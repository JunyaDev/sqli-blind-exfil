"""Tests for the heuristic ranking layer."""

from __future__ import annotations

from blindsqli.metadata import ColumnRef
from blindsqli.ranking import (
    keyword_shapes, rank_columns, score_column, tokenize,
)


def _col(table, column, dtype=None, db="db"):
    return ColumnRef(db, "dbo", table, column, data_type=dtype)


def test_tokenize_splits_conventions():
    assert tokenize("user_email") == ["user", "email"]
    assert tokenize("userEmail") == ["user", "email"]
    assert tokenize("invoice-number") == ["invoice", "number"]


def test_email_keyword_prefers_email_columns():
    cols = [
        _col("customers", "email"),
        _col("customers", "user_email"),
        _col("customers", "created_at"),
        _col("logs", "message"),
    ]
    ranked = rank_columns("alice@example.com", cols)
    top_two = {r.column.column for r in ranked[:2]}
    assert top_two == {"email", "user_email"}


def test_invoice_keyword_prefers_invoice_columns():
    cols = [
        _col("orders", "invoice_number"),
        _col("orders", "created_at"),
        _col("billing", "amount"),
    ]
    ranked = rank_columns("invoice-82731", cols)
    assert ranked[0].column.column == "invoice_number"


def test_numeric_column_penalized_for_text_keyword():
    text_col = score_column("alice@example.com", _col("t", "note", "varchar"))
    num_col = score_column("alice@example.com", _col("t", "note2", "int"))
    assert text_col.score > num_col.score


def test_keyword_shapes():
    assert "email" in keyword_shapes("bob@host.com")
    assert "code" in keyword_shapes("invoice-82731")
    assert "secret" in keyword_shapes("password")


def test_ranking_is_deterministic():
    cols = [_col("t", "b"), _col("t", "a"), _col("t", "c")]
    r1 = [c.column.location for c in rank_columns("x", cols)]
    r2 = [c.column.location for c in rank_columns("x", cols)]
    assert r1 == r2
