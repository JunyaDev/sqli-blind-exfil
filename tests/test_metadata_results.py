"""Tests for the metadata index and search-result store persistence."""

from __future__ import annotations

from blindsqli.metadata import ColumnRef, MetadataIndex
from blindsqli.results import KeywordMatch, MatchStatus, SearchResults


def test_index_add_and_iter():
    idx = MetadataIndex()
    idx.add_column("db1", "users", "username", data_type="varchar")
    idx.add_column("db1", "users", "email")
    idx.add_column("db2", "orders", "total")
    assert idx.database_names() == ["db1", "db2"]
    cols = {c.location for c in idx.iter_columns()}
    assert cols == {"db1.dbo.users.username", "db1.dbo.users.email", "db2.dbo.orders.total"}
    assert idx.counts() == {"databases": 2, "tables": 2, "columns": 3}


def test_index_restrict_by_database():
    idx = MetadataIndex()
    idx.add_column("db1", "users", "username")
    idx.add_column("db2", "orders", "total")
    cols = {c.location for c in idx.iter_columns(databases=["db1"])}
    assert cols == {"db1.dbo.users.username"}


def test_index_roundtrip(tmp_path):
    idx = MetadataIndex()
    idx.add_column("db1", "users", "username", data_type="varchar")
    idx.databases["db1"].tables_enumerated = True
    p = tmp_path / "meta.json"
    idx.save(str(p))
    loaded = MetadataIndex.load(str(p))
    assert loaded.counts() == idx.counts()
    assert loaded.databases["db1"].tables_enumerated is True
    col = next(loaded.iter_columns())
    assert col.data_type == "varchar"


def test_index_load_missing_returns_empty():
    idx = MetadataIndex.load("/nonexistent/path/meta.json")
    assert idx.counts()["columns"] == 0


def test_results_dedup_upgrades_status():
    res = SearchResults()
    ref = ColumnRef("db", "dbo", "t", "c")
    res.record(KeywordMatch.from_ref("admin", ref, status=MatchStatus.CANDIDATE))
    res.record(KeywordMatch.from_ref("admin", ref, status=MatchStatus.CONFIRMED))
    matches = res.for_keyword("admin")
    assert len(matches) == 1
    assert matches[0].status == MatchStatus.CONFIRMED


def test_results_never_downgrade():
    res = SearchResults()
    ref = ColumnRef("db", "dbo", "t", "c")
    res.record(KeywordMatch.from_ref("admin", ref, status=MatchStatus.CONFIRMED))
    res.record(KeywordMatch.from_ref("admin", ref, status=MatchStatus.ABSENT))
    assert res.for_keyword("admin")[0].status == MatchStatus.CONFIRMED


def test_results_roundtrip(tmp_path):
    res = SearchResults()
    ref = ColumnRef("dbB", "dbo", "customers", "email")
    res.record(KeywordMatch.from_ref(
        "alice@example.com", ref, status=MatchStatus.CONFIRMED, confidence=0.9))
    p = tmp_path / "results.json"
    res.save(str(p))
    loaded = SearchResults.load(str(p))
    m = loaded.for_keyword("alice@example.com")[0]
    assert m.status == MatchStatus.CONFIRMED
    assert m.location == "dbB.dbo.customers.email"
    assert m.confidence == 0.9


def test_results_summary_counts():
    res = SearchResults()
    res.record(KeywordMatch.from_ref("a", ColumnRef("d", "dbo", "t", "c1"),
                                     status=MatchStatus.CONFIRMED))
    res.record(KeywordMatch.from_ref("a", ColumnRef("d", "dbo", "t", "c2"),
                                     status=MatchStatus.ABSENT))
    summary = res.summary()
    assert summary["a"]["CONFIRMED"] == 1
    assert summary["a"]["ABSENT"] == 1
