"""End-to-end tests for discovery + cross-scope keyword search.

Drives the real MetadataDiscoverer, KeywordSearchEngine, ranking and result
store against an in-memory multi-database schema (SchemaOracle), with no network
or DBMS. Verifies that each keyword is located independently and that ranking
plus caching keep the confirmation cost bounded.
"""

from __future__ import annotations

import pytest

from blindsqli.config import Config, PRINTABLE_CHARSET
from blindsqli.dialect import get_dialect
from blindsqli.discovery import MetadataDiscoverer
from blindsqli.engine import ExfiltrationEngine
from blindsqli.keywords import Keyword, parse_keywords
from blindsqli.metadata import MetadataIndex
from blindsqli.ranking import PatternMemory
from blindsqli.results import MatchStatus
from blindsqli.search import KeywordSearchEngine, estimate_scope

from tests.fakes import SchemaOracle


SCHEMA = {
    "appdb": {
        "accounts": {"username": ["admin", "bob"], "password": ["h1", "h2"]},
        "projects": {"project_code": ["project-x"], "title": ["Apollo"]},
    },
    "billing": {
        "customers": {"email": ["alice@example.com"], "full_name": ["Alice"]},
        "invoices": {"invoice_number": ["invoice-82731"], "amount": ["100"]},
    },
}


def _engine(oracle):
    cfg = Config()
    cfg.charset = PRINTABLE_CHARSET  # names + any punctuation
    cfg.workers = 4
    cfg.verbosity = 0
    return ExfiltrationEngine(cfg, oracle)


def _discover_all():
    oracle = SchemaOracle(SCHEMA, current_db="appdb")
    engine = _engine(oracle)
    index = MetadataIndex()
    disc = MetadataDiscoverer(engine, get_dialect("mssql"), index)
    disc.discover_all_columns()
    return oracle, engine, index


def test_discovery_populates_full_index():
    _oracle, _engine_, index = _discover_all()
    assert set(index.database_names()) == {"appdb", "billing"}
    counts = index.counts()
    assert counts["databases"] == 2
    assert counts["tables"] == 4
    assert counts["columns"] == 8
    locations = {c.location for c in index.iter_columns()}
    assert "billing.dbo.customers.email" in locations
    assert "appdb.dbo.accounts.username" in locations


def test_search_locates_each_keyword_independently():
    oracle, engine, index = _discover_all()
    se = KeywordSearchEngine(engine, get_dialect("mssql"), index, workers=1)
    keywords = [
        Keyword("admin"),
        Keyword("alice@example.com"),
        Keyword("invoice"),
        Keyword("project-x"),
    ]
    se.search(keywords, max_candidates=50)

    def confirmed_locs(kw):
        return {m.location for m in se.results.for_keyword(kw)
                if m.status == MatchStatus.CONFIRMED}

    assert confirmed_locs("admin") == {"appdb.dbo.accounts.username"}
    assert confirmed_locs("alice@example.com") == {"billing.dbo.customers.email"}
    assert confirmed_locs("invoice") == {"billing.dbo.invoices.invoice_number"}
    assert confirmed_locs("project-x") == {"appdb.dbo.projects.project_code"}


def test_results_are_not_merged_across_keywords():
    oracle, engine, index = _discover_all()
    se = KeywordSearchEngine(engine, get_dialect("mssql"), index)
    se.search([Keyword("admin"), Keyword("invoice")], max_candidates=50)
    # each keyword keeps its own result set
    assert se.results.for_keyword("admin")
    assert se.results.for_keyword("invoice")
    for m in se.results.for_keyword("admin"):
        assert m.keyword == "admin"


def test_where_clause_is_ready_for_extraction():
    oracle, engine, index = _discover_all()
    se = KeywordSearchEngine(engine, get_dialect("mssql"), index)
    se.search([Keyword("admin")], max_candidates=50)
    conf = [m for m in se.results.for_keyword("admin")
            if m.status == MatchStatus.CONFIRMED][0]
    assert "username" in conf.where_clause
    assert "admin" in conf.where_clause


def test_count_matches_returns_row_count():
    oracle, engine, index = _discover_all()
    se = KeywordSearchEngine(engine, get_dialect("mssql"), index)
    se.search([Keyword("admin")], max_candidates=50, count_rows=True)
    conf = [m for m in se.results.for_keyword("admin")
            if m.status == MatchStatus.CONFIRMED][0]
    assert conf.match_count == 1


def test_ranking_bounds_confirmation_cost():
    # With a tiny candidate cap the search still spends only a few requests.
    oracle, engine, index = _discover_all()
    disc_requests = oracle.requests_completed
    se = KeywordSearchEngine(engine, get_dialect("mssql"), index)
    se.search([Keyword("admin")], max_candidates=3)
    spent = oracle.requests_completed - disc_requests
    assert spent <= 3  # never more confirmations than the cap


def test_concurrent_search_matches_serial():
    oracle, engine, index = _discover_all()
    se = KeywordSearchEngine(engine, get_dialect("mssql"), index, workers=4)
    se.search([Keyword("admin"), Keyword("alice@example.com"),
               Keyword("invoice"), Keyword("project-x")], max_candidates=50)
    locs = {m.location for m in se.results.confirmed()}
    assert locs == {
        "appdb.dbo.accounts.username",
        "billing.dbo.customers.email",
        "billing.dbo.invoices.invoice_number",
        "appdb.dbo.projects.project_code",
    }


def test_estimate_scope_flags_expense():
    index = MetadataIndex()
    # simulate a large discovered scope
    for d in range(8):
        for t in range(50):
            for c in range(20):
                index.add_column(f"db{d}", f"t{t}", f"c{c}")
    # A capped search stays affordable: cost is bounded by the candidate cap,
    # not the raw column count. This is the whole point of ranking + a cap.
    capped = estimate_scope(index, keywords=14, candidates_per_keyword=50)
    assert capped.columns == 8 * 50 * 20
    assert capped.confirm_requests == 14 * 50
    assert capped.level == "MODERATE"
    # An exhaustive search (test every column) is flagged as very expensive.
    exhaustive = estimate_scope(index, keywords=14,
                                candidates_per_keyword=index.counts()["columns"])
    assert exhaustive.level == "VERY HIGH"
    assert exhaustive.suggestions
    assert "Keywords" in exhaustive.render()


def test_pattern_memory_boosts_recurring_names():
    idx = MetadataIndex()
    idx.add_column("A", "users", "username")
    idx.add_column("B", "accounts", "username")
    pm = PatternMemory()
    from blindsqli.ranking import score_column
    from blindsqli.metadata import ColumnRef
    ref = ColumnRef("B", "dbo", "accounts", "username")
    before = score_column("someuser", ref).score
    pm.record(ColumnRef("A", "dbo", "users", "username"))
    after = score_column("someuser", ref, pm).score
    assert after > before


def test_case_sensitive_keyword_respects_case():
    oracle = SchemaOracle(
        {"db": {"t": {"c": ["Admin"]}}}, current_db="db")
    engine = _engine(oracle)
    index = MetadataIndex()
    MetadataDiscoverer(engine, get_dialect("mssql"), index).discover_all_columns()
    se = KeywordSearchEngine(engine, get_dialect("mssql"), index)
    # case-sensitive "admin" should NOT match "Admin"
    se.search([Keyword("admin", case_sensitive=True)], max_candidates=10)
    assert not [m for m in se.results.for_keyword("admin")
                if m.status == MatchStatus.CONFIRMED]
    # case-insensitive should match
    se2 = KeywordSearchEngine(engine, get_dialect("mssql"), index)
    se2.search([Keyword("admin", case_sensitive=False)], max_candidates=10)
    assert [m for m in se2.results.for_keyword("admin")
            if m.status == MatchStatus.CONFIRMED]
