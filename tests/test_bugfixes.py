"""Regression tests for the September 2026 bug-fix batch.

Each test pins a specific defect found during the in-depth review so it cannot
silently return. Grouped by module; every test names the bug it guards.
"""

from __future__ import annotations

import json

import pytest

from blindsqli import rce
from blindsqli.config import Config, PRINTABLE_CHARSET
from blindsqli.dialect import MSSQLDialect, MySQLDialect, get_dialect
from blindsqli.discovery import MetadataDiscoverer
from blindsqli.engine import ExfiltrationEngine
from blindsqli.keywords import parse_keywords
from blindsqli.metadata import MetadataIndex
from blindsqli.results import KeywordMatch, MatchStatus, SearchResults
from blindsqli.targets import Target
from blindsqli.wizard import Wizard

from tests.fakes import FakeOracle, SchemaOracle
from tests.test_rce import FakeEngine, FakeRceOracle


# --------------------------------------------------------------------------
# engine.py: over-length values / discover_count overflow / set_charset
# --------------------------------------------------------------------------
def _engine(secret, **cfg_kw):
    cfg = Config(charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ", strategy="binary",
                 workers=1, verbosity=0, **cfg_kw)
    return ExfiltrationEngine(cfg, FakeOracle(secret))


def _mssql_target():
    return Target(name="t", expression="(SELECT x)", dialect=MSSQLDialect())


def test_overlength_value_flagged_truncated_not_complete():
    # A value longer than max_length used to report complete=True/truncated=False.
    eng = _engine("ABCDEFGHIJ", max_length=5, discover_length=True)
    r = eng.extract(_mssql_target())
    assert r.value == "ABCDE"
    assert r.truncated is True
    assert r.complete is False
    assert r.exists is True


def test_exact_max_length_value_still_complete():
    eng = _engine("ABCDE", max_length=5, discover_length=True)
    r = eng.extract(_mssql_target())
    assert r.value == "ABCDE"
    assert r.truncated is False
    assert r.complete is True


def test_discover_count_overflow_returns_none():
    # FakeOracle answers every COUNT probe FALSE, i.e. count > cap -> None,
    # not a bogus "exact count == max_count".
    eng = _engine("x")
    assert eng.discover_count("(SELECT COUNT(*) FROM t)", max_count=8) is None


def test_set_charset_changes_extraction_alphabet():
    eng = _engine("ab", max_length=8, discover_length=True)  # uppercase charset
    r1 = eng.extract(_mssql_target())
    assert not r1.complete  # lowercase 'ab' unreachable in an uppercase charset
    eng.set_charset("abcdefgh")
    r2 = eng.extract(_mssql_target())
    assert r2.value == "ab"
    assert r2.complete is True


# --------------------------------------------------------------------------
# dialect.py: MSSQL trailing-space length, MySQL backslash escaping
# --------------------------------------------------------------------------
def test_mssql_length_preserves_trailing_spaces():
    expr = MSSQLDialect().length_le("(SELECT x)", 5)
    assert "LEN(" in expr and "+ 'x'" in expr and "- 1" in expr


def test_mysql_quote_str_escapes_backslash():
    assert MySQLDialect().quote_str("a\\b") == "'a\\\\b'"


def test_mysql_char_eq_backslash_literal_is_wellformed():
    cond = MySQLDialect().char_eq("(SELECT x)", 1, "\\")
    # one literal backslash must be doubled for MySQL's string-literal parser
    assert cond.endswith("= '\\\\'")


def test_mysql_like_doubles_backslash_and_escape_clause():
    lit = MySQLDialect()._contains_literal("a_b")
    assert "ESCAPE '\\\\'" in lit         # escape char survives as one backslash
    assert lit.startswith("'%") and "%'" in lit


# --------------------------------------------------------------------------
# results.py: status ladder + optional-field preservation + robust load
# --------------------------------------------------------------------------
def _m(status, **kw):
    return KeywordMatch(keyword="k", database="d", schema="dbo",
                        table="t", column="c", status=status, **kw)


def test_absent_overrides_candidate():
    r = SearchResults()
    r.record(_m(MatchStatus.CANDIDATE))
    r.record(_m(MatchStatus.ABSENT))
    assert r.for_keyword("k")[0].status is MatchStatus.ABSENT


def test_absent_overrides_probable():
    r = SearchResults()
    r.record(_m(MatchStatus.PROBABLE))
    r.record(_m(MatchStatus.ABSENT))
    assert r.for_keyword("k")[0].status is MatchStatus.ABSENT


def test_confirmed_not_downgraded_by_absent():
    r = SearchResults()
    r.record(_m(MatchStatus.CONFIRMED))
    r.record(_m(MatchStatus.ABSENT))
    assert r.for_keyword("k")[0].status is MatchStatus.CONFIRMED


def test_candidate_does_not_override_confirmed():
    r = SearchResults()
    r.record(_m(MatchStatus.CONFIRMED, match_count=3))
    r.record(_m(MatchStatus.CANDIDATE))
    got = r.for_keyword("k")[0]
    assert got.status is MatchStatus.CONFIRMED and got.match_count == 3


def test_equal_status_rerecord_preserves_match_count():
    r = SearchResults()
    r.record(_m(MatchStatus.CONFIRMED, match_count=5))
    r.record(_m(MatchStatus.CONFIRMED))  # re-record without the count
    assert r.for_keyword("k")[0].match_count == 5


def test_search_results_load_tolerates_missing_field(tmp_path):
    p = tmp_path / "r.json"
    # a row missing the required "keyword" field must not crash load()
    p.write_text(json.dumps(
        {"matches": [{"database": "d", "schema": "s", "table": "t", "column": "c"}]}
    ))
    assert SearchResults.load(str(p)).all() == []


# --------------------------------------------------------------------------
# metadata.py: robust load + prune helpers
# --------------------------------------------------------------------------
def test_metadata_load_recovers_missing_table_name(tmp_path):
    p = tmp_path / "meta.json"
    p.write_text(json.dumps({
        "databases_enumerated": True,
        "databases": {"appdb": {"tables_enumerated": True, "tables": {
            "dbo.accounts": {"schema": "dbo",
                             "columns": {"id": {"data_type": None}}},
        }}},
    }))
    idx = MetadataIndex.load(str(p))
    names = [t.name for _db, t in idx.iter_tables()]
    assert "accounts" in names


def test_metadata_prune_helpers():
    idx = MetadataIndex()
    idx.add_column("a", "t1", "c1")
    idx.add_column("a", "t2", "c1")
    idx.add_database("b")
    idx.prune_databases(["a"])          # keeps "a" (and "") only
    assert set(idx.database_names()) == {"a"}
    idx.databases["a"].prune_tables(["t1"])
    assert [t.name for _d, t in idx.iter_tables()] == ["t1"]


# --------------------------------------------------------------------------
# discovery.py: force=True evicts stale entries
# --------------------------------------------------------------------------
def test_force_rediscovery_evicts_dropped_database():
    schema = {"a": {"t": {"c": ["x"]}}, "b": {"t": {"c": ["y"]}}}
    oracle = SchemaOracle(schema, current_db="a")
    cfg = Config(charset=PRINTABLE_CHARSET, workers=2, verbosity=0)
    engine = ExfiltrationEngine(cfg, oracle)
    disc = MetadataDiscoverer(engine, get_dialect("mssql"), MetadataIndex())
    assert set(disc.discover_databases()) == {"a", "b"}
    del schema["b"]  # b dropped between runs
    assert set(disc.discover_databases(force=True)) == {"a"}


# --------------------------------------------------------------------------
# keywords.py: ' ;; ' separator requires surrounding whitespace
# --------------------------------------------------------------------------
def test_keyword_value_with_double_semicolon_preserved():
    assert [k.value for k in parse_keywords("a;;b")] == ["a;;b"]


def test_keyword_options_still_parse_with_spaces():
    kws = parse_keywords("invoice ;; exact")
    assert kws[0].value == "invoice" and kws[0].exact is True


# --------------------------------------------------------------------------
# rce.py: WAITFOR HH:MM:SS for delays >= 60, sub-second delay floor
# --------------------------------------------------------------------------
def test_waitfor_build_sql_carries_into_minutes_and_hours():
    p = rce.EXEC_PROBES_BY_KEY["waitfor"]
    assert "00:00:05" in p.build_sql(5)
    assert "00:01:00" in p.build_sql(60)
    assert "01:01:01" in p.build_sql(3661)


def test_verify_execution_subsecond_delay_still_confirms():
    oracle = FakeRceOracle(executes={"waitfor": True})
    res = rce.verify_execution(
        FakeEngine(oracle), rce.EXEC_PROBES_BY_KEY["waitfor"], delay=0.4)
    assert res.verdict is rce.ExecVerdict.CONFIRMED


def test_resolve_exec_probes_auto_combined_with_named():
    probes = rce.resolve_exec_probes(["waitfor", "auto"])
    keys = [p.key for p in probes]
    assert "waitfor" in keys and "xp_cmdshell_nix" in keys
    assert len(keys) == len(set(keys))  # de-duplicated


# --------------------------------------------------------------------------
# http_client.py: max_retries=0 still sends one request
# --------------------------------------------------------------------------
def test_zero_retries_still_sends_one_request(monkeypatch):
    requests = pytest.importorskip("requests")
    from blindsqli.http_client import HttpClient, RequestError

    client = HttpClient(Config(target_url="http://localhost/", retry_backoff=0.0,
                               max_retries=0))
    calls = {"n": 0}

    class S:
        def request(self, *a, **k):
            calls["n"] += 1
            raise requests.exceptions.ConnectionError("x")

    monkeypatch.setattr(client, "_session", lambda: S())
    with pytest.raises(RequestError):
        client.send("x")
    assert calls["n"] == 1


# --------------------------------------------------------------------------
# cli.py: argparse choices + mutually-exclusive target
# --------------------------------------------------------------------------
def test_method_accepts_put():
    from blindsqli.cli import build_parser
    args = build_parser().parse_args(["extract", "--url", "http://x/", "--method", "PUT"])
    assert args.http_method == "PUT"


def test_body_mode_accepts_query():
    from blindsqli.cli import build_parser
    args = build_parser().parse_args(["extract", "--url", "http://x/", "--body-mode", "query"])
    assert args.body_mode == "query"


def test_preset_and_expr_are_mutually_exclusive():
    from blindsqli.cli import build_parser
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["extract", "--preset", "first-table", "--expr", "(SELECT 1)"])


# --------------------------------------------------------------------------
# wizard.py: _choose_from + charset widening go through set_charset
# --------------------------------------------------------------------------
class _ScriptedPrompt:
    def __init__(self, answers):
        self.answers = list(answers)

    def __call__(self, _msg):
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


_WIZ_SCHEMA = {"appdb": {"accounts": {"username": ["admin"]}}}


def test_choose_from_invalid_index_selects_nothing():
    cfg = Config(charset=PRINTABLE_CHARSET, verbosity=0)
    engine = ExfiltrationEngine(cfg, SchemaOracle(_WIZ_SCHEMA, current_db="appdb"))
    wiz = Wizard(cfg, engine, get_dialect("mssql"),
                 prompt=_ScriptedPrompt(["99"]), out=[].append)
    assert wiz._choose_from("Items:", ["x", "y", "z"]) == []


def test_wizard_extract_widens_engine_charset(monkeypatch):
    cfg = Config(charset="abc", verbosity=0, workers=1)
    engine = ExfiltrationEngine(cfg, SchemaOracle(_WIZ_SCHEMA, current_db="appdb"))
    monkeypatch.setattr(engine, "discover_count", lambda *a, **k: None)
    wiz = Wizard(cfg, engine, get_dialect("mssql"),
                 prompt=_ScriptedPrompt(["", "0", "n"]), out=[].append)
    wiz.state.selected_table = ("appdb", "accounts")
    wiz.state.selected_columns = ["username"]
    assert "m" not in engine.ordered_charset  # narrow before
    wiz.extract_object()
    assert set("admin") <= set(engine.ordered_charset)  # widened to printable
