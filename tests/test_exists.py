"""Tests for existence verification before character-by-character extraction.

A scalar subquery that selects nothing returns NULL. Before this guard, the
engine mistook a NULL target for a value longer than max_length and burned a
full extraction on it. Now it verifies existence cheaply and skips.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import pytest

from blindsqli.config import Config
from blindsqli.dialect import get_dialect
from blindsqli.engine import ExfiltrationEngine
from blindsqli.targets import custom

from tests.fakes import FakeOracle


def _engine(secret, verify=False, workers=2):
    cfg = Config()
    cfg.verbosity = 0
    cfg.workers = workers
    cfg.verify_exists = verify
    oracle = FakeOracle(secret)
    return cfg, oracle, ExfiltrationEngine(cfg, oracle)


def _target():
    return custom(get_dialect("mssql"), "X", "(SELECT x FROM t WHERE id=1)")


def test_exists_true_for_present_value():
    _cfg, _o, engine = _engine("jun_users")
    assert engine.exists(_target()) is True


def test_exists_false_for_null_target():
    _cfg, _o, engine = _engine(None)  # None models a NULL / absent scalar
    assert engine.exists(_target()) is False


def test_verify_exists_skips_missing_cheaply():
    cfg, oracle, engine = _engine(None, verify=True)
    result = engine.extract(_target())
    assert result.missing is True
    assert result.exists is False
    assert result.value == ""
    # a couple of requests at most -- not a full character search
    assert oracle.requests_completed <= 3


def test_automatic_guard_detects_missing_without_flag():
    # Even without --verify-exists, length discovery now probes existence
    # instead of assuming "longer than max_length" and extracting 64 chars.
    cfg, oracle, engine = _engine(None, verify=False)
    result = engine.extract(_target())
    assert result.missing is True
    assert result.exists is False
    assert oracle.requests_completed <= 6  # tiny; a full search would be 100s


def test_present_value_still_extracts_and_marks_exists():
    cfg, oracle, engine = _engine("jun_users", verify=True)
    result = engine.extract(_target())
    assert result.value == "jun_users"
    assert result.complete is True
    assert result.exists is True


def test_empty_string_is_not_treated_as_missing():
    # "" exists (length 0); it must NOT be reported as a missing/NULL target.
    cfg, oracle, engine = _engine("", verify=False)
    result = engine.extract(_target())
    assert result.value == ""
    assert result.complete is True
    assert result.missing is False


# --- CLI / enumerate: NULL rows are skipped -------------------------------

requests = pytest.importorskip("requests")
from blindsqli.cli import main  # noqa: E402
from mock_target import MockTarget  # noqa: E402


@pytest.fixture()
def server_with_null_row():
    srv = MockTarget(secrets=["accounts", None, "products"], param="q", port=0).start()
    try:
        yield srv
    finally:
        srv.stop()


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def test_enumerate_skips_null_row(server_with_null_row):
    rc, out = _run([
        "enumerate", "--url", server_with_null_row.url, "--param", "q", "--quiet",
        "--what", "tables", "--verify-exists",
    ])
    data = json.loads(out)
    rows = {r["offset"]: r for r in data["rows"]}
    assert rows[0]["value"] == "accounts"
    assert rows[1]["exists"] is False and rows[1]["value"] == ""
    assert rows[2]["value"] == "products"
    assert rc == 0  # a NULL cell is not an extraction failure


def test_enumerate_skips_null_row_even_without_flag(server_with_null_row):
    # the automatic guard skips the NULL row cheaply even without --verify-exists
    rc, out = _run([
        "enumerate", "--url", server_with_null_row.url, "--param", "q", "--quiet",
        "--what", "tables",
    ])
    data = json.loads(out)
    rows = {r["offset"]: r for r in data["rows"]}
    assert rows[1]["exists"] is False
    assert rows[0]["value"] == "accounts" and rows[2]["value"] == "products"
