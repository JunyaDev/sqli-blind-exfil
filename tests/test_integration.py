"""Integration test against the local mock target over real HTTP.

Exercises the full stack: HTTP client -> payload -> oracle -> auto-calibrated
classifier -> engine. Skipped automatically if `requests` is not installed.
"""

import pytest

requests = pytest.importorskip("requests")

from blindsqli.config import Config
from blindsqli.dialect import get_dialect
from blindsqli.engine import ExfiltrationEngine
from blindsqli.oracle import BooleanOracle
from blindsqli.targets import first_table_name
from mock_target import MockTarget


@pytest.fixture()
def server():
    srv = MockTarget(secret="jun_users", param="q", port=0).start()
    try:
        yield srv
    finally:
        srv.stop()


def make_config(url: str) -> Config:
    return Config(
        target_url=url,
        injection_param="q",
        http_method="GET",
        workers=6,
        verbosity=0,
        request_timeout=5.0,
    )


def test_end_to_end_extracts_table_name(server):
    cfg = make_config(server.url)
    oracle = BooleanOracle(cfg)  # auto-calibrates from 1=1 / 1=2 probes
    engine = ExfiltrationEngine(cfg, oracle)
    result = engine.extract(first_table_name(get_dialect("mssql")))
    assert result.value == "jun_users"
    assert result.complete is True


def test_calibration_finds_side_channel(server):
    cfg = make_config(server.url)
    oracle = BooleanOracle(cfg)
    oracle.calibrate()
    # TRUE condition -> normal page; FALSE condition -> SQL error page
    assert oracle.test("1=1").value == "TRUE"
    assert oracle.test("1=2").value == "FALSE"


def test_boolean_true_false_detection(server):
    """The two examples the brief asks for: an observable TRUE and FALSE."""
    cfg = make_config(server.url)
    oracle = BooleanOracle(cfg)
    oracle.calibrate()
    dialect = get_dialect("mssql")
    target = first_table_name(dialect)
    # 'jun_users' starts with 'jun' (TRUE) but not 'xyz' (FALSE)
    assert oracle.test(target.starts_with("jun")).name == "TRUE"
    assert oracle.test(target.starts_with("xyz")).name == "FALSE"
