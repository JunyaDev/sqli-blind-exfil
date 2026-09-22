"""JSON / raw body support.

Unit tests for request construction (no network) and end-to-end extraction over
a JSON body against the JSON-aware mock (skipped if `requests` is absent).
"""

import json

import pytest

from blindsqli.config import Config
from blindsqli.http_client import HttpClient


def client(**over):
    return HttpClient(Config(target_url="http://localhost:3000/", **over))


# --- request construction ---------------------------------------------------

def test_auto_get_uses_query_string():
    kw = client(http_method="GET", injection_param="q").build_request("VAL", "GET")
    assert kw == {"params": {"q": "VAL"}}


def test_auto_post_uses_form_body():
    kw = client(http_method="POST", injection_param="q").build_request("VAL", "POST")
    assert kw == {"data": {"q": "VAL"}}


def test_json_flat_key():
    kw = client(body_mode="json", injection_param="q").build_request("VAL", "POST")
    assert kw == {"json": {"q": "VAL"}}


def test_json_nested_path_into_template():
    c = client(body_mode="json", injection_param="filter.username",
               json_template={"page": 1})
    kw = c.build_request("VAL", "POST")
    assert kw == {"json": {"page": 1, "filter": {"username": "VAL"}}}
    # the template itself must not be mutated across calls
    c.build_request("OTHER", "POST")
    assert c.config.json_template == {"page": 1}


def test_raw_template_json_escapes_value():
    c = client(body_mode="raw", body_template='{"q":"{value_json}"}',
               content_type="application/json")
    payload = 'a"b\\c'  # contains chars that must be JSON-escaped
    kw = c.build_request(payload, "POST")
    assert kw["headers"]["Content-Type"] == "application/json"
    # the rendered body must be valid JSON that round-trips to the payload
    assert json.loads(kw["data"].decode())["q"] == payload


def test_raw_template_verbatim_value():
    c = client(body_mode="raw", body_template="user={value}&x=1",
               content_type="application/x-www-form-urlencoded")
    kw = c.build_request("VAL", "POST")
    assert kw["data"].decode() == "user=VAL&x=1"


# --- validation --------------------------------------------------------------

def test_raw_requires_template():
    with pytest.raises(ValueError):
        Config(body_mode="raw").validate()


def test_raw_template_requires_placeholder():
    with pytest.raises(ValueError):
        Config(body_mode="raw", body_template="no placeholder").validate()


def test_bad_body_mode_rejected():
    with pytest.raises(ValueError):
        Config(body_mode="xml").validate()


# --- end to end over a JSON body --------------------------------------------

def test_extract_over_json_body():
    pytest.importorskip("requests")
    from blindsqli.oracle import BooleanOracle
    from blindsqli.engine import ExfiltrationEngine
    from blindsqli.dialect import get_dialect
    from blindsqli.targets import first_table_name
    from mock_target import MockTarget

    with MockTarget(secret="jun_users", param="creds.username", port=0) as srv:
        cfg = Config(
            target_url=srv.url, http_method="POST", body_mode="json",
            injection_param="creds.username", json_template={"page": 1},
            workers=6, verbosity=0,
        )
        oracle = BooleanOracle(cfg)
        result = ExfiltrationEngine(cfg, oracle).extract(first_table_name(get_dialect("mssql")))
        assert result.value == "jun_users"
        assert result.complete is True


def test_extract_over_raw_json_template():
    pytest.importorskip("requests")
    from blindsqli.oracle import BooleanOracle
    from blindsqli.engine import ExfiltrationEngine
    from blindsqli.dialect import get_dialect
    from blindsqli.targets import first_table_name
    from mock_target import MockTarget

    with MockTarget(secret="jun_users", param="q", port=0) as srv:
        cfg = Config(
            target_url=srv.url, http_method="POST", body_mode="raw",
            body_template='{"q":"{value_json}","page":1}',
            content_type="application/json", injection_param="q",
            workers=6, verbosity=0,
        )
        oracle = BooleanOracle(cfg)
        result = ExfiltrationEngine(cfg, oracle).extract(first_table_name(get_dialect("mssql")))
        assert result.value == "jun_users"
        assert result.complete is True
