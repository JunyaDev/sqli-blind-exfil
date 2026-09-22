"""Tests for the Burp exporter's pure logic (burp_sqli.core).

These run under CPython 3; the same module runs under Jython inside Burp.
"""

import json

import pytest

from burp_sqli import core
from blindsqli.config import Config


GET_RAW = (
    "GET /search?q=juniper&page=2 HTTP/1.1\r\n"
    "Host: localhost:3000\r\n"
    "User-Agent: demo\r\n"
    "Cookie: session=abc123; theme=dark\r\n"
    "\r\n"
)

FORM_RAW = (
    "POST /login HTTP/1.1\r\n"
    "Host: h\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 21\r\n"
    "\r\n"
    "user=admin&pass=secret"
)

JSON_RAW = (
    "POST /api/search HTTP/1.1\r\n"
    "Host: h\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"page":1,"creds":{"username":"bob","role":"admin"}}'
)


# --- parsing / enumeration --------------------------------------------------

def test_parse_builds_absolute_url():
    m = core.parse_request(GET_RAW, "http", "localhost", 3000)
    assert m.method == "GET"
    assert m.url == "http://localhost:3000/search?q=juniper&page=2"
    assert m.cookies == {"session": "abc123", "theme": "dark"}


def test_enumerate_query_and_cookies():
    m = core.parse_request(GET_RAW, "http", "localhost", 3000)
    params = core.enumerate_parameters(m)
    locs = {(p.name, p.location) for p in params}
    assert ("q", "query") in locs
    assert ("page", "query") in locs
    assert ("session", "cookie") in locs
    assert ("theme", "cookie") in locs


def test_enumerate_form_params():
    m = core.parse_request(FORM_RAW, "http", "h", 80)
    params = core.enumerate_parameters(m)
    assert {(p.name, p.location) for p in params} == {("user", "form"), ("pass", "form")}


def test_enumerate_json_dotted_paths():
    m = core.parse_request(JSON_RAW, "http", "h", 80)
    names = [(p.name, p.location) for p in params_of(m)]
    assert ("creds.username", "json") in names
    assert ("creds.role", "json") in names


def params_of(model):
    return core.enumerate_parameters(model)


# --- config building --------------------------------------------------------

def _select(model, name, location):
    for p in core.enumerate_parameters(model):
        if p.name == name and p.location == location:
            return p
    raise AssertionError("param not found: {0} [{1}]".format(name, location))


def test_build_query_config():
    m = core.parse_request(GET_RAW, "http", "localhost", 3000)
    cfg = core.build_request_config(m, _select(m, "q", "query"))
    assert cfg["target_url"] == "http://localhost:3000/search"   # query stripped
    assert cfg["body_mode"] == "query"
    assert cfg["injection_param"] == "q"
    assert cfg["static_params"] == {"page": "2"}                 # other query param
    assert cfg["cookies"] == {"session": "abc123", "theme": "dark"}
    # headers cleaned of transport-managed fields
    assert "Host" not in cfg["headers"] and "Cookie" not in cfg["headers"]
    assert cfg["headers"] == {"User-Agent": "demo"}
    assert cfg["_burp_export"]["selected_param"] == "q"
    assert cfg["_burp_export"]["location"] == "query"


def test_build_form_config_keeps_query_in_url():
    raw = FORM_RAW.replace("/login", "/login?ref=home")
    m = core.parse_request(raw, "http", "h", 80)
    cfg = core.build_request_config(m, _select(m, "user", "form"))
    assert cfg["body_mode"] == "form"
    assert cfg["target_url"] == "http://h/login?ref=home"        # query preserved
    assert cfg["static_params"] == {"pass": "secret"}


def test_build_json_config():
    m = core.parse_request(JSON_RAW, "http", "h", 80)
    cfg = core.build_request_config(m, _select(m, "creds.username", "json"))
    assert cfg["body_mode"] == "json"
    assert cfg["injection_param"] == "creds.username"
    assert cfg["json_template"] == {"page": 1, "creds": {"username": "bob", "role": "admin"}}
    assert cfg["target_url"] == "http://h/api/search"


def test_build_cookie_config():
    m = core.parse_request(GET_RAW, "http", "localhost", 3000)
    cfg = core.build_request_config(m, _select(m, "session", "cookie"))
    assert cfg["body_mode"] == "cookie"
    assert cfg["injection_param"] == "session"
    assert cfg["cookies"]["session"] == "abc123"
    assert cfg["target_url"] == "http://localhost:3000/search?q=juniper&page=2"


# --- merge / file safety ----------------------------------------------------

def test_merge_preserves_unrelated_and_clears_stale():
    existing = {
        "charset": "abcdef", "workers": 5, "base_payload": "X",
        "classifier": {"auto_calibrate": True},
        "json_template": {"stale": 1},
    }
    m = core.parse_request(GET_RAW, "http", "localhost", 3000)
    req = core.build_request_config(m, _select(m, "q", "query"))
    merged = core.merge_config(existing, req)
    # unrelated settings preserved
    assert merged["charset"] == "abcdef"
    assert merged["workers"] == 5
    assert merged["base_payload"] == "X"
    assert merged["classifier"] == {"auto_calibrate": True}
    # request keys updated; stale json_template cleared for a query export
    assert merged["body_mode"] == "query"
    assert merged["json_template"] is None


def test_export_writes_valid_json_and_preserves(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"workers": 7, "base_payload": "KEEP"}))
    m = core.parse_request(JSON_RAW, "http", "h", 80)
    core.export(str(path), m, _select(m, "creds.username", "json"))
    on_disk = json.loads(path.read_text())
    assert on_disk["workers"] == 7               # preserved
    assert on_disk["base_payload"] == "KEEP"     # preserved
    assert on_disk["body_mode"] == "json"        # updated
    assert on_disk["injection_param"] == "creds.username"


def test_export_refuses_to_corrupt_bad_existing(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text("{ this is not valid json ")
    m = core.parse_request(GET_RAW, "http", "localhost", 3000)
    with pytest.raises(ValueError):
        core.export(str(path), m, _select(m, "q", "query"))
    # the bad file must be left untouched
    assert path.read_text() == "{ this is not valid json "


# --- compatibility with the tool's own loader -------------------------------

def test_exported_config_loads_in_tool(tmp_path):
    path = tmp_path / "cfg.json"
    m = core.parse_request(JSON_RAW, "http", "h", 80)
    core.export(str(path), m, _select(m, "creds.username", "json"))
    cfg = Config.load(str(path))          # must not raise despite _burp_export
    cfg.validate()                        # must not raise
    assert cfg.body_mode == "json"
    assert cfg.injection_param == "creds.username"
    assert not hasattr(cfg, "_burp_export")   # unknown key ignored on load


def test_end_to_end_export_then_extract(tmp_path):
    pytest.importorskip("requests")
    from urllib.parse import urlsplit
    from mock_target import MockTarget
    from blindsqli.oracle import BooleanOracle
    from blindsqli.engine import ExfiltrationEngine
    from blindsqli.dialect import get_dialect
    from blindsqli.targets import first_table_name

    with MockTarget(secret="jun_users", port=0) as srv:
        host = urlsplit(srv.url).hostname
        port = urlsplit(srv.url).port
        raw = (
            "POST /api/search HTTP/1.1\r\n"
            "Host: {0}:{1}\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{{"page":1,"creds":{{"username":"seed"}}}}'
        ).format(host, port)
        m = core.parse_request(raw, "http", host, port)
        core.export(str(tmp_path / "cfg.json"), m, _select(m, "creds.username", "json"))

        cfg = Config.load(str(tmp_path / "cfg.json"))
        oracle = BooleanOracle(cfg)
        result = ExfiltrationEngine(cfg, oracle).extract(first_table_name(get_dialect("mssql")))
        assert result.value == "jun_users"
        assert result.complete is True
