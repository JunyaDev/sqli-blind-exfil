import json

import pytest

from blindsqli.cli import build_parser, _apply_overrides, _build_target, main
from blindsqli.config import Config


def test_version(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip()


def test_overrides_applied():
    parser = build_parser()
    args = parser.parse_args([
        "extract", "--url", "http://localhost:3000/", "--workers", "7",
        "--strategy", "binary", "--param", "search",
    ])
    cfg = _apply_overrides(Config(), args)
    assert cfg.workers == 7
    assert cfg.strategy == "binary"
    assert cfg.injection_param == "search"


def test_build_target_preset():
    parser = build_parser()
    args = parser.parse_args(["extract", "--preset", "first-table"])
    cfg = _apply_overrides(Config(), args)
    target = _build_target(cfg, args)
    assert "INFORMATION_SCHEMA.TABLES" in target.expression


def test_build_target_custom_expr():
    parser = build_parser()
    args = parser.parse_args(["extract", "--expr", "(SELECT DB_NAME())", "--target-name", "DB"])
    cfg = _apply_overrides(Config(), args)
    target = _build_target(cfg, args)
    assert target.expression == "(SELECT DB_NAME())"
    assert target.name == "DB"


def test_scope_error_exit_code():
    # external host without opt-in -> scope error exit code 3
    rc = main(["extract", "--url", "http://example.com/", "--quiet", "--no-length"])
    assert rc == 3


def test_full_cli_extract_against_mock(tmp_path):
    pytest.importorskip("requests")
    from mock_target import MockTarget

    with MockTarget(secret="jun_users", param="q", port=0) as srv:
        out = tmp_path / "result.json"
        rc = main([
            "extract",
            "--url", srv.url,
            "--param", "q",
            "--preset", "first-table",
            "--workers", "6",
            "--quiet",
            "--output", str(out),
        ])
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["value"] == "jun_users"
        assert data["complete"] is True


def test_proxy_overrides_applied():
    parser = build_parser()
    args = parser.parse_args(["extract", "--proxy", "http://127.0.0.1:8080", "--proxy-insecure"])
    cfg = _apply_overrides(Config(), args)
    assert cfg.proxy == "http://127.0.0.1:8080"
    assert cfg.proxy_insecure is True


def test_proxy_absent_keeps_config_value():
    # a config file value must survive when the flag is not passed
    parser = build_parser()
    args = parser.parse_args(["extract", "--url", "http://localhost:3000/"])
    base = Config(proxy="http://10.0.0.1:3128")
    cfg = _apply_overrides(base, args)
    assert cfg.proxy == "http://10.0.0.1:3128"


def test_config_flag_accepted_after_subcommand():
    # regression: "extract --config X" used to fail with "unrecognized arguments"
    parser = build_parser()
    args = parser.parse_args(["extract", "--config", "cfg.json", "--preset", "first-table"])
    assert args.config == "cfg.json"


def test_config_flag_accepted_before_subcommand():
    parser = build_parser()
    args = parser.parse_args(["--config", "cfg.json", "extract"])
    assert args.config == "cfg.json"


def test_config_flag_absent_is_none():
    parser = build_parser()
    args = parser.parse_args(["extract"])
    assert args.config is None


def test_collation_flags():
    parser = build_parser()
    assert parser.parse_args(["extract", "--no-collation"]).collation == ""
    assert parser.parse_args(["extract", "--collation", "SQL_X"]).collation == "SQL_X"
    assert parser.parse_args(["extract"]).collation is None


def test_build_target_applies_collation():
    from argparse import Namespace
    from blindsqli.cli import _build_target
    # disable
    t = _build_target(Config(collation=""), Namespace(preset=None))
    assert "COLLATE" not in t.char_is(1, "a")
    # default keeps MSSQL binary collation
    t2 = _build_target(Config(collation=None), Namespace(preset=None))
    assert "COLLATE Latin1_General_BIN" in t2.char_is(1, "a")
    # custom name
    t3 = _build_target(Config(collation="SQL_Latin1_General_CP1_CS_AS"), Namespace(preset=None))
    assert "COLLATE SQL_Latin1_General_CP1_CS_AS" in t3.char_is(1, "a")


def test_enumerate_all_tables(tmp_path):
    pytest.importorskip("requests")
    from mock_target import MockTarget
    with MockTarget(secrets=["jun_notes", "jun_roles", "jun_users"], param="q", port=0) as srv:
        out = tmp_path / "tables.json"
        rc = main(["enumerate", "--url", srv.url, "--param", "q", "--quiet", "--output", str(out)])
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["count"] == 3
        assert data["values"] == ["jun_notes", "jun_roles", "jun_users"]


def test_enumerate_databases(tmp_path):
    pytest.importorskip("requests")
    from mock_target import MockTarget
    with MockTarget(secrets=["appdb", "master"], param="q", port=0) as srv:
        out = tmp_path / "dbs.json"
        rc = main(["enumerate", "--what", "databases", "--url", srv.url, "--param", "q",
                   "--quiet", "--output", str(out)])
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["values"] == ["appdb", "master"]


def test_enumerate_tables_scoped_to_database(tmp_path):
    pytest.importorskip("requests")
    from mock_target import MockTarget
    with MockTarget(secrets=["jun_notes", "jun_roles", "jun_users"], param="q", port=0) as srv:
        out = tmp_path / "t.json"
        rc = main(["enumerate", "--url", srv.url, "--param", "q", "--database", "otherdb",
                   "--quiet", "--output", str(out)])
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["count"] == 3
        assert data["values"] == ["jun_notes", "jun_roles", "jun_users"]
