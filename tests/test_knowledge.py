"""Persistent knowledge-base tests: load/save/dedup, prediction seeding, and
CLI integration (seeding + updating the file, marking already-known values)."""

import json

import pytest

from blindsqli.knowledge import load_knowledge, save_knowledge, seed_predictors


def test_load_missing_returns_empty(tmp_path):
    assert load_knowledge(str(tmp_path / "nope.json")) == []


def test_load_accepts_array_and_object(tmp_path):
    a = tmp_path / "a.json"
    a.write_text(json.dumps(["x", "y"]))
    assert load_knowledge(str(a)) == ["x", "y"]
    b = tmp_path / "b.json"
    b.write_text(json.dumps({"values": ["p", "q"]}))
    assert load_knowledge(str(b)) == ["p", "q"]


def test_load_invalid_returns_empty(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    assert load_knowledge(str(bad)) == []


def test_save_dedups_and_sorts(tmp_path):
    path = tmp_path / "kb.json"
    merged = save_knowledge(str(path), ["b", "a", "b", "", "a", "c"])
    assert merged == ["a", "b", "c"]
    assert load_knowledge(str(path)) == ["a", "b", "c"]


def test_save_is_union_on_reload(tmp_path):
    path = tmp_path / "kb.json"
    save_knowledge(str(path), ["a", "b"])
    existing = load_knowledge(str(path))
    save_knowledge(str(path), existing + ["b", "c"])
    assert load_knowledge(str(path)) == ["a", "b", "c"]


def test_seeding_speeds_up_known_value():
    pytest.importorskip("requests")
    from blindsqli.config import Config
    from blindsqli.oracle import BooleanOracle
    from blindsqli.engine import ExfiltrationEngine
    from blindsqli.predictor import CharacterPredictor
    from blindsqli.sequence import SequencePredictor
    from blindsqli.dialect import get_dialect
    from blindsqli.targets import first_table_name
    from mock_target import MockTarget

    d = get_dialect("mssql")
    with MockTarget(secret="jun_users", port=0) as srv:
        cfg = Config(target_url=srv.url, verbosity=0, workers=1)

        base_oracle = BooleanOracle(cfg)
        ExfiltrationEngine(cfg, base_oracle).extract(first_table_name(d))
        baseline = base_oracle.requests_completed

        seeded_oracle = BooleanOracle(cfg)
        cp = CharacterPredictor(cfg.charset, order=cfg.predictor_order)
        sp = SequencePredictor(min_prefix=cfg.min_seq_prefix)
        seed_predictors(cp, sp, ["jun_users"])   # pretend a prior run found it
        engine = ExfiltrationEngine(cfg, seeded_oracle, char_predictor=cp, seq_predictor=sp)
        result = engine.extract(first_table_name(d))

        assert result.value == "jun_users"
        # a value we already knew is confirmed far more cheaply
        assert seeded_oracle.requests_completed < baseline


def test_cli_extract_uses_and_updates_knowledge(tmp_path):
    pytest.importorskip("requests")
    from blindsqli.cli import main
    from mock_target import MockTarget

    kb = tmp_path / "kb.json"
    with MockTarget(secret="jun_users", param="q", port=0) as srv:
        rc = main(["extract", "--url", srv.url, "--param", "q", "--preset", "first-table",
                   "--quiet", "--knowledge", str(kb), "--output", str(tmp_path / "o1.json")])
        assert rc == 0
        assert "jun_users" in load_knowledge(str(kb))

        out2 = tmp_path / "o2.json"
        rc2 = main(["extract", "--url", srv.url, "--param", "q", "--preset", "first-table",
                    "--quiet", "--knowledge", str(kb), "--output", str(out2)])
        assert rc2 == 0
        assert json.loads(out2.read_text())["already_known"] is True
