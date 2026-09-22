import pytest

from blindsqli.config import Config
from blindsqli.dialect import get_dialect
from blindsqli.engine import ExfiltrationEngine
from blindsqli.predictor import CharacterPredictor
from blindsqli.sequence import SequencePredictor
from blindsqli.targets import Target
from blindsqli.result_types import OracleObservation, OracleResult
from tests.fakes import FakeOracle


def make_target():
    return Target("TABLE_NAME", "(SELECT TOP(1) TABLE_NAME FROM INFORMATION_SCHEMA.TABLES)", get_dialect("mssql"))


def make_engine(oracle, cfg=None, seq=None):
    cfg = cfg or Config(verbosity=0)
    return ExfiltrationEngine(cfg, oracle, seq_predictor=seq, logger=None)


@pytest.mark.parametrize("strategy", ["adaptive", "linear", "binary"])
def test_extracts_value_all_strategies(strategy):
    oracle = FakeOracle(secret="jun_users")
    engine = make_engine(oracle, Config(verbosity=0, strategy=strategy))
    result = engine.extract(make_target())
    assert result.value == "jun_users"
    assert result.complete is True
    assert result.length == 9


def test_length_is_discovered():
    oracle = FakeOracle(secret="abc")
    engine = make_engine(oracle)
    result = engine.extract(make_target())
    assert result.length == 3
    assert result.value == "abc"


def test_empty_value():
    oracle = FakeOracle(secret="")
    engine = make_engine(oracle)
    result = engine.extract(make_target())
    assert result.value == ""
    assert result.complete is True
    assert result.length == 0


def test_truncation_without_length_discovery():
    oracle = FakeOracle(secret="jun_users")
    engine = make_engine(oracle, Config(verbosity=0, discover_length=False, max_length=3))
    result = engine.extract(make_target())
    assert result.value == "jun"
    assert result.truncated is True
    assert result.complete is False


def test_sequence_phase_recovers_value():
    oracle = FakeOracle(secret="jun_users")
    seq = SequencePredictor(min_prefix=2)
    seq.learn_value("jun_roles")
    seq.learn_value("jun_projects")  # establishes recurring "jun_"
    engine = make_engine(oracle, Config(verbosity=0, strategy="adaptive"), seq=seq)
    result = engine.extract(make_target())
    assert result.value == "jun_users"
    assert result.complete is True


def test_undetermined_position_reported():
    class PartialOracle(FakeOracle):
        def ask(self, condition):
            if ",2,1)" in condition:  # every single-char probe at position 2
                with self._lock:
                    self.requests_completed += 1
                return OracleObservation(condition, OracleResult.UNKNOWN, 1)
            return super().ask(condition)

    oracle = PartialOracle(secret="jun_users")
    engine = make_engine(oracle, Config(verbosity=0, strategy="adaptive"))
    result = engine.extract(make_target())
    assert result.complete is False
    assert result.undetermined_at == 2
    assert result.value == "j"


def test_predictor_reduces_requests():
    # With a warm predictor, adaptive should need fewer requests than a naive
    # linear scan of the whole charset per character.
    warm = CharacterPredictor(Config().charset, order=3)
    for _ in range(5):
        warm.learn_value("jun_users")
    oracle = FakeOracle(secret="jun_users")
    engine = ExfiltrationEngine(Config(verbosity=0, strategy="adaptive"), oracle,
                                char_predictor=warm, logger=None)
    result = engine.extract(make_target())
    assert result.value == "jun_users"
    # naive worst case would be ~ len(charset) * 9; assert we are far below
    assert oracle.requests_completed < len(Config().charset) * 9
