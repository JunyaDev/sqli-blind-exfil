import threading
import time

from blindsqli.config import Config
from blindsqli.dialect import get_dialect
from blindsqli.engine import ExfiltrationEngine
from blindsqli.result_types import OracleObservation, OracleResult
from blindsqli.targets import Target
from mock_target import evaluate_condition
from tests.fakes import FakeOracle


def make_target():
    return Target("T", "(SELECT TOP(1) TABLE_NAME FROM INFORMATION_SCHEMA.TABLES)", get_dialect("mssql"))


def test_ordering_preserved_with_out_of_order_completion():
    # Random-ish latency per request; result must still be exactly the secret.
    class JitterOracle(FakeOracle):
        def ask(self, condition):
            # vary delay by content so requests finish out of submission order
            time.sleep(0.002 * (len(condition) % 5))
            return super().ask(condition)

    oracle = JitterOracle(secret="jun_users_table")
    engine = ExfiltrationEngine(Config(verbosity=0, workers=8, strategy="adaptive"),
                                oracle, logger=None)
    result = engine.extract(make_target())
    assert result.value == "jun_users_table"


def test_worker_pool_is_bounded():
    max_workers = 4
    active = {"cur": 0, "max": 0}
    lock = threading.Lock()

    class CountingOracle(FakeOracle):
        def ask(self, condition):
            with lock:
                active["cur"] += 1
                active["max"] = max(active["max"], active["cur"])
            time.sleep(0.01)
            try:
                return super().ask(condition)
            finally:
                with lock:
                    active["cur"] -= 1

    oracle = CountingOracle(secret="jun_users")
    engine = ExfiltrationEngine(
        Config(verbosity=0, workers=max_workers, strategy="adaptive", char_batch=8),
        oracle, logger=None,
    )
    result = engine.extract(make_target())
    assert result.value == "jun_users"
    assert active["max"] <= max_workers


def test_shared_oracle_thread_safe_counters():
    oracle = FakeOracle(secret="jun_users", delay=0.001)
    engine = ExfiltrationEngine(Config(verbosity=0, workers=10, char_batch=6),
                                oracle, logger=None)
    result = engine.extract(make_target())
    assert result.value == "jun_users"
    # every ask incremented the counter exactly once
    assert oracle.requests_completed == len(oracle.asked)
