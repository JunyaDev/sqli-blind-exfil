import pytest

from blindsqli.classifier import BaseClassifier, SignatureClassifier
from blindsqli.config import Config
from blindsqli.http_client import RequestError, TimeoutError_
from blindsqli.oracle import BooleanOracle, CalibrationError
from blindsqli.result_types import ClassifierDecision, OracleResult, Verdict
from mock_target import evaluate_condition, extract_condition
from tests.fakes import ScriptedHttpClient, html


def behaviour_for(secret):
    def behave(value):
        cond = extract_condition(value)
        ok = cond is not None and evaluate_condition(cond, secret)
        if ok:
            return html(200, "<ul>results</ul>" * 10)
        return html(500, "Conversion failed when converting the varchar value 'a'")
    return behave


def make_oracle(secret="jun_users", **overrides):
    cfg = Config(**overrides)
    http = ScriptedHttpClient(behaviour_for(secret))
    clf = SignatureClassifier(error_body=["Conversion failed"], ok_body=["results"])
    return BooleanOracle(cfg, http=http, classifier=clf)


def test_maps_ok_to_true_and_error_to_false():
    o = make_oracle()
    assert o.test("SUBSTRING(x,1,4) = 'jun_'") is OracleResult.TRUE
    assert o.test("SUBSTRING(x,1,4) = 'zzzz'") is OracleResult.FALSE
    assert o.requests_completed == 2


def test_calibration_builds_classifier():
    cfg = Config()
    http = ScriptedHttpClient(behaviour_for("jun_users"))
    o = BooleanOracle(cfg, http=http, classifier=None)
    o.calibrate()
    assert o.classifier is not None
    assert o.test("1=1") is OracleResult.TRUE
    assert o.test("1=2") is OracleResult.FALSE


def test_calibration_detects_no_side_channel():
    cfg = Config()
    http = ScriptedHttpClient(lambda v: html(200, "identical"))
    o = BooleanOracle(cfg, http=http, classifier=None)
    with pytest.raises(CalibrationError):
        o.calibrate()


class AlwaysUnknown(BaseClassifier):
    def classify(self, response, sent=None):
        return ClassifierDecision(Verdict.UNKNOWN, "cannot tell")


def test_unknown_is_retried_then_reported():
    cfg = Config(ambiguous_retries=2, retry_backoff=0.0)
    http = ScriptedHttpClient(lambda v: html(200, "?"))
    o = BooleanOracle(cfg, http=http, classifier=AlwaysUnknown())
    obs = o.ask("1=1")
    assert obs.result is OracleResult.UNKNOWN
    assert obs.attempts == 3  # 1 + 2 ambiguous retries


def test_timeout_never_becomes_false():
    cfg = Config(ambiguous_retries=1, retry_backoff=0.0)

    def raise_timeout(v):
        raise TimeoutError_("boom")

    http = ScriptedHttpClient(raise_timeout)
    o = BooleanOracle(cfg, http=http, classifier=SignatureClassifier(error_body=["x"]))
    obs = o.ask("1=1")
    assert obs.result is OracleResult.TIMEOUT
    assert o.requests_failed >= 1


def test_request_error_recovers_on_retry():
    cfg = Config(ambiguous_retries=3, retry_backoff=0.0)
    state = {"n": 0}

    def flaky(v):
        state["n"] += 1
        if state["n"] < 3:
            raise RequestError("connreset")
        return html(200, "results")

    http = ScriptedHttpClient(flaky)
    o = BooleanOracle(cfg, http=http, classifier=SignatureClassifier(ok_body=["results"]))
    obs = o.ask("1=1")
    assert obs.result is OracleResult.TRUE
    assert obs.attempts == 3


# --- both TRUE and FALSE return an error, differing only in the string -------

def _both_error_behaviour(secret):
    tpl = "<h1>SQL error</h1>\n<pre>{msg}</pre>\n<a>Back</a>"
    def behave(value):
        cond = extract_condition(value)
        is_true = cond is not None and evaluate_condition(cond, secret)
        if is_true:
            return html(500, tpl.format(msg="Divide by zero error encountered."))
        return html(500, tpl.format(msg="Conversion failed converting varchar 'a' to int."))
    return behave


def test_oracle_maps_when_both_branches_error():
    cfg = Config(ambiguous_retries=1, retry_backoff=0.0)
    o = BooleanOracle(cfg, http=ScriptedHttpClient(_both_error_behaviour("jun_users")),
                      classifier=None)
    o.calibrate()  # both probes are HTTP 500, differing only in body
    assert o.test("1=1") is OracleResult.TRUE
    assert o.test("1=2") is OracleResult.FALSE
    assert o.test("SUBSTRING(x,1,4) = 'jun_'") is OracleResult.TRUE
    assert o.test("SUBSTRING(x,1,4) = 'zzzz'") is OracleResult.FALSE


def test_oracle_dynamic_error_is_unknown_not_false():
    """FALSE error string is non-deterministic and same length as the TRUE error.
    The oracle must retry and report UNKNOWN rather than silently return FALSE."""
    secret = "jun_users"
    n = 120
    pad = lambda s: s.ljust(n, ".")[:n]
    state = {"k": 0}

    def behave(value):
        cond = extract_condition(value)
        is_true = cond is not None and evaluate_condition(cond, secret)
        if is_true:
            return html(500, pad("SQL error: divide by zero encountered"))
        state["k"] += 1
        return html(500, pad(f"SQL error: conversion failed token={state['k']:08d} end"))

    cfg = Config(ambiguous_retries=2, retry_backoff=0.0)
    o = BooleanOracle(cfg, http=ScriptedHttpClient(behave), classifier=None)
    o.calibrate()
    # the static TRUE error still resolves cleanly
    assert o.test("1=1") is OracleResult.TRUE
    # the dynamic FALSE error cannot be decided -> UNKNOWN, never FALSE
    obs = o.ask("1=2")
    assert obs.result is OracleResult.UNKNOWN
    assert obs.result is not OracleResult.FALSE
    assert obs.attempts == 3  # 1 + 2 ambiguous retries


def _reflect_behaviour(secret):
    """Both branches 500; body echoes the sent payload (so length tracks the
    payload length) and differs only by a fixed base string."""
    def behave(value):
        cond = extract_condition(value)
        is_true = cond is not None and evaluate_condition(cond, secret)
        base = "<pre>TRUEBODY</pre>" if is_true else "<pre>FALSE-BODY-LONGER</pre>"
        return html(500, base + value)  # + value == reflected payload
    return behave


def test_oracle_length_signal_survives_reflection():
    cfg = Config(ambiguous_retries=0, retry_backoff=0.0)
    o = BooleanOracle(cfg, http=ScriptedHttpClient(_reflect_behaviour("jun_users")),
                      classifier=None)
    o.calibrate()  # both 500, differ only in base string; body echoes payload
    assert o.test("SUBSTRING(x,1,4) = 'jun_'") is OracleResult.TRUE
    assert o.test("SUBSTRING(x,1,4) = 'zzzz'") is OracleResult.FALSE
