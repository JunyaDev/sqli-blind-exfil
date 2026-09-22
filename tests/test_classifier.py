from blindsqli.classifier import (
    BaselineClassifier,
    CompositeClassifier,
    LengthClassifier,
    SignatureClassifier,
    StatusClassifier,
    TimingClassifier,
    from_config,
)
from blindsqli.config import ClassifierConfig
from blindsqli.result_types import Verdict
from tests.fakes import html


def test_status_classifier():
    c = StatusClassifier(error_status=[500], ok_status=[200])
    assert c.classify(html(500, "x")).verdict is Verdict.ERROR
    assert c.classify(html(200, "x")).verdict is Verdict.OK
    assert c.classify(html(404, "x")).verdict is Verdict.UNKNOWN


def test_signature_classifier():
    c = SignatureClassifier(error_body=["Conversion failed"], ok_body=["results"])
    assert c.classify(html(200, "Conversion failed ...")).verdict is Verdict.ERROR
    assert c.classify(html(200, "here are results")).verdict is Verdict.OK
    assert c.classify(html(200, "nothing")).verdict is Verdict.UNKNOWN


def test_length_classifier():
    c = LengthClassifier(threshold=100, shorter_is_error=True)
    assert c.classify(html(200, "x" * 50)).verdict is Verdict.ERROR
    assert c.classify(html(200, "x" * 150)).verdict is Verdict.OK


def test_timing_classifier():
    c = TimingClassifier(threshold=2.0)
    assert c.classify(html(200, "x", elapsed=3.0)).verdict is Verdict.ERROR
    assert c.classify(html(200, "x", elapsed=0.1)).verdict is Verdict.OK


def test_composite_first_definite_wins():
    c = CompositeClassifier([
        SignatureClassifier(error_body=["boom"]),
        StatusClassifier(error_status=[500], ok_status=[200]),
    ])
    # signature is UNKNOWN, falls through to status
    assert c.classify(html(200, "fine")).verdict is Verdict.OK
    # signature matches first
    assert c.classify(html(200, "boom")).verdict is Verdict.ERROR


def test_baseline_classifier_by_status_and_length():
    ok = html(200, "<ul><li>a</li></ul>" * 5)
    err = html(500, "Conversion failed when converting the varchar value 'a'")
    c = BaselineClassifier(ok, err)
    assert c.classify(html(500, "Conversion failed when converting the varchar value 'a'")).verdict is Verdict.ERROR
    assert c.classify(html(200, "<ul><li>a</li></ul>" * 5)).verdict is Verdict.OK


def test_baseline_classifier_length_only():
    # identical status -> must fall back to length/markers
    ok = html(200, "x" * 500)
    err = html(200, "y" * 20)
    c = BaselineClassifier(ok, err)
    assert c.classify(html(200, "z" * 480)).verdict is Verdict.OK
    assert c.classify(html(200, "z" * 25)).verdict is Verdict.ERROR


def test_from_config_returns_none_when_empty():
    assert from_config(ClassifierConfig()) is None


def test_from_config_builds_composite():
    cfg = ClassifierConfig(error_status=[500], ok_status=[200], error_body_signatures=["Conversion"])
    clf = from_config(cfg)
    assert clf is not None
    assert clf.classify(html(200, "Conversion failed")).verdict is Verdict.ERROR


# --- both branches return an HTTP error, differing only in the body ---------

def test_baseline_both_branches_error_differ_by_body():
    """TRUE and FALSE both yield HTTP 500; the classifier must decide from the
    body markers, not the (identical) status."""
    tpl = "<h1>SQL error</h1>\n<pre>{msg}</pre>\n<a>Back</a>"
    ok = html(500, tpl.format(msg="Divide by zero error encountered."))
    err = html(500, tpl.format(msg="Conversion failed converting varchar 'a' to int."))
    clf = BaselineClassifier(ok, err)
    assert clf.classify(ok).verdict is Verdict.OK
    assert clf.classify(err).verdict is Verdict.ERROR


def test_baseline_dynamic_error_same_length_is_unknown():
    """When the FALSE error string is dynamic (per-request token) and the bodies
    share a length, the calibrated marker no longer matches and the classifier
    cannot decide -> UNKNOWN (which the oracle then retries), never a wrong OK."""
    n = 120
    pad = lambda s: s.ljust(n, ".")[:n]
    ok = html(500, pad("SQL error: divide by zero encountered"))
    err = html(500, pad("SQL error: conversion failed token=00000001 end"))
    clf = BaselineClassifier(ok, err)
    later_false = html(500, pad("SQL error: conversion failed token=00000002 end"))
    decision = clf.classify(later_false)
    assert decision.verdict is Verdict.UNKNOWN


def test_signature_classifier_both_error_with_dynamic_noise():
    """Recommended config when both branches error: explicit body signatures
    (no status rule) classify deterministically despite dynamic surrounding
    text."""
    cfg = ClassifierConfig(
        error_body_signatures=["Conversion failed"],
        ok_body_signatures=["Divide by zero"],
        auto_calibrate=False,
    )
    clf = from_config(cfg)
    assert clf is not None
    assert clf.classify(html(500, "x Conversion failed token=91733 y")).verdict is Verdict.ERROR
    assert clf.classify(html(500, "x Divide by zero at 12:00:01 y")).verdict is Verdict.OK


# --- reflection removal (payload echoed in the body) ------------------------

def test_strip_reflection_removes_raw_and_encoded():
    from blindsqli.classifier import strip_reflection
    body = "q=abc'--x and encoded q%3Dabc%27--"
    out = strip_reflection(body, "abc'--")
    assert "abc'--" not in out
    assert "abc%27--" not in out


def test_baseline_length_survives_payload_echo():
    # Both 500; the body echoes the sent payload, so raw length tracks payload
    # size. With reflection removal the true/false length signal is recovered.
    ok = html(500, "OK" + "P" * 3)          # ok base "OK", cal payload "PPP"
    err = html(500, "ERRERR" + "P" * 3)     # error base is longer
    clf = BaselineClassifier(ok, err, ok_sent="P" * 3, error_sent="P" * 3)
    long_sent = "Q" * 60                     # a much longer extraction payload
    assert clf.classify(html(500, "OK" + long_sent), sent=long_sent).verdict is Verdict.OK
    assert clf.classify(html(500, "ERRERR" + long_sent), sent=long_sent).verdict is Verdict.ERROR


def test_baseline_single_line_json_shared_prefix():
    # Single-line JSON bodies (both HTTP 500) that share a long identical prefix
    # and differ only later. The old marker logic returned the shared prefix and
    # matched every response as ERROR; the fix must classify by the real diff.
    prefix = '{"cause":null,"stackTrace":[],"businessError":"B","application":"svc",'
    ok = html(500, prefix + '"detail":"OK_LONGER_RESULT_PADDING"}')   # TRUE, longer
    err = html(500, prefix + '"detail":"FAIL"}')                       # FALSE, shorter
    clf = BaselineClassifier(ok, err)
    # a genuine TRUE response must not be stamped ERROR by a shared-prefix marker
    assert clf.classify(html(500, prefix + '"detail":"OK_LONGER_RESULT_PADDING"}')).verdict is Verdict.OK
    assert clf.classify(html(500, prefix + '"detail":"FAIL"}')).verdict is Verdict.ERROR


def test_diff_marker_never_returns_shared_prefix():
    a = "COMMONPREFIX_that_is_quite_long___AAA_tail"
    b = "COMMONPREFIX_that_is_quite_long___BBB_tail"
    m = BaselineClassifier._diff_marker(a, b)
    assert m is not None and m not in b   # exclusive to a
    assert "AAA" in m
