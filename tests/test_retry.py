"""HTTP-client-level retry, backoff and error-translation tests.

Requires `requests` (for its exception classes); skipped otherwise. Oracle-level
retry/ambiguity behaviour is covered in test_oracle.py without requests.
"""

import pytest

requests = pytest.importorskip("requests")

from blindsqli.config import Config
from blindsqli.http_client import HttpClient, RequestError, TimeoutError_


class FakeResp:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text
        self.headers = {"Content-Type": "text/html"}
        self.url = "http://localhost:3000/"


def make_client(**over):
    cfg = Config(target_url="http://localhost:3000/", retry_backoff=0.0, **over)
    return HttpClient(cfg)


def test_retries_then_raises_timeout(monkeypatch):
    client = make_client(max_retries=3)
    calls = {"n": 0}

    class S:
        def request(self, method, url, *a, **k):
            calls["n"] += 1
            raise requests.exceptions.Timeout("t")

    monkeypatch.setattr(client, "_session", lambda: S())
    with pytest.raises(TimeoutError_):
        client.send("x")
    assert calls["n"] == 3


def test_retries_then_raises_request_error(monkeypatch):
    client = make_client(max_retries=2)

    class S:
        def request(self, method, url, *a, **k):
            raise requests.exceptions.ConnectionError("reset")

    monkeypatch.setattr(client, "_session", lambda: S())
    with pytest.raises(RequestError):
        client.send("x")


def test_recovers_after_transient_failure(monkeypatch):
    client = make_client(max_retries=3)
    state = {"n": 0}

    class S:
        def request(self, method, url, *a, **k):
            state["n"] += 1
            if state["n"] < 2:
                raise requests.exceptions.ConnectionError("reset")
            return FakeResp(200, "recovered")

    monkeypatch.setattr(client, "_session", lambda: S())
    resp = client.send("x")
    assert resp.status == 200 and resp.body == "recovered"


def test_5xx_not_retried(monkeypatch):
    # A 500 may itself be the FALSE signal, so it must be returned, not retried.
    client = make_client(max_retries=3)
    calls = {"n": 0}

    class S:
        def request(self, method, url, *a, **k):
            calls["n"] += 1
            return FakeResp(500, "error page")

    monkeypatch.setattr(client, "_session", lambda: S())
    resp = client.send("x")
    assert resp.status == 500
    assert calls["n"] == 1
