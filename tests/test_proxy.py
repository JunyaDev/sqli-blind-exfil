"""Proxy option tests.

Verify the HTTP session is configured for an intercepting proxy, and that the
explicit proxy is not silently bypassed for loopback targets. Requires
`requests` (a real Session is inspected); skipped otherwise.
"""

import pytest

requests = pytest.importorskip("requests")

from blindsqli.config import Config
from blindsqli.http_client import HttpClient


def _session(**over):
    cfg = Config(target_url="http://localhost:3000/", **over)
    return HttpClient(cfg)._session()


def test_no_proxy_leaves_session_default():
    sess = _session()
    assert not sess.proxies          # empty -> direct connection
    assert sess.trust_env is True    # default requests behaviour untouched


def test_proxy_configures_session():
    sess = _session(proxy="http://127.0.0.1:8080")
    assert sess.proxies == {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }
    # explicit proxy must win over env and not be bypassed for localhost
    assert sess.trust_env is False
    assert sess.verify is True       # verification on unless explicitly insecure


def test_proxy_insecure_disables_verify():
    sess = _session(proxy="http://127.0.0.1:8080", proxy_insecure=True)
    assert sess.verify is False


def test_proxy_insecure_ignored_without_proxy():
    # proxy_insecure alone (no proxy) should not weaken a direct connection
    sess = _session(proxy_insecure=True)
    assert not sess.proxies
    assert sess.verify is True
