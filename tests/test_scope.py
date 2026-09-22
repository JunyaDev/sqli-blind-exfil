import pytest

from blindsqli.scope import ScopeError, enforce, is_local_host


def test_localhost_variants_allowed():
    for url in ["http://localhost:3000/", "http://127.0.0.1:3000/", "http://[::1]:3000/"]:
        enforce(url)  # should not raise


def test_external_host_refused():
    with pytest.raises(ScopeError):
        enforce("http://example.com/")


def test_external_ip_refused():
    with pytest.raises(ScopeError):
        enforce("http://8.8.8.8/")


def test_opt_in_bypass():
    enforce("http://example.com/", allow_nonlocal=True)  # explicit opt-in


def test_is_local_host():
    assert is_local_host("localhost")
    assert is_local_host("127.0.0.1")
    assert not is_local_host("example.com")
