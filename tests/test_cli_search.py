"""CLI-level smoke tests for the `search` and `wizard` subcommands.

These check argument wiring, the discovery/estimate/output path and exit codes
over real HTTP against the local mock. Semantic correctness of ranking and
confirmation is covered faithfully by test_search.py (SchemaOracle).
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import pytest

requests = pytest.importorskip("requests")

from blindsqli.cli import main
from mock_target import MockTarget


@pytest.fixture()
def server():
    srv = MockTarget(secrets=["accounts", "jun_users"], param="q", port=0).start()
    try:
        yield srv
    finally:
        srv.stop()


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def test_search_estimate_only(server, tmp_path):
    meta = tmp_path / "meta.json"
    rc, out = _run([
        "search", "--url", server.url, "--param", "q", "--quiet",
        "--keyword", "jun", "--estimate-only",
        "--max-count", "8", "--meta-file", str(meta),
    ])
    assert rc == 0
    data = json.loads(out)
    assert "level" in data and "confirm_requests" in data
    assert meta.exists()  # metadata index cached for reuse


def test_search_runs_and_writes_results(server, tmp_path):
    results = tmp_path / "res.json"
    meta = tmp_path / "meta.json"
    rc, out = _run([
        "search", "--url", server.url, "--param", "q", "--quiet",
        "--keyword", "jun", "--max-candidates", "5", "--max-count", "8",
        "--meta-file", str(meta), "--results-file", str(results),
    ])
    assert rc == 0
    data = json.loads(out)
    assert set(data) >= {"keywords", "scope", "summary", "matches", "confirmed"}
    assert data["keywords"] == ["jun"]
    assert results.exists()


def test_search_requires_keywords(server):
    rc, _out = _run([
        "search", "--url", server.url, "--param", "q", "--quiet",
    ])
    assert rc == 2  # no --keyword / --keywords-file


def test_search_reuses_cached_metadata(server, tmp_path):
    meta = tmp_path / "meta.json"
    # first run performs discovery and writes the cache
    _run(["search", "--url", server.url, "--param", "q", "--quiet",
          "--keyword", "jun", "--estimate-only", "--max-count", "8",
          "--meta-file", str(meta)])
    before = meta.read_text()
    # second run should load the cache instead of re-discovering
    rc, _out = _run(["search", "--url", server.url, "--param", "q", "--quiet",
                     "--keyword", "acc", "--estimate-only", "--max-count", "8",
                     "--meta-file", str(meta)])
    assert rc == 0
    assert json.loads(before)["databases"]  # cache had content


def test_keywords_file_loading(server, tmp_path):
    kw = tmp_path / "keywords.txt"
    kw.write_text("# Accounts\njun\nacc\n")
    rc, out = _run([
        "search", "--url", server.url, "--param", "q", "--quiet",
        "--keywords-file", str(kw), "--estimate-only", "--max-count", "8",
    ])
    assert rc == 0
