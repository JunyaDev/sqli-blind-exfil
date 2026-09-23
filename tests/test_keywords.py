"""Tests for keyword-file parsing."""

from __future__ import annotations

from blindsqli.keywords import Keyword, parse_keyword_line, parse_keywords


def test_comments_and_blank_lines_ignored():
    text = """
    # a comment
    admin

    alice@example.com
    # trailing comment
    """
    kws = parse_keywords(text, tags_from_headings=False)
    assert [k.value for k in kws] == ["admin", "alice@example.com"]


def test_headings_become_tags():
    text = """
    # Accounts
    admin
    alice@example.com

    # Business data
    invoice
    customer
    """
    kws = parse_keywords(text)
    tags = {k.value: k.tag for k in kws}
    assert tags["admin"] == "Accounts"
    assert tags["alice@example.com"] == "Accounts"
    assert tags["invoice"] == "Business data"
    assert tags["customer"] == "Business data"


def test_per_keyword_options():
    kw = parse_keyword_line("invoice ;; exact, cs, tag=crm")
    assert kw == Keyword("invoice", exact=True, case_sensitive=True, tag="crm")


def test_directive_sets_defaults():
    text = """
    #! mode=exact case=sensitive tag=Infra
    internal
    project-x ;; ci
    """
    kws = {k.value: k for k in parse_keywords(text)}
    assert kws["internal"].exact and kws["internal"].case_sensitive
    assert kws["internal"].tag == "Infra"
    # per-keyword option overrides the directive default
    assert kws["project-x"].case_sensitive is False
    assert kws["project-x"].exact is True  # still exact from the directive


def test_dedup_keeps_distinct_modes():
    text = """
    admin
    admin
    admin ;; exact
    """
    kws = parse_keywords(text)
    modes = sorted((k.value, k.exact) for k in kws)
    assert modes == [("admin", False), ("admin", True)]


def test_values_with_spaces_preserved():
    kw = parse_keyword_line("project x ;; tag=code")
    assert kw.value == "project x"
    assert kw.tag == "code"


def test_load_from_file(tmp_path):
    from blindsqli.keywords import load_keywords
    p = tmp_path / "keywords.txt"
    p.write_text("# Accounts\nadmin\nalice@example.com\n")
    kws = load_keywords(str(p))
    assert [k.value for k in kws] == ["admin", "alice@example.com"]
    assert all(k.tag == "Accounts" for k in kws)
