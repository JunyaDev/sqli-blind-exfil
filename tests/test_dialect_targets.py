from blindsqli.dialect import get_dialect, MSSQLDialect
from blindsqli.targets import Target, first_table_name


def make_target():
    d = get_dialect("mssql")
    return Target("T", "(SELECT TOP(1) TABLE_NAME FROM INFORMATION_SCHEMA.TABLES)", d)


def test_char_is_condition():
    t = make_target()
    cond = t.char_is(4, "u")
    assert "SUBSTRING(" in cond and ",4,1)" in cond and "= 'u'" in cond


def test_char_le_condition():
    t = make_target()
    assert "<= 'm'" in t.char_le(1, "m")


def test_substring_is_sequence():
    t = make_target()
    cond = t.substring_is(1, "jun_")
    assert ",1,4)" in cond and "= 'jun_'" in cond


def test_prefix_like_escapes_wildcards():
    t = make_target()
    cond = t.starts_with("jun_%")
    # % and _ must be escaped so they match literally
    assert "\\_" in cond and "\\%" in cond and "ESCAPE '\\'" in cond


def test_quote_escapes_single_quote():
    d = MSSQLDialect()
    assert d.quote_str("o'brien") == "'o''brien'"


def test_length_conditions():
    t = make_target()
    assert t.length_is(9).endswith("= 9")
    assert t.length_le(9).endswith("<= 9")
    assert t.length_ge(9).endswith(">= 9")


def test_first_table_name_factory():
    t = first_table_name(get_dialect("mssql"))
    assert "INFORMATION_SCHEMA.TABLES" in t.expression
    assert t.name.startswith("TABLE_NAME")


from blindsqli.targets import nth_database_name, first_column_name, _catalog_prefix


def test_first_table_name_database_scope():
    t = first_table_name(get_dialect("mssql"), database="appdb")
    assert "[appdb].INFORMATION_SCHEMA.TABLES" in t.expression


def test_nth_database_name_uses_sys_databases():
    assert "sys.databases" in nth_database_name(get_dialect("mssql"), 0).expression
    assert "OFFSET 2 ROWS" in nth_database_name(get_dialect("mssql"), 2).expression


def test_column_name_database_scope():
    t = first_column_name(get_dialect("mssql"), "jun_users", offset=1, database="appdb")
    assert "[appdb].INFORMATION_SCHEMA.COLUMNS" in t.expression


def test_catalog_prefix_escapes_bracket():
    assert _catalog_prefix("a]b") == "[a]]b]."
    assert _catalog_prefix(None) == ""
