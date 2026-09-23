"""Tests for the interactive wizard, driven by scripted input."""

from __future__ import annotations

from blindsqli.config import Config, PRINTABLE_CHARSET
from blindsqli.dialect import get_dialect
from blindsqli.engine import ExfiltrationEngine
from blindsqli.keywords import Keyword
from blindsqli.results import MatchStatus
from blindsqli.wizard import Wizard, WizardState

from tests.fakes import SchemaOracle

SCHEMA = {
    "appdb": {
        "accounts": {"username": ["admin"], "password": ["h1"]},
        "projects": {"project_code": ["project-x"]},
    },
    "billing": {
        "customers": {"email": ["alice@example.com"]},
    },
}


class ScriptedPrompt:
    """Returns queued answers; raises EOFError (-> default) when exhausted."""

    def __init__(self, answers):
        self.answers = list(answers)

    def __call__(self, _msg):
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


def _wizard(answers, keywords=None):
    cfg = Config()
    cfg.charset = PRINTABLE_CHARSET
    cfg.verbosity = 0
    cfg.workers = 2
    engine = ExfiltrationEngine(cfg, SchemaOracle(SCHEMA, current_db="appdb"))
    out_lines = []
    wiz = Wizard(cfg, engine, get_dialect("mssql"),
                 prompt=ScriptedPrompt(answers), out=out_lines.append)
    if keywords:
        wiz.state.keywords = keywords
    return wiz, out_lines


def test_menu_options_complete():
    wiz, _ = _wizard([])
    keys = [k for k, _ in wiz.menu_options()]
    assert keys == ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]


def test_run_discovers_then_quits():
    wiz, out = _wizard(["1", "all", "0"])
    rc = wiz.run()
    assert rc == 0
    assert set(wiz.index.database_names()) == {"appdb", "billing"}
    assert wiz.state.selected_databases == ["appdb", "billing"]


def test_wizard_search_confirms_location():
    # keywords preloaded; scope=all, cap=50 (LOW cost -> no proceed prompt)
    wiz, out = _wizard(["all", "50"], keywords=[Keyword("admin")])
    wiz.search_values()
    confirmed = [m for m in wiz.results.for_keyword("admin")
                 if m.status == MatchStatus.CONFIRMED]
    assert confirmed and confirmed[0].location == "appdb.dbo.accounts.username"


def test_wizard_progressive_selection_state():
    wiz, out = _wizard(["all"])  # discover + select all databases
    wiz.discover_databases()
    assert wiz.state.selected_databases
    # discover tables in the selected databases, pick a single one by index
    wiz._prompt = ScriptedPrompt(["", "0"])  # no LIKE filter, pick table [0]
    wiz.discover_tables()
    assert wiz.state.selected_table is not None


def test_wizard_save_session(tmp_path):
    meta = tmp_path / "meta.json"
    res = tmp_path / "res.json"
    wiz, out = _wizard(["all", "50"], keywords=[Keyword("admin")])
    wiz.meta_file = str(meta)
    wiz.results_file = str(res)
    wiz.search_values()
    wiz.save_session()
    assert meta.exists() and res.exists()
