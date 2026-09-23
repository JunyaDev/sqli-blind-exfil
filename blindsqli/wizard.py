"""Interactive setup and exploration wizard.

The tool has grown many operations and filters. The wizard guides an assessment
through the natural workflow instead of asking the operator to remember flag
syntax::

    discover databases -> filter -> discover tables -> filter ->
    discover columns -> filter -> extract rows

and the value-search workflow::

    load keywords -> discover/reuse metadata -> rank -> confirm -> locate.

It remembers what has been discovered (a shared
:class:`~blindsqli.metadata.MetadataIndex`) and what the operator has selected,
and offers the logical next steps for the current state. Every operation it runs
is one already covered by the tested engine/search modules -- the wizard only
sequences them and explains the choices. I/O goes through injected ``prompt``
and ``out`` callables so the flow can be driven in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .config import PRINTABLE_CHARSET
from .dialect import SqlDialect
from .discovery import MetadataDiscoverer
from .keywords import Keyword, load_keywords, parse_keyword_line
from .metadata import MetadataIndex
from .results import MatchStatus, SearchResults
from .search import KeywordSearchEngine, estimate_scope


@dataclass
class WizardState:
    """What the operator has discovered and selected so far."""

    selected_databases: List[str] = field(default_factory=list)
    selected_table: Optional[Tuple[Optional[str], str]] = None  # (database, table)
    selected_columns: List[str] = field(default_factory=list)
    keywords: List[Keyword] = field(default_factory=list)

    @property
    def database(self) -> Optional[str]:
        if self.selected_table:
            return self.selected_table[0]
        return self.selected_databases[0] if self.selected_databases else None


# Top-level menu (mirrors the requested "What would you like to do?" list).
_MENU = [
    ("1", "Discover databases"),
    ("2", "Discover tables"),
    ("3", "Discover columns"),
    ("4", "Extract a specific object"),
    ("5", "Search for known values"),
    ("6", "Load a keyword file"),
    ("7", "Review previous discoveries"),
    ("8", "Estimate search scope / cost"),
    ("9", "Save session (metadata + results)"),
    ("0", "Quit"),
]


class Wizard:
    def __init__(self, cfg, engine, dialect: SqlDialect,
                 prompt: Callable[[str], str] = input,
                 out: Callable[[str], None] = print,
                 index: Optional[MetadataIndex] = None,
                 results: Optional[SearchResults] = None,
                 meta_file: Optional[str] = None,
                 results_file: Optional[str] = None) -> None:
        self.cfg = cfg
        self.engine = engine
        self.dialect = dialect
        self._prompt = prompt
        self._out = out
        self.index = index or MetadataIndex()
        self.results = results or SearchResults()
        self.meta_file = meta_file
        self.results_file = results_file
        self.state = WizardState()
        self.discoverer = MetadataDiscoverer(engine, dialect, self.index)
        self.search_engine = KeywordSearchEngine(
            engine, dialect, self.index, results=self.results,
            workers=getattr(cfg, "workers", 1))

    # -- small I/O helpers --------------------------------------------------
    def _ask(self, msg: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        try:
            ans = self._prompt(f"{msg}{suffix}: ").strip()
        except EOFError:
            return default
        return ans or default

    def _choose_from(self, title: str, items: List[str]) -> List[str]:
        """Show a numbered list and let the operator pick by index, by a LIKE
        pattern, or 'all'. Returns the chosen subset (possibly all)."""
        if not items:
            self._out("  (nothing to choose from yet)")
            return []
        self._out(title)
        for i, item in enumerate(items):
            self._out(f"  [{i}] {item}")
        raw = self._ask("Select index(es) comma-separated, a LIKE pattern (e.g. %user%), "
                        "or 'all'", "all")
        if raw.lower() == "all":
            return list(items)
        if any(ch in raw for ch in "%_"):
            pat = raw.replace("%", ".*").replace("_", ".")
            import re
            rx = re.compile("^" + pat + "$", re.IGNORECASE)
            return [it for it in items if rx.match(it)]
        picked = []
        for tok in raw.split(","):
            tok = tok.strip()
            if tok.isdigit() and 0 <= int(tok) < len(items):
                picked.append(items[int(tok)])
            elif tok in items:
                picked.append(tok)
        if not picked:
            # The operator typed something that matched nothing (e.g. an
            # out-of-range index). Select nothing rather than silently selecting
            # everything, which would be an expensive surprise.
            self._out(f"No valid selection in {raw!r}; nothing selected "
                      f"(type 'all' to select everything).")
        return picked

    # -- menu ---------------------------------------------------------------
    def menu_options(self) -> List[Tuple[str, str]]:
        return list(_MENU)

    def _print_menu(self) -> None:
        self._out("\nWhat would you like to do?")
        for key, label in self.menu_options():
            self._out(f"  {key}. {label}")

    def run(self) -> int:
        """Interactive loop. Returns 0 on a clean quit."""
        handlers = {
            "1": self.discover_databases,
            "2": self.discover_tables,
            "3": self.discover_columns,
            "4": self.extract_object,
            "5": self.search_values,
            "6": self.load_keyword_file,
            "7": self.review,
            "8": self.estimate,
            "9": self.save_session,
        }
        while True:
            self._print_menu()
            choice = self._ask("Choose")
            if choice in ("0", "q", "quit", "exit", ""):
                self._out("Bye.")
                return 0
            handler = handlers.get(choice)
            if handler is None:
                self._out("Unknown choice.")
                continue
            try:
                handler()
            except KeyboardInterrupt:
                self._out("\n(interrupted; back to menu)")

    # -- handlers -----------------------------------------------------------
    def discover_databases(self) -> None:
        self._out("Discovering databases (read-only enumeration)...")
        names = self.discoverer.discover_databases()
        self._out(f"Found {len(names)} databases.")
        chosen = self._choose_from("Databases:", names)
        if chosen:
            self.state.selected_databases = chosen
            self._out(f"Selected: {', '.join(chosen)}")
            self._out("Next: choose 2 to discover tables in the selected databases.")

    def discover_tables(self) -> None:
        dbs = self.state.selected_databases or [self.state.database or ""]
        where = self._like_where("TABLE_NAME")
        for db in dbs:
            self._out(f"Discovering tables in {db or 'current DB'}...")
            tables = self.discoverer.discover_tables(db or None, where=where)
            self._out(f"  {len(tables)} tables.")
        all_tables = [f"{d or ''}{'.' if d else ''}{t.name}"
                      for d, t in self.index.iter_tables(dbs or None)]
        chosen = self._choose_from("Tables:", all_tables)
        if len(chosen) == 1:
            db, _, name = chosen[0].rpartition(".")
            self.state.selected_table = (db or None, name)
            self._out(f"Selected table {chosen[0]}. Next: 3 to discover its columns.")

    def discover_columns(self) -> None:
        if not self.state.selected_table:
            self._out("Select a single table first (option 2).")
            return
        db, table = self.state.selected_table
        self._out(f"Discovering columns of {table}...")
        cols = self.discoverer.discover_columns(db, table)
        names = [c.name for c in cols]
        self._out(f"  {len(names)} columns: {', '.join(names)}")
        chosen = self._choose_from("Columns:", names)
        if chosen:
            self.state.selected_columns = chosen
            self._out(f"Selected columns: {', '.join(chosen)}. "
                      f"Next: 4 to extract rows from this table.")

    def extract_object(self) -> None:
        if not self.state.selected_table:
            self._out("Select a table (option 2) and columns (option 3) first.")
            return
        db, table = self.state.selected_table
        cols = self.state.selected_columns or [c.name for c in
                                               self.discoverer.discover_columns(db, table)]
        where = self._ask("Optional WHERE filter (blank for none)")
        limit = self._ask("Row limit (0 = all)", "0")
        verify = self._ask("Verify each value exists before extracting "
                           "(skips NULL cells cheaply)? (Y/n)", "y")
        self.cfg.verify_exists = not verify.lower().startswith("n")
        from . import targets as targets_mod
        # Widen charset for real data values. The engine snapshots its charset
        # at construction, so this must go through set_charset() -- mutating
        # cfg.charset alone would not reach the already-built engine.
        if self.cfg.charset != PRINTABLE_CHARSET:
            self.engine.set_charset(PRINTABLE_CHARSET)
        count_expr = targets_mod.row_count_expr(db, "dbo", table, where=where or None)
        total = self.engine.discover_count(count_expr)
        if total is None:
            self._out("Could not determine the row count.")
            return
        if limit.isdigit() and int(limit) > 0:
            total = min(total, int(limit))
        self._out(f"Extracting {total} row(s) of {', '.join(cols)}...")
        for i in range(total):
            if self.engine.cancelled():
                break
            tgt = targets_mod.row_value(self.dialect, table, cols, offset=i,
                                        database=db, schema="dbo",
                                        where=where or None)
            res = self.engine.extract(tgt)
            if res.missing:
                self._out(f"  [{i}] <NULL> (skipped)")
            else:
                self._out(f"  [{i}] {res.value!r}{'' if res.complete else ' (partial)'}")

    def load_keyword_file(self) -> None:
        path = self._ask("Keyword file path", "keywords.txt")
        try:
            kws = load_keywords(path)
        except OSError as exc:
            self._out(f"Could not read {path}: {exc}")
            return
        self.state.keywords = kws
        self._out(f"Loaded {len(kws)} keywords.")
        tags = sorted({k.tag for k in kws if k.tag})
        if tags:
            self._out(f"Categories: {', '.join(tags)}")

    def search_values(self) -> None:
        if not self.state.keywords:
            mode = self._ask("Search one value or multiple? (single/file)", "single")
            if mode.startswith("f"):
                self.load_keyword_file()
            else:
                val = self._ask("Value to search for")
                if not val:
                    return
                self.state.keywords = [parse_keyword_line(val)]
        kws = self.state.keywords
        if not kws:
            return
        scope = self._ask("Search scope: all databases or selected? (all/selected)", "all")
        databases = None
        if scope.startswith("s") and self.state.selected_databases:
            databases = self.state.selected_databases
        # ensure metadata exists to search
        if self.index.counts(databases)["columns"] == 0:
            self._out("No metadata cached yet; discovering scope first...")
            self.discoverer.discover_all_columns(databases=databases)
        cap = self._ask("Max candidate columns per keyword (heuristic cap)", "50")
        cap_n = int(cap) if cap.isdigit() else 50
        est = estimate_scope(self.index, len(kws), cap_n, databases)
        self._out(est.render())
        if est.level in ("HIGH", "VERY HIGH"):
            if not self._ask("This may be expensive. Proceed? (y/N)", "n").lower().startswith("y"):
                self._out("Cancelled.")
                return
        self._out("Searching (ranked candidates, confirmed via the boolean oracle)...")
        self.search_engine.search(kws, databases=databases, max_candidates=cap_n)
        self._report_matches()

    def review(self) -> None:
        counts = self.index.counts()
        self._out(f"Known scope: {counts['databases']} databases, "
                  f"{counts['tables']} tables, {counts['columns']} columns.")
        self._report_matches()

    def estimate(self) -> None:
        n = len(self.state.keywords) or 1
        cap = self._ask("Candidate cap per keyword", "50")
        cap_n = int(cap) if cap.isdigit() else 50
        self._out(estimate_scope(self.index, n, cap_n).render())

    def save_session(self) -> None:
        if self.meta_file:
            self.index.save(self.meta_file)
            self._out(f"Saved metadata index to {self.meta_file}")
        if self.results_file:
            self.results.save(self.results_file)
            self._out(f"Saved search results to {self.results_file}")
        if not (self.meta_file or self.results_file):
            self._out("No --meta-file / --results-file configured; nothing saved.")

    # -- shared ------------------------------------------------------------
    def _like_where(self, column: str) -> Optional[str]:
        pat = self._ask(f"Optional LIKE pattern on {column} (e.g. %user%, blank for none)")
        if not pat:
            return None
        lit = self.dialect.like_literal(pat.strip("%"))
        return f"{column} LIKE {lit}"

    def _report_matches(self) -> None:
        if not self.results.all():
            self._out("No matches recorded yet.")
            return
        self._out("\nResults by keyword:")
        for kw in self.results.keywords():
            self._out(f"  {kw}")
            for m in self.results.for_keyword(kw):
                mark = {MatchStatus.CONFIRMED: "CONFIRMED",
                        MatchStatus.PROBABLE: "probable",
                        MatchStatus.ABSENT: "absent",
                        MatchStatus.CANDIDATE: "candidate"}[m.status]
                if m.status.is_positive:
                    self._out(f"    -> {m.location}  [{mark}] conf={m.confidence:.2f}")
