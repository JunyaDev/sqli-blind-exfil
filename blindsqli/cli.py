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
import sys
from typing import Optional

from . import __version__
from .config import Config
from .dialect import get_dialect
from .engine import ExfiltrationEngine
from .logging_util import Logger
from .oracle import BooleanOracle, CalibrationError
from .predictor import CharacterPredictor
from .reporting import NullReporter, TerminalReporter
from .scope import ScopeError
from . import targets as targets_mod


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

    ex = sub.add_parser("extract", help="extract a target value")
    add_common(ex)
    ex.add_argument("--charset", dest="charset")
    ex.add_argument("--max-length", dest="max_length", type=int)
    ex.add_argument("--strategy", dest="strategy", choices=["adaptive", "linear", "binary"])
    ex.add_argument("--no-length", dest="discover_length", action="store_false", default=None)
    ex.add_argument("--target-name", dest="target_name")
    ex.add_argument("--expr", dest="target_expression",
                    help="scalar SQL subquery to exfiltrate")
    ex.add_argument("--preset", choices=["first-table", "db-name"],
                    help="use a built-in target instead of --expr")
    ex.add_argument("--output", dest="output_file")

    cal = sub.add_parser("calibrate", help="probe target and show true/false fingerprints")
    add_common(cal)

    sub.add_parser("version", help="print version")
    return p


def _apply_overrides(cfg: Config, args: argparse.Namespace) -> Config:
    fields = [
        "target_url", "http_method", "injection_param", "base_payload",
        "request_timeout", "max_retries", "workers", "dialect", "charset",
        "max_length", "strategy", "discover_length", "target_name",
        "target_expression", "output_file", "allow_nonlocal",
        "proxy", "proxy_insecure", "body_mode", "body_template", "content_type",
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


def _build_target(cfg: Config, args: argparse.Namespace):
    dialect = get_dialect(cfg.dialect)
    preset = getattr(args, "preset", None)
    if preset == "first-table":
        return targets_mod.first_table_name(dialect)
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


def cmd_extract(cfg: Config, args: argparse.Namespace, logger: Logger) -> int:
    reporter = NullReporter() if cfg.verbosity == 0 else TerminalReporter(verbosity=cfg.verbosity)
    oracle = BooleanOracle(cfg, logger=logger)
    predictor = CharacterPredictor(cfg.charset, order=cfg.predictor_order)
    engine = ExfiltrationEngine(cfg, oracle, char_predictor=predictor,
                                logger=logger, reporter=reporter)
    target = _build_target(cfg, args)
    logger.info(f"Extracting {target.name} from {cfg.target_url}")
    logger.verbose(f"target expression: {target.expression}")
    try:
        result = engine.extract(target)
    except CalibrationError as exc:
        logger.error(f"calibration failed: {exc}")
        return 2

    out = result.to_dict()
    with open(cfg.output_file, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    logger.info(f"wrote {cfg.output_file}")
    print(json.dumps(out, indent=2))
    return 0 if result.complete else 1


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
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 3
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
