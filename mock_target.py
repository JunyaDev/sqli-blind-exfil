"""A local mock of the vulnerable training application.

It reproduces the *observable behaviour* the real lab exhibits for the CASE
type-confusion technique, so the tool, its tests and its demos can run without
the real service:

  * a request whose injected CASE condition is TRUE  -> HTTP 200 normal page;
  * a request whose injected CASE condition is FALSE -> HTTP 500 with a SQL
    "Conversion failed ... to data type int" error and a different body length.

The mock parses the specific condition shapes the tool emits (numeric equality,
LEN, SUBSTRING = , SUBSTRING <= , LIKE prefix) and evaluates them against a
single secret scalar (default: the "first table name"). It binds loopback only.

Run standalone:   python mock_target.py --port 3000 --secret jun_users
"""

from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlparse


def _json_string_values(obj):
    """All string values anywhere inside a JSON structure."""
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out += _json_string_values(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _json_string_values(v)
    elif isinstance(obj, str):
        out.append(obj)
    return out


def _dig(data, dotted):
    """Fetch a value from nested dicts by a dotted path; '' if absent."""
    cur = data
    for key in dotted.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return ""
    return cur if isinstance(cur, str) else ""

# --- condition patterns (match what blindsqli.dialect emits) ----------------
_RE_NUM_EQ = re.compile(r"^\s*(\d+)\s*=\s*(\d+)\s*$")
_RE_LEN = re.compile(r"LEN\(.*?\)\s*(<=|>=|=)\s*(\d+)", re.IGNORECASE | re.DOTALL)
# A trailing "(... COLLATE <name>)" wrapper is optional, so the mock also
# understands the collation-forced comparisons the MSSQL dialect emits.
_COLLATE = r"(?:\s+COLLATE\s+\S+)?\s*\)?"
_RE_SUBSTR_EQ = re.compile(
    r"SUBSTRING\(.*?,\s*(\d+)\s*,\s*(\d+)\s*\)" + _COLLATE + r"\s*=\s*'((?:[^']|'')*)'",
    re.IGNORECASE | re.DOTALL,
)
_RE_SUBSTR_LE = re.compile(
    r"SUBSTRING\(.*?,\s*(\d+)\s*,\s*1\s*\)" + _COLLATE + r"\s*<=\s*'((?:[^']|'')*)'",
    re.IGNORECASE | re.DOTALL,
)
_RE_LIKE = re.compile(r"LIKE\s*'((?:[^']|'')*)'", re.IGNORECASE | re.DOTALL)
_RE_CASE = re.compile(r"CASE\s+WHEN\s*\((.*)\)\s*THEN", re.IGNORECASE | re.DOTALL)

OK_BODY = (
    "<html><body><h1>Product search</h1>"
    "<ul><li>Widget</li><li>Gadget</li><li>Sprocket</li></ul>"
    "<!-- results rendered ok --></body></html>"
)
ERROR_BODY = (
    "<html><body><h1>Server Error</h1><pre>"
    "System.Data.SqlClient.SqlException: Conversion failed when converting the "
    "varchar value 'a' to data type int.</pre></body></html>"
)


def _unquote_sql(s: str) -> str:
    return s.replace("''", "'")


def _like_prefix(pattern: str) -> str:
    """Convert a LIKE pattern (escaped, trailing %) into a literal prefix."""
    pattern = _unquote_sql(pattern)
    if pattern.endswith("%"):
        pattern = pattern[:-1]
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(pattern[i + 1])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def evaluate_condition(condition: str, secret) -> bool:
    """Evaluate one injected boolean condition against the secret scalar.

    A NULL / absent scalar is modelled as ``secret is None`` (distinct from the
    empty string ""). Any comparison against NULL is unknown, so it reads as
    not-true, exactly like the real type-confusion side channel.
    """
    condition = condition.strip()
    up = condition.upper()

    if secret is None:
        if "IS NULL" in up:
            return True
        return False  # IS NOT NULL and every LEN/SUBSTRING/LIKE probe -> not true
    if "IS NOT NULL" in up:
        return True
    if "IS NULL" in up:
        return False

    m = _RE_NUM_EQ.match(condition)
    if m:
        return int(m.group(1)) == int(m.group(2))

    m = _RE_LEN.search(condition)
    if m:
        op, n = m.group(1), int(m.group(2))
        L = len(secret)
        return {"=": L == n, "<=": L <= n, ">=": L >= n}[op]

    m = _RE_SUBSTR_EQ.search(condition)
    if m:
        pos, length, val = int(m.group(1)), int(m.group(2)), _unquote_sql(m.group(3))
        return secret[pos - 1: pos - 1 + length] == val

    m = _RE_SUBSTR_LE.search(condition)
    if m:
        pos, ch = int(m.group(1)), _unquote_sql(m.group(2))
        actual = secret[pos - 1: pos] or ""
        return actual <= ch

    m = _RE_LIKE.search(condition)
    if m:
        prefix = _like_prefix(m.group(1))
        return secret.startswith(prefix)

    # Unknown condition shape -> behave like the DB can't prove it true.
    return False


def extract_condition(injected_value: str) -> str | None:
    m = _RE_CASE.search(injected_value)
    return m.group(1) if m else None


_RE_COUNT = re.compile(r"COUNT\(\*\)", re.IGNORECASE)
_RE_COUNT_CMP = re.compile(r"(<=|>=|<|>|=)\s*(\d+)")
_RE_OFFSET = re.compile(r"OFFSET\s+(\d+)\s+ROWS", re.IGNORECASE)
# A catalog filter the tool emits for `enumerate --what tables --where ...`,
# e.g. "WHERE TABLE_NAME LIKE '%user%'". This is distinct from the prefix LIKE
# the value search wraps around the subquery, so it is matched (and stripped)
# specifically as a WHERE <col> LIKE clause before the rest runs.
_RE_WHERE_LIKE = re.compile(
    r"WHERE\s+[\w.\[\]]+\s+LIKE\s*'((?:[^']|'')*)'",
    re.IGNORECASE | re.DOTALL,
)


def _like_to_regex(pattern: str) -> "re.Pattern":
    """Compile a SQL LIKE pattern (% and _ wildcards) to an anchored regex."""
    pattern = _unquote_sql(pattern)
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if c == "%":
            out.append(".*")
        elif c == "_":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    # MSSQL's default collation is case-insensitive; mirror that for the filter.
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def evaluate_condition_multi(condition: str, secrets: list) -> bool:
    """Evaluate a condition against a *rowset*.

    Adds three things over the single-secret evaluator so the mock can serve
    enumeration: an optional ``WHERE <col> LIKE '...'`` catalog filter that
    narrows the rowset, COUNT(*) comparisons against the (filtered) row count,
    and OFFSET n row selection. Only a single LIKE predicate is simulated; a
    compound WHERE (AND/OR of several predicates) is beyond this lab mock.
    """
    rows = secrets
    m = _RE_WHERE_LIKE.search(condition)
    if m:
        rx = _like_to_regex(m.group(1))
        rows = [s for s in secrets if s is not None and rx.match(s)]
        # Drop the filter clause so any *value-search* LIKE left in the
        # condition is what the single-secret evaluator sees downstream.
        condition = condition[:m.start()] + condition[m.end():]
    if _RE_COUNT.search(condition):
        m = _RE_COUNT_CMP.search(condition)
        if not m:
            return False
        op, num, c = m.group(1), int(m.group(2)), len(rows)
        return {"<=": c <= num, ">=": c >= num, "<": c < num, ">": c > num, "=": c == num}[op]
    m = _RE_OFFSET.search(condition)
    idx = int(m.group(1)) if m else 0
    secret = rows[idx] if 0 <= idx < len(rows) else ""
    return evaluate_condition(condition, secret)


class _Handler(BaseHTTPRequestHandler):
    secrets = ["jun_users"]
    param = "q"

    def log_message(self, *args) -> None:  # silence default logging
        pass

    def _respond(self, injected: str) -> None:
        cond = extract_condition(injected or "")
        if cond is None:
            # No injection detected: behave like a normal successful request.
            self._send(200, OK_BODY)
            return
        try:
            is_true = evaluate_condition_multi(cond, self.secrets)
        except Exception:
            is_true = False
        if is_true:
            self._send(200, OK_BODY)
        else:
            self._send(500, ERROR_BODY)

    def _send(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _find_injection(self, body: str = "") -> str:
        """Location-agnostic: return the first value (from query string, cookies
        or body) that contains an injected CASE condition. This lets the mock
        serve query, form, JSON and cookie injection points without being told
        which one is in play."""
        values = []
        # query string
        values += [v for _, v in parse_qsl(urlparse(self.path).query, keep_blank_values=True)]
        # cookies
        cookie_header = self.headers.get("Cookie", "") or ""
        for part in cookie_header.split(";"):
            if "=" in part:
                values.append(part.split("=", 1)[1].strip())
        # body
        if body:
            ctype = (self.headers.get("Content-Type", "") or "").lower()
            if "application/json" in ctype:
                try:
                    values += _json_string_values(json.loads(body))
                except ValueError:
                    pass
            else:
                values += [v for _, v in parse_qsl(body, keep_blank_values=True)]
        for v in values:
            if extract_condition(v) is not None:
                return v
        return ""

    def do_GET(self) -> None:
        self._respond(self._find_injection())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode(errors="replace")
        self._respond(self._find_injection(body))

    # PUT/PATCH behave like POST for the lab (JSON APIs often use them).
    do_PUT = do_POST
    do_PATCH = do_POST


class MockTarget:
    """Context-managed background mock server bound to loopback."""

    def __init__(self, secret: str = "jun_users", param: str = "q", port: int = 0,
                 secrets: list = None) -> None:
        # `secrets` (a list, in ORDER BY order) enables enumeration via COUNT and
        # OFFSET; `secret` remains for the single-value case.
        rows = list(secrets) if secrets is not None else [secret]
        handler = type("Handler", (_Handler,), {"secrets": rows, "param": param})
        self.server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def start(self) -> "MockTarget":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> "MockTarget":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description="Local mock SQLi training target")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--secret", default="jun_users", help="the scalar the injection extracts")
    ap.add_argument("--secrets",
                    help="comma-separated rowset (in ORDER BY order) for enumeration, "
                         "e.g. table names: 'accounts,jun_users,products,user_sessions'. "
                         "Overrides --secret when given.")
    ap.add_argument("--param", default="q")
    args = ap.parse_args()
    rows = None
    if args.secrets:
        rows = [s.strip() for s in args.secrets.split(",") if s.strip()]
    srv = MockTarget(secret=args.secret, param=args.param, port=args.port, secrets=rows)
    srv.start()
    shown = rows if rows is not None else args.secret
    print(f"mock target on {srv.url} (param={args.param}, secret(s)={shown!r})")
    try:
        srv.thread.join()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
