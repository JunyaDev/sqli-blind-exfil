# Architecture

The tool is a pipeline of small, independently replaceable modules. Nothing but
`result_types` is shared vocabulary; every other module depends only on the
narrow interface of the one below it.

```text
                 ┌─────────────────────────────┐
                 │      CLI / Config (cli.py,   │
                 │        config.py)            │
                 └──────────────┬──────────────┘
                                │ builds
                                ▼
   ┌────────────────┐   asks   ┌───────────────────────────┐
   │  Exfiltration  │────────► │      Boolean Oracle        │
   │  Engine        │ conditions│      (oracle.py)           │
   │  (engine.py)   │◄──────── │ TRUE/FALSE/ERROR/TIMEOUT/  │
   └───┬────────┬───┘  result  │ UNKNOWN                    │
       │        │              └───────┬───────────┬────────┘
       │ learn  │ generate             │ build      │ classify
       ▼        ▼ conditions           ▼            ▼
 ┌──────────┐ ┌───────────────┐  ┌───────────┐ ┌──────────────────┐
 │ Char +   │ │ Target/Query  │  │  Payload  │ │ Response/Error   │
 │ Sequence │ │ Definitions   │  │  Builder  │ │ Classifier       │
 │ Predict. │ │ (targets.py + │  │(payload.py)│ │ (classifier.py) │
 │(predictor│ │  dialect.py)  │  └─────┬─────┘ └──────────────────┘
 │ .py,     │ └───────────────┘        │ send            ▲
 │ sequence │                          ▼                 │ HttpResponse
 │ .py)     │                    ┌───────────────┐       │
 └──────────┘                    │  HTTP Client  │───────┘
                                 │ (http_client) │
                                 └───────────────┘
```

## Module responsibilities

| Module | Responsibility | Depends on |
|---|---|---|
| `result_types` | Shared enums/dataclasses (`OracleResult`, `Verdict`, `HttpResponse`, …) | — |
| `config` | Config model, JSON/YAML loading, validation | — |
| `scope` | Loopback allowlist enforcement | — |
| `logging_util` | Leveled, thread-safe logger | — |
| `http_client` | Timeouts, bounded retries, exception translation, per-thread sessions | config, scope, result_types |
| `dialect` | DB-specific SQL fragments (SUBSTRING/LEN/LIKE/compare) + escaping | — |
| `targets` | Turns value hypotheses into boolean SQL conditions via a dialect | dialect |
| `payload` | Substitutes a condition into the CASE payload template | — |
| `classifier` | Decides ERROR vs OK from a response (status/body/length/headers/timing; composite; auto-calibrated baseline) | config, result_types |
| `oracle` | Payload → HTTP → classify → TRUE/FALSE; retries; calibration | payload, http_client, classifier |
| `predictor` | Order-k Markov character model with backoff | — |
| `sequence` | Recurring-pattern / completion proposals + cost model | — |
| `engine` | Adaptive search, length discovery, concurrency, model updates | oracle, predictor, sequence, targets |
| `reporting` | Live terminal progress | result_types |
| `cli` | Wire everything together, I/O | all of the above |

Because dependencies point one way, you can replace, say, the `classifier`
implementation (hand-written rules ↔ auto-calibrated baseline ↔ an ML model)
without touching the engine or predictors, and swap `http_client` for an async
transport by preserving its `send()` contract.

## The oracle abstraction

```text
hypothesis  ->  Target.<method>()  ->  boolean SQL condition
            ->  PayloadBuilder     ->  injection value
            ->  HttpClient.send()  ->  HttpResponse
            ->  Classifier         ->  Verdict (OK/ERROR/UNKNOWN)
            ->  Oracle             ->  OracleResult (TRUE/FALSE/…)
```

The engine only ever calls `oracle.ask(condition)` and reads `OracleResult`. It
does not know how the true/false decision is made.

## Adaptive search strategy (engine)

For each value:

1. **Length discovery** — binary search on `LEN(expr) <= n` over `[0, max_length]`
   (≈ log₂ requests), or skip and stop at a terminator.
2. **Per position** (1-based `SUBSTRING`):
   - **Sequence phase** (adaptive only): the sequence predictor proposes
     multi-character continuations (completions of previously seen values and
     recurring prefixes). A cost model compares "verify this k-char sequence in
     one request, fall back on miss" against "k characters one at a time" and
     only tests worthwhile hypotheses. A confirmed `SUBSTRING(expr,pos,k)=seq`
     advances k positions in a single verified request. Concurrent hypotheses
     are tested in parallel; the longest confirmed one wins.
   - **Character phase**: the character predictor ranks candidates; the top few
     are tested **concurrently** as equality probes (at most one can be true).
     If prediction misses, a deterministic **binary search** over the ordered
     charset (`SUBSTRING(expr,pos,1) <= mid`) guarantees the character is found,
     followed by an equality verification.
3. **Verification** — every accepted character/sequence is confirmed through the
   oracle. Predictions are only hypotheses.
4. **Learning** — both predictors update from each confirmed character and from
   each completed value, so accuracy improves within and across extractions.

## Concurrency model

- A single bounded `ThreadPoolExecutor(max_workers=workers)` per extraction.
- Independent oracle questions (predicted-candidate batches, sequence
  hypotheses) run concurrently; each HTTP request uses a per-thread `requests`
  session.
- **Ordering is preserved** because a position is fully resolved before the
  known prefix advances. Requests may complete out of order, but the character
  accepted for position *n* is always fixed before position *n+1* begins.
- Timeouts, connection failures, transient errors, retries and clean pool
  shutdown are handled in `http_client` and `oracle`; the pool is closed via a
  `with` block so no threads leak on completion or error.

## Prediction models

- **Character predictor** (`predictor.py`): counts transitions at context
  lengths `0..order` and estimates `P(next | prefix)` with stupid-backoff and a
  small uniform prior. Data-driven — it starts near-uniform and is dominated by
  observed data as soon as any exists.
- **Sequence predictor** (`sequence.py`): stores whole discovered values and
  counts recurring prefixes, proposing continuations and providing the expected
  request-cost comparison used to choose between sequence and char-by-char.

## Reliability

`OracleResult` distinguishes `TRUE`, `FALSE`, `REQUEST_ERROR`, `TIMEOUT`,
`UNKNOWN`. The engine's `_is_true()` maps only definite answers to a boolean and
returns `None` otherwise — a failure is never coerced to `FALSE`. Ambiguity is
retried; unresolved characters stop extraction with a clear partial result.
