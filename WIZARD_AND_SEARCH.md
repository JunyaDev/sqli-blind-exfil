# Wizard and cross-scope value search

This guide covers the two features that turn `blindsqli` from a single-value
extractor into an exploration tool:

- the **cross-scope keyword search** (`search`), which finds *where* known values
  live across the authorized scope, and
- the **interactive wizard** (`wizard`), which sequences the whole assessment so
  you don't have to remember flags.

Everything here is read-only and stays within the same loopback scope guard as
the rest of the tool. See [README.md](README.md#safety-and-scope).

---

## The mental model

> Treat the database environment as a searchable graph of objects and values.
> Use discovered metadata, multiple independent keywords, heuristics, caching and
> targeted boolean confirmation to reduce how much blind extraction you do.

```text
Load keyword file
        v
Discover the authorized database scope   (once, cached in a metadata index)
        v
Rank candidate columns per keyword        (heuristics: name/shape/type/patterns)
        v
Confirm the promising ones                (boolean oracle: COUNT(* WHERE match)>0)
        v
Record exact locations, per keyword       (CANDIDATE / PROBABLE / CONFIRMED / ABSENT)
        v
Targeted extraction from a confirmed hit  (reuses `enumerate --what rows --where`)
```

Discovery is **separate from extraction**: you narrow the search space first,
then spend expensive blind requests only on what survives filtering.

---

## `search`: find known values

### Minimal

```bash
python -m blindsqli search --url http://localhost:3000/ --param q \
    --keyword alice@example.com
```

The first run has no cached metadata, so it discovers the scope (databases ->
tables -> columns) read-only, prints a cost estimate, ranks the columns most
likely to hold `alice@example.com` (an `@` makes `email`/`contact` columns
likely), confirms the top candidates through the oracle, and prints the
confirmed locations.

### Many keywords, from a file, with caching

```bash
python -m blindsqli search --url http://localhost:3000/ --param q \
    --keywords-file keywords.txt \
    --databases appdb,billing \
    --max-candidates 40 \
    --meta-file scope.json \
    --results-file matches.json \
    --search-workers 4
```

- `--keywords-file` loads many independent targets at once (see the format
  below). `--keyword` can also be repeated and combined with a file.
- `--databases` restricts the scope to named databases.
- `--meta-file scope.json` caches the discovered schema. **Re-running reuses it**
  instead of enumerating again, so a second search over new keywords is cheap.
- `--results-file matches.json` persists every match; a later run loads it and
  keeps upgrading statuses (a confirmed cell is never downgraded).
- `--search-workers 4` searches independent keywords concurrently within the
  worker limit; results stay per keyword.

### Keyword A vs keyword B (independence)

Each keyword is its own investigation. A run over

```text
admin
alice@example.com
invoice-82731
project-x
```

can resolve to completely different places:

```text
admin              -> appdb.dbo.accounts.username
alice@example.com  -> billing.dbo.customers.email
invoice-82731      -> billing.dbo.invoices.invoice_number
project-x          -> appdb.dbo.projects.project_code
```

The tool never combines these into one logical query. If you want a relationship
between two values, you build that query yourself with `extract`/`enumerate`.

### From a confirmed match to the data

A confirmed match carries a ready-to-use `WHERE` clause. Hand it to targeted
extraction:

```bash
python -m blindsqli enumerate --url http://localhost:3000/ --param q \
    --what rows --database billing --table customers \
    --columns id,email --where "email LIKE '%alice@example.com%'"
```

---

## Keyword file format

One keyword per line. `keywords.example.txt` is included.

```text
# Accounts                 <- comment; also tags the keywords below it
admin
alice@example.com

# Business data
invoice ;; exact           <- per-keyword options after ' ;; '
customer

#! mode=substring case=insensitive   <- directive: defaults for following lines
internal
project-x ;; tag=infra
```

Rules:

| Syntax | Meaning |
|---|---|
| blank line | ignored |
| `# text` | comment; a short heading also becomes the current category tag |
| `#! mode=exact\|substring` | default match mode for following lines |
| `#! case=sensitive\|insensitive` | default case behaviour |
| `#! tag=NAME` | default category tag |
| `value ;; exact, cs, tag=foo` | per-keyword options (win over directives) |

Option tokens: `exact`/`substring`, `cs`/`ci` (case), `tag=NAME`.

---

## Controlling cost

Every blind request is expensive. `search` estimates the scope before working:

```text
Estimated search scope:
  Keywords:                    14
  Databases:                    8
  Tables:                   2,431
  Columns (known):         18,942
  Candidates/keyword:          50
  Confirmation requests: ~    700
  Cost level:            MODERATE
  Suggested actions:
    - Search metadata first (discover, then filter tables/columns)
    - Lower --max-candidates so only the most likely columns are tested
    - Restrict --databases to the ones in scope
    - Filter tables with a LIKE pattern before searching
```

Cost is bounded by **ranking + `--max-candidates`**: only the N most likely
columns per keyword are ever confirmed, so 18,942 columns does not mean 18,942
requests. Levers:

| Flag | Effect |
|---|---|
| `--max-candidates N` | test only the N top-ranked columns per keyword (default 50) |
| `--estimate-only` | discover + estimate, then stop |
| `--exhaustive` | test every discovered column (ignores the cap; can be very slow) |
| `--stop-after K` | stop a keyword after K confirmed locations |
| `--count-rows` | also count matching rows per confirmed hit (extra requests) |
| `--search-workers N` | search independent keywords concurrently |

---

## How ranking works (heuristics only)

For each `(keyword, column)` the ranker combines:

- **name similarity** of the column to the keyword;
- **value shape**: an `@` -> `email`-ish columns; digits+`-` -> `invoice`/`code`;
  `pass`/`token` -> secret-ish columns;
- **table/schema name** hints;
- **data type** suitability (text column beats an integer column for a string);
- **pattern memory**: columns whose names already produced confirmed matches
  (e.g. `username` in one table) boost look-alikes elsewhere. This is how the
  tool "detects repeated patterns" and recurring naming conventions.

A high score is only a priority. **Every hit is still confirmed through the
boolean oracle** before it is recorded as `CONFIRMED`.

Result statuses form a ladder:

| Status | Meaning |
|---|---|
| `CANDIDATE` | ranked as relevant, not yet tested |
| `PROBABLE` | oracle was undetermined; heuristics still favour it |
| `CONFIRMED` | the oracle proved the value is present |
| `ABSENT` | the oracle proved it is not here |

---

## `wizard`: guided workflow

```bash
python -m blindsqli wizard --url http://localhost:3000/ --param q \
    --meta-file scope.json --results-file matches.json
```

The wizard is a menu loop that sequences the same operations and remembers state
(selected databases -> table -> columns; loaded keywords). Typical paths:

**Progressive metadata exploration**

```text
1 Discover databases  ->  select/filter  ->
2 Discover tables     ->  select one     ->
3 Discover columns    ->  select some    ->
4 Extract a specific object (rows, optionally with a WHERE filter)
```

**Value search**

```text
6 Load a keyword file      (or 5 -> enter a single value)
5 Search for known values  -> choose scope -> see the estimate -> confirm
7 Review previous discoveries   9 Save session (metadata + results)
```

At every list you can pick by index, by exact name, or by a `LIKE` pattern such
as `%user%`. The wizard shows the estimated cost before a search and asks for
confirmation when the cost level is HIGH or VERY HIGH.

---

## Persistence and resuming

- **Metadata index** (`--meta-file`): the discovered schema, so repeated searches
  don't re-enumerate. Load-if-present, saved after discovery.
- **Results** (`--results-file`): every match with full location detail,
  confidence, evidence and timestamp. Reloaded on the next run; statuses only
  ever upgrade.

Both are plain local JSON files. They are analysis artifacts on *your* machine,
never objects created on the target.
