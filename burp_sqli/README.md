# Burp Suite → blindsqli exporter

A small Burp Suite extension that turns a request you selected in Burp into a
ready-to-use `blindsqli` configuration file, so you don't hand-copy URLs,
headers, cookies and bodies.

It does one job: **extract and serialize the request**. It never sends requests
or performs any SQLi testing — that stays entirely in the `blindsqli` tool. The
two are loosely coupled through the config file only.

## Why Jython (and not Java/Montoya)?

Both are valid. This project is Python end to end, so the extension's real logic
(request parsing, parameter enumeration, config merge) lives in
[`core.py`](core.py) as plain Python with **no Burp dependency**. That same file
runs under Jython inside Burp *and* under CPython for the test suite
(`tests/test_burp_export.py`), so the export logic is actually verified. The
Burp/Swing glue in [`extension.py`](extension.py) is a thin shim. If you prefer
Java, you can reimplement only the shim against the Montoya API and reuse the
same config format.

## Requirements

- Burp Suite (Professional or Community — the Extender API is in both).
- The **Jython standalone** JAR (2.7.x), from https://www.jython.org/download.

## Install

1. Burp → **Extender → Options → Python Environment** → set the location of the
   Jython standalone JAR.
2. Burp → **Extender → Extensions → Add**:
   - Extension type: **Python**
   - Extension file: select `burp_sqli/extension.py`
3. You should see "Export to blindsqli" registered with no errors in the Output
   tab. `core.py` must sit next to `extension.py` (it is imported at load time).

## Use

1. In **Proxy → HTTP history** or **Repeater**, right-click the request.
2. Choose **Export to SQLi Tool**.
3. In the dialog:
   - pick the **vulnerable parameter** from the dropdown (you choose it — the
     extension never guesses);
   - confirm or **Browse** to the config file path (default:
     `~/blindsqli_config.json`);
   - click **OK**.
4. A message confirms the export, e.g. *"Exported the json parameter
   'creds.username' to …"*.

```
Selected request → Select vulnerable parameter → Export → Configuration updated
```

## What it writes

Only the request/target keys are written; every other key already in the file
is preserved:

| Config key | From the Burp request |
|---|---|
| `target_url` | scheme/host/port + path (query kept except for query-mode) |
| `http_method` | request method |
| `injection_param` | the parameter you selected (a dotted path for JSON) |
| `body_mode` | `query`, `form`, `json`, or `cookie` — from the parameter's location |
| `static_params` | the *other* parameters in the same location (query/form) |
| `json_template` | the full JSON body (for a JSON parameter) |
| `headers` | request headers minus Host, Content-Length, Cookie, Content-Type |
| `cookies` | all cookies (so they ride along in every mode) |
| `_burp_export` | metadata noting which parameter/location was chosen (the tool ignores it) |

Parameter locations handled: **URL query, form body, JSON body (nested via dotted
path), and cookies.**

Safety: the file is written atomically (temp file + rename). If an existing file
is present but not valid JSON, the export **aborts** and leaves it untouched
rather than risk corrupting it.

## Then run the tool

The export fills in the request and target. You still set the SQLi specifics
(the injection payload and, if not the default, what to extract):

```bash
python -m blindsqli extract --config ~/blindsqli_config.json \
  --base-payload "juniper' AND 1=(SELECT CASE WHEN ({condition}) THEN 1 ELSE 'a' END)-- " \
  --preset first-table -v
```

`--base-payload` is SQLi logic, not request data, so it is intentionally not
exported from Burp.

## Troubleshooting

- **`NameError: name '__file__' is not defined`** on load: Burp's Jython does
  not define `__file__`. This is handled — the extension falls back to the
  current frame's path and then to searching `sys.path` for `core.py`. Just make
  sure `core.py` sits in the **same folder** as `extension.py`. If you moved
  them apart, add the folder under Extender → Options → Python Environment →
  "Folder for loading modules".

## Tests

The pure logic is covered by `tests/test_burp_export.py` (run from the project
root with `pytest`): request parsing, parameter enumeration for all four
locations, config building per location, merge-preserves-other-keys,
atomic-write / corrupt-file safety, and an end-to-end export-then-extract
against the local mock.
