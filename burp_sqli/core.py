# -*- coding: utf-8 -*-
"""Pure logic for the Burp -> blindsqli exporter.

No Burp imports here on purpose: this module must run under Jython 2.7 (inside
Burp) *and* CPython 3 (for the unit tests). Keep the syntax 2/3 compatible:
no f-strings, no type annotations.

Responsibilities:
  * parse a raw HTTP request into a small model;
  * enumerate its parameters across query / form / JSON / cookie locations;
  * turn the model + a chosen parameter into the blindsqli request config keys;
  * merge those keys into an existing config file without touching other keys,
    and write the file atomically so a failure never corrupts it.
"""

import copy
import json
import os
import tempfile

try:  # Python 3
    from urllib.parse import urlsplit, urlunsplit, parse_qsl
except ImportError:  # Python 2 / Jython
    from urlparse import urlsplit, urlunsplit, parse_qsl

# The config keys that describe the request/target. Only these are written on
# export; every other key in an existing file is preserved untouched.
REQUEST_KEYS = [
    "target_url", "http_method", "injection_param", "body_mode",
    "static_params", "json_template", "body_template", "content_type",
    "headers", "cookies",
]

# Request headers that must not be copied into the config (the tool/requests
# manages these itself; copying them would conflict or duplicate).
_DROP_HEADERS = set(["host", "content-length", "cookie", "content-type"])


class Param(object):
    """One candidate injection parameter."""

    def __init__(self, name, location, value):
        self.name = name          # for JSON this is a dotted path
        self.location = location  # query | form | json | cookie
        self.value = value

    def label(self):
        val = self.value if len(self.value) <= 40 else self.value[:37] + "..."
        return "{0}  [{1}]  = {2}".format(self.name, self.location, val)

    def __repr__(self):
        return "Param({0!r}, {1!r})".format(self.name, self.location)


class RequestModel(object):
    def __init__(self, method, url, headers, body, cookies, content_type):
        self.method = method
        self.url = url            # absolute, including any query string
        self.headers = headers    # list of (name, value), order preserved
        self.body = body
        self.cookies = cookies    # Ordered-ish dict {name: value}
        self.content_type = content_type  # lowercased, may be ""


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def _split_head_body(raw):
    for sep in ("\r\n\r\n", "\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep):]
    return raw, ""


def _parse_cookies(cookie_header):
    cookies = {}
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        cookies[k.strip()] = v.strip()
    return cookies


def _header_value(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return ""


def parse_request(raw_request, scheme, host, port):
    """Parse a raw HTTP request plus its service into a RequestModel.

    scheme/host/port come from Burp's HttpService and are authoritative for
    building the absolute URL (the request line is usually origin-form).
    """
    head, body = _split_head_body(raw_request)
    lines = head.split("\n")
    request_line = lines[0].strip("\r").strip()
    parts = request_line.split(" ")
    method = parts[0].upper() if parts and parts[0] else "GET"
    target = parts[1] if len(parts) > 1 else "/"

    headers = []
    for line in lines[1:]:
        line = line.strip("\r")
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))

    content_type = _header_value(headers, "content-type").lower()
    cookies = _parse_cookies(_header_value(headers, "cookie"))

    if target[:7] == "http://" or target[:8] == "https://":
        url = target
    else:
        default = (scheme == "http" and int(port) == 80) or (scheme == "https" and int(port) == 443)
        netloc = host if default else "{0}:{1}".format(host, port)
        if not target.startswith("/"):
            target = "/" + target
        url = "{0}://{1}{2}".format(scheme, netloc, target)

    return RequestModel(method, url, headers, body, cookies, content_type)


# --------------------------------------------------------------------------- #
# parameter enumeration
# --------------------------------------------------------------------------- #
def _flatten_json(obj, prefix=""):
    """Dotted paths to scalar leaves reachable through dict keys.

    List contents are skipped: the tool addresses JSON by dotted dict path and
    cannot index into arrays, so offering an array element would produce a path
    it could not use.
    """
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = k if not prefix else prefix + "." + k
            out += _flatten_json(v, path)
    elif isinstance(obj, (str, bytes)) or obj is True or obj is False or _is_number(obj):
        if prefix:
            out.append((prefix, _as_text(obj)))
    # lists / None -> skipped
    return out


def _is_number(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _as_text(x):
    if isinstance(x, bytes):
        return x.decode("utf-8", "replace")
    return x if isinstance(x, str) else str(x)


def _body_is_json(model):
    if "json" in model.content_type:
        return True
    if "x-www-form-urlencoded" in model.content_type:
        return False
    body = (model.body or "").strip()
    if body[:1] in ("{", "["):
        try:
            json.loads(model.body)
            return True
        except ValueError:
            return False
    return False


def enumerate_parameters(model):
    """All candidate injection parameters, in the order query, body, cookie."""
    params = []
    query = urlsplit(model.url).query
    for name, value in parse_qsl(query, keep_blank_values=True):
        params.append(Param(name, "query", value))

    if model.body:
        if _body_is_json(model):
            try:
                data = json.loads(model.body)
            except ValueError:
                data = None
            if data is not None:
                for path, value in _flatten_json(data):
                    params.append(Param(path, "json", value))
        else:
            for name, value in parse_qsl(model.body, keep_blank_values=True):
                params.append(Param(name, "form", value))

    for name, value in model.cookies.items():
        params.append(Param(name, "cookie", value))
    return params


# --------------------------------------------------------------------------- #
# config building / merging
# --------------------------------------------------------------------------- #
def _filtered_headers(model):
    out = {}
    for k, v in model.headers:
        if k.lower() in _DROP_HEADERS:
            continue
        out[k] = v
    return out


def _query_dict(url):
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def _url_without_query(url):
    s = urlsplit(url)
    return urlunsplit((s.scheme, s.netloc, s.path, "", ""))


def build_request_config(model, selected):
    """Turn *model* + a chosen Param into the blindsqli request config keys.

    Query string is stripped from target_url only for query-injection (the tool
    rebuilds it); for form/json/cookie the full URL is kept so its query still
    rides along. All cookies are always exported, so cross-location context
    (cookies, headers, and query for non-query modes) is preserved.
    """
    loc = selected.location
    cfg = {
        "http_method": model.method,
        "headers": _filtered_headers(model),
        "cookies": dict(model.cookies),
        # neutral defaults; the branch below sets what applies to this location
        "static_params": {},
        "json_template": None,
        "body_template": None,
        "content_type": None,
    }

    if loc == "query":
        cfg["target_url"] = _url_without_query(model.url)
        cfg["body_mode"] = "query"
        cfg["injection_param"] = selected.name
        others = _query_dict(model.url)
        others.pop(selected.name, None)
        cfg["static_params"] = others
    elif loc == "form":
        cfg["target_url"] = model.url  # keep query so it is still sent
        cfg["body_mode"] = "form"
        cfg["injection_param"] = selected.name
        others = dict(parse_qsl(model.body or "", keep_blank_values=True))
        others.pop(selected.name, None)
        cfg["static_params"] = others
    elif loc == "json":
        cfg["target_url"] = model.url
        cfg["body_mode"] = "json"
        cfg["injection_param"] = selected.name
        try:
            cfg["json_template"] = json.loads(model.body)
        except ValueError:
            cfg["json_template"] = {}
    elif loc == "cookie":
        cfg["target_url"] = model.url
        cfg["body_mode"] = "cookie"
        cfg["injection_param"] = selected.name
        # cookies (incl. the target one) already set above
    else:
        raise ValueError("unknown parameter location: {0}".format(loc))

    # Non-config metadata: makes the chosen parameter obvious to a human reading
    # the file. The tool ignores unknown keys, so this never affects a run.
    cfg["_burp_export"] = {
        "selected_param": selected.name,
        "location": loc,
        "source": "burp",
    }
    return cfg


def merge_config(existing, request_config):
    """Overlay the request keys onto a copy of *existing*, preserving the rest."""
    merged = copy.deepcopy(existing) if existing else {}
    for k, v in request_config.items():
        merged[k] = v
    return merged


def load_existing(path):
    """Return the parsed existing config, or {} if absent/empty.

    Raises ValueError if the file exists but is not valid JSON, so we refuse to
    overwrite (and thereby corrupt) a file we could not understand.
    """
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r") as fh:
        text = fh.read()
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("existing config is not valid JSON: {0}".format(exc))
    if not isinstance(data, dict):
        raise ValueError("existing config must be a JSON object")
    return data


def write_config(path, data):
    """Atomically write *data* as pretty JSON to *path*."""
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    fd, tmp = tempfile.mkstemp(prefix=".blindsqli-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.rename(tmp, path)  # atomic on the same filesystem
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def export(path, model, selected):
    """Full export: read existing, merge the chosen request, write. Returns the
    merged dict. Raises ValueError on an unreadable existing file."""
    existing = load_existing(path)
    request_config = build_request_config(model, selected)
    merged = merge_config(existing, request_config)
    write_config(path, merged)
    return merged
