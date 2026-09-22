"""HTTP client.

Thin, replaceable wrapper around ``requests`` that:
  * enforces the local-scope guard on every request;
  * applies timeouts and bounded retries with exponential backoff;
  * translates network failures into typed exceptions the oracle understands;
  * returns a transport-neutral :class:`HttpResponse`.

The rest of the toolkit depends only on the small surface below, so swapping in
httpx/aiohttp later touches this file alone.
"""

from __future__ import annotations

import copy
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional, Union

from .config import Config
from .logging_util import Logger
from .result_types import HttpResponse
from .scope import enforce


class TimeoutError_(Exception):
    """Request exceeded the configured timeout (all attempts)."""


class RequestError(Exception):
    """Connection failure / transport error (all attempts exhausted)."""


def _requests() -> Any:
    """Import ``requests`` lazily so modules that never issue real HTTP (and
    unit tests that inject a fake client) do not require it to be installed."""
    try:
        import requests  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "the 'requests' package is required for live HTTP; install it with "
            "'pip install requests' (see requirements.txt)"
        ) from exc
    return requests


class HttpClient:
    def __init__(self, config: Config, logger: Optional[Logger] = None) -> None:
        self.config = config
        self.logger = logger or Logger(config.verbosity)
        enforce(config.target_url, config.allow_nonlocal)
        # A Session per thread avoids sharing connection pools across threads,
        # which keeps behaviour predictable under the worker pool.
        self._local = threading.local()

    def _session(self):
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = _requests().Session()
            sess.headers.update(self.config.headers)
            if self.config.cookies:
                sess.cookies.update(self.config.cookies)
            if self.config.proxy:
                sess.proxies = {"http": self.config.proxy, "https": self.config.proxy}
                # An explicit proxy must win over environment variables and,
                # critically, must NOT be bypassed for loopback targets — which
                # is the whole point of pointing a local lab at Burp/ZAP.
                sess.trust_env = False
                if self.config.proxy_insecure:
                    sess.verify = False
                    try:  # silence the resulting InsecureRequestWarning
                        import urllib3  # type: ignore
                        urllib3.disable_warnings()
                    except Exception:  # pragma: no cover
                        pass
            self._local.session = sess
        return sess

    def _effective_mode(self, method: str) -> str:
        mode = (self.config.body_mode or "auto").lower()
        if mode == "auto":
            return "query" if method == "GET" else "form"
        return mode

    _PATH_TOKEN = re.compile(r"\[(\d+)\]|([^.\[\]]+)")

    @classmethod
    def _parse_path(cls, path: str) -> List[Union[str, int]]:
        """Tokenize a path into dict keys and list indices.

        Examples: 'creds.username' -> ['creds','username'];
                  '[0].vulnerableParam' -> [0,'vulnerableParam'];
                  'data.items[2].name' -> ['data','items',2,'name'].
        """
        tokens: List[Union[str, int]] = []
        for m in cls._PATH_TOKEN.finditer(path):
            if m.group(1) is not None:
                tokens.append(int(m.group(1)))
            else:
                tokens.append(m.group(2))
        return tokens

    @classmethod
    def _set_path(cls, obj: Any, path: str, value: Any) -> None:
        """Set value at a dotted/indexed path. Navigates existing dicts and
        lists; creates intermediate dicts only for missing string keys (list
        elements are expected to already exist in the JSON template)."""
        tokens = cls._parse_path(path)
        cur = obj
        for tok in tokens[:-1]:
            if isinstance(tok, int):
                cur = cur[tok]
            else:
                nxt = cur.get(tok) if isinstance(cur, dict) else None
                if not isinstance(nxt, (dict, list)):
                    nxt = {}
                    cur[tok] = nxt
                cur = nxt
        cur[tokens[-1]] = value

    def build_request(self, injected_value: str, method: str) -> Dict[str, Any]:
        """Return the requests kwargs that carry *injected_value* per body_mode.

        Pure and side-effect free, so it can be unit-tested without any network.
        """
        mode = self._effective_mode(method)
        if mode in ("query", "form"):
            params: Dict[str, str] = dict(self.config.static_params)
            params[self.config.injection_param] = injected_value
            return {"params": params} if mode == "query" else {"data": params}
        if mode == "cookie":
            # inject into one cookie; other configured cookies ride along, and
            # any query string in target_url is still sent as-is.
            cookies = dict(self.config.cookies)
            cookies[self.config.injection_param] = injected_value
            return {"cookies": cookies}
        if mode == "json":
            # the template may be a dict or a top-level list; use `is not None`
            # so an intentional list root isn't turned into {}
            if self.config.json_template is not None:
                body = copy.deepcopy(self.config.json_template)
            else:
                body = {}
            self._set_path(body, self.config.injection_param, injected_value)
            return {"json": body}
        # raw
        val_json = json.dumps(injected_value)[1:-1]  # escaped, no surrounding quotes
        rendered = (self.config.body_template or "").replace("{value_json}", val_json).replace("{value}", injected_value)
        ctype = self.config.content_type or "application/json"
        return {"data": rendered.encode("utf-8"), "headers": {"Content-Type": ctype}}

    def send(self, injected_value: str) -> HttpResponse:
        """Send one request with *injected_value* placed at the injection point.

        The value is carried per ``body_mode`` (query string, form body, a JSON
        body at a dotted key path, or a raw templated body). Raises
        :class:`TimeoutError_` or :class:`RequestError` after exhausting retries.
        Transient 5xx are *not* retried here — the classifier may treat a 500 as
        a meaningful (FALSE) signal, so retrying would corrupt results.
        """
        method = self.config.http_method.upper()
        req_kwargs = self.build_request(injected_value, method)

        last_exc: Optional[Exception] = None
        backoff = self.config.retry_backoff
        rq = _requests()

        for attempt in range(1, self.config.max_retries + 1):
            start = time.time()
            try:
                sess = self._session()
                resp = sess.request(
                    method,
                    self.config.target_url,
                    timeout=self.config.request_timeout,
                    **req_kwargs,
                )
                elapsed = time.time() - start
                self.logger.debug(
                    f"HTTP {method} attempt {attempt} -> {resp.status_code} "
                    f"len={len(resp.text)} {elapsed:.3f}s"
                )
                return HttpResponse.from_requests(resp, elapsed)
            except rq.exceptions.Timeout as exc:
                last_exc = exc
                self.logger.debug(f"timeout on attempt {attempt}: {exc}")
            except rq.exceptions.RequestException as exc:
                last_exc = exc
                self.logger.debug(f"request error on attempt {attempt}: {exc}")

            if attempt < self.config.max_retries:
                time.sleep(backoff)
                backoff *= 2

        if isinstance(last_exc, rq.exceptions.Timeout):
            raise TimeoutError_(str(last_exc)) from last_exc
        raise RequestError(str(last_exc)) from last_exc
