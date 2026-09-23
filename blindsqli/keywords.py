"""Keyword loading for the cross-scope value search.

A *keyword* is one independent search target: a value the operator knows (or
suspects) exists somewhere in the authorized scope, without knowing which
database, table, column or row holds it. Keywords never combine into a single
query -- each is investigated on its own (see :mod:`blindsqli.search`).

Keywords can be typed on the command line or loaded from a plain-text file:

    # Accounts            <- a comment; also sets the category for the lines below
    admin
    alice@example.com

    # Business data
    invoice ;; exact
    customer ;; tag=crm

Rules:
  * Blank lines and ``#`` comment lines are ignored.
  * A ``#! key=value`` directive line sets a default for the lines that follow
    (``mode=exact|substring``, ``case=sensitive|insensitive``, ``tag=NAME``).
  * A bare ``# Some Heading`` comment optionally becomes the current category
    tag when ``tags_from_headings`` is on (the default), so the example above
    tags ``admin`` with ``Accounts``.
  * A keyword line may carry per-keyword options after a `` ;; `` separator, as
    comma-separated tokens: ``exact`` / ``substring``, ``cs`` / ``ci``
    (case sensitivity), and ``tag=NAME``.

Per-keyword options win over ``#!`` directives, which win over the function
defaults.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

OPT_SEP = ";;"
_HEADING_RE = re.compile(r"^[A-Za-z0-9][\w .\-/&]{0,48}$")


@dataclass(frozen=True)
class Keyword:
    """One independent search target.

    Attributes:
      value:          the literal being searched for.
      exact:          True -> match a whole column value; False -> substring.
      case_sensitive: True -> case-sensitive comparison (binary collation).
      tag:            optional free-form category, for grouping results.
    """

    value: str
    exact: bool = False
    case_sensitive: bool = False
    tag: Optional[str] = None

    @property
    def mode(self) -> str:
        return "exact" if self.exact else "substring"

    def __str__(self) -> str:
        bits = [self.mode, "cs" if self.case_sensitive else "ci"]
        if self.tag:
            bits.append(f"tag={self.tag}")
        return f"{self.value!r} ({', '.join(bits)})"


def _apply_token(token: str, exact: bool, cs: bool, tag: Optional[str]):
    """Fold one option token into the (exact, case_sensitive, tag) triple."""
    t = token.strip().lower()
    if t in ("exact", "eq", "="):
        exact = True
    elif t in ("substring", "sub", "contains", "like"):
        exact = False
    elif t in ("cs", "case", "case-sensitive", "sensitive"):
        cs = True
    elif t in ("ci", "nocase", "case-insensitive", "insensitive"):
        cs = False
    elif t.startswith("tag=") or t.startswith("category="):
        tag = token.split("=", 1)[1].strip() or None
    return exact, cs, tag


def parse_keyword_line(
    line: str,
    default_exact: bool = False,
    default_cs: bool = False,
    default_tag: Optional[str] = None,
) -> Optional[Keyword]:
    """Parse a single non-comment keyword line, or return None if it is blank.

    The raw value keeps its internal spaces; only surrounding whitespace and the
    trailing `` ;; options`` segment are stripped.
    """
    value_part = line
    exact, cs, tag = default_exact, default_cs, default_tag
    if OPT_SEP in line:
        value_part, opt_part = line.split(OPT_SEP, 1)
        for token in opt_part.split(","):
            if token.strip():
                exact, cs, tag = _apply_token(token, exact, cs, tag)
    value = value_part.strip()
    if not value:
        return None
    return Keyword(value=value, exact=exact, case_sensitive=cs, tag=tag)


def parse_keywords(
    text: str,
    default_exact: bool = False,
    default_case_sensitive: bool = False,
    tags_from_headings: bool = True,
) -> List[Keyword]:
    """Parse keyword-file *text* into a de-duplicated list of :class:`Keyword`.

    De-duplication is by ``(value, exact, case_sensitive)`` so the same literal
    can appear under two modes but never twice identically; the first tag seen
    wins.
    """
    out: List[Keyword] = []
    seen = set()
    cur_exact, cur_cs, cur_tag = default_exact, default_case_sensitive, None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#!"):
            # directive: change the running defaults
            body = line[2:].strip()
            for token in re.split(r"[,\s]+", body):
                if "=" in token:
                    key, _, val = token.partition("=")
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "mode":
                        cur_exact = val.lower() in ("exact", "eq")
                    elif key == "case":
                        cur_cs = val.lower() in ("sensitive", "cs", "yes", "true")
                    elif key in ("tag", "category"):
                        cur_tag = val or None
            continue
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
            if tags_from_headings and heading and _HEADING_RE.match(heading):
                cur_tag = heading
            continue
        kw = parse_keyword_line(raw, cur_exact, cur_cs, cur_tag)
        if kw is None:
            continue
        key = (kw.value, kw.exact, kw.case_sensitive)
        if key in seen:
            continue
        seen.add(key)
        out.append(kw)
    return out


def load_keywords(path: str, **kwargs) -> List[Keyword]:
    """Load and parse a keyword file. Raises OSError if it cannot be read."""
    with open(path, "r", encoding="utf-8") as fh:
        return parse_keywords(fh.read(), **kwargs)
