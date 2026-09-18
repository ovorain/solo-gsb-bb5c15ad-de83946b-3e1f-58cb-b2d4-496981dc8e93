"""Field redaction driven by JSON Pointer glob patterns.

The :func:`apply_redactions` entry point evaluates a list of redaction
rules against a JSON document. Each rule pairs a ``path`` -- an RFC 6901
JSON Pointer that may contain the wildcard tokens ``*`` (matches exactly
one object member or one array element) and ``**`` (matches any number of
levels, including zero) -- with an ``action``:

* ``remove`` -- delete the matched member or element;
* ``mask``   -- replace the matched value with the string ``"***"``;
* ``hash``   -- replace the matched value with the SHA-256 hex digest of
  its RFC 8785 (JCS) canonical JSON text, exactly the digest
  ``POST /canonicalize`` reports for that value.

All rules are validated before anything is matched or applied
(:class:`RedactStructureError`, HTTP 422). Every rule is then matched
against the *original* document, so one rule can never observe another
rule's effect. When several rules match the same path a single winning
action is chosen: the rule with fewer wildcard tokens wins, then the one
with more path tokens, then the one declared first.

The winning actions are applied to a deep copy of the document --
replacements first (deepest path first), then removals (deepest path
first, highest array index first) -- so every path keeps addressing the
original document and array removals cannot shift each other's targets.
An action whose target disappeared because an ancestor was replaced or
removed is subsumed and skipped, but its path still counts as matched. A
``remove`` that wins at the root pointer ``""`` is a
:class:`RedactConflict` (HTTP 409), mirroring ``POST /patch``.

The function returns the redacted copy together with every matched path
rendered as an RFC 6901 pointer; the input document is never modified.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

from .canonicalize import canonicalize
from .jsonutil import MISSING, escape_pointer
from .patch import PatchStructureError, parse_pointer

SUPPORTED_ACTIONS = ("remove", "mask", "hash")

# The replacement value used by the "mask" action.
MASK_VALUE = "***"

# Pattern tokens that match structurally rather than literally.
_WILDCARDS = ("*", "**")


class RedactStructureError(Exception):
    """Raised for an invalid rule structure or JSON Pointer glob (422)."""

    def __init__(self, reason: str, index: int = -1, path: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.index = index
        self.path = path


class RedactConflict(Exception):
    """Raised when a valid rule set cannot be applied (409)."""

    def __init__(self, reason: str, index: int, path: str):
        super().__init__(reason)
        self.reason = reason
        self.index = index
        self.path = path


def _check_rules(rules: list) -> list[list[str]]:
    """Validate every rule and return the parsed glob token lists.

    Nothing is matched or applied until every rule has been checked, so a
    single bad rule fails the whole request before any work happens.
    """
    if not isinstance(rules, list):
        raise RedactStructureError("'rules' must be an array")
    patterns: list[list[str]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise RedactStructureError("each rule must be an object", index)
        action = rule.get("action", MISSING)
        if action is MISSING:
            raise RedactStructureError(
                "missing 'action' field", index, rule.get("path")
            )
        if action not in SUPPORTED_ACTIONS:
            raise RedactStructureError(
                f"unsupported action {action!r}; supported actions are: "
                "remove, mask, hash",
                index,
                rule.get("path"),
            )
        path = rule.get("path", MISSING)
        if path is MISSING or not isinstance(path, str):
            raise RedactStructureError("missing or non-string 'path' field", index)
        try:
            tokens = parse_pointer(path, index)
        except PatchStructureError as exc:
            raise RedactStructureError(exc.reason, index, path) from exc
        patterns.append(tokens)
    return patterns


def _array_index(token: str) -> int | None:
    """Return the array index named by a canonical index token, else None.

    Only canonical RFC 6901 index tokens count: ASCII digits without
    leading zeros. Anything else (including ``-``) can still match an
    object member literally but never names an array element.
    """
    if not token.isascii() or not token.isdigit():
        return None
    if len(token) > 1 and token[0] == "0":
        return None
    if len(token) > 18:
        # Beyond any plausible array length (and Python's int-parsing
        # digit limit); such a token simply matches nothing in an array.
        return None
    return int(token)


def _match(
    tokens: list[str],
    node: Any,
    path: tuple,
    hits: set,
    values: dict,
) -> None:
    """Collect every path at which the glob ``tokens`` matches below node.

    ``path`` holds the raw reference tokens of ``node``. Each fully
    matched path is added to ``hits`` and its (original) value recorded
    in ``values``.
    """
    if not tokens:
        hits.add(path)
        values[path] = node
        return
    token, rest = tokens[0], tokens[1:]
    if token == "**":
        # "**" matches zero levels right here ...
        _match(rest, node, path, hits, values)
        # ... or consumes one level and stays available for those below.
        if isinstance(node, dict):
            for key, child in node.items():
                _match(tokens, child, path + (key,), hits, values)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                _match(tokens, child, path + (str(i),), hits, values)
    elif token == "*":
        if isinstance(node, dict):
            for key, child in node.items():
                _match(rest, child, path + (key,), hits, values)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                _match(rest, child, path + (str(i),), hits, values)
    elif isinstance(node, dict):
        if token in node:
            _match(rest, node[token], path + (token,), hits, values)
    elif isinstance(node, list):
        index = _array_index(token)
        if index is not None and index < len(node):
            _match(rest, node[index], path + (token,), hits, values)


def _apply_key(path: tuple) -> tuple:
    """Order paths for application: deepest first, highest index first."""
    return tuple(
        (0, index) if (index := _array_index(token)) is not None else (1, token)
        for token in path
    )


def _matched_sort_key(path: tuple) -> tuple:
    """Order matched pointers for the response: indices numerically first.

    Within a level, array indices sort numerically before member names;
    member names sort by Unicode code point. The root path sorts first.
    """
    return tuple(
        (0, index, "") if (index := _array_index(token)) is not None else (1, 0, token)
        for token in path
    )


def _render(path: tuple) -> str:
    """Render a matched path as an RFC 6901 JSON Pointer."""
    return "".join(f"/{escape_pointer(token)}" for token in path)


def _set(document: Any, path: tuple, value: Any) -> None:
    """Replace the value at ``path``; every ancestor must still exist."""
    node = document
    for token in path[:-1]:
        node = node[token] if isinstance(node, dict) else node[int(token)]
    token = path[-1]
    if isinstance(node, dict):
        node[token] = value
    else:
        node[int(token)] = value


def _remove(document: Any, path: tuple) -> None:
    """Remove the value at ``path`` if it still resolves.

    A path whose ancestor was itself replaced or removed no longer
    resolves; the removal is then subsumed by the ancestor's action and
    silently skipped.
    """
    node = document
    for token in path[:-1]:
        if isinstance(node, dict):
            if token not in node:
                return
            node = node[token]
        elif isinstance(node, list):
            index = _array_index(token)
            if index is None or index >= len(node):
                return
            node = node[index]
        else:
            return
    token = path[-1]
    if isinstance(node, dict):
        node.pop(token, None)
    elif isinstance(node, list):
        index = _array_index(token)
        if index is not None and index < len(node):
            del node[index]


def apply_redactions(document: Any, rules: list) -> tuple[Any, list[str]]:
    """Validate ``rules`` and apply their winning actions to a deep copy.

    Returns ``(redacted_document, matched_pointers)`` where the pointers
    are every RFC 6901 path at least one rule matched, sorted with array
    indices numerically before member names. Raises
    :class:`RedactStructureError` for an invalid rule set (before any
    matching happens) and :class:`RedactConflict` when a ``remove`` wins
    at the root pointer. The input ``document`` is never modified.
    """
    patterns = _check_rules(rules)

    # Match every rule against the original document and arbitrate each
    # matched path: fewer wildcard tokens win, then more path tokens,
    # then the earlier declaration.
    matched: set[tuple] = set()
    values: dict[tuple, Any] = {}
    winners: dict[tuple, tuple] = {}
    for index, tokens in enumerate(patterns):
        hits: set[tuple] = set()
        _match(tokens, document, (), hits, values)
        priority = (
            sum(1 for token in tokens if token in _WILDCARDS),
            -len(tokens),
            index,
        )
        for path in hits:
            matched.add(path)
            if path not in winners or priority < winners[path][0]:
                winners[path] = (priority, index)

    # Split the winning actions into replacements and removals. Hash
    # digests are computed from the original values captured above.
    replacements: list[tuple] = []
    removals: list[tuple] = []
    for path, (_priority, index) in winners.items():
        action = rules[index]["action"]
        if action == "remove":
            removals.append(path)
        elif action == "mask":
            replacements.append((path, MASK_VALUE))
        else:  # hash
            canonical = canonicalize(values[path])
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            replacements.append((path, digest))

    if () in removals:
        raise RedactConflict(
            "'remove' cannot target the whole document",
            winners[()][1],
            "",
        )

    result = deepcopy(document)
    # Replacements first, deepest path first: every parent still exists
    # when its descendant is replaced, and an ancestor replacement then
    # simply overwrites its already-processed descendants.
    for path, value in sorted(
        replacements, key=lambda item: _apply_key(item[0]), reverse=True
    ):
        if path:
            _set(result, path, value)
        else:
            result = value
    # Removals last, deepest path and highest array index first, so one
    # removal can never shift the target of another.
    for path in sorted(removals, key=_apply_key, reverse=True):
        _remove(result, path)

    pointers = [_render(path) for path in sorted(matched, key=_matched_sort_key)]
    return result, pointers
