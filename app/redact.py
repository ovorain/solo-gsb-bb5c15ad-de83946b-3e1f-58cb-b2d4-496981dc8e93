"""Field-level JSON redaction driven by JSON Pointer glob rules.

Each rule is ``{"path": <pointer-glob>, "action": remove|mask|hash}``.
A path uses RFC 6901 syntax (``/`` separated tokens, ``~0`` / ``~1``
escaping) with two glob extensions:

* a token that is exactly ``*`` matches exactly one level: every member
  of an object or every element of an array;
* a token that is exactly ``**`` matches zero or more levels (it may
  consume no segment at all, so ``/a/**/b`` matches ``/a/b`` and
  ``/**`` matches the whole document);
* array positions accept ``*`` as well; a literal numeric token
  addresses that index.

An asterisk in any other position (e.g. ``/a*b``) is a literal
character, not a wildcard.

All rules are validated before the document is touched, so a bad rule
never produces a partial result. When several rules match the same
concrete path the winner is chosen by

1. fewer wildcard tokens (``*`` and ``**`` each count as one);
2. longer pattern (more reference tokens);
3. earlier declaration order.

A matched node is terminal: ``remove`` deletes it (array elements shift
together), ``mask`` replaces it wholesale with the string ``"***"`` and
``hash`` replaces it with the SHA-256 hex digest of the value's RFC 8785
canonical JSON text. Rules matching nodes inside a subtree that an
ancestor rule already removed or replaced do not fire and are not
reported as hits.
"""

from __future__ import annotations

import hashlib
import sys
from typing import Any, Iterator

from .canonicalize import CanonicalizationError, canonicalize
from .jsonutil import escape_pointer

SUPPORTED_ACTIONS = ("remove", "mask", "hash")

#: Replacement value for the ``mask`` action.
MASK = "***"


class RedactionError(Exception):
    """A rule is structurally invalid (HTTP 422)."""

    def __init__(self, reason: str, index: int = -1, path: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.index = index
        self.path = path


class RedactionConflict(Exception):
    """A valid rule cannot apply to this document (HTTP 409)."""

    def __init__(self, reason: str, index: int, path: str):
        super().__init__(reason)
        self.reason = reason
        self.index = index
        self.path = path


def _parse_glob(pointer: Any, index: int) -> list[str]:
    """Parse a pointer-glob into raw (unescaped) tokens.

    Mirrors RFC 6901: ``""`` addresses the root, every other pointer
    must start with ``/`` and ``~`` may only be followed by ``0``/``1``.
    The tokens ``*`` and ``**`` keep their literal spelling here; the
    matcher interprets them as wildcards.
    """
    if not isinstance(pointer, str):
        raise RedactionError("'path' must be a JSON Pointer string", index)
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise RedactionError(
            "malformed JSON Pointer: non-empty pointer must start with '/'",
            index,
            pointer,
        )
    tokens: list[str] = []
    for raw in pointer[1:].split("/"):
        token = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == "~":
                if i + 1 >= len(raw) or raw[i + 1] not in "01":
                    raise RedactionError(
                        "malformed JSON Pointer: '~' must be followed by '0' or '1'",
                        index,
                        pointer,
                    )
                token.append("~" if raw[i + 1] == "0" else "/")
                i += 2
            else:
                token.append(ch)
                i += 1
        tokens.append("".join(token))
    return tokens


def validate_rules(rules: Any) -> list[tuple[int, list[str], str]]:
    """Validate every rule independently of the document.

    Returns ``(declaration index, parsed tokens, action)`` tuples. A
    rule must be an object with a string ``path`` and an ``action`` in
    :data:`SUPPORTED_ACTIONS`; extra fields are ignored.
    """
    if not isinstance(rules, list):
        raise RedactionError("'rules' must be an array")
    parsed: list[tuple[int, list[str], str]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise RedactionError("each rule must be an object", index)
        action = rule.get("action")
        if not isinstance(action, str):
            raise RedactionError(
                "missing or non-string 'action' field",
                index,
                rule.get("path") if isinstance(rule.get("path"), str) else None,
            )
        if action not in SUPPORTED_ACTIONS:
            raise RedactionError(
                f"unsupported action {action!r}; supported actions are: "
                "remove, mask, hash",
                index,
                rule.get("path") if isinstance(rule.get("path"), str) else None,
            )
        if "path" not in rule:
            raise RedactionError("missing 'path' field", index)
        tokens = _parse_glob(rule["path"], index)
        parsed.append((index, tokens, action))
    return parsed


def _array_index(token: str) -> int | None:
    """Interpret a literal token as an RFC 6901 array index, or ``None``."""
    if not token.isdigit() or (len(token) > 1 and token[0] == "0"):
        return None
    return int(token)


def _matches(pattern: list[str], node: Any) -> Iterator[tuple[str, ...]]:
    """Yield every concrete token path at which ``pattern`` hits ``node``.

    Concrete paths use member names and decimal array indices as
    strings, ready to render back as RFC 6901 pointers.
    """

    def rec(ti: int, current: Any, concrete: tuple[str, ...]) -> None:
        # ``concrete`` uniquely identifies a node in the JSON tree, and
        # ``ti`` the pattern position; memoizing that pair keeps the
        # zero-or-more branching of consecutive ``**`` tokens linear in
        # the document rather than exponential.
        state = (ti, concrete)
        if state in seen:
            return
        seen.add(state)
        if ti == len(pattern):
            yield_paths.add(concrete)
            return
        head = pattern[ti]
        if head == "*":
            # Exactly one level: every object member or array element.
            if isinstance(current, dict):
                for key, value in current.items():
                    rec(ti + 1, value, concrete + (key,))
            elif isinstance(current, list):
                for i, value in enumerate(current):
                    rec(ti + 1, value, concrete + (str(i),))
        elif head == "**":
            # Zero levels (anchor itself matches) ...
            rec(ti + 1, current, concrete)
            # ... or one level, keeping the globstar to consume more.
            if isinstance(current, dict):
                for key, value in current.items():
                    rec(ti, value, concrete + (key,))
            elif isinstance(current, list):
                for i, value in enumerate(current):
                    rec(ti, value, concrete + (str(i),))
        else:
            if isinstance(current, dict) and head in current:
                rec(ti + 1, current[head], concrete + (head,))
            elif isinstance(current, list):
                i = _array_index(head)
                if i is not None and 0 <= i < len(current):
                    rec(ti + 1, current[i], concrete + (head,))

    # A pattern containing "**" can reach the same concrete path by
    # several segment consumptions; deduplicate to keep work bounded.
    yield_paths: set[tuple[str, ...]] = set()
    seen: set[tuple[int, tuple[str, ...]]] = set()
    rec(0, node, ())
    yield from yield_paths


def _wildcard_count(pattern: list[str]) -> int:
    """Number of wildcard tokens (``*`` or ``**``) in the pattern."""
    return sum(1 for token in pattern if token == "*" or token == "**")


def _render_pointer(concrete: tuple[str, ...]) -> str:
    """Render a concrete token path as an RFC 6901 pointer."""
    return "".join("/" + escape_pointer(token) for token in concrete)


def _path_sort_key(path: str):
    """Array indices sort numerically and before member names.

    Mirrors the ordering used by the validation service; the root
    pointer sorts first.
    """
    if path == "":
        return ()
    key = []
    for raw in path.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if token.isdigit() and not (len(token) > 1 and token.startswith("0")):
            key.append((0, int(token), ""))
        else:
            key.append((1, 0, token))
    return tuple(key)


def redact(document: Any, rules: Any) -> tuple[Any, list[dict]]:
    """Validate ``rules`` and apply the winners to a rebuilt copy of document.

    Returns ``(redacted_document, hits)`` where each hit records the
    RFC 6901 ``path``, the winning ``action`` and the declaring rule
    index. The input document is never mutated: the result is rebuilt
    while walking the original, so a failure (or the copy itself) never
    aliases the request data.

    :raises RedactionError: a rule is structurally invalid (422).
    :raises RedactionConflict: a winning ``remove`` targets the root (409).
    """
    parsed = validate_rules(rules)

    # Glob expansion and the rebuild walk the document recursively, so
    # finite documents nested deeper than the interpreter default need
    # headroom (same approach as the validation service).
    previous_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(previous_limit, 10000))
    try:
        # Pick one winning rule per concrete path.
        winners: dict[tuple[str, ...], tuple[tuple, int, str]] = {}
        for index, pattern, action in parsed:
            wildcard_count = _wildcard_count(pattern)
            for concrete in _matches(pattern, document):
                score = (wildcard_count, -len(pattern), index)
                incumbent = winners.get(concrete)
                if incumbent is None or score < incumbent[0]:
                    winners[concrete] = (score, index, action)

        root_winner = winners.get(())
        if root_winner is not None and root_winner[2] == "remove":
            raise RedactionConflict(
                "'remove' cannot target the whole document", root_winner[1], ""
            )

        remove_sentinel = object()
        hits: list[dict] = []

        def apply(node: Any, concrete: tuple[str, ...]) -> Any:
            winner = winners.get(concrete)
            if winner is not None:
                _score, index, action = winner
                pointer = _render_pointer(concrete)
                if action == "remove":
                    result: Any = remove_sentinel
                elif action == "mask":
                    result = MASK
                else:  # hash
                    try:
                        canonical = canonicalize(node)
                    except CanonicalizationError as exc:
                        raise RedactionError(
                            f"value cannot be hashed under RFC 8785: {exc}",
                            index,
                            pointer,
                        ) from exc
                    result = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                hits.append({"path": pointer, "action": action, "rule": index})
                # Terminal: the subtree has been replaced or removed, so no
                # rule targeting a descendant can apply.
                return result
            if isinstance(node, dict):
                rebuilt = {}
                for key, value in node.items():
                    child = apply(value, concrete + (key,))
                    if child is not remove_sentinel:
                        rebuilt[key] = child
                return rebuilt
            if isinstance(node, list):
                rebuilt = []
                for i, value in enumerate(node):
                    child = apply(value, concrete + (str(i),))
                    if child is not remove_sentinel:
                        rebuilt.append(child)
                return rebuilt
            return node

        result = apply(document, ())
    finally:
        sys.setrecursionlimit(previous_limit)
    hits.sort(key=lambda hit: _path_sort_key(hit["path"]))
    return result, hits
