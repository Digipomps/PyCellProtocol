"""Byte-exact reproduction of the Swift canonical signing payload.

Swift signs `JSONSerialization.data(withJSONObject:options:[.sortedKeys])` of
the `JSONEncoder` output (see `CanonicalPayloadEncoder` in CellProtocol). Two
details make that different from `json.dumps(sort_keys=True)`:

* Foundation sorts keys like `NSString.compare` with numeric, case-insensitive
  and forced-ordering options, so `requestID` sorts after `requestedScopes`.
* `/` is escaped as `\\/`, and non-ASCII text is written as raw UTF-8.

`JSONEncoder` with `.sortedKeys` (the wire JSON, the ticket token and the
signed bridge challenge) sorts keys in plain code-point order instead, so it
puts `requestID` before `requestedDomains`. Pass `key_order="encoder"` for that.

The golden fixtures in `fixtures/interop/v1` (CellProtocol) are the authority.
"""

from __future__ import annotations

import functools
import math
import re
from typing import Any, Iterable, Mapping

_TOKEN = re.compile(r"\d+|\D")


class CanonicalEncodingError(ValueError):
    """Raised for values Foundation's JSONSerialization would refuse."""


def _compare_keys(left: str, right: str) -> int:
    """Foundation key order: numeric runs as numbers, letters case-insensitive.

    Ties under that order fall back to plain code-point order, which is what
    `.forcedOrdering` guarantees: a total, stable order.
    """
    left_tokens = _TOKEN.findall(left)
    right_tokens = _TOKEN.findall(right)
    for a, b in zip(left_tokens, right_tokens):
        if a.isdigit() and b.isdigit():
            if int(a) != int(b):
                return -1 if int(a) < int(b) else 1
            continue
        fa, fb = a.casefold(), b.casefold()
        if fa != fb:
            return -1 if fa < fb else 1
    if len(left_tokens) != len(right_tokens):
        return -1 if len(left_tokens) < len(right_tokens) else 1
    if left == right:
        return 0
    return -1 if left < right else 1


foundation_key = functools.cmp_to_key(_compare_keys)


def sorted_keys(keys: Iterable[str]) -> list[str]:
    return sorted(keys, key=foundation_key)


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "/": "\\/",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _string(value: str, escape_slashes: bool = True) -> str:
    out = ['"']
    for char in value:
        if char == "/" and not escape_slashes:
            out.append(char)
            continue
        escaped = _ESCAPES.get(char)
        if escaped is not None:
            out.append(escaped)
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _number(value: int | float) -> str:
    if isinstance(value, bool):  # pragma: no cover - guarded by caller
        raise CanonicalEncodingError("bool is not a number")
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise CanonicalEncodingError("Foundation refuses NaN and infinity")
    if value.is_integer() and abs(value) < 2**53:
        return str(int(value))
    return repr(value)


def _write(value: Any, out: list[str], key_order: str = "foundation", escape_slashes: bool = True) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, (int, float)):
        out.append(_number(value))
    elif isinstance(value, str):
        out.append(_string(value, escape_slashes))
    elif isinstance(value, Mapping):
        out.append("{")
        if not all(isinstance(key, str) for key in value.keys()):
            raise CanonicalEncodingError("object keys must be strings")
        keys = sorted(value.keys()) if key_order == "encoder" else sorted_keys(value.keys())
        for index, key in enumerate(keys):
            if index:
                out.append(",")
            out.append(_string(key, escape_slashes))
            out.append(":")
            _write(value[key], out, key_order, escape_slashes)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out, key_order, escape_slashes)
        out.append("]")
    else:
        raise CanonicalEncodingError(f"cannot encode {type(value).__name__}")


def canonical_json(value: Any, key_order: str = "foundation", escape_slashes: bool = True) -> bytes:
    """Encode a JSON value exactly like Foundation with `.sortedKeys`.

    `key_order="foundation"` is `JSONSerialization` (what signatures cover);
    `key_order="encoder"` is `JSONEncoder` (code-point order).
    `escape_slashes=False` is `JSONEncoder` with `.withoutEscapingSlashes`,
    used by the bridge channel authentication envelopes.
    """
    if key_order not in ("foundation", "encoder"):
        raise ValueError(f"unknown key order {key_order}")
    out: list[str] = []
    _write(value, out, key_order, escape_slashes)
    return "".join(out).encode("utf-8")


def canonical_payload(wire: Mapping[str, Any], excluding: Iterable[str] = ()) -> bytes:
    """The bytes a Swift `CanonicalPayloadSignable` signs: drop top-level keys, encode."""
    excluded = set(excluding)
    return canonical_json({key: item for key, item in wire.items() if key not in excluded})
