from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, MutableMapping

from .value import JSONValue, from_json_value


class KeyPathError(KeyError):
    pass


@dataclass(frozen=True)
class AppendToken:
    pass


@dataclass(frozen=True)
class MatchToken:
    key: str
    value: Any


Token = str | int | AppendToken | MatchToken


def _parse_literal(raw: str) -> Any:
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1]
    if text == "true":
        return True
    if text == "false":
        return False
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def parse_keypath(path: str) -> list[Token]:
    path = path.strip()
    if not path:
        return []
    tokens: list[Token] = []
    segment = ""
    index = 0
    while index < len(path):
        char = path[index]
        if char == ".":
            if segment:
                tokens.append(segment)
                segment = ""
            index += 1
            continue
        if char == "[":
            if segment:
                tokens.append(segment)
                segment = ""
            end = path.find("]", index)
            if end == -1:
                raise KeyPathError(f"Invalid keypath bracket: {path}")
            content = path[index + 1 : end].strip()
            if content == "+":
                tokens.append(AppendToken())
            elif "=" in content:
                key, raw_value = content.split("=", 1)
                tokens.append(MatchToken(key.strip(), _parse_literal(raw_value)))
            else:
                try:
                    tokens.append(int(content))
                except ValueError as error:
                    raise KeyPathError(f"Invalid list index '{content}' in {path}") from error
            index = end + 1
            continue
        segment += char
        index += 1
    if segment:
        tokens.append(segment)
    return tokens


def _empty_for_next(next_token: Token | None) -> Any:
    if isinstance(next_token, (int, AppendToken, MatchToken)):
        return []
    return {}


def _ensure_list_slot(target: list[Any], index: int, next_token: Token | None) -> Any:
    while len(target) <= index:
        target.append(_empty_for_next(next_token))
    if target[index] is None:
        target[index] = _empty_for_next(next_token)
    return target[index]


def _find_match(target: list[Any], token: MatchToken, create: bool, next_token: Token | None) -> Any:
    for item in target:
        if isinstance(item, MutableMapping) and item.get(token.key) == token.value:
            return item
    if not create:
        raise KeyPathError(f"No item matching [{token.key}={token.value!r}]")
    item = {token.key: token.value}
    target.append(item)
    return item


def get_keypath(root: Any, path: str | Iterable[Token]) -> JSONValue:
    tokens = list(parse_keypath(path) if isinstance(path, str) else path)
    current = root
    for token in tokens:
        if isinstance(token, AppendToken):
            raise KeyPathError("Cannot get append token '[+]'")
        if isinstance(token, int):
            if not isinstance(current, list) or token < 0 or token >= len(current):
                raise KeyPathError(f"List index not found: {token}")
            current = current[token]
        elif isinstance(token, MatchToken):
            if not isinstance(current, list):
                raise KeyPathError("Match token requires a list")
            current = _find_match(current, token, create=False, next_token=None)
        else:
            if not isinstance(current, MutableMapping) or token not in current:
                raise KeyPathError(f"Key not found: {token}")
            current = current[token]
    return from_json_value(current)


def set_keypath(root: Any, path: str | Iterable[Token], value: Any) -> Any:
    tokens = list(parse_keypath(path) if isinstance(path, str) else path)
    if not tokens:
        return from_json_value(value)
    current = root
    for index, token in enumerate(tokens[:-1]):
        next_token = tokens[index + 1]
        following = tokens[index + 2] if index + 2 < len(tokens) else None
        if isinstance(token, int):
            if not isinstance(current, list):
                raise KeyPathError("List index requires a list")
            current = _ensure_list_slot(current, token, next_token)
        elif isinstance(token, AppendToken):
            if not isinstance(current, list):
                raise KeyPathError("Append token requires a list")
            item = _empty_for_next(next_token)
            current.append(item)
            current = item
        elif isinstance(token, MatchToken):
            if not isinstance(current, list):
                raise KeyPathError("Match token requires a list")
            current = _find_match(current, token, create=True, next_token=next_token)
        else:
            if not isinstance(current, MutableMapping):
                raise KeyPathError("Object key requires an object")
            if token not in current or current[token] is None:
                current[token] = _empty_for_next(next_token)
            if isinstance(next_token, MatchToken) and not isinstance(current[token], list):
                current[token] = []
            current = current[token]
        _ = following

    final = tokens[-1]
    encoded = from_json_value(value)
    if isinstance(final, int):
        if not isinstance(current, list):
            raise KeyPathError("List index requires a list")
        _ensure_list_slot(current, final, None)
        current[final] = encoded
    elif isinstance(final, AppendToken):
        if not isinstance(current, list):
            raise KeyPathError("Append token requires a list")
        current.append(encoded)
    elif isinstance(final, MatchToken):
        if not isinstance(current, list):
            raise KeyPathError("Match token requires a list")
        item = _find_match(current, final, create=True, next_token=None)
        if isinstance(encoded, MutableMapping):
            item.update(encoded)
        else:
            idx = current.index(item)
            current[idx] = encoded
    else:
        if not isinstance(current, MutableMapping):
            raise KeyPathError("Object key requires an object")
        current[final] = encoded
    return root
