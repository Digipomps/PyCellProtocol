from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, ClassVar, Mapping, MutableMapping

JSONValue = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]


class CodecError(ValueError):
    """Raised when a value cannot be represented with the CellProtocol wire codec."""


def stable_json_dumps(value: Any) -> str:
    return json.dumps(to_json_value(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def to_json_value(value: Any) -> JSONValue:
    if isinstance(value, TypedValue):
        return to_json_value(value.value)
    if hasattr(value, "to_json") and callable(value.to_json):
        return value.to_json()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list) or isinstance(value, tuple):
        return [to_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): to_json_value(item) for key, item in value.items()}
    raise CodecError(f"Cannot encode {type(value).__name__} as a CellProtocol JSON value")


def from_json_value(value: Any) -> JSONValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [from_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): from_json_value(item) for key, item in value.items()}
    raise CodecError(f"Cannot decode {type(value).__name__} as a CellProtocol JSON value")


@dataclass(frozen=True)
class TypedValue:
    """A Swift `ValueType` case where the bridge needs an explicit wire key."""

    kind: str
    value: Any

    BRIDGE_KEYS: ClassVar[dict[str, str]] = {
        "description": "&description",
        "connectState": "&connectState",
        "agreementState": "&agreementState",
        "agreementPayload": "&agreementPayload",
        "verifiableCredential": "&verifiableCredential",
        "cellConfiguration": "&cellConfiguration",
        "cellReference": "&cellReference",
        "connectContext": "&connectContext",
        "flowElement": "&flowElement",
        "cell": "&cell",
        "keyValue": "&keyValue",
        "setValueState": "&setValueState",
        "setValueResponse": "&setValueResponse",
        "signData": "sign",
        "signature": "&signature",
        "object": "&object",
        "number": "&number",
        "string": "&string",
        "list": "&list",
        "bool": "bool",
        "float": "float",
        "data": "data",
        "integer": "integer",
    }
    DECODE_PRIORITY: ClassVar[list[str]] = [
        "&agreementPayload",
        "&description",
        "&connectState",
        "&agreementState",
        "&verifiableCredential",
        "&flowElement",
        "&object",
        "&list",
        "&string",
        "&number",
        "float",
        "data",
        "bool",
        "integer",
        "&cellReference",
        "&cellConfiguration",
        "&cell",
        "&keyValue",
        "&setValueState",
        "&setValueResponse",
        "sign",
        "&signature",
        "connectEmitter",
        "absorbFlow",
        "removeConnecion",
        "dropFlow",
        "disconnectAll",
        "unsubscribeAll",
        "keys",
        "typeForKey",
    ]

    @classmethod
    def infer(cls, value: Any) -> "TypedValue":
        if isinstance(value, TypedValue):
            return value
        if isinstance(value, bool):
            return cls("bool", value)
        if isinstance(value, int) and not isinstance(value, bool):
            return cls("integer", value)
        if isinstance(value, float):
            return cls("float", value)
        if isinstance(value, str):
            return cls("string", value)
        if isinstance(value, bytes):
            return cls("data", value)
        if isinstance(value, list):
            return cls("list", value)
        if isinstance(value, Mapping):
            return cls("object", value)
        if value is None:
            return cls("null", None)
        if isinstance(value, KeyValue):
            return cls("keyValue", value)
        if isinstance(value, SetValueResponse):
            return cls("setValueResponse", value)
        return cls("object", to_json_value(value))

    @classmethod
    def bridge_key_to_kind(cls, key: str) -> str:
        for kind, bridge_key in cls.BRIDGE_KEYS.items():
            if bridge_key == key:
                return kind
        return key

    @property
    def bridge_key(self) -> str:
        if self.kind == "null":
            raise CodecError("null payloads are omitted from BridgeCommand JSON")
        try:
            return self.BRIDGE_KEYS[self.kind]
        except KeyError as error:
            raise CodecError(f"Unknown typed value kind: {self.kind}") from error

    def bridge_payload_json(self) -> JSONValue:
        if self.kind == "data" and isinstance(self.value, bytes):
            return base64.b64encode(self.value).decode("ascii")
        return to_json_value(self.value)


@dataclass
class KeyValue:
    key: str
    value: Any | None = None
    target: str | None = None

    _ENCODE_KEYS: ClassVar[dict[type, str]] = {
        str: "string",
        int: "integer",
        float: "float",
        list: "list",
        dict: "object",
    }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "KeyValue":
        key = payload.get("key")
        if not isinstance(key, str):
            raise CodecError("KeyValue requires string field 'key'")
        target = payload.get("target")
        if target is not None and not isinstance(target, str):
            raise CodecError("KeyValue field 'target' must be a string when present")
        value: Any | None = None
        present = False
        for field in ("string", "number", "float", "integer", "object", "list"):
            if field in payload:
                value = from_json_value(payload[field])
                present = True
                break
        if not present and "value" in payload:
            value = from_json_value(payload["value"])
        return cls(key=key, value=value, target=target)

    def to_json(self) -> dict[str, JSONValue]:
        output: dict[str, JSONValue] = {"key": self.key}
        if self.target is not None:
            output["target"] = self.target
        value = self.value
        if isinstance(value, TypedValue):
            value = value.value
        if isinstance(value, dict):
            output["object"] = to_json_value(value)
        elif isinstance(value, list):
            output["list"] = to_json_value(value)
        elif isinstance(value, str):
            output["string"] = value
        elif isinstance(value, int) and not isinstance(value, bool):
            output["integer"] = value
        elif isinstance(value, float):
            output["float"] = value
        elif value is not None:
            output["value"] = to_json_value(value)
        return output


@dataclass
class SetValueResponse:
    state: str
    value: Any | None = None

    VALID_STATES: ClassVar[set[str]] = {"ok", "denied", "paramErr", "error"}

    @classmethod
    def ok(cls, value: Any | None = None) -> "SetValueResponse":
        return cls("ok", value)

    @classmethod
    def error(cls, value: Any | None = None) -> "SetValueResponse":
        return cls("error", value)

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "SetValueResponse":
        state = payload.get("state")
        if state not in cls.VALID_STATES:
            raise CodecError("SetValueResponse requires a valid 'state'")
        return cls(state=state, value=from_json_value(payload["value"]) if "value" in payload else None)

    def to_json(self) -> dict[str, JSONValue]:
        output: dict[str, JSONValue] = {"state": self.state}
        if self.value is not None:
            output["value"] = to_json_value(self.value)
        return output


def payload_from_bridge_json(key: str, value: Any) -> TypedValue:
    kind = TypedValue.bridge_key_to_kind(key)
    if kind == "keyValue":
        return TypedValue(kind, KeyValue.from_json(value))
    if kind == "setValueResponse":
        return TypedValue(kind, SetValueResponse.from_json(value))
    if kind == "data":
        if isinstance(value, str):
            return TypedValue(kind, base64.b64decode(value.encode("ascii")))
        raise CodecError("Bridge data payload must be base64 string")
    return TypedValue(kind, from_json_value(value))


def merge_json_object(target: MutableMapping[str, Any], patch: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), MutableMapping):
            merge_json_object(target[key], value)
        else:
            target[key] = from_json_value(value)
    return target
