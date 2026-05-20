from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .configuration import CellConfiguration, CellReference
from .general_cell import FlowElement
from .identity import Identity
from .value import (
    KeyValue,
    SetValueResponse,
    TypedValue,
    from_json_value,
    payload_from_bridge_json,
    to_json_value,
)


COMMANDS = {
    "ready",
    "description",
    "admit",
    "agreement",
    "feed",
    "state",
    "emitter",
    "valueForKeypath",
    "setValueForKeypath",
    "get",
    "set",
    "connectEmitter",
    "absorbFlow",
    "removeConnecion",
    "dropFlow",
    "disconnectAll",
    "unsubscribeAll",
    "attachedStatus",
    "attachedStatuses",
    "keys",
    "typeForKey",
    "sign",
    "response",
    "none",
}


@dataclass
class BridgeCommand:
    cmd: str
    payload: Any | None = None
    cid: int = 0
    identity: Identity | None = None

    @property
    def command(self) -> str:
        return self.cmd if self.cmd in COMMANDS else "none"

    @classmethod
    def from_json(cls, payload: str | bytes | Mapping[str, Any]) -> "BridgeCommand":
        if isinstance(payload, (str, bytes)):
            payload = json.loads(payload)
        cmd = payload.get("cmd")
        if not isinstance(cmd, str):
            raise ValueError("BridgeCommand requires string field 'cmd'")
        cid = payload.get("cid")
        if not isinstance(cid, int):
            raise ValueError("BridgeCommand requires integer field 'cid'")
        identity = None
        if isinstance(payload.get("identity"), Mapping):
            identity = Identity.from_json(dict(payload["identity"]))
        typed_payload = None
        for key in TypedValue.DECODE_PRIORITY:
            if key in payload:
                typed_payload = payload_from_bridge_json(key, payload[key])
                break
        return cls(cmd=cmd, cid=cid, identity=identity, payload=typed_payload)

    def to_json(self) -> dict[str, Any]:
        output: dict[str, Any] = {"cmd": self.cmd, "cid": self.cid}
        if self.identity is not None:
            output["identity"] = self.identity.to_json()
        if self.payload is not None:
            typed = TypedValue.infer(self.payload)
            if typed.kind != "null":
                output[typed.bridge_key] = typed.bridge_payload_json()
        return output

    def dumps(self) -> str:
        return json.dumps(self.to_json(), separators=(",", ":"), sort_keys=True)


class BridgeEndpoint:
    """Command handler for a local cell exposed over a Swift-compatible bridge."""

    def __init__(self, target: Any, owner: Identity | None = None) -> None:
        self.target = target
        self.owner = owner

    async def handle(self, command: BridgeCommand) -> list[BridgeCommand]:
        requester = command.identity or self.owner
        cid = command.cid
        try:
            match command.command:
                case "ready":
                    return [BridgeCommand("ready", cid=cid)]
                case "description":
                    return [BridgeCommand("response", TypedValue("description", await self.target.advertise(requester)), cid)]
                case "admit":
                    return [BridgeCommand("response", TypedValue("connectState", await self.target.admit(command.payload)), cid)]
                case "agreement":
                    return [BridgeCommand("response", TypedValue("agreementState", "signed"), cid)]
                case "get":
                    keypath = _payload_string(command.payload)
                    value = await self.target.get(keypath, requester)
                    return [BridgeCommand("response", TypedValue.infer(value), cid)]
                case "set":
                    key_value = _payload_key_value(command.payload)
                    result = await self.target.set(key_value.key, key_value.value, requester)
                    return [
                        BridgeCommand(
                            "response",
                            TypedValue("setValueResponse", SetValueResponse.ok(result)),
                            cid,
                        )
                    ]
                case "keys":
                    return [BridgeCommand("response", TypedValue("list", await self.target.keys(requester)), cid)]
                case "typeForKey":
                    keypath = _payload_string(command.payload)
                    return [
                        BridgeCommand(
                            "response",
                            TypedValue("string", await self.target.type_for_key(keypath, requester) or "unknown"),
                            cid,
                        )
                    ]
                case "attachedStatus":
                    keypath = _payload_string(command.payload)
                    return [BridgeCommand("response", TypedValue("string", await self.target.attached_status(keypath, requester)), cid)]
                case "attachedStatuses":
                    return [BridgeCommand("response", TypedValue("object", await self.target.attached_statuses(requester)), cid)]
                case "sign":
                    message = _payload_bytes(command.payload)
                    if requester is None:
                        raise RuntimeError("sign requires identity")
                    signature = await requester.sign(message)
                    return [BridgeCommand("response", TypedValue("signature", signature), cid)]
                case _:
                    return [BridgeCommand("response", TypedValue("string", f"unsupported command: {command.cmd}"), cid)]
        except Exception as error:
            return [
                BridgeCommand(
                    "response",
                    TypedValue("setValueResponse", SetValueResponse.error(str(error))),
                    cid,
                )
            ]


class BridgeBase:
    """Outbound bridge proxy with cid-correlated request/response handling."""

    def __init__(self, send_command: Any | None = None, identity: Identity | None = None) -> None:
        self._send_command = send_command
        self.identity = identity
        self._cid = 0

    async def request(self, cmd: str, payload: Any | None = None) -> Any:
        if self._send_command is None:
            raise RuntimeError("BridgeBase has no transport")
        self._cid += 1
        command = BridgeCommand(cmd=cmd, payload=payload, cid=self._cid, identity=self.identity)
        response = await self._send_command(command)
        if isinstance(response, list):
            response = response[-1]
        if isinstance(response, BridgeCommand) and isinstance(response.payload, TypedValue):
            return response.payload.value
        return response

    async def get(self, keypath: str, requester: Identity | None = None) -> Any:
        _ = requester
        return await self.request("get", TypedValue("string", keypath))

    async def set(self, keypath: str, value: Any, requester: Identity | None = None) -> Any:
        _ = requester
        response = await self.request("set", TypedValue("keyValue", KeyValue(keypath, value)))
        if isinstance(response, SetValueResponse):
            if response.state != "ok":
                raise RuntimeError(response.value or response.state)
            return response.value
        return response

    async def sign(self, identity: Identity, message: bytes) -> bytes:
        previous = self.identity
        self.identity = identity
        try:
            result = await self.request("sign", TypedValue("signData", message))
        finally:
            self.identity = previous
        return result


class WebSocketBridgeSession:
    def __init__(self, websocket: Any, endpoint: BridgeEndpoint) -> None:
        self.websocket = websocket
        self.endpoint = endpoint

    async def run(self) -> None:
        await self.websocket.accept()
        await self.websocket.send_text(BridgeCommand("ready", cid=0).dumps())
        while True:
            text = await self.websocket.receive_text()
            command = BridgeCommand.from_json(text)
            for response in await self.endpoint.handle(command):
                await self.websocket.send_text(response.dumps())


def _payload_string(payload: Any) -> str:
    if isinstance(payload, TypedValue):
        payload = payload.value
    if not isinstance(payload, str):
        raise ValueError("Expected string payload")
    return payload


def _payload_key_value(payload: Any) -> KeyValue:
    if isinstance(payload, TypedValue):
        payload = payload.value
    if isinstance(payload, KeyValue):
        return payload
    if isinstance(payload, Mapping):
        return KeyValue.from_json(payload)
    raise ValueError("Expected KeyValue payload")


def _payload_bytes(payload: Any) -> bytes:
    if isinstance(payload, TypedValue):
        payload = payload.value
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return json.dumps(to_json_value(payload), sort_keys=True).encode("utf-8")


def decode_configuration_payload(payload: Any) -> CellConfiguration:
    if isinstance(payload, TypedValue):
        payload = payload.value
    if not isinstance(payload, Mapping):
        raise ValueError("Expected CellConfiguration object")
    return CellConfiguration.from_json(payload)


def decode_cell_reference_payload(payload: Any) -> CellReference:
    if isinstance(payload, TypedValue):
        payload = payload.value
    if not isinstance(payload, Mapping):
        raise ValueError("Expected CellReference object")
    return CellReference.from_json(payload)
