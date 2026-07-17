from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
from dataclasses import dataclass
from typing import Any, AsyncIterator, Mapping

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

_DEFAULT_BRIDGE_IDENTITY = object()


class BridgeTransportError(RuntimeError):
    """Raised when an outbound bridge transport cannot send or receive safely."""


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
        # A wire identity is only a public reference. It is never upgraded to
        # the server owner and cannot prove control without an authenticated
        # challenge/session layer.
        requester = command.identity
        cid = command.cid
        try:
            match command.command:
                case "ready":
                    return []
                case "description":
                    return [BridgeCommand("response", TypedValue("description", await self.target.advertise(requester)), cid)]
                case "admit":
                    context = _payload_value(command.payload)
                    if context is None:
                        context = {}
                    return [BridgeCommand("response", TypedValue("connectState", await self.target.admit(context)), cid)]
                case "agreement":
                    if hasattr(self.target, "add_agreement"):
                        state = await self.target.add_agreement(_payload_value(command.payload), requester)
                    else:
                        state = "signed"
                    return [BridgeCommand("response", TypedValue("agreementState", state), cid)]
                case "feed":
                    return []
                case "state":
                    if hasattr(self.target, "state"):
                        value = await self.target.state(requester)
                    else:
                        value = await self.target.get("state", requester)
                    return [BridgeCommand("response", TypedValue.infer(value), cid)]
                case "emitter":
                    return [BridgeCommand("response", TypedValue("description", await self.target.advertise(requester)), cid)]
                case "get" | "valueForKeypath":
                    keypath = _payload_string(command.payload)
                    value = await self.target.get(keypath, requester)
                    return [BridgeCommand("response", TypedValue.infer(value), cid)]
                case "set" | "setValueForKeypath":
                    key_value = _payload_key_value(command.payload)
                    result = await self.target.set(key_value.key, key_value.value, requester)
                    return [
                        BridgeCommand(
                            "response",
                            TypedValue("setValueResponse", SetValueResponse.ok(result)),
                            cid,
                        )
                    ]
                case "connectEmitter":
                    label, emitter = _payload_connect_emitter(command.payload)
                    result = await self.target.attach(emitter, label, requester)
                    return [BridgeCommand("response", TypedValue("connectState", result), cid)]
                case "absorbFlow":
                    await _maybe_await(self.target.absorb_flow(_payload_string(command.payload), requester))
                    return []
                case "removeConnecion":
                    await _maybe_await(self.target.detach(_payload_string(command.payload), requester))
                    return []
                case "dropFlow":
                    if hasattr(self.target, "drop_flow"):
                        await _maybe_await(self.target.drop_flow(_payload_string(command.payload), requester))
                    return []
                case "disconnectAll":
                    if hasattr(self.target, "detach_all"):
                        await _maybe_await(self.target.detach_all(requester))
                    return []
                case "unsubscribeAll":
                    if hasattr(self.target, "drop_all_flows"):
                        await _maybe_await(self.target.drop_all_flows(requester))
                    return []
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
                    _ = _payload_bytes(command.payload)
                    raise PermissionError(
                        "Remote signing is unavailable until a validated purpose/audience/nonce/expiry challenge is implemented"
                    )
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

    async def feed_responses(self, command: BridgeCommand) -> AsyncIterator[BridgeCommand]:
        requester = command.identity or self.owner
        async for element in self.target.flow(requester):
            yield BridgeCommand("response", TypedValue("flowElement", element), command.cid)


class BridgeBase:
    """Outbound bridge proxy with cid-correlated request/response handling."""

    def __init__(self, send_command: Any | None = None, identity: Identity | None = None) -> None:
        self._send_command = send_command
        self.identity = identity
        self._cid = 0

    def _next_cid(self) -> int:
        self._cid += 1
        return self._cid

    async def request(
        self,
        cmd: str,
        payload: Any | None = None,
        requester: Identity | None = None,
        *,
        identity: Identity | None | object = _DEFAULT_BRIDGE_IDENTITY,
    ) -> Any:
        if self._send_command is None:
            raise RuntimeError("BridgeBase has no transport")
        command_identity = self.identity if identity is _DEFAULT_BRIDGE_IDENTITY else identity
        if requester is not None:
            command_identity = requester
        command = BridgeCommand(cmd=cmd, payload=payload, cid=self._next_cid(), identity=command_identity)
        response = await self._send_command(command)
        if isinstance(response, list):
            response = response[-1]
        if isinstance(response, BridgeCommand) and isinstance(response.payload, TypedValue):
            return response.payload.value
        return response

    async def get(self, keypath: str, requester: Identity | None = None) -> Any:
        return await self.request("get", TypedValue("string", keypath), requester=requester)

    async def set(self, keypath: str, value: Any, requester: Identity | None = None) -> Any:
        response = await self.request("set", TypedValue("keyValue", KeyValue(keypath, value)), requester=requester)
        if isinstance(response, SetValueResponse):
            if response.state != "ok":
                raise RuntimeError(response.value or response.state)
            return response.value
        return response

    async def admit(self, context: Any = None, requester: Identity | None = None) -> Any:
        payload = TypedValue("connectContext", context) if context is not None else None
        return await self.request("admit", payload, requester=requester)

    async def add_agreement(self, agreement: Any, requester: Identity | None = None) -> Any:
        return await self.request("agreement", TypedValue("agreementPayload", agreement), requester=requester)

    async def attach(self, emitter: Any, label: str, requester: Identity | None = None) -> Any:
        advertise = getattr(emitter, "advertise", None)
        publisher = await _maybe_await(advertise(requester or self.identity)) if advertise is not None else emitter
        return await self.request(
            "connectEmitter",
            TypedValue("object", {"label": label, "publisher": publisher}),
            requester=requester,
        )

    async def keys(self, requester: Identity | None = None) -> list[str]:
        response = await self.request("keys", requester=requester)
        return response if isinstance(response, list) else []

    async def type_for_key(self, keypath: str, requester: Identity | None = None) -> Any:
        return await self.request("typeForKey", TypedValue("string", keypath), requester=requester)

    async def attached_status(self, label: str, requester: Identity | None = None) -> Any:
        return await self.request("attachedStatus", TypedValue("string", label), requester=requester)

    async def attached_statuses(self, requester: Identity | None = None) -> Any:
        return await self.request("attachedStatuses", requester=requester)

    async def sign(self, identity: Identity, message: bytes) -> bytes:
        return await self.request(
            "sign",
            TypedValue("signData", message),
            identity=identity,
        )


class WebSocketBridgeClient(BridgeBase):
    """Outbound WebSocket transport for Swift-compatible bridgehead endpoints."""

    def __init__(
        self,
        url: str,
        identity: Identity | None = None,
        connect: Any | None = None,
        response_timeout: float = 30.0,
    ) -> None:
        super().__init__(send_command=self._send_command, identity=identity)
        self.url = url
        self.response_timeout = response_timeout
        self._connect_factory = connect
        self._websocket: Any | None = None
        self._connect_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._receiver_task: asyncio.Task[None] | None = None
        self._pending: dict[int, asyncio.Future[BridgeCommand]] = {}
        self._streams: dict[int, asyncio.Queue[BridgeCommand | None]] = {}
        self._ready_waiter: asyncio.Future[None] | None = None
        self.unhandled_commands: asyncio.Queue[BridgeCommand] = asyncio.Queue()

    @property
    def is_connected(self) -> bool:
        return self._websocket is not None and self._receiver_task is not None and not self._receiver_task.done()

    async def connect(self) -> "WebSocketBridgeClient":
        if self.is_connected:
            return self
        async with self._connect_lock:
            if self.is_connected:
                return self
            loop = asyncio.get_running_loop()
            self._ready_waiter = loop.create_future()
            self._websocket = await self._open_websocket()
            self._receiver_task = asyncio.create_task(self._receive_loop())
        try:
            await asyncio.wait_for(asyncio.shield(self._ready_waiter), timeout=self.response_timeout)
        except asyncio.TimeoutError as error:
            await self.close()
            raise BridgeTransportError(f"Timed out waiting for bridge ready at {self.url}") from error
        return self

    async def close(self) -> None:
        websocket = self._websocket
        if websocket is not None:
            close = getattr(websocket, "close", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    with contextlib.suppress(Exception):
                        await result
        task = self._receiver_task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._websocket = None
        self._receiver_task = None
        self._fail_pending(BridgeTransportError("WebSocket bridge closed"))
        self._close_streams()

    async def send_untracked(self, command: BridgeCommand) -> None:
        await self.connect()
        async with self._send_lock:
            await self._send_text(command.dumps())

    async def send_command(self, cmd: str, payload: Any | None = None, requester: Identity | None = None) -> int:
        command = BridgeCommand(cmd=cmd, payload=payload, cid=self._next_cid(), identity=requester or self.identity)
        await self.send_untracked(command)
        return command.cid

    async def absorb_flow(self, label: str, requester: Identity | None = None) -> None:
        await self.send_command("absorbFlow", TypedValue("string", label), requester=requester)

    async def detach(self, label: str, requester: Identity | None = None) -> None:
        await self.send_command("removeConnecion", TypedValue("string", label), requester=requester)

    async def drop_flow(self, label: str, requester: Identity | None = None) -> None:
        await self.send_command("dropFlow", TypedValue("string", label), requester=requester)

    async def detach_all(self, requester: Identity | None = None) -> None:
        await self.send_command("disconnectAll", requester=requester)

    async def drop_all_flows(self, requester: Identity | None = None) -> None:
        await self.send_command("unsubscribeAll", requester=requester)

    async def flow(self, requester: Identity | None = None) -> AsyncIterator[FlowElement]:
        await self.connect()
        cid = self._next_cid()
        queue: asyncio.Queue[BridgeCommand | None] = asyncio.Queue()
        self._streams[cid] = queue
        try:
            async with self._send_lock:
                await self._send_text(BridgeCommand("feed", cid=cid, identity=requester or self.identity).dumps())
            while True:
                response = await queue.get()
                if response is None:
                    return
                if isinstance(response.payload, TypedValue) and response.payload.kind == "flowElement":
                    yield _flow_element_from_payload(response.payload.value)
        finally:
            self._streams.pop(cid, None)

    async def __aenter__(self) -> "WebSocketBridgeClient":
        return await self.connect()

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        _ = exc_type, exc, traceback
        await self.close()

    async def _send_command(self, command: BridgeCommand) -> BridgeCommand:
        await self.connect()
        loop = asyncio.get_running_loop()
        future: asyncio.Future[BridgeCommand] = loop.create_future()
        self._pending[command.cid] = future
        try:
            async with self._send_lock:
                await self._send_text(command.dumps())
            return await asyncio.wait_for(future, timeout=self.response_timeout)
        except asyncio.TimeoutError as error:
            self._pending.pop(command.cid, None)
            raise BridgeTransportError(f"Timed out waiting for bridge response cid={command.cid}") from error
        except Exception:
            self._pending.pop(command.cid, None)
            raise

    async def _open_websocket(self) -> Any:
        connect = self._connect_factory
        if connect is None:
            connect = _load_websocket_connect()
        try:
            websocket = connect(self.url)
            if inspect.isawaitable(websocket):
                websocket = await websocket
            return websocket
        except Exception as error:
            raise BridgeTransportError(f"Failed to connect WebSocket bridge at {self.url}: {error}") from error

    async def _receive_loop(self) -> None:
        error: Exception | None = None
        try:
            while True:
                raw = await self._receive_text()
                if raw is None:
                    raise BridgeTransportError("WebSocket bridge closed without a close frame")
                command = BridgeCommand.from_json(raw)
                if command.command == "ready" and command.cid == 0:
                    self._mark_ready()
                    continue
                stream = self._streams.get(command.cid)
                if stream is not None:
                    await stream.put(command)
                    continue
                future = self._pending.pop(command.cid, None)
                if future is not None and not future.done():
                    future.set_result(command)
                else:
                    await self.unhandled_commands.put(command)
        except asyncio.CancelledError:
            raise
        except Exception as received_error:
            if isinstance(received_error, BridgeTransportError):
                error = received_error
            else:
                error = BridgeTransportError(f"WebSocket bridge receive failed: {received_error}")
        finally:
            if error is None:
                error = BridgeTransportError("WebSocket bridge closed")
            self._mark_ready(error)
            self._fail_pending(error)
            self._close_streams()
            self._websocket = None

    async def _send_text(self, text: str) -> None:
        websocket = self._require_websocket()
        send = getattr(websocket, "send", None) or getattr(websocket, "send_text", None)
        if send is None:
            raise BridgeTransportError("WebSocket object does not support send/send_text")
        result = send(text)
        if inspect.isawaitable(result):
            await result

    async def _receive_text(self) -> str | bytes | None:
        websocket = self._require_websocket()
        receive = getattr(websocket, "recv", None) or getattr(websocket, "receive_text", None)
        if receive is None:
            raise BridgeTransportError("WebSocket object does not support recv/receive_text")
        result = receive()
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, bytes):
            return result.decode("utf-8")
        if result is None or isinstance(result, str):
            return result
        raise BridgeTransportError(f"Unsupported WebSocket message type: {type(result).__name__}")

    def _require_websocket(self) -> Any:
        if self._websocket is None:
            raise BridgeTransportError("WebSocket bridge is not connected")
        return self._websocket

    def _mark_ready(self, error: Exception | None = None) -> None:
        waiter = self._ready_waiter
        if waiter is None or waiter.done():
            return
        if error is None:
            waiter.set_result(None)
        else:
            waiter.set_exception(error)

    def _fail_pending(self, error: Exception) -> None:
        for future in self._pending.values():
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

    def _close_streams(self) -> None:
        for queue in self._streams.values():
            queue.put_nowait(None)
        self._streams.clear()


class CloudBridge(WebSocketBridgeClient):
    """Python outbound bridge named after the Swift/Vapor CloudBridge role."""


class CloudBridgePublisherSession:
    """Connect to a Swift bridgehead and publish a local Python cell over it."""

    def __init__(
        self,
        url: str,
        target: Any,
        owner: Identity | None = None,
        connect: Any | None = None,
        response_timeout: float = 30.0,
    ) -> None:
        self.url = url
        self.owner = owner
        self.endpoint = BridgeEndpoint(target, owner=owner)
        self.bridge = CloudBridge(url, identity=owner, connect=connect, response_timeout=response_timeout)
        self._task: asyncio.Task[None] | None = None
        self._flow_tasks: set[asyncio.Task[None]] = set()
        self._stop: asyncio.Event | None = None

    async def start(self) -> "CloudBridgePublisherSession":
        await self.bridge.connect()
        await self.bridge.send_untracked(BridgeCommand("ready", cid=0, identity=self.owner))
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._serve_commands())
        return self

    async def run(self) -> None:
        await self.start()
        task = self._task
        if task is not None:
            await task

    async def close(self) -> None:
        if self._stop is not None:
            self._stop.set()
        for flow_task in list(self._flow_tasks):
            flow_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await flow_task
        self._flow_tasks.clear()
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._task = None
        await self.bridge.close()

    async def __aenter__(self) -> "CloudBridgePublisherSession":
        return await self.start()

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        _ = exc_type, exc, traceback
        await self.close()

    async def _serve_commands(self) -> None:
        while self._stop is not None and not self._stop.is_set():
            command = await self.bridge.unhandled_commands.get()
            if command.command == "ready":
                continue
            if command.command == "feed":
                task = asyncio.create_task(self._send_feed(command))
                self._flow_tasks.add(task)
                task.add_done_callback(self._flow_tasks.discard)
                continue
            for response in await self.endpoint.handle(command):
                await self.bridge.send_untracked(response)

    async def _send_feed(self, command: BridgeCommand) -> None:
        async for response in self.endpoint.feed_responses(command):
            await self.bridge.send_untracked(response)


def _load_websocket_connect() -> Any:
    try:
        from websockets.asyncio.client import connect

        return connect
    except Exception:
        try:
            from websockets import connect

            return connect
        except Exception as fallback_error:
            raise BridgeTransportError(
                "WebSocket bridge transport requires the optional 'websockets' package. "
                'Install with: python3 -m pip install -e ".[bridge]" or ".[scaffold]".'
            ) from fallback_error


class WebSocketBridgeSession:
    def __init__(self, websocket: Any, endpoint: BridgeEndpoint) -> None:
        self.websocket = websocket
        self.endpoint = endpoint
        self._flow_tasks: set[asyncio.Task[None]] = set()

    async def run(self) -> None:
        await self.websocket.accept()
        await self.websocket.send_text(BridgeCommand("ready", cid=0).dumps())
        try:
            while True:
                text = await self.websocket.receive_text()
                command = BridgeCommand.from_json(text)
                if command.command == "feed":
                    task = asyncio.create_task(self._send_feed(command))
                    self._flow_tasks.add(task)
                    task.add_done_callback(self._flow_tasks.discard)
                    continue
                for response in await self.endpoint.handle(command):
                    await self.websocket.send_text(response.dumps())
        finally:
            for flow_task in list(self._flow_tasks):
                flow_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await flow_task
            self._flow_tasks.clear()

    async def _send_feed(self, command: BridgeCommand) -> None:
        async for response in self.endpoint.feed_responses(command):
            await self.websocket.send_text(response.dumps())


class _RemoteEmitterDescription:
    def __init__(self, description: Mapping[str, Any]) -> None:
        self.description = dict(description)
        self.uuid = str(description.get("uuid") or "")
        self.name = str(description.get("name") or self.uuid or "RemoteEmitter")

    async def advertise(self, requester: Identity | None = None) -> dict[str, Any]:
        _ = requester
        return dict(self.description)

    async def flow(self, requester: Identity | None = None) -> AsyncIterator[FlowElement]:
        _ = requester
        if False:
            yield FlowElement(title="")


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


def _payload_value(payload: Any) -> Any:
    if isinstance(payload, TypedValue):
        return payload.value
    return payload


def _payload_connect_emitter(payload: Any) -> tuple[str, Any]:
    payload = _payload_value(payload)
    if not isinstance(payload, Mapping):
        raise ValueError("Expected connectEmitter object payload")
    label = payload.get("label")
    if isinstance(label, TypedValue):
        label = label.value
    if not isinstance(label, str):
        raise ValueError("connectEmitter payload requires string label")
    publisher = payload.get("publisher")
    if isinstance(publisher, TypedValue):
        publisher = publisher.value
    if isinstance(publisher, Mapping):
        return label, _RemoteEmitterDescription(publisher)
    return label, publisher


def _payload_bytes(payload: Any) -> bytes:
    if isinstance(payload, TypedValue):
        payload = payload.value
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return json.dumps(to_json_value(payload), sort_keys=True).encode("utf-8")


def _flow_element_from_payload(payload: Any) -> FlowElement:
    if isinstance(payload, FlowElement):
        return payload
    if isinstance(payload, Mapping):
        return FlowElement.from_json(dict(payload))
    return FlowElement(title="Bridge feed", content=payload)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


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
