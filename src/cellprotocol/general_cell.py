from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
from uuid import uuid4

from .keypath import KeyPathError, get_keypath, set_keypath
from .value import JSONValue, from_json_value, to_json_value

GetHandler = Callable[[str, Any | None], Awaitable[Any]]
SetHandler = Callable[[str, Any, Any | None], Awaitable[Any | None]]


@dataclass
class FlowElement:
    title: str
    content: Any = None
    properties: dict[str, Any] = field(default_factory=lambda: {"type": "content", "contentType": "object"})
    topic: str | None = None
    origin: str | None = None
    id: str = field(default_factory=lambda: str(uuid4()))

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "FlowElement":
        return cls(
            title=str(payload.get("title", "")),
            content=from_json_value(payload.get("content")),
            properties=from_json_value(payload.get("properties", {})),
            topic=payload.get("topic") if isinstance(payload.get("topic"), str) else None,
            origin=payload.get("origin") if isinstance(payload.get("origin"), str) else None,
            id=payload.get("id") if isinstance(payload.get("id"), str) else str(uuid4()),
        )

    def to_json(self) -> dict[str, JSONValue]:
        output: dict[str, JSONValue] = {
            "id": self.id,
            "title": self.title,
            "content": to_json_value(self.content),
            "properties": to_json_value(self.properties),
        }
        if self.topic is not None:
            output["topic"] = self.topic
        if self.origin is not None:
            output["origin"] = self.origin
        return output


@dataclass
class Grant:
    keypath: str
    permission: str
    uuid: str = field(default_factory=lambda: str(uuid4()))
    name: str = "Condition grant"

    def to_json(self) -> dict[str, str]:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "keypath": self.keypath,
            "permission": self.permission,
        }


class AgreementTemplate:
    def __init__(self) -> None:
        self.grants: list[Grant] = []

    def add_grant(self, permission: str, keypath: str) -> None:
        self.grants.append(Grant(keypath=keypath, permission=permission))

    def to_json(self) -> dict[str, Any]:
        return {"grants": [grant.to_json() for grant in self.grants]}


class GeneralCell:
    """A pragmatic Python base cell with Swift-like async get/set/flow hooks."""

    cell_scope = "scaffoldUnique"
    persistancy = "ephemeral"

    def __init__(self, owner: Any | None = None, name: str | None = None, uuid: str | None = None) -> None:
        self.owner = owner
        self.uuid = uuid or str(uuid4())
        self.name = name or self.__class__.__name__.removesuffix("Cell")
        self.agreement_template = AgreementTemplate()
        self.identity_domain: str | None = None
        self._storage: dict[str, Any] = {}
        self._get_handlers: dict[str, GetHandler] = {}
        self._set_handlers: dict[str, SetHandler] = {}
        self._explore_contracts: dict[str, dict[str, Any]] = {}
        self._attached: dict[str, Any] = {}
        self._flow_queue: asyncio.Queue[FlowElement | None] = asyncio.Queue()

    async def add_get_handler(self, key: str, handler: GetHandler) -> None:
        self._get_handlers[key] = handler

    async def add_set_handler(self, key: str, handler: SetHandler) -> None:
        self._set_handlers[key] = handler

    async def register_explore_contract(
        self,
        key: str,
        method: str,
        input_schema: Any = None,
        returns: Any = None,
        permissions: list[str] | None = None,
        description: str | None = None,
    ) -> None:
        self._explore_contracts[key] = {
            "key": key,
            "method": method,
            "input": input_schema if input_schema is not None else {"type": "null"},
            "returns": returns if returns is not None else {"type": "unknown"},
            "permissions": permissions or [],
            "required": True,
            "description": description or "",
        }

    async def get(self, keypath: str, requester: Any | None = None) -> Any:
        handler = self._handler_for(keypath, self._get_handlers)
        if handler is not None:
            return await handler(keypath, requester)
        if keypath == "description":
            return await self.advertise(requester)
        if keypath == "keys":
            return await self.keys(requester)
        return get_keypath(self._storage, keypath)

    async def set(self, keypath: str, value: Any, requester: Any | None = None) -> Any | None:
        handler = self._handler_for(keypath, self._set_handlers)
        if handler is not None:
            return await handler(keypath, value, requester)
        set_keypath(self._storage, keypath, value)
        self.push_flow_element(
            FlowElement(
                title="Cell update",
                content={"keypath": keypath, "data": value},
                topic="cell.update",
                origin=self.uuid,
            )
        )
        return None

    async def keys(self, requester: Any | None = None) -> list[str]:
        keys = set(self._explore_contracts)
        keys.update(self._get_handlers)
        keys.update(self._set_handlers)
        keys.update(self._storage.keys())
        return sorted(keys)

    async def type_for_key(self, keypath: str, requester: Any | None = None) -> str | None:
        contract = self._explore_contracts.get(keypath)
        if contract:
            returns = contract.get("returns")
            if isinstance(returns, dict) and isinstance(returns.get("type"), str):
                return returns["type"]
        try:
            value = await self.get(keypath, requester)
        except Exception:
            return None
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "bool"
        if isinstance(value, int) and not isinstance(value, bool):
            return "integer"
        if isinstance(value, float):
            return "float"
        if isinstance(value, str):
            return "string"
        if isinstance(value, list):
            return "list"
        if isinstance(value, dict):
            return "object"
        return type(value).__name__

    async def attach(self, emitter: Any, label: str, requester: Any | None = None) -> str:
        self._attached[label] = emitter
        return "connected"

    async def absorb_flow(self, label: str, requester: Any | None = None) -> None:
        emitter = self._attached.get(label)
        if emitter is None:
            raise KeyPathError(f"No attached emitter with label {label}")

        async def pump() -> None:
            async for element in emitter.flow(requester):
                self.push_flow_element(element)

        asyncio.create_task(pump())

    async def detach(self, label: str, requester: Any | None = None) -> None:
        self._attached.pop(label, None)

    async def attached_status(self, label: str, requester: Any | None = None) -> str:
        return "connected" if label in self._attached else "notConnected"

    async def attached_statuses(self, requester: Any | None = None) -> dict[str, str]:
        return {label: "connected" for label in self._attached}

    async def flow(self, requester: Any | None = None) -> AsyncIterator[FlowElement]:
        while True:
            item = await self._flow_queue.get()
            if item is None:
                break
            yield item

    def push_flow_element(self, element: FlowElement) -> None:
        self._flow_queue.put_nowait(element)

    def push_completion(self) -> None:
        self._flow_queue.put_nowait(None)

    async def admit(self, context: Any) -> str:
        return "connected"

    async def add_agreement(self, contract: Any, identity: Any) -> str:
        return "signed"

    async def advertise(self, requester: Any | None = None) -> dict[str, Any]:
        owner_json = _identity_json(self.owner or requester)
        contract_template = {
            "uuid": str(uuid4()),
            "name": "Contract name here",
            "state": "template",
            "owner": owner_json,
            "signatories": [owner_json],
            "grants": [grant.to_json() for grant in self.agreement_template.grants],
            "duration": 60 * 60 * 24 * 365,
        }
        return {
            "uuid": self.uuid,
            "name": self.name,
            "cellScope": self.cell_scope,
            "persistancy": self.persistancy,
            "identityDomain": self.identity_domain or "",
            "contractTemplate": contract_template,
            "agreementTemplate": self.agreement_template.to_json(),
            "keys": await self.keys(requester),
        }

    async def is_member(self, identity: Any, requester: Any | None = None) -> bool:
        return bool(self.owner is None or identity is self.owner or getattr(identity, "uuid", None) == getattr(self.owner, "uuid", None))

    def _handler_for(self, keypath: str, handlers: dict[str, Any]) -> Any | None:
        candidates = [
            key
            for key in handlers
            if keypath == key or keypath.startswith(f"{key}.")
        ]
        if not candidates:
            return None
        return handlers[max(candidates, key=len)]

    async def validate_access(self, permission: str, keypath: str, requester: Any | None = None) -> bool:
        _ = permission, keypath, requester
        return True


def _identity_json(identity: Any | None) -> dict[str, Any]:
    if identity is not None and hasattr(identity, "to_json"):
        return identity.to_json()
    return {
        "uuid": getattr(identity, "uuid", "00000000-0000-0000-0000-000000000000"),
        "displayName": getattr(identity, "displayName", "Python Scaffold"),
        "properties": {},
    }
