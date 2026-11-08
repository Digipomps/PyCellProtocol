from __future__ import annotations

import asyncio
import copy

from .agreement import YEAR, Grant, covers, derive, issue, permission_masks, valid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
from uuid import NAMESPACE_URL, uuid4, uuid5

from .identity import Identity, proves_identity_control, same_identity_reference
from .keypath import KeyPathError, get_keypath, set_keypath
from .value import JSONValue, from_json_value, to_json_value

GetHandler = Callable[[str, Any | None], Awaitable[Any]]
SetHandler = Callable[[str, Any, Any | None], Awaitable[Any | None]]


class _ReentrantAsyncLock:
    """Serialize Cell operations while allowing same-task handler composition."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._owner: asyncio.Task[Any] | None = None
        self._depth = 0

    async def __aenter__(self) -> "_ReentrantAsyncLock":
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("Cell state access requires an asyncio task")
        if self._owner is task:
            self._depth += 1
            return self
        await self._lock.acquire()
        self._owner = task
        self._depth = 1
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        task = asyncio.current_task()
        if task is None or self._owner is not task or self._depth <= 0:
            raise RuntimeError("Cell state lock released by a non-owner task")
        self._depth -= 1
        if self._depth == 0:
            self._owner = None
            self._lock.release()


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


class AgreementTemplate:
    def __init__(self) -> None:
        self.grants: list[Grant] = []
        self.duration = YEAR
        self.conditions = []
        self.authorization_policy_binding = None

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
        self._contract_template_uuid = str(
            uuid5(NAMESPACE_URL, f"cellprotocol:{self.uuid}:contractTemplate")
        )
        self.name = name or self.__class__.__name__.removesuffix("Cell")
        self.agreement_template = AgreementTemplate()
        self.owner_published_reads = frozenset()
        self._contracts = {}
        self.identity_domain: str | None = None
        self._storage: dict[str, Any] = {}
        self._get_handlers: dict[str, GetHandler] = {}
        self._set_handlers: dict[str, SetHandler] = {}
        self._explore_contracts: dict[str, dict[str, Any]] = {}
        self._attached: dict[str, Any] = {}
        self._flow_tasks: dict[str, asyncio.Task[None]] = {}
        self._flow_queue: asyncio.Queue[FlowElement | None] = asyncio.Queue()
        self._state_lock = _ReentrantAsyncLock()

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
        if keypath == "description":
            return await self.advertise(requester)
        if keypath == "keys":
            return await self.keys(requester)
        async with self._state_lock:
            await self._require_access("r---", keypath, requester)
            handler = self._handler_for(keypath, self._get_handlers)
            if handler is not None:
                return await handler(keypath, requester)
            return get_keypath(self._storage, keypath)

    async def set(self, keypath: str, value: Any, requester: Any | None = None) -> Any | None:
        async with self._state_lock:
            await self._require_access("-w--", keypath, requester)
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
        await self._require_access("r---", "keys", requester)
        return self._declared_keys()

    def _declared_keys(self) -> list[str]:
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
        await self._require_access("--x-", label, requester)
        self._attached[label] = emitter
        return "connected"

    async def absorb_flow(self, label: str, requester: Any | None = None) -> None:
        await self._require_access("r---", label, requester)
        emitter = self._attached.get(label)
        if emitter is None:
            raise KeyPathError(f"No attached emitter with label {label}")
        await self.drop_flow(label, requester)

        async def pump() -> None:
            async for element in emitter.flow(requester):
                self.push_flow_element(element)

        self._flow_tasks[label] = asyncio.create_task(pump())

    async def detach(self, label: str, requester: Any | None = None) -> None:
        await self._require_access("--x-", label, requester)
        await self.drop_flow(label, requester)
        self._attached.pop(label, None)

    async def detach_all(self, requester: Any | None = None) -> None:
        await self.drop_all_flows(requester)
        self._attached.clear()

    async def drop_flow(self, label: str, requester: Any | None = None) -> None:
        _ = requester
        task = self._flow_tasks.pop(label, None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def drop_all_flows(self, requester: Any | None = None) -> None:
        for label in list(self._flow_tasks):
            await self.drop_flow(label, requester)

    async def attached_status(self, label: str, requester: Any | None = None) -> str:
        await self._require_access("r---", label, requester)
        return "connected" if label in self._attached else "notConnected"

    async def attached_statuses(self, requester: Any | None = None) -> dict[str, str]:
        await self._require_access("r---", "attachedStatuses", requester)
        return {label: "connected" for label in self._attached}

    async def flow(self, requester: Any | None = None) -> AsyncIterator[FlowElement]:
        await self._require_access("r---", "feed", requester)
        while True:
            item = await self._flow_queue.get()
            if item is None:
                break
            await self._require_access("r---", "feed", requester)
            yield item

    def push_flow_element(self, element: FlowElement) -> None:
        self._flow_queue.put_nowait(element)

    def push_completion(self) -> None:
        self._flow_queue.put_nowait(None)

    async def admit(self, context: Any) -> str:
        identity = context.get("identity") if isinstance(context, dict) else None
        if identity is None:
            return "notConnected"
        if self.owner is not None and await self.is_member(identity):
            return "connected"
        return "signContract"

    async def _prove(self, identity):
        return isinstance(identity, Identity) and await proves_identity_control(
            identity, identity
        )

    def _active_contracts(self, identity):
        if self.owner is None or not isinstance(identity, Identity):
            return []
        saved = self._contracts.get((identity.uuid, identity.publicSecureKey), {})
        return [
            c
            for c in saved.values()
            if valid(
                c,
                self.owner,
                identity,
                self.identity_domain or self.uuid,
                self._template(),
            )
        ]

    async def add_agreement(self, contract, identity, *, authorized_by=None):
        issuer = self.owner
        if issuer is None or not await self._prove(identity):
            return "rejected"
        authority = identity if authorized_by is None else authorized_by
        owner_approved = same_identity_reference(
            authority, issuer
        ) and await self._prove(authority)
        try:
            agreement = derive(contract, self._template(), issuer, identity)
        except (ValueError, TypeError, KeyError, AttributeError):
            return "rejected"

        def approved():
            return owner_approved or all(
                g["keypath"] in self.owner_published_reads
                and permission_masks(g["permission"]) == (4, 0)
                for g in agreement["grants"]
            )

        if not approved():
            return "rejected"
        try:
            signed = await issue(
                agreement, issuer, identity, self.identity_domain or self.uuid
            )
        except Exception:
            return "rejected"
        if not approved() or not valid(
            signed,
            self.owner,
            identity,
            self.identity_domain or self.uuid,
            self._template(),
        ):
            return "rejected"
        scope = tuple(
            sorted(
                {
                    (g["keypath"], permission_masks(g["permission"]))
                    for g in agreement["grants"]
                }
            )
        )
        self._contracts.setdefault((identity.uuid, identity.publicSecureKey), {})[
            scope
        ] = signed
        return "signed"

    async def contracts_for(self, identity):
        if not await self._prove(identity):
            raise PermissionError("Identity proof required")
        return copy.deepcopy(self._active_contracts(identity))

    def _template(self):
        owner_json = _identity_json(self.owner)
        template = {
            "uuid": self._contract_template_uuid,
            "name": "Contract name here",
            "state": "template",
            "owner": owner_json,
            "signatories": [owner_json],
            "grants": [grant.to_json() for grant in self.agreement_template.grants],
            "duration": self.agreement_template.duration,
        }
        if self.agreement_template.conditions:
            template["conditions"] = copy.deepcopy(self.agreement_template.conditions)
        if self.agreement_template.authorization_policy_binding is not None:
            template["authorizationPolicyBinding"] = copy.deepcopy(self.agreement_template.authorization_policy_binding)
        return template

    async def advertise(self, requester: Any | None = None) -> dict[str, Any]:
        contract_template = self._template()
        return {
            "uuid": self.uuid,
            "name": self.name,
            "cellScope": self.cell_scope,
            "persistancy": self.persistancy,
            "identityDomain": self.identity_domain or self.uuid,
            "contractTemplate": contract_template,
            "agreementTemplate": self.agreement_template.to_json(),
            "keys": self._declared_keys(),
        }

    async def is_member(self, identity: Any, requester: Any | None = None) -> bool:
        if self.owner is None:
            return True
        if requester is not None:
            await self._require_access("r---", "isMember", requester)
            return same_identity_reference(identity, self.owner) or bool(
                self._active_contracts(identity)
            )
        return await self._prove(identity) and (
            same_identity_reference(identity, self.owner)
            or bool(self._active_contracts(identity))
        )

    def _handler_for(self, keypath: str, handlers: dict[str, Any]) -> Any | None:
        candidates = [
            key for key in handlers if keypath == key or keypath.startswith(f"{key}.")
        ]
        if not candidates:
            return None
        return handlers[max(candidates, key=len)]

    async def validate_access(
        self, permission: str, keypath: str, requester: Any | None = None
    ) -> bool:
        if self.owner is None:
            return True
        if same_identity_reference(requester, self.owner):
            return await self._prove(requester) and same_identity_reference(
                requester, self.owner
            )
        if not self.has_contract_grant(permission, keypath, requester):
            return False
        return await self._prove(requester) and self.has_contract_grant(
            permission, keypath, requester
        )

    def has_contract_grant(self, permission, keypath, requester):
        """Check current grant state. Callers must separately prove the requester."""
        return any(
            covers(g, {"keypath": keypath, "permission": permission})
            for c in self._active_contracts(requester)
            for g in c["agreement"]["grants"]
        )

    async def _require_access(
        self, permission: str, keypath: str, requester: Any | None
    ) -> None:
        if not await self.validate_access(permission, keypath, requester):
            raise PermissionError(
                "Cell access denied: requester did not prove control of the owner identity"
            )


def _identity_json(identity: Any | None) -> dict[str, Any]:
    if isinstance(identity, Identity):
        encoded = identity.to_json()
        return {
            key: encoded[key]
            for key in (
                "uuid",
                "displayName",
                "publicSecureKey",
                "publicKeyAgreementSecureKey",
            )
            if key in encoded
        }
    output = {
        "uuid": getattr(identity, "uuid", "00000000-0000-0000-0000-000000000000"),
        "displayName": getattr(identity, "displayName", "Python Scaffold"),
    }
    return output
