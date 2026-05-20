from __future__ import annotations

from typing import Any, AsyncIterator, Protocol, runtime_checkable


@runtime_checkable
class Meddle(Protocol):
    async def get(self, keypath: str, requester: Any | None = None) -> Any: ...

    async def set(self, keypath: str, value: Any, requester: Any | None = None) -> Any | None: ...


@runtime_checkable
class Explore(Protocol):
    async def keys(self, requester: Any | None = None) -> list[str]: ...

    async def type_for_key(self, keypath: str, requester: Any | None = None) -> str | None: ...


@runtime_checkable
class Emit(Protocol):
    uuid: str
    name: str

    async def flow(self, requester: Any | None = None) -> AsyncIterator[Any]: ...

    async def admit(self, context: Any) -> str: ...

    async def advertise(self, requester: Any | None = None) -> dict[str, Any]: ...


@runtime_checkable
class Absorb(Protocol):
    async def attach(self, emitter: Emit, label: str, requester: Any | None = None) -> str: ...

    async def absorb_flow(self, label: str, requester: Any | None = None) -> None: ...

    async def detach(self, label: str, requester: Any | None = None) -> None: ...


@runtime_checkable
class GroupProtocol(Protocol):
    async def is_member(self, identity: Any, requester: Any | None = None) -> bool: ...


class CellProtocol(Absorb, Emit, Meddle, Explore, GroupProtocol, Protocol):
    pass
