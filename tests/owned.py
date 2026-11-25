"""Test helper: a cell with an owner, driven as that owner.

A cell without an owner denies every access (as Swift and Go), so tests that
only exercise a cell's logic create it with an owner and call it as the owner.
"""
from __future__ import annotations

from typing import Any

from cellprotocol.identity import InMemoryIdentityVault


class AsOwner:
    def __init__(self, cell: Any, owner: Any) -> None:
        object.__setattr__(self, "cell", cell)
        object.__setattr__(self, "owner", owner)

    async def set(self, keypath: str, value: Any, requester: Any | None = None) -> Any:
        return await self.cell.set(keypath, value, self.owner)

    async def get(self, keypath: str, requester: Any | None = None) -> Any:
        return await self.cell.get(keypath, self.owner)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.cell, name)


async def owned(cell_class: Any, *args: Any, **kwargs: Any) -> AsOwner:
    owner = await InMemoryIdentityVault().identity("owner")
    return AsOwner(cell_class(*args, owner=owner, **kwargs), owner)


def open_cell(cell_class: Any) -> Any:
    """A transport-test fixture: a cell that answers anyone.

    Only for tests of the wire itself (framing, cids, feeds). A wire identity
    cannot prove key control without an admitted channel, so a real owned cell
    would refuse these calls, which is what the access tests assert elsewhere.
    """

    class Open(cell_class):  # type: ignore[misc, valid-type]
        async def validate_access(self, permission: str, keypath: str, requester: Any | None = None) -> bool:
            return True

    Open.__name__ = f"Open{cell_class.__name__}"
    return Open


def owned_sync(make: Any) -> AsOwner:
    """As `owned`, outside an event loop: `make(owner)` builds the cell."""
    import asyncio

    owner = asyncio.run(InMemoryIdentityVault().identity("owner"))
    return AsOwner(make(owner), owner)
