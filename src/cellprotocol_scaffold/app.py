import asyncio
import os
from typing import Any

from cellprotocol.bridge import BridgeEndpoint, WebSocketBridgeSession
from cellprotocol.cells import EntityAnchorCell, GraphIndexCell, TrustedIssuersProxyCell, VaultCell
from cellprotocol.identity import InMemoryIdentityVault
from cellprotocol.resolver import CellResolver, CellUsageScope

from cellprotocol.interop import channel as channel_auth

from . import entity_anchor_data
from .bridge_auth import AuthenticatedBridgeSession
from .registry import ScaffoldRegistry


async def build_default_resolver(registry: ScaffoldRegistry | None = None) -> tuple[CellResolver, Any]:
    vault = InMemoryIdentityVault()
    owner = await vault.identity("scaffold", make_new_if_not_found=True)
    resolver = CellResolver()
    await resolver.register_named_emit_cell(
        "EntityAnchor",
        factory=lambda identity=None: EntityAnchorCell(owner=identity or owner),
        scope=CellUsageScope.identityUnique,
        identity=owner,
    )
    await resolver.register_named_emit_cell("Vault", emit_cell=VaultCell(owner=owner), scope=CellUsageScope.scaffoldUnique, identity=owner)
    await resolver.register_named_emit_cell("GraphIndex", emit_cell=GraphIndexCell(owner=owner), scope=CellUsageScope.scaffoldUnique, identity=owner)
    await resolver.register_named_emit_cell(
        "TrustedIssuers",
        emit_cell=TrustedIssuersProxyCell(owner=owner),
        scope=CellUsageScope.scaffoldUnique,
        identity=owner,
    )
    if registry is not None:
        await registry.register_with(resolver, owner=owner)
    return resolver, owner


def create_app(
    registry: ScaffoldRegistry | None = None,
    *,
    public_url: str | None = None,
    allow_insecure_loopback: bool | None = None,
    legacy_ready_bridge: bool | None = None,
) -> Any:
    """ASGI scaffold.

    `/bridgehead/...` requires org.haven.bridge-channel.v1 admission, like a
    Swift bridgehead. The signed audience is `public_url` + route, configured
    here or in `PYCELL_PUBLIC_URL` (for example `wss://node.example`), never
    taken from Host or Forwarded headers. Without it the bridge refuses.
    `legacy_ready_bridge` restores the old unauthenticated `ready` bridge for
    local tests with older Python peers only; Swift peers reject it.
    """
    public_url = public_url if public_url is not None else os.environ.get("PYCELL_PUBLIC_URL")
    if allow_insecure_loopback is None:
        allow_insecure_loopback = os.environ.get("PYCELL_ALLOW_INSECURE_LOOPBACK") == "1"
    if legacy_ready_bridge is None:
        legacy_ready_bridge = os.environ.get("PYCELL_LEGACY_READY_BRIDGE") == "1"
    try:
        from fastapi import FastAPI, Query, WebSocket
    except Exception as error:
        raise RuntimeError("cellprotocol_scaffold.create_app requires optional dependency 'fastapi'") from error

    app = FastAPI(title="PyCellProtocol Scaffold", version="0.1.0")
    state: dict[str, Any] = {"resolver": None, "owner": None, "lock": asyncio.Lock()}

    async def ensure() -> tuple[CellResolver, Any]:
        if state["resolver"] is None:
            async with state["lock"]:
                if state["resolver"] is None:
                    state["resolver"], state["owner"] = await build_default_resolver(registry)
        return state["resolver"], state["owner"]

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "service": "pycellprotocol-scaffold"}

    @app.get("/cells")
    async def cells() -> dict[str, Any]:
        resolver, owner = await ensure()
        named = await resolver.named_cells(owner)
        return {"cells": {name: await cell.advertise(owner) for name, cell in named.items()}}

    @app.get("/resolver")
    async def resolver_state() -> dict[str, Any]:
        resolver, _owner = await ensure()
        return {"remoteHosts": resolver.remote_host_snapshot()}

    @app.get("/entity-anchor-data/v1/contract")
    async def entity_anchor_contract() -> dict[str, Any]:
        return entity_anchor_data.contract()

    @app.get("/entity-anchor-data/v1/keypaths")
    async def entity_anchor_keypaths() -> dict[str, Any]:
        return entity_anchor_data.keypaths()

    @app.get("/entity-anchor-data/v1/autocomplete")
    async def entity_anchor_autocomplete(
        query: str = "",
        prefix: str = "",
        scope: str = "all",
        include_derived: bool = False,
        limit: int = Query(20, ge=1, le=50),
    ) -> dict[str, Any]:
        return entity_anchor_data.autocomplete(query, prefix, scope, include_derived, limit)

    @app.get("/entity-anchor-data/v1/sprout-map")
    async def entity_anchor_sprout_map() -> dict[str, Any]:
        return entity_anchor_data.sprout_map()

    @app.get("/entity-anchor-data/v1/schema")
    async def entity_anchor_schema() -> dict[str, Any]:
        return entity_anchor_data.json_schema()

    @app.websocket("/bridgehead/{first}/{second}")
    async def bridge_socket(websocket: WebSocket, first: str, second: str) -> None:
        resolver, owner = await ensure()
        endpoint_name = second if _looks_like_uuid(first) else first
        if legacy_ready_bridge:
            cell = await resolver.cell_at_endpoint(f"cell:///{endpoint_name}", owner)
            await WebSocketBridgeSession(websocket, BridgeEndpoint(cell, owner=owner)).run()
            return
        if not public_url:
            await websocket.close(code=1008)
            return
        try:
            channel_endpoint = channel_auth.Endpoint.from_url(
                public_url.rstrip("/") + f"/bridgehead/{first}/{second}",
                "bridge",
                allow_insecure_loopback=bool(allow_insecure_loopback),
            )
        except channel_auth.ChannelFailure:
            await websocket.close(code=1008)
            return

        async def open_endpoint(_admitted: channel_auth.AdmittedChannel) -> BridgeEndpoint:
            # Resolver lookup happens only after admission.
            cell = await resolver.cell_at_endpoint(f"cell:///{endpoint_name}", owner)
            return BridgeEndpoint(cell, owner=owner)

        await AuthenticatedBridgeSession(websocket, channel_endpoint, open_endpoint).run()

    return app


def _looks_like_uuid(value: str) -> bool:
    return len(value) >= 32 and value.count("-") in {0, 4}
