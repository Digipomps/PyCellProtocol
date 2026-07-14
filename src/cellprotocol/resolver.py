from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable
from urllib.parse import urlparse

from .bridge import BridgeBase
from .configuration import CellConfiguration, CellReference
from .general_cell import GeneralCell
from .identity import identity_signing_fingerprint
from .value import KeyValue


class ResolverError(RuntimeError):
    pass


class CellUsageScope(StrEnum):
    scaffoldUnique = "scaffoldUnique"
    template = "template"
    identityUnique = "identityUnique"


class Persistancy(StrEnum):
    persistant = "persistant"
    ephemeral = "ephemeral"


@dataclass
class RemoteCellHostRoute:
    websocketEndpoint: str = "bridgehead"
    schemePreference: str = "automatic"
    pathLayout: str = "endpointThenPublisherUUID"

    def websocket_scheme(self, allows_insecure: bool = False) -> str:
        if self.schemePreference == "automatic":
            return "ws" if allows_insecure else "wss"
        if self.schemePreference == "ws" and not allows_insecure:
            raise ResolverError("Insecure ws transport is disabled")
        if self.schemePreference not in {"ws", "wss"}:
            raise ResolverError(f"Unsupported websocket scheme: {self.schemePreference}")
        return self.schemePreference

    def bridge_path(self, endpoint: str, publisher_uuid: str) -> str:
        endpoint = endpoint.strip("/")
        if self.pathLayout == "publisherUUIDThenEndpoint":
            return f"/{self.websocketEndpoint}/{publisher_uuid}/{endpoint}"
        return f"/{self.websocketEndpoint}/{endpoint}/{publisher_uuid}"

    def bridge_url(self, host: str, endpoint: str, publisher_uuid: str, allows_insecure: bool = False) -> str:
        return f"{self.websocket_scheme(allows_insecure)}://{host}{self.bridge_path(endpoint, publisher_uuid)}"


@dataclass
class CellResolve:
    name: str
    emit_cell: Any | None = None
    factory: Callable[..., Any] | None = None
    scope: CellUsageScope = CellUsageScope.scaffoldUnique
    identity: Any | None = None
    persistancy: Persistancy = Persistancy.ephemeral

    _scaffold_instance: Any | None = None
    _identity_instances: dict[str, Any] | None = None
    _instance_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def resolve(self, requester: Any | None = None) -> Any:
        if self.scope == CellUsageScope.template:
            return await self._new_instance(requester)
        if self.scope == CellUsageScope.identityUnique:
            identity_key = _identity_cache_key(requester or self.identity)
            async with self._instance_lock:
                if self._identity_instances is None:
                    self._identity_instances = {}
                if identity_key not in self._identity_instances:
                    self._identity_instances[identity_key] = await self._new_instance(requester)
                return self._identity_instances[identity_key]
        async with self._instance_lock:
            if self._scaffold_instance is None:
                self._scaffold_instance = self.emit_cell or await self._new_instance(requester)
            return self._scaffold_instance

    async def _new_instance(self, requester: Any | None = None) -> Any:
        if self.factory is None:
            if self.emit_cell is not None:
                return self.emit_cell
            raise ResolverError(f"No cell factory registered for {self.name}")
        owner = requester or self.identity
        try:
            value = self.factory(owner)
        except TypeError:
            value = self.factory()
        if inspect.isawaitable(value):
            return await value
        return value


class CellResolver:
    def __init__(self, allows_insecure_websockets: bool = False) -> None:
        self.allows_insecure_websockets = allows_insecure_websockets
        self._named: dict[str, CellResolve] = {}
        self._uuid: dict[str, Any] = {}
        self._remote_hosts: dict[str, RemoteCellHostRoute] = {}
        self._remote_cache: dict[tuple[str, str], BridgeBase] = {}

    async def register_named_emit_cell(
        self,
        name: str,
        emit_cell: Any | None = None,
        scope: CellUsageScope | str = CellUsageScope.scaffoldUnique,
        identity: Any | None = None,
        factory: Callable[..., Any] | None = None,
        persistancy: Persistancy | str = Persistancy.ephemeral,
    ) -> None:
        if name in self._named:
            raise ResolverError(f"Cell name already registered: {name}")
        scope_value = CellUsageScope(scope)
        persistancy_value = Persistancy(persistancy)
        resolve = CellResolve(
            name=name,
            emit_cell=emit_cell,
            factory=factory,
            scope=scope_value,
            identity=identity,
            persistancy=persistancy_value,
        )
        self._named[name] = resolve
        if emit_cell is not None and getattr(emit_cell, "uuid", None):
            self._uuid[emit_cell.uuid] = emit_cell

    async def unregister_emit_cell(self, uuid: str) -> None:
        self._uuid.pop(uuid, None)
        for name, resolve in list(self._named.items()):
            if getattr(resolve.emit_cell, "uuid", None) == uuid:
                self._named.pop(name, None)

    def register_remote_host(self, host: str, route: RemoteCellHostRoute | None = None) -> None:
        self._remote_hosts[host] = route or RemoteCellHostRoute()

    def remote_host_snapshot(self) -> dict[str, dict[str, str]]:
        return {
            host: {
                "websocketEndpoint": route.websocketEndpoint,
                "schemePreference": route.schemePreference,
                "pathLayout": route.pathLayout,
            }
            for host, route in self._remote_hosts.items()
        }

    async def cell_at_endpoint(self, endpoint: str, requester: Any | None = None) -> Any:
        parsed = urlparse(endpoint)
        if parsed.scheme and parsed.scheme not in {"cell", "ws", "wss"}:
            raise ResolverError(f"Unsupported endpoint scheme: {parsed.scheme}")
        if parsed.scheme in {"ws", "wss"}:
            return self._remote_bridge(endpoint, requester)
        if parsed.scheme == "cell" and parsed.netloc:
            route = self._remote_hosts.get(parsed.netloc)
            if route is None:
                raise ResolverError(f"No remote host route registered for {parsed.netloc}")
            logical = parsed.path.strip("/")
            bridge_url = route.bridge_url(
                parsed.netloc,
                logical,
                getattr(requester, "uuid", "anonymous"),
                self.allows_insecure_websockets,
            )
            return self._remote_bridge(bridge_url, requester)
        name = _local_name(endpoint)
        if name in self._named:
            cell = await self._named[name].resolve(requester)
            if getattr(cell, "uuid", None):
                self._uuid[cell.uuid] = cell
            return cell
        if name in self._uuid:
            return self._uuid[name]
        raise ResolverError(f"No cell registered for endpoint: {endpoint}")

    async def named_cells(self, requester: Any | None = None) -> dict[str, Any]:
        return {name: await resolve.resolve(requester) for name, resolve in self._named.items()}

    async def load_cell(self, configuration: CellConfiguration, into: Any, requester: Any | None = None) -> list[Any]:
        loaded = []
        for reference in configuration.cellReferences:
            loaded.append(await self._load_reference(reference, into, requester))
        return loaded

    async def get_from_url(self, url: str, requester: Any | None = None) -> Any:
        endpoint, keypath = self._split_cell_url(url)
        cell = await self.cell_at_endpoint(endpoint, requester)
        return await cell.get(keypath, requester)

    async def set_into_url(self, value: Any, url: str, requester: Any | None = None) -> Any:
        endpoint, keypath = self._split_cell_url(url)
        cell = await self.cell_at_endpoint(endpoint, requester)
        return await cell.set(keypath, value, requester)

    async def _load_reference(self, reference: CellReference, into: Any, requester: Any | None = None) -> Any:
        target = await self.cell_at_endpoint(reference.endpoint, requester)
        label = reference.label or getattr(target, "name", reference.endpoint)
        if hasattr(into, "attach"):
            await into.attach(target, label, requester)
            if reference.subscribeFeed and hasattr(into, "absorb_flow"):
                await into.absorb_flow(label, requester)
        await self._apply_set_keys_and_values(reference, target, requester)
        for subscription in reference.subscriptions:
            await self._load_reference(subscription, target, requester)
        return target

    async def _apply_set_keys_and_values(self, reference: CellReference, target: Any, requester: Any | None) -> None:
        _ = reference
        for item in reference.setKeysAndValues:
            if not isinstance(item, dict):
                continue
            key_value = KeyValue.from_json(item)
            if key_value.value is not None:
                await target.set(key_value.key, key_value.value, requester)
                continue
            value = await target.get(key_value.key, requester)
            if key_value.target and key_value.target.startswith("cell://"):
                await self.set_into_url(value, key_value.target, requester)
            elif key_value.target:
                await target.set(key_value.target, value, requester)

    def _remote_bridge(self, bridge_url: str, requester: Any | None = None) -> BridgeBase:
        key = (bridge_url, _identity_cache_key(requester))
        if key not in self._remote_cache:
            self._remote_cache[key] = BridgeBase(identity=requester)
        return self._remote_cache[key]

    def _split_cell_url(self, url: str) -> tuple[str, str]:
        parsed = urlparse(url)
        if parsed.scheme != "cell":
            raise ResolverError(f"Expected cell URL, got {url}")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            raise ResolverError(f"Cell URL must include cell and keypath: {url}")
        keypath = parts[-1]
        cell_path = "/".join(parts[:-1])
        if parsed.netloc:
            return f"cell://{parsed.netloc}/{cell_path}", keypath
        return f"cell:///{cell_path}", keypath


def _local_name(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme == "cell":
        if parsed.netloc:
            raise ResolverError(f"Remote cell endpoint cannot be local: {endpoint}")
        return parsed.path.strip("/").split("/", 1)[0]
    return endpoint.strip("/").split("/", 1)[0]


def _identity_cache_key(identity: Any | None) -> str:
    if identity is None:
        return "anonymous"
    uuid = str(getattr(identity, "uuid", "anonymous"))
    fingerprint = identity_signing_fingerprint(identity)
    if fingerprint is None:
        raise ResolverError("Identity-scoped resolution requires a public signing key")
    return f"{uuid}:{fingerprint}"
