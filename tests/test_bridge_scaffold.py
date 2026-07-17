import asyncio

import pytest

from cellprotocol.bridge import BridgeCommand, BridgeEndpoint, BridgeTransportError, CloudBridgePublisherSession, WebSocketBridgeClient
from cellprotocol.general_cell import FlowElement, GeneralCell
from cellprotocol.identity import InMemoryIdentityVault
from cellprotocol.resolver import CellResolver, RemoteCellHostRoute, ResolverError
from cellprotocol.value import KeyValue, SetValueResponse, TypedValue
from cellprotocol_scaffold import entity_anchor_data


def run(coro):
    return asyncio.run(coro)


def test_bridge_endpoint_handles_get_set_description():
    async def scenario():
        cell = GeneralCell(name="Echo")
        endpoint = BridgeEndpoint(cell)

        set_response = await endpoint.handle(
            BridgeCommand("set", TypedValue("keyValue", KeyValue("state.value", "ok")), 1)
        )
        assert set_response[0].cmd == "response"
        assert isinstance(set_response[0].payload.value, SetValueResponse)
        assert set_response[0].payload.value.state == "ok"

        get_response = await endpoint.handle(BridgeCommand("get", TypedValue("string", "state.value"), 2))
        assert get_response[0].payload.value == "ok"

        description = await endpoint.handle(BridgeCommand("description", cid=3))
        assert description[0].payload.kind == "description"
        assert description[0].payload.value["name"] == "Echo"

    run(scenario())


def test_bridge_endpoint_handles_swift_aliases_state_agreement_and_lifecycle_commands():
    class LifecycleTestCell(GeneralCell):
        async def admit(self, context):
            _ = context
            return "connected"

        async def add_agreement(self, contract, identity):
            _ = contract, identity
            return "signed"

    async def scenario():
        owner = await InMemoryIdentityVault().identity("swift-requester")
        assert owner is not None
        cell = LifecycleTestCell(name="Lifecycle")
        endpoint = BridgeEndpoint(cell, owner=owner)

        set_response = await endpoint.handle(
            BridgeCommand("setValueForKeypath", TypedValue("keyValue", KeyValue("state.value", "alias-ok")), 1, owner)
        )
        assert set_response[0].payload.value.state == "ok"

        get_response = await endpoint.handle(
            BridgeCommand("valueForKeypath", TypedValue("string", "state.value"), 2, owner)
        )
        assert get_response[0].payload.value == "alias-ok"

        state_response = await endpoint.handle(BridgeCommand("state", cid=3, identity=owner))
        assert state_response[0].payload.value == {"value": "alias-ok"}

        admit_response = await endpoint.handle(BridgeCommand("admit", cid=4, identity=owner))
        assert admit_response[0].payload.kind == "connectState"
        assert admit_response[0].payload.value == "connected"

        agreement_response = await endpoint.handle(
            BridgeCommand("agreement", TypedValue("agreementPayload", {"uuid": "agreement-1"}), 5, owner)
        )
        assert agreement_response[0].payload.kind == "agreementState"
        assert agreement_response[0].payload.value == "signed"

        connect_response = await endpoint.handle(
            BridgeCommand(
                "connectEmitter",
                TypedValue("object", {"label": "remote", "publisher": {"uuid": "remote-1", "name": "Remote"}}),
                6,
                owner,
            )
        )
        assert connect_response[0].payload.kind == "connectState"
        assert connect_response[0].payload.value == "connected"

        status_response = await endpoint.handle(BridgeCommand("attachedStatus", TypedValue("string", "remote"), 7, owner))
        assert status_response[0].payload.value == "connected"

        assert await endpoint.handle(BridgeCommand("absorbFlow", TypedValue("string", "remote"), 8, owner)) == []
        assert await endpoint.handle(BridgeCommand("dropFlow", TypedValue("string", "remote"), 9, owner)) == []
        assert await endpoint.handle(BridgeCommand("removeConnecion", TypedValue("string", "remote"), 10, owner)) == []

        status_response = await endpoint.handle(BridgeCommand("attachedStatus", TypedValue("string", "remote"), 11, owner))
        assert status_response[0].payload.value == "notConnected"

        assert await endpoint.handle(BridgeCommand("disconnectAll", cid=12, identity=owner)) == []
        assert await endpoint.handle(BridgeCommand("unsubscribeAll", cid=13, identity=owner)) == []

    run(scenario())


def test_websocket_bridge_client_round_trips_commands_over_transport():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("python-cloudbridge")
        assert owner is not None
        fake_socket = FakeBridgeSocket(BridgeEndpoint(GeneralCell(name="Echo"), owner=owner))

        async def connect(url: str):
            assert url == "ws://example.test/bridgehead/Echo/client"
            return fake_socket

        client = WebSocketBridgeClient(
            "ws://example.test/bridgehead/Echo/client",
            identity=owner,
            connect=connect,
            response_timeout=1,
        )

        description = await client.request("description")
        assert description["name"] == "Echo"

        assert await client.set("state.value", "ok") is None
        assert await client.get("state.value") == "ok"

        sent = BridgeCommand.from_json(fake_socket.sent[0])
        assert sent.identity is not None
        assert sent.identity.uuid == owner.uuid
        await client.close()

    run(scenario())


def test_websocket_bridge_client_streams_feed_and_sends_lifecycle_commands():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("python-cloudbridge")
        assert owner is not None
        remote_cell = GeneralCell(name="Remote")
        fake_socket = FakeBridgeSocket(BridgeEndpoint(remote_cell, owner=owner))

        client = WebSocketBridgeClient(
            "ws://example.test/bridgehead/Remote/client",
            identity=owner,
            connect=lambda _url: fake_socket,
            response_timeout=1,
        )

        source = GeneralCell(name="Source")
        assert await client.attach(source, "source") == "connected"
        assert await client.attached_status("source") == "connected"
        await client.detach("source")
        assert await client.attached_status("source") == "notConnected"

        remote_cell.push_flow_element(FlowElement(title="Remote update", content={"value": 1}, topic="remote.update"))
        stream = client.flow(owner)
        element = await asyncio.wait_for(anext(stream), timeout=1)
        assert element.title == "Remote update"
        assert element.content == {"value": 1}

        await client.close()

    run(scenario())


def test_resolver_remote_cell_endpoint_uses_outbound_cloudbridge_transport():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("remote-requester")
        assert owner is not None
        urls: list[str] = []

        def bridge_factory(url: str, requester):
            urls.append(url)
            fake_socket = FakeBridgeSocket(BridgeEndpoint(GeneralCell(name="Remote"), owner=requester))
            return WebSocketBridgeClient(url, identity=requester, connect=lambda _url: fake_socket, response_timeout=1)

        resolver = CellResolver(allows_insecure_websockets=True, remote_bridge_factory=bridge_factory)
        resolver.register_remote_host("example.test", RemoteCellHostRoute(schemePreference="ws"))

        remote = await resolver.cell_at_endpoint("cell://example.test/Remote", owner)
        assert await remote.set("state.answer", 42) is None
        assert await remote.get("state.answer") == 42
        assert urls == [f"ws://example.test/bridgehead/Remote/{owner.uuid}"]

    run(scenario())


def test_resolver_rejects_direct_insecure_ws_without_dev_flag():
    async def scenario():
        resolver = CellResolver()
        with pytest.raises(ResolverError, match="Insecure ws transport is disabled"):
            await resolver.cell_at_endpoint("ws://example.test/bridgehead/Remote/client")

    run(scenario())


def test_websocket_bridge_client_surfaces_malformed_wire_payloads():
    async def scenario():
        client = WebSocketBridgeClient("wss://example.test/bridgehead/Broken/client", connect=lambda _url: MalformedSocket(), response_timeout=1)

        with pytest.raises(BridgeTransportError):
            await client.request("description")

        await client.close()

    run(scenario())


def test_cloudbridge_publisher_session_serves_python_cell_to_remote_bridgehead():
    async def scenario():
        vault = InMemoryIdentityVault()
        owner = await vault.identity("python-publisher")
        remote = await vault.identity("swift-bridgehead")
        assert owner is not None
        assert remote is not None

        cell = GeneralCell(name="PublishedPython")
        socket = ScriptedBridgeheadSocket()
        session = CloudBridgePublisherSession(
            "wss://swift.example.test/bridgehead/Porthole/PublishedPython",
            cell,
            owner=owner,
            connect=lambda _url: socket,
            response_timeout=1,
        )

        await session.start()
        ready = await socket.next_sent_command()
        assert ready.command == "ready"
        assert ready.identity is not None
        assert ready.identity.uuid == owner.uuid

        await socket.send_to_client(BridgeCommand("description", cid=11, identity=remote))
        description = await socket.next_sent_command()
        assert description.cmd == "response"
        assert description.cid == 11
        assert description.payload.kind == "description"
        assert description.payload.value["name"] == "PublishedPython"

        await socket.send_to_client(BridgeCommand("set", TypedValue("keyValue", KeyValue("state.value", "from-swift")), cid=12, identity=remote))
        set_response = await socket.next_sent_command()
        assert set_response.cid == 12
        assert set_response.payload.value.state == "ok"

        await socket.send_to_client(BridgeCommand("get", TypedValue("string", "state.value"), cid=13, identity=remote))
        get_response = await socket.next_sent_command()
        assert get_response.cid == 13
        assert get_response.payload.value == "from-swift"

        cell.push_flow_element(FlowElement(title="Published update", content={"value": "streamed"}))
        await socket.send_to_client(BridgeCommand("feed", cid=14, identity=remote))
        feed_response = await socket.next_sent_command()
        if feed_response.payload.value["title"] != "Published update":
            feed_response = await socket.next_sent_command()
        assert feed_response.cmd == "response"
        assert feed_response.cid == 14
        assert feed_response.payload.kind == "flowElement"
        assert feed_response.payload.value["title"] == "Published update"
        assert feed_response.payload.value["content"]["value"] == "streamed"

        await session.close()

    run(scenario())


def test_entity_anchor_data_is_static_value_free_and_autocompleteable():
    contract = entity_anchor_data.contract()
    assert contract["safety"]["expose_values"] is False
    assert "keypaths" in contract
    result = entity_anchor_data.autocomplete(query="identity", scope="sprout")
    paths = [item["path"] for item in result["suggestions"]]
    assert "proofs.identityLinks" in paths


class FakeBridgeSocket:
    def __init__(self, endpoint: BridgeEndpoint) -> None:
        self.endpoint = endpoint
        self.incoming: asyncio.Queue[str | None] = asyncio.Queue()
        self.sent: list[str] = []
        self.incoming.put_nowait(BridgeCommand("ready", cid=0).dumps())

    async def send(self, text: str) -> None:
        self.sent.append(text)
        command = BridgeCommand.from_json(text)
        if command.command == "feed":
            asyncio.create_task(self._pump_feed(command))
            return
        for response in await self.endpoint.handle(command):
            await self.incoming.put(response.dumps())

    async def _pump_feed(self, command: BridgeCommand) -> None:
        async for response in self.endpoint.feed_responses(command):
            await self.incoming.put(response.dumps())

    async def recv(self) -> str | None:
        return await self.incoming.get()

    async def close(self) -> None:
        await self.incoming.put(None)


class MalformedSocket:
    async def send(self, text: str) -> None:
        _ = text

    async def recv(self) -> str:
        return "{not-json"

    async def close(self) -> None:
        pass


class ScriptedBridgeheadSocket:
    def __init__(self) -> None:
        self.incoming: asyncio.Queue[str | None] = asyncio.Queue()
        self.sent: list[str] = []
        self.sent_queue: asyncio.Queue[str] = asyncio.Queue()
        self.incoming.put_nowait(BridgeCommand("ready", cid=0).dumps())

    async def send(self, text: str) -> None:
        self.sent.append(text)
        await self.sent_queue.put(text)

    async def recv(self) -> str | None:
        return await self.incoming.get()

    async def send_to_client(self, command: BridgeCommand) -> None:
        await self.incoming.put(command.dumps())

    async def next_sent_command(self) -> BridgeCommand:
        text = await asyncio.wait_for(self.sent_queue.get(), timeout=1)
        return BridgeCommand.from_json(text)

    async def close(self) -> None:
        await self.incoming.put(None)
