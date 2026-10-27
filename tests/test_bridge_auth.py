"""Authenticated bridge: Python client against the Python scaffold, over a real socket.

The handshake bytes themselves are pinned to the Swift vectors in
test_interop_channel.py; this file proves the transport wiring around them.
"""

import asyncio
import contextlib
import json
import socket

import pytest

pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")
websockets = pytest.importorskip("websockets")

from cellprotocol.bridge import BridgeCommand, BridgeTransportError, WebSocketBridgeClient
from cellprotocol.identity import InMemoryIdentityVault
from cellprotocol.interop import channel as auth
from cellprotocol_scaffold.app import create_app

ROUTE = "/bridgehead/00000000-0000-4000-8000-000000000001/Vault"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.asynccontextmanager
async def serve(**kwargs):
    port = _free_port()
    kwargs.setdefault("public_url", f"ws://127.0.0.1:{port}")
    kwargs.setdefault("allow_insecure_loopback", True)
    kwargs.setdefault("legacy_ready_bridge", False)
    server = uvicorn.Server(uvicorn.Config(create_app(**kwargs), host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.02)
    try:
        yield f"ws://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


async def _identity(name: str):
    identity = await InMemoryIdentityVault().identity(name, make_new_if_not_found=True)
    assert identity is not None
    return identity


def run(coro):
    return asyncio.run(coro)


def test_python_client_is_admitted_and_can_call_the_cell():
    async def scenario():
        alice = await _identity("alice")
        async with serve() as base:
            client = WebSocketBridgeClient(base + ROUTE, identity=alice, authenticate=True, allow_insecure_loopback=True, response_timeout=5)
            async with client:
                assert client.admitted_channel is not None
                assert client.admitted_channel.identity.uuid == alice.uuid
                description = await client.request("description")
                assert description["name"]

    run(scenario())


def test_ready_first_frame_is_refused_and_no_ready_is_ever_sent():
    async def scenario():
        async with serve() as base:
            async with websockets.connect(base + ROUTE) as ws:
                await ws.send(BridgeCommand("ready", cid=0).dumps())
                with pytest.raises(websockets.ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), timeout=5)

    run(scenario())


def test_command_before_admission_is_refused():
    async def scenario():
        alice = await _identity("alice")
        async with serve() as base:
            async with websockets.connect(base + ROUTE) as ws:
                await ws.send(BridgeCommand("description", cid=1, identity=alice).dumps())
                with pytest.raises(websockets.ConnectionClosed):
                    await asyncio.wait_for(ws.recv(), timeout=5)

    run(scenario())


def test_command_signed_for_another_identity_closes_the_channel():
    async def scenario():
        alice = await _identity("alice")
        mallory = await _identity("mallory")
        async with serve() as base:
            client = WebSocketBridgeClient(base + ROUTE, identity=alice, authenticate=True, allow_insecure_loopback=True, response_timeout=2)
            async with client:
                await client.send_untracked(BridgeCommand("description", cid=99, identity=mallory))
                with pytest.raises(BridgeTransportError):
                    await client.request("description")

    run(scenario())


def test_client_refuses_a_server_that_signs_for_another_audience():
    async def scenario():
        alice = await _identity("alice")
        port = _free_port()
        # The server believes it is a different host than the one dialled.
        async with serve(public_url="wss://other.example") as base:
            client = WebSocketBridgeClient(base + ROUTE, identity=alice, authenticate=True, allow_insecure_loopback=True, response_timeout=5)
            with pytest.raises(BridgeTransportError):
                await client.connect()
        _ = port

    run(scenario())


def test_bridge_without_public_url_refuses():
    async def scenario():
        async with serve(public_url="") as base:
            alice = await _identity("alice")
            client = WebSocketBridgeClient(base + ROUTE, identity=alice, authenticate=True, allow_insecure_loopback=True, response_timeout=5)
            with pytest.raises(BridgeTransportError):
                await client.connect()

    run(scenario())


def test_client_needs_the_owners_own_vault():
    async def scenario():
        from cellprotocol.identity import Identity

        alice = await _identity("alice")
        bare = Identity(uuid=alice.uuid, displayName="alice", publicSecureKey=alice.publicSecureKey)
        client = WebSocketBridgeClient("ws://127.0.0.1:1" + ROUTE, identity=bare, authenticate=True, allow_insecure_loopback=True, connect=lambda _u: _NullSocket())
        with pytest.raises(BridgeTransportError):
            await client.connect()

    run(scenario())


def test_plain_ws_needs_explicit_loopback_opt_in():
    with pytest.raises(auth.ChannelFailure):
        auth.Endpoint.from_url("ws://127.0.0.1:9000" + ROUTE, "bridge")
    with pytest.raises(auth.ChannelFailure):
        auth.Endpoint.from_url("ws://node.example" + ROUTE, "bridge", allow_insecure_loopback=True)


class _NullSocket:
    async def send(self, _text):
        return None

    async def recv(self):
        await asyncio.sleep(10)

    async def close(self):
        return None


def test_accepted_envelope_shape_matches_swift():
    # Every handshake frame is a cid-0 command carrying the body in "&string".
    body = json.loads(auth.envelope("channelAuthHello", {"a": 1}))
    assert body["cid"] == 0 and body["cmd"] == "channelAuthHello" and "&string" in body
