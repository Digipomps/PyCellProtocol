"""Authenticated inbound bridge for the Python scaffold.

Speaks `org.haven.bridge-channel.v1` (see `cellprotocol.interop.channel`) before
any Cell command, the way a Swift bridgehead does: no `ready` frame, no command
before admission, and every later command must carry the admitted public key.

Admission proves control of a key. It grants no Cell permission: the Cell's own
authorization still decides what that key may read or write, and Python's
owner-proof boundary stays fail-closed until the origin-proof callback exists.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
from typing import Any, Awaitable, Callable, Optional

from cellprotocol.bridge import BridgeCommand, BridgeEndpoint
from cellprotocol.identity import Identity
from cellprotocol.interop import channel as auth

PolicyCheck = Callable[[auth.PublicIdentity], None]


def public_identity(identity: Optional[Identity]) -> Optional[auth.PublicIdentity]:
    """The minimal public principal of a wire identity, or None if it has no key."""
    if identity is None or not identity.publicSecureKey:
        return None
    try:
        key = base64.b64decode(identity.publicSecureKey, validate=True)
    except ValueError:
        raise auth.ChannelFailure("identityMismatch", "unreadable public key")
    return auth.PublicIdentity(uuid=identity.uuid, public_key=key)


class AuthenticatedBridgeSession:
    """One WebSocket connection: admission first, then commands for one Cell.

    `open_endpoint` runs only after admission (the Swift factory rule) and gets
    the proven principal, never wire-supplied metadata.
    """

    def __init__(
        self,
        websocket: Any,
        channel_endpoint: auth.Endpoint,
        open_endpoint: Callable[[auth.AdmittedChannel], Awaitable[BridgeEndpoint]],
        *,
        recheck_policy: Optional[PolicyCheck] = None,
        server: Optional[auth.ChannelServer] = None,
    ) -> None:
        self.websocket = websocket
        self.server = server or auth.ChannelServer(channel_endpoint, recheck_policy=recheck_policy)
        self._open_endpoint = open_endpoint
        self._flow_tasks: set[asyncio.Task[None]] = set()
        self.admitted: Optional[auth.AdmittedChannel] = None
        self.failure: Optional[str] = None

    async def run(self) -> None:
        await self.websocket.accept()
        try:
            await self._admit()
            assert self.admitted is not None
            try:
                endpoint = await self._open_endpoint(self.admitted)
            except Exception:
                # Same answer for "no such Cell" and "not allowed": unavailable.
                self.failure = "unavailable"
                return
            await self._serve(endpoint)
        except auth.ChannelFailure as failure:
            self.failure = failure.code
        finally:
            for task in list(self._flow_tasks):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            self._flow_tasks.clear()
            with contextlib.suppress(Exception):
                await self.websocket.close()

    async def _receive_frame(self) -> str:
        """One frame as text. Swift's VaporBridgeTransport sends binary frames, Python and Go send text."""
        message = await self.websocket.receive()
        if message.get("type") == "websocket.disconnect":
            raise ConnectionError(f"disconnected ({message.get('code')})")
        if message.get("text") is not None:
            return message["text"]
        data = message.get("bytes")
        if data is None:
            raise auth.ChannelFailure("malformed")
        return data.decode("utf-8")

    async def _admit(self) -> None:
        deadline = auth.PRE_AUTH_DEADLINE
        while self.server.state != "authenticated":
            try:
                text = await asyncio.wait_for(self._receive_frame(), timeout=deadline)
            except asyncio.TimeoutError as error:
                raise auth.ChannelFailure("expired") from error
            reply = self.server.receive(text.encode("utf-8"))
            await self.websocket.send_text(reply.decode("utf-8"))
        self.admitted = self.server.admitted

    def _check(self, command: BridgeCommand) -> None:
        assert self.admitted is not None
        if command.cmd.startswith("channelAuth") or command.command == "ready":
            raise auth.ChannelFailure("unexpectedMessage")
        self.admitted.check_identity(public_identity(command.identity), required=command.command != "response")

    async def _serve(self, endpoint: BridgeEndpoint) -> None:
        while True:
            try:
                text = await self._receive_frame()
            except Exception:
                # Peer went away (WebSocketDisconnect or transport error).
                return
            try:
                command = BridgeCommand.from_json(text)
            except Exception as error:
                raise auth.ChannelFailure("malformed") from error
            self._check(command)
            if command.command == "feed":
                task = asyncio.create_task(self._send_feed(endpoint, command))
                self._flow_tasks.add(task)
                task.add_done_callback(self._flow_tasks.discard)
                continue
            for response in await endpoint.handle(command):
                assert self.admitted is not None
                self.admitted.check()
                await self.websocket.send_text(response.dumps())

    async def _send_feed(self, endpoint: BridgeEndpoint, command: BridgeCommand) -> None:
        async for response in endpoint.feed_responses(command):
            if self.admitted is None:
                return
            try:
                self.admitted.check()
            except auth.ChannelFailure:
                return
            await self.websocket.send_text(response.dumps())
