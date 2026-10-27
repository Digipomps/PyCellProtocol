"""Python peer for the cross-language interop matrix (`haven.interop-peer.v1`).

Run with `python -m cellprotocol_scaffold.interop_peer`. The matrix runner
(`interop/matrix/run_matrix.py`) starts one peer per party and sends one JSON
object per line on stdin; the peer answers one line on stdout:
`{"ok": true, "result": ...}` or `{"ok": false, "error": "..."}`. The protocol
is described in `interop/matrix/README.md`; the Go and Swift peers speak the
same one.
"""

import asyncio
import json
import sys
import threading
import time
from typing import Any

from cellprotocol.bridge import WebSocketBridgeClient
from cellprotocol.cells import EntityScaffoldExtensionCell
from cellprotocol.cells.chat import ChatCell
from cellprotocol.cells.entity_anchor import descriptor_for
from cellprotocol.cells.invitation import InvitationCell
from cellprotocol.identity import InMemoryIdentityVault
from cellprotocol.resolver import CellUsageScope

PROTOCOL = "haven.interop-peer.v1"


class Refused(Exception):
    """A refusal the runner sees as ok: false."""


def _refusal(result: Any) -> str | None:
    """Bridge answers carry refusals as {state: error}; normalise them."""
    state = getattr(result, "state", None)
    value = getattr(result, "value", None)
    if isinstance(result, dict):
        state, value = result.get("state"), result.get("value")
    if state == "error":
        return str(value)
    return None


class Peer:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.me = None
        self.cells: dict[str, Any] = {}
        self.bridges: dict[str, WebSocketBridgeClient] = {}
        self.server = None

    def run(self, coro: Any, timeout: float = 20) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    # ---- ops ------------------------------------------------------------------

    def op_hello(self, _: dict) -> Any:
        return {"lang": "python", "protocol": PROTOCOL}

    def op_init(self, msg: dict) -> Any:
        vault = InMemoryIdentityVault()
        self.me = self.run(vault.identity(msg.get("name") or "peer", make_new_if_not_found=True))
        key = vault._private_signing_keys[self.me.uuid]
        self.signer = key.sign
        self.descriptor = descriptor_for(self.me)
        self.cells = {
            "home": ChatCell(owner=self.me),
            "extension": EntityScaffoldExtensionCell(owner=self.me, descriptor=self.descriptor, signer=self.signer, display_name=self.me.displayName),
        }
        return {"identity": self.me.to_json(), "descriptor": self.descriptor.to_wire()}

    def op_invitation(self, msg: dict) -> Any:
        self.cells["invitation"] = InvitationCell(
            owner=self.me,
            descriptor=self.descriptor,
            signer=self.signer,
            display_name=self.me.displayName,
            landing_base=msg.get("landingBase", ""),
            contact_endpoint_id=msg.get("contactEndpointID") or None,
        )
        return {"cell": "invitation"}

    def op_serve(self, msg: dict) -> Any:
        import uvicorn

        from .app import create_app
        from .invite_landing import InviteLanding

        port = int(msg["port"])
        chat = ChatCell(owner=self.me, topic=msg.get("topic") or "chat")
        self.cells["chat"] = chat

        class Registry:
            async def register_with(self, resolver: Any, owner: Any = None) -> None:
                await resolver.register_named_emit_cell("Chat", emit_cell=chat, scope=CellUsageScope.scaffoldUnique, identity=owner)

        app = create_app(
            Registry(),
            public_url=f"ws://127.0.0.1:{port}",
            allow_insecure_loopback=True,
            invite_landing=InviteLanding(rate_limit=False),
        )
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        threading.Thread(target=self.server.run, daemon=True).start()
        for _ in range(100):
            if self.server.started:
                break
            time.sleep(0.05)
        return {"landingBase": f"http://127.0.0.1:{port}", "chatURL": f"ws://127.0.0.1:{port}/bridgehead/{chat.uuid}/Chat"}

    def op_admit(self, msg: dict) -> Any:
        """Swift's owner signs an Agreement here; this ChatCell admits by the verified acceptance."""
        return {"admittedBy": "acceptance"}

    def op_call(self, msg: dict) -> Any:
        cell = self.cells.get(msg["cell"])
        if cell is None:
            raise Refused(f"no cell {msg['cell']}")
        if msg.get("method") == "get":
            coro = cell.get(msg["key"], self.me)
        else:
            coro = cell.set(msg["key"], msg.get("value"), self.me)
        try:
            return self.run(coro)
        except PermissionError as error:
            raise Refused(str(error)) from error

    def op_remote(self, msg: dict) -> Any:
        url = msg["url"]

        async def call() -> Any:
            bridge = self.bridges.get(url)
            if bridge is None:
                bridge = WebSocketBridgeClient(url, identity=self.me, authenticate=True, allow_insecure_loopback=True, response_timeout=10)
                await bridge.connect()
                self.bridges[url] = bridge
            if msg.get("method") == "get":
                return await bridge.get(msg["key"], self.me)
            return await bridge.set(msg["key"], msg.get("value"), self.me)

        result = self.run(call())
        refusal = _refusal(result)
        if refusal is not None:
            raise Refused(refusal)
        return result


def _jsonable(value: Any) -> Any:
    if hasattr(value, "to_wire"):
        return value.to_wire()
    if hasattr(value, "to_json"):
        return value.to_json()
    return value


def main() -> None:
    peer = Peer()
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        handler = getattr(peer, "op_" + str(msg.get("op")), None)
        try:
            if handler is None:
                raise Refused(f"unknown op {msg.get('op')}")
            reply = {"ok": True, "result": handler(msg)}
        except Exception as error:  # noqa: BLE001 - every failure goes back to the runner as data
            reply = {"ok": False, "error": f"{type(error).__name__}: {error}"}
        sys.stdout.write(json.dumps(reply, default=_jsonable) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
