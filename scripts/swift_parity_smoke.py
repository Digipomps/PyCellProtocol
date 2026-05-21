#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import textwrap
from pathlib import Path
from typing import Any

from cellprotocol.bridge import BridgeCommand, BridgeEndpoint
from cellprotocol.cells import VaultCell
from cellprotocol.identity import Identity, InMemoryIdentityVault


ROOT = Path(__file__).resolve().parents[1]
CELLPROTOCOL = Path(os.environ.get("PY_CELL_SWIFT_CELLPROTOCOL_DIR", ROOT.parent / "CellProtocol")).expanduser().resolve()
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


async def main() -> int:
    if not CELLPROTOCOL.exists():
        raise RuntimeError(
            "CellProtocol checkout not found. Set PY_CELL_SWIFT_CELLPROTOCOL_DIR "
            "or place CellProtocol next to PyCellProtocol."
        )
    vault = InMemoryIdentityVault()
    owner = await vault.identity("python-scaffold", make_new_if_not_found=True)
    assert owner is not None
    endpoint = BridgeEndpoint(VaultCell(owner=owner), owner=owner)
    server = await asyncio.start_server(lambda r, w: websocket_client(r, w, endpoint), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    print(f"PY_PARITY_SERVER ws://127.0.0.1:{port}/bridgehead/Vault/<bridge-uuid>")
    try:
        package_dir = Path(os.environ.get("PY_CELL_SWIFT_SMOKE_DIR", "/private/tmp/pycell-swift-parity-smoke"))
        package_dir.mkdir(parents=True, exist_ok=True)
        write_swift_package(package_dir, port)
        env = os.environ.copy()
        env["CELL_PARITY_PORT"] = str(port)
        process = await asyncio.create_subprocess_exec(
            "arch",
            "-arm64",
            "swift",
            "run",
            "PyCellProtocolSwiftParitySmoke",
            cwd=package_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=180)
        print(stdout.decode("utf-8", errors="replace"))
        return process.returncode or 0
    finally:
        server.close()
        await server.wait_closed()


async def websocket_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, endpoint: BridgeEndpoint) -> None:
    try:
        request = await reader.readuntil(b"\r\n\r\n")
        headers = parse_headers(request.decode("latin1"))
        key = headers.get("sec-websocket-key")
        if not key:
            raise RuntimeError("missing Sec-WebSocket-Key")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        writer.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "\r\n"
            ).encode("ascii")
        )
        await writer.drain()
        await send_text(writer, BridgeCommand("ready", cid=0).dumps())
        while True:
            frame = await read_frame(reader)
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 0x8:
                await send_close(writer)
                return
            if opcode == 0x9:
                await send_frame(writer, 0xA, payload)
                continue
            if opcode not in {0x1, 0x2}:
                continue
            command = BridgeCommand.from_json(payload.decode("utf-8"))
            for response in await endpoint.handle(command):
                await send_text(writer, response.dumps())
    except (asyncio.IncompleteReadError, ConnectionError, RuntimeError):
        return
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes] | None:
    header = await reader.readexactly(2)
    first, second = header
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length)
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


async def send_text(writer: asyncio.StreamWriter, text: str) -> None:
    await send_frame(writer, 0x1, text.encode("utf-8"))


async def send_close(writer: asyncio.StreamWriter) -> None:
    await send_frame(writer, 0x8, b"")


async def send_frame(writer: asyncio.StreamWriter, opcode: int, payload: bytes) -> None:
    writer.write(encode_frame(opcode, payload))
    await writer.drain()


def encode_frame(opcode: int, payload: bytes) -> bytes:
    first = 0x80 | opcode
    if len(payload) < 126:
        return bytes([first, len(payload)]) + payload
    if len(payload) <= 0xFFFF:
        return bytes([first, 126]) + struct.pack("!H", len(payload)) + payload
    return bytes([first, 127]) + struct.pack("!Q", len(payload)) + payload


def write_swift_package(package_dir: Path, port: int) -> None:
    (package_dir / "Sources" / "PyCellProtocolSwiftParitySmoke").mkdir(parents=True, exist_ok=True)
    (package_dir / "Package.swift").write_text(
        textwrap.dedent(
            f"""
            // swift-tools-version:5.8
            import PackageDescription

            let package = Package(
                name: "PyCellProtocolSwiftParitySmoke",
                platforms: [.macOS(.v13)],
                dependencies: [
                    .package(path: "{CELLPROTOCOL}")
                ],
                targets: [
                    .executableTarget(
                        name: "PyCellProtocolSwiftParitySmoke",
                        dependencies: [
                            .product(name: "CellBase", package: "CellProtocol")
                        ]
                    )
                ]
            )
            """
        ).strip()
        + "\n"
    )
    (package_dir / "Sources" / "PyCellProtocolSwiftParitySmoke" / "main.swift").write_text(
        textwrap.dedent(
            f"""
            import Foundation
            import CellBase

            @main
            struct PyCellProtocolSwiftParitySmoke {{
                static func main() async throws {{
                    CellBase.webSocketSecurityPolicy = .developmentOnlyInsecureAllowed
                    CellBase.sendDataAsText = true

                    let resolver = CellResolver.sharedInstance
                    CellBase.defaultCellResolver = resolver
                    try await resolver.registerDefaultWebSocketBridgeTransports()
                    resolver.registerRemoteCellHost(
                        "127.0.0.1",
                        route: RemoteCellHostRoute(
                            websocketEndpoint: "bridgehead",
                            schemePreference: .ws,
                            pathLayout: .endpointThenPublisherUUID
                        )
                    )

                    let requester = Identity(
                        "00000000-0000-0000-0000-00000000BEEF",
                        displayName: "swift-parity-smoke",
                        identityVault: nil
                    )

                    let emit = try await resolver.cellAtEndpoint(
                        endpoint: "cell://127.0.0.1:{port}/Vault",
                        requester: requester
                    )
                    guard let meddle = emit as? Meddle else {{
                        throw SmokeError.notMeddle
                    }}

                    let created = try await meddle.set(
                        keypath: "vault.note.create",
                        value: .object([
                            "id": .string("swift-note"),
                            "title": .string("Swift smoke"),
                            "content": .string("Hello from Swift")
                        ]),
                        requester: requester
                    )
                    guard case let .object(createdObject)? = created,
                          case let .string(createdStatus)? = createdObject["status"],
                          createdStatus == "ok" else {{
                        throw SmokeError.unexpectedCreate(String(describing: created))
                    }}
                    let createdJson = try created?.jsonString() ?? "null"
                    print("SWIFT_CREATE_OK \\(createdJson)")

                    let state = try await meddle.get(keypath: "vault.state", requester: requester)
                    let stateJson = try state.jsonString()
                    guard case let .object(stateObject) = state,
                          case let .string(schemaVersion)? = stateObject["schemaVersion"],
                          schemaVersion == "haven.vault.state.v1",
                          case let .integer(noteCount)? = stateObject["noteCount"],
                          noteCount == 1 else {{
                        throw SmokeError.unexpectedState(stateJson)
                    }}
                    print("SWIFT_STATE_OK \\(stateJson)")
                    print("SWIFT_PARITY_SMOKE_OK")
                }}
            }}

            enum SmokeError: Error {{
                case notMeddle
                case unexpectedCreate(String)
                case unexpectedState(String)
            }}
            """
        ).strip()
        + "\n"
    )


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
