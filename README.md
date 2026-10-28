# PyCellProtocol

Python v1 implementation of the HAVEN CellProtocol core contracts.

This repository intentionally keeps two installable import packages in one repo:

- `cellprotocol`: protocol types, wire codecs, resolver, bridge primitives, identity/vault interfaces, and built-in cells.
- `cellprotocol_scaffold`: ASGI scaffold, bridge routes, diagnostics, EntityAnchorData v1, decorators, and CLI.

The first priority is Swift wire compatibility. Python names may be pleasant to use, but JSON payloads, command names, resolver scopes, keypaths, and failure behavior must remain compatible with the Swift implementation.

## Current security boundary

Identity signing uses Ed25519 private keys held by the identity vault; an
identity UUID is never signing material. Owned Cells require a fresh
private-key control proof for local `get`, `set`, key inspection, flow, and
attachment operations. Caller-supplied Agreements still fail closed because
Python does not yet implement Swift's owner-approved Agreement admission.

The ASGI bridge speaks `org.haven.bridge-channel.v1`, the admission handshake
current Swift bridgeheads require: the client signs a purpose-, audience-,
nonce- and expiry-bound challenge with its vault key, the server never sends a
`ready` frame, nothing reaches a Cell before admission, and every later
command must carry the admitted public key. Admission proves control of a key
and grants no Cell permission; protected reads and writes stay denied until
Agreement admission and the origin-proof callback exist. The signed audience is
the configured public URL (`--public-url` / `PYCELL_PUBLIC_URL`, for example
`wss://node.example`), never the Host header; without it the bridge refuses.
`ws://` needs `--allow-insecure-loopback` and a loopback host.
`PYCELL_LEGACY_READY_BRIDGE=1` restores the old unauthenticated bridge for
local tests with older Python peers only. Outbound, use
`WebSocketBridgeClient(url, identity, authenticate=True)`.

Ownerless Cells are intentionally local/public and should not carry private
state. These limitations are release boundaries, not claims of full Swift
security or persistence parity.

## Quick Check

```bash
python3 -m pytest
```

Optional scaffold runtime dependencies are installed with:

```bash
python3 -m pip install -e ".[scaffold]"
pycell scaffold serve --host 127.0.0.1 --port 8080
```

Outbound bridge-only dependencies can be installed with:

```bash
python3 -m pip install -e ".[bridge]"
```

Remote `cell://host/CellName` references are resolved through registered
bridgehead routes. `wss://` is the default; `ws://` is rejected unless the
resolver is created with `allows_insecure_websockets=True` for local/dev use.
The default route shape is `/bridgehead/{CellName}/{requesterUUID}`, which
maps to Vapor's `/bridgehead/:pubId/:bridgeId` bridgehead naming.

## Cross-language contracts (`cellprotocol.interop`)

Wire models, canonical encoding and verifiers for the three flows that must
work between Swift, Python and Go scaffolds: entity extension, invitation and
chat, plus the identity proof a bridge asks for. They reproduce Swift byte for
byte and are tested against the golden fixtures Swift generates
(`tests/fixtures/interop/v1`, copied from CellProtocol `fixtures/interop/v1`):

```bash
python3 -m pytest tests/test_interop_fixtures.py
```

`cellprotocol.interop.channel` is the bridge admission handshake; its tests
replay the Swift vectors and show the Python server and client emit the same
bytes. The cells that run the three flows on a Python scaffold are not here
yet.

## Upstream parity watch

The `Upstream CellProtocol sync` GitHub Actions workflow watches upstream
`CellProtocol` and `CellScaffold` heads through `repository_dispatch`, manual
runs, and an hourly scheduled fallback. It classifies upstream diffs before
running parity checks and treats resolver, vault, `CellConfiguration`, bridge,
identity-vault, and related Swift tests as contract-critical paths.
