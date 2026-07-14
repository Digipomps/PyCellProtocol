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
attachment operations. Caller-supplied Agreements and inbound bridge signing
fail closed because Python does not yet implement Swift's complete
owner-approved Agreement admission or purpose/audience/nonce/expiry signing
challenge lifecycle.

The ASGI bridge therefore exposes public descriptions but does not upgrade a
wire-supplied identity into the server owner. Protected bridge reads and writes
remain denied until an authenticated, replay-resistant session proof is added.
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
