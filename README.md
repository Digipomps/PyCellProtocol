# PyCellProtocol

Python v1 implementation of the HAVEN CellProtocol core contracts.

This repository intentionally keeps two installable import packages in one repo:

- `cellprotocol`: protocol types, wire codecs, resolver, bridge primitives, identity/vault interfaces, and built-in cells.
- `cellprotocol_scaffold`: ASGI scaffold, bridge routes, diagnostics, EntityAnchorData v1, decorators, and CLI.

The first priority is Swift wire compatibility. Python names may be pleasant to use, but JSON payloads, command names, resolver scopes, keypaths, and failure behavior must remain compatible with the Swift implementation.

## Quick Check

```bash
python3 -m pytest
```

Optional scaffold runtime dependencies are installed with:

```bash
python3 -m pip install -e ".[scaffold]"
pycell scaffold serve --host 127.0.0.1 --port 8080
```
