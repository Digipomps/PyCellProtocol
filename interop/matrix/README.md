# Interop matrix

`run_matrix.py` checks that the three student flows work between scaffolds
written in different languages:

- **extend**: a new device asks to join an entity, the entity's node reviews and
  signs the approval, the device verifies it.
- **invite**: a node issues an invitation and publishes it on its own landing
  (`/i/...`, as CellScaffold); the invitee verifies the link, replies by short
  code, and the issuer sees the reply.
- **chat**: a node hosts a chat and invites a guest; the guest signs the
  acceptance on its own node, joins over the authenticated bridge
  (`org.haven.bridge-channel.v1`), sends and reads.

Each flow runs for every host → guest pair of the peers you give, with negative
steps (strangers, revoked links and guests, owner-only keys, someone else's
approval). With Swift, Python and Go that is 3 flows × 9 pairs.

```sh
pip install -e '.[scaffold]'
go build -o /tmp/interop-peer github.com/Digipomps/GoCellProtocol/cmd/interop-peer
python3 interop/matrix/run_matrix.py \
  --peer python="python3 -m cellprotocol_scaffold.interop_peer" \
  --peer go=/tmp/interop-peer \
  --out TESTRESULT.md
```

## Peer protocol `haven.interop-peer.v1`

A peer is a program that reads one JSON object per line on stdin and writes one
JSON line per request on stdout: `{"ok": true, "result": ...}` or
`{"ok": false, "error": "..."}`. A refusal (access denied, a bridge answer with
`state: error`) is `ok: false`. Results are the cell's own wire JSON. A cell
result such as `"error: ..."` is a result, not a refusal.

| op | fields | does | result |
|---|---|---|---|
| `hello` | | | `{lang, protocol: "haven.interop-peer.v1"}` |
| `init` | `name` | Makes a fresh identity in an in-memory vault, a home `ChatCell` (`home`) and an `EntityScaffoldExtensionCell` (`extension`) owned by it | `{identity, descriptor}`: the identity's wire JSON and its `IdentityPublicKeyDescriptor` |
| `invitation` | `landingBase`, `contactEndpointID`? | (Re)creates the `InvitationCell` (`invitation`) | `{cell}` |
| `serve` | `port`, `topic`? | Starts a node on `127.0.0.1:port`: an authenticated bridgehead whose public URL is `ws://127.0.0.1:port`, a `ChatCell` named `Chat` owned by the identity (`chat`), and the invitation landing at `/i/` with rate limits off | `{landingBase, chatURL}` |
| `admit` | `identity` | The chat owner admits an invited identity the way its language does. Swift's ChatCell needs an Agreement the owner signs (`addAgreement(_:for:authorizedBy: owner)`); the Python and Go ChatCells admit by the verified acceptance and answer `{admittedBy: "acceptance"}` | `{admittedBy}` |
| `call` | `cell`, `method` (`get`/`set`), `key`, `value` | Calls a local cell as its owner | the cell's answer |
| `remote` | `url`, `method`, `key`, `value` | Calls a cell over the authenticated bridge as this identity; one connection per URL | the cell's answer |

Peers today:

- Python: `python3 -m cellprotocol_scaffold.interop_peer` (this repo).
- Go: `cmd/interop-peer` in Digipomps/GoCellProtocol.
- Swift: to be added on a CellScaffold build (CellBase `ChatCell`, the
  CellScaffold bridgehead and `VaporInviteLanding`, Binding's `InvitationCell`
  and `EntityScaffoldExtensionCell`).

CI runs the Python and Go pairs (`.github/workflows/interop-matrix.yml`).
