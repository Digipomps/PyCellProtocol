Copied from Digipomps/CellProtocol `fixtures/interop/v1`, branch
`claude/organization-entity-informasjonssystemer` at 4878dd5 (PR #91), which
adds the `org.*` cases to the fixtures from `pdd/interop-fixtures-v1` at
8406d34 (PR #75). Do not edit here: regenerate in CellProtocol and copy again,
so Python is always measured against Swift.

`extend.request.valid.json` copied again from CellProtocol branch
`claude/extend-hash-v2` (2026-11-23): `related.humanCode` is now derived from
the request hash, and `bindingRequestHashBase64` is gone because the extension
flow uses CellBase's request hash everywhere.
