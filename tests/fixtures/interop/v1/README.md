# Interop fixtures v1

Public, synthetic test data for the three flows that must work between Swift,
Python and Go scaffolds: entity extension (`extend`), invitation (`invite`) and
chat (`chat`), plus the identity proof a bridge asks for (`bridge`).

Every key here is a **public test key** derived from
`SHA-256("haven-interop-v1/<name>")`. Never use them for anything else.

## What each case file holds

| Field | Meaning |
|---|---|
| `type` | The Swift type, e.g. `HavenInviteTicket` |
| `encodedBase64` | The wire JSON exactly as Swift `JSONEncoder` wrote it (sorted keys). Decode this, not `object` |
| `object` | The same JSON, for reading |
| `excludedTopLevelKeys` | Keys removed before signing (`proof`, or `pf` for the ticket) |
| `canonicalBase64` | The exact bytes the signature covers |
| `canonicalSHA256Hex` | SHA-256 of those bytes |
| `signer` | The public key descriptor the verifier must use |
| `signatureBase64` | Ed25519 signature (RFC 8032) over the canonical bytes |
| `expect.signatureValid` | Whether the signature verifies against `signer` |
| `expect.verdict` | What the Swift verifier for this type answers at `verifyAt` in `manifest.json`. For `extend` it is the envelope signature only (`valid` or `bad_signature`); the full `IdentityLinkProtocolService` verdicts come with the extend cell |
| `related` | Links to other cases, and derived values such as `requestHashBase64` |

## How another implementation passes

For every case in `manifest.json`:

1. Decode `encodedBase64` into your model of `type`.
2. Re-encode it canonically and compare **byte for byte** with `canonicalBase64`.
3. Verify `signatureBase64` with `signer.publicKey` over your bytes and compare with `expect.signatureValid`.
4. Once your verifier exists for the type, compare its answer with `expect.verdict`.

## The canonical rule (where implementations go wrong)

Swift encodes with `JSONEncoder()` (default strategies: `Data` as standard
base64 with padding, `Date` is not used in these types), removes the excluded
top-level keys, and writes the result with
`JSONSerialization.data(withJSONObject:options:[.sortedKeys])`. That means:

- `/` is written as `\/`.
- Non-ASCII text (æøå, emoji) is written as raw UTF-8, not `\u` escapes.
- `"` `\` newline and tab are escaped as `\"` `\\` `\n` `\t`.
- No spaces between tokens.
- Keys are sorted, and the order is **not** plain byte order:
  `JSONSerialization` compares case-insensitively with numeric runs as
  numbers, so in `extend.request.valid` `requestID` comes after
  `requestedScopes`. `JSONEncoder` with `.sortedKeys` (the wire JSON in
  `encodedBase64`, the ticket token, the signed bridge challenge) uses plain
  code-point order and puts `requestID` first. The fixtures were made on
  Linux; the macOS run of this test shows whether Darwin agrees.
- Optional fields that are `nil` are left out, not written as `null`.
- `HavenInviteTicket` uses short coded keys (`v`, `t`, `is`, ...) and leaves
  out `capabilities` when they equal the default, `basis` when empty and
  `nonce` when empty.

`IdentitySigningChallenge` is the exception: its signed bytes are the
`JSONEncoder` output with `.sortedKeys` directly, with nothing removed.

## Bridge channel admission (`BridgeChannelAuthV1`)

The `bridge.channel-auth.*` cases are the four WebSocket messages of
`org.haven.bridge-channel.v1` (see `Docs/BridgeIdentitySecurity.md`) with fixed
nonces, session ID and generation. `encodedBase64` is the transcript,
`canonicalBase64` the `IdentitySigningChallenge` bytes the client signs, and
`related` holds each full envelope and the transcript digest.

- Envelopes and bodies use `JSONEncoder` with `.sortedKeys` **and**
  `.withoutEscapingSlashes`, in code-point key order.
- The signed challenge escapes slashes like every other `IdentitySigningChallenge`.
- `issuedAt` is `issuedAtMilliseconds / 1000` through Foundation `Date`, which
  stores seconds since 2001. `expiresAt` is that date plus 30 seconds, read back.
  Do the same arithmetic in doubles to get the same digits.

## Organizations owned by a group (`org`)

The `org.*` cases come from `Tests/CellBaseTests/InteropFixturesV1OrganizationCases.swift`
(PDD `informasjonssystemer-gruppeentitet`). The manifest has a fourth party,
`custodian`: the organization key that the vault holds.

| Type | Excluded | Verdict |
|---|---|---|
| `GovernancePolicy` | nothing, unsigned | `valid`; `related.policyHashBase64` is SHA-256 of the canonical bytes |
| `OrganizationGenesisSeal` | `signatures` | `OrganizationGenesisSeal.verify(initialPolicy:)` against `related.policy`: `valid` or the error case name (`founderSignatureInvalid`, `unexpectedSigner`, ...) |
| `OrganizationActionProposal` | nothing, unsigned | `valid`; `related.proposalHashBase64` is what approvals sign |
| `OrganizationApproval` | `signature` | `valid` or `bad_signature` |
| `ApprovalBundle` | nothing, unsigned | `GovernancePolicyEvaluator.evaluate` against `related.policy` at `verifyAt`: `met:<ruleID>:<clauseIndex>` or the `GovernanceEvaluationError` case name |
| `VCClaim` (role) | `proof` | `valid` or `invalid`. Signed by `custodian`; `related.payloadHashBase64` is the hash the owners approve |
| `OrganizationRoleStatusList` | `signature` | `valid` or `bad_signature`, verified with the key inside `issuerDID` (did:key) |

The evaluator rules a port must copy exactly:

- An approval is refused, in this order, when it is for another proposal, its signature fails, the approver is not a member, the approver lacks the role, the approval falls outside the member's validity, or the decision is `reject`.
- A person who approves twice counts once.
- A clause's role counts are filled with distinct people, trying people in sorted uuid order.
- When no candidate rule holds, the error is the first gate failure (exclusion, limit, fresh auth) if any rule had one, otherwise the first `clauseNotSatisfied`.

`org.access-matrix.json` is not a signed case but a shared table: seven
scenarios (valid, wrong role, revoked, expired, tampered, issuer not trusted,
stale status mirror) with the decision (`met` or `unresolved`) and the
TrustedIssuer reason every implementation must reach. Swift checks it in
`OrganizationVaultTests.testAccessMatrixMatchesSharedTable` through
`ProvedClaimCondition` and `TrustedIssuerCell`.

## Regenerating

On Linux, where swift-crypto's Ed25519 is deterministic, through the Linux gate
in `.github/workflows/cellprotocol-swift-linux.yml`:

```bash
HAVEN_WRITE_INTEROP_FIXTURES=1 swift test --filter InteropFixturesV1Tests
```

`InteropFixturesV1Tests.testInteropFixturesV1MatchThisPlatform` runs on every
platform and fails by case id if this platform's Foundation produces other
bytes than the committed ones.

## Not in v1

`ChatMessage` (unsigned, carries a full `Identity`) and the Cell commands after
admission. They come with the chat and bridge work packages.
