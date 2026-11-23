# Chat model fixtures v1

Scenario fixtures for a language model as a participant in a shared chat
(PDD_modell-i-felles-chat_2026-11-15). Swift (`ChatModelConsentLedger`,
`ChatModelRules` in CellBase), Python and Go must give the same answers.

Synthetic data only. The UUIDs are made up.

## What `scenarios.json` holds

| Section | Input | Expected |
|---|---|---|
| `ledgerScenarios` | Steps: `event` (`propose`, `consent`, `decline`, `remove`, `membersChanged`), `member`, `external` (for propose and consent), `at`, `members` (the human members at that moment) | `expect` after each step: `refusal` (`null`, `not_member`, `already_present`, `no_proposal`), `status`, `activatedAt`, `modelConsentHolds`, `externalAllowed`, `consentedMembers` (in `members` order), `awaitingAnswer` per member |
| `mentionCases` | `text` | `expect`: is the message addressed to the model (`@modell` or `@model`, any case, not inside a word) |
| `contextCases` | `messages` (`id`, `createdAt`), `activatedAt`, `questionID`, `limit` | `expect`: the message ids the model may read |
| `sanitizeCases` | `text` | `expect` and `expectScalarCount` (Unicode scalars / code points / runes) |

`constants` lists the shared limits.

## Rules another implementation must match

- A refused event changes nothing.
- The model becomes active when every current member has said yes and nobody
  has said no. A no, or everyone leaving, sends it back to `proposed`.
- A member who joins after activation does not stop the model, but
  `externalAllowed` needs an explicit external yes from every current member.
- `remove` clears all answers; the model must be proposed again.
- A word character next to the mention is a letter, digit or `_` (Unicode).
- Context: messages up to and including the question, with
  `createdAt >= activatedAt` compared as strings, newest `limit` kept.
- Sanitize: CRLF and CR become LF; drop U+0000–U+001F except LF and TAB,
  U+007F and U+0080–U+009F; trim Unicode whitespace at both ends; keep the
  first 4000 scalars (this may split an emoji sequence, on purpose, so all
  runtimes cut at the same place).

## Regenerate and check

    HAVEN_WRITE_CHAT_MODEL_FIXTURES=1 swift test --filter ChatModelFixturesV1Tests
    swift test --filter ChatModelFixturesV1Tests
