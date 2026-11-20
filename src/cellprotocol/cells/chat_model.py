"""A language model as a named participant in a chat (PDD_modell-i-felles-chat_2026-11-15).

The same pure rules as CellBase Swift's `ChatModelConsentLedger` and
`ChatModelRules`, checked against the same scenario fixtures
(`tests/fixtures/interop/chat-model-v1`, copied from CellProtocol).

- The model comes in only when every human member has said yes.
- Any member can say no or take back a yes; the model loses access at once.
- A member who joins after the model came in does not stop it, but external
  routes need every current member's explicit yes, including the newcomer's.
- Any member can remove the model. It must be proposed again to come back.

`ChatModelProvider` is the pluggable model: `FakeChatModelProvider` answers in
tests, and `serve_open_asks` drives one round of asks for a model identity.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

CONTEXT_LIMIT = 20
ANSWER_LIMIT_SCALARS = 4_000
ASK_LIFETIME_SECONDS = 600
MENTION_TOKENS = ("@modell", "@model")


class ChatModelRefusal(Exception):
    """A refused ledger event. `code` is the shared wire value."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


NOT_MEMBER = "not_member"
ALREADY_PRESENT = "already_present"
NO_PROPOSAL = "no_proposal"


@dataclass
class Consent:
    external: bool
    at: str


@dataclass
class ChatModelConsentLedger:
    status: str = "none"  # none | proposed | active | removed
    model_uuid: Optional[str] = None
    model_display_name: Optional[str] = None
    proposed_by_uuid: Optional[str] = None
    proposed_at: Optional[str] = None
    activated_at: Optional[str] = None
    consents: dict[str, Consent] = field(default_factory=dict)
    declined: dict[str, str] = field(default_factory=dict)

    # -- events ---------------------------------------------------------------

    def propose(self, model_uuid: str, display_name: str, by: str, external: bool, at: str, members: list[str]) -> None:
        if by not in members:
            raise ChatModelRefusal(NOT_MEMBER)
        if self.status not in ("none", "removed"):
            raise ChatModelRefusal(ALREADY_PRESENT)
        self.status = "proposed"
        self.model_uuid = model_uuid
        self.model_display_name = display_name
        self.proposed_by_uuid = by
        self.proposed_at = at
        self.activated_at = None
        self.consents = {by: Consent(external=external, at=at)}
        self.declined = {}
        self._reevaluate(members, at)

    def consent(self, by: str, external: bool, at: str, members: list[str]) -> None:
        self._require_open(by, members)
        self.consents[by] = Consent(external=external, at=at)
        self.declined.pop(by, None)
        self._reevaluate(members, at)

    def decline(self, by: str, at: str, members: list[str]) -> None:
        """Says no to a proposal, or takes back a yes. The model stops at once."""
        self._require_open(by, members)
        self.consents.pop(by, None)
        self.declined[by] = at
        self._reevaluate(members, at)

    def remove(self, by: str, at: str, members: list[str]) -> None:
        _ = at
        self._require_open(by, members)
        self.status = "removed"
        self.activated_at = None
        self.consents = {}
        self.declined = {}

    def members_changed(self, members: list[str], at: str) -> None:
        self._reevaluate(members, at)

    def _require_open(self, by: str, members: list[str]) -> None:
        if by not in members:
            raise ChatModelRefusal(NOT_MEMBER)
        if self.status not in ("proposed", "active"):
            raise ChatModelRefusal(NO_PROPOSAL)

    def _reevaluate(self, members: list[str], at: str) -> None:
        if self.status == "proposed":
            if members and all(m in self.consents and m not in self.declined for m in members):
                self.status = "active"
                self.activated_at = at
        elif self.status == "active":
            if not members or any(m in self.declined for m in members):
                self.status = "proposed"
                self.activated_at = None

    # -- questions ------------------------------------------------------------

    def model_consent_holds(self, members: list[str]) -> bool:
        return self.status == "active" and bool(members) and all(m not in self.declined for m in members)

    def external_allowed(self, members: list[str]) -> bool:
        return self.model_consent_holds(members) and all(
            m in self.consents and self.consents[m].external for m in members
        )

    def awaiting_answer(self, member: str, members: list[str]) -> bool:
        return self.status == "proposed" and member in members and member not in self.consents and member not in self.declined

    def consented_members(self, members: list[str]) -> list[str]:
        return [m for m in members if m in self.consents and m not in self.declined]


# -- pure rules ----------------------------------------------------------------


def _is_word_char(ch: str) -> bool:
    return ch == "_" or unicodedata.category(ch)[0] in ("L", "M", "N")


def is_addressed_to_model(text: str) -> bool:
    """`@modell` or `@model` (any case) not inside a word."""
    lower = text.lower()
    for token in MENTION_TOKENS:
        start = 0
        while (index := lower.find(token, start)) >= 0:
            end = index + len(token)
            preceded_ok = index == 0 or not _is_word_char(lower[index - 1])
            followed_ok = end == len(lower) or not _is_word_char(lower[end])
            if preceded_ok and followed_ok:
                return True
            start = end
    return False


def context_message_ids(messages: list[dict[str, str]], activated_at: str, question_id: str, limit: int = CONTEXT_LIMIT) -> list[str]:
    """Messages written at or after `activated_at`, up to and including the question, newest `limit` kept."""
    index = next((i for i, message in enumerate(messages) if message["id"] == question_id), None)
    if index is None:
        return []
    eligible = [message["id"] for message in messages[: index + 1] if message["createdAt"] >= activated_at]
    limit = max(0, limit)
    return eligible[len(eligible) - limit :] if limit else []


def _dropped(code: int) -> bool:
    if code in (0x0A, 0x09):
        return False
    return code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F


def sanitize_answer(text: str) -> str:
    """Plain text: CRLF/CR to LF, controls other than LF and TAB dropped, trimmed, at most 4000 scalars."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    kept = "".join(ch for ch in normalized if not _dropped(ord(ch)))
    return kept.strip()[:ANSWER_LIMIT_SCALARS]


# -- pluggable provider ----------------------------------------------------------


class ChatModelUnavailable(Exception):
    """The provider could not answer. Only the asker is told."""

    def __init__(self, code: str = "model_unavailable", message: str = "Modellen svarte ikke.") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ChatModelReply:
    text: str
    model: str


class ChatModelProvider(Protocol):
    async def answer(self, question: str, messages: list[dict[str, Any]], route: str) -> ChatModelReply: ...


class FakeChatModelProvider:
    """Answers from `reply(question, messages, route)`, or fails with `failure`. Records each call."""

    def __init__(
        self,
        reply: Callable[[str, list[dict[str, Any]], str], str] | str = "Svar fra testmodellen.",
        *,
        model: str = "fake-model",
        failure: Optional[ChatModelUnavailable] = None,
    ) -> None:
        self._reply = reply
        self.model = model
        self.failure = failure
        self.calls: list[dict[str, Any]] = []

    async def answer(self, question: str, messages: list[dict[str, Any]], route: str) -> ChatModelReply:
        self.calls.append({"question": question, "messages": messages, "route": route})
        if self.failure is not None:
            raise self.failure
        text = self._reply(question, messages, route) if callable(self._reply) else self._reply
        return ChatModelReply(text=text, model=self.model)


async def serve_open_asks(chat: Any, model_identity: Any, provider: ChatModelProvider) -> list[Any]:
    """One round for the model identity: read each open ask, ask the provider, answer or fail."""
    state = await chat.get("model.state", model_identity)
    if not isinstance(state, dict):
        return []
    results = []
    for ask in state.get("openAsks", []):
        ask_id = ask["askID"]
        context = await chat.set("model.context", {"askID": ask_id}, model_identity)
        if not isinstance(context, dict) or context.get("status") != "ok":
            results.append(context)
            continue
        try:
            reply = await provider.answer(context["question"], context["messages"], ask["routeClass"])
        except ChatModelUnavailable as failure:
            results.append(await chat.set("model.fail", {"askID": ask_id, "code": failure.code, "message": failure.message}, model_identity))
            continue
        results.append(await chat.set("model.answer", {"askID": ask_id, "text": reply.text, "model": reply.model}, model_identity))
    return results
