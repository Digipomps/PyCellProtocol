"""Chat model rules (Python) against the Swift scenario fixtures (chat-model-v1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cellprotocol.cells import chat_model as cm

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "interop" / "chat-model-v1" / "scenarios.json").read_text(encoding="utf-8"))
MODEL = "6F1C2B0A-0000-4000-8000-0000000A0DE1"


def _apply(ledger: cm.ChatModelConsentLedger, step: dict) -> str | None:
    member, at, members = step.get("member", ""), step["at"], step["members"]
    external = step.get("external", False)
    try:
        event = step["event"]
        if event == "propose":
            ledger.propose(MODEL, "Modell", member, external, at, members)
        elif event == "consent":
            ledger.consent(member, external, at, members)
        elif event == "decline":
            ledger.decline(member, at, members)
        elif event == "remove":
            ledger.remove(member, at, members)
        elif event == "membersChanged":
            ledger.members_changed(members, at)
        else:
            return "unknown_event"
    except cm.ChatModelRefusal as refusal:
        return refusal.code
    return None


def _snapshot(ledger: cm.ChatModelConsentLedger, members: list[str], refusal: str | None) -> dict:
    return {
        "refusal": refusal,
        "status": ledger.status,
        "activatedAt": ledger.activated_at,
        "modelConsentHolds": ledger.model_consent_holds(members),
        "externalAllowed": ledger.external_allowed(members),
        "consentedMembers": ledger.consented_members(members),
        "awaitingAnswer": {m: ledger.awaiting_answer(m, members) for m in members},
    }


def test_constants_match_swift():
    constants = FIXTURE["constants"]
    assert constants["contextLimit"] == cm.CONTEXT_LIMIT
    assert constants["answerLimitScalars"] == cm.ANSWER_LIMIT_SCALARS
    assert constants["askLifetimeSeconds"] == cm.ASK_LIFETIME_SECONDS
    assert tuple(constants["mentionTokens"]) == cm.MENTION_TOKENS


@pytest.mark.parametrize("scenario", FIXTURE["ledgerScenarios"], ids=lambda s: s["name"])
def test_ledger_scenarios(scenario):
    ledger = cm.ChatModelConsentLedger()
    for index, step in enumerate(scenario["steps"]):
        refusal = _apply(ledger, step)
        assert _snapshot(ledger, step["members"], refusal) == step["expect"], f"step {index}"


@pytest.mark.parametrize("case", FIXTURE["mentionCases"], ids=lambda c: c["text"])
def test_mentions(case):
    assert cm.is_addressed_to_model(case["text"]) is case["expect"]


@pytest.mark.parametrize("case", FIXTURE["contextCases"], ids=lambda c: c["name"])
def test_context(case):
    got = cm.context_message_ids(case["messages"], case["activatedAt"], case["questionID"], case["limit"])
    assert got == case["expect"]


@pytest.mark.parametrize("case", FIXTURE["sanitizeCases"], ids=lambda c: c["name"])
def test_sanitize(case):
    got = cm.sanitize_answer(case["text"])
    assert got == case["expect"]
    assert len(got) == case["expectScalarCount"]
