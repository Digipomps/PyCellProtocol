"""The model as a chat participant on a Python ChatCell, as in Swift (PDD_modell-i-felles-chat)."""

from __future__ import annotations

import asyncio

import pytest

from cellprotocol.cells.chat import ChatCell, MODEL_PARTICIPANT_KEYS
from cellprotocol.cells.chat_model import FakeChatModelProvider, ChatModelUnavailable, serve_open_asks
from cellprotocol.identity import Identity, InMemoryIdentityVault


def run(coro):
    return asyncio.run(coro)


def public(identity: Identity) -> Identity:
    return Identity.from_json(identity.to_json())


class Clock:
    def __init__(self, start: float = 1_795_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        self.now += 0.01
        return self.now


async def _request(chat, requester, keys=None):
    template = dict((await chat.advertise(requester))["contractTemplate"])
    if keys is not None:
        template["grants"] = [grant for grant in template["grants"] if grant["keypath"] in keys]
    return template


async def _chat(with_carol: bool = False):
    """Alice owns the chat; Bob (and Carol) are owner-accepted members with contracts."""
    vault = InMemoryIdentityVault()
    alice = await vault.identity("Alice", make_new_if_not_found=True)
    bob = public(await InMemoryIdentityVault().identity("Bob", make_new_if_not_found=True))
    carol = public(await InMemoryIdentityVault().identity("Carol", make_new_if_not_found=True))
    model = public(await InMemoryIdentityVault().identity("Qwen", make_new_if_not_found=True))
    mallory = public(await InMemoryIdentityVault().identity("Mallory", make_new_if_not_found=True))
    clock = Clock()
    chat = ChatCell(owner=alice, clock=clock)
    await chat.set("audience.admissionConditions", ["member"], alice)
    people = [bob, carol] if with_carol else [bob]
    await chat.set("audience.inviteIdentities", [p.to_json() for p in people], alice)
    await chat.set("audience.acceptInvites", [p.uuid for p in people], alice)
    for person in people:
        assert await chat.add_agreement(await _request(chat, person), person) == "signed"
    return chat, clock, alice, bob, carol, model, mallory


async def _activate(chat, alice, bob, model, external=False):
    proposed = await chat.set("model.propose", {"identity": model.to_json(), "displayName": "Qwen", "external": external}, alice)
    assert proposed["status"] == "ok" and proposed["model"]["status"] == "proposed"
    consented = await chat.set("model.consent", {"external": external}, bob)
    assert consented["model"]["isActive"] is True
    assert await chat.add_agreement(await _request(chat, model, set(MODEL_PARTICIPANT_KEYS)), model) == "signed"


def test_model_comes_in_only_when_every_member_says_yes():
    async def scenario():
        chat, _, alice, bob, carol, model, _ = await _chat(with_carol=True)
        await chat.set("model.propose", {"identity": model.to_json(), "displayName": "Qwen"}, alice)
        # Not yet: Bob and Carol have not answered, so the model cannot get a contract.
        assert await chat.get("audience.admission.modelConsent", model) is False
        assert await chat.add_agreement(await _request(chat, model, set(MODEL_PARTICIPANT_KEYS)), model) == "rejected"
        assert (await chat.get("model.state", carol))["awaitingMe"] is True
        await chat.set("model.consent", {}, bob)
        assert await chat.add_agreement(await _request(chat, model, set(MODEL_PARTICIPANT_KEYS)), model) == "rejected"
        state = (await chat.set("model.consent", {}, carol))["model"]
        assert state["isActive"] is True and state["consentedCount"] == 3 and state["memberCount"] == 3
        assert await chat.get("audience.admission.modelConsent", model) is True
        assert await chat.add_agreement(await _request(chat, model, set(MODEL_PARTICIPANT_KEYS)), model) == "signed"
        assert (await chat.get("model.state", model))["openAsks"] == []

    run(scenario())


def test_model_reads_only_for_an_open_ask_and_answers_as_model():
    async def scenario():
        chat, _, alice, bob, _, model, _ = await _chat()
        await chat.set("sendMessage", "skrevet før modellen kom", bob)
        await _activate(chat, alice, bob, model)
        # The model has no other keys, and nothing to read without an ask.
        with pytest.raises(PermissionError):
            await chat.get("messages", model)
        with pytest.raises(PermissionError):
            await chat.set("sendMessage", "hei", model)
        sent = await chat.set("sendMessage", "@modell hva er et formål?", bob)
        question_id = sent["message"]["id"]
        # Only the author may ask about their message.
        assert (await chat.set("model.ask", {"messageID": question_id}, alice))["code"] == "not_your_message"
        opened = await chat.set("model.ask", {"messageID": question_id}, bob)
        assert opened["status"] == "open" and opened["ask"]["contextCount"] == 1

        provider = FakeChatModelProvider(lambda q, msgs, route: f"Svar på: {q}\r\n\u0007ferdig")
        results = await serve_open_asks(chat, model, provider)
        assert results[0]["status"] == "sent"
        assert [m["content"] for m in provider.calls[0]["messages"]] == ["@modell hva er et formål?"]
        answer = results[0]["message"]
        assert answer["authorKind"] == "model" and answer["askedByUUID"] == bob.uuid
        assert answer["content"] == "Svar på: @modell hva er et formål?\nferdig"
        assert answer["routeClass"] == "local" and answer["contextCount"] == 1 and answer["model"] == "fake-model"
        assert answer["ownerDisplayName"] == "Qwen" and answer["contentType"] == "text/plain"
        # The ask is spent.
        assert (await chat.set("model.context", {"askID": opened["ask"]["askID"]}, model))["code"] == "no_open_ask"
        kinds = {row["id"]: row["kind"] for row in await chat.get("participants", alice)}
        assert kinds[model.uuid] == "model" and kinds[bob.uuid] == "person"

    run(scenario())


def test_context_is_capped_at_twenty_messages():
    async def scenario():
        chat, _, alice, bob, _, model, _ = await _chat()
        await _activate(chat, alice, bob, model)
        for index in range(25):
            await chat.set("sendMessage", f"melding {index}", alice)
        question = await chat.set("sendMessage", "@model oppsummer", bob)
        ask = await chat.set("model.ask", {"messageID": question["message"]["id"]}, bob)
        context = await chat.set("model.context", {"askID": ask["ask"]["askID"]}, model)
        assert len(context["messages"]) == 20 and context["messages"][-1]["content"] == "@model oppsummer"

    run(scenario())


def test_withdrawal_stops_the_model_at_once_and_tells_the_asker():
    async def scenario():
        chat, _, alice, bob, _, model, _ = await _chat()
        await _activate(chat, alice, bob, model)
        question = await chat.set("sendMessage", "@modell hei", bob)
        await chat.set("model.ask", {"messageID": question["message"]["id"]}, bob)
        await chat.set("model.decline", None, alice)
        assert await chat.get("audience.admission.modelConsent", model) is False
        with pytest.raises(PermissionError):
            await chat.get("model.state", model)
        notice = (await chat.get("model.state", bob))["notice"]
        assert notice["code"] == "model_removed"
        assert (await chat.get("model.state", alice))["notice"] is None
        # A yes again lets it back; removing means it must be proposed again.
        await chat.set("model.consent", {}, alice)
        assert await chat.get("audience.admission.modelConsent", model) is True
        removed = await chat.set("model.remove", None, bob)
        assert removed["model"]["status"] == "removed" and removed["model"]["canPropose"] is True
        assert (await chat.set("model.consent", {}, alice))["code"] == "no_proposal"
        assert await chat.get("audience.admission.modelConsent", model) is False

    run(scenario())


def test_newcomer_keeps_model_but_external_needs_their_yes():
    async def scenario():
        chat, _, alice, bob, _, model, _ = await _chat()
        await _activate(chat, alice, bob, model, external=True)
        assert (await chat.get("model.state", alice))["externalAllowed"] is True
        carol = public(await InMemoryIdentityVault().identity("Carol", make_new_if_not_found=True))
        await chat.set("audience.inviteIdentities", [carol.to_json()], alice)
        await chat.set("audience.acceptInvites", [carol.uuid], alice)
        assert await chat.add_agreement(await _request(chat, carol), carol) == "signed"
        state = await chat.get("model.state", carol)
        assert state["isActive"] is True and state["externalAllowed"] is False
        question = await chat.set("sendMessage", "@modell ekstern?", bob)
        refused = await chat.set("model.ask", {"messageID": question["message"]["id"], "route": "external"}, bob)
        assert refused["code"] == "external_not_allowed"
        await chat.set("model.consent", {"external": True}, carol)
        opened = await chat.set("model.ask", {"messageID": question["message"]["id"], "route": "external"}, bob)
        assert opened["status"] == "open"
        # Carol withdraws external only: the answer is held back and Bob is told.
        await chat.set("model.consent", {"external": False}, carol)
        answered = await chat.set("model.answer", {"askID": opened["ask"]["askID"], "text": "hei"}, model)
        assert answered["code"] == "external_not_allowed"
        assert (await chat.get("model.state", bob))["notice"]["code"] == "external_not_allowed"
        assert all(m.get("authorKind") == "person" for m in await chat.get("messages", alice))

    run(scenario())


def test_failure_is_shown_only_to_the_asker():
    async def scenario():
        chat, _, alice, bob, _, model, _ = await _chat()
        await _activate(chat, alice, bob, model)
        question = await chat.set("sendMessage", "@modell hei", bob)
        await chat.set("model.ask", {"messageID": question["message"]["id"]}, bob)
        failing = FakeChatModelProvider(failure=ChatModelUnavailable("model_unavailable", "Den lokale modellen er ikke i gang."))
        results = await serve_open_asks(chat, model, failing)
        assert results[0]["status"] == "ok"
        assert (await chat.get("model.state", bob))["notice"]["message"] == "Den lokale modellen er ikke i gang."
        assert (await chat.get("model.state", alice))["notice"] is None
        assert len(await chat.get("messages", alice)) == 1
        dismissed = await chat.set("model.dismissNotice", None, bob)
        assert dismissed["model"]["notice"] is None

    run(scenario())


def test_ask_expires_after_ten_minutes():
    async def scenario():
        chat, clock, alice, bob, _, model, _ = await _chat()
        await _activate(chat, alice, bob, model)
        question = await chat.set("sendMessage", "@modell hei", bob)
        ask = await chat.set("model.ask", {"messageID": question["message"]["id"]}, bob)
        clock.now += 601
        assert (await chat.set("model.context", {"askID": ask["ask"]["askID"]}, model))["code"] == "no_open_ask"
        assert (await chat.get("model.state", bob))["notice"]["code"] == "ask_expired"

    run(scenario())


def test_strangers_and_impostors_cannot_act_for_or_as_the_model():
    async def scenario():
        chat, _, alice, bob, _, model, mallory = await _chat()
        assert (await chat.set("model.propose", {"identity": bob.to_json()}, alice))["code"] == "invalid_model"
        await _activate(chat, alice, bob, model)
        with pytest.raises(PermissionError):
            await chat.set("model.propose", {"identity": mallory.to_json()}, mallory)
        with pytest.raises(PermissionError):
            await chat.get("model.state", mallory)
        impostor = Identity.from_json({**mallory.to_json(), "uuid": model.uuid})
        assert await chat.get("audience.admission.modelConsent", impostor) is False
        with pytest.raises(PermissionError):
            await chat.set("model.answer", {"askID": "x", "text": "hei"}, impostor)
        # A member cannot pose as the model.
        assert await chat.set("model.answer", {"askID": "x", "text": "hei"}, bob) == "denied"

    run(scenario())


def test_node_hosted_chat_counts_only_its_people():
    async def scenario():
        chat, _, alice, bob, carol, model, _ = await _chat(with_carol=True)
        assert (await chat.set("model.ownerIsMember", False, alice)) == {"status": "ok", "ownerIsMember": False}
        with pytest.raises(PermissionError):
            await chat.set("model.ownerIsMember", True, bob)
        await chat.set("model.propose", {"identity": model.to_json(), "displayName": "Qwen"}, bob)
        state = (await chat.set("model.consent", {}, carol))["model"]
        assert state["isActive"] is True and state["memberCount"] == 2
        assert await chat.set("model.decline", None, alice) == "denied"
        assert await chat.get("audience.admission.modelConsent", model) is True
        assert await chat.add_agreement(await _request(chat, model, set(MODEL_PARTICIPANT_KEYS)), model) == "signed"
        await chat.set("model.remove", None, bob)
        refused = await chat.set("model.propose", {"identity": public(alice).to_json()}, bob)
        assert refused["code"] == "invalid_model"

    run(scenario())
