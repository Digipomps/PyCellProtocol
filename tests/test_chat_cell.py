"""ChatCell on a Python node: signed invitation, acceptance, membership, messages."""

from __future__ import annotations

import asyncio

import pytest

from cellprotocol.cells.chat import ChatCell
from cellprotocol.identity import Identity, InMemoryIdentityVault
from cellprotocol.interop import models as m
from cellprotocol.interop import verify as v


def run(coro):
    return asyncio.run(coro)


async def _people():
    alice = await InMemoryIdentityVault().identity("Alice", make_new_if_not_found=True)
    bob = await InMemoryIdentityVault().identity("Bob", make_new_if_not_found=True)
    mallory = await InMemoryIdentityVault().identity("Mallory", make_new_if_not_found=True)
    return alice, bob, mallory


def public(identity: Identity) -> Identity:
    """What arrives over the authenticated bridge: the key, no vault."""
    return Identity.from_json(identity.to_json())


async def _invited_chat(conditions=("invitationAccepted",)):
    alice, bob, mallory = await _people()
    chat = ChatCell(owner=alice)
    assert await chat.set("audience.admissionConditions", list(conditions), alice) == list(conditions)
    bob_home = ChatCell(owner=bob)
    await chat.set("audience.inviteIdentities", [bob.to_json()], alice)
    artifacts = await chat.set("audience.generateInvitationArtifacts", True, alice)
    acceptance = await bob_home.set("audience.generateInvitationAcceptance", artifacts[0], bob)
    return alice, bob, mallory, chat, artifacts[0], acceptance


async def _request(chat, requester, keys=None):
    """What a guest sends: the advertised template, with the grants it wants."""
    template = dict((await chat.advertise(requester))["contractTemplate"])
    if keys is not None:
        template["grants"] = [grant for grant in template["grants"] if grant["keypath"] in keys]
    return template


def test_artifact_and_acceptance_verify_as_swift_does():
    async def scenario():
        _, _, _, chat, artifact, acceptance = await _invited_chat()
        a = m.ChatInvitationArtifact.from_wire(artifact)
        b = m.ChatInvitationAcceptance.from_wire(acceptance)
        v.verify_chat_invitation(a, expected_chat_cell_uuid=chat.uuid, expected_inviter_uuid=chat.owner.uuid)
        v.verify_chat_acceptance(b, a, expected_chat_cell_uuid=chat.uuid)
        assert len(a.nonce) == 64 and a.created_at.endswith("Z")

    run(scenario())


def test_invitee_joins_sends_and_reads_after_accepting():
    async def scenario():
        alice, bob, mallory, chat, artifact, acceptance = await _invited_chat()
        remote_bob = public(bob)
        with pytest.raises(PermissionError):
            await chat.get("messages", remote_bob)
        # No proof yet: the Agreement's condition does not hold.
        assert await chat.add_agreement(await _request(chat, remote_bob), remote_bob) == "rejected"
        assert await chat.get("audience.admission.invitationAccepted", remote_bob) is False
        accepted = await chat.set("audience.acceptInvitationArtifact", {"artifact": artifact, "acceptance": acceptance}, remote_bob)
        assert accepted["status"] == "accepted" and accepted["idempotent"] is False
        again = await chat.set("audience.acceptInvitationArtifact", {"artifact": artifact, "acceptance": acceptance}, remote_bob)
        assert again["idempotent"] is True
        # The proof alone opens nothing; the contract does.
        with pytest.raises(PermissionError):
            await chat.get("messages", remote_bob)
        assert await chat.get("audience.admission.invitationAccepted", remote_bob) is True
        wanted = {"messages", "sendMessage"}
        assert await chat.add_agreement(await _request(chat, remote_bob, wanted), remote_bob) == "signed"

        sent = await chat.set("sendMessage", "Hei Alice", remote_bob)
        assert sent["status"] == "sent" and sent["message"]["ownerUUID"] == bob.uuid
        await chat.set("sendMessage", {"content": "# Hei", "contentType": "markdown"}, alice)
        messages = await chat.get("messages", remote_bob)
        assert [msg["content"] for msg in messages] == ["Hei Alice", "# Hei"]
        assert messages[1]["isMarkdown"] is True
        audience = await chat.get("audience", alice)
        assert audience["acceptedInviteCount"] == 1 and {r["identityUUID"] for r in audience["resolvedRecipients"]} == {alice.uuid, bob.uuid}

        # Strangers and impostors stay out.
        with pytest.raises(PermissionError):
            await chat.set("sendMessage", "hei", public(mallory))
        impostor = Identity.from_json({**mallory.to_json(), "uuid": bob.uuid})
        with pytest.raises(PermissionError):
            await chat.get("messages", impostor)
        # Bob asked only for reading and sending; the owner's keys stay the owner's.
        with pytest.raises(PermissionError):
            await chat.set("audience.generateInvitationArtifacts", True, remote_bob)
        with pytest.raises(PermissionError):
            await chat.set("audience.admissionConditions", [], remote_bob)
        assert await chat.add_agreement(await _request(chat, public(mallory)), public(mallory)) == "rejected"

        # Revoking takes access away again.
        await chat.set("audience.revokeInvites", [bob.uuid], alice)
        with pytest.raises(PermissionError):
            await chat.get("messages", remote_bob)

    run(scenario())


def test_refuses_tampered_foreign_and_superseded_proofs():
    async def scenario():
        alice, bob, mallory, chat, artifact, acceptance = await _invited_chat()
        tampered = {**artifact, "topic": "annet"}
        result = await chat.set("audience.acceptInvitationArtifact", {"artifact": tampered, "acceptance": acceptance}, public(bob))
        assert result == "error: invalidArtifactProof"

        other_chat = ChatCell(owner=alice)
        await other_chat.set("audience.inviteIdentities", [bob.to_json()], alice)
        assert (await other_chat.set("audience.acceptInvitationArtifact", {"artifact": artifact, "acceptance": acceptance}, public(bob))) == "error: chatCellMismatch"

        mallory_home = ChatCell(owner=mallory)
        assert (await mallory_home.set("audience.generateInvitationAcceptance", artifact, mallory)) == "error: requester does not match invited identity"

        # A new artifact supersedes the old one.
        await chat.set("audience.declineInvites", [bob.uuid], alice)
        fresh = await chat.set("audience.generateInvitationArtifacts", [bob.uuid], alice)
        assert fresh[0]["invitationID"] != artifact["invitationID"]
        stale = await chat.set("audience.acceptInvitationArtifact", {"artifact": artifact, "acceptance": acceptance}, public(bob))
        assert stale == "error: invitation artifact has been superseded"

    run(scenario())


def test_composer_and_flow_events():
    async def scenario():
        alice, bob, _, chat, artifact, acceptance = await _invited_chat()
        await chat.set("audience.acceptInvitationArtifact", {"artifact": artifact, "acceptance": acceptance}, public(bob))
        assert await chat.add_agreement(await _request(chat, public(bob)), public(bob)) == "signed"
        await chat.set("compose.body", "  utkast  ", public(bob))
        assert (await chat.get("compose.state", public(bob)))["canSend"] is True
        sent = await chat.set("sendComposedMessage", None, public(bob))
        assert sent["message"]["content"] == "utkast"
        assert (await chat.set("sendComposedMessage", None, public(bob))) == "error: empty composer body"
        topics = []
        while not chat._flow_queue.empty():
            element = chat._flow_queue.get_nowait()
            topics.append(element.topic)
        assert "chat.message" in topics and "chat.participant" in topics and "chat.status" in topics

    run(scenario())


def test_agreement_conditions_decide_admission_as_in_swift():
    async def scenario():
        alice, bob, mallory, chat, artifact, acceptance = await _invited_chat(("member",))
        remote_bob = public(bob)
        # An owner-accepted invitee is a member without presenting proof.
        await chat.set("audience.acceptInvites", [bob.uuid], alice)
        assert await chat.add_agreement(await _request(chat, remote_bob), remote_bob) == "signed"
        assert (await chat.set("sendMessage", "hei", remote_bob))["status"] == "sent"

        # The same identity does not meet "invitationAccepted" without proof.
        _, bob2, _, chat2, _, _ = await _invited_chat(("invitationAccepted",))
        await chat2.set("audience.acceptInvites", [bob2.uuid], chat2.owner)
        assert await chat2.add_agreement(await _request(chat2, public(bob2)), public(bob2)) == "rejected"

        # A guest cannot widen the grants or drop the conditions.
        widened = await _request(chat, remote_bob)
        widened["grants"] = widened["grants"] + [{"keypath": "audience.admissionConditions", "permission": {"group": 6, "other": 0}}]
        assert await chat.add_agreement(widened, remote_bob) == "rejected"
        dropped = {**(await _request(chat, remote_bob)), "conditions": []}
        assert await chat.add_agreement(dropped, remote_bob) == "rejected"

        # Without conditions only the owner approves.
        assert await chat.set("audience.admissionConditions", [], alice) == []
        assert await chat.add_agreement(await _request(chat, public(mallory)), public(mallory)) == "rejected"
        assert await chat.add_agreement(await _request(chat, public(mallory), {"messages"}), public(mallory), authorized_by=alice) == "signed"
        assert isinstance(await chat.get("messages", public(mallory)), list)

    run(scenario())


def test_conditions_travel_in_swifts_agreement_wire_format():
    async def scenario():
        _, bob, _, chat, _, _ = await _invited_chat(("invitationAccepted", "member"))
        template = await _request(chat, public(bob))
        assert [c["type"] for c in template["conditions"]] == ["lookup", "lookup"]
        assert template["conditions"][0]["condition"]["keypath"] == "target.audience.admission.invitationAccepted"
        assert template["conditions"][0]["condition"]["expectedValue"] is True
        assert template["conditions"][0]["condition"]["name"] == "Lookup condition"
        grant = next(g for g in template["grants"] if g["keypath"] == "sendMessage")
        assert grant["permission"] == {"group": 6, "other": 0}

    run(scenario())
