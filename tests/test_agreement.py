import asyncio

from cellprotocol.bridge import BridgeCommand, BridgeEndpoint
from cellprotocol.value import TypedValue


def test_missing_agreement_handler_rejects_anonymous_request():
    command = BridgeCommand("agreement", TypedValue("agreementPayload", {}), 17)
    (reply,) = asyncio.run(BridgeEndpoint(object()).handle(command))
    assert reply.to_json() == {
        "cmd": "response",
        "cid": 17,
        "&agreementState": "rejected",
    }


def test_owner_approval_proof_and_current_template_at_use(monkeypatch):
    import copy
    from cellprotocol import agreement
    from cellprotocol.general_cell import GeneralCell
    from cellprotocol.identity import Identity, InMemoryIdentityVault

    async def scenario():
        vault = InMemoryIdentityVault()
        owner, member = await vault.identity("owner"), await vault.identity("member")
        clone = Identity.from_json(member.to_json())
        cell = GeneralCell(owner=owner)
        cell.agreement_template.add_grant("r--s", "shared")
        await cell.set("shared", "ok", owner)
        req = (await cell.advertise())["contractTemplate"]
        req["duration"] = 10
        assert await cell.add_agreement(req, member) == "rejected"
        assert await cell.add_agreement(req, clone, authorized_by=owner) == "rejected"
        for field, value in (
            ("duration", -1),
            ("duration", True),
            ("conditions", [{}]),
            ("authorizationPolicyBinding", {}),
            ("owner", member.to_json()),
        ):
            assert (
                await cell.add_agreement(
                    {**req, field: value}, member, authorized_by=owner
                )
                == "rejected"
            )
        assert await cell.add_agreement(req, member, authorized_by=owner) == "signed"
        assert await cell.get("shared", member) == "ok"
        assert not await cell.validate_access("r---", "shared", clone)
        assert not await cell.validate_access("-w--", "shared", member)
        assert not await cell.validate_access("r---", "shared.child", member)
        (receipt,) = await cell.contracts_for(member)
        changed = copy.deepcopy(receipt)
        changed["agreement"]["grants"][0]["permission"]["group"] |= 2
        assert not agreement.valid(changed, owner, member, cell.uuid, cell._template())
        assert not agreement.valid(
            receipt, owner, member, "another cell", cell._template()
        )
        assert not await cell.validate_access("-w--", "shared", member)
        with monkeypatch.context() as patch:
            patch.setattr(agreement.time, "time", lambda: receipt["expiresAt"] + 1)
            assert not await cell.validate_access("r---", "shared", member)
            assert await cell.admit({"identity": member}) == "signContract"
        cell.agreement_template.grants.clear()
        assert not await cell.validate_access("r---", "shared", member)

    asyncio.run(scenario())


def test_bad_handler_and_spoofed_context_fail_closed():
    from cellprotocol.general_cell import GeneralCell
    from cellprotocol.identity import InMemoryIdentityVault

    class Broken:
        async def add_agreement(self, contract, requester):
            raise RuntimeError("failed signing")

    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        spoof = BridgeCommand(
            "admit", TypedValue("connectContext", {"identity": owner}), 3
        )
        (reply,) = await BridgeEndpoint(GeneralCell(owner=owner)).handle(spoof)
        assert reply.to_json()["&connectState"] == "notConnected"
        req = BridgeCommand("agreement", TypedValue("agreementPayload", {}), 5, owner)
        (reply,) = await BridgeEndpoint(Broken()).handle(req)
        assert reply.to_json()["&agreementState"] == "rejected"

    asyncio.run(scenario())


def test_grant_permission_legacy_masks_and_zero_group():
    from cellprotocol.agreement import Grant, covers, permission_masks

    assert permission_masks(" rwxr-- ") == (7, 4)
    assert permission_masks("r--sr---") == (12, 4)
    g = Grant("result", "r--sr---").to_json()
    assert covers(g, {"keypath": "result", "permission": "r---r---"})
    assert not covers(g, {"keypath": "result", "permission": "----r---"})
    assert not covers(g, {"keypath": "result", "permission": "r---rw--"})


def test_anonymous_and_revoked_feeds_do_not_deliver():
    import pytest
    from cellprotocol.general_cell import GeneralCell, FlowElement
    from cellprotocol.identity import InMemoryIdentityVault

    async def scenario():
        vault = InMemoryIdentityVault()
        owner, member = await vault.identity("owner"), await vault.identity("member")
        cell = GeneralCell(owner=owner)
        cell.agreement_template.add_grant("r---", "feed")
        request = (await cell.advertise())["contractTemplate"]
        assert (
            await cell.add_agreement(request, member, authorized_by=owner) == "signed"
        )
        endpoint = BridgeEndpoint(cell, owner=owner)
        cell.push_flow_element(FlowElement("first"))
        with pytest.raises(PermissionError):
            await anext(endpoint.feed_responses(BridgeCommand("feed", cid=3)))
        stream = cell.flow(member)
        assert (await anext(stream)).title == "first"
        cell.agreement_template.grants.clear()
        cell.push_flow_element(FlowElement("revoked"))
        with pytest.raises(PermissionError):
            await anext(stream)

    asyncio.run(scenario())


def test_conditional_template_cannot_be_stripped_or_bypassed_at_use():
    from cellprotocol.general_cell import GeneralCell
    from cellprotocol.identity import InMemoryIdentityVault

    async def scenario():
        vault = InMemoryIdentityVault()
        owner, peer = await vault.identity("owner"), await vault.identity("peer")
        cell = GeneralCell(owner=owner)
        cell.agreement_template.add_grant("r---", "x")
        cell.owner_published_reads = {"x"}
        plain = (await cell.advertise())["contractTemplate"]
        assert await cell.add_agreement(plain, peer) == "signed"
        for key, value in (
            ("conditions", [{"type": "prove"}]),
            ("authorization_policy_binding", {"id": "policy"}),
        ):
            setattr(cell.agreement_template, key, value)
            assert not await cell.validate_access("r---", "x", peer)
            assert (
                await cell.add_agreement(plain, peer, authorized_by=owner) == "rejected"
            )
            setattr(cell.agreement_template, key, [] if key == "conditions" else None)

    asyncio.run(scenario())
