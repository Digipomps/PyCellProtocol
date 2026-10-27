"""EntityAnchor identityLinks.*: genesis, approve, complete and revoke, verified as in Swift."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import pytest

from cellprotocol.cells import EntityAnchorCell
from cellprotocol.cells.entity_anchor import descriptor_for
from cellprotocol.identity import InMemoryIdentityVault
from cellprotocol.interop import identity_link as il
from cellprotocol.interop import models as m
from cellprotocol.interop import verify as v

FIXTURES = Path(__file__).parent / "fixtures" / "interop" / "v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
SEEDS = {party["name"]: bytes.fromhex(party["seedHex"]) for party in MANIFEST["parties"]}
DESCRIPTORS = {party["name"]: m.IdentityPublicKeyDescriptor.from_wire(party["descriptor"]) for party in MANIFEST["parties"]}
NOW = MANIFEST["verifyAtEpoch"] - 30
CHALLENGE = b"\x07" * 32
DOMAIN = "node.example"


def run(coro):
    return asyncio.run(coro)


def _request() -> m.IdentityEnrollmentRequest:
    case = json.loads((FIXTURES / "extend.request.valid.json").read_text(encoding="utf-8"))
    return m.IdentityEnrollmentRequest.from_wire(json.loads(base64.b64decode(case["encodedBase64"])))


def _completion(package: dict, request: m.IdentityEnrollmentRequest) -> dict:
    """What Bob, the new key, sends back after presenting the credential."""
    package = il.IdentityLinkApprovalPackage.from_wire(package)
    bob_sign, _ = v.ed25519_signer(SEEDS["bob"])
    presentation = il.VCPresentation.bind_and_sign(
        credentials=[package.same_entity_credential],
        holder=request.new_identity,
        signer=bob_sign,
        challenge=CHALLENGE,
        domain=DOMAIN,
        presentation_uuid="9E5E0000-0000-4000-8000-0000000000A1",
        created_at=NOW,
    )
    return il.IdentityLinkCompletionEnvelope(
        request=request,
        approval=package.approval,
        same_entity_credential=package.same_entity_credential,
        presentation=presentation,
        issuer_identity=package.issuer_identity,
        expected_audience=request.audience,
        expected_origin=request.origin,
        expected_presentation_challenge=CHALLENGE,
        expected_presentation_domain=DOMAIN,
    ).to_wire()


async def _anchor():
    owner = await InMemoryIdentityVault().identity("owner")
    return owner, EntityAnchorCell(owner=owner, clock=lambda: NOW)


def test_genesis_seals_to_the_owner_once():
    async def scenario():
        owner, anchor = await _anchor()
        sealed = await anchor.set("identityLinks.genesis", {"trigger": "onboarding"}, owner)
        assert sealed["status"] == "sealed"
        seal = il.EntityGenesisSeal.from_wire(sealed["seal"])
        record = il.IdentityLinkRecord.from_wire(sealed["record"])
        il.verify_genesis(seal, record)
        assert record.linked_identity.same_key(descriptor_for(owner)) and record.approved_scopes == ["same_entity"]

        again = await anchor.set("identityLinks.genesis", "onboarding", owner)
        assert again["code"] == "alreadySealed"
        assert (await anchor.set("identityLinks.genesis.trigger", "directEdit", owner))["code"] == "genesisKeypathIsImmutable"
        assert (await anchor.set(il.record_keypath(record.link_id), {}, owner))["code"] == "genesisKeypathIsImmutable"
        assert (await anchor.set("identityLinks.revoke", record.link_id, owner))["code"] == "cannotRevokeGenesisLink"

    run(scenario())


def test_first_persist_seals_and_strangers_cannot():
    async def scenario():
        owner, anchor = await _anchor()
        stranger = await InMemoryIdentityVault().identity("stranger")
        envelope = {"schema": "test", "mutations": [{"keypath": "person.displayName", "value": "Ada"}]}
        with pytest.raises(PermissionError):
            await anchor.set("entity.batchPersist", envelope, stranger)
        assert (await anchor.get("identityLinks.state", owner))["sealed"] is False
        assert (await anchor.set("entity.batchPersist", envelope, owner))["status"] == "persisted"
        state = await anchor.get("identityLinks.state", owner)
        assert state["sealed"] is True and state["genesis"]["trigger"] == "firstPersist"
        with pytest.raises(PermissionError):
            await anchor.set("identityLinks.genesis", {}, stranger)

    run(scenario())


def test_approve_complete_replay_and_revoke():
    async def scenario():
        owner, anchor = await _anchor()
        request = _request()
        approved = await anchor.set(
            "identityLinks.approveEnrollment", il.IdentityLinkApprovalEnvelope(request=request, approved_scopes=["chat.read"]).to_wire(), owner
        )
        assert approved["status"] == "approved", approved
        package = approved["approvalPackage"]
        approval = m.IdentityEnrollmentApproval.from_wire(package["approval"])
        v.verify_enrollment_approval(approval, descriptor_for(owner), request)

        completion = _completion(package, request)
        completed = await anchor.set("identityLinks.completeEnrollment", completion, owner)
        assert completed["status"] == "completed", completed
        record = il.IdentityLinkRecord.from_wire(completed["record"])
        assert record.linked_identity.same_key(DESCRIPTORS["bob"]) and record.approved_scopes == ["chat.read"]

        replay = await anchor.set("identityLinks.completeEnrollment", completion, owner)
        assert replay["code"] == "replayDetected"

        revoked = await anchor.set("identityLinks.revoke", {"linkID": record.link_id}, owner)
        assert revoked["status"] == "revoked" and revoked["record"]["revokedAt"]

    run(scenario())


def test_complete_refuses_a_tampered_or_unsigned_chain():
    async def scenario():
        owner, anchor = await _anchor()
        request = _request()
        approved = await anchor.set("identityLinks.approveEnrollment", il.IdentityLinkApprovalEnvelope(request=request).to_wire(), owner)
        completion = _completion(approved["approvalPackage"], request)
        escalated = json.loads(json.dumps(completion))
        escalated["approval"]["approvedScopes"].append("admin")
        assert (await anchor.set("identityLinks.completeEnrollment", escalated, owner))["status"] == "error"
        assert (await anchor.set("identityLinks.completeEnrollment", {"linkID": "x"}, owner))["code"] == "bad_payload"
        assert (await anchor.set("identityLinks.approveEnrollment", {"approvalID": "a"}, owner))["code"] == "bad_payload"

    run(scenario())
