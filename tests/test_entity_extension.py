"""Entity extension cell (Binding's keypaths) on a Python node."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

from cellprotocol.cells.entity_extension import (
    EntityScaffoldExtensionCell,
    binding_request_hash,
    data_from_base64url,
    human_code,
)
from cellprotocol.identity import InMemoryIdentityVault
from cellprotocol.interop import models as m
from cellprotocol.interop import verify as v

FIXTURES = Path(__file__).parent / "fixtures" / "interop" / "v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
SEEDS = {party["name"]: bytes.fromhex(party["seedHex"]) for party in MANIFEST["parties"]}
DESCRIPTORS = {party["name"]: m.IdentityPublicKeyDescriptor.from_wire(party["descriptor"]) for party in MANIFEST["parties"]}
VERIFY_AT = MANIFEST["verifyAtEpoch"]
AUDIENCE = "https://staging.haven.digipomps.org"


def _case(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def _wire(case: dict) -> dict:
    return json.loads(base64.b64decode(case["encodedBase64"]))


def run(coro):
    return asyncio.run(coro)


def _cell(party: str, now: float = VERIFY_AT) -> EntityScaffoldExtensionCell:
    signer, _ = v.ed25519_signer(SEEDS[party])
    counter = iter(range(1, 10_000))
    return EntityScaffoldExtensionCell(
        descriptor=DESCRIPTORS[party],
        signer=signer,
        display_name=party.capitalize(),
        clock=lambda: now,
        new_uuid=lambda: f"00000000-0000-4000-8000-{next(counter):012d}",
    )


def test_request_hash_and_human_code_match_swift():
    case = _case("extend.request.valid")
    request = m.IdentityEnrollmentRequest.from_wire(_wire(case))
    assert base64.b64encode(binding_request_hash(request)).decode() == case["related"]["bindingRequestHashBase64"]
    assert human_code(request.request_id + request.audience) == case["related"]["humanCode"]


def test_reviews_a_swift_request():
    approver = _cell("alice")
    valid = approver.review_request({"request": _wire(_case("extend.request.valid"))})
    assert valid["status"] == "reviewable" and valid["signatureValid"] is True
    assert valid["humanCode"] == _case("extend.request.valid")["related"]["humanCode"]
    tampered = approver.review_request(_wire(_case("extend.request.tampered")))
    assert tampered["status"] == "rejected" and tampered["signatureValid"] is False


def test_ask_approve_accept_between_two_python_places():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        new_place, approver = _cell("bob"), _cell("alice")
        asked = await new_place.set("extension.beginRequest", {"audience": AUDIENCE, "requestedScopes": ["entity.read", "agreement.sign", "admin"]}, owner)
        assert asked["status"] == "ok" and len(asked["humanCode"]) == 6

        review = await approver.set("extension.reviewRequest", asked["payload"], owner)
        assert review["status"] == "reviewable" and review["unknownScopes"] == ["admin"]
        assert review["humanCode"] == asked["humanCode"]

        approved = await approver.set("extension.approveRequest", {"payload": asked["payload"], "approvedScopes": ["entity.read"]}, owner)
        assert approved["status"] == "ok"
        assert approved["refusedScopes"] == ["admin", "agreement.sign"]
        approval = m.IdentityEnrollmentApproval.from_wire(json.loads(data_from_base64url(approved["payload"])))
        v.verify_enrollment_approval(approval, DESCRIPTORS["alice"])

        accepted = await new_place.set("extension.acceptApproval", {"payload": approved["payload"], "issuerIdentity": approved["issuerIdentity"]}, owner)
        assert accepted["status"] == "ok" and accepted["signatureVerified"] is True
        assert accepted["approvedScopes"] == ["entity.read"]

        state = await new_place.get("extension.state", owner)
        assert state["activeLinkCount"] == 1 and state["pending"][0]["approved"] is True
        assert (await approver.get("extension.links", owner))[0]["status"] == "active"

        revoked = await approver.set("extension.revokeLink", {"linkID": approved["linkID"]}, owner)
        revocation = m.IdentityLinkRevocation.from_wire(revoked["revocation"])
        v.verify_link_revocation(revocation, DESCRIPTORS["alice"])
        assert (await approver.get("extension.links", owner))[0]["status"] == "revoked"

    run(scenario())


def test_accept_refuses_a_foreign_or_tampered_approval():
    new_place, approver, other = _cell("bob"), _cell("alice"), _cell("bob")
    asked = new_place.begin_request({"audience": AUDIENCE})
    approved = approver.approve_request(asked["payload"])

    # Same key, but a different request: the hash does not cover it.
    other.begin_request({"audience": AUDIENCE + "/other"})
    assert other.accept_approval(approved["payload"])["code"] == "request_hash_mismatch"

    approval = json.loads(data_from_base64url(approved["payload"]))
    approval["approvedScopes"].append("agreement.sign")
    tampered = {"approval": approval, "issuerIdentity": approved["issuerIdentity"]}
    assert new_place.accept_approval(tampered)["code"] == "bad_signature"

    # Without the approver's key, Binding links on the hash alone and says so.
    plain = new_place.accept_approval(approved["payload"])
    assert plain["status"] == "ok" and plain["signatureVerified"] is False


def test_accept_refuses_an_expired_approval():
    new_place = _cell("bob")
    asked = new_place.begin_request({"audience": AUDIENCE})
    approved = _cell("alice").approve_request({"payload": asked["payload"], "ttlMinutes": 2})
    new_place._clock = lambda: VERIFY_AT + 3600
    assert new_place.accept_approval(approved["payload"])["code"] == "expired"


def test_refuses_without_audience_or_scopes():
    assert _cell("bob").begin_request({})["code"] == "missing_audience"
    asked = _cell("bob").begin_request({"audience": AUDIENCE, "requestedScopes": ["admin"]})
    assert _cell("alice").approve_request(asked["payload"])["code"] == "no_scopes"
