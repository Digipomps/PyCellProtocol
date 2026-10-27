"""test.interop.extend (Python): entity extension completion against the Swift fixtures.

The credential, the presentation and the completion envelope are checked on
wire bytes, signed bytes, signature and verdict. A credential and presentation
that Python builds from the same inputs carry the very same signatures, since
Ed25519 is deterministic.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from cellprotocol.interop import identity_link as il
from cellprotocol.interop import models as m
from cellprotocol.interop import verify as v

FIXTURES = Path(__file__).parent / "fixtures" / "interop" / "v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
CASES = {
    entry["id"]: json.loads((FIXTURES / entry["file"]).read_text(encoding="utf-8"))
    for entry in MANIFEST["cases"]
    if entry["type"] in ("VCClaim", "VCPresentation", "IdentityLinkCompletionEnvelope", "EntityGenesisSeal")
}
SEEDS = {party["name"]: bytes.fromhex(party["seedHex"]) for party in MANIFEST["parties"]}
DESCRIPTORS = {party["name"]: m.IdentityPublicKeyDescriptor.from_wire(party["descriptor"]) for party in MANIFEST["parties"]}
VERIFY_AT = MANIFEST["verifyAtEpoch"]
TYPES = {"EntityGenesisSeal": il.EntityGenesisSeal, "VCClaim": il.VCClaim, "VCPresentation": il.VCPresentation, "IdentityLinkCompletionEnvelope": il.IdentityLinkCompletionEnvelope}


def _b(text: str) -> bytes:
    return base64.b64decode(text)


def _decode(case: dict):
    return TYPES[case["type"]].from_wire(json.loads(_b(case["encodedBase64"])))


def test_cases_present():
    assert len(CASES) == 14


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_wire_and_signed_bytes_match_swift(case_id):
    case = CASES[case_id]
    model = _decode(case)
    assert model.to_json_bytes() == _b(case["encodedBase64"])
    assert model.canonical_payload() == _b(case["canonicalBase64"])
    signer = m.IdentityPublicKeyDescriptor.from_wire(case["signer"])
    assert v.verify_signature(_b(case["signatureBase64"]), model.canonical_payload(), signer) == case["expect"]["signatureValid"]


def _verdict(case: dict) -> str:
    model = _decode(case)
    if case["type"] == "VCClaim":
        return "valid" if model.verify(DESCRIPTORS["alice"]) else "invalid"
    if case["type"] == "EntityGenesisSeal":
        record = il.IdentityLinkRecord.from_wire(json.loads(_b(case["related"]["recordBase64"])))
        try:
            il.verify_genesis(model, record)
        except il.LinkFailure as failure:
            return failure.code
        return "valid"
    if case["type"] == "VCPresentation":
        challenge = base64.b64decode(CASES["extend.completion.valid"]["object"]["expectedPresentationChallenge"])
        return "valid" if model.verify_holder_proof(challenge, "staging.haven.digipomps.org") else "invalid"
    try:
        il.verify_completion(model, now=VERIFY_AT)
    except il.LinkFailure as failure:
        return failure.code
    return "valid"


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_verdict_matches_swift(case_id):
    assert _verdict(CASES[case_id]) == CASES[case_id]["expect"]["verdict"]


def test_completion_record_matches_swift():
    case = CASES["extend.completion.valid"]
    result = il.verify_completion(_decode(case), now=VERIFY_AT)
    assert result.record.to_json_bytes() == _b(case["related"]["recordBase64"])
    assert result.record.link_id == case["related"]["linkID"]


def test_did_key_matches_swift():
    related = CASES["extend.credential.valid"]["related"]
    assert il.did_key(DESCRIPTORS["alice"]) == related["issuerDID"]
    assert il.did_key(DESCRIPTORS["bob"]) == related["holderDID"]
    curve, key = il.public_key_from_did_key(related["holderDID"])
    assert curve == "Curve25519" and key == DESCRIPTORS["bob"].public_key


def test_replayed_approval_is_refused():
    envelope = _decode(CASES["extend.completion.valid"])
    with pytest.raises(il.LinkFailure) as failure:
        il.verify_completion(envelope, now=VERIFY_AT, used_approval_jtis={envelope.approval.jti})
    assert failure.value.code == "replayDetected"


def test_python_built_credential_and_presentation_equal_swift():
    valid = _decode(CASES["extend.completion.valid"])
    swift_claim = valid.same_entity_credential
    alice_sign, _ = v.ed25519_signer(SEEDS["alice"])
    bob_sign, _ = v.ed25519_signer(SEEDS["bob"])
    subject = dict(swift_claim.credential_subject)
    subject.pop("id")
    claim = il.VCClaim.issue(
        credential_type=il.CREDENTIAL_TYPE,
        issuer=DESCRIPTORS["alice"],
        subject=valid.request.new_identity,
        credential_subject=subject,
        signer=alice_sign,
        claim_uuid=swift_claim.id.rsplit("/", 1)[-1],
        issued_at=il.parse_iso8601(swift_claim.issuance_date).timestamp(),
    )
    assert claim.to_json_bytes() == swift_claim.to_json_bytes()

    swift_presentation = valid.presentation
    presentation = il.VCPresentation.bind_and_sign(
        credentials=[claim],
        holder=DESCRIPTORS["bob"],
        signer=bob_sign,
        challenge=swift_presentation.challenge,
        domain=swift_presentation.domain,
        presentation_uuid=swift_presentation.id.rsplit("/", 1)[-1],
        created_at=il.parse_iso8601(swift_presentation.proof.created).timestamp(),
    )
    assert presentation.to_json_bytes() == swift_presentation.to_json_bytes()


def test_python_approver_and_new_key_complete_a_link():
    """Python on both sides: approve, present, complete."""
    valid = _decode(CASES["extend.completion.valid"])
    request = valid.request
    alice_sign, _ = v.ed25519_signer(SEEDS["alice"])
    bob_sign, _ = v.ed25519_signer(SEEDS["bob"])
    now = VERIFY_AT - 30
    package = il.approve_enrollment(
        il.IdentityLinkApprovalEnvelope(request=request, approved_scopes=["chat.read"]),
        issuer=DESCRIPTORS["alice"],
        signer=alice_sign,
        now=now,
        approval_id="APR-PY-0001",
        credential_uuid="C1A10000-0000-4000-8000-0000000000F1",
    )
    challenge = b"\x07" * 32
    presentation = il.VCPresentation.bind_and_sign(
        credentials=[package.same_entity_credential],
        holder=request.new_identity,
        signer=bob_sign,
        challenge=challenge,
        domain="node.example",
        presentation_uuid="9E5E0000-0000-4000-8000-0000000000F1",
        created_at=now,
    )
    envelope = il.IdentityLinkCompletionEnvelope(
        request=request,
        approval=package.approval,
        same_entity_credential=package.same_entity_credential,
        presentation=presentation,
        issuer_identity=package.issuer_identity,
        expected_audience=request.audience,
        expected_origin=request.origin,
        expected_presentation_challenge=challenge,
        expected_presentation_domain="node.example",
    )
    # Survives the wire both ways.
    envelope = il.IdentityLinkCompletionEnvelope.from_wire(json.loads(envelope.to_json_bytes()))
    result = il.verify_completion(envelope, now=VERIFY_AT)
    assert result.record.approved_scopes == ["chat.read"]
    assert result.record.linked_identity.same_key(request.new_identity)


def test_base58_round_trip_with_leading_zeros():
    for data in (b"", b"\x00", b"\x00\x00\x01", b"\xed\x01" + bytes(range(32))):
        assert il.base58_decode(il.base58_encode(data)) == data


def test_python_built_genesis_seal_equals_swift():
    case = CASES["extend.genesis.valid"]
    swift_seal = _decode(case)
    alice_sign, _ = v.ed25519_signer(SEEDS["alice"])
    seal, record = il.seal_genesis(
        swift_seal.anchor_id,
        DESCRIPTORS["alice"],
        alice_sign,
        identity_domain="private",
        trigger="onboarding",
        now=il.parse_iso8601(swift_seal.sealed_at).timestamp(),
    )
    assert seal.to_json_bytes() == swift_seal.to_json_bytes()
    assert record.to_json_bytes() == _b(case["related"]["recordBase64"])
    assert il.record_keypath(record.link_id) == case["related"]["recordKeypath"]
