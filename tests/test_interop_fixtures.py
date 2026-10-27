"""test.interop.fixtures (Python): PyCellProtocol reproduces Swift byte for byte.

For every case in fixtures/interop/v1 (copied from CellProtocol), decode the
wire JSON into the Python model, re-encode it, and compare the canonical bytes,
the signature verdict and the verifier verdict with what Swift produced.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from cellprotocol.interop import WIRE_TYPES, canonical_json, sorted_keys
from cellprotocol.interop import models as m
from cellprotocol.interop import verify as v

FIXTURES = Path(__file__).parent / "fixtures" / "interop" / "v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
CASES = {entry["id"]: json.loads((FIXTURES / entry["file"]).read_text(encoding="utf-8")) for entry in MANIFEST["cases"]}
NOW = float(MANIFEST["verifyAtEpoch"])


def _b(text: str) -> bytes:
    return base64.b64decode(text)


def _decode(case: dict) -> m.WireModel:
    return WIRE_TYPES[case["type"]].from_wire(json.loads(_b(case["encodedBase64"])))


def _signer(case: dict) -> m.IdentityPublicKeyDescriptor:
    return m.IdentityPublicKeyDescriptor.from_wire(case["signer"])


def _related(case: dict, name: str):
    return _decode(CASES[case["related"][name]])


def test_manifest_covers_all_three_flows_and_the_bridge_proof():
    flows = {entry["flow"] for entry in MANIFEST["cases"]}
    assert flows == {"extend", "invite", "chat", "bridge"}
    assert len(CASES) >= 28


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_model_round_trip_reproduces_swift_wire_json(case_id):
    case = CASES[case_id]
    model = _decode(case)
    # The wire JSON Swift wrote (JSONEncoder, sortedKeys) is what we write too.
    assert model.to_json_bytes() == _b(case["encodedBase64"])


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_canonical_bytes_match_swift(case_id):
    case = CASES[case_id]
    model = _decode(case)
    produced = model.signing_data() if isinstance(model, m.IdentitySigningChallenge) else model.canonical_payload()
    assert produced == _b(case["canonicalBase64"]), produced.decode("utf-8")


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_signature_verdict_matches_swift(case_id):
    case = CASES[case_id]
    signature = _b(case["signatureBase64"]) if "signatureBase64" in case else None
    ok = v.verify_signature(signature, _b(case["canonicalBase64"]), _signer(case))
    assert ok is case["expect"]["signatureValid"]


def _verifier_verdict(case: dict) -> str:
    model = _decode(case)
    kind = case["type"]
    if case["flow"] == "extend":
        # v1 records the envelope signature only for the extend flow; the full
        # IdentityLinkProtocolService verdicts arrive with the extend cell.
        signature_ok = v.verify_signature(model.proof.signature, model.canonical_payload(), _signer(case))
        return "valid" if signature_ok else "bad_signature"
    if kind == "HavenInviteTicket":
        return v.verify_ticket(model, now=NOW)
    if kind == "HavenInvitePublication":
        return v.verdict(lambda: v.verify_publication(model, now=NOW))
    if kind == "HavenInviteReply":
        return v.verdict(lambda: v.verify_reply(model, _related(case, "ticket"), now=NOW))
    if kind == "HavenInviteRevocationNotice":
        return v.verdict(lambda: v.verify_revocation_notice(model, _related(case, "ticket")))
    if kind == "HavenInviteContactRequest":
        return v.verdict(lambda: v.verify_contact_request(model, _related(case, "ticket"), now=NOW))
    if kind == "ChatInvitationArtifact":
        return v.verdict(lambda: v.verify_chat_invitation(model, now=NOW))
    if kind == "ChatInvitationAcceptance":
        return v.verdict(lambda: v.verify_chat_acceptance(model, _related(case, "invitation"), now=NOW))
    if kind == "IdentitySigningChallenge":
        return v.verdict(lambda: v.validate_signing_challenge(_b(case["canonicalBase64"]), _signer(case), now=NOW))
    raise AssertionError(f"no verifier for {kind}")


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_verifier_verdict_matches_swift(case_id):
    case = CASES[case_id]
    assert _verifier_verdict(case) == case["expect"]["verdict"]


def test_derived_hashes_match_swift():
    request = _decode(CASES["extend.request.valid"])
    assert v.request_hash(request) == _b(CASES["extend.request.valid"]["related"]["requestHashBase64"])
    approval = _decode(CASES["extend.approval.valid"])
    assert approval.request_hash == v.request_hash(request)
    artifact = _decode(CASES["chat.invitation.valid"])
    assert v.invitation_hash(artifact) == _b(CASES["chat.invitation.valid"]["related"]["invitationHashBase64"])
    ticket = _decode(CASES["invite.ticket.valid"])
    assert ticket.to_token() == CASES["invite.ticket.valid"]["related"]["ticketToken"]
    assert m.HavenInviteTicket.from_token(ticket.to_token()) == ticket


def test_python_signed_envelopes_verify_like_swift_ones():
    """A Python node can mint what a Swift node accepts: same bytes, Ed25519."""
    seeds = {party["name"]: bytes.fromhex(party["seedHex"]) for party in MANIFEST["parties"]}
    sign, public = v.ed25519_signer(seeds["alice"])
    alice = m.IdentityPublicKeyDescriptor.from_wire(next(p for p in MANIFEST["parties"] if p["name"] == "alice")["descriptor"])
    assert alice.public_key == public

    ticket = _decode(CASES["invite.ticket.valid"]).replace(proof=None, ticket_id="inv-python-0001")
    signed = v.sign_model(ticket, sign, alice.uuid)
    assert v.verify_ticket(signed, now=NOW) == "valid"
    # Ed25519 (RFC 8032) is deterministic: the Python signature over Swift's
    # bytes for the same ticket equals the Swift one.
    swift_ticket = _decode(CASES["invite.ticket.valid"])
    resigned = v.sign_model(swift_ticket.replace(proof=None), sign, alice.uuid)
    assert resigned.proof.signature == swift_ticket.proof.signature


def test_foundation_key_order_is_not_byte_order():
    assert sorted_keys(["requestID", "requestedScopes", "requestedDomains"]) == [
        "requestedDomains",
        "requestedScopes",
        "requestID",
    ]
    assert sorted_keys(["k10", "k9", "K1"]) == ["K1", "k9", "k10"]


def test_canonical_strings_escape_like_foundation():
    assert canonical_json({"a": "x/y \"q\" \\ \n\t\u0001 æ 🙂"}) == (
        '{"a":"x\\/y \\"q\\" \\\\ \\n\\t\\u0001 æ 🙂"}'.encode("utf-8")
    )
