"""test.ge.interop (Python): an organization owned by a group, against Swift.

For every `org.*` case in fixtures/interop/v1 (copied from CellProtocol):
decode the wire JSON, re-encode it, compare the signed bytes and the
signature verdict, and reach the same verdict as Swift for the seal, the
approvals, the evaluator's decision on each approval bundle, the role
credential and the status list.

The native tests below repeat the Swift scenarios in OrganizationGenesisTests
and OrganizationVaultTests (test.ge.*), so a Python node decides like a Swift
node: one owner gives roles at the start, adding an owner needs every owner,
a revoked or stale role fails closed.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from cellprotocol.interop import identity_link as il
from cellprotocol.interop import models as m
from cellprotocol.interop import organization as org
from cellprotocol.interop import verify as v

FIXTURES = Path(__file__).parent / "fixtures" / "interop" / "v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
CASES = {
    entry["id"]: json.loads((FIXTURES / entry["file"]).read_text(encoding="utf-8"))
    for entry in MANIFEST["cases"]
    if entry["flow"] == "org"
}
SEEDS = {party["name"]: bytes.fromhex(party["seedHex"]) for party in MANIFEST["parties"]}
PARTY = {party["name"]: m.IdentityPublicKeyDescriptor.from_wire(party["descriptor"]) for party in MANIFEST["parties"]}
NOW = float(MANIFEST["verifyAtEpoch"])
TYPES = {**org.ORGANIZATION_WIRE_TYPES, "VCClaim": il.VCClaim}


def _b(text: str) -> bytes:
    return base64.b64decode(text)


def _decode(case: dict):
    return TYPES[case["type"]].from_wire(json.loads(_b(case["encodedBase64"])))


def _policy(case: dict) -> org.GovernancePolicy:
    return _decode(CASES[case["related"]["policy"]])


def test_org_cases_present():
    assert len(CASES) == 23
    assert {case["type"] for case in CASES.values()} == set(TYPES)


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_wire_and_signed_bytes_match_swift(case_id):
    case = CASES[case_id]
    model = _decode(case)
    assert model.to_json_bytes() == _b(case["encodedBase64"])
    assert model.canonical_payload() == _b(case["canonicalBase64"]), model.canonical_payload().decode("utf-8")
    if "signer" in case:
        signer = m.IdentityPublicKeyDescriptor.from_wire(case["signer"])
        signature = _b(case["signatureBase64"]) if "signatureBase64" in case else None
        assert v.verify_signature(signature, model.canonical_payload(), signer) is case["expect"]["signatureValid"]


def _verdict(case: dict) -> str:
    model = _decode(case)
    kind = case["type"]
    if kind in ("GovernancePolicy", "OrganizationActionProposal"):
        return "valid"
    if kind == "OrganizationGenesisSeal":
        return org.seal_verdict(model, _policy(case))
    if kind == "OrganizationApproval":
        return "valid" if model.signature_is_valid() else "bad_signature"
    if kind == "ApprovalBundle":
        return org.bundle_verdict(_policy(case), model, NOW)
    if kind == "VCClaim":
        return "valid" if org.verify_role_credential(model) else "invalid"
    if kind == "OrganizationRoleStatusList":
        return "valid" if model.signature_is_valid() else "bad_signature"
    raise AssertionError(kind)


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_verdict_matches_swift(case_id):
    assert _verdict(CASES[case_id]) == CASES[case_id]["expect"]["verdict"]


def test_derived_hashes_and_summaries_match_swift():
    for case_id in ("org.policy.v1", "org.policy.v2", "org.policy.all-two"):
        assert _decode(CASES[case_id]).policy_hash() == _b(CASES[case_id]["related"]["policyHashBase64"])
    seal = _decode(CASES["org.genesis.valid"])
    assert seal.seal_hash() == _b(CASES["org.genesis.valid"]["related"]["sealHashBase64"])
    proposal = _decode(CASES["org.proposal.role-issue"])
    assert proposal.proposal_hash() == _b(CASES["org.proposal.role-issue"]["related"]["proposalHashBase64"])

    role = CASES["org.role.valid"]
    credential = _decode(role)
    assert org.role_payload_hash(credential) == _b(role["related"]["payloadHashBase64"])
    assert org.role_payload_hash(credential) == proposal.payload_hash
    assert org.role_summary(credential, seal.display_name) == role["related"]["summary"] == proposal.payload_summary
    assert credential.issuer == role["related"]["issuerDID"] == il.did_key(PARTY["custodian"])

    v1, v2 = _decode(CASES["org.policy.v1"]), _decode(CASES["org.policy.v2"])
    amend = _decode(CASES["org.bundle.amend-v2.alice"])
    assert org.amendment_summary(v1, v2) == amend.proposal.payload_summary
    assert amend.proposal.payload_hash == v2.policy_hash()
    assert v2.previous_policy_hash == v1.policy_hash()


def test_python_builds_the_same_policy_seal_and_role_as_swift():
    """Ed25519 is deterministic, so Python's signatures equal Swift's."""
    alice_sign, _ = v.ed25519_signer(SEEDS["alice"])
    custodian_sign, _ = v.ed25519_signer(SEEDS["custodian"])
    v1 = org.owner_group_policy(policy_id="entity:interop-gruppe", owners=[PARTY["alice"]],
                                agreement=org.ROLES_ONE_GOVERNANCE_ALL, valid_from="2026-10-01T00:00:00Z")
    assert v1.to_json_bytes() == _b(CASES["org.policy.v1"]["encodedBase64"])

    seal = org.OrganizationGenesisSeal(
        anchor_id="entity:interop-gruppe", display_name="Interop-gruppa (test)",
        initial_policy_hash=v1.policy_hash(), custodian_key=PARTY["custodian"],
        founders=[PARTY["alice"]], sealed_at="2026-10-27T11:58:00Z")
    seal.sign(PARTY["alice"], alice_sign, "2026-10-27T11:58:00Z")
    assert seal.to_json_bytes() == _b(CASES["org.genesis.valid"]["encodedBase64"])
    seal.verify(v1)

    credential = org.unsigned_role_credential(
        organization_anchor_id="entity:interop-gruppe", credential_type="InteropGruppeRoleCredential",
        custodian=PARTY["custodian"], subject=PARTY["bob"], role="researcher", cohort="MasterHAVEN26",
        valid_until="2027-06-30", policy_hash=v1.policy_hash(),
        issued_at=il.parse_iso8601("2026-10-27T11:59:45Z").timestamp(),
        claim_uuid="0201E000-0000-4000-8000-000000000001")
    credential.proof.signature_data = custodian_sign(credential.unsigned_bytes())
    assert credential.to_json_bytes() == _b(CASES["org.role.valid"]["encodedBase64"])

    status = org.OrganizationRoleStatusList.make(
        organization_anchor_id="entity:interop-gruppe", issuer_did=il.did_key(PARTY["custodian"]),
        sequence=2, issued_at="2026-10-27T11:59:50Z", revoked_credential_ids=[credential.id, credential.id])
    status.signature = custodian_sign(status.canonical_payload())
    assert status.to_json_bytes() == _b(CASES["org.status.v2"]["encodedBase64"])


# ---------------------------------------------------------------------------
# Native scenarios (test.ge.*), same as the Swift suites
# ---------------------------------------------------------------------------

ANCHOR = "entity:interop-gruppe"
T0 = "2026-10-27T11:59:00Z"
T_END = "2026-10-27T12:09:00Z"
T_APPROVE = "2026-10-27T11:59:30Z"


def _signer(name: str):
    return v.ed25519_signer(SEEDS[name])[0]


def _policy_for(names, agreement=org.ROLES_ONE_GOVERNANCE_ALL, version=1, previous=None):
    return org.owner_group_policy(policy_id=ANCHOR, owners=[PARTY[n] for n in names], agreement=agreement,
                                  valid_from="2026-10-01T00:00:00Z", version=version,
                                  previous_policy_hash=previous.policy_hash() if previous else None)


def _proposal(policy, action=org.ROLE_ISSUE, proposer="alice", label="p"):
    return org.OrganizationActionProposal(
        proposal_id=f"prop-{label}", organization_anchor_id=ANCHOR, policy_hash=policy.policy_hash(),
        action_class=action, payload_hash=b"\x01" * 32, payload_summary="test", audience=ANCHOR,
        created_at=T0, expires_at=T_END, nonce=label.encode(), proposer=PARTY[proposer])


def _bundle(proposal, names):
    return org.ApprovalBundle(proposal, [org.OrganizationApproval.signed(proposal, PARTY[n], _signer(n), T_APPROVE) for n in names])


def _amend(current, nxt, names, label):
    proposal = org.amendment_proposal(current, nxt, organization_anchor_id=ANCHOR, proposer=PARTY["alice"],
                                      proposal_id=f"amend-{label}", created_at=T0, expires_at=T_END, nonce=label.encode())
    return _bundle(proposal, names)


def test_ge_start_one_owner_gives_roles_and_outsider_cannot():
    v1 = _policy_for(["alice"])
    assert org.evaluate(v1, _bundle(_proposal(v1), ["alice"]), NOW).rule_id == org.ROLES_RULE_ID
    with pytest.raises(org.OrganizationFailure) as refused:
        org.evaluate(v1, _bundle(_proposal(v1, proposer="mallory"), ["mallory"]), NOW)
    assert refused.value.code == "approverNotMember"


def test_ge_owner_change_is_a_new_version_needing_all_owners():
    v1 = _policy_for(["alice"])
    v2 = _policy_for(["alice", "bob"], version=2, previous=v1)
    org.verify_amendment(v1, v2, _amend(v1, v2, ["alice"], "v2"), ANCHOR)
    v3 = _policy_for(["alice", "bob", "mallory"], version=3, previous=v2)
    with pytest.raises(org.OrganizationFailure) as refused:
        org.verify_amendment(v2, v3, _amend(v2, v3, ["alice"], "v3"), ANCHOR)
    assert (refused.value.code, str(refused.value)) == ("approvalsRefused", "approvalsRefused: clauseNotSatisfied")
    org.verify_amendment(v2, v3, _amend(v2, v3, ["alice", "bob"], "v3b"), ANCHOR)

    skipped = _policy_for(["alice", "bob"], version=3, previous=v1)
    with pytest.raises(org.OrganizationFailure) as refused:
        org.verify_amendment(v1, skipped, _amend(v1, skipped, ["alice"], "skip"), ANCHOR)
    assert refused.value.code == "versionNotNext"
    role_bundle = _bundle(_proposal(v1), ["alice"])
    with pytest.raises(org.OrganizationFailure) as refused:
        org.verify_amendment(v1, v2, role_bundle, ANCHOR)
    assert refused.value.code == "proposalIsNotAnAmendment"


@pytest.mark.parametrize("agreement,owners,approvers,action,expected", [
    (org.ROLES_ONE_GOVERNANCE_ALL, ["alice", "bob"], ["alice"], org.ROLE_ISSUE, "met:roller:0"),
    (org.ROLES_ONE_GOVERNANCE_ALL, ["alice", "bob"], ["alice"], org.POLICY_AMEND, "clauseNotSatisfied"),
    (org.ALL_TWO, ["alice", "bob"], ["alice"], org.ROLE_ISSUE, "clauseNotSatisfied"),
    (org.ALL_TWO, ["alice", "bob"], ["alice", "bob"], org.POLICY_AMEND, "met:styring:0"),
    (org.ONE_ALONE, ["alice", "bob"], ["bob"], org.POLICY_AMEND, "met:styring:0"),
    (org.TWO_OF_THREE, ["alice", "bob", "mallory"], ["alice"], org.ROLE_REVOKE, "clauseNotSatisfied"),
    (org.TWO_OF_THREE, ["alice", "bob", "mallory"], ["bob", "mallory"], org.ROLE_REVOKE, "met:roller:0"),
    (org.TWO_OF_THREE, ["alice", "bob", "mallory"], ["alice", "mallory"], org.POLICY_AMEND, "met:styring:0"),
])
def test_ge_agreement_templates(agreement, owners, approvers, action, expected):
    policy = _policy_for(owners, agreement)
    assert org.bundle_verdict(policy, _bundle(_proposal(policy, action, label=action), approvers), NOW) == expected


def test_ge_impossible_quorum_is_refused_when_the_policy_is_built():
    with pytest.raises(org.OrganizationFailure) as refused:
        _policy_for(["alice"], org.ALL_TWO)
    assert refused.value.code == "quorumCannotBeMet"


def test_ge_genesis_founders_must_be_the_owners():
    v1 = _policy_for(["alice", "bob"])
    seal = org.OrganizationGenesisSeal(anchor_id=ANCHOR, display_name="G", initial_policy_hash=v1.policy_hash(),
                                       custodian_key=PARTY["custodian"], founders=[PARTY["alice"]], sealed_at=T0)
    seal.sign(PARTY["alice"], _signer("alice"), T0)
    assert org.seal_verdict(seal, v1) == "ownerNotFounder"
    seal.founders.append(PARTY["bob"])
    assert org.seal_verdict(seal, v1) == "founderSignatureInvalid"  # Alice signed the old founder list
    seal.sign(PARTY["alice"], _signer("alice"), T0)
    assert org.seal_verdict(seal, v1) == "founderSignatureMissing"
    seal.sign(PARTY["bob"], _signer("bob"), T0)
    assert org.seal_verdict(seal, v1) == "valid"


def _rig():
    """The Swift fixture's role credential, a trusted issuer and a fresh mirror."""
    credential = _decode(CASES["org.role.valid"])
    issuer = CASES["org.role.valid"]["related"]["issuerDID"]
    registry = org.CredentialStatusRegistry()
    registry.accept(_decode(CASES["org.status.v1"]), now=NOW)
    return credential, issuer, registry


def _access(credential, issuer, registry, now=NOW, expected_role="researcher", trusted=True):
    return org.role_access(
        credential, trusted_issuers={issuer: ["informasjonssystemer.researcher"]} if trusted else {},
        context_id="informasjonssystemer.researcher", requester_did=il.did_key(PARTY["bob"]),
        required_type="InteropGruppeRoleCredential", expected_role=expected_role, registry=registry, now=now)


def test_ge_role_opens_until_revoked_and_stale_mirror_fails_closed():
    credential, issuer, registry = _rig()
    granted = _access(credential, issuer, registry)
    assert granted.decision == "trusted", granted.reasons
    assert "revocation_status_valid" in granted.reasons
    assert _access(credential, issuer, registry, expected_role="supervisor").decision == "untrusted"

    stale = _access(credential, issuer, registry, now=NOW + org.DEFAULT_MAXIMUM_AGE + 1)
    assert stale.decision == "untrusted" and "revocation_status_unknown" in stale.reasons

    registry.accept(_decode(CASES["org.status.v2"]), now=NOW)
    revoked = _access(credential, issuer, registry)
    assert revoked.decision == "untrusted" and "revocation_check_failed" in revoked.reasons

    with pytest.raises(org.OrganizationFailure) as refused:
        registry.accept(_decode(CASES["org.status.v1"]), now=NOW)
    assert refused.value.code == "sequenceNotNewer"
    with pytest.raises(org.OrganizationFailure) as refused:
        registry.accept(_decode(CASES["org.status.wrong-key"]), now=NOW)
    assert refused.value.code == "signatureInvalid"


def test_ge_untrusted_issuer_expired_role_and_tampered_role_are_refused():
    credential, issuer, registry = _rig()
    assert _access(credential, issuer, registry, trusted=False).reasons == ["issuer_not_registered_or_inactive"]

    after_end = il.parse_iso8601("2027-07-01T00:00:00Z").timestamp()
    registry.accept(_decode(CASES["org.status.v1"]), now=after_end)  # same list again refreshes the mirror
    expired = _access(credential, issuer, registry, now=after_end)
    assert expired.decision == "untrusted" and "vc_subject_validity_expired" in expired.reasons

    tampered = _decode(CASES["org.role.tampered"])
    refused = _access(tampered, issuer, registry, expected_role="supervisor")
    assert refused.decision == "untrusted" and "vc_signature_invalid" in refused.reasons


def test_ge_status_list_is_deduplicated_and_sorted_like_swift():
    status = org.OrganizationRoleStatusList.make(organization_anchor_id=ANCHOR, issuer_did="did:key:z", sequence=3,
                                                 issued_at=T0, revoked_credential_ids=["b", "a", "b"])
    assert status.revoked_credential_ids == ["a", "b"]
    assert status.summary("G", ["b", "a"]) == "G trekker tilbake 2 rolle(r): a, b. Statusliste nr. 3."


# ---------------------------------------------------------------------------
# test.ge.condition-interop: the shared access table (Python column)
# ---------------------------------------------------------------------------

MATRIX = json.loads((FIXTURES / "org.access-matrix.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", MATRIX["scenarios"], ids=lambda s: s["id"])
def test_access_matrix_matches_shared_table(scenario):
    credential = _decode(CASES["org.role.tampered" if scenario["credential"] == "tampered" else "org.role.valid"])
    issuer = CASES["org.role.valid"]["related"]["issuerDID"]
    # "expired": check after the signed validUntil (2027-06-30) instead of issuing a new credential.
    now = il.parse_iso8601("2027-07-01T00:00:00Z").timestamp() if scenario["credential"] == "expired" else NOW
    registry = org.CredentialStatusRegistry()
    mirrored_at = now - MATRIX["maximumMirrorAgeSeconds"] - 1 if scenario["status"] == "stale" else now
    registry.accept(_decode(CASES["org.status.v1"]), now=mirrored_at)
    if scenario["status"] == "revoked":
        registry.accept(_decode(CASES["org.status.v2"]), now=mirrored_at)
    result = org.role_access(
        credential,
        trusted_issuers={issuer: [MATRIX["contextId"]]} if scenario["issuerTrusted"] else {},
        context_id=MATRIX["contextId"], requester_did=il.did_key(PARTY["bob"]),
        required_type="InteropGruppeRoleCredential", expected_role=scenario["expectedRole"],
        registry=registry, now=now)
    assert ("met" if result.decision == "trusted" else "unresolved") == scenario["decision"], result.reasons
    assert scenario["reason"] in result.reasons
