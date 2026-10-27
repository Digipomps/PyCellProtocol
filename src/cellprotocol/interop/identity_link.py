"""Entity extension completion, as CellProtocol Swift does it.

Extending an entity with a new key takes four signed pieces, all checked by
the Cell that owns the entity (`EntityAnchorCell`, keypath
`identityLinks.completeEnrollment`):

1. `IdentityEnrollmentRequest`, signed by the new key (`models`).
2. `IdentityEnrollmentApproval`, signed by an existing key of the entity.
3. A `SameEntityIdentityLinkCredential` (`VCClaim`) from the approver to the new key.
4. A `VCPresentation` of that credential by the new key, bound to the
   server's challenge and domain.

`verify_completion` gives the same answer as Swift's
`IdentityLinkProtocolService.verifyCompletion`, with the same
`IdentityLinkCompletionError` case names.

Signed bytes: `VCClaim` and `VCPresentation` sign JSONEncoder with
`.sortedKeys` and `.withoutEscapingSlashes` of themselves without `proof`
(code-point key order). The claim's `uuid` is never encoded. A presentation
writes `verifiableCredential` as `null` when it has none, and its
credentials keep their proofs.

Swift sources: `Identity/IdentityLinkCompletion.swift`,
`Identity/IdentityLinkingModels.swift`, `Identity/DIDKeyParser.swift`,
`VerifiableCredentials/VCClaim.swift`, `VCPresentation.swift`, `VCProof.swift`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional

from .canonical import canonical_json
from .models import (
    EntityBindingDescriptor,
    IdentityEnrollmentApproval,
    IdentityEnrollmentApprovalProof,
    IdentityEnrollmentRequest,
    IdentityLinkFreshAuthEvidence,
    IdentityPublicKeyDescriptor,
    WireDecodeError,
    WireModel,
    _s,
)
from .verify import Signer, VerificationFailure, request_hash, sha256, verify_signature

VC_CONTEXT = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"]
CREDENTIAL_TYPE = "SameEntityIdentityLinkCredential"
PRESENTATION_TYPE = "SameEntityIdentityLinkPresentation"
ISSUER_TYPES = ("existingDevice", "custodian", "recoveryAuthority")


class LinkFailure(VerificationFailure):
    """`IdentityLinkCompletionError` case name, without associated values."""


# ---------------------------------------------------------------------------
# did:key (DIDKeyParser)
# ---------------------------------------------------------------------------

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_PREFIXES = {"Curve25519": b"\xed\x01", "secp256k1": b"\xe7\x01", "P256": b"\x80\x24"}


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number > 0:
        number, remainder = divmod(number, 58)
        out = _ALPHABET[remainder] + out
    for byte in data:
        if byte != 0:
            break
        out = "1" + out
    return out


def base58_decode(text: str) -> bytes:
    number = 0
    for char in text:
        index = _ALPHABET.find(char)
        if index < 0:
            raise ValueError("not base58")
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading + body


def did_key(descriptor: IdentityPublicKeyDescriptor) -> str:
    """`IdentityLinkProtocolService.did(for:)` / `Identity.did()`."""
    prefix = _PREFIXES.get(descriptor.curve_type)
    if prefix is None:
        raise LinkFailure("missingPublicKey", descriptor.uuid)
    return "did:key:z" + base58_encode(prefix + descriptor.public_key)


def public_key_from_did_key(did: str) -> tuple[str, bytes]:
    """(curveType, public key) from a did:key."""
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    decoded = base58_decode(did[len("did:key:z"):])
    for curve, prefix in _PREFIXES.items():
        if decoded.startswith(prefix):
            return curve, decoded[len(prefix):]
    raise ValueError("unsupported key type")


# ---------------------------------------------------------------------------
# Dates: ISO8601DateFormatter (internet date time, no fractions) and the
# VC RFC 3339 formatter "yyyy-MM-dd'T'HH:mm:ssZZZZZ" in UTC.
# ---------------------------------------------------------------------------

_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:?\d{2})$")


def parse_iso8601(text: str) -> Optional[datetime]:
    match = _ISO.match(text)
    if match is None:
        return None
    zone = match.group(7)
    try:
        moment = datetime(*(int(match.group(i)) for i in range(1, 7)), tzinfo=timezone.utc)
    except ValueError:
        return None
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        moment -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return moment


def iso8601(moment: float) -> str:
    return datetime.fromtimestamp(int(moment // 1), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _vc_encode(wire: dict[str, Any]) -> bytes:
    return canonical_json(wire, key_order="encoder", escape_slashes=False)


# ---------------------------------------------------------------------------
# Verifiable credentials
# ---------------------------------------------------------------------------


@dataclass
class VCProof(WireModel):
    type: str  # Ed25519Signature2020 | EcdsaSecp256r1Signature2019
    created: str  # RFC 3339, whole seconds, UTC
    proof_purpose: str  # assertionMethod | authentication
    verification_method: str  # the signer's identity UUID
    signature_data: bytes = b""

    SPECS = {
        "type": _s("type"),
        "created": _s("created"),
        "proof_purpose": _s("proofPurpose"),
        "verification_method": _s("verificationMethod"),
        "signature_data": _s("signatureData", "bytes"),
    }

    @classmethod
    def from_wire(cls, wire: Any) -> "VCProof":
        proof = super().from_wire(wire)
        if parse_iso8601(proof.created) is None or not proof.created.endswith("Z") and "+" not in proof.created:
            raise WireDecodeError("VCProof.created: not RFC 3339")
        return proof


def proof_type_for(descriptor: IdentityPublicKeyDescriptor) -> Optional[str]:
    return {
        ("EdDSA", "Curve25519"): "Ed25519Signature2020",
        ("ECDSA", "P256"): "EcdsaSecp256r1Signature2019",
    }.get((descriptor.algorithm, descriptor.curve_type))


@dataclass
class VCClaim(WireModel):
    id: str
    type: list[str]
    issuer: Any  # did string (reference) or embedded object
    issuance_date: str
    credential_subject: dict[str, Any]
    proof: VCProof
    context: Optional[list[str]] = None

    SPECS = {
        "context": _s("@context", "strs", optional=True),
        "id": _s("id"),
        "type": _s("type", "strs"),
        "issuer": _s("issuer", "raw"),
        "issuance_date": _s("issuanceDate"),
        "credential_subject": _s("credentialSubject", "raw"),
        "proof": _s("proof", "model", model=VCProof),
    }

    @classmethod
    def from_wire(cls, wire: Any) -> "VCClaim":
        claim = super().from_wire(wire)
        if not isinstance(claim.issuer, (str, dict)) or not isinstance(claim.credential_subject, dict):
            raise WireDecodeError("VCClaim: issuer or credentialSubject has the wrong shape")
        if parse_iso8601(claim.issuance_date) is None:
            raise WireDecodeError("VCClaim.issuanceDate: not RFC 3339")
        return claim

    def unsigned_bytes(self) -> bytes:
        """`VCClaim.canonicalUnsignedClaimData`."""
        wire = self.to_wire()
        wire.pop("proof", None)
        return _vc_encode(wire)

    def canonical_payload(self) -> bytes:
        return self.unsigned_bytes()

    def verify(self, issuer: IdentityPublicKeyDescriptor) -> bool:
        """`VCClaim.verify(issuer:)`."""
        expected_type = proof_type_for(issuer)
        try:
            issuer_did = did_key(issuer)
        except LinkFailure:
            return False
        return (
            self.issuer == issuer_did
            and self.proof.verification_method == issuer.uuid
            and self.proof.proof_purpose == "assertionMethod"
            and expected_type is not None
            and self.proof.type == expected_type
            and 0 < len(self.proof.signature_data) <= 512
            and verify_signature(self.proof.signature_data, self.unsigned_bytes(), issuer)
        )

    @classmethod
    def issue(
        cls,
        *,
        credential_type: str,
        issuer: IdentityPublicKeyDescriptor,
        subject: IdentityPublicKeyDescriptor,
        credential_subject: dict[str, Any],
        signer: Signer,
        claim_uuid: str,
        issued_at: float,
    ) -> "VCClaim":
        """`VCClaim(type:issuerIdentity:subjectIdentity:credentialSubject:)` + `generateProof`."""
        proof_type = proof_type_for(issuer)
        if proof_type is None:
            raise LinkFailure("missingPublicKey", issuer.uuid)
        subject_body = dict(credential_subject)
        subject_body["id"] = did_key(subject)
        claim = cls(
            context=list(VC_CONTEXT),
            id=f"cell:///identity/{subject.uuid}/claims/{claim_uuid}",
            type=["VerifiableCredential", credential_type],
            issuer=did_key(issuer),
            issuance_date=iso8601(issued_at),
            credential_subject=subject_body,
            proof=VCProof(type=proof_type, created=iso8601(issued_at), proof_purpose="assertionMethod", verification_method=issuer.uuid),
        )
        claim.proof.signature_data = signer(claim.unsigned_bytes())
        return claim


@dataclass
class VCPresentation(WireModel):
    id: str
    type: list[str]
    holder: Any
    proof: VCProof
    context: Optional[list[str]] = None
    challenge: Optional[bytes] = None
    domain: Optional[str] = None
    holder_binding: Optional[IdentityPublicKeyDescriptor] = None
    verifiable_credential: Optional[list[VCClaim]] = None

    SPECS = {
        "context": _s("@context", "strs", optional=True),
        "id": _s("id"),
        "type": _s("type", "strs"),
        "holder": _s("holder", "raw"),
        "challenge": _s("challenge", "bytes", optional=True),
        "domain": _s("domain", optional=True),
        "holder_binding": _s("holderBinding", "model", model=IdentityPublicKeyDescriptor, optional=True),
        "verifiable_credential": _s("verifiableCredential", "models", model=VCClaim, optional=True),
        "proof": _s("proof", "model", model=VCProof),
    }

    def to_wire(self) -> dict[str, Any]:
        wire = super().to_wire()
        # Swift encodes this one with `encode`, not `encodeIfPresent`.
        wire.setdefault("verifiableCredential", None)
        return wire

    def unsigned_bytes(self) -> bytes:
        """`VCPresentation.canonicalPayloadData`."""
        wire = self.to_wire()
        wire.pop("proof", None)
        return _vc_encode(wire)

    def canonical_payload(self) -> bytes:
        return self.unsigned_bytes()

    def verify_holder_proof(self, expected_challenge: bytes, expected_domain: str) -> bool:
        """`VCPresentation.verifyHolderProof`."""
        binding = self.holder_binding
        if (
            self.challenge != expected_challenge
            or self.domain != expected_domain
            or binding is None
            or self.proof.proof_purpose != "authentication"
            or self.proof.verification_method != binding.uuid
            or not self.proof.signature_data
        ):
            return False
        try:
            holder_did = did_key(binding)
        except LinkFailure:
            return False
        return (
            self.holder == holder_did
            and self.proof.type == proof_type_for(binding)
            and verify_signature(self.proof.signature_data, self.unsigned_bytes(), binding)
        )

    @classmethod
    def bind_and_sign(
        cls,
        *,
        credentials: list[VCClaim],
        holder: IdentityPublicKeyDescriptor,
        signer: Signer,
        challenge: bytes,
        domain: str,
        presentation_uuid: str,
        created_at: float,
        presentation_type: str = PRESENTATION_TYPE,
    ) -> "VCPresentation":
        """`IdentityLinkProtocolService.makeVerifierBoundPresentation`."""
        proof_type = proof_type_for(holder)
        if proof_type is None:
            raise LinkFailure("missingPublicKey", holder.uuid)
        presentation = cls(
            context=list(VC_CONTEXT),
            id=f"cell:///identity/{holder.uuid}/claims/{presentation_uuid}",
            type=["VerifiableCredential", presentation_type],
            holder=did_key(holder),
            challenge=challenge,
            domain=domain,
            holder_binding=holder,
            verifiable_credential=list(credentials),
            proof=VCProof(type=proof_type, created=iso8601(created_at), proof_purpose="authentication", verification_method=holder.uuid),
        )
        presentation.proof.signature_data = signer(presentation.unsigned_bytes())
        return presentation


@dataclass
class SameEntityIdentityLinkCredentialSubject(WireModel):
    id: str
    entity_binding: EntityBindingDescriptor
    linked_identity: IdentityPublicKeyDescriptor
    approved_domains: list[str]
    approved_identity_contexts: list[str]
    approved_scopes: list[str]
    enrollment_request_hash: bytes
    assurance_source: str
    assurance_level: str
    valid_until: str
    link_type: str = "same_entity"
    revocation_reference: Optional[str] = None

    SPECS = {
        "id": _s("id"),
        "link_type": _s("linkType"),
        "entity_binding": _s("entityBinding", "model", model=EntityBindingDescriptor),
        "linked_identity": _s("linkedIdentity", "model", model=IdentityPublicKeyDescriptor),
        "approved_domains": _s("approvedDomains", "strs"),
        "approved_identity_contexts": _s("approvedIdentityContexts", "strs"),
        "approved_scopes": _s("approvedScopes", "strs"),
        "enrollment_request_hash": _s("enrollmentRequestHash", "bytes"),
        "assurance_source": _s("assuranceSource"),
        "assurance_level": _s("assuranceLevel"),
        "valid_until": _s("validUntil"),
        "revocation_reference": _s("revocationReference", optional=True),
    }


@dataclass
class IdentityLinkRecord(WireModel):
    link_id: str
    entity_binding: EntityBindingDescriptor
    linked_identity: IdentityPublicKeyDescriptor
    approved_domains: list[str]
    approved_identity_contexts: list[str]
    approved_scopes: list[str]
    issuer_identity_uuid: str
    issuer_type: str
    linked_at: str
    status: str = "active"  # active | revoked | expired | pending
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revocation_reference: Optional[str] = None

    SPECS = {
        "link_id": _s("linkID"),
        "entity_binding": _s("entityBinding", "model", model=EntityBindingDescriptor),
        "linked_identity": _s("linkedIdentity", "model", model=IdentityPublicKeyDescriptor),
        "approved_domains": _s("approvedDomains", "strs"),
        "approved_identity_contexts": _s("approvedIdentityContexts", "strs"),
        "approved_scopes": _s("approvedScopes", "strs"),
        "issuer_identity_uuid": _s("issuerIdentityUUID"),
        "issuer_type": _s("issuerType"),
        "status": _s("status"),
        "linked_at": _s("linkedAt"),
        "last_used_at": _s("lastUsedAt", optional=True),
        "revoked_at": _s("revokedAt", optional=True),
        "revocation_reference": _s("revocationReference", optional=True),
    }


@dataclass
class IdentityLinkCompletionEnvelope(WireModel):
    """What `identityLinks.completeEnrollment` takes."""

    request: IdentityEnrollmentRequest
    approval: IdentityEnrollmentApproval
    same_entity_credential: VCClaim
    presentation: VCPresentation
    issuer_identity: IdentityPublicKeyDescriptor
    expected_audience: str
    expected_origin: str
    expected_presentation_challenge: bytes
    expected_presentation_domain: str
    require_fresh_auth_evidence: Optional[bool] = None

    SPECS = {
        "request": _s("request", "model", model=IdentityEnrollmentRequest),
        "approval": _s("approval", "model", model=IdentityEnrollmentApproval),
        "same_entity_credential": _s("sameEntityCredential", "model", model=VCClaim),
        "presentation": _s("presentation", "model", model=VCPresentation),
        "issuer_identity": _s("issuerIdentity", "model", model=IdentityPublicKeyDescriptor),
        "expected_audience": _s("expectedAudience"),
        "expected_origin": _s("expectedOrigin"),
        "expected_presentation_challenge": _s("expectedPresentationChallenge", "bytes"),
        "expected_presentation_domain": _s("expectedPresentationDomain"),
        "require_fresh_auth_evidence": _s("requireFreshAuthEvidence", "bool", optional=True),
    }

    def canonical_payload(self) -> bytes:
        return self.presentation.unsigned_bytes()


@dataclass
class IdentityLinkApprovalEnvelope(WireModel):
    """What `identityLinks.approveEnrollment` takes; the Cell's owner signs."""

    request: IdentityEnrollmentRequest
    issuer_type: str = "existingDevice"
    fresh_auth_required: bool = True
    approved_domains: Optional[list[str]] = None
    approved_identity_contexts: Optional[list[str]] = None
    approved_scopes: Optional[list[str]] = None
    expires_at: Optional[str] = None
    jti: Optional[str] = None
    fresh_auth_performed_at: Optional[str] = None
    fresh_auth_evidence: Optional[IdentityLinkFreshAuthEvidence] = None
    revocation_reference: Optional[str] = None

    SPECS = {
        "request": _s("request", "model", model=IdentityEnrollmentRequest),
        "issuer_type": _s("issuerType"),
        "approved_domains": _s("approvedDomains", "strs", optional=True),
        "approved_identity_contexts": _s("approvedIdentityContexts", "strs", optional=True),
        "approved_scopes": _s("approvedScopes", "strs", optional=True),
        "expires_at": _s("expiresAt", optional=True),
        "jti": _s("jti", optional=True),
        "fresh_auth_required": _s("freshAuthRequired", "bool"),
        "fresh_auth_performed_at": _s("freshAuthPerformedAt", optional=True),
        "fresh_auth_evidence": _s("freshAuthEvidence", "model", model=IdentityLinkFreshAuthEvidence, optional=True),
        "revocation_reference": _s("revocationReference", optional=True),
    }


@dataclass
class IdentityLinkApprovalPackage(WireModel):
    """What the approver hands back: approval, credential and its own key."""

    approval: IdentityEnrollmentApproval
    same_entity_credential: VCClaim
    issuer_identity: IdentityPublicKeyDescriptor

    SPECS = {
        "approval": _s("approval", "model", model=IdentityEnrollmentApproval),
        "same_entity_credential": _s("sameEntityCredential", "model", model=VCClaim),
        "issuer_identity": _s("issuerIdentity", "model", model=IdentityPublicKeyDescriptor),
    }


@dataclass
class CompletionResult:
    record: IdentityLinkRecord
    request_hash: bytes
    approval_jti: str
    credential_id: str
    presentation_id: str


# ---------------------------------------------------------------------------
# IdentityLinkProtocolService
# ---------------------------------------------------------------------------


def _ensure_not_expired(expires_at: str, now: float) -> None:
    moment = parse_iso8601(expires_at)
    if moment is None:
        raise LinkFailure("invalidExpiry", expires_at)
    if moment.timestamp() < now:
        raise LinkFailure("expired", expires_at)


def _ensure_subset(approved: Iterable[str], requested: Iterable[str], label: str) -> None:
    unknown = [item for item in approved if item not in set(requested)]
    if unknown:
        raise LinkFailure("scopeEscalation", f"{label}: {','.join(unknown)}")


def validate_enrollment_request(request: IdentityEnrollmentRequest, now: float) -> bytes:
    """`IdentityLinkProtocolService.validateEnrollmentRequest`; returns the request hash."""
    if request.purpose != "link_identity":
        raise LinkFailure("invalidPurpose", request.purpose)
    if request.entity_binding is None:
        raise LinkFailure("missingEntityBinding")
    if len(request.nonce) < 16:
        raise LinkFailure("invalidNonce")
    if (
        not request.audience.strip()
        or not request.origin.strip()
        or not request.requested_domains
        or not request.requested_identity_contexts
        or not request.requested_scopes
    ):
        raise LinkFailure("missingRequiredContext", "request")
    _ensure_not_expired(request.expires_at, now)
    proof = request.proof
    if proof is None or not proof.signature:
        raise LinkFailure("missingRequestProof")
    identity = request.new_identity
    if proof.by_identity_uuid != identity.uuid or proof.algorithm != identity.algorithm or proof.curve_type != identity.curve_type:
        raise LinkFailure("identityMismatch", "request proof does not match new identity")
    payload = request.canonical_payload()
    if not verify_signature(proof.signature, payload, identity):
        raise LinkFailure("invalidRequestSignature")
    return sha256(payload)


FreshAuthVerifier = Callable[[IdentityEnrollmentApproval], bool]


def _validate_approval(
    approval: IdentityEnrollmentApproval,
    request: IdentityEnrollmentRequest,
    hash_: bytes,
    issuer: IdentityPublicKeyDescriptor,
    envelope: IdentityLinkCompletionEnvelope,
    now: float,
    used_jtis: Iterable[str],
    fresh_auth_verifier: Optional[FreshAuthVerifier],
) -> None:
    if approval.purpose != "approve_link_identity":
        raise LinkFailure("invalidPurpose", approval.purpose)
    if approval.request_hash != hash_:
        raise LinkFailure("requestHashMismatch")
    if not approval.subject_identity.same_key(request.new_identity):
        raise LinkFailure("identityMismatch", "approval subject does not match request identity")
    if approval.entity_binding != request.entity_binding:
        raise LinkFailure("identityMismatch", "approval entity binding does not match request")
    if approval.audience != request.audience or approval.audience != envelope.expected_audience:
        raise LinkFailure("audienceMismatch")
    if approval.origin != request.origin or approval.origin != envelope.expected_origin:
        raise LinkFailure("originMismatch")
    if not approval.jti.strip():
        raise LinkFailure("missingRequiredContext", "approval.jti")
    if approval.jti in set(used_jtis):
        raise LinkFailure("replayDetected", approval.jti)
    if approval.issuer_type not in ISSUER_TYPES:
        raise LinkFailure("issuerTypeNotAllowed", approval.issuer_type)
    if approval.issuer_identity_uuid == request.new_identity.uuid or issuer.same_key(request.new_identity):
        raise LinkFailure("sameKeyOnBothSides")
    # Policy default: requireFreshApprovalAuth = true.
    if not approval.fresh_auth_required or approval.fresh_auth_performed_at is None:
        raise LinkFailure("missingFreshAuth")
    if envelope.require_fresh_auth_evidence:
        evidence = approval.fresh_auth_evidence
        if evidence is None:
            raise LinkFailure("missingFreshAuth")
        if evidence.challenge != hash_:
            raise LinkFailure("invalidFreshAuthEvidence", "challenge does not match request hash")
        if fresh_auth_verifier is None:
            raise LinkFailure("invalidFreshAuthEvidence", "no verifier available")
        if not fresh_auth_verifier(approval):
            raise LinkFailure("invalidFreshAuthEvidence", "verifier rejected evidence")
    _ensure_not_expired(approval.expires_at, now)
    _ensure_subset(approval.approved_domains, request.requested_domains, "domains")
    _ensure_subset(approval.approved_identity_contexts, request.requested_identity_contexts, "identityContexts")
    _ensure_subset(approval.approved_scopes, request.requested_scopes, "scopes")
    proof = approval.proof
    if proof is None or not proof.signature:
        raise LinkFailure("missingApprovalProof")
    if (
        proof.issuer_identity_uuid != issuer.uuid
        or proof.issuer_type != approval.issuer_type
        or proof.algorithm != issuer.algorithm
        or proof.curve_type != issuer.curve_type
        or approval.issuer_identity_uuid != issuer.uuid
    ):
        raise LinkFailure("issuerMismatch")
    if not verify_signature(proof.signature, approval.canonical_payload(), issuer):
        raise LinkFailure("invalidApprovalSignature")


def _validate_credential(
    credential: VCClaim,
    request: IdentityEnrollmentRequest,
    approval: IdentityEnrollmentApproval,
    issuer: IdentityPublicKeyDescriptor,
    hash_: bytes,
    now: float,
) -> SameEntityIdentityLinkCredentialSubject:
    if CREDENTIAL_TYPE not in credential.type:
        raise LinkFailure("invalidCredentialType")
    if not isinstance(credential.issuer, str) or credential.issuer != did_key(issuer):
        raise LinkFailure("issuerMismatch")
    if not credential.verify(issuer):
        raise LinkFailure("invalidCredentialSignature")
    try:
        subject = SameEntityIdentityLinkCredentialSubject.from_wire(credential.credential_subject)
    except WireDecodeError as error:
        raise LinkFailure("invalidCredentialSubject", "decode") from error
    if subject.link_type != "same_entity":
        raise LinkFailure("invalidCredentialSubject", "linkType")
    if subject.id != did_key(request.new_identity):
        raise LinkFailure("holderMismatch")
    if not subject.linked_identity.same_key(request.new_identity):
        raise LinkFailure("identityMismatch", "credential linked identity")
    if (
        subject.entity_binding != approval.entity_binding
        or subject.enrollment_request_hash != hash_
        or subject.approved_domains != approval.approved_domains
        or subject.approved_identity_contexts != approval.approved_identity_contexts
        or subject.approved_scopes != approval.approved_scopes
    ):
        raise LinkFailure("invalidCredentialSubject", "approval linkage")
    _ensure_not_expired(subject.valid_until, now)
    return subject


def _validate_presentation(
    presentation: VCPresentation,
    credential: VCClaim,
    linked: IdentityPublicKeyDescriptor,
    envelope: IdentityLinkCompletionEnvelope,
) -> None:
    binding = presentation.holder_binding
    if (
        PRESENTATION_TYPE not in presentation.type
        or not any(item.id == credential.id for item in (presentation.verifiable_credential or []))
        or binding is None
        or not binding.same_key(linked)
        or not isinstance(presentation.holder, str)
        or presentation.holder != did_key(linked)
    ):
        raise LinkFailure("holderMismatch")
    if not presentation.verify_holder_proof(envelope.expected_presentation_challenge, envelope.expected_presentation_domain):
        raise LinkFailure("invalidPresentation")


def verify_completion(
    envelope: IdentityLinkCompletionEnvelope,
    *,
    now: float,
    used_approval_jtis: Iterable[str] = (),
    fresh_auth_verifier: Optional[FreshAuthVerifier] = None,
) -> CompletionResult:
    """`IdentityLinkProtocolService.verifyCompletion`: all four pieces, in Swift's order."""
    request, approval = envelope.request, envelope.approval
    hash_ = validate_enrollment_request(request, now)
    _validate_approval(approval, request, hash_, envelope.issuer_identity, envelope, now, used_approval_jtis, fresh_auth_verifier)
    subject = _validate_credential(envelope.same_entity_credential, request, approval, envelope.issuer_identity, hash_, now)
    _validate_presentation(envelope.presentation, envelope.same_entity_credential, request.new_identity, envelope)
    record = IdentityLinkRecord(
        link_id=approval.approval_id,
        entity_binding=approval.entity_binding,
        linked_identity=request.new_identity,
        approved_domains=list(approval.approved_domains),
        approved_identity_contexts=list(approval.approved_identity_contexts),
        approved_scopes=list(approval.approved_scopes),
        issuer_identity_uuid=envelope.issuer_identity.uuid,
        issuer_type=approval.issuer_type,
        status="active",
        linked_at=iso8601(now),
        revocation_reference=subject.revocation_reference,
    )
    return CompletionResult(
        record=record,
        request_hash=hash_,
        approval_jti=approval.jti,
        credential_id=envelope.same_entity_credential.id,
        presentation_id=envelope.presentation.id,
    )


def approve_enrollment(
    envelope: IdentityLinkApprovalEnvelope,
    *,
    issuer: IdentityPublicKeyDescriptor,
    signer: Signer,
    now: float,
    approval_id: str,
    credential_uuid: str,
    jti: Optional[str] = None,
) -> IdentityLinkApprovalPackage:
    """`IdentityLinkProtocolService.approveEnrollment`: the existing key approves,
    and issues the same-entity credential. IDs are passed in so callers decide
    how they are drawn (Swift uses fresh UUIDs)."""
    request = envelope.request
    hash_ = validate_enrollment_request(request, now)
    if request.entity_binding is None:
        raise LinkFailure("missingEntityBinding")
    expiry: float
    if envelope.expires_at is not None:
        parsed = parse_iso8601(envelope.expires_at)
        if parsed is None:
            raise LinkFailure("invalidExpiry", envelope.expires_at)
        expiry = parsed.timestamp()
    else:
        expiry = now + 300
    performed: Optional[str] = envelope.fresh_auth_performed_at
    if performed is not None and parse_iso8601(performed) is None:
        raise LinkFailure("invalidExpiry", performed)
    if performed is None and envelope.fresh_auth_required:
        performed = iso8601(now)
    approval = IdentityEnrollmentApproval(
        approval_id=approval_id,
        request_hash=hash_,
        entity_binding=request.entity_binding,
        subject_identity=request.new_identity,
        approved_domains=list(envelope.approved_domains if envelope.approved_domains is not None else request.requested_domains),
        approved_identity_contexts=list(
            envelope.approved_identity_contexts if envelope.approved_identity_contexts is not None else request.requested_identity_contexts
        ),
        approved_scopes=list(envelope.approved_scopes if envelope.approved_scopes is not None else request.requested_scopes),
        issuer_identity_uuid=issuer.uuid,
        issuer_type=envelope.issuer_type,
        audience=request.audience,
        origin=request.origin,
        created_at=iso8601(now),
        expires_at=iso8601(expiry),
        jti=jti or envelope.jti or approval_id,
        fresh_auth_required=envelope.fresh_auth_required,
        fresh_auth_method="local-user-presence" if envelope.fresh_auth_required else None,
        fresh_auth_performed_at=performed,
        fresh_auth_evidence=envelope.fresh_auth_evidence,
        proof=IdentityEnrollmentApprovalProof(
            issuer_identity_uuid=issuer.uuid, issuer_type=envelope.issuer_type, algorithm=issuer.algorithm, curve_type=issuer.curve_type
        ),
    )
    assert approval.proof is not None
    approval.proof.signature = signer(approval.canonical_payload())
    subject = SameEntityIdentityLinkCredentialSubject(
        id=did_key(request.new_identity),
        entity_binding=approval.entity_binding,
        linked_identity=request.new_identity,
        approved_domains=approval.approved_domains,
        approved_identity_contexts=approval.approved_identity_contexts,
        approved_scopes=approval.approved_scopes,
        enrollment_request_hash=hash_,
        assurance_source="fresh_auth_and_possession" if approval.fresh_auth_required else "possession_only",
        assurance_level="high" if approval.fresh_auth_required else "medium",
        valid_until=iso8601(expiry),
        revocation_reference=envelope.revocation_reference,
    )
    credential = VCClaim.issue(
        credential_type=CREDENTIAL_TYPE,
        issuer=issuer,
        subject=request.new_identity,
        credential_subject=subject.to_wire(),
        signer=signer,
        claim_uuid=credential_uuid,
        issued_at=now,
    )
    return IdentityLinkApprovalPackage(approval=approval, same_entity_credential=credential, issuer_identity=issuer)


__all__ = [
    "CompletionResult",
    "IdentityLinkApprovalEnvelope",
    "IdentityLinkApprovalPackage",
    "IdentityLinkCompletionEnvelope",
    "IdentityLinkRecord",
    "LinkFailure",
    "SameEntityIdentityLinkCredentialSubject",
    "VCClaim",
    "VCPresentation",
    "VCProof",
    "approve_enrollment",
    "did_key",
    "public_key_from_did_key",
    "validate_enrollment_request",
    "verify_completion",
]
