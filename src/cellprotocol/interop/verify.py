"""Signing and verification that give the same answers as CellProtocol Swift.

Verdict strings are the Swift ones, so a Python node and a Swift node can be
compared case by case against `fixtures/interop/v1`:

* invitations: `HavenInviteVerifier` codes (`valid`, `unsigned`,
  `issuer_mismatch`, `bad_signature`, `ttl_too_long`, `revoked`, `expired`,
  `wrong_audience`) and `HavenInvitePublicationVerifier.Failure` codes;
* chat: `ChatInvitationProofUtilityError` case names;
* bridge: `IdentitySigningChallengeError` case names;
* entity extension: `valid` or `bad_signature` for the signed envelope.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Callable, Optional, Union

from .models import (
    ED25519,
    ChatInvitationAcceptance,
    ChatInvitationArtifact,
    HavenInviteContactRequest,
    HavenInvitePublication,
    HavenInviteReply,
    HavenInviteRevocationNotice,
    HavenInviteTicket,
    HavenSignatureProof,
    IdentityEnrollmentApproval,
    IdentityEnrollmentRequest,
    IdentityLinkRevocation,
    IdentityPublicKeyDescriptor,
    IdentitySigningChallenge,
    SignatureProof,
    WireDecodeError,
    WireModel,
)

Signer = Callable[[bytes], bytes]


class VerificationFailure(Exception):
    """A verifier said no. `code` is the Swift code for the same refusal."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_signature(signature: Optional[bytes], message: bytes, descriptor: IdentityPublicKeyDescriptor) -> bool:
    """`IdentityPublicKeySignatureVerifier.verify`. Only Ed25519 is accepted here;
    Swift also accepts P-256 ECDSA, which no interop flow uses yet."""
    if signature is None or (descriptor.algorithm, descriptor.curve_type) != ED25519:
        return False
    if len(descriptor.public_key) != 32 or len(signature) != 64:
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(descriptor.public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def ed25519_signer(private_key_seed: bytes) -> tuple[Signer, bytes]:
    """Signer and raw public key for a 32-byte Ed25519 seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.from_private_bytes(private_key_seed)
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key.sign, public


def sign_model(model: WireModel, signer: Signer, signer_uuid: str) -> WireModel:
    """Attach the proof Swift expects to a freshly built envelope."""
    payload = model.canonical_payload()
    signature = signer(payload)
    proof = getattr(model, "proof", None)
    if isinstance(model, IdentityEnrollmentApproval) or isinstance(model, IdentityLinkRevocation):
        if proof is None:
            raise ValueError("approval and revocation proofs need issuer type; set proof before signing")
        return model.replace(proof=proof.replace(signature=signature))
    if isinstance(
        model,
        (HavenInviteTicket, HavenInvitePublication, HavenInviteReply, HavenInviteRevocationNotice, HavenInviteContactRequest),
    ):
        return model.replace(proof=HavenSignatureProof(by_identity_uuid=signer_uuid, signature=signature))
    if isinstance(model, (IdentityEnrollmentRequest, ChatInvitationArtifact, ChatInvitationAcceptance)):
        return model.replace(proof=SignatureProof(by_identity_uuid=signer_uuid, signature=signature))
    raise TypeError(f"{type(model).__name__} is not a signed envelope")


def _iso_date(value: str) -> Optional[datetime]:
    """ISO 8601 internet date time, with or without fractional seconds."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _now(now: Optional[float]) -> float:
    return time.time() if now is None else now


# ---------------------------------------------------------------------------
# Entity extension
# ---------------------------------------------------------------------------


def request_hash(request: IdentityEnrollmentRequest) -> bytes:
    return sha256(request.canonical_payload())


def verify_enrollment_request(request: IdentityEnrollmentRequest) -> None:
    proof = request.proof
    if proof is None or proof.signature is None:
        raise VerificationFailure("unsigned")
    if proof.by_identity_uuid != request.new_identity.uuid:
        raise VerificationFailure("issuer_mismatch")
    if not verify_signature(proof.signature, request.canonical_payload(), request.new_identity):
        raise VerificationFailure("bad_signature")


def verify_enrollment_approval(
    approval: IdentityEnrollmentApproval,
    issuer: IdentityPublicKeyDescriptor,
    request: Optional[IdentityEnrollmentRequest] = None,
) -> None:
    proof = approval.proof
    if proof is None or proof.signature is None:
        raise VerificationFailure("unsigned")
    if proof.issuer_identity_uuid != issuer.uuid or approval.issuer_identity_uuid != issuer.uuid:
        raise VerificationFailure("issuer_mismatch")
    if not verify_signature(proof.signature, approval.canonical_payload(), issuer):
        raise VerificationFailure("bad_signature")
    if request is not None:
        if approval.request_hash != request_hash(request):
            raise VerificationFailure("request_hash_mismatch")
        if not approval.subject_identity.same_key(request.new_identity):
            raise VerificationFailure("subject_mismatch")


def verify_link_revocation(revocation: IdentityLinkRevocation, issuer: IdentityPublicKeyDescriptor) -> None:
    proof = revocation.proof
    if proof is None or proof.signature is None:
        raise VerificationFailure("unsigned")
    if proof.issuer_identity_uuid != issuer.uuid or revocation.revoked_by_identity_uuid != issuer.uuid:
        raise VerificationFailure("issuer_mismatch")
    if not verify_signature(proof.signature, revocation.canonical_payload(), issuer):
        raise VerificationFailure("bad_signature")


# ---------------------------------------------------------------------------
# Invitation
# ---------------------------------------------------------------------------


def verify_ticket(
    ticket: HavenInviteTicket,
    *,
    revoked_ticket_ids: frozenset[str] | set[str] = frozenset(),
    expected_audience_token: Optional[str] = None,
    now: Optional[float] = None,
) -> str:
    """`HavenInviteVerifier.verify(...).code`."""
    moment = _now(now)
    proof = ticket.proof
    if proof is None or proof.signature is None:
        return "unsigned"
    if proof.by_identity_uuid != ticket.issuer.uuid:
        return "issuer_mismatch"
    if not verify_signature(proof.signature, ticket.canonical_payload(), ticket.issuer):
        return "bad_signature"
    if ticket.claims_too_long_a_life:
        return "ttl_too_long"
    if ticket.ticket_id in revoked_ticket_ids:
        return "revoked"
    if ticket.is_expired(moment):
        return "expired"
    if expected_audience_token is not None and expected_audience_token != ticket.audience_token:
        return "wrong_audience"
    return "valid"


def _verify_envelope(envelope: WireModel, proof: Optional[HavenSignatureProof], descriptor: IdentityPublicKeyDescriptor) -> None:
    if proof is None or proof.signature is None:
        raise VerificationFailure("unsigned")
    if proof.by_identity_uuid != descriptor.uuid:
        raise VerificationFailure("issuer_mismatch")
    if not verify_signature(proof.signature, envelope.canonical_payload(), descriptor):
        raise VerificationFailure("bad_signature")


def verify_publication(publication: HavenInvitePublication, now: Optional[float] = None) -> HavenInviteTicket:
    """`HavenInvitePublicationVerifier.verifyPublication`."""
    moment = _now(now)
    try:
        ticket = HavenInviteTicket.from_token(publication.ticket_token)
    except WireDecodeError as error:
        raise VerificationFailure("ticket_invalid:malformed_payload", str(error)) from error
    # Swift checks the signature first and maps any signature failure to bad_signature.
    if verify_ticket(ticket, now=moment) in ("unsigned", "issuer_mismatch", "bad_signature"):
        raise VerificationFailure("bad_signature")
    if ticket.is_expired(moment):
        raise VerificationFailure("ticket_expired")
    if ticket.claims_too_long_a_life:
        raise VerificationFailure("ticket_invalid:ttl_too_long")
    if publication.expires_at != ticket.expires_at:
        raise VerificationFailure("ticket_mismatch", "expiresAt")
    if ticket.ticket_id != publication.ticket_id:
        raise VerificationFailure("ticket_mismatch", "ticketID")
    if ticket.human_code != publication.human_code:
        raise VerificationFailure("ticket_mismatch", "humanCode")
    if ticket.audience_token != publication.audience_token:
        raise VerificationFailure("ticket_mismatch", "audienceToken")
    if ticket.issuer.uuid != publication.issuer_identity_uuid:
        raise VerificationFailure("issuer_mismatch")
    _verify_envelope(publication, publication.proof, ticket.issuer)
    return ticket


def verify_revocation_notice(notice: HavenInviteRevocationNotice, ticket: HavenInviteTicket) -> None:
    if notice.ticket_id != ticket.ticket_id:
        raise VerificationFailure("ticket_mismatch", "ticketID")
    if notice.issuer_identity_uuid != ticket.issuer.uuid:
        raise VerificationFailure("issuer_mismatch")
    _verify_envelope(notice, notice.proof, ticket.issuer)


def verify_contact_request(request: HavenInviteContactRequest, ticket: HavenInviteTicket, now: Optional[float] = None) -> None:
    moment = _now(now)
    if request.ticket_id != ticket.ticket_id:
        raise VerificationFailure("ticket_mismatch", "ticketID")
    if ticket.issuer_contact_endpoint is None or request.issuer_endpoint_id != ticket.issuer_contact_endpoint:
        raise VerificationFailure("ticket_mismatch", "issuerEndpointID")
    if request.is_expired(moment):
        raise VerificationFailure("expired")
    if ticket.is_expired(moment):
        raise VerificationFailure("ticket_expired")
    if request.sender.uuid == ticket.issuer.uuid:
        raise VerificationFailure("issuer_mismatch")
    _verify_envelope(request, request.proof, request.sender)


def verify_reply(reply: HavenInviteReply, ticket: HavenInviteTicket, now: Optional[float] = None) -> None:
    moment = _now(now)
    if reply.ticket_id != ticket.ticket_id:
        raise VerificationFailure("ticket_mismatch", "ticketID")
    if reply.audience_token != ticket.audience_token:
        raise VerificationFailure("ticket_mismatch", "audienceToken")
    if ticket.is_expired(moment):
        raise VerificationFailure("ticket_expired")
    if reply.replier.uuid == ticket.issuer.uuid:
        raise VerificationFailure("issuer_mismatch")
    _verify_envelope(reply, reply.proof, reply.replier)


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


def invitation_hash(artifact: ChatInvitationArtifact) -> bytes:
    return sha256(artifact.canonical_payload())


def _validate_nonce(nonce: bytes) -> None:
    if not (IdentitySigningChallenge.MINIMUM_NONCE_BYTES <= len(nonce) <= IdentitySigningChallenge.MAXIMUM_NONCE_BYTES):
        raise VerificationFailure("invalidNonce")


def _validate_invitation(artifact: ChatInvitationArtifact, moment: float) -> None:
    if artifact.version != 1:
        raise VerificationFailure("unsupportedVersion")
    if artifact.purpose != "chat_invitation":
        raise VerificationFailure("invalidPurpose")
    _validate_nonce(artifact.nonce)
    created, expires = _iso_date(artifact.created_at), _iso_date(artifact.expires_at)
    if (
        created is None
        or expires is None
        or not expires > created
        or not created.timestamp() <= moment + IdentitySigningChallenge.ALLOWED_CLOCK_SKEW
    ):
        raise VerificationFailure("invalidTimestamp")
    if not expires.timestamp() >= moment:
        raise VerificationFailure("expiredArtifact")


def verify_chat_invitation(
    artifact: ChatInvitationArtifact,
    *,
    expected_chat_cell_uuid: Optional[str] = None,
    expected_inviter_uuid: Optional[str] = None,
    now: Optional[float] = None,
) -> None:
    """`ChatInvitationProofUtility.verifyInvitationArtifact`."""
    moment = _now(now)
    _validate_invitation(artifact, moment)
    if expected_chat_cell_uuid is not None and artifact.chat_cell_uuid != expected_chat_cell_uuid:
        raise VerificationFailure("chatCellMismatch")
    if expected_inviter_uuid is not None and artifact.inviter_identity.uuid != expected_inviter_uuid:
        raise VerificationFailure("inviterMismatch")
    expires = _iso_date(artifact.expires_at)
    if expires is None or expires.timestamp() < moment:
        raise VerificationFailure("expiredArtifact")
    proof = artifact.proof
    if proof is None or proof.signature is None:
        raise VerificationFailure("missingSignature")
    if proof.type != "signature":
        raise VerificationFailure("invalidProofType")
    if (
        proof.by_identity_uuid != artifact.inviter_identity.uuid
        or proof.algorithm != artifact.inviter_identity.algorithm
        or proof.curve_type != artifact.inviter_identity.curve_type
    ):
        raise VerificationFailure("inviterMismatch")
    if not verify_signature(proof.signature, artifact.canonical_payload(), artifact.inviter_identity):
        raise VerificationFailure("invalidArtifactProof")


def verify_chat_acceptance(
    acceptance: ChatInvitationAcceptance,
    artifact: ChatInvitationArtifact,
    *,
    expected_chat_cell_uuid: Optional[str] = None,
    now: Optional[float] = None,
) -> None:
    """`ChatInvitationProofUtility.verifyAcceptance`."""
    moment = _now(now)
    verify_chat_invitation(
        artifact,
        expected_chat_cell_uuid=expected_chat_cell_uuid,
        expected_inviter_uuid=acceptance.inviter_identity_uuid,
        now=moment,
    )
    if acceptance.version != 1:
        raise VerificationFailure("unsupportedVersion")
    if acceptance.purpose != "accept_chat_invitation":
        raise VerificationFailure("invalidPurpose")
    _validate_nonce(acceptance.nonce)
    invited_at, expires_at, accepted_at = (
        _iso_date(artifact.created_at),
        _iso_date(artifact.expires_at),
        _iso_date(acceptance.created_at),
    )
    skew = IdentitySigningChallenge.ALLOWED_CLOCK_SKEW
    if (
        invited_at is None
        or expires_at is None
        or accepted_at is None
        or not accepted_at.timestamp() >= invited_at.timestamp() - skew
        or not accepted_at <= expires_at
        or not accepted_at.timestamp() <= moment + skew
    ):
        raise VerificationFailure("invalidTimestamp")
    if acceptance.invitation_id != artifact.invitation_id:
        raise VerificationFailure("invitationHashMismatch")
    if acceptance.chat_cell_uuid != artifact.chat_cell_uuid:
        raise VerificationFailure("chatCellMismatch")
    if not acceptance.invitee_identity.same_key(artifact.invited_identity):
        raise VerificationFailure("inviteeMismatch")
    if acceptance.invitation_hash != invitation_hash(artifact):
        raise VerificationFailure("invitationHashMismatch")
    proof = acceptance.proof
    if proof is None or proof.signature is None:
        raise VerificationFailure("missingSignature")
    if proof.type != "signature":
        raise VerificationFailure("invalidProofType")
    if (
        proof.by_identity_uuid != acceptance.invitee_identity.uuid
        or proof.algorithm != acceptance.invitee_identity.algorithm
        or proof.curve_type != acceptance.invitee_identity.curve_type
    ):
        raise VerificationFailure("inviteeMismatch")
    if not verify_signature(proof.signature, acceptance.canonical_payload(), acceptance.invitee_identity):
        raise VerificationFailure("invalidAcceptanceProof")


# ---------------------------------------------------------------------------
# Bridge identity proof
# ---------------------------------------------------------------------------


def validate_signing_challenge(
    data: bytes,
    identity: IdentityPublicKeyDescriptor,
    now: Optional[float] = None,
) -> IdentitySigningChallenge:
    """`IdentitySigningChallenge.validateSigningData`. Raises with the Swift case name."""
    C = IdentitySigningChallenge
    moment = _now(now)
    if len(data) > C.MAXIMUM_ENCODED_BYTES:
        raise VerificationFailure("payloadTooLarge")
    try:
        challenge = C.from_wire(json.loads(data))
    except (ValueError, WireDecodeError) as error:
        raise VerificationFailure("invalidPayload") from error
    if challenge.type != C.TYPE:
        raise VerificationFailure("wrongType")
    if challenge.version != 1:
        raise VerificationFailure("unsupportedVersion")
    if challenge.purpose != C.PURPOSE:
        raise VerificationFailure("wrongPurpose")
    if challenge.identity_uuid != identity.uuid:
        raise VerificationFailure("identityMismatch")
    expected = (challenge.public_key_fingerprint or "").strip()
    if not expected:
        raise VerificationFailure("missingPublicKeyFingerprint")
    if expected != identity.fingerprint:
        raise VerificationFailure("publicKeyMismatch")
    if len(challenge.nonce) < C.MINIMUM_NONCE_BYTES:
        raise VerificationFailure("missingNonce")
    if len(challenge.nonce) > C.MAXIMUM_NONCE_BYTES:
        raise VerificationFailure("payloadTooLarge")
    scope = [challenge.domain, challenge.resource, challenge.action, challenge.audience]
    if any(not item.strip() for item in scope):
        raise VerificationFailure("missingChallengeScope")
    if any(len(item) > C.MAXIMUM_SCOPE_CHARACTERS for item in scope):
        raise VerificationFailure("payloadTooLarge")
    if not (challenge.expires_at >= challenge.issued_at and challenge.expires_at - challenge.issued_at <= C.DEFAULT_VALIDITY):
        raise VerificationFailure("invalidValidity")
    if not challenge.issued_at <= moment + C.ALLOWED_CLOCK_SKEW:
        raise VerificationFailure("issuedInFuture")
    if not challenge.expires_at >= moment:
        raise VerificationFailure("expired")
    return challenge


def verdict(check: Callable[[], object]) -> str:
    """Run a raising verifier and return `valid` or the Swift code."""
    try:
        result = check()
    except VerificationFailure as failure:
        return failure.code
    if isinstance(result, str):
        return result
    return "valid"


__all__ = [
    "Signer",
    "VerificationFailure",
    "ed25519_signer",
    "invitation_hash",
    "request_hash",
    "sha256",
    "sign_model",
    "validate_signing_challenge",
    "verdict",
    "verify_chat_acceptance",
    "verify_chat_invitation",
    "verify_contact_request",
    "verify_enrollment_approval",
    "verify_enrollment_request",
    "verify_link_revocation",
    "verify_publication",
    "verify_reply",
    "verify_revocation_notice",
    "verify_signature",
    "verify_ticket",
]
