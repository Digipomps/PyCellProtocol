"""Chat invitation builders, as `ChatInvitationProofUtility` in CellBase Swift.

`build_invitation` is `generateInvitationArtifact` (signed by the inviter) and
`build_acceptance` is `generateAcceptance` (signed by the invitee). The
verifiers are `verify.verify_chat_invitation` and `verify.verify_chat_acceptance`.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from uuid import uuid4

from .models import ChatInvitationAcceptance, ChatInvitationArtifact, IdentityPublicKeyDescriptor, SignatureProof
from .verify import Signer, invitation_hash, verify_chat_invitation

DEFAULT_SUITE_ID = "haven.chat.message.v1"
INVITATION_LIFETIME = 7 * 86_400
NONCE_BYTES = 64


def timestamp(moment: Optional[float] = None) -> str:
    """ISO 8601 with milliseconds and Z, as Swift's `.withFractionalSeconds`."""
    value = datetime.fromtimestamp(time.time() if moment is None else moment, tz=timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _sign(model, signer: Signer, descriptor: IdentityPublicKeyDescriptor):
    unsigned = model.replace(
        proof=SignatureProof(by_identity_uuid=descriptor.uuid, algorithm=descriptor.algorithm, curve_type=descriptor.curve_type)
    )
    return unsigned.replace(proof=unsigned.proof.replace(signature=signer(unsigned.canonical_payload())))


def build_invitation(
    *,
    chat_cell_uuid: str,
    topic: str,
    audience_mode: str,
    persistence_mode: str,
    inviter: IdentityPublicKeyDescriptor,
    invited: IdentityPublicKeyDescriptor,
    signer: Signer,
    suite_id: str = DEFAULT_SUITE_ID,
    invitation_id: Optional[str] = None,
    now: Optional[float] = None,
    lifetime: int = INVITATION_LIFETIME,
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> ChatInvitationArtifact:
    moment = time.time() if now is None else now
    artifact = ChatInvitationArtifact(
        invitation_id=invitation_id or str(uuid4()).upper(),
        chat_cell_uuid=chat_cell_uuid,
        topic=topic,
        audience_mode=audience_mode,
        suite_id=suite_id,
        persistence_mode=persistence_mode,
        inviter_identity=inviter,
        invited_identity=invited,
        created_at=timestamp(moment),
        expires_at=timestamp(moment + lifetime),
        nonce=random_bytes(NONCE_BYTES),
    )
    return _sign(artifact, signer, inviter)


def build_acceptance(
    artifact: ChatInvitationArtifact,
    invitee: IdentityPublicKeyDescriptor,
    signer: Signer,
    *,
    acceptance_id: Optional[str] = None,
    key_agreement_key: Optional[bytes] = None,
    now: Optional[float] = None,
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> ChatInvitationAcceptance:
    """Refuses (with the Swift code) an artifact that is not for `invitee` or does not verify."""
    from .verify import VerificationFailure

    if not invitee.same_key(artifact.invited_identity):
        raise VerificationFailure("inviteeMismatch")
    verify_chat_invitation(artifact, now=now)
    acceptance = ChatInvitationAcceptance(
        acceptance_id=acceptance_id or str(uuid4()).upper(),
        invitation_id=artifact.invitation_id,
        invitation_hash=invitation_hash(artifact),
        chat_cell_uuid=artifact.chat_cell_uuid,
        inviter_identity_uuid=artifact.inviter_identity.uuid,
        invitee_identity=invitee,
        invitee_key_agreement_key=key_agreement_key,
        created_at=timestamp(now),
        nonce=random_bytes(NONCE_BYTES),
    )
    return _sign(acceptance, signer, invitee)
