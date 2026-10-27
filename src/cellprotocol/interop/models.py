"""Wire models for the three cross-language flows, mirroring CellProtocol Swift.

Each model decodes from and encodes to the exact JSON shape Swift's
`JSONEncoder` produces: `Data` as padded standard base64, optional fields left
out when absent, and the coded key names Swift uses (the invitation ticket's
short keys included). `canonical_payload()` returns the bytes Swift signs.

Swift sources mirrored (CellProtocol `Sources/CellBase`):
`Identity/IdentityLinkingModels.swift`, `Identity/IdentitySigningChallenge.swift`,
`Invitation/HavenInviteTicket.swift`, `Invitation/HavenInvitePublication.swift`,
`Invitation/HavenInviteReply.swift`, `Cells/Chat/ChatInvitationProofUtility.swift`.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
from dataclasses import dataclass, field
from typing import Any, ClassVar, Mapping, Optional, TypeVar

from .canonical import canonical_json, canonical_payload

T = TypeVar("T", bound="WireModel")


class WireDecodeError(ValueError):
    """The JSON does not have the shape Swift would decode."""


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise WireDecodeError(f"{name}: expected base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise WireDecodeError(f"{name}: invalid base64") from error


@dataclass(frozen=True)
class Spec:
    """How one field travels: wire key, kind, and when it is left out."""

    key: str
    kind: str  # str | int | bool | bytes | strs | model | models | number
    model: Optional[type] = None
    optional: bool = False
    default: Any = None
    omit_when_default: bool = False


class WireModel:
    """Base for dataclass wire models. Subclasses declare `SPECS` per field."""

    SPECS: ClassVar[dict[str, Spec]] = {}
    EXCLUDED_FROM_SIGNATURE: ClassVar[tuple[str, ...]] = ()

    # -- encoding -----------------------------------------------------------

    def to_wire(self) -> dict[str, Any]:
        wire: dict[str, Any] = {}
        for name, spec in self.SPECS.items():
            value = getattr(self, name)
            if value is None:
                if spec.optional:
                    continue
                raise WireDecodeError(f"{type(self).__name__}.{name} is required")
            if spec.omit_when_default and value == _default_value(spec):
                continue
            wire[spec.key] = _encode(value, spec)
        return wire

    def to_json_bytes(self) -> bytes:
        """What Swift `JSONEncoder` with `.sortedKeys` writes for this value."""
        return canonical_json(self.to_wire(), key_order="encoder")

    def canonical_payload(self) -> bytes:
        return canonical_payload(self.to_wire(), self.EXCLUDED_FROM_SIGNATURE)

    # -- decoding -----------------------------------------------------------

    @classmethod
    def from_wire(cls: type[T], wire: Mapping[str, Any]) -> T:
        if not isinstance(wire, Mapping):
            raise WireDecodeError(f"{cls.__name__}: expected an object")
        values: dict[str, Any] = {}
        for name, spec in cls.SPECS.items():
            if spec.key not in wire or wire[spec.key] is None:
                if spec.optional:
                    values[name] = None
                    continue
                if spec.default is not None or spec.omit_when_default:
                    values[name] = _default_value(spec)
                    continue
                raise WireDecodeError(f"{cls.__name__}: missing {spec.key}")
            values[name] = _decode(wire[spec.key], spec, f"{cls.__name__}.{spec.key}")
        return cls(**values)  # type: ignore[call-arg]

    def replace(self: T, **changes: Any) -> T:
        return dataclasses.replace(self, **changes)  # type: ignore[type-var]


def _default_value(spec: Spec) -> Any:
    default = spec.default
    if callable(default):
        return default()
    if isinstance(default, (list, dict)):
        return type(default)(default)
    return default


def _encode(value: Any, spec: Spec) -> Any:
    kind = spec.kind
    if kind == "bytes":
        return _b64(value)
    if kind == "model":
        return value.to_wire()
    if kind == "models":
        return [item.to_wire() for item in value]
    if kind == "strs":
        return list(value)
    return value


def _decode(value: Any, spec: Spec, name: str) -> Any:
    kind = spec.kind
    if kind == "str":
        if not isinstance(value, str):
            raise WireDecodeError(f"{name}: expected string")
        return value
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise WireDecodeError(f"{name}: expected integer")
        return value
    if kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise WireDecodeError(f"{name}: expected number")
        return value
    if kind == "bool":
        if not isinstance(value, bool):
            raise WireDecodeError(f"{name}: expected bool")
        return value
    if kind == "bytes":
        return _unb64(value, name)
    if kind == "strs":
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise WireDecodeError(f"{name}: expected list of strings")
        return list(value)
    if kind == "model":
        assert spec.model is not None
        return spec.model.from_wire(value)
    if kind == "models":
        assert spec.model is not None
        if not isinstance(value, list):
            raise WireDecodeError(f"{name}: expected list")
        return [spec.model.from_wire(item) for item in value]
    raise WireDecodeError(f"{name}: unknown kind {kind}")


def _s(key: str, kind: str = "str", **kwargs: Any) -> Spec:
    return Spec(key=key, kind=kind, **kwargs)


# ---------------------------------------------------------------------------
# Shared descriptors and proofs
# ---------------------------------------------------------------------------

ED25519 = ("EdDSA", "Curve25519")


@dataclass
class IdentityPublicKeyDescriptor(WireModel):
    uuid: str
    public_key: bytes
    algorithm: str = "EdDSA"
    curve_type: str = "Curve25519"
    display_name: Optional[str] = None

    SPECS = {
        "uuid": _s("uuid"),
        "public_key": _s("publicKey", "bytes"),
        "algorithm": _s("algorithm"),
        "curve_type": _s("curveType"),
        "display_name": _s("displayName", optional=True),
    }

    def same_key(self, other: "IdentityPublicKeyDescriptor") -> bool:
        return (
            self.uuid == other.uuid
            and self.public_key == other.public_key
            and self.algorithm == other.algorithm
            and self.curve_type == other.curve_type
        )

    @property
    def fingerprint(self) -> str:
        """`Identity.signingPublicKeyFingerprint` in Swift."""
        return f"{self.algorithm}:{self.curve_type}:{_b64(self.public_key)}"


@dataclass
class SignatureProof(WireModel):
    """`IdentityEnrollmentRequestProof`, `ChatInvitationArtifactProof` and
    `ChatInvitationAcceptanceProof` share this shape."""

    by_identity_uuid: str
    algorithm: str = "EdDSA"
    curve_type: str = "Curve25519"
    type: str = "signature"
    signature: Optional[bytes] = None

    SPECS = {
        "type": _s("type"),
        "by_identity_uuid": _s("byIdentityUUID"),
        "algorithm": _s("algorithm"),
        "curve_type": _s("curveType"),
        "signature": _s("signature", "bytes", optional=True),
    }


@dataclass
class HavenSignatureProof(WireModel):
    """Short-keyed proof used by every invitation type."""

    by_identity_uuid: str
    algorithm: str = "EdDSA"
    curve_type: str = "Curve25519"
    type: str = "signature"
    signature: Optional[bytes] = None

    SPECS = {
        "type": _s("ty"),
        "by_identity_uuid": _s("by"),
        "algorithm": _s("al"),
        "curve_type": _s("cv"),
        "signature": _s("sg", "bytes", optional=True),
    }


# ---------------------------------------------------------------------------
# Entity extension
# ---------------------------------------------------------------------------


@dataclass
class EntityBindingDescriptor(WireModel):
    mode: str  # localEntityAnchor | pairwise | blinded
    entity_anchor_reference: Optional[str] = None
    binding_id: Optional[str] = None
    audience: Optional[str] = None

    SPECS = {
        "mode": _s("mode"),
        "entity_anchor_reference": _s("entityAnchorReference", optional=True),
        "binding_id": _s("bindingID", optional=True),
        "audience": _s("audience", optional=True),
    }


@dataclass
class IdentityEnrollmentRequest(WireModel):
    request_id: str
    new_identity: IdentityPublicKeyDescriptor
    requested_domains: list[str]
    requested_identity_contexts: list[str]
    requested_scopes: list[str]
    audience: str
    origin: str
    created_at: str
    expires_at: str
    nonce: bytes
    version: int = 1
    purpose: str = "link_identity"
    entity_binding: Optional[EntityBindingDescriptor] = None
    platform: Optional[str] = None
    device_label: Optional[str] = None
    proof: Optional[SignatureProof] = None

    SPECS = {
        "version": _s("version", "int"),
        "request_id": _s("requestID"),
        "purpose": _s("purpose"),
        "entity_binding": _s("entityBinding", "model", model=EntityBindingDescriptor, optional=True),
        "new_identity": _s("newIdentity", "model", model=IdentityPublicKeyDescriptor),
        "requested_domains": _s("requestedDomains", "strs"),
        "requested_identity_contexts": _s("requestedIdentityContexts", "strs"),
        "requested_scopes": _s("requestedScopes", "strs"),
        "audience": _s("audience"),
        "origin": _s("origin"),
        "created_at": _s("createdAt"),
        "expires_at": _s("expiresAt"),
        "nonce": _s("nonce", "bytes"),
        "platform": _s("platform", optional=True),
        "device_label": _s("deviceLabel", optional=True),
        "proof": _s("proof", "model", model=SignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


@dataclass
class IdentityEnrollmentApprovalProof(WireModel):
    issuer_identity_uuid: str
    issuer_type: str  # existingDevice | custodian | recoveryAuthority
    algorithm: str = "EdDSA"
    curve_type: str = "Curve25519"
    type: str = "signature"
    signature: Optional[bytes] = None

    SPECS = {
        "type": _s("type"),
        "issuer_identity_uuid": _s("issuerIdentityUUID"),
        "issuer_type": _s("issuerType"),
        "algorithm": _s("algorithm"),
        "curve_type": _s("curveType"),
        "signature": _s("signature", "bytes", optional=True),
    }


@dataclass
class IdentityLinkFreshAuthEvidence(WireModel):
    method: str
    challenge: bytes
    performed_at: str
    credential_id: Optional[bytes] = None
    authenticator_data: Optional[bytes] = None
    client_data_json: Optional[bytes] = None
    signature: Optional[bytes] = None

    SPECS = {
        "method": _s("method"),
        "challenge": _s("challenge", "bytes"),
        "performed_at": _s("performedAt"),
        "credential_id": _s("credentialID", "bytes", optional=True),
        "authenticator_data": _s("authenticatorData", "bytes", optional=True),
        "client_data_json": _s("clientDataJSON", "bytes", optional=True),
        "signature": _s("signature", "bytes", optional=True),
    }


@dataclass
class IdentityEnrollmentApproval(WireModel):
    approval_id: str
    request_hash: bytes
    entity_binding: EntityBindingDescriptor
    subject_identity: IdentityPublicKeyDescriptor
    approved_domains: list[str]
    approved_identity_contexts: list[str]
    approved_scopes: list[str]
    issuer_identity_uuid: str
    issuer_type: str
    audience: str
    origin: str
    created_at: str
    expires_at: str
    jti: str
    fresh_auth_required: bool
    version: int = 1
    purpose: str = "approve_link_identity"
    fresh_auth_method: Optional[str] = None
    fresh_auth_performed_at: Optional[str] = None
    fresh_auth_evidence: Optional[IdentityLinkFreshAuthEvidence] = None
    proof: Optional[IdentityEnrollmentApprovalProof] = None

    SPECS = {
        "version": _s("version", "int"),
        "approval_id": _s("approvalID"),
        "purpose": _s("purpose"),
        "request_hash": _s("requestHash", "bytes"),
        "entity_binding": _s("entityBinding", "model", model=EntityBindingDescriptor),
        "subject_identity": _s("subjectIdentity", "model", model=IdentityPublicKeyDescriptor),
        "approved_domains": _s("approvedDomains", "strs"),
        "approved_identity_contexts": _s("approvedIdentityContexts", "strs"),
        "approved_scopes": _s("approvedScopes", "strs"),
        "issuer_identity_uuid": _s("issuerIdentityUUID"),
        "issuer_type": _s("issuerType"),
        "audience": _s("audience"),
        "origin": _s("origin"),
        "created_at": _s("createdAt"),
        "expires_at": _s("expiresAt"),
        "jti": _s("jti"),
        "fresh_auth_required": _s("freshAuthRequired", "bool"),
        "fresh_auth_method": _s("freshAuthMethod", optional=True),
        "fresh_auth_performed_at": _s("freshAuthPerformedAt", optional=True),
        "fresh_auth_evidence": _s("freshAuthEvidence", "model", model=IdentityLinkFreshAuthEvidence, optional=True),
        "proof": _s("proof", "model", model=IdentityEnrollmentApprovalProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


@dataclass
class IdentityLinkRevocation(WireModel):
    link_id: str
    reason: str
    revoked_at: str
    revoked_by_identity_uuid: str
    issuer_type: str
    version: int = 1
    proof: Optional[IdentityEnrollmentApprovalProof] = None

    SPECS = {
        "version": _s("version", "int"),
        "link_id": _s("linkID"),
        "reason": _s("reason"),
        "revoked_at": _s("revokedAt"),
        "revoked_by_identity_uuid": _s("revokedByIdentityUUID"),
        "issuer_type": _s("issuerType"),
        "proof": _s("proof", "model", model=IdentityEnrollmentApprovalProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


# ---------------------------------------------------------------------------
# Invitation
# ---------------------------------------------------------------------------

DEFAULT_TICKET_CAPABILITIES = ["create_own_entity", "send_contact_request_to_issuer"]
TICKET_DEFAULT_TTL = 14 * 86_400
TICKET_MAXIMUM_TTL = 90 * 86_400


@dataclass
class HavenInviteBasisField(WireModel):
    key: str
    value: str
    origin: Optional[str] = None

    SPECS = {"key": _s("k"), "value": _s("v"), "origin": _s("o", optional=True)}


@dataclass
class HavenInviteTicket(WireModel):
    SCHEMA: ClassVar[str] = "haven.invite.ticket.v1"

    ticket_id: str
    issuer: IdentityPublicKeyDescriptor
    issuer_display_name: str
    audience_token: str
    human_code: str
    created_at: int
    expires_at: int
    version: int = 1
    audience_kind: str = "email"
    issuer_contact_endpoint: Optional[str] = None
    issuer_entity_ref: Optional[str] = None
    greeting_name: Optional[str] = None
    note: Optional[str] = None
    identity_domain: Optional[str] = None
    basis: list[HavenInviteBasisField] = field(default_factory=list)
    nonce: bytes = b""
    capabilities: list[str] = field(default_factory=lambda: list(DEFAULT_TICKET_CAPABILITIES))
    proof: Optional[HavenSignatureProof] = None

    SPECS = {
        "version": _s("v", "int", default=1),
        "ticket_id": _s("t"),
        "issuer": _s("is", "model", model=IdentityPublicKeyDescriptor),
        "issuer_display_name": _s("n"),
        "issuer_contact_endpoint": _s("ce", optional=True),
        "issuer_entity_ref": _s("er", optional=True),
        "audience_token": _s("au"),
        "audience_kind": _s("ak", default="email"),
        "human_code": _s("hc"),
        "greeting_name": _s("gn", optional=True),
        "note": _s("no", optional=True),
        "identity_domain": _s("id", optional=True),
        "basis": _s("bs", "models", model=HavenInviteBasisField, default=list, omit_when_default=True),
        "created_at": _s("ca", "int"),
        "expires_at": _s("ea", "int"),
        "nonce": _s("nc", "bytes", default=bytes, omit_when_default=True),
        "capabilities": _s(
            "cp", "strs", default=lambda: list(DEFAULT_TICKET_CAPABILITIES), omit_when_default=True
        ),
        "proof": _s("pf", "model", model=HavenSignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("pf",)

    def is_expired(self, now_epoch: float) -> bool:
        return now_epoch > self.expires_at

    @property
    def claims_too_long_a_life(self) -> bool:
        return self.expires_at - self.created_at > TICKET_MAXIMUM_TTL

    @property
    def can_receive_contact_request(self) -> bool:
        return "send_contact_request_to_issuer" in self.capabilities and bool(self.issuer_contact_endpoint)

    # The long link carries the ticket as base64url of JSONEncoder(.sortedKeys).
    def to_token(self) -> str:
        return base64.urlsafe_b64encode(self.to_json_bytes()).decode("ascii").rstrip("=")

    @classmethod
    def from_token(cls, token: str) -> "HavenInviteTicket":
        import json

        padded = token + "=" * (-len(token) % 4)
        try:
            data = base64.urlsafe_b64decode(padded.encode("ascii"))
            wire = json.loads(data)
        except (ValueError, binascii.Error) as error:
            raise WireDecodeError("malformed ticket token") from error
        ticket = cls.from_wire(wire)
        if ticket.version != 1:
            raise WireDecodeError(f"unsupported ticket version {ticket.version}")
        return ticket


@dataclass
class HavenInvitePublication(WireModel):
    SCHEMA: ClassVar[str] = "haven.invite.publication.v1"

    ticket_id: str
    human_code: str
    ticket_token: str
    audience_token: str
    issuer_identity_uuid: str
    expires_at: int
    published_at: int
    status_key: str
    max_contact_requests: int = 3
    schema: str = "haven.invite.publication.v1"
    proof: Optional[HavenSignatureProof] = None

    SPECS = {
        "schema": _s("schema"),
        "ticket_id": _s("ticketID"),
        "human_code": _s("humanCode"),
        "ticket_token": _s("ticketToken"),
        "audience_token": _s("audienceToken"),
        "issuer_identity_uuid": _s("issuerIdentityUUID"),
        "expires_at": _s("expiresAt", "int"),
        "published_at": _s("publishedAt", "int"),
        "max_contact_requests": _s("maxContactRequests", "int"),
        "status_key": _s("statusKey"),
        "proof": _s("proof", "model", model=HavenSignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


@dataclass
class HavenInviteRevocationNotice(WireModel):
    ticket_id: str
    reason: str
    revoked_at: int
    issuer_identity_uuid: str
    schema: str = "haven.invite.revocation.v1"
    proof: Optional[HavenSignatureProof] = None

    SPECS = {
        "schema": _s("schema"),
        "ticket_id": _s("ticketID"),
        "reason": _s("reason"),
        "revoked_at": _s("revokedAt", "int"),
        "issuer_identity_uuid": _s("issuerIdentityUUID"),
        "proof": _s("proof", "model", model=HavenSignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


@dataclass
class HavenInviteContactRequest(WireModel):
    request_id: str
    ticket_id: str
    issuer_endpoint_id: str
    sender: IdentityPublicKeyDescriptor
    sender_display_name: str
    created_at: int
    expires_at: int
    nonce: bytes
    schema: str = "haven.invite.contactRequest.v1"
    sender_entity_ref: Optional[str] = None
    sender_endpoint: Optional[str] = None
    message: Optional[str] = None
    sender_key_agreement_key: Optional[bytes] = None
    proof: Optional[HavenSignatureProof] = None

    SPECS = {
        "schema": _s("schema"),
        "request_id": _s("requestID"),
        "ticket_id": _s("ticketID"),
        "issuer_endpoint_id": _s("issuerEndpointID"),
        "sender": _s("sender", "model", model=IdentityPublicKeyDescriptor),
        "sender_display_name": _s("senderDisplayName"),
        "sender_entity_ref": _s("senderEntityRef", optional=True),
        "sender_endpoint": _s("senderEndpoint", optional=True),
        "message": _s("message", optional=True),
        "sender_key_agreement_key": _s("senderKeyAgreementKey", "bytes", optional=True),
        "created_at": _s("createdAt", "int"),
        "expires_at": _s("expiresAt", "int"),
        "nonce": _s("nonce", "bytes"),
        "proof": _s("proof", "model", model=HavenSignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)

    def is_expired(self, now_epoch: float) -> bool:
        return now_epoch > self.expires_at


INVITE_DECISIONS = ("yes", "notNow", "never")


@dataclass
class HavenInviteReply(WireModel):
    reply_id: str
    ticket_id: str
    audience_token: str
    decision: str  # yes | notNow | never
    replier: IdentityPublicKeyDescriptor
    created_at: int
    nonce: bytes
    schema: str = "haven.invite.reply.v1"
    replier_key_agreement_key: Optional[bytes] = None
    proof: Optional[HavenSignatureProof] = None

    SPECS = {
        "schema": _s("schema"),
        "reply_id": _s("replyID"),
        "ticket_id": _s("ticketID"),
        "audience_token": _s("audienceToken"),
        "decision": _s("decision"),
        "replier": _s("replier", "model", model=IdentityPublicKeyDescriptor),
        "replier_key_agreement_key": _s("replierKeyAgreementKey", "bytes", optional=True),
        "created_at": _s("createdAt", "int"),
        "nonce": _s("nonce", "bytes"),
        "proof": _s("proof", "model", model=HavenSignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


@dataclass
class ChatInvitationArtifact(WireModel):
    invitation_id: str
    chat_cell_uuid: str
    topic: str
    audience_mode: str
    suite_id: str
    persistence_mode: str
    inviter_identity: IdentityPublicKeyDescriptor
    invited_identity: IdentityPublicKeyDescriptor
    created_at: str
    expires_at: str
    nonce: bytes
    version: int = 1
    purpose: str = "chat_invitation"
    proof: Optional[SignatureProof] = None

    SPECS = {
        "version": _s("version", "int"),
        "invitation_id": _s("invitationID"),
        "purpose": _s("purpose"),
        "chat_cell_uuid": _s("chatCellUUID"),
        "topic": _s("topic"),
        "audience_mode": _s("audienceMode"),
        "suite_id": _s("suiteID"),
        "persistence_mode": _s("persistenceMode"),
        "inviter_identity": _s("inviterIdentity", "model", model=IdentityPublicKeyDescriptor),
        "invited_identity": _s("invitedIdentity", "model", model=IdentityPublicKeyDescriptor),
        "created_at": _s("createdAt"),
        "expires_at": _s("expiresAt"),
        "nonce": _s("nonce", "bytes"),
        "proof": _s("proof", "model", model=SignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


@dataclass
class ChatInvitationAcceptance(WireModel):
    acceptance_id: str
    invitation_id: str
    invitation_hash: bytes
    chat_cell_uuid: str
    inviter_identity_uuid: str
    invitee_identity: IdentityPublicKeyDescriptor
    created_at: str
    nonce: bytes
    version: int = 1
    purpose: str = "accept_chat_invitation"
    invitee_key_agreement_key: Optional[bytes] = None
    proof: Optional[SignatureProof] = None

    SPECS = {
        "version": _s("version", "int"),
        "acceptance_id": _s("acceptanceID"),
        "purpose": _s("purpose"),
        "invitation_id": _s("invitationID"),
        "invitation_hash": _s("invitationHash", "bytes"),
        "chat_cell_uuid": _s("chatCellUUID"),
        "inviter_identity_uuid": _s("inviterIdentityUUID"),
        "invitee_identity": _s("inviteeIdentity", "model", model=IdentityPublicKeyDescriptor),
        "invitee_key_agreement_key": _s("inviteeKeyAgreementKey", "bytes", optional=True),
        "created_at": _s("createdAt"),
        "nonce": _s("nonce", "bytes"),
        "proof": _s("proof", "model", model=SignatureProof, optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("proof",)


# ---------------------------------------------------------------------------
# Bridge identity proof
# ---------------------------------------------------------------------------


@dataclass
class IdentitySigningChallenge(WireModel):
    """Signed as the whole JSONEncoder(.sortedKeys) output; nothing excluded."""

    TYPE: ClassVar[str] = "org.haven.cellprotocol.identity-signing-challenge"
    PURPOSE: ClassVar[str] = "identity-origin-proof"
    DEFAULT_VALIDITY: ClassVar[float] = 60
    ALLOWED_CLOCK_SKEW: ClassVar[float] = 300
    MAXIMUM_ENCODED_BYTES: ClassVar[int] = 8 * 1024
    MINIMUM_NONCE_BYTES: ClassVar[int] = 32
    MAXIMUM_NONCE_BYTES: ClassVar[int] = 128
    MAXIMUM_SCOPE_CHARACTERS: ClassVar[int] = 512

    identity_uuid: str
    domain: str
    resource: str
    action: str
    audience: str
    nonce: bytes
    issued_at: float
    expires_at: float
    public_key_fingerprint: Optional[str] = None
    type: str = "org.haven.cellprotocol.identity-signing-challenge"
    version: int = 1
    purpose: str = "identity-origin-proof"

    SPECS = {
        "type": _s("type"),
        "version": _s("version", "int"),
        "purpose": _s("purpose"),
        "identity_uuid": _s("identityUUID"),
        "public_key_fingerprint": _s("publicKeyFingerprint", optional=True),
        "domain": _s("domain"),
        "resource": _s("resource"),
        "action": _s("action"),
        "audience": _s("audience"),
        "nonce": _s("nonce", "bytes"),
        "issued_at": _s("issuedAt", "number"),
        "expires_at": _s("expiresAt", "number"),
    }

    def signing_data(self) -> bytes:
        return self.to_json_bytes()


WIRE_TYPES: dict[str, type[WireModel]] = {
    cls.__name__: cls
    for cls in (
        IdentityEnrollmentRequest,
        IdentityEnrollmentApproval,
        IdentityLinkRevocation,
        HavenInviteTicket,
        HavenInvitePublication,
        HavenInviteReply,
        HavenInviteRevocationNotice,
        HavenInviteContactRequest,
        ChatInvitationArtifact,
        ChatInvitationAcceptance,
        IdentitySigningChallenge,
    )
}
