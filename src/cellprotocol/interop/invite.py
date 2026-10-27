"""Invitation helpers that give the same bytes and answers as CellBase Swift.

Ports of `HavenInviteLink`, `HavenInviteVerifier.payload`, `HavenInviteCopy`
boundary lines, `HavenInvitePublication.makeStatusKey`,
`HavenInviteStatusReport` and Binding's `disclosureToken`, plus builders for
the four signed envelopes an invitation needs: the ticket, its publication,
its revocation notice, and the invitee's contact request.

Swift has no builder for the contact request yet (only the scaffold receives
one). The builder here follows `HavenInviteContactRequest` and
`HavenInvitePublicationVerifier.verifyContactRequest` exactly, so a Swift
scaffold accepts what it builds.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from .models import (
    HavenInviteContactRequest,
    HavenInvitePublication,
    HavenInviteRevocationNotice,
    HavenInviteTicket,
    IdentityPublicKeyDescriptor,
    WireDecodeError,
)
from .verify import Signer, sign_model, verify_ticket

PATH_SEGMENT = "i"
CUSTOM_SCHEME = "haven"
HUMAN_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
HUMAN_CODE_LENGTH = 6
VERDICT_SCHEMA = "haven.invite.verdict.v1"
STATUS_SCHEMA = "haven.invite.status.v1"

BOUNDARY_LINE = (
    "Lenken lar deg opprette din egen entitet i HAVEN og sende meg en kontaktforespørsel tilbake. "
    "Den gir ingen tilgang til noe av mitt, og den gir meg ingen tilgang til noe av ditt."
)
BOUNDARY_LINE_WITHOUT_REPLY = (
    "Lenken lar deg opprette din egen entitet i HAVEN. "
    "Den gir ingen tilgang til noe av mitt, og den gir meg ingen tilgang til noe av ditt."
)

LIFECYCLES = ("published", "opened", "accepted", "declined", "expired", "revoked")


class LinkFailure(Exception):
    """`HavenInviteLink.Failure`, with the Swift code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# HavenInviteLink
# ---------------------------------------------------------------------------


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def data_from_base64url(text: str) -> Optional[bytes]:
    padded = text.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def human_code(seed: str) -> str:
    """Six characters with no 0/O or 1/I/L, as `HavenInviteLink.humanCode`."""
    digest = sha256_hex(seed)
    return "".join(
        HUMAN_CODE_ALPHABET[int(digest[i : i + 2], 16) % len(HUMAN_CODE_ALPHABET)]
        for i in range(0, HUMAN_CODE_LENGTH * 2, 2)
    )


def looks_like_human_code(candidate: str) -> bool:
    return len(candidate) == HUMAN_CODE_LENGTH and all(ch in HUMAN_CODE_ALPHABET for ch in candidate)


def encode_ticket(ticket: HavenInviteTicket) -> str:
    return ticket.to_token()


def decode_ticket(token: str) -> HavenInviteTicket:
    """`HavenInviteLink.decode`: malformed_payload or unsupported_version."""
    data = data_from_base64url(token)
    if data is None:
        raise LinkFailure("malformed_payload", "Lenken inneholder ikke en lesbar invitasjon.")
    try:
        wire = json.loads(data)
        if not isinstance(wire, dict):
            raise ValueError("not an object")
        version = wire.get("v", 1)
        ticket = HavenInviteTicket.from_wire(wire)
    except (ValueError, WireDecodeError, TypeError, KeyError) as error:
        raise LinkFailure("malformed_payload", "Lenken inneholder ikke en lesbar invitasjon.") from error
    if version != 1 or ticket.version != 1:
        raise LinkFailure("unsupported_version", f"Invitasjonen bruker versjon {ticket.version}, som denne appen ikke kjenner.")
    return ticket


def _trim_base(landing_base: str) -> str:
    return landing_base.strip(" /")


def universal_link(ticket: HavenInviteTicket, landing_base: str) -> Optional[str]:
    base = _trim_base(landing_base)
    return f"{base}/{PATH_SEGMENT}/{encode_ticket(ticket)}" if base else None


def app_link(ticket: HavenInviteTicket) -> str:
    return f"{CUSTOM_SCHEME}://invite/{encode_ticket(ticket)}"


def short_link(ticket: HavenInviteTicket, landing_base: str) -> Optional[str]:
    base = _trim_base(landing_base)
    return f"{base}/{PATH_SEGMENT}/{ticket.human_code}" if base else None


def token_from_link(link: str) -> str:
    """`HavenInviteLink.token(fromLink:)`."""
    trimmed = link.strip()
    if not trimmed:
        raise LinkFailure("not_a_haven_link", "Dette ser ikke ut som en HAVEN-invitasjon.")
    prefix = f"{CUSTOM_SCHEME}://invite/"
    if trimmed.startswith(prefix):
        return trimmed[len(prefix) :]
    try:
        parsed = urlparse(trimmed)
    except ValueError:
        return trimmed
    query = parse_qs(parsed.query)
    if query.get("t"):
        return query["t"][0]
    parts = [part for part in parsed.path.split("/") if part]
    if PATH_SEGMENT in parts:
        index = len(parts) - 1 - parts[::-1].index(PATH_SEGMENT)
        if index + 1 < len(parts):
            return parts[index + 1]
    if parts and (len(parts[-1]) > 16 or looks_like_human_code(parts[-1])):
        return parts[-1]
    raise LinkFailure("not_a_haven_link", "Dette ser ikke ut som en HAVEN-invitasjon.")


# ---------------------------------------------------------------------------
# Binding helpers
# ---------------------------------------------------------------------------


def normalize_email(raw: str) -> Optional[str]:
    """Binding's `HavenRelationNormalizer.normalizeEmail`, for the audience token."""
    value = raw.strip()
    if value.startswith("mailto:"):
        value = value[len("mailto:") :]
    if "<" in value and ">" in value and value.rindex("<") < value.rindex(">"):
        value = value[value.rindex("<") + 1 : value.rindex(">")]
    value = value.strip(" \"'<>,;")
    if "@" not in value:
        return None
    at = value.rindex("@")
    local, domain = value[:at], value[at + 1 :].lower()
    if not local or not domain or "." not in domain or domain.startswith(".") or domain.endswith("."):
        return None
    if " " in domain or " " in local or not all(domain.split(".")):
        return None
    tld = domain.split(".")[-1]
    if len(tld) < 2 or not tld.isalpha():
        return None
    return f"{local.lower()}@{domain}"


def disclosure_token(kind: str, normalized: str) -> str:
    """`HavenRelationNormalizer.disclosureToken`: 16 hex characters."""
    return sha256_hex(f"haven.endpoint.v1|{kind}|{normalized}")[:16]


def make_status_key(random_bytes: Callable[[int], bytes] = os.urandom) -> str:
    return base64url(random_bytes(32))


def status_key_digest(key: str) -> str:
    """What a scaffold stores in place of the bearer (`digestStatusKey`)."""
    return sha256_hex(key)


def boundary(ticket: HavenInviteTicket) -> str:
    return BOUNDARY_LINE if ticket.can_receive_contact_request else BOUNDARY_LINE_WITHOUT_REPLY


# ---------------------------------------------------------------------------
# HavenInviteVerifier verdict
# ---------------------------------------------------------------------------

_REASONS = {
    "unsigned": "Invitasjonen er ikke signert.",
    "issuer_mismatch": "Signaturen tilhører en annen identitet enn avsenderen i invitasjonen.",
    "uncanonical": "Invitasjonen kunne ikke gjøres om til den formen signaturen dekker.",
    "bad_signature": "Signaturen stemmer ikke. Invitasjonen kan være endret underveis.",
    "ttl_too_long": "Invitasjonen påstår å gjelde lenger enn 90 dager.",
    "revoked": "{name} har trukket denne invitasjonen tilbake.",
    "expired": "Invitasjonen har gått ut. Be {name} om en ny.",
    "wrong_audience": "Invitasjonen var adressert til noen andre.",
    "valid": "Gyldig invitasjon fra {name}.",
}


@dataclass
class Verdict:
    is_valid: bool
    signature_valid: bool
    expired: bool
    revoked: bool
    audience_matches: Optional[bool]
    reason: str
    code: str
    ticket_id: str
    issuer_display_name: str
    issuer_identity_uuid: str


def verify(
    ticket: HavenInviteTicket,
    *,
    revoked_ticket_ids: frozenset[str] | set[str] = frozenset(),
    expected_audience_token: Optional[str] = None,
    now: Optional[float] = None,
) -> Verdict:
    """`HavenInviteVerifier.verify`, with the Swift reasons."""
    moment = time.time() if now is None else now
    code = verify_ticket(ticket, revoked_ticket_ids=revoked_ticket_ids, expected_audience_token=expected_audience_token, now=moment)
    early = code in ("unsigned", "issuer_mismatch")
    audience = None if early or expected_audience_token is None else expected_audience_token == ticket.audience_token
    return Verdict(
        is_valid=code == "valid",
        signature_valid=code not in ("unsigned", "issuer_mismatch", "bad_signature", "uncanonical"),
        expired=ticket.is_expired(moment),
        revoked=ticket.ticket_id in revoked_ticket_ids,
        audience_matches=audience,
        reason=_REASONS[code].format(name=ticket.issuer_display_name),
        code=code,
        ticket_id=ticket.ticket_id,
        issuer_display_name=ticket.issuer_display_name,
        issuer_identity_uuid=ticket.issuer.uuid,
    )


def verdict_payload(verdict: Verdict, ticket: HavenInviteTicket) -> dict[str, Any]:
    """`HavenInviteVerifier.payload(for:ticket:)`."""
    return {
        "schema": VERDICT_SCHEMA,
        "status": "valid" if verdict.is_valid else "invalid",
        "isValid": verdict.is_valid,
        "signatureValid": verdict.signature_valid,
        "expired": verdict.expired,
        "revoked": verdict.revoked,
        "audienceMatches": verdict.audience_matches,
        "reason": verdict.reason,
        "code": verdict.code,
        "ticketID": verdict.ticket_id,
        "issuerDisplayName": verdict.issuer_display_name,
        "issuerIdentityUUID": verdict.issuer_identity_uuid,
        "capabilities": list(ticket.capabilities),
        "canReceiveContactRequest": ticket.can_receive_contact_request,
        "grantsAccess": False,
        "boundaryStatement": BOUNDARY_LINE,
        "humanCode": ticket.human_code,
        "greetingName": ticket.greeting_name or "",
        "expiresAt": ticket.expires_at,
        "sideEffect": False,
    }


def status_report(
    ticket_id: str,
    state: str,
    *,
    first_opened_at: Optional[int] = None,
    open_count: int = 0,
    responded_at: Optional[int] = None,
    contact_request_count: int = 0,
    resulting_entity_ref: Optional[str] = None,
) -> dict[str, Any]:
    """`HavenInviteStatusReport` as Swift's JSONEncoder writes it (nil omitted)."""
    report: dict[str, Any] = {
        "schema": STATUS_SCHEMA,
        "ticketID": ticket_id,
        "state": state,
        "openCount": open_count,
        "contactRequestCount": contact_request_count,
    }
    if first_opened_at is not None:
        report["firstOpenedAt"] = first_opened_at
    if responded_at is not None:
        report["respondedAt"] = responded_at
    if resulting_entity_ref is not None:
        report["resultingEntityRef"] = resulting_entity_ref
    return report


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_ticket(
    issuer: IdentityPublicKeyDescriptor,
    signer: Signer,
    *,
    issuer_display_name: str,
    audience_token: str,
    audience_kind: str = "email",
    contact_endpoint_id: Optional[str] = None,
    issuer_entity_ref: Optional[str] = None,
    greeting_name: Optional[str] = None,
    note: Optional[str] = None,
    ttl_days: int = 14,
    now: Optional[float] = None,
    random_bytes: Callable[[int], bytes] = os.urandom,
    new_uuid: Callable[[], str] = lambda: str(uuid4()),
) -> HavenInviteTicket:
    """Binding's `invite.prepare` minting step: id, code, capabilities, signature."""
    moment = int(time.time() if now is None else now)
    ticket_id = f"inv-{new_uuid().lower()}"
    capabilities = ["create_own_entity"]
    if contact_endpoint_id:
        capabilities.append("send_contact_request_to_issuer")
    ticket = HavenInviteTicket(
        ticket_id=ticket_id,
        issuer=issuer,
        issuer_display_name=issuer_display_name,
        issuer_contact_endpoint=contact_endpoint_id or None,
        issuer_entity_ref=issuer_entity_ref,
        audience_token=audience_token,
        audience_kind=audience_kind,
        human_code=human_code(ticket_id + audience_token),
        greeting_name=greeting_name,
        note=note,
        created_at=moment,
        expires_at=moment + min(90, max(1, ttl_days)) * 86_400,
        nonce=random_bytes(12),
        capabilities=capabilities,
    )
    return sign_model(ticket, signer, issuer.uuid)


def build_publication(
    ticket: HavenInviteTicket,
    signer: Signer,
    *,
    status_key: str,
    max_contact_requests: int = 3,
    now: Optional[float] = None,
) -> HavenInvitePublication:
    publication = HavenInvitePublication(
        ticket_id=ticket.ticket_id,
        human_code=ticket.human_code,
        ticket_token=encode_ticket(ticket),
        audience_token=ticket.audience_token,
        issuer_identity_uuid=ticket.issuer.uuid,
        expires_at=ticket.expires_at,
        published_at=int(time.time() if now is None else now),
        status_key=status_key,
        max_contact_requests=max_contact_requests,
    )
    return sign_model(publication, signer, ticket.issuer.uuid)


def build_revocation(
    ticket_id: str,
    issuer: IdentityPublicKeyDescriptor,
    signer: Signer,
    *,
    reason: str = "Trukket tilbake av avsender.",
    now: Optional[float] = None,
) -> HavenInviteRevocationNotice:
    notice = HavenInviteRevocationNotice(
        ticket_id=ticket_id,
        reason=reason,
        revoked_at=int(time.time() if now is None else now),
        issuer_identity_uuid=issuer.uuid,
    )
    return sign_model(notice, signer, issuer.uuid)


def build_contact_request(
    ticket: HavenInviteTicket,
    sender: IdentityPublicKeyDescriptor,
    signer: Signer,
    *,
    sender_display_name: str,
    sender_entity_ref: Optional[str] = None,
    sender_endpoint: Optional[str] = None,
    message: Optional[str] = None,
    ttl_seconds: int = 7 * 86_400,
    now: Optional[float] = None,
    random_bytes: Callable[[int], bytes] = os.urandom,
    new_uuid: Callable[[], str] = lambda: str(uuid4()),
) -> HavenInviteContactRequest:
    """The invitee's signed "I'd like to connect", answering `ticket`.

    Refuses a ticket that promises no reply channel, since the scaffold and the
    issuer would both refuse the request anyway.
    """
    if not ticket.issuer_contact_endpoint:
        raise LinkFailure("no_reply_channel", "Invitasjonen har ingen kontaktflate å svare til.")
    moment = int(time.time() if now is None else now)
    request = HavenInviteContactRequest(
        request_id=f"icr-{new_uuid().lower()}",
        ticket_id=ticket.ticket_id,
        issuer_endpoint_id=ticket.issuer_contact_endpoint,
        sender=sender,
        sender_display_name=sender_display_name,
        sender_entity_ref=sender_entity_ref,
        sender_endpoint=sender_endpoint,
        message=message,
        created_at=moment,
        expires_at=min(moment + ttl_seconds, ticket.expires_at),
        nonce=random_bytes(16),
    )
    return sign_model(request, signer, sender.uuid)
