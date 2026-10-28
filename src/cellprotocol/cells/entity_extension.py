"""Extend my own entity onto a new scaffold or device.

A port of Binding's `BindingEntityScaffoldExtensionCell`, with the same
keypaths, payloads and result shapes, so a Python node can ask, approve or
accept against a Swift or Go node:

1. the new place asks, signing with its own fresh key (`extension.beginRequest`)
2. a place I already control reviews and approves, signing over a hash of the
   exact request it saw (`extension.reviewRequest`, `extension.approveRequest`)
3. the new place accepts, and both sides hold a link record
   (`extension.acceptApproval`)

Transport packets are base64url of the model's JSON, as Binding sends them.

The request hash here is Binding's: the UTF-8 bytes of the hex SHA-256 of the
base64 of the canonical request. `EntityAnchorCell` and the VC completion chain
in CellBase use the raw SHA-256 of the canonical request instead, so an
approval from this flow does not complete on an `EntityAnchor`. That mismatch
is in Swift; it is kept here so Binding accepts what Python approves.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import time
from typing import Any, Callable, Optional
from uuid import uuid4

from ..general_cell import GeneralCell
from ..interop.identity_link import IdentityLinkRecord, iso8601, parse_iso8601
from ..interop.models import (
    EntityBindingDescriptor,
    IdentityEnrollmentApproval,
    IdentityEnrollmentApprovalProof,
    IdentityEnrollmentRequest,
    IdentityLinkRevocation,
    IdentityPublicKeyDescriptor,
    SignatureProof,
    WireDecodeError,
)
from ..interop.verify import Signer, verify_signature
from ..value import from_json_value

ENDPOINT = "cell:///EntityScaffoldExtension"

DEFAULT_SCOPES: list[dict[str, Any]] = [
    {"id": "entity.read", "label": "Lese entiteten min", "detail": "Se relasjoner, formål og innstillinger.", "defaultOn": True},
    {"id": "entity.write", "label": "Endre entiteten min", "detail": "Legge til og endre relasjoner og innstillinger.", "defaultOn": True},
    {"id": "invite.issue", "label": "Lage invitasjoner", "detail": "Signere invitasjoner i mitt navn.", "defaultOn": False},
    {
        "id": "agreement.sign",
        "label": "Signere avtaler",
        "detail": "Inngå avtaler i mitt navn. Gi bare dette til noe du stoler helt på.",
        "defaultOn": False,
    },
]
_KNOWN_SCOPES = {scope["id"]: scope for scope in DEFAULT_SCOPES}
_DEFAULT_ON = [scope["id"] for scope in DEFAULT_SCOPES if scope["defaultOn"]]

READABLE_KEYS = ["state", "extension.state", "extension.links", "extension.pending", "extension.defaultScopes", "extension.lastResult"]
WRITABLE_KEYS = [
    "extension.beginRequest",
    "extension.reviewRequest",
    "extension.approveRequest",
    "extension.acceptApproval",
    "extension.revokeLink",
    "extension.clearPending",
]

_HUMAN_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


# ---------------------------------------------------------------------------
# Helpers shared with Swift's HavenInviteLink
# ---------------------------------------------------------------------------


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def human_code(seed: str) -> str:
    """Six characters with no 0/O or 1/I/L, as `HavenInviteLink.humanCode`."""
    digest = sha256_hex(seed)
    return "".join(_HUMAN_CODE_ALPHABET[int(digest[i : i + 2], 16) % len(_HUMAN_CODE_ALPHABET)] for i in range(0, 12, 2))


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def data_from_base64url(text: str) -> Optional[bytes]:
    padded = text.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def binding_request_hash(request: IdentityEnrollmentRequest) -> bytes:
    """`Data(sha256Hex(canonical.base64EncodedString()).utf8)` from Binding."""
    canonical = base64.b64encode(request.canonical_payload()).decode("ascii")
    return sha256_hex(canonical).encode("utf-8")


def _ok(message: str, side_effect: bool, **extra: Any) -> dict[str, Any]:
    return {"status": "ok", "message": message, "sideEffect": side_effect, **extra}


def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"status": "error", "code": code, "message": message, "sideEffect": False, **extra}


def _string(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [value]
    return []


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _decode_transport(model: type, value: Any, key: str) -> Any:
    """Accepts a base64url string, `{"payload": ...}`, `{key: {...}}` or the bare object."""
    payload = value if isinstance(value, dict) else None
    text = _string(payload.get("payload")) if payload else _string(value)
    if text:
        data = data_from_base64url(text)
        if data is not None:
            try:
                return model.from_wire(json.loads(data))
            except (ValueError, WireDecodeError, TypeError, KeyError):
                pass
    for candidate in ([payload.get(key)] if payload and isinstance(payload.get(key), dict) else []) + [value]:
        if isinstance(candidate, dict):
            try:
                return model.from_wire(candidate)
            except (WireDecodeError, TypeError, ValueError, KeyError):
                continue
    return None


def _encode(model: Any) -> str:
    return base64url(model.to_json_bytes())


def _readable(moment: float) -> str:
    months = ["jan.", "feb.", "mar.", "apr.", "mai", "jun.", "jul.", "aug.", "sep.", "okt.", "nov.", "des."]
    stamp = time.gmtime(moment)
    return f"{stamp.tm_mday}. {months[stamp.tm_mon - 1]} {stamp.tm_year}, {stamp.tm_hour:02d}:{stamp.tm_min:02d}"


def _status_text(status: str) -> str:
    return {"active": "Aktiv", "revoked": "Trukket tilbake", "expired": "Utløpt", "pending": "Venter"}.get(status, status)


class EntityScaffoldExtensionCell(GeneralCell):
    """`cell:///EntityScaffoldExtension` for a Python node.

    `descriptor` and `signer` are the owner's signing key. `entity_anchor_reference`
    and `display_name` go into the request the way Binding fills them from the
    owner identity.
    """

    def __init__(
        self,
        owner: Any | None = None,
        *,
        descriptor: IdentityPublicKeyDescriptor,
        signer: Signer,
        entity_anchor_reference: str = "cell:///EntityAnchor",
        display_name: Optional[str] = None,
        platform: str = "python",
        name: str = "EntityScaffoldExtension",
        uuid: str | None = None,
        clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = os.urandom,
        new_uuid: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self.descriptor = descriptor
        self._signer = signer
        self.entity_anchor_reference = entity_anchor_reference
        self.display_name = display_name if display_name is not None else descriptor.display_name
        self.platform = platform
        self._clock = clock
        self._random_bytes = random_bytes
        self._new_uuid = new_uuid
        self.links: list[IdentityLinkRecord] = []
        self.outgoing: list[dict[str, Any]] = []  # request, humanCode, createdAt, approvedAt, linkID
        self.last_result: dict[str, Any] = _ok("Klar til å utvide entiteten til et nytt sted.", False)
        for key in READABLE_KEYS:
            self.agreement_template.add_grant("r---", key)
            self._get_handlers[key] = self._read
        for key in WRITABLE_KEYS:
            self.agreement_template.add_grant("rw--", key)
            self._set_handlers[key] = self._write

    # -- dispatch -----------------------------------------------------------

    async def _read(self, keypath: str, requester: Any | None) -> Any:
        _ = requester
        if keypath in ("state", "extension.state"):
            return self.state_object()
        if keypath == "extension.links":
            return self.link_rows()
        if keypath == "extension.pending":
            return self.pending_rows()
        if keypath == "extension.defaultScopes":
            return [dict(scope) for scope in DEFAULT_SCOPES]
        if keypath == "extension.lastResult":
            return self.last_result
        return None

    async def _write(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        _ = requester
        value = from_json_value(value)
        if keypath == "extension.beginRequest":
            return self.begin_request(value)
        if keypath == "extension.reviewRequest":
            return self.review_request(value)
        if keypath == "extension.approveRequest":
            return self.approve_request(value)
        if keypath == "extension.acceptApproval":
            return self.accept_approval(value)
        if keypath == "extension.revokeLink":
            return self.revoke_link(value)
        if keypath == "extension.clearPending":
            return self.clear_pending()
        return _error("unsupported_keypath", "Ukjent utvidelses-handling.")

    def _fail(self, error: dict[str, Any]) -> dict[str, Any]:
        self.last_result = error
        return error

    def _iso(self, moment: float) -> str:
        return iso8601(moment)

    # -- 1. Ask ---------------------------------------------------------------

    def begin_request(self, value: Any) -> dict[str, Any]:
        payload = value if isinstance(value, dict) else {}
        audience = _string(payload.get("audience"))
        if not audience:
            return self._fail(
                _error("missing_audience", "Si hvilket scaffold dette gjelder — `audience`, for eksempel https://staging.haven.digipomps.org.")
            )
        now = self._clock()
        ttl = min(1440, max(2, _int(payload.get("ttlMinutes")) or 15))
        request_id = f"enr-{self._new_uuid().lower()}"
        request = IdentityEnrollmentRequest(
            request_id=request_id,
            entity_binding=EntityBindingDescriptor(mode="localEntityAnchor", entity_anchor_reference=self.entity_anchor_reference, audience=audience),
            new_identity=self.descriptor,
            requested_domains=_strings(payload.get("requestedDomains")) or ["private"],
            requested_identity_contexts=_strings(payload.get("requestedIdentityContexts")) or ["default"],
            requested_scopes=_strings(payload.get("requestedScopes")) or list(_DEFAULT_ON),
            audience=audience,
            origin=_string(payload.get("origin")) or ENDPOINT,
            created_at=self._iso(now),
            expires_at=self._iso(now + ttl * 60),
            nonce=self._random_bytes(16),
            platform=self.platform,
            device_label=_string(payload.get("deviceLabel")) or self.display_name,
        )
        signature = self._signer(request.canonical_payload())
        request = request.replace(
            proof=SignatureProof(
                by_identity_uuid=self.descriptor.uuid,
                algorithm=self.descriptor.algorithm,
                curve_type=self.descriptor.curve_type,
                signature=signature,
            )
        )
        code = human_code(request_id + audience)
        self.outgoing = [entry for entry in self.outgoing if entry["request"].request_id != request_id]
        self.outgoing.insert(0, {"request": request, "humanCode": code, "createdAt": now, "approvedAt": None, "linkID": None})
        result = _ok(
            f"Forespørselen er klar. Vis koden {code} eller send pakken til en enhet du allerede bruker, og godkjenn der.",
            True,
            requestID=request_id,
            humanCode=code,
            payload=_encode(request),
            expiresAt=request.expires_at,
            expiresInMinutes=ttl,
            requestedScopes=list(request.requested_scopes),
            audience=audience,
            nextStep="Åpne HAVEN på en enhet du allerede bruker, og send pakken til extension.approveRequest der.",
            warning="Godkjenn aldri en forespørsel du ikke selv startet. Sjekk at koden på denne skjermen er den samme som på den andre.",
        )
        self.last_result = result
        return result

    # -- 2. Review and approve ---------------------------------------------

    def review_request(self, value: Any) -> dict[str, Any]:
        request = _decode_transport(IdentityEnrollmentRequest, value, "request")
        if request is None:
            return _error("bad_payload", "Fant ingen gyldig forespørsel i det du sendte.")
        now = self._clock()
        expiry = parse_iso8601(request.expires_at)
        expired = expiry is None or now > expiry.timestamp()
        proof = request.proof
        signature_valid = bool(
            proof is not None
            and proof.signature is not None
            and proof.by_identity_uuid == request.new_identity.uuid
            and verify_signature(proof.signature, request.canonical_payload(), request.new_identity)
        )
        already_linked = any(link.linked_identity.uuid == request.new_identity.uuid and link.status == "active" for link in self.links)
        code = human_code(request.request_id + request.audience)
        return {
            "schema": "haven.entityExtension.review.v1",
            "status": "reviewable" if signature_valid and not expired else "rejected",
            "requestID": request.request_id,
            "signatureValid": signature_valid,
            "expired": expired,
            "alreadyLinked": already_linked,
            "audience": request.audience,
            "deviceLabel": request.device_label or "ukjent enhet",
            "platform": request.platform or "",
            "requestedScopes": [
                {
                    "id": scope,
                    "label": _KNOWN_SCOPES.get(scope, {}).get("label", scope),
                    "detail": _KNOWN_SCOPES.get(scope, {}).get("detail", "Ukjent rettighet — vær ekstra forsiktig."),
                    "recognised": scope in _KNOWN_SCOPES,
                }
                for scope in request.requested_scopes
            ],
            "unknownScopes": [scope for scope in request.requested_scopes if scope not in _KNOWN_SCOPES],
            "requestedDomains": list(request.requested_domains),
            "expiresAt": request.expires_at,
            "humanCode": code,
            "summaryText": _review_summary(request, signature_valid, expired, already_linked),
            "confirmationQuestion": f"Stemmer koden {code} med det som står på den andre skjermen?",
            "sideEffect": False,
        }

    def approve_request(self, value: Any) -> dict[str, Any]:
        payload = value if isinstance(value, dict) else {}
        request = _decode_transport(IdentityEnrollmentRequest, value, "request")
        if request is None:
            return self._fail(_error("bad_payload", "Fant ingen gyldig forespørsel i det du sendte."))
        review = self.review_request(value)
        if review.get("status") != "reviewable":
            return self._fail(_error("not_approvable", review.get("summaryText") or "Forespørselen kan ikke godkjennes.", review=review))

        requested = set(request.requested_scopes)
        granted = _strings(payload.get("approvedScopes")) or [scope for scope in request.requested_scopes if scope in _KNOWN_SCOPES]
        refused = sorted(requested - set(granted))
        if not granted:
            return self._fail(_error("no_scopes", "Ingen rettigheter ble godkjent, så det er ikke noe å koble."))

        now = self._clock()
        ttl = min(1440, max(2, _int(payload.get("ttlMinutes")) or 15))
        fresh_method = _string(payload.get("freshAuthMethod"))
        approval = IdentityEnrollmentApproval(
            approval_id=f"apr-{self._new_uuid().lower()}",
            request_hash=binding_request_hash(request),
            entity_binding=request.entity_binding or EntityBindingDescriptor(mode="localEntityAnchor", audience=request.audience),
            subject_identity=request.new_identity,
            approved_domains=_strings(payload.get("approvedDomains")) or list(request.requested_domains),
            approved_identity_contexts=list(request.requested_identity_contexts),
            approved_scopes=granted,
            issuer_identity_uuid=self.descriptor.uuid,
            issuer_type="existingDevice",
            audience=request.audience,
            origin=ENDPOINT,
            created_at=self._iso(now),
            expires_at=self._iso(now + ttl * 60),
            jti=self._new_uuid().lower(),
            fresh_auth_required=True,
            fresh_auth_method=fresh_method,
            fresh_auth_performed_at=self._iso(now) if fresh_method else None,
        )
        approval = approval.replace(
            proof=IdentityEnrollmentApprovalProof(
                issuer_identity_uuid=self.descriptor.uuid,
                issuer_type="existingDevice",
                algorithm=self.descriptor.algorithm,
                curve_type=self.descriptor.curve_type,
                signature=self._signer(approval.canonical_payload()),
            )
        )
        record = IdentityLinkRecord(
            link_id=f"lnk-{self._new_uuid().lower()}",
            entity_binding=approval.entity_binding,
            linked_identity=request.new_identity,
            approved_domains=list(approval.approved_domains),
            approved_identity_contexts=list(approval.approved_identity_contexts),
            approved_scopes=list(approval.approved_scopes),
            issuer_identity_uuid=self.descriptor.uuid,
            issuer_type="existingDevice",
            status="active",
            linked_at=self._iso(now),
        )
        self._store_link(record)
        message = f"Godkjent. {request.device_label or 'Den nye enheten'} får {len(granted)} rettighet(er)."
        if refused:
            message += f" Jeg holdt tilbake: {', '.join(refused)}."
        result = _ok(
            message,
            True,
            approvalID=approval.approval_id,
            linkID=record.link_id,
            payload=_encode(approval),
            approvedScopes=granted,
            refusedScopes=refused,
            expiresAt=approval.expires_at,
            nextStep="Send denne pakken tilbake til den nye enheten og kjør extension.acceptApproval der.",
            links=self.link_rows(),
            # Not in Binding: lets the new place check the approver's signature.
            issuerIdentity=self.descriptor.to_wire(),
        )
        self.last_result = result
        return result

    # -- 3. Accept --------------------------------------------------------------

    def accept_approval(self, value: Any) -> dict[str, Any]:
        approval = _decode_transport(IdentityEnrollmentApproval, value, "approval")
        if approval is None:
            return self._fail(_error("bad_payload", "Fant ingen gyldig godkjenning i det du sendte."))
        pending = next((entry for entry in self.outgoing if entry["request"].new_identity.uuid == approval.subject_identity.uuid), None)
        if pending is None:
            return self._fail(_error("no_matching_request", "Denne godkjenningen hører ikke til noen forespørsel denne enheten har sendt."))
        if approval.request_hash != binding_request_hash(pending["request"]):
            return self._fail(
                _error("request_hash_mismatch", "Godkjenningen gjelder en annen forespørsel enn den denne enheten sendte. Jeg kobler ingenting.")
            )
        now = self._clock()
        expiry = parse_iso8601(approval.expires_at)
        if expiry is not None and now > expiry.timestamp():
            return self._fail(_error("expired", "Godkjenningen er utløpt. Start forespørselen på nytt."))

        signature_present = approval.proof is not None and approval.proof.signature is not None
        # Binding cannot check the approver's signature because it has no key
        # for it. When the caller hands one over, check it and refuse a bad one.
        issuer = _issuer_descriptor(value)
        signature_verified = False
        if issuer is not None:
            proof = approval.proof
            signature_verified = bool(
                proof is not None
                and proof.signature is not None
                and issuer.uuid == approval.issuer_identity_uuid == proof.issuer_identity_uuid
                and verify_signature(proof.signature, approval.canonical_payload(), issuer)
            )
            if not signature_verified:
                return self._fail(_error("bad_signature", "Signaturen på godkjenningen stemmer ikke med godkjennerens nøkkel. Jeg kobler ingenting."))

        record = IdentityLinkRecord(
            link_id=f"lnk-{self._new_uuid().lower()}",
            entity_binding=approval.entity_binding,
            linked_identity=approval.subject_identity,
            approved_domains=list(approval.approved_domains),
            approved_identity_contexts=list(approval.approved_identity_contexts),
            approved_scopes=list(approval.approved_scopes),
            issuer_identity_uuid=approval.issuer_identity_uuid,
            issuer_type=approval.issuer_type,
            status="active",
            linked_at=self._iso(now),
        )
        self._store_link(record)
        for entry in self.outgoing:
            if entry["request"].request_id == pending["request"].request_id:
                entry["approvedAt"] = now
                entry["linkID"] = record.link_id
        note = (
            "Forespørselens hash og godkjennerens signatur stemmer."
            if signature_verified
            else "Forespørselens hash stemmer, og godkjenningen er signert, men denne enheten har ikke godkjennerens offentlige nøkkel og kan derfor ikke sjekke signaturen selv. Bekreft koden muntlig, eller hent nøkkelen fra scaffoldet."
        )
        result = _ok(
            f"Koblet. Dette stedet er nå en del av entiteten din, med {len(approval.approved_scopes)} rettighet(er).",
            True,
            linkID=record.link_id,
            approvedScopes=list(approval.approved_scopes),
            issuerIdentityUUID=approval.issuer_identity_uuid,
            signaturePresent=signature_present,
            signatureVerified=signature_verified,
            verificationNote=note,
            links=self.link_rows(),
        )
        self.last_result = result
        return result

    # -- Revocation ---------------------------------------------------------

    def revoke_link(self, value: Any) -> dict[str, Any]:
        payload = value if isinstance(value, dict) else {}
        link_id = _string(payload.get("linkID")) or _string(value)
        if not link_id:
            return self._fail(_error("missing_id", "Mangler `linkID`."))
        link = next((item for item in self.links if item.link_id == link_id), None)
        if link is None:
            return self._fail(_error("not_found", f"Fant ingen kobling med id {link_id}."))
        now = self._clock()
        revocation = IdentityLinkRevocation(
            link_id=link_id,
            reason=_string(payload.get("reason")) or "Trukket tilbake av eier.",
            revoked_at=self._iso(now),
            revoked_by_identity_uuid=self.descriptor.uuid,
            issuer_type="existingDevice",
        )
        revocation = revocation.replace(
            proof=IdentityEnrollmentApprovalProof(
                issuer_identity_uuid=self.descriptor.uuid,
                issuer_type="existingDevice",
                algorithm=self.descriptor.algorithm,
                curve_type=self.descriptor.curve_type,
                signature=self._signer(revocation.canonical_payload()),
            )
        )
        link.status = "revoked"
        link.revoked_at = self._iso(now)
        link.revocation_reference = base64.b64encode(revocation.proof.signature).decode("ascii")
        result = _ok(
            "Koblingen er trukket tilbake her. Merk at et scaffold som allerede har koblingen slutter å godta den først når det har sett tilbakekallingen.",
            True,
            linkID=link_id,
            revocation=revocation.to_wire(),
            payload=_encode(revocation),
            enforcement="local_immediately_remote_on_receipt",
            links=self.link_rows(),
        )
        self.last_result = result
        return result

    def clear_pending(self) -> dict[str, Any]:
        now = self._clock()
        before = len(self.outgoing)

        def finished(entry: dict[str, Any]) -> bool:
            if entry["approvedAt"] is not None:
                return True
            expiry = parse_iso8601(entry["request"].expires_at)
            return expiry is None or now > expiry.timestamp()

        self.outgoing = [entry for entry in self.outgoing if not finished(entry)]
        removed = before - len(self.outgoing)
        return _ok(f"Ryddet {removed} ferdige eller utløpte forespørsler.", removed > 0)

    # -- Presentation -------------------------------------------------------

    def _store_link(self, record: IdentityLinkRecord) -> None:
        self.links = [link for link in self.links if not (link.linked_identity.uuid == record.linked_identity.uuid and link.status != "revoked")]
        self.links.insert(0, record)

    def link_rows(self) -> list[dict[str, Any]]:
        rows = []
        for link in self.links:
            linked_at = parse_iso8601(link.linked_at)
            revoked_at = parse_iso8601(link.revoked_at) if link.revoked_at else None
            name = link.linked_identity.display_name
            rows.append(
                {
                    "linkID": link.link_id,
                    "identityUUID": link.linked_identity.uuid,
                    "displayName": name or link.linked_identity.uuid,
                    "audience": link.entity_binding.audience or "",
                    "status": link.status,
                    "statusText": _status_text(link.status),
                    "scopes": list(link.approved_scopes),
                    "scopeSummary": ", ".join(_KNOWN_SCOPES.get(scope, {}).get("label", scope) for scope in link.approved_scopes),
                    "linkedAt": link.linked_at,
                    "linkedAtText": _readable(linked_at.timestamp()) if linked_at else link.linked_at,
                    "revokedAtText": _readable(revoked_at.timestamp()) if revoked_at else "",
                    "summaryLine": f"{name or 'Ukjent enhet'} · {_status_text(link.status)}",
                }
            )
        return rows

    def pending_rows(self) -> list[dict[str, Any]]:
        now = self._clock()
        rows = []
        for entry in self.outgoing:
            request = entry["request"]
            expiry = parse_iso8601(request.expires_at)
            expired = expiry is None or now > expiry.timestamp()
            approved = entry["approvedAt"] is not None
            rows.append(
                {
                    "requestID": request.request_id,
                    "humanCode": entry["humanCode"],
                    "audience": request.audience,
                    "deviceLabel": request.device_label or "",
                    "createdAtText": _readable(entry["createdAt"]),
                    "expiresAt": request.expires_at,
                    "expired": expired,
                    "approved": approved,
                    "linkID": entry["linkID"] or "",
                    "statusLine": "Godkjent"
                    if approved
                    else ("Utløpt — start på nytt" if expired else f"Venter på godkjenning · kode {entry['humanCode']}"),
                }
            )
        return rows

    def state_object(self) -> dict[str, Any]:
        active = sum(1 for link in self.links if link.status == "active")
        waiting = sum(1 for entry in self.outgoing if entry["approvedAt"] is None)
        if active == 0 and waiting == 0:
            summary = "Entiteten din finnes bare her. Du kan utvide den til et scaffold eller en annen enhet."
        else:
            summary = f"{active} aktive koblinger" + (f", {waiting} venter på godkjenning." if waiting > 0 else ".")
        return {
            "schema": "haven.entityExtension.state.v1",
            "summary": summary,
            "activeLinkCount": active,
            "pendingCount": waiting,
            "links": self.link_rows(),
            "pending": self.pending_rows(),
            "safetyLine": "Godkjenn bare en forespørsel du selv startet, og bare når koden er den samme på begge skjermene.",
            "lastResult": self.last_result,
            "updatedAt": self._iso(self._clock()),
        }


def _review_summary(request: IdentityEnrollmentRequest, signature_valid: bool, expired: bool, already_linked: bool) -> str:
    if not signature_valid:
        return "Signaturen på forespørselen stemmer ikke. Ikke godkjenn denne."
    if expired:
        return "Forespørselen er utløpt. Start en ny på den andre enheten."
    if already_linked:
        return "Denne identiteten er allerede koblet til entiteten din."
    device = request.device_label or "En ny enhet"
    return f"{device} ber om å bli en del av entiteten din på {request.audience}, med {len(request.requested_scopes)} rettighet(er)."


def _issuer_descriptor(value: Any) -> Optional[IdentityPublicKeyDescriptor]:
    if not isinstance(value, dict) or not isinstance(value.get("issuerIdentity"), dict):
        return None
    try:
        return IdentityPublicKeyDescriptor.from_wire(value["issuerIdentity"])
    except (WireDecodeError, TypeError, ValueError):
        return None
