"""Invite someone to HAVEN, and answer an invitation, from a Python node.

The issuer half is a port of Binding's `BindingInvitationCell`: the same
`invite.*` keypaths, the same signed ticket, publication and revocation notice,
and the same scaffold calls (`/i/api/publish`, `/i/api/status`,
`/i/api/requests`, `/i/api/revoke`). Binding picks the recipient from its
`Relations` cell and hands the message to Mail or Messages; here the caller
names the recipient (`recipient`, `recipientDisplayName`) and gets the link and
the message text back. Nothing is sent to the person by this cell.

The invitee half is new: `invite.respond` takes a link (long token or short
code), checks the ticket, signs a `HavenInviteContactRequest` with this node's
key and posts it to `/i/<token>/reply` on the scaffold that holds the ticket.
Swift has no builder for that request yet; the Swift scaffold accepts this one.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse
from uuid import uuid4

from ..general_cell import GeneralCell
from ..interop import invite as inv
from ..interop.models import HavenInviteContactRequest, HavenInviteTicket, IdentityPublicKeyDescriptor, WireDecodeError
from ..interop.verify import Signer, VerificationFailure, verify_contact_request
from ..value import from_json_value

ENDPOINT = "cell:///Invitation"

READABLE_KEYS = [
    "state",
    "invite.state",
    "invite.outbox",
    "invite.inbox",
    "invite.settings",
    "invite.revoked",
    "invite.lastResult",
    "invite.boundaryStatement",
]
WRITABLE_KEYS = [
    "invite.configure",
    "invite.prepare",
    "invite.publish",
    "invite.markSent",
    "invite.refreshStatus",
    "invite.pullContactRequests",
    "invite.acceptContactRequest",
    "invite.revoke",
    "invite.verify",
    "invite.clearOutbox",
    "invite.respond",
]

# (status, parsed JSON body or None)
Transport = Callable[[str, str, Optional[dict[str, Any]], dict[str, str]], Awaitable[tuple[int, Any]]]


async def urllib_transport(method: str, url: str, body: Optional[dict[str, Any]], headers: dict[str, str]) -> tuple[int, Any]:
    """Plain HTTP with the standard library, off the event loop. 8 s, like Binding."""

    def call() -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        for key, value in headers.items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw, status = error.read(), error.code
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    try:
        return await asyncio.to_thread(call)
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        return 0, {"code": "transport", "message": f"Fikk ikke kontakt med scaffoldet: {error}"}


def _ok(message: str, side_effect: bool, **extra: Any) -> dict[str, Any]:
    return {"status": "ok", "message": message, "sideEffect": side_effect, **extra}


def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"status": "error", "code": code, "message": message, "sideEffect": False, **extra}


def _string(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value != "" else None


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _bool(value: Any) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _normalize_url(raw: str) -> Optional[str]:
    value = raw.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        return None
    return value


def _normalize_phone(raw: str) -> Optional[str]:
    digits = "".join(ch for ch in raw if ch.isdigit())
    if raw.strip().startswith("+"):
        return "+" + digits if len(digits) >= 8 else None
    if raw.strip().startswith("00"):
        return "+" + digits[2:] if len(digits) >= 10 else None
    if len(digits) == 8:  # Norwegian national number, as Binding's default region
        return "+47" + digits
    return None


def _rejected(status: int, body: Any) -> str:
    if isinstance(body, dict) and isinstance(body.get("message"), str):
        return body["message"]
    return {401: "ikke autorisert", 403: "ikke autorisert", 404: "billetten finnes ikke der", 409: "billetten er allerede registrert"}.get(
        status, f"HTTP {status}"
    )


def _readable(moment: float) -> str:
    months = ["jan.", "feb.", "mar.", "apr.", "mai", "jun.", "jul.", "aug.", "sep.", "okt.", "nov.", "des."]
    stamp = time.gmtime(moment)
    return f"{stamp.tm_mday}. {months[stamp.tm_mon - 1]} {stamp.tm_year}, {stamp.tm_hour:02d}:{stamp.tm_min:02d}"


class InvitationCell(GeneralCell):
    """`cell:///Invitation` for a Python node. `descriptor` and `signer` are the owner's key."""

    def __init__(
        self,
        owner: Any | None = None,
        *,
        descriptor: IdentityPublicKeyDescriptor,
        signer: Signer,
        display_name: Optional[str] = None,
        landing_base: str = "",
        contact_endpoint_id: Optional[str] = None,
        transport: Transport = urllib_transport,
        name: str = "Invitation",
        uuid: str | None = None,
        clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = os.urandom,
        new_uuid: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self.descriptor = descriptor
        self._signer = signer
        self._transport = transport
        self._clock = clock
        self._random_bytes = random_bytes
        self._new_uuid = new_uuid
        self.settings: dict[str, Any] = {
            "landingBase": landing_base,
            "fallbackLandingBase": "",
            "issuerDisplayName": display_name if display_name is not None else descriptor.display_name,
            "issuerEntityRef": None,
            "contactEndpointID": contact_endpoint_id,
            "defaultNote": "",
            "ttlDays": 14,
            "maxContactRequests": 3,
            "autoPublish": True,
        }
        self.outbox: list[dict[str, Any]] = []
        self.inbox: list[dict[str, Any]] = []
        self.revoked: list[dict[str, Any]] = []
        self.sent_replies: list[dict[str, Any]] = []
        self.last_result: dict[str, Any] = _ok("Klar til å lage en invitasjon.", False)
        for key in READABLE_KEYS:
            self.agreement_template.add_grant("r---", key)
            self._get_handlers[key] = self._read
        for key in WRITABLE_KEYS:
            self.agreement_template.add_grant("rw--", key)
            self._set_handlers[key] = self._write

    # -- dispatch -----------------------------------------------------------

    async def _read(self, keypath: str, requester: Any | None) -> Any:
        _ = requester
        if keypath in ("state", "invite.state"):
            return self.state_object()
        if keypath == "invite.outbox":
            return self.outbox_rows()
        if keypath == "invite.inbox":
            return self.inbox_rows()
        if keypath == "invite.settings":
            return self.settings_object()
        if keypath == "invite.revoked":
            return [{"ticketID": row["ticketID"], "reason": row["reason"], "revokedAtText": _readable(row["revokedAt"])} for row in self.revoked]
        if keypath == "invite.lastResult":
            return self.last_result
        if keypath == "invite.boundaryStatement":
            return inv.BOUNDARY_LINE
        return None

    async def _write(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        _ = requester
        value = from_json_value(value)
        handlers = {
            "invite.configure": self.configure,
            "invite.prepare": self.prepare,
            "invite.publish": self.publish,
            "invite.markSent": self.mark_sent,
            "invite.refreshStatus": self.refresh_status,
            "invite.pullContactRequests": self.pull_contact_requests,
            "invite.acceptContactRequest": self.accept_contact_request,
            "invite.revoke": self.revoke,
            "invite.verify": self.verify,
            "invite.clearOutbox": self.clear_outbox,
            "invite.respond": self.respond,
        }
        handler = handlers.get(keypath)
        if handler is None:
            return _error("unsupported_keypath", "Ukjent invitasjonshandling.")
        result = handler(value)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    def _fail(self, error: dict[str, Any]) -> dict[str, Any]:
        self.last_result = error
        return error

    def _done(self, result: dict[str, Any]) -> dict[str, Any]:
        self.last_result = result
        return result

    def _entry(self, ticket_id: Optional[str]) -> Optional[dict[str, Any]]:
        return next((entry for entry in self.outbox if entry["ticket"].ticket_id == ticket_id), None)

    def _bases(self) -> list[str]:
        seen: set[str] = set()
        bases = []
        for base in (self.settings["landingBase"], self.settings["fallbackLandingBase"]):
            base = (base or "").strip()
            if base and base.lower() not in seen:
                seen.add(base.lower())
                bases.append(base)
        return bases

    async def _post(self, base: str, path: str, body: dict[str, Any]) -> tuple[int, Any]:
        return await self._transport("POST", base.strip(" /") + path, body, {})

    # -- settings -------------------------------------------------------------

    def configure(self, value: Any) -> dict[str, Any]:
        payload = value if isinstance(value, dict) else {}
        problems = []
        for key in ("landingBase", "fallbackLandingBase"):
            if isinstance(payload.get(key), str):
                if payload[key] == "" and key == "fallbackLandingBase":
                    self.settings[key] = ""
                elif (normalized := _normalize_url(payload[key])) is not None:
                    self.settings[key] = normalized
                else:
                    problems.append(f"«{payload[key]}» ser ikke ut som en https-adresse, så jeg lot den stå.")
        if isinstance(payload.get("issuerDisplayName"), str):
            self.settings["issuerDisplayName"] = payload["issuerDisplayName"]
        for key in ("issuerEntityRef", "contactEndpointID"):
            if key in payload:
                self.settings[key] = _string(payload[key])
        if isinstance(payload.get("defaultNote"), str):
            self.settings["defaultNote"] = payload["defaultNote"]
        if (days := _int(payload.get("ttlDays"))) is not None:
            self.settings["ttlDays"] = min(90, max(1, days))
        if (cap := _int(payload.get("maxContactRequests"))) is not None:
            self.settings["maxContactRequests"] = min(20, max(1, cap))
        if (auto := _bool(payload.get("autoPublish"))) is not None:
            self.settings["autoPublish"] = auto
        message = " ".join(problems) if problems else "Invitasjonsoppsettet er lagret."
        return self._done(_ok(message, True, settings=self.settings_object()))

    def settings_object(self) -> dict[str, Any]:
        has_scaffold = bool(self._bases())
        can_reply = bool(self.settings["contactEndpointID"])
        return {
            "landingBase": self.settings["landingBase"],
            "fallbackLandingBase": self.settings["fallbackLandingBase"],
            "issuerDisplayName": self.settings["issuerDisplayName"],
            "issuerEntityRef": self.settings["issuerEntityRef"] or "",
            "contactEndpointID": self.settings["contactEndpointID"] or "",
            "defaultNote": self.settings["defaultNote"],
            "ttlDays": self.settings["ttlDays"],
            "maxContactRequests": self.settings["maxContactRequests"],
            "autoPublish": self.settings["autoPublish"],
            "hasScaffold": has_scaffold,
            "canReceiveReplies": can_reply,
            "linkMode": ("short" if self.settings["autoPublish"] else "selfContained") if has_scaffold else "appLinkOnly",
        }

    # -- prepare --------------------------------------------------------------

    async def prepare(self, value: Any) -> dict[str, Any]:
        payload = value if isinstance(value, dict) else {"recipient": value}
        force = _bool(payload.get("force")) or False
        raw = _string(payload.get("recipient")) or _string(payload.get("endpoint"))
        if raw is None:
            return self._fail(_error("bad_request", "Si hvem invitasjonen gjelder: `recipient` (e-post eller telefon)."))
        requested = (_string(payload.get("channel")) or "").lower()
        email = None if requested in ("sms", "phone") else inv.normalize_email(raw)
        phone = None if email else _normalize_phone(raw)
        if email is None and phone is None:
            return self._fail(_error("no_channel", f"«{raw}» er verken en e-postadresse eller et telefonnummer jeg kan bruke."))
        kind, normalized = ("email", email) if email else ("phone", phone)
        channel = "email" if kind == "email" else "sms"
        audience = inv.disclosure_token(kind, normalized)
        display = _string(payload.get("recipientDisplayName")) or _string(payload.get("displayName")) or raw
        now = self._clock()

        if not force:
            duplicate = next(
                (
                    entry
                    for entry in self.outbox
                    if entry["ticket"].audience_token == audience
                    and not entry["ticket"].is_expired(now)
                    and entry["state"] in ("prepared", "sent", "opened")
                ),
                None,
            )
            if duplicate is not None:
                return self._fail(
                    _error(
                        "already_invited",
                        f"{display} har allerede en åpen invitasjon. Send `force: true` hvis du vil lage en ny.",
                        ticketID=duplicate["ticket"].ticket_id,
                    )
                )
        bases = self._bases()
        if channel == "sms" and not (self.settings["autoPublish"] and bases):
            return self._fail(
                _error("sms_requires_publication", "SMS krever kort lenke, og kort lenke krever at billetten registreres hos scaffoldet.")
            )

        given = _string(payload.get("givenName")) or (display.split()[0] if display and "@" not in display else None)
        ticket = inv.build_ticket(
            self.descriptor,
            self._signer,
            issuer_display_name=self.settings["issuerDisplayName"] or self.descriptor.display_name,
            audience_token=audience,
            audience_kind=kind,
            contact_endpoint_id=self.settings["contactEndpointID"],
            issuer_entity_ref=self.settings["issuerEntityRef"],
            greeting_name=given,
            note=_string(payload.get("note")) or (self.settings["defaultNote"] or None),
            ttl_days=self.settings["ttlDays"],
            now=now,
            random_bytes=self._random_bytes,
            new_uuid=self._new_uuid,
        )
        entry: dict[str, Any] = {
            "ticket": ticket,
            "recipientDisplayName": display,
            "recipient": raw,
            "channel": channel,
            "state": "prepared",
            "published": False,
            "statusKey": None,
            "landingBase": None,
            "preparedAt": now,
            "sentAt": None,
            "openCount": 0,
            "respondedAt": None,
            "resultingEntityRef": None,
            "contactRequestCount": 0,
        }
        note = None
        attempted = self.settings["autoPublish"] and bool(bases)
        if attempted:
            outcome = await self._publish_ticket(ticket, bases)
            if isinstance(outcome, tuple):
                entry["statusKey"], entry["landingBase"] = outcome
                entry["published"] = True
                if outcome[1] != self.settings["landingBase"]:
                    note = f"Registrert hos {outcome[1]}, den primære landingssiden svarte ikke."
            else:
                note = outcome
                if channel == "sms":
                    return self._fail(_error("publish_failed", f"SMS krever kort lenke, og registreringen hos scaffoldet feilet: {outcome}"))
        base = entry["landingBase"] or (bases[0] if bases else None)
        app = inv.app_link(ticket)
        self_contained = inv.universal_link(ticket, base) if base else None
        short = inv.short_link(ticket, base) if entry["published"] and base else None
        if entry["published"]:
            link = short or self_contained or app
        elif not attempted:
            link = self_contained or app
        else:
            link = app
            note = f"Ingen landingsside svarte ({note}), så invitasjonen fikk en haven://-lenke som bare virker der HAVEN allerede er installert."
        entry.update(link=link, appLink=app, selfContainedLink=self_contained, shortLink=short)
        subject, body = _compose(ticket, display, link, channel)
        entry.update(subject=subject, body=body)
        self.outbox = [row for row in self.outbox if row["ticket"].ticket_id != ticket.ticket_id]
        self.outbox.insert(0, entry)

        headline = f"Invitasjon til {display} er klar på {'e-post' if channel == 'email' else 'SMS'}."
        extra: dict[str, Any] = {
            "ticketID": ticket.ticket_id,
            "displayName": display,
            "channel": channel,
            "recipient": raw,
            "humanCode": ticket.human_code,
            "expiresAt": ticket.expires_at,
            "expiresAtText": _readable(ticket.expires_at),
            "link": link,
            "shortLink": short or "",
            "selfContainedLink": self_contained or "",
            "appLink": app,
            "linkLength": len(link),
            "published": entry["published"],
            "subject": subject,
            "body": body,
            "boundaryStatement": inv.boundary(ticket),
            "capabilities": list(ticket.capabilities),
            "canReceiveContactRequest": ticket.can_receive_contact_request,
            "requiresUserToPressSend": True,
            "nextAction": "invite.markSent",
            "outbox": self.outbox_rows(),
        }
        if note:
            extra["publicationWarning"] = note
            headline += " " + note
        return self._done(_ok(headline, True, **extra))

    async def _publish_ticket(self, ticket: HavenInviteTicket, bases: list[str]) -> tuple[str, str] | str:
        """(statusKey, landingBase) from the first host that accepts, else the last failure text."""
        if not bases:
            return "Ingen landingsside er satt opp, så billetten ble ikke registrert."
        status_key = inv.make_status_key(self._random_bytes)
        publication = inv.build_publication(
            ticket, self._signer, status_key=status_key, max_contact_requests=self.settings["maxContactRequests"], now=self._clock()
        )
        failure = ""
        for base in bases:
            status, body = await self._post(base, "/i/api/publish", publication.to_wire())
            if 200 <= status < 300:
                return status_key, base
            failure = f"Scaffoldet avviste forespørselen: {_rejected(status, body)}" if status else _rejected(status, body)
        return failure

    async def publish(self, value: Any) -> dict[str, Any]:
        ticket_id = _string(value.get("ticketID")) if isinstance(value, dict) else _string(value)
        entry = self._entry(ticket_id)
        if entry is None:
            return self._fail(_error("not_found", "Fant ingen invitasjon med den id-en."))
        if entry["published"]:
            return _ok("Billetten er allerede registrert.", False)
        outcome = await self._publish_ticket(entry["ticket"], self._bases())
        if not isinstance(outcome, tuple):
            return self._fail(_error("publish_failed", outcome))
        entry["statusKey"], entry["landingBase"] = outcome
        entry["published"] = True
        entry["shortLink"] = inv.short_link(entry["ticket"], outcome[1])
        entry["link"] = entry["shortLink"] or entry["link"]
        return self._done(_ok(f"Billetten er registrert. Kort lenke: {entry['shortLink']}", True, ticketID=ticket_id, shortLink=entry["shortLink"]))

    def mark_sent(self, value: Any) -> dict[str, Any]:
        ticket_id = _string(value.get("ticketID")) if isinstance(value, dict) else _string(value)
        entry = self._entry(ticket_id)
        if entry is None:
            return self._fail(_error("not_found", "Fant ingen invitasjon med den id-en."))
        if entry["state"] == "prepared":
            entry["state"] = "sent"
            entry["sentAt"] = self._clock()
        return self._done(_ok(f"Merket som sendt til {entry['recipientDisplayName']}.", True, ticketID=ticket_id))

    # -- status and replies ---------------------------------------------------

    async def refresh_status(self, value: Any) -> dict[str, Any]:
        only = _string(value.get("ticketID")) if isinstance(value, dict) else None
        candidates = [
            entry
            for entry in self.outbox
            if entry["published"]
            and entry["statusKey"]
            and (entry["ticket"].ticket_id == only if only else entry["state"] in ("prepared", "sent", "opened"))
        ]
        if not candidates:
            return _ok("Ingen registrerte invitasjoner å hente status for.", False)
        updated, joined = 0, []
        for entry in candidates:
            status, report = await self._post(
                entry["landingBase"], "/i/api/status", {"ticketID": entry["ticket"].ticket_id, "statusKey": entry["statusKey"]}
            )
            if not (200 <= status < 300) or not isinstance(report, dict) or report.get("state") not in inv.LIFECYCLES:
                continue
            previous = entry["state"]
            entry["openCount"] = _int(report.get("openCount")) or 0
            entry["contactRequestCount"] = _int(report.get("contactRequestCount")) or 0
            if report.get("respondedAt") is not None:
                entry["respondedAt"] = _int(report["respondedAt"])
            entry["resultingEntityRef"] = report.get("resultingEntityRef")
            mapped = {"opened": "opened", "accepted": "joined", "declined": "declined", "revoked": "blocked"}.get(report["state"], previous)
            entry["state"] = mapped
            if mapped != previous:
                updated += 1
                if mapped == "joined":
                    joined.append(entry["recipientDisplayName"])
        if updated == 0:
            message = "Ingen endring siden sist."
        elif not joined:
            message = f"{updated} invitasjoner har fått ny status."
        else:
            message = f"{', '.join(joined)} er i HAVEN nå."
        return self._done(_ok(message, updated > 0, updatedCount=updated, outbox=self.outbox_rows()))

    async def pull_contact_requests(self, value: Any) -> dict[str, Any]:
        _ = value
        candidates = [entry for entry in self.outbox if entry["published"] and entry["statusKey"]]
        if not candidates:
            return _ok("Ingen registrerte invitasjoner å hente svar for.", False)
        received, names, rejected = 0, [], 0
        for entry in candidates:
            status, body = await self._post(
                entry["landingBase"], "/i/api/requests", {"ticketID": entry["ticket"].ticket_id, "statusKey": entry["statusKey"]}
            )
            if not (200 <= status < 300) or not isinstance(body, dict) or not isinstance(body.get("requests"), list):
                continue
            for wire in body["requests"]:
                # The scaffold only relayed this. Verify it here, against the ticket it answers.
                try:
                    request = HavenInviteContactRequest.from_wire(wire)
                    verify_contact_request(request, entry["ticket"], now=self._clock())
                except (VerificationFailure, WireDecodeError, TypeError, ValueError, KeyError):
                    rejected += 1
                    continue
                if any(row["request"].request_id == request.request_id for row in self.inbox):
                    continue
                self.inbox.insert(0, {"request": request, "receivedAt": self._clock(), "accepted": False})
                received += 1
                names.append(request.sender_display_name)
        message = (
            "Ingen nye svar."
            if received == 0
            else f"{', '.join(names)} har svart på invitasjonen. Se over og godta for å opprette kontakten."
        )
        return self._done(_ok(message, received > 0, receivedCount=received, rejectedCount=rejected, inbox=self.inbox_rows()))

    def accept_contact_request(self, value: Any) -> dict[str, Any]:
        request_id = _string(value.get("requestID")) if isinstance(value, dict) else _string(value)
        row = next((row for row in self.inbox if row["request"].request_id == request_id), None)
        if row is None:
            return self._fail(_error("not_found", "Fant ikke det svaret."))
        row["accepted"] = True
        request = row["request"]
        entry = self._entry(request.ticket_id)
        if entry is not None:
            entry["state"] = "joined"
            entry["resultingEntityRef"] = request.sender_entity_ref
        return self._done(
            _ok(
                f"{request.sender_display_name} er lagt til som kontakt.",
                True,
                requestID=request_id,
                sender=request.sender.to_wire(),
                senderEntityRef=request.sender_entity_ref or "",
                senderEndpoint=request.sender_endpoint or "",
            )
        )

    # -- revoke and verify ----------------------------------------------------

    async def revoke(self, value: Any) -> dict[str, Any]:
        payload = value if isinstance(value, dict) else {}
        ticket_id = _string(payload.get("ticketID")) or _string(value)
        if ticket_id is None:
            return _error("missing_ticket", "Mangler `ticketID`.")
        reason = _string(payload.get("reason")) or "Trukket tilbake av avsender."
        entry = self._entry(ticket_id)
        self.revoked = [row for row in self.revoked if row["ticketID"] != ticket_id]
        self.revoked.append({"ticketID": ticket_id, "reason": reason, "revokedAt": self._clock()})
        if entry is not None:
            entry["state"] = "declined"
        remote = "Lenken virker fortsatt for den som allerede har den, den ble aldri registrert hos noe scaffold."
        if entry is not None and entry["published"]:
            notice = inv.build_revocation(ticket_id, self.descriptor, self._signer, reason=reason, now=self._clock())
            status, body = await self._post(entry["landingBase"], "/i/api/revoke", notice.to_wire())
            if 200 <= status < 300:
                remote = "Lenken slutter å virke med én gang."
            else:
                remote = f"Lokalt trukket tilbake, men scaffoldet svarte ikke: {_rejected(status, body)} Prøv igjen."
        return self._done(_ok("Invitasjonen er trukket tilbake. " + remote, True, ticketID=ticket_id))

    def verify(self, value: Any) -> dict[str, Any]:
        payload = value if isinstance(value, dict) else {}
        link = _string(payload.get("link")) or _string(value)
        try:
            if link is not None:
                ticket = inv.decode_ticket(inv.token_from_link(link))
            elif isinstance(payload.get("ticket"), dict):
                ticket = HavenInviteTicket.from_wire(payload["ticket"])
            else:
                return _error("bad_request", "Send `link` eller `ticket`.")
        except inv.LinkFailure as failure:
            return _error(failure.code, failure.message)
        except (WireDecodeError, TypeError, ValueError, KeyError):
            return _error("bad_link", "Invitasjonen kunne ikke leses.")
        verdict = inv.verify(
            ticket,
            revoked_ticket_ids={row["ticketID"] for row in self.revoked},
            expected_audience_token=_string(payload.get("expectedAudienceToken")),
            now=self._clock(),
        )
        return inv.verdict_payload(verdict, ticket)

    def clear_outbox(self, value: Any) -> dict[str, Any]:
        only_resolved = _bool(value.get("onlyResolved")) if isinstance(value, dict) else None
        before = len(self.outbox)
        if only_resolved is False:
            self.outbox = []
        else:
            self.outbox = [entry for entry in self.outbox if entry["state"] not in ("joined", "declined")]
        removed = before - len(self.outbox)
        return _ok(f"Ryddet {removed} invitasjoner ut av listen.", removed > 0)

    # -- the invitee side -----------------------------------------------------

    async def respond(self, value: Any) -> dict[str, Any]:
        """Answer an invitation: verify the ticket, sign a contact request, post it to the scaffold."""
        payload = value if isinstance(value, dict) else {"link": value}
        link = _string(payload.get("link"))
        if link is None:
            return self._fail(_error("bad_request", "Send `link`: invitasjonslenken du fikk."))
        try:
            token = inv.token_from_link(link)
        except inv.LinkFailure as failure:
            return self._fail(_error(failure.code, failure.message))
        parsed = urlparse(link.strip())
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme in ("http", "https") and parsed.netloc else None
        base = base or _string(payload.get("landingBase")) or (self._bases()[0] if self._bases() else None)

        if inv.looks_like_human_code(token):
            if base is None:
                return self._fail(_error("not_configured", "En kort kode trenger adressen til scaffoldet som holder invitasjonen."))
            status, body = await self._transport("GET", f"{base.strip(' /')}/i/{token}", None, {})
            if not (200 <= status < 300) or not isinstance(body, dict) or not isinstance(body.get("ticketToken"), str):
                return self._fail(_error("not_available", _rejected(status, body) if status else "Fikk ikke kontakt med scaffoldet."))
            token = body["ticketToken"]
        try:
            ticket = inv.decode_ticket(token)
        except inv.LinkFailure as failure:
            return self._fail(_error(failure.code, failure.message))

        verdict = inv.verify(ticket, now=self._clock())
        if not verdict.is_valid:
            return self._fail(_error(verdict.code, verdict.reason, verdict=inv.verdict_payload(verdict, ticket)))
        if not ticket.can_receive_contact_request:
            return self._fail(_error("no_reply_channel", f"{ticket.issuer_display_name} har ikke åpnet for svar på denne invitasjonen."))
        if base is None:
            return self._fail(_error("not_configured", "Vet ikke hvilket scaffold som holder invitasjonen. Send `landingBase`."))
        request = inv.build_contact_request(
            ticket,
            self.descriptor,
            self._signer,
            sender_display_name=_string(payload.get("displayName")) or self.settings["issuerDisplayName"] or self.descriptor.display_name,
            # The scaffold reads a reply without an entity ref as "declined".
            sender_entity_ref=_string(payload.get("senderEntityRef")) or self.settings["issuerEntityRef"] or "cell:///EntityAnchor",
            sender_endpoint=_string(payload.get("senderEndpoint")) or self.settings["contactEndpointID"],
            message=_string(payload.get("message")),
            now=self._clock(),
            random_bytes=self._random_bytes,
            new_uuid=self._new_uuid,
        )
        status, body = await self._transport("POST", f"{base.strip(' /')}/i/{token}/reply", request.to_wire(), {})
        if not (200 <= status < 300):
            code = body.get("code") if isinstance(body, dict) and isinstance(body.get("code"), str) else "rejected"
            return self._fail(_error(code, _rejected(status, body) if status else "Fikk ikke kontakt med scaffoldet.", httpStatus=status))
        self.sent_replies.insert(0, {"requestID": request.request_id, "ticketID": ticket.ticket_id, "issuer": ticket.issuer_display_name, "sentAt": self._clock()})
        message = body.get("message") if isinstance(body, dict) and isinstance(body.get("message"), str) else "Svaret er levert."
        return self._done(
            _ok(
                message,
                True,
                requestID=request.request_id,
                ticketID=ticket.ticket_id,
                issuerDisplayName=ticket.issuer_display_name,
                issuerIdentityUUID=ticket.issuer.uuid,
            )
        )

    # -- presentation ---------------------------------------------------------

    def outbox_rows(self) -> list[dict[str, Any]]:
        revoked = {row["ticketID"] for row in self.revoked}
        now = self._clock()
        return [
            {
                "ticketID": entry["ticket"].ticket_id,
                "displayName": entry["recipientDisplayName"],
                "recipient": entry["recipient"],
                "channel": entry["channel"],
                "state": entry["state"],
                "humanCode": entry["ticket"].human_code,
                "link": entry.get("link") or "",
                "published": entry["published"],
                "openCount": entry["openCount"],
                "contactRequestCount": entry["contactRequestCount"],
                "preparedAtText": _readable(entry["preparedAt"]),
                "sentAtText": _readable(entry["sentAt"]) if entry["sentAt"] else "",
                "expired": entry["ticket"].is_expired(now),
                "revoked": entry["ticket"].ticket_id in revoked,
            }
            for entry in self.outbox
        ]

    def inbox_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "requestID": row["request"].request_id,
                "ticketID": row["request"].ticket_id,
                "displayName": row["request"].sender_display_name,
                "message": row["request"].message or "",
                "endpoint": row["request"].sender_endpoint or "",
                "senderEntityRef": row["request"].sender_entity_ref or "",
                "receivedAtText": _readable(row["receivedAt"]),
                "delivered": row["accepted"],
                "statusLine": "Lagt inn som kontakt" if row["accepted"] else f"{row['request'].sender_display_name} vil koble seg til deg",
            }
            for row in self.inbox
        ]

    def state_object(self) -> dict[str, Any]:
        pending = [row for row in self.inbox if not row["accepted"]]
        counts = {
            "total": len(self.outbox),
            "waiting": sum(1 for entry in self.outbox if entry["state"] == "prepared"),
            "sent": sum(1 for entry in self.outbox if entry["state"] in ("sent", "opened")),
            "joined": sum(1 for entry in self.outbox if entry["state"] == "joined"),
        }
        return {
            "schema": "haven.invite.state.v1",
            "settings": self.settings_object(),
            "outbox": self.outbox_rows(),
            "inbox": self.inbox_rows(),
            "sentReplies": [dict(row) for row in self.sent_replies],
            "pendingReplyCount": len(pending),
            "counts": counts,
            "boundaryStatement": inv.BOUNDARY_LINE,
            "lastResult": self.last_result,
            "privacyBoundary": "owner_local_ticket_mint_publication_is_opt_in_no_automatic_send",
        }


def _compose(ticket: HavenInviteTicket, display: str, link: str, channel: str) -> tuple[str, str]:
    greeting = f"Hei {ticket.greeting_name}!" if ticket.greeting_name else "Hei!"
    note = f"\n\n{ticket.note}" if ticket.note else ""
    if channel == "sms":
        return "", f"{greeting} {ticket.issuer_display_name} inviterer deg til HAVEN: {link} (kode {ticket.human_code})"
    subject = f"{ticket.issuer_display_name} inviterer deg til HAVEN"
    body = (
        f"{greeting}{note}\n\n{inv.boundary(ticket)}\n\n{link}\n\n"
        f"Koden er {ticket.human_code}. Invitasjonen gjelder til {_readable(ticket.expires_at)}."
    )
    return subject, body
