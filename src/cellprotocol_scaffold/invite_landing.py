"""The scaffold end of an invitation, as CellScaffold's `VaporInviteLanding`.

Same routes, bodies, status codes and `{"code", "message"}` answers as the
Swift scaffold, so a Swift, Python or Go issuer can publish here and a Swift,
Python or Go invitee can reply here:

* `POST /i/api/publish`  signed `HavenInvitePublication`
* `POST /i/api/revoke`   signed `HavenInviteRevocationNotice`
* `POST /i/api/status`   `{ticketID, statusKey}` -> `HavenInviteStatusReport`
* `POST /i/api/requests` `{ticketID, statusKey}` -> `{requests: [...]}`
* `GET  /i/<token or code>` landing page
* `POST /i/<token or code>/reply` signed `HavenInviteContactRequest` as JSON

The store is in memory. Like Swift it keeps only a digest of the status key,
redacts opening telemetry from the status answer, deletes replies once the
issuer has collected them, and drops expired tickets after a day of grace.

One addition: `GET /i/<...>` with `Accept: application/json` answers with the
verdict payload and the ticket token instead of HTML, so an app can resolve a
six-character code. Swift serves only HTML there.
"""


import html
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from cellprotocol.interop import invite as inv
from cellprotocol.interop.models import (
    HavenInviteContactRequest,
    HavenInvitePublication,
    HavenInviteRevocationNotice,
    HavenInviteTicket,
    WireDecodeError,
)
from cellprotocol.interop.verify import (
    VerificationFailure,
    verify_contact_request,
    verify_publication,
    verify_revocation_notice,
)

EXPIRED_TICKET_GRACE = 24 * 60 * 60

_FAILURE_TEXT = {
    "unsigned": "Meldingen er ikke signert.",
    "issuer_mismatch": "Signaturen tilhører en annen identitet enn den meldingen oppgir.",
    "bad_signature": "Signaturen stemmer ikke.",
    "ticket_mismatch": "Meldingen passer ikke billetten.",
    "expired": "Meldingen er utløpt.",
    "ticket_expired": "Invitasjonen meldingen viser til er utløpt.",
    "wrong_decision": "Svaret er av feil slag for dette.",
}

_UNAVAILABLE = "Koden finnes ikke, eller invitasjonen er ikke lenger aktiv. Be den som inviterte deg om en ny."


def failure_message(failure: VerificationFailure) -> str:
    if failure.code.startswith("ticket_invalid:"):
        return f"Invitasjonen meldingen viser til gjelder ikke ({failure.code.split(':', 1)[1]})."
    return _FAILURE_TEXT.get(failure.code, failure.code)


@dataclass
class Response:
    status: int
    body: Any
    content_type: str = "application/json; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)

    def body_bytes(self) -> bytes:
        if isinstance(self.body, (bytes, bytearray)):
            return bytes(self.body)
        if isinstance(self.body, str):
            return self.body.encode("utf-8")
        return json.dumps(self.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def json(self) -> Any:
        return self.body


def _json(status: int, code: str, message: str, **extra: Any) -> Response:
    return Response(status, {"code": code, "message": message, **extra}, headers={"cache-control": "no-store"})


@dataclass
class TicketRecord:
    ticket_id: str
    human_code: str
    ticket_token: str
    audience_token: str
    issuer_identity_uuid: str
    issuer_display_name: str
    status_key_digest: str
    expires_at: float
    max_contact_requests: int
    open_count: int = 0
    first_opened_at: Optional[float] = None
    responded_at: Optional[float] = None
    resulting_entity_ref: Optional[str] = None
    revoked_at: Optional[float] = None
    revocation_reason: Optional[str] = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_expired(self, now: float) -> bool:
        return now > self.expires_at

    def matches_status_key(self, candidate: str) -> bool:
        import hmac

        return hmac.compare_digest(inv.status_key_digest(candidate), self.status_key_digest)

    def lifecycle(self, now: float) -> str:
        if self.is_revoked:
            return "revoked"
        if self.responded_at is not None:
            return "declined" if self.resulting_entity_ref is None else "accepted"
        if self.is_expired(now):
            return "expired"
        if self.open_count > 0:
            return "opened"
        return "published"


@dataclass
class ContactRequestRecord:
    request_id: str
    ticket_id: str
    payload_json: str
    sender_display_name: str


class RateLimiter:
    """Attempts per key in a window; past the limit, blocked for a while."""

    def __init__(self, window: float, max_attempts: int, block: float, clock: Callable[[], float]) -> None:
        self.window, self.max_attempts, self.block, self._clock = window, max_attempts, block, clock
        self._attempts: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}

    def record_attempt(self, key: str) -> Optional[int]:
        """Seconds to wait when blocked, else None."""
        now = self._clock()
        until = self._blocked_until.get(key)
        if until is not None and until > now:
            return int(until - now) + 1
        attempts = [moment for moment in self._attempts.get(key, []) if now - moment < self.window]
        attempts.append(now)
        self._attempts[key] = attempts
        if len(attempts) > self.max_attempts:
            self._blocked_until[key] = now + self.block
            return int(self.block)
        return None


class InviteLanding:
    """Framework-free handler. `mount_fastapi` wires it into the scaffold."""

    def __init__(self, clock: Callable[[], float] = time.time, *, rate_limit: bool = True) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self.tickets: dict[str, TicketRecord] = {}
        self.requests: list[ContactRequestRecord] = []
        self._rate_limit = rate_limit
        self._short_code_limiter = RateLimiter(10 * 60, 20, 15 * 60, clock)
        self._reply_limiter = RateLimiter(10 * 60, 8, 30 * 60, clock)

    # -- lookups --------------------------------------------------------------

    def _by_code(self, code: str) -> Optional[TicketRecord]:
        return next((record for record in self.tickets.values() if record.human_code == code), None)

    def purge_expired(self) -> tuple[int, int]:
        """`InviteLandingRetention.purgeExpired`: tickets past a day of grace, with their replies."""
        cutoff = self._clock() - EXPIRED_TICKET_GRACE
        with self._lock:
            gone = {ticket_id for ticket_id, record in self.tickets.items() if record.expires_at < cutoff}
            before = len(self.requests)
            self.requests = [row for row in self.requests if row.ticket_id not in gone]
            for ticket_id in gone:
                del self.tickets[ticket_id]
            return len(gone), before - len(self.requests)

    # -- issuer API -----------------------------------------------------------

    def publish(self, body: Any) -> Response:
        try:
            publication = HavenInvitePublication.from_wire(body)
        except (WireDecodeError, TypeError, ValueError, KeyError):
            return _json(400, "bad_request", "Ugyldig registrering.")
        now = self._clock()
        try:
            ticket = verify_publication(publication, now=now)
        except VerificationFailure as failure:
            return _json(403, failure.code, failure_message(failure))
        if ticket.is_expired(now):
            return _json(400, "expired", "Billetten er allerede utløpt.")
        with self._lock:
            existing = self.tickets.get(publication.ticket_id)
            if existing is not None:
                if existing.ticket_token != publication.ticket_token:
                    return _json(409, "already_published", "En annen billett er allerede registrert med den id-en.")
                return _json(200, "ok", "Allerede registrert.")
            if self._by_code(publication.human_code) is not None:
                return _json(409, "code_taken", "Koden er allerede i bruk. Lag en ny invitasjon.")
            self.tickets[publication.ticket_id] = TicketRecord(
                ticket_id=publication.ticket_id,
                human_code=publication.human_code,
                ticket_token=publication.ticket_token,
                audience_token=publication.audience_token,
                issuer_identity_uuid=publication.issuer_identity_uuid,
                issuer_display_name=ticket.issuer_display_name,
                status_key_digest=inv.status_key_digest(publication.status_key),
                expires_at=ticket.expires_at,
                max_contact_requests=max(1, min(20, publication.max_contact_requests)),
            )
        return _json(200, "ok", "Registrert.", humanCode=publication.human_code)

    def revoke(self, body: Any) -> Response:
        try:
            notice = HavenInviteRevocationNotice.from_wire(body)
        except (WireDecodeError, TypeError, ValueError, KeyError):
            return _json(400, "bad_request", "Ugyldig tilbakekalling.")
        with self._lock:
            record = self.tickets.get(notice.ticket_id)
            if record is None:
                return _json(404, "not_found", "Ukjent billett.")
            try:
                ticket = inv.decode_ticket(record.ticket_token)
                verify_revocation_notice(notice, ticket)
            except VerificationFailure as failure:
                return _json(403, failure.code, failure_message(failure))
            except inv.LinkFailure:
                return _json(400, "bad_request", "Ugyldig tilbakekalling.")
            record.revoked_at = self._clock()
            record.revocation_reason = notice.reason[:240]
        return _json(200, "ok", "Trukket tilbake.")

    def _authorised(self, body: Any) -> Optional[TicketRecord]:
        if not isinstance(body, dict):
            return None
        ticket_id, key = body.get("ticketID"), body.get("statusKey")
        if not isinstance(ticket_id, str) or not isinstance(key, str):
            return None
        record = self.tickets.get(ticket_id)
        # Same answer for "wrong key" and "no such ticket".
        if record is None or not record.matches_status_key(key):
            return None
        return record

    def status(self, body: Any) -> Response:
        if not isinstance(body, dict) or not isinstance(body.get("ticketID"), str) or not isinstance(body.get("statusKey"), str):
            return _json(400, "bad_request", "Mangler ticketID eller statusKey.")
        with self._lock:
            record = self._authorised(body)
            if record is None:
                return _json(404, "not_found", "Ukjent billett.")
            state = record.lifecycle(self._clock())
            report = inv.status_report(
                record.ticket_id,
                "published" if state == "opened" else state,
                responded_at=None if record.responded_at is None else int(record.responded_at),
                contact_request_count=sum(1 for row in self.requests if row.ticket_id == record.ticket_id),
                resulting_entity_ref=record.resulting_entity_ref,
            )
        return Response(200, report, headers={"cache-control": "no-store"})

    def collect(self, body: Any) -> Response:
        if not isinstance(body, dict) or not isinstance(body.get("ticketID"), str) or not isinstance(body.get("statusKey"), str):
            return _json(400, "bad_request", "Mangler ticketID eller statusKey.")
        with self._lock:
            record = self._authorised(body)
            if record is None:
                return _json(404, "not_found", "Ukjent billett.")
            mine = [row for row in self.requests if row.ticket_id == record.ticket_id]
            self.requests = [row for row in self.requests if row.ticket_id != record.ticket_id]
        payloads = []
        for row in mine:
            try:
                payloads.append(json.loads(row.payload_json))
            except ValueError:
                continue
        return Response(200, {"requests": payloads}, headers={"cache-control": "no-store"})

    # -- the page -------------------------------------------------------------

    def landing(self, raw: str, *, remote: str = "unknown", wants_json: bool = False) -> Response:
        raw = raw.strip()
        if not raw or len(raw) > 4096:
            return _page(404, "Fant ikke siden", "")
        is_code = inv.looks_like_human_code(raw)
        if is_code and self._rate_limit:
            retry = self._short_code_limiter.record_attempt(f"invite-code:{remote}")
            if retry is not None:
                return _page(429, "Vent litt", f"For mange forsøk fra denne maskinen. Prøv igjen om {max(1, retry // 60)} minutter.", wants_json, "rate_limited")
        now = self._clock()
        with self._lock:
            record: Optional[TicketRecord]
            if is_code:
                record = self._by_code(raw.upper())
                ticket = None
                if record is not None:
                    try:
                        ticket = inv.decode_ticket(record.ticket_token)
                    except inv.LinkFailure:
                        ticket = None
                if ticket is None:
                    return _page(404, "Invitasjonen er ikke tilgjengelig", _UNAVAILABLE, wants_json, "not_available")
            else:
                try:
                    ticket = inv.decode_ticket(raw)
                except inv.LinkFailure as failure:
                    return _page(400, "Denne lenken ser ikke riktig ut", failure.message, wants_json, failure.code)
                record = self.tickets.get(ticket.ticket_id)
            revoked = {ticket.ticket_id} if record is not None and record.is_revoked else set()
            verdict = inv.verify(ticket, revoked_ticket_ids=revoked, now=now)
            if record is not None and verdict.is_valid:
                record.open_count += 1
                if record.first_opened_at is None:
                    record.first_opened_at = now
        if not verdict.is_valid:
            if is_code:
                return _page(410, "Invitasjonen er ikke tilgjengelig", _UNAVAILABLE, wants_json, "not_available")
            return _page(410, "Denne invitasjonen kan ikke brukes", verdict.reason, wants_json, verdict.code)
        if wants_json:
            payload = inv.verdict_payload(verdict, ticket)
            payload["ticketToken"] = inv.encode_ticket(ticket)
            payload["isPublished"] = record is not None
            payload["boundaryStatement"] = inv.boundary(ticket)
            return Response(200, payload, headers={"cache-control": "no-store", "referrer-policy": "no-referrer"})
        return _landing_page(ticket, verdict, record is not None)

    # -- replying -------------------------------------------------------------

    def reply(self, raw: str, body: Any, *, is_json: bool, remote: str = "unknown") -> Response:
        if not raw:
            return _json(404, "not_found", "Fant ikke siden.")
        if self._rate_limit:
            retry = self._reply_limiter.record_attempt(f"invite-reply:{remote}")
            if retry is not None:
                return _json(429, "rate_limited", f"For mange forsøk. Prøv igjen om {max(1, retry // 60)} minutter.")
        request = None
        if is_json:
            try:
                request = HavenInviteContactRequest.from_wire(body)
            except (WireDecodeError, TypeError, ValueError, KeyError):
                request = None
        if request is None:
            # The browser path needs a signed-in person; this scaffold has no web login.
            return Response(303, b"", "text/plain", {"location": f"/login?next=/i/{raw}"})
        return self._store(request)

    def _store(self, request: HavenInviteContactRequest) -> Response:
        now = self._clock()
        with self._lock:
            record = self.tickets.get(request.ticket_id)
            if record is None:
                return _json(404, "not_found", "Ukjent billett.")
            if record.is_revoked or record.is_expired(now):
                return _json(410, "not_active", "Invitasjonen er ikke lenger aktiv.")
            try:
                ticket = inv.decode_ticket(record.ticket_token)
                verify_contact_request(request, ticket, now=now)
            except VerificationFailure as failure:
                return _json(403, failure.code, failure_message(failure))
            except inv.LinkFailure:
                return _json(400, "bad_request", "Ugyldig forespørsel.")
            existing = sum(1 for row in self.requests if row.ticket_id == record.ticket_id)
            if existing >= record.max_contact_requests:
                return _json(409, "inbox_full", "Denne invitasjonen har allerede tatt imot så mange svar som den kan.")
            if any(row.request_id == request.request_id for row in self.requests):
                return _json(200, "ok", "Allerede mottatt.")
            self.requests.append(
                ContactRequestRecord(
                    request_id=request.request_id,
                    ticket_id=record.ticket_id,
                    payload_json=request.to_json_bytes().decode("utf-8"),
                    sender_display_name=request.sender_display_name[:120],
                )
            )
            record.responded_at = now
            record.resulting_entity_ref = request.sender_entity_ref
        return _json(200, "ok", f"Svaret er levert. {ticket.issuer_display_name} henter det neste gang HAVEN er åpen.")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_HEADERS = {"cache-control": "no-store", "referrer-policy": "no-referrer"}


def _page(status: int, headline: str, detail: str, wants_json: bool = False, code: str = "") -> Response:
    if wants_json:
        return Response(status, {"code": code or "not_available", "message": detail or headline}, headers=dict(_HTML_HEADERS))
    body = (
        "<!doctype html><html lang=\"nb\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(headline)}</title></head><body><main>"
        f"<h1>{html.escape(headline)}</h1><p>{html.escape(detail)}</p></main></body></html>"
    )
    return Response(status, body, "text/html; charset=utf-8", dict(_HTML_HEADERS))


def _landing_page(ticket: HavenInviteTicket, verdict: inv.Verdict, is_published: bool) -> Response:
    greeting = f"Hei {ticket.greeting_name}," if ticket.greeting_name else "Hei,"
    note = f"<blockquote>{html.escape(ticket.note)}</blockquote>" if ticket.note else ""
    reply = (
        "<p>Åpne lenken i HAVEN-appen for å opprette din egen entitet og svare.</p>"
        if ticket.can_receive_contact_request
        else "<p>Åpne lenken i HAVEN-appen for å opprette din egen entitet.</p>"
    )
    body = (
        "<!doctype html><html lang=\"nb\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>Invitasjon fra {html.escape(ticket.issuer_display_name)}</title></head><body><main>"
        f"<p>{html.escape(greeting)}</p>"
        f"<h1>{html.escape(ticket.issuer_display_name)} inviterer deg til HAVEN</h1>{note}"
        f"<p>{html.escape(inv.boundary(ticket))}</p>{reply}"
        f"<p>Kode: <strong>{html.escape(ticket.human_code)}</strong></p>"
        f"<p><small>{html.escape(verdict.reason)}{'' if is_published else ' (ikke registrert her)'}</small></p>"
        "</main></body></html>"
    )
    return Response(200, body, "text/html; charset=utf-8", dict(_HTML_HEADERS))


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------


def mount_fastapi(app: Any, landing: InviteLanding) -> None:
    from fastapi import Request
    from fastapi.responses import Response as FastResponse

    def respond(response: Response) -> FastResponse:
        headers = dict(response.headers)
        return FastResponse(content=response.body_bytes(), status_code=response.status, media_type=response.content_type, headers=headers)

    async def body_of(request: Request) -> Any:
        try:
            return json.loads(await request.body())
        except ValueError:
            return None

    def remote_of(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    @app.post("/i/api/publish")
    async def invite_publish(request: Request) -> FastResponse:
        return respond(landing.publish(await body_of(request)))

    @app.post("/i/api/revoke")
    async def invite_revoke(request: Request) -> FastResponse:
        return respond(landing.revoke(await body_of(request)))

    @app.post("/i/api/status")
    async def invite_status(request: Request) -> FastResponse:
        return respond(landing.status(await body_of(request)))

    @app.post("/i/api/requests")
    async def invite_requests(request: Request) -> FastResponse:
        return respond(landing.collect(await body_of(request)))

    @app.get("/i/{token}")
    async def invite_landing(token: str, request: Request) -> FastResponse:
        wants_json = "application/json" in request.headers.get("accept", "")
        return respond(landing.landing(token, remote=remote_of(request), wants_json=wants_json))

    @app.post("/i/{token}/reply")
    async def invite_reply(token: str, request: Request) -> FastResponse:
        is_json = request.headers.get("content-type", "").split(";")[0].strip() == "application/json"
        return respond(landing.reply(token, await body_of(request) if is_json else None, is_json=is_json, remote=remote_of(request)))
