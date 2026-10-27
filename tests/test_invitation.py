"""Invitation on a Python node: landing (as CellScaffold) and cell (as Binding)."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from urllib.parse import urlparse

from cellprotocol.cells.invitation import InvitationCell
from cellprotocol.interop import invite as inv
from cellprotocol.interop import models as m
from cellprotocol.interop import verify as v
from cellprotocol_scaffold.invite_landing import InviteLanding

FIXTURES = Path(__file__).parent / "fixtures" / "interop" / "v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
SEEDS = {party["name"]: bytes.fromhex(party["seedHex"]) for party in MANIFEST["parties"]}
DESCRIPTORS = {party["name"]: m.IdentityPublicKeyDescriptor.from_wire(party["descriptor"]) for party in MANIFEST["parties"]}
VERIFY_AT = MANIFEST["verifyAtEpoch"]
BASE = "https://landing.test"


def _wire(name: str) -> dict:
    case = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(case["encodedBase64"]))


def run(coro):
    return asyncio.run(coro)


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def in_process(landing: InviteLanding):
    """A transport that calls the landing directly, by route, as HTTP would."""

    async def transport(method, url, body, headers):
        path = urlparse(url).path
        if method == "POST" and path == "/i/api/publish":
            response = landing.publish(body)
        elif method == "POST" and path == "/i/api/revoke":
            response = landing.revoke(body)
        elif method == "POST" and path == "/i/api/status":
            response = landing.status(body)
        elif method == "POST" and path == "/i/api/requests":
            response = landing.collect(body)
        elif method == "GET" and path.startswith("/i/"):
            response = landing.landing(path[3:], wants_json=True)
        elif method == "POST" and path.startswith("/i/") and path.endswith("/reply"):
            response = landing.reply(path[3:-6], body, is_json=True)
        else:
            return 404, None
        # Round-trip through JSON, as the wire does.
        return response.status, json.loads(response.body_bytes()) if response.body_bytes() else None

    return transport


def _cell(party: str, clock: Clock, landing: InviteLanding, **kwargs) -> InvitationCell:
    signer, _ = v.ed25519_signer(SEEDS[party])
    counter = iter(range(1, 10_000))
    return InvitationCell(
        descriptor=DESCRIPTORS[party],
        signer=signer,
        display_name=party.capitalize(),
        landing_base=BASE,
        transport=in_process(landing),
        clock=clock,
        new_uuid=lambda: f"00000000-0000-4000-8000-{next(counter):012d}",
        **kwargs,
    )


# -- landing against the Swift fixtures ---------------------------------------


def test_landing_accepts_swift_publication_and_refuses_a_swapped_code():
    landing = InviteLanding(Clock(VERIFY_AT))
    swapped = landing.publish(_wire("invite.publication.code-swapped"))
    assert (swapped.status, swapped.body["code"]) == (403, "ticket_mismatch")
    accepted = landing.publish(_wire("invite.publication.valid"))
    assert accepted.status == 200 and accepted.body["code"] == "ok"
    assert landing.publish(_wire("invite.publication.valid")).body["message"] == "Allerede registrert."
    record = next(iter(landing.tickets.values()))
    status_key = _wire("invite.publication.valid")["statusKey"]
    assert record.status_key_digest == inv.status_key_digest(status_key) != status_key


def test_landing_stores_swift_contact_request_once_and_deletes_on_collect():
    landing = InviteLanding(Clock(VERIFY_AT))
    publication = _wire("invite.publication.valid")
    landing.publish(publication)
    reply = landing.reply("ABC234", _wire("invite.contact-request.valid"), is_json=True)
    assert reply.status == 200, reply.body
    query = {"ticketID": publication["ticketID"], "statusKey": publication["statusKey"]}
    status = landing.status(query).body
    assert status["contactRequestCount"] == 1 and status["openCount"] == 0 and "firstOpenedAt" not in status
    assert landing.status({**query, "statusKey": "wrong"}).status == 404
    collected = landing.collect(query).body["requests"]
    assert len(collected) == 1
    request = m.HavenInviteContactRequest.from_wire(collected[0])
    ticket = inv.decode_ticket(publication["ticketToken"])
    v.verify_contact_request(request, ticket, now=VERIFY_AT)
    assert landing.collect(query).body["requests"] == []


def test_landing_revocation_checks_the_issuer():
    landing = InviteLanding(Clock(VERIFY_AT))
    landing.publish(_wire("invite.publication.valid"))
    forged = landing.revoke(_wire("invite.revocation.forged"))
    assert forged.status == 403
    assert landing.revoke(_wire("invite.revocation.valid")).status == 200
    assert landing.landing("ABC234", wants_json=True).status == 410
    assert landing.reply("ABC234", _wire("invite.contact-request.valid"), is_json=True).body["code"] == "not_active"


def test_landing_page_counts_opens_but_status_does_not_tell():
    landing = InviteLanding(Clock(VERIFY_AT))
    publication = _wire("invite.publication.valid")
    landing.publish(publication)
    page = landing.landing("ABC234")
    assert page.status == 200 and "Alice" in page.body
    assert landing.tickets[publication["ticketID"]].open_count == 1
    status = landing.status({"ticketID": publication["ticketID"], "statusKey": publication["statusKey"]}).body
    assert status["state"] == "published" and status["openCount"] == 0
    assert landing.landing("ZZZZZZ").status == 404
    assert landing.landing("not-a-ticket-at-all-really").status == 400


def test_link_helpers_match_swift():
    ticket = inv.decode_ticket(_wire("invite.publication.valid")["ticketToken"])
    token = inv.encode_ticket(ticket)
    assert inv.token_from_link(f"haven://invite/{token}") == token
    assert inv.token_from_link(f"https://x.test/i/{token}") == token
    assert inv.token_from_link(f"https://gw.test/redirect?t={token}") == token
    assert inv.token_from_link("https://x.test/i/ABC234") == "ABC234"
    verdict = inv.verify(ticket, now=VERIFY_AT)
    payload = inv.verdict_payload(verdict, ticket)
    assert payload["code"] == "valid" and payload["reason"] == "Gyldig invitasjon fra Alice." and payload["audienceMatches"] is None
    assert inv.disclosure_token("email", inv.normalize_email("Ola <Ola@Example.COM>")) == inv.sha256_hex("haven.endpoint.v1|email|ola@example.com")[:16]


# -- cells end to end ---------------------------------------------------------


def test_invite_reply_pull_accept_between_two_python_cells():
    clock = Clock(VERIFY_AT)
    landing = InviteLanding(clock)
    alice = _cell("alice", clock, landing, contact_endpoint_id="ep-alice")
    bob = _cell("bob", clock, landing)

    prepared = run(alice.set("invite.prepare", {"recipient": "bob@example.org", "recipientDisplayName": "Bob Testesen"}))
    assert prepared["status"] == "ok" and prepared["published"], prepared
    assert prepared["link"] == f"{BASE}/i/{prepared['humanCode']}"
    assert prepared["canReceiveContactRequest"] is True

    # Bob checks the short link, then answers it.
    checked = run(bob.set("invite.verify", {"link": prepared["selfContainedLink"]}))
    assert checked["code"] == "valid"
    answered = run(bob.set("invite.respond", {"link": prepared["link"], "message": "Hei Alice!", "senderEntityRef": "cell:///EntityAnchor"}))
    assert answered["status"] == "ok", answered

    status = run(alice.set("invite.refreshStatus", {}))
    assert status["outbox"][0]["state"] == "joined" and status["outbox"][0]["contactRequestCount"] == 1
    pulled = run(alice.set("invite.pullContactRequests", {}))
    assert pulled["receivedCount"] == 1 and pulled["inbox"][0]["message"] == "Hei Alice!"
    accepted = run(alice.set("invite.acceptContactRequest", {"requestID": pulled["inbox"][0]["requestID"]}))
    assert accepted["sender"]["uuid"] == DESCRIPTORS["bob"].uuid
    assert run(alice.set("invite.pullContactRequests", {}))["receivedCount"] == 0


def test_revoke_stops_the_link_and_the_reply():
    clock = Clock(VERIFY_AT)
    landing = InviteLanding(clock)
    alice = _cell("alice", clock, landing, contact_endpoint_id="ep-alice")
    bob = _cell("bob", clock, landing)
    prepared = run(alice.set("invite.prepare", {"recipient": "bob@example.org"}))
    revoked = run(alice.set("invite.revoke", {"ticketID": prepared["ticketID"]}))
    assert "slutter å virke" in revoked["message"]
    refused = run(bob.set("invite.respond", {"link": prepared["selfContainedLink"]}))
    assert refused["status"] == "error" and refused["code"] == "not_active", refused
    assert run(alice.set("invite.verify", {"link": prepared["selfContainedLink"]}))["code"] == "revoked"


def test_no_reply_channel_means_no_reply_capability():
    clock = Clock(VERIFY_AT)
    landing = InviteLanding(clock)
    alice = _cell("alice", clock, landing)
    bob = _cell("bob", clock, landing)
    prepared = run(alice.set("invite.prepare", {"recipient": "bob@example.org"}))
    assert prepared["capabilities"] == ["create_own_entity"]
    assert run(bob.set("invite.respond", {"link": prepared["link"]}))["code"] == "no_reply_channel"


def test_inbox_cap_and_unreachable_landing():
    clock = Clock(VERIFY_AT)
    landing = InviteLanding(clock, rate_limit=False)
    alice = _cell("alice", clock, landing, contact_endpoint_id="ep-alice")
    run(alice.set("invite.configure", {"maxContactRequests": 1}))
    prepared = run(alice.set("invite.prepare", {"recipient": "bob@example.org"}))
    first = run(_cell("bob", clock, landing).set("invite.respond", {"link": prepared["link"]}))
    second = run(_cell("mallory", clock, landing).set("invite.respond", {"link": prepared["link"]}))
    assert first["status"] == "ok" and second["code"] == "inbox_full"

    async def down(method, url, body, headers):
        return 0, {"code": "transport", "message": "nede"}

    offline = InvitationCell(descriptor=DESCRIPTORS["alice"], signer=v.ed25519_signer(SEEDS["alice"])[0], landing_base=BASE, transport=down, clock=clock)
    result = run(offline.set("invite.prepare", {"recipient": "bob@example.org"}))
    assert result["published"] is False and result["link"].startswith("haven://invite/") and "publicationWarning" in result
