"""test.interop.bridge-auth (Python): org.haven.bridge-channel.v1 as Swift speaks it.

The Swift vectors fix every random input (nonces, session ID, generation), so a
Python server and client driven with the same inputs must emit the very same
envelopes, and a Python client signature equals the Swift one (Ed25519 is
deterministic).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from cellprotocol.interop import channel as ch
from cellprotocol.interop import verify as v

FIXTURES = Path(__file__).parent / "fixtures" / "interop" / "v1"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
VECTORS = {
    entry["id"]: json.loads((FIXTURES / entry["file"]).read_text(encoding="utf-8"))
    for entry in MANIFEST["cases"]
    if entry["id"].startswith("bridge.channel-auth.")
}
SEEDS = {party["name"]: bytes.fromhex(party["seedHex"]) for party in MANIFEST["parties"]}


def _b(text: str) -> bytes:
    return base64.b64decode(text)


def _transcript(case: dict) -> ch.Transcript:
    return ch.Transcript.from_json(ch.decode(_b(case["encodedBase64"])))


class Clock:
    def __init__(self, wall: float) -> None:
        self.wall = wall
        self.mono = 1000.0

    def now(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono


def _server_for(case: dict, clock: Clock, **kwargs) -> ch.ChannelServer:
    t = _transcript(case)
    ids = iter([t.generation, t.session_id])
    return ch.ChannelServer(
        t.endpoint,
        wall_clock=clock.now,
        monotonic=clock.monotonic,
        random_bytes=lambda n: t.server_nonce,
        new_uuid=lambda: next(ids),
        **kwargs,
    )


def _client_for(case: dict, clock: Clock, signer_name: str = "bob") -> ch.ChannelClient:
    t = _transcript(case)
    sign, _public = v.ed25519_signer(SEEDS[signer_name])
    return ch.ChannelClient(t.identity, t.endpoint, sign, wall_clock=clock.now, monotonic=clock.monotonic, random_bytes=lambda n: t.client_nonce)


def test_vectors_present():
    assert set(VECTORS) == {"bridge.channel-auth.valid", "bridge.channel-auth.whole-second", "bridge.channel-auth.wrong-key"}


@pytest.mark.parametrize("case_id", sorted(VECTORS))
def test_transcript_signing_data_and_envelopes_match_swift(case_id):
    case = VECTORS[case_id]
    t = _transcript(case)
    assert ch.encode(t.to_json()) == _b(case["encodedBase64"])
    assert t.digest == case["related"]["transcriptDigestHex"]
    assert t.endpoint.audience == case["related"]["endpointAudience"]
    assert ch.signing_data(t) == _b(case["canonicalBase64"])
    related = case["related"]
    assert ch.envelope("channelAuthHello", ch.hello_body(t.identity, t.client_nonce)) == _b(related["helloEnvelopeBase64"])
    assert ch.envelope("channelAuthChallenge", ch.challenge_body(t)) == _b(related["challengeEnvelopeBase64"])
    assert ch.envelope("channelAuthProof", ch.proof_body(t.session_id, t.generation, _b(case["signatureBase64"]))) == _b(related["proofEnvelopeBase64"])
    assert ch.envelope("channelAuthAccepted", ch.accepted_body(t)) == _b(related["acceptedEnvelopeBase64"])
    assert ch.Endpoint.from_url(t.endpoint.audience, t.endpoint.domain) == t.endpoint


@pytest.mark.parametrize("case_id", ["bridge.channel-auth.valid", "bridge.channel-auth.whole-second"])
def test_python_server_and_client_reproduce_the_swift_handshake(case_id):
    case = VECTORS[case_id]
    t = _transcript(case)
    related = case["related"]
    clock = Clock(t.issued_at_ms / 1000)
    server = _server_for(case, clock)
    client = _client_for(case, clock)

    hello = client.hello()
    assert hello == _b(related["helloEnvelopeBase64"])
    challenge = server.receive(hello)
    assert challenge == _b(related["challengeEnvelopeBase64"])
    proof = client.receive(challenge)
    assert proof == _b(related["proofEnvelopeBase64"])
    accepted = server.receive(proof)
    assert accepted == _b(related["acceptedEnvelopeBase64"])
    assert client.receive(accepted) is None

    assert server.state == client.state == "authenticated"
    assert server.admitted.identity == client.admitted.identity == t.identity
    assert server.admitted.transcript_digest == t.digest
    server.admitted.check_identity(t.identity, required=True, now=clock.wall)


def test_swift_client_messages_are_accepted_by_python_server():
    case = VECTORS["bridge.channel-auth.valid"]
    related = case["related"]
    t = _transcript(case)
    clock = Clock(t.issued_at_ms / 1000 + 1)
    server = _server_for(case, clock)
    server._wall = lambda: t.issued_at_ms / 1000  # challenge issued at the vector time
    assert server.receive(_b(related["helloEnvelopeBase64"])) == _b(related["challengeEnvelopeBase64"])
    server._wall = clock.now
    assert server.receive(_b(related["proofEnvelopeBase64"])) == _b(related["acceptedEnvelopeBase64"])


def test_proof_from_another_key_is_refused_and_terminal():
    case = VECTORS["bridge.channel-auth.wrong-key"]
    related = case["related"]
    t = _transcript(case)
    clock = Clock(t.issued_at_ms / 1000)
    server = _server_for(case, clock)
    server.receive(_b(related["helloEnvelopeBase64"]))
    with pytest.raises(ch.ChannelFailure) as failure:
        server.receive(_b(related["proofEnvelopeBase64"]))
    assert failure.value.code == "invalidProof"
    assert server.state == "closed" and server.admitted is None
    with pytest.raises(ch.ChannelFailure):
        server.receive(_b(related["helloEnvelopeBase64"]))


def test_replayed_proof_cannot_open_a_second_channel():
    case = VECTORS["bridge.channel-auth.valid"]
    related = case["related"]
    t = _transcript(case)
    clock = Clock(t.issued_at_ms / 1000)
    server = _server_for(case, clock)
    server.receive(_b(related["helloEnvelopeBase64"]))
    server.receive(_b(related["proofEnvelopeBase64"]))
    with pytest.raises(ch.ChannelFailure) as failure:
        server.receive(_b(related["proofEnvelopeBase64"]))
    assert failure.value.code == "unexpectedMessage"
    # A fresh connection issues a new generation, so the old proof is stale.
    other = ch.ChannelServer(t.endpoint, wall_clock=clock.now, monotonic=clock.monotonic, random_bytes=lambda n: t.server_nonce)
    other.receive(_b(related["helloEnvelopeBase64"]))
    with pytest.raises(ch.ChannelFailure) as stale:
        other.receive(_b(related["proofEnvelopeBase64"]))
    assert stale.value.code == "staleGeneration"


def test_late_proof_is_expired():
    case = VECTORS["bridge.channel-auth.valid"]
    related = case["related"]
    t = _transcript(case)
    clock = Clock(t.issued_at_ms / 1000)
    server = _server_for(case, clock)
    server.receive(_b(related["helloEnvelopeBase64"]))
    clock.wall += ch.CHALLENGE_LIFETIME
    with pytest.raises(ch.ChannelFailure) as failure:
        server.receive(_b(related["proofEnvelopeBase64"]))
    assert failure.value.code == "expired"


def test_pre_auth_deadline_closes_the_connection():
    case = VECTORS["bridge.channel-auth.valid"]
    t = _transcript(case)
    clock = Clock(t.issued_at_ms / 1000)
    server = _server_for(case, clock)
    clock.mono += ch.PRE_AUTH_DEADLINE
    with pytest.raises(ch.ChannelFailure) as failure:
        server.receive(_b(case["related"]["helloEnvelopeBase64"]))
    assert failure.value.code == "expired"


def test_client_refuses_a_challenge_for_another_endpoint():
    """A peer cannot make the client sign for a route it did not choose."""
    case = VECTORS["bridge.channel-auth.valid"]
    t = _transcript(case)
    clock = Clock(t.issued_at_ms / 1000)
    elsewhere = ch.Endpoint.from_url("wss://evil.example/bridgehead/x/y", "bridge")
    server = ch.ChannelServer(elsewhere, wall_clock=clock.now, monotonic=clock.monotonic)
    signed: list[bytes] = []
    sign, _ = v.ed25519_signer(SEEDS["bob"])
    client = ch.ChannelClient(t.identity, t.endpoint, lambda data: signed.append(data) or sign(data), wall_clock=clock.now, monotonic=clock.monotonic)
    challenge = server.receive(client.hello())
    with pytest.raises(ch.ChannelFailure) as failure:
        client.receive(challenge)
    assert failure.value.code == "invalidProof"
    assert signed == []


def test_client_refuses_a_challenge_that_lies_about_signing_data():
    case = VECTORS["bridge.channel-auth.valid"]
    t = _transcript(case)
    clock = Clock(t.issued_at_ms / 1000)
    client = _client_for(case, clock)
    client.hello()
    body = ch.challenge_body(t)
    body["signingData"] = base64.b64encode(b"sign me instead").decode()
    with pytest.raises(ch.ChannelFailure):
        client.receive(ch.envelope("channelAuthChallenge", body))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.replace(b'"cid":0', b'"cid":1'),
        lambda raw: raw.replace(b'{"&string"', b'{"identity":null,"&string"'),
        lambda raw: raw + b" ",
        lambda raw: raw.replace(b"channelAuthHello", b"get"),
    ],
)
def test_noncanonical_or_foreign_envelopes_are_malformed(mutate):
    case = VECTORS["bridge.channel-auth.valid"]
    t = _transcript(case)
    server = _server_for(case, Clock(t.issued_at_ms / 1000))
    with pytest.raises(ch.ChannelFailure):
        server.receive(mutate(_b(case["related"]["helloEnvelopeBase64"])))
    assert server.state == "closed"


@pytest.mark.parametrize(
    "url",
    [
        "ws://staging.haven.digipomps.org/bridgehead/a/b",
        "wss://user@host.example/a",
        "wss://host.example/a?x=1",
        "wss://Host.example/a",
        "wss://host.example:443/a",
        "wss://host.example/a/../b",
        "wss://host.example//a",
    ],
)
def test_endpoint_validation_matches_swift(url):
    with pytest.raises(ch.ChannelFailure):
        ch.Endpoint.from_url(url, "bridge")


def test_loopback_ws_needs_explicit_opt_in():
    with pytest.raises(ch.ChannelFailure):
        ch.Endpoint.from_url("ws://127.0.0.1:8080/bridgehead/a/b", "bridge")
    endpoint = ch.Endpoint.from_url("ws://127.0.0.1:8080/bridgehead/a/b", "bridge", allow_insecure_loopback=True)
    assert endpoint.origin == "ws://127.0.0.1:8080" and endpoint.route == "/bridgehead/a/b"


def test_later_commands_must_carry_the_admitted_key():
    case = VECTORS["bridge.channel-auth.valid"]
    t = _transcript(case)
    admitted = ch.AdmittedChannel(t.identity, t.endpoint, t.session_id, t.generation, t.digest, t.channel_expires_at_ms / 1000)
    now = t.issued_at_ms / 1000
    admitted.check_identity(t.identity, required=True, now=now)
    admitted.check_identity(None, required=False, now=now)
    other = ch.PublicIdentity(uuid=t.identity.uuid, public_key=v.ed25519_signer(SEEDS["mallory"])[1])
    with pytest.raises(ch.ChannelFailure):
        admitted.check_identity(other, required=True, now=now)
    with pytest.raises(ch.ChannelFailure):
        admitted.check_identity(None, required=True, now=now)
    with pytest.raises(ch.ChannelFailure):
        admitted.check(now=t.channel_expires_at_ms / 1000)
