"""Bridge channel admission, `org.haven.bridge-channel.v1`, as Swift speaks it.

Before any Cell command, a Swift bridgehead requires four messages on the
WebSocket (CellProtocol `BridgeChannelAuthentication`, `BridgeChannelSession`,
`BridgeChannelClientOperation`; see `Docs/BridgeIdentitySecurity.md`):

1. client -> server `channelAuthHello`     {profile, identity, clientNonce}
2. server -> client `channelAuthChallenge` {transcript, signingData}
3. client -> server `channelAuthProof`     {sessionID, generation, signature}
4. server -> client `channelAuthAccepted`  {sessionID, generation, transcriptDigest}

Each is a BridgeCommand `{"&string": C(body), "cid": 0, "cmd": name}` where C is
`JSONEncoder` with `.sortedKeys` and `.withoutEscapingSlashes`. Bodies are
decoded strictly: re-encoding must give the same bytes. The client signs an
`IdentitySigningChallenge` whose resource binds SHA-256 of the transcript.

Admission proves control of a public key. It grants no Cell permission.

This module is transport-free: `ChannelServer` and `ChannelClient` take bytes
and return bytes, so the ASGI scaffold, a test, or another transport can use them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid as uuidlib
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

from .canonical import canonical_json
from .models import IdentityPublicKeyDescriptor, IdentitySigningChallenge
from .verify import VerificationFailure, validate_signing_challenge, verify_signature

PROFILE = "org.haven.bridge-channel.v1"
ACTION = "openBridgeChannel"
MAXIMUM_ENVELOPE_BYTES = 16 * 1024
CHALLENGE_LIFETIME = 30.0
CHANNEL_LIFETIME = 300.0
PRE_AUTH_DEADLINE = 10.0
DIRECTION = "client-to-server"
AUTH_COMMANDS = ("channelAuthHello", "channelAuthChallenge", "channelAuthProof", "channelAuthAccepted")

# Foundation's Date stores seconds since 2001-01-01. Swift turns milliseconds
# into a Date and back, and the signed doubles carry that rounding.
_REFERENCE_DATE_OFFSET = 978_307_200.0


class ChannelFailure(VerificationFailure):
    """`BridgeChannelAuthentication.Failure` case names."""


def encode(value: Any) -> bytes:
    """`BridgeChannelAuthentication.encode`: sorted keys, slashes not escaped."""
    return canonical_json(value, key_order="encoder", escape_slashes=False)


def decode(data: bytes) -> dict[str, Any]:
    """Strict decode: bounded, an object, and byte-identical on re-encode."""
    if len(data) > MAXIMUM_ENVELOPE_BYTES:
        raise ChannelFailure("malformed", "envelope too large")
    try:
        value = json.loads(data)
    except ValueError as error:
        raise ChannelFailure("malformed", "not JSON") from error
    if not isinstance(value, dict) or encode(value) != data:
        raise ChannelFailure("malformed", "not canonical")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ChannelFailure("malformed", "expected base64")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ChannelFailure("malformed", "bad base64") from error


def _exact_keys(value: Mapping[str, Any], keys: set[str]) -> None:
    if set(value.keys()) != keys:
        raise ChannelFailure("malformed", f"fields {sorted(value.keys())}")


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ChannelFailure("malformed", "uuid")
    try:
        parsed = uuidlib.UUID(value)
    except ValueError as error:
        raise ChannelFailure("malformed", "uuid") from error
    return str(parsed).upper()


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicIdentity:
    """Only UUID, algorithm, curve and public key. Never a full Identity."""

    uuid: str
    public_key: bytes
    algorithm: str = "EdDSA"
    curve: str = "Curve25519"

    def to_json(self) -> dict[str, Any]:
        return {"uuid": self.uuid, "algorithm": self.algorithm, "curve": self.curve, "publicKey": _b64(self.public_key)}

    @classmethod
    def from_json(cls, value: Any) -> "PublicIdentity":
        if not isinstance(value, dict):
            raise ChannelFailure("malformed", "identity")
        _exact_keys(value, {"uuid", "algorithm", "curve", "publicKey"})
        identity = cls(uuid=value["uuid"], public_key=_unb64(value["publicKey"]), algorithm=value["algorithm"], curve=value["curve"])
        identity.validate()
        return identity

    def validate(self) -> None:
        if not isinstance(self.uuid, str) or not self.uuid or len(self.uuid.encode("utf-8")) > 512:
            raise ChannelFailure("malformed", "identity uuid")
        # Swift also accepts P-256; the Python node signs and verifies Ed25519 only.
        if (self.algorithm, self.curve) != ("EdDSA", "Curve25519") or len(self.public_key) != 32:
            raise ChannelFailure("malformed", "unsupported key")

    @property
    def descriptor(self) -> IdentityPublicKeyDescriptor:
        return IdentityPublicKeyDescriptor(uuid=self.uuid, public_key=self.public_key, algorithm=self.algorithm, curve_type=self.curve)

    @property
    def fingerprint(self) -> str:
        return self.descriptor.fingerprint


@dataclass(frozen=True)
class Endpoint:
    """Built from a locally configured URL, never from Host or Forwarded headers."""

    origin: str
    route: str
    domain: str

    @property
    def audience(self) -> str:
        return self.origin + self.route

    @classmethod
    def from_url(cls, url: str, domain: str, allow_insecure_loopback: bool = False) -> "Endpoint":
        parts = urlsplit(url)
        scheme, host = parts.scheme, parts.hostname or ""
        netloc_host = parts.netloc.rsplit("@", 1)[-1]
        if (
            not scheme
            or not host
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or "?" in url
            or "#" in url
            or scheme != scheme.lower()
            or netloc_host.split(":")[0] != netloc_host.split(":")[0].lower()
            or host.endswith(".")
            or not parts.path.startswith("/")
            or "//" in parts.path
            or any(segment in (".", "..") for segment in parts.path.split("/"))
            or "%" in parts.path
            or not domain
            or len(domain.encode("utf-8")) > 512
        ):
            raise ChannelFailure("malformed", "endpoint")
        try:
            port = parts.port
        except ValueError as error:
            raise ChannelFailure("malformed", "port") from error
        if port is not None and not (1 <= port <= 65535):
            raise ChannelFailure("malformed", "port")
        loopback = host in ("localhost", "127.0.0.1", "::1")
        if not (scheme == "wss" or (allow_insecure_loopback and scheme == "ws" and loopback)):
            raise ChannelFailure("insecureEndpoint")
        if (scheme == "wss" and port == 443) or (scheme == "ws" and port == 80):
            raise ChannelFailure("malformed", "explicit default port")
        origin = f"{scheme}://{netloc_host}"
        if len((origin + parts.path).encode("utf-8")) > 512:
            raise ChannelFailure("malformed", "endpoint too long")
        return cls(origin=origin, route=parts.path, domain=domain)

    def to_json(self) -> dict[str, Any]:
        return {"origin": self.origin, "route": self.route, "domain": self.domain}

    @classmethod
    def from_json(cls, value: Any) -> "Endpoint":
        if not isinstance(value, dict):
            raise ChannelFailure("malformed", "endpoint")
        _exact_keys(value, {"origin", "route", "domain"})
        return cls(origin=value["origin"], route=value["route"], domain=value["domain"])


@dataclass(frozen=True)
class Transcript:
    endpoint: Endpoint
    identity: PublicIdentity
    client_nonce: bytes
    server_nonce: bytes
    session_id: str
    generation: str
    issued_at_ms: int
    channel_expires_at_ms: int
    profile: str = PROFILE
    direction: str = DIRECTION

    def to_json(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "endpoint": self.endpoint.to_json(),
            "identity": self.identity.to_json(),
            "clientNonce": _b64(self.client_nonce),
            "serverNonce": _b64(self.server_nonce),
            "sessionID": self.session_id,
            "generation": self.generation,
            "direction": self.direction,
            "issuedAtMilliseconds": self.issued_at_ms,
            "channelExpiresAtMilliseconds": self.channel_expires_at_ms,
        }

    @classmethod
    def from_json(cls, value: Any) -> "Transcript":
        if not isinstance(value, dict):
            raise ChannelFailure("malformed", "transcript")
        _exact_keys(value, {
            "profile", "endpoint", "identity", "clientNonce", "serverNonce", "sessionID",
            "generation", "direction", "issuedAtMilliseconds", "channelExpiresAtMilliseconds",
        })
        for key in ("issuedAtMilliseconds", "channelExpiresAtMilliseconds"):
            if isinstance(value[key], bool) or not isinstance(value[key], int):
                raise ChannelFailure("malformed", key)
        return cls(
            profile=value["profile"],
            endpoint=Endpoint.from_json(value["endpoint"]),
            identity=PublicIdentity.from_json(value["identity"]),
            client_nonce=_unb64(value["clientNonce"]),
            server_nonce=_unb64(value["serverNonce"]),
            session_id=value["sessionID"],
            generation=value["generation"],
            direction=value["direction"],
            issued_at_ms=value["issuedAtMilliseconds"],
            channel_expires_at_ms=value["channelExpiresAtMilliseconds"],
        )

    @property
    def digest(self) -> str:
        return digest(encode(self.to_json()))


def signing_challenge(transcript: Transcript) -> IdentitySigningChallenge:
    """The challenge Swift's `BridgeChannelAuthentication.signingData` builds."""
    seconds = transcript.issued_at_ms / 1000
    reference = seconds - _REFERENCE_DATE_OFFSET
    return IdentitySigningChallenge(
        identity_uuid=transcript.identity.uuid,
        public_key_fingerprint=transcript.identity.fingerprint,
        domain=transcript.endpoint.domain,
        resource=f"{PROFILE}:{transcript.digest}",
        action=ACTION,
        audience=transcript.endpoint.audience,
        nonce=transcript.server_nonce,
        issued_at=reference + _REFERENCE_DATE_OFFSET,
        expires_at=(reference + CHALLENGE_LIFETIME) + _REFERENCE_DATE_OFFSET,
    )


def signing_data(transcript: Transcript) -> bytes:
    return signing_challenge(transcript).signing_data()


def envelope(name: str, body: Mapping[str, Any]) -> bytes:
    return encode({"&string": encode(body).decode("utf-8"), "cid": 0, "cmd": name})


def open_envelope(data: bytes) -> tuple[str, dict[str, Any]]:
    """Validate an auth BridgeCommand and return (cmd, body)."""
    command = decode(data)
    _exact_keys(command, {"&string", "cid", "cmd"})
    if command["cid"] != 0 or isinstance(command["cid"], bool) or command["cmd"] not in AUTH_COMMANDS:
        raise ChannelFailure("malformed", "auth envelope")
    if not isinstance(command["&string"], str):
        raise ChannelFailure("malformed", "auth payload")
    return command["cmd"], decode(command["&string"].encode("utf-8"))


def hello_body(identity: PublicIdentity, client_nonce: bytes) -> dict[str, Any]:
    return {"profile": PROFILE, "identity": identity.to_json(), "clientNonce": _b64(client_nonce)}


def challenge_body(transcript: Transcript) -> dict[str, Any]:
    return {"transcript": transcript.to_json(), "signingData": _b64(signing_data(transcript))}


def proof_body(session_id: str, generation: str, signature: bytes) -> dict[str, Any]:
    return {"sessionID": session_id, "generation": generation, "signature": _b64(signature)}


def accepted_body(transcript: Transcript) -> dict[str, Any]:
    return {"sessionID": transcript.session_id, "generation": transcript.generation, "transcriptDigest": transcript.digest}


def _ms(now: float) -> int:
    return int(now * 1000 // 1)


# ---------------------------------------------------------------------------
# Server side (inbound bridge)
# ---------------------------------------------------------------------------


@dataclass
class AdmittedChannel:
    """What a host gets after admission: a proven public key, nothing more."""

    identity: PublicIdentity
    endpoint: Endpoint
    session_id: str
    generation: str
    transcript_digest: str
    expires_at: float

    def check(self, now: Optional[float] = None) -> None:
        if (time.time() if now is None else now) >= self.expires_at:
            raise ChannelFailure("expired")

    def check_identity(self, identity: Optional[PublicIdentity], *, required: bool, now: Optional[float] = None) -> None:
        """Every later command must carry the same public key (`session.check`)."""
        self.check(now)
        if identity is None:
            if required:
                raise ChannelFailure("identityMismatch")
            return
        if identity != self.identity:
            raise ChannelFailure("identityMismatch")


class ChannelServer:
    """One connection's admission state: unauthenticated -> challengeIssued ->
    verifying -> authenticated, or closed. Any misstep is terminal."""

    def __init__(
        self,
        endpoint: Endpoint,
        *,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        random_bytes: Callable[[int], bytes] = os.urandom,
        new_uuid: Callable[[], str] = lambda: str(uuidlib.uuid4()).upper(),
        recheck_policy: Optional[Callable[[PublicIdentity], None]] = None,
    ) -> None:
        self.endpoint = endpoint
        self._wall = wall_clock
        self._mono = monotonic
        self._random = random_bytes
        self._uuid = new_uuid
        self._recheck = recheck_policy
        self.generation = new_uuid()
        self._deadline = monotonic() + PRE_AUTH_DEADLINE
        self.state = "unauthenticated"
        self._pending: Optional[tuple[Transcript, bytes]] = None
        self.admitted: Optional[AdmittedChannel] = None

    def _fail(self, code: str, detail: str = "") -> ChannelFailure:
        self.state = "closed"
        self._pending = None
        return ChannelFailure(code, detail)

    def receive(self, data: bytes) -> bytes:
        """Consume one inbound frame before admission; returns the reply frame."""
        if self.state in ("closed", "authenticated"):
            raise self._fail("unexpectedMessage")
        try:
            name, body = open_envelope(data)
        except ChannelFailure:
            self.state = "closed"
            raise
        if self._mono() >= self._deadline:
            raise self._fail("expired")
        if name == "channelAuthHello" and self.state == "unauthenticated":
            return self._on_hello(body)
        if name == "channelAuthProof" and self.state == "challengeIssued":
            return self._on_proof(body)
        raise self._fail("unexpectedMessage", name)

    def _on_hello(self, body: dict[str, Any]) -> bytes:
        try:
            _exact_keys(body, {"profile", "identity", "clientNonce"})
            if body["profile"] != PROFILE:
                raise ChannelFailure("malformed", "profile")
            identity = PublicIdentity.from_json(body["identity"])
            client_nonce = _unb64(body["clientNonce"])
            if len(client_nonce) != 32:
                raise ChannelFailure("malformed", "client nonce")
        except ChannelFailure as failure:
            raise self._fail(failure.code, str(failure)) from failure
        issued = _ms(self._wall())
        transcript = Transcript(
            endpoint=self.endpoint,
            identity=identity,
            client_nonce=client_nonce,
            server_nonce=self._random(32),
            session_id=self._uuid(),
            generation=self.generation,
            issued_at_ms=issued,
            channel_expires_at_ms=issued + int(CHANNEL_LIFETIME * 1000),
        )
        self._pending = (transcript, signing_data(transcript))
        self.state = "challengeIssued"
        return envelope("channelAuthChallenge", challenge_body(transcript))

    def _on_proof(self, body: dict[str, Any]) -> bytes:
        pending, self._pending = self._pending, None  # consume before verifying
        self.state = "verifying"
        if pending is None:
            raise self._fail("unexpectedMessage")
        transcript, data = pending
        try:
            _exact_keys(body, {"sessionID", "generation", "signature"})
            signature = _unb64(body["signature"])
        except ChannelFailure as failure:
            raise self._fail(failure.code, str(failure)) from failure
        now = self._wall()
        if now >= transcript.issued_at_ms / 1000 + CHALLENGE_LIFETIME:
            raise self._fail("expired")
        if body["sessionID"] != transcript.session_id or body["generation"] != self.generation:
            raise self._fail("staleGeneration")
        if len(signature) > 256 or not verify_signature(signature, data, transcript.identity.descriptor):
            raise self._fail("invalidProof")
        if self._recheck is not None:
            try:
                self._recheck(transcript.identity)
            except Exception as error:
                raise self._fail("revoked", str(error)) from error
        if self._mono() >= self._deadline or self._wall() >= transcript.channel_expires_at_ms / 1000:
            raise self._fail("expired")
        self.admitted = AdmittedChannel(
            identity=transcript.identity,
            endpoint=self.endpoint,
            session_id=transcript.session_id,
            generation=self.generation,
            transcript_digest=transcript.digest,
            expires_at=transcript.channel_expires_at_ms / 1000,
        )
        self.state = "authenticated"
        return envelope("channelAuthAccepted", accepted_body(transcript))


# ---------------------------------------------------------------------------
# Client side (outgoing bridge)
# ---------------------------------------------------------------------------


class ChannelClient:
    """One locally initiated connect. Signs exactly one challenge that matches
    the endpoint it chose itself; a peer cannot widen what gets signed."""

    def __init__(
        self,
        identity: PublicIdentity,
        endpoint: Endpoint,
        signer: Callable[[bytes], bytes],
        *,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> None:
        identity.validate()
        self.identity = identity
        self.endpoint = endpoint
        self._sign = signer
        self._wall = wall_clock
        self._mono = monotonic
        self._deadline = monotonic() + PRE_AUTH_DEADLINE
        self.client_nonce = random_bytes(32)
        self.state = "new"
        self._transcript: Optional[Transcript] = None
        self._offered: Optional[bytes] = None
        self.admitted: Optional[AdmittedChannel] = None

    def _fail(self, code: str, detail: str = "") -> ChannelFailure:
        self.state = "closed"
        return ChannelFailure(code, detail)

    def hello(self) -> bytes:
        if self.state != "new":
            raise self._fail("unexpectedMessage")
        self.state = "helloSent"
        return envelope("channelAuthHello", hello_body(self.identity, self.client_nonce))

    def receive(self, data: bytes) -> Optional[bytes]:
        """Synchronous convenience: challenge -> proof (signs inline), accepted -> None."""
        name = self._peek(data)
        if name == "channelAuthChallenge":
            offered = self.begin_challenge(data)
            return self.finish_challenge(self._sign(offered))
        self.accept(data)
        return None

    def _peek(self, data: bytes) -> str:
        try:
            name, _body = open_envelope(data)
        except ChannelFailure:
            self.state = "closed"
            raise
        return name

    def begin_challenge(self, data: bytes) -> bytes:
        """Validate the challenge completely and return the exact bytes to sign.

        For an async vault: `begin_challenge`, await the signature, then
        `finish_challenge`. Only one challenge is ever accepted."""
        try:
            name, body = open_envelope(data)
        except ChannelFailure:
            self.state = "closed"
            raise
        if self._mono() >= self._deadline:
            raise self._fail("expired")
        if name != "channelAuthChallenge" or self.state != "helloSent":
            raise self._fail("unexpectedMessage", name)
        self.state = "signing"  # consumed before signing
        try:
            _exact_keys(body, {"transcript", "signingData"})
            transcript = Transcript.from_json(body["transcript"])
            offered = _unb64(body["signingData"])
        except ChannelFailure as failure:
            raise self._fail(failure.code, str(failure)) from failure
        now_ms = _ms(self._wall())
        t = transcript
        if not (
            t.profile == PROFILE
            and t.direction == DIRECTION
            and t.endpoint == self.endpoint
            and t.identity == self.identity
            and t.client_nonce == self.client_nonce
            and len(t.server_nonce) == 32
            and _is_uuid(t.session_id)
            and _is_uuid(t.generation)
            and 0 < t.issued_at_ms < 9_000_000_000_000_000
            and 0 < t.channel_expires_at_ms < 9_000_000_000_000_000
            and t.issued_at_ms <= now_ms + 5_000
            and t.issued_at_ms > now_ms - 30_000
            and t.channel_expires_at_ms > now_ms
            and t.channel_expires_at_ms - t.issued_at_ms == int(CHANNEL_LIFETIME * 1000)
            and offered == signing_data(t)
        ):
            raise self._fail("invalidProof", "challenge does not match this connect")
        try:
            validate_signing_challenge(offered, self.identity.descriptor, now=now_ms / 1000)
        except VerificationFailure as failure:
            raise self._fail("invalidProof", failure.code) from failure
        self._transcript = t
        self._offered = offered
        return offered

    def finish_challenge(self, signature: bytes) -> bytes:
        t, offered = self._transcript, self._offered
        if self.state != "signing" or t is None or offered is None:
            raise self._fail("unexpectedMessage")
        self._offered = None
        if self._mono() >= self._deadline or not verify_signature(signature, offered, self.identity.descriptor):
            raise self._fail("staleGeneration")
        try:
            validate_signing_challenge(offered, self.identity.descriptor, now=self._wall())
        except VerificationFailure as failure:
            raise self._fail("expired", failure.code) from failure
        self.state = "proofSent"
        return envelope("channelAuthProof", proof_body(t.session_id, t.generation, signature))

    def accept(self, data: bytes) -> None:
        try:
            name, body = open_envelope(data)
        except ChannelFailure:
            self.state = "closed"
            raise
        if self._mono() >= self._deadline:
            raise self._fail("expired")
        if name != "channelAuthAccepted" or self.state != "proofSent":
            raise self._fail("unexpectedMessage", name)
        self._on_accepted(body)

    def _on_accepted(self, body: dict[str, Any]) -> None:
        t = self._transcript
        try:
            _exact_keys(body, {"sessionID", "generation", "transcriptDigest"})
        except ChannelFailure as failure:
            raise self._fail(failure.code) from failure
        if t is None or body["sessionID"] != t.session_id or body["generation"] != t.generation or body["transcriptDigest"] != t.digest:
            raise self._fail("invalidProof", "acknowledgement")
        if self._wall() >= t.channel_expires_at_ms / 1000:
            raise self._fail("expired")
        self.admitted = AdmittedChannel(
            identity=t.identity,
            endpoint=t.endpoint,
            session_id=t.session_id,
            generation=t.generation,
            transcript_digest=t.digest,
            expires_at=t.channel_expires_at_ms / 1000,
        )
        self.state = "authenticated"


def _is_uuid(value: str) -> bool:
    try:
        uuidlib.UUID(value)
    except (ValueError, TypeError, AttributeError):
        return False
    return True


__all__ = [
    "ACTION",
    "AdmittedChannel",
    "ChannelClient",
    "ChannelFailure",
    "ChannelServer",
    "Endpoint",
    "PROFILE",
    "PublicIdentity",
    "Transcript",
    "decode",
    "encode",
    "envelope",
    "open_envelope",
    "signing_challenge",
    "signing_data",
]
