from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import math
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol
from uuid import uuid4

from .value import JSONValue, from_json_value, to_json_value


class IdentityVaultProtocol(Protocol):
    async def initialize(self) -> "IdentityVaultProtocol": ...

    async def add_identity(self, identity: "Identity", context: str) -> None: ...

    async def identity(self, context: str, make_new_if_not_found: bool = True) -> "Identity | None": ...

    async def identity_for_uuid(self, uuid: str) -> "Identity | None": ...

    async def sign_message_for_identity(self, identity: "Identity", message: bytes) -> bytes: ...

    async def verify_signature(self, signature: bytes, message: bytes, identity: "Identity") -> bool: ...

    async def random_bytes64(self) -> bytes: ...

    async def aquire_key_for_tag(self, tag: str) -> tuple[str, str]: ...


@dataclass
class Identity:
    displayName: str
    uuid: str = field(default_factory=lambda: str(uuid4()))
    publicSecureKey: str | None = None
    publicKeyAgreementSecureKey: str | None = None
    properties: dict[str, JSONValue] = field(default_factory=dict)
    entityAnchorReference: str = "cell:///EntityAnchor"
    identityVault: IdentityVaultProtocol | None = None
    _public_secure_key_wire: dict[str, JSONValue] | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _public_key_agreement_secure_key_wire: dict[str, JSONValue] | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"publicSecureKey", "publicKeyAgreementSecureKey"} and name in self.__dict__:
            current = self.__dict__[name]
            if current is not None and value != current:
                raise AttributeError(f"{name} is immutable once published")
        object.__setattr__(self, name, value)

    @classmethod
    def from_json(cls, payload: dict[str, Any], vault: IdentityVaultProtocol | None = None) -> "Identity":
        public_key, public_key_wire = _decode_public_secure_key(
            payload.get("publicSecureKey") or payload.get("publicKey"),
            expected_use="signature",
            expected_algorithm="EdDSA",
        )
        agreement_key, agreement_key_wire = _decode_public_secure_key(
            payload.get("publicKeyAgreementSecureKey"),
            expected_use="keyAgreement",
            expected_algorithm="X25519",
        )
        identity = cls(
            uuid=str(payload.get("uuid") or uuid4()),
            displayName=str(payload.get("displayName") or payload.get("name") or "Identity"),
            publicSecureKey=public_key,
            publicKeyAgreementSecureKey=agreement_key,
            properties=from_json_value(payload.get("properties", {})),
            identityVault=vault,
        )
        object.__setattr__(identity, "_public_secure_key_wire", public_key_wire)
        object.__setattr__(identity, "_public_key_agreement_secure_key_wire", agreement_key_wire)
        return identity

    def to_json(self) -> dict[str, JSONValue]:
        output: dict[str, JSONValue] = {
            "uuid": self.uuid,
            "displayName": self.displayName,
            "properties": self.properties,
        }
        if self.publicSecureKey is not None:
            output["publicSecureKey"] = self._wire_secure_key(
                self.publicSecureKey,
                metadata_attribute="_public_secure_key_wire",
                use="signature",
                algorithm="EdDSA",
            )
        if self.publicKeyAgreementSecureKey is not None:
            output["publicKeyAgreementSecureKey"] = self._wire_secure_key(
                self.publicKeyAgreementSecureKey,
                metadata_attribute="_public_key_agreement_secure_key_wire",
                use="keyAgreement",
                algorithm="X25519",
            )
        return output

    def _wire_secure_key(
        self,
        compressed_key: str,
        *,
        metadata_attribute: str,
        use: str,
        algorithm: str,
    ) -> dict[str, JSONValue]:
        existing = getattr(self, metadata_attribute)
        if isinstance(existing, dict) and existing.get("compressedKey") == compressed_key:
            return dict(existing)
        generated = _canonical_public_secure_key(
            compressed_key,
            use=use,
            algorithm=algorithm,
        )
        object.__setattr__(self, metadata_attribute, generated)
        return dict(generated)

    async def sign(self, message: bytes) -> bytes:
        if self.identityVault is None:
            raise RuntimeError("Identity has no vault")
        return await self.identityVault.sign_message_for_identity(self, message)

    async def verify(self, signature: bytes, message: bytes) -> bool:
        return verify_identity_signature(signature, message, self)

    async def get(self, keypath: str, requester: "Identity | None" = None, resolver: Any | None = None) -> Any:
        if resolver is None:
            raise RuntimeError("Identity.get requires resolver")
        relative = keypath.removeprefix("identity.")
        return await resolver.get_from_url(f"{self.entityAnchorReference}/{relative}", requester or self)

    async def set(self, keypath: str, value: Any, requester: "Identity | None" = None, resolver: Any | None = None) -> Any:
        if resolver is None:
            raise RuntimeError("Identity.set requires resolver")
        relative = keypath.removeprefix("identity.")
        return await resolver.set_into_url(value, f"{self.entityAnchorReference}/{relative}", requester or self)


class InMemoryIdentityVault:
    def __init__(self) -> None:
        self._contexts: dict[str, str] = {}
        self._identities: dict[str, Identity] = {}
        self._private_signing_keys: dict[str, Any] = {}
        self._tag_keys: dict[str, tuple[str, str]] = {}

    async def initialize(self) -> "InMemoryIdentityVault":
        return self

    async def add_identity(self, identity: Identity, context: str) -> None:
        existing = self._identities.get(identity.uuid)
        if existing is not None and existing is not identity:
            raise PermissionError(
                "An existing identity UUID cannot be rebound to a new object or context without an explicit restore proof"
            )
        private_key = self._private_signing_keys.get(identity.uuid)
        if private_key is None and identity.publicSecureKey is None:
            private_key = _ed25519_private_key_class().generate()
            self._private_signing_keys[identity.uuid] = private_key
        if private_key is not None:
            encoded_public_key = _public_key_bytes(private_key.public_key())
            public_key = base64.b64encode(encoded_public_key).decode("ascii")
            if identity.publicSecureKey is not None and identity.publicSecureKey != public_key:
                raise RuntimeError("Identity signing key does not match its public key")
            identity.publicSecureKey = public_key
        identity.identityVault = self if private_key is not None else None
        self._contexts[context] = identity.uuid
        self._identities[identity.uuid] = identity

    async def identity(self, context: str, make_new_if_not_found: bool = True) -> Identity | None:
        if context in self._contexts:
            return self._identities[self._contexts[context]]
        if not make_new_if_not_found:
            return None
        identity = Identity(displayName=context)
        await self.add_identity(identity, context)
        return identity

    async def identity_for_uuid(self, uuid: str) -> Identity | None:
        return self._identities.get(uuid)

    async def identity_exists_in_vault(self, uuid: str) -> bool:
        return uuid in self._identities

    async def sign_message_for_identity(self, identity: Identity, message: bytes) -> bytes:
        private_key = self._private_signing_keys.get(identity.uuid)
        if private_key is None:
            raise RuntimeError("Identity signing key is unavailable")
        if not same_identity_reference(identity, self._identities.get(identity.uuid)):
            raise RuntimeError("Identity signing key reference mismatch")
        return private_key.sign(message)

    async def verify_signature(self, signature: bytes, message: bytes, identity: Identity) -> bool:
        return verify_identity_signature(signature, message, identity)

    async def random_bytes64(self) -> bytes:
        return os.urandom(64)

    async def aquire_key_for_tag(self, tag: str) -> tuple[str, str]:
        if tag not in self._tag_keys:
            self._tag_keys[tag] = (
                base64.b64encode(os.urandom(32)).decode(),
                base64.b64encode(os.urandom(32)).decode(),
            )
        return self._tag_keys[tag]


class LocalIdentityVault(InMemoryIdentityVault):
    """Encrypted-at-rest local vault compatible with the scaffold env convention.

    The vault uses `cryptography` when available. If the optional dependency is
    missing, initialization fails clearly instead of silently storing plaintext.
    """

    MAGIC = b"PYCVLT1"
    KEY_ENV = "CELL_VAULT_MASTER_KEY_B64"
    KEY_PATH_ENV = "CELL_VAULT_MASTER_KEY_PATH"
    ALLOW_DEV_KEYGEN_ENV = "CELL_VAULT_ALLOW_DEV_KEYGEN"

    def __init__(self, path: str | Path, scope: str = "default") -> None:
        super().__init__()
        self.path = Path(path)
        self.scope = scope
        self._persistence_lock = asyncio.Lock()

    async def initialize(self) -> "LocalIdentityVault":
        if self.path.exists():
            data = self._decrypt(self.path.read_bytes())
            payload = json.loads(data.decode("utf-8"))
            self._tag_keys = {
                str(tag): (str(value[0]), str(value[1]))
                for tag, value in payload.get("tagKeys", {}).items()
                if isinstance(value, list) and len(value) == 2
            }
            for item in payload.get("identities", []):
                identity = Identity.from_json(item)
                private_key_b64 = item.get("privateSigningKey")
                if not isinstance(private_key_b64, str):
                    if item.get("secret") is not None:
                        raise RuntimeError(
                            "Legacy UUID-derived signing keys are unsafe and cannot be restored; re-enrol the identity"
                        )
                    await self.add_identity(identity, item.get("context", identity.displayName))
                    continue
                private_key = _ed25519_private_key_from_bytes(base64.b64decode(private_key_b64))
                self._private_signing_keys[identity.uuid] = private_key
                await self.add_identity(identity, item.get("context", identity.displayName))
        return self

    async def save(self) -> None:
        async with self._persistence_lock:
            identities = []
            for identity in self._identities.values():
                item = {
                    **identity.to_json(),
                    "context": next(
                        (ctx for ctx, uid in self._contexts.items() if uid == identity.uuid),
                        identity.displayName,
                    ),
                }
                private_key = self._private_signing_keys.get(identity.uuid)
                if private_key is not None:
                    item["privateSigningKey"] = base64.b64encode(
                        _private_key_bytes(private_key)
                    ).decode("ascii")
                identities.append(item)
            payload = {
                "identities": identities,
                "tagKeys": {tag: list(value) for tag, value in self._tag_keys.items()},
            }
            encrypted = self._encrypt(json.dumps(payload, sort_keys=True).encode("utf-8"))
            _atomic_secure_write(self.path, encrypted)

    def _master_key(self) -> bytes:
        env = os.environ
        if env.get(self.KEY_ENV):
            key = base64.b64decode(env[self.KEY_ENV])
            if len(key) == 32:
                return key
        key_path = Path(env.get(self.KEY_PATH_ENV, str(self.path.parent / ".secrets" / "vault-master.key")))
        if key_path.exists():
            raw = key_path.read_bytes().strip()
            try:
                decoded = base64.b64decode(raw)
            except Exception:
                decoded = raw
            if len(decoded) == 32:
                return decoded
        allow = env.get(self.ALLOW_DEV_KEYGEN_ENV, "true").lower() in {"1", "true", "yes", "on"}
        if not allow:
            raise RuntimeError("No Cell vault master key configured")
        key = os.urandom(32)
        try:
            _exclusive_secure_create(key_path, base64.b64encode(key))
            return key
        except FileExistsError:
            decoded = base64.b64decode(key_path.read_bytes().strip())
            if len(decoded) == 32:
                return decoded
            raise RuntimeError("Concurrent vault master-key creation produced invalid key material")

    def _fernet(self) -> Any:
        try:
            from cryptography.fernet import Fernet
        except Exception as error:
            raise RuntimeError("LocalIdentityVault requires optional dependency 'cryptography'") from error
        key = base64.urlsafe_b64encode(hashlib.sha256(self._master_key() + self.scope.encode()).digest())
        return Fernet(key)

    def _encrypt(self, plaintext: bytes) -> bytes:
        return self.MAGIC + self._fernet().encrypt(plaintext)

    def _decrypt(self, data: bytes) -> bytes:
        if not data.startswith(self.MAGIC):
            raise RuntimeError("Unsupported vault format")
        return self._fernet().decrypt(data[len(self.MAGIC) :])


class BridgeIdentityVault:
    def __init__(self, bridge: Any, signing_scope_validator: Any | None = None) -> None:
        self.bridge = bridge
        self.signing_scope_validator = signing_scope_validator
        self._used_signing_challenges: set[tuple[str, str]] = set()
        self._signing_lock = asyncio.Lock()

    async def initialize(self) -> "BridgeIdentityVault":
        return self

    async def add_identity(self, identity: Identity, context: str) -> None:
        _ = identity, context
        raise RuntimeError("BridgeIdentityVault is delegated and stateless")

    async def identity(self, context: str, make_new_if_not_found: bool = True) -> Identity | None:
        _ = make_new_if_not_found
        return Identity(displayName="Delegated", uuid=context, identityVault=self)

    async def identity_for_uuid(self, uuid: str) -> Identity | None:
        return Identity(displayName="Delegated", uuid=uuid, identityVault=self)

    async def sign_message_for_identity(self, identity: Identity, message: bytes) -> bytes:
        async with self._signing_lock:
            challenge, replay_key = _validated_signing_challenge(message, identity)
            if self.signing_scope_validator is None:
                raise PermissionError("Delegated signing challenge scope was not explicitly authorized")
            validation_result = self.signing_scope_validator(challenge, identity)
            if inspect.isawaitable(validation_result):
                validation_result = await validation_result
            if validation_result is not True:
                raise PermissionError("Delegated signing challenge scope was not explicitly authorized")
            if replay_key in self._used_signing_challenges:
                raise PermissionError("Delegated signing challenge was already used")
            result = await self.bridge.sign(identity, message)
            if isinstance(result, bytes):
                signature = result
            elif isinstance(result, str):
                signature = base64.b64decode(result)
            else:
                raise RuntimeError("Bridge sign returned unsupported signature")
            if not verify_identity_signature(signature, message, identity):
                raise PermissionError("Delegated signer returned an invalid identity signature")
            self._used_signing_challenges.add(replay_key)
            return signature

    async def verify_signature(self, signature: bytes, message: bytes, identity: Identity) -> bool:
        return verify_identity_signature(signature, message, identity)

    async def random_bytes64(self) -> bytes:
        return os.urandom(64)

    async def aquire_key_for_tag(self, tag: str) -> tuple[str, str]:
        raise RuntimeError("Delegated tag-key acquisition requires an authenticated bridge operation")


def verify_identity_signature(signature: bytes, message: bytes, identity: Identity) -> bool:
    if not isinstance(identity.publicSecureKey, str):
        return False
    try:
        public_key = _ed25519_public_key_from_bytes(base64.b64decode(identity.publicSecureKey, validate=True))
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


async def proves_identity_control(requester: Identity | None, expected: Identity | None) -> bool:
    if not same_identity_reference(requester, expected):
        return False
    if requester is None or requester.identityVault is None:
        return False
    challenge = b"pycellprotocol.identity-control.v1\x00" + os.urandom(32)
    try:
        signature = await requester.sign(challenge)
    except Exception:
        return False
    return verify_identity_signature(signature, challenge, expected)


def same_identity_reference(left: Identity | None, right: Identity | None) -> bool:
    return bool(
        left is not None
        and right is not None
        and left.uuid == right.uuid
        and isinstance(left.publicSecureKey, str)
        and left.publicSecureKey == right.publicSecureKey
    )


def _decode_public_secure_key(
    value: Any,
    *,
    expected_use: str,
    expected_algorithm: str,
) -> tuple[str | None, dict[str, JSONValue] | None]:
    if value is None:
        return None, None
    if isinstance(value, str):
        _validated_public_key_bytes(value)
        return value, None
    if not isinstance(value, Mapping):
        raise ValueError("Identity public key must be a Swift SecureKey object")
    if value.get("privateKey") is not False:
        raise ValueError("Identity public key must not contain private key material")
    if value.get("use") != expected_use or value.get("algorithm") != expected_algorithm:
        raise ValueError("Identity public key role or algorithm is incompatible")
    if value.get("curveType") != "Curve25519" or value.get("size") != 256:
        raise ValueError("Identity public key curve or size is incompatible")
    date = value.get("date")
    if (
        not isinstance(date, (int, float))
        or isinstance(date, bool)
        or not math.isfinite(float(date))
    ):
        raise ValueError("Identity public key date is invalid")
    compressed_key = value.get("compressedKey")
    if not isinstance(compressed_key, str):
        raise ValueError("Identity public key is missing compressedKey")
    _validated_public_key_bytes(compressed_key)
    wire: dict[str, JSONValue] = {
        "algorithm": expected_algorithm,
        "compressedKey": compressed_key,
        "curveType": "Curve25519",
        "date": date,
        "privateKey": False,
        "size": 256,
        "use": expected_use,
    }
    for coordinate in ("x", "y"):
        coordinate_value = value.get(coordinate)
        if coordinate_value is not None:
            if not isinstance(coordinate_value, str):
                raise ValueError("Identity public key coordinates must be base64 strings")
            base64.b64decode(coordinate_value, validate=True)
            wire[coordinate] = coordinate_value
    return compressed_key, wire


def _canonical_public_secure_key(
    compressed_key: str,
    *,
    use: str,
    algorithm: str,
) -> dict[str, JSONValue]:
    _validated_public_key_bytes(compressed_key)
    return {
        "algorithm": algorithm,
        "compressedKey": compressed_key,
        "curveType": "Curve25519",
        # Swift JSONEncoder's default Date strategy is seconds since 2001-01-01.
        "date": time.time() - 978_307_200,
        "privateKey": False,
        "size": 256,
        "use": use,
    }


def _validated_public_key_bytes(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as error:
        raise ValueError("Identity public key is not valid base64") from error
    if len(decoded) != 32:
        raise ValueError("Curve25519 public keys must contain exactly 32 bytes")
    return decoded


def _ed25519_private_key_class() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception as error:
        raise RuntimeError("PyCellProtocol identity signing requires cryptography Ed25519 support") from error
    return Ed25519PrivateKey


def _ed25519_private_key_from_bytes(value: bytes) -> Any:
    return _ed25519_private_key_class().from_private_bytes(value)


def _ed25519_public_key_from_bytes(value: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as error:
        raise RuntimeError("PyCellProtocol identity verification requires cryptography Ed25519 support") from error
    return Ed25519PublicKey.from_public_bytes(value)


def _public_key_bytes(public_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _private_key_bytes(private_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def identity_signing_fingerprint(identity: Identity) -> str | None:
    if not isinstance(identity.publicSecureKey, str) or not identity.publicSecureKey:
        return None
    return f"EdDSA:Curve25519:{identity.publicSecureKey}"


def _validated_signing_challenge(message: bytes, identity: Identity) -> tuple[dict[str, Any], tuple[str, str]]:
    if len(message) > 8 * 1024:
        raise PermissionError("Signing challenge is too large")
    try:
        challenge = json.loads(message.decode("utf-8"))
    except Exception as error:
        raise PermissionError("Signing data is not a valid identity challenge") from error
    if not isinstance(challenge, dict):
        raise PermissionError("Signing challenge must be an object")
    if challenge.get("type") != "org.haven.cellprotocol.identity-signing-challenge":
        raise PermissionError("Signing challenge type is invalid")
    if challenge.get("version") != 1 or challenge.get("purpose") != "identity-origin-proof":
        raise PermissionError("Signing challenge version or purpose is invalid")
    if challenge.get("identityUUID") != identity.uuid:
        raise PermissionError("Signing challenge identity does not match")
    expected_fingerprint = identity_signing_fingerprint(identity)
    if not expected_fingerprint or challenge.get("publicKeyFingerprint") != expected_fingerprint:
        raise PermissionError("Signing challenge public key does not match")
    for key in ("domain", "resource", "action", "audience"):
        value = challenge.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 512:
            raise PermissionError("Signing challenge scope is invalid")
    try:
        nonce = base64.b64decode(challenge.get("nonce", ""), validate=True)
    except Exception as error:
        raise PermissionError("Signing challenge nonce is invalid") from error
    if not 32 <= len(nonce) <= 128:
        raise PermissionError("Signing challenge nonce length is invalid")
    issued_at = challenge.get("issuedAt")
    expires_at = challenge.get("expiresAt")
    if (
        not isinstance(issued_at, (int, float))
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, (int, float))
        or isinstance(expires_at, bool)
        or not math.isfinite(float(issued_at))
        or not math.isfinite(float(expires_at))
    ):
        raise PermissionError("Signing challenge validity is invalid")
    if expires_at < issued_at or expires_at - issued_at > 60:
        raise PermissionError("Signing challenge validity is invalid")
    now = time.time()
    if issued_at > now + 300:
        raise PermissionError("Signing challenge was issued in the future")
    if expires_at < now:
        raise PermissionError("Signing challenge expired")
    replay_key = (identity.uuid, base64.b64encode(nonce).decode("ascii"))
    return challenge, replay_key


def _exclusive_secure_create(path: Path, data: bytes) -> None:
    _ensure_secure_parent(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _atomic_secure_write(path: Path, data: bytes) -> None:
    _ensure_secure_parent(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _ensure_secure_parent(directory: Path) -> None:
    missing: list[Path] = []
    cursor = directory
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for created in reversed(missing):
        _fsync_directory(created.parent)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
