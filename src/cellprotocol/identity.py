from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
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

    @classmethod
    def from_json(cls, payload: dict[str, Any], vault: IdentityVaultProtocol | None = None) -> "Identity":
        return cls(
            uuid=str(payload.get("uuid") or uuid4()),
            displayName=str(payload.get("displayName") or payload.get("name") or "Identity"),
            publicSecureKey=payload.get("publicSecureKey") or payload.get("publicKey"),
            publicKeyAgreementSecureKey=payload.get("publicKeyAgreementSecureKey"),
            properties=from_json_value(payload.get("properties", {})),
            identityVault=vault,
        )

    def to_json(self) -> dict[str, JSONValue]:
        output: dict[str, JSONValue] = {
            "uuid": self.uuid,
            "displayName": self.displayName,
            "properties": self.properties,
        }
        if self.publicSecureKey is not None:
            output["publicSecureKey"] = self.publicSecureKey
            output["publicKey"] = self.publicSecureKey
        if self.publicKeyAgreementSecureKey is not None:
            output["publicKeyAgreementSecureKey"] = self.publicKeyAgreementSecureKey
        return output

    async def sign(self, message: bytes) -> bytes:
        if self.identityVault is None:
            raise RuntimeError("Identity has no vault")
        return await self.identityVault.sign_message_for_identity(self, message)

    async def verify(self, signature: bytes, message: bytes) -> bool:
        if self.identityVault is None:
            return False
        return await self.identityVault.verify_signature(signature, message, self)

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
        self._secrets: dict[str, bytes] = {}

    async def initialize(self) -> "InMemoryIdentityVault":
        return self

    async def add_identity(self, identity: Identity, context: str) -> None:
        identity.identityVault = self
        self._contexts[context] = identity.uuid
        self._identities[identity.uuid] = identity
        self._secrets.setdefault(identity.uuid, hashlib.sha256(identity.uuid.encode()).digest())
        identity.publicSecureKey = base64.b64encode(self._secrets[identity.uuid]).decode("ascii")

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
        secret = self._secrets.get(identity.uuid)
        if secret is None:
            raise RuntimeError("Unknown identity")
        return hmac.new(secret, message, hashlib.sha256).digest()

    async def verify_signature(self, signature: bytes, message: bytes, identity: Identity) -> bool:
        secret = self._secrets.get(identity.uuid)
        if secret is None:
            return False
        expected = hmac.new(secret, message, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected)

    async def random_bytes64(self) -> bytes:
        return os.urandom(64)

    async def aquire_key_for_tag(self, tag: str) -> tuple[str, str]:
        digest = hashlib.sha256(tag.encode()).digest()
        return base64.b64encode(digest[:16]).decode(), base64.b64encode(digest[16:32]).decode()


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

    async def initialize(self) -> "LocalIdentityVault":
        if self.path.exists():
            data = self._decrypt(self.path.read_bytes())
            payload = json.loads(data.decode("utf-8"))
            for item in payload.get("identities", []):
                identity = Identity.from_json(item)
                await self.add_identity(identity, item.get("context", identity.displayName))
                secret_b64 = item.get("secret")
                if secret_b64:
                    self._secrets[identity.uuid] = base64.b64decode(secret_b64)
        return self

    async def save(self) -> None:
        payload = {
            "identities": [
                {
                    **identity.to_json(),
                    "context": next((ctx for ctx, uid in self._contexts.items() if uid == identity.uuid), identity.displayName),
                    "secret": base64.b64encode(self._secrets[identity.uuid]).decode("ascii"),
                }
                for identity in self._identities.values()
            ]
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(self._encrypt(json.dumps(payload, sort_keys=True).encode("utf-8")))
        os.chmod(self.path, 0o600)

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
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(base64.b64encode(key))
        os.chmod(key_path, 0o600)
        return key

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
    def __init__(self, bridge: Any) -> None:
        self.bridge = bridge

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
        result = await self.bridge.sign(identity, message)
        if isinstance(result, bytes):
            return result
        if isinstance(result, str):
            return base64.b64decode(result)
        raise RuntimeError("Bridge sign returned unsupported signature")

    async def verify_signature(self, signature: bytes, message: bytes, identity: Identity) -> bool:
        local = InMemoryIdentityVault()
        await local.add_identity(identity, identity.uuid)
        return await local.verify_signature(signature, message, identity)

    async def random_bytes64(self) -> bytes:
        return os.urandom(64)

    async def aquire_key_for_tag(self, tag: str) -> tuple[str, str]:
        digest = hashlib.sha256(tag.encode()).digest()
        return base64.b64encode(digest[:16]).decode(), base64.b64encode(digest[16:32]).decode()
