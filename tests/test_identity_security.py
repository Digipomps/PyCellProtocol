import asyncio
import base64
import json
import os
import stat
import time

import cellprotocol.identity as identity_module
import pytest

from cellprotocol.bridge import BridgeBase, BridgeCommand, BridgeEndpoint
from cellprotocol.general_cell import FlowElement, GeneralCell
from cellprotocol.identity import (
    BridgeIdentityVault,
    Identity,
    InMemoryIdentityVault,
    LocalIdentityVault,
    identity_signing_fingerprint,
    verify_identity_signature,
)
from cellprotocol.resolver import CellResolver, CellUsageScope, ResolverError
from cellprotocol.value import KeyValue, SetValueResponse, TypedValue


def run(coro):
    return asyncio.run(coro)


def test_identity_signatures_use_ed25519_and_uuid_is_not_a_secret():
    async def scenario():
        owner_vault = InMemoryIdentityVault()
        owner = await owner_vault.identity("owner")
        assert owner is not None
        assert len(base64.b64decode(owner.publicSecureKey or "")) == 32

        message = b"identity-proof"
        signature = await owner.sign(message)
        assert len(signature) == 64
        assert verify_identity_signature(signature, message, owner)
        assert not verify_identity_signature(signature, message + b"!", owner)

        attacker_vault = InMemoryIdentityVault()
        attacker = Identity(displayName="forged", uuid=owner.uuid)
        await attacker_vault.add_identity(attacker, "forged")
        assert attacker.publicSecureKey != owner.publicSecureKey
        attacker_signature = await attacker.sign(message)
        assert not verify_identity_signature(attacker_signature, message, owner)

        public_clone = Identity.from_json(owner.to_json())
        with pytest.raises(RuntimeError, match="no vault"):
            await public_clone.sign(message)
        assert await public_clone.verify(signature, message)
        assert not await public_clone.verify(signature, message + b"!")

    run(scenario())


def test_existing_private_key_authority_cannot_be_rebound_to_public_clone():
    async def scenario():
        vault = InMemoryIdentityVault()
        owner = await vault.identity("owner")
        assert owner is not None
        clone = Identity.from_json(owner.to_json())

        with pytest.raises(PermissionError, match="cannot be rebound"):
            await vault.add_identity(clone, "attacker-context")

        assert clone.identityVault is None
        assert await vault.identity("attacker-context", make_new_if_not_found=False) is None
        signature = await owner.sign(b"owner-still-controls")
        assert verify_identity_signature(signature, b"owner-still-controls", owner)

        public_owner = Identity.from_json(owner.to_json())
        cell = GeneralCell(owner=public_owner)
        attacker_vault = InMemoryIdentityVault()
        await attacker_vault.add_identity(public_owner, "public-reference")
        assert public_owner.identityVault is None
        with pytest.raises(AttributeError, match="immutable once published"):
            public_owner.publicSecureKey = None
        await attacker_vault.add_identity(public_owner, "public-reference")
        with pytest.raises(PermissionError, match="did not prove"):
            await cell.set("private.value", "mutated", public_owner)

    run(scenario())


def test_local_vault_round_trip_preserves_private_key_and_rejects_legacy_secret(tmp_path, monkeypatch):
    async def scenario():
        master_key = base64.b64encode(b"m" * 32).decode("ascii")
        monkeypatch.setenv(LocalIdentityVault.KEY_ENV, master_key)
        path = tmp_path / "identity-vault.bin"

        first = await LocalIdentityVault(path).initialize()
        owner = await first.identity("owner")
        assert owner is not None
        before = await owner.sign(b"round-trip")
        tag_keys = await first.aquire_key_for_tag("content")
        await first.save()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

        second = await LocalIdentityVault(path).initialize()
        restored = await second.identity("owner", make_new_if_not_found=False)
        assert restored is not None
        assert restored.publicSecureKey == owner.publicSecureKey
        assert verify_identity_signature(before, b"round-trip", restored)
        assert verify_identity_signature(await restored.sign(b"after"), b"after", restored)
        assert await second.aquire_key_for_tag("content") == tag_keys

        legacy_path = tmp_path / "legacy-vault.bin"
        legacy = LocalIdentityVault(legacy_path)
        legacy_payload = {
            "identities": [
                {
                    **owner.to_json(),
                    "context": "owner",
                    "secret": base64.b64encode(b"unsafe-uuid-derived-material").decode("ascii"),
                }
            ]
        }
        legacy_path.write_bytes(legacy._encrypt(json.dumps(legacy_payload).encode("utf-8")))
        with pytest.raises(RuntimeError, match="unsafe and cannot be restored"):
            await legacy.initialize()

        await asyncio.gather(*(second.save() for _ in range(20)))
        third = await LocalIdentityVault(path).initialize()
        assert await third.identity("owner", make_new_if_not_found=False) is not None

        encrypted = path.read_bytes()
        tampered_path = tmp_path / "tampered-vault.bin"
        tampered_path.write_bytes(encrypted[:-1] + bytes([encrypted[-1] ^ 0x01]))
        with pytest.raises(Exception):
            await LocalIdentityVault(tampered_path).initialize()

        monkeypatch.setenv(LocalIdentityVault.KEY_ENV, base64.b64encode(b"w" * 32).decode("ascii"))
        with pytest.raises(Exception):
            await LocalIdentityVault(path).initialize()

    run(scenario())


def test_owned_cell_requires_fresh_private_key_proof_and_agreement_admission_fails_closed():
    async def scenario():
        owner_vault = InMemoryIdentityVault()
        owner = await owner_vault.identity("owner")
        assert owner is not None
        cell = GeneralCell(owner=owner)
        await cell.set("private.value", "healthy", owner)

        outsider = await InMemoryIdentityVault().identity("outsider")
        with pytest.raises(PermissionError, match="did not prove"):
            await cell.get("private.value", outsider)
        with pytest.raises(PermissionError, match="did not prove"):
            await cell.set("private.value", "mutated", outsider)

        wrong_key_vault = InMemoryIdentityVault()
        wrong_key = Identity(displayName="wrong-key", uuid=owner.uuid)
        await wrong_key_vault.add_identity(wrong_key, "wrong-key")
        with pytest.raises(PermissionError, match="did not prove"):
            await cell.get("private.value", wrong_key)

        public_clone = Identity.from_json(owner.to_json())
        with pytest.raises(PermissionError, match="did not prove"):
            await cell.get("private.value", public_clone)

        assert await cell.get("private.value", owner) == "healthy"
        with pytest.raises(PermissionError, match="owner-approved signatures"):
            await cell.add_agreement({"state": "signed"}, outsider)

    run(scenario())


def test_bridge_never_upgrades_self_asserted_identity_or_signs_arbitrary_bytes():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        assert owner is not None
        cell = GeneralCell(owner=owner)
        await cell.set("private.value", "healthy", owner)
        endpoint = BridgeEndpoint(cell, owner=owner)
        asserted_owner = Identity.from_json(owner.to_json())

        get_response = await endpoint.handle(
            BridgeCommand("get", TypedValue("string", "private.value"), 1, asserted_owner)
        )
        denied = get_response[0].payload.value
        assert isinstance(denied, SetValueResponse)
        assert denied.state == "error"
        assert "did not prove" in str(denied.value)

        set_response = await endpoint.handle(
            BridgeCommand(
                "set",
                TypedValue("keyValue", KeyValue("private.value", "mutated")),
                2,
                asserted_owner,
            )
        )
        assert set_response[0].payload.value.state == "error"
        assert await cell.get("private.value", owner) == "healthy"

        sign_response = await endpoint.handle(
            BridgeCommand("sign", TypedValue("signData", b"attacker-chosen"), 3, asserted_owner)
        )
        assert sign_response[0].payload.value.state == "error"
        assert "validated purpose" in str(sign_response[0].payload.value.value)

        agreement_response = await endpoint.handle(
            BridgeCommand("agreement", TypedValue("object", {"state": "signed"}), 4, asserted_owner)
        )
        assert agreement_response[0].payload.value.state == "error"
        assert "owner-approved signatures" in str(agreement_response[0].payload.value.value)

    run(scenario())


def test_delegated_signing_requires_current_exact_scoped_challenge_and_rejects_replay():
    class SigningBridge:
        def __init__(self, signer):
            self.signer = signer
            self.messages = []

        async def sign(self, identity, message):
            self.messages.append((identity, message))
            return await self.signer.sign(message)

    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        assert owner is not None
        bridge = SigningBridge(owner)

        def allows_expected_scope(challenge, identity):
            return (
                identity.uuid == owner.uuid
                and challenge["domain"] == "private"
                and challenge["resource"] == "cell:///Vault"
                and challenge["action"] == "identity.sign"
                and challenge["audience"] == "pycellprotocol.security.test"
            )

        vault = BridgeIdentityVault(bridge, signing_scope_validator=allows_expected_scope)
        delegated = Identity.from_json(owner.to_json(), vault=vault)

        def challenge(*, nonce=None, issued_offset=0, expires_offset=60, domain="private"):
            now = time.time()
            return json.dumps(
                {
                    "action": "identity.sign",
                    "audience": "pycellprotocol.security.test",
                    "domain": domain,
                    "expiresAt": now + expires_offset,
                    "identityUUID": owner.uuid,
                    "issuedAt": now + issued_offset,
                    "nonce": base64.b64encode(nonce or os.urandom(64)).decode("ascii"),
                    "publicKeyFingerprint": identity_signing_fingerprint(owner),
                    "purpose": "identity-origin-proof",
                    "resource": "cell:///Vault",
                    "type": "org.haven.cellprotocol.identity-signing-challenge",
                    "version": 1,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")

        valid = challenge()
        signature = await delegated.sign(valid)
        assert verify_identity_signature(signature, valid, owner)
        assert len(bridge.messages) == 1

        with pytest.raises(PermissionError, match="already used"):
            await delegated.sign(valid)
        with pytest.raises(PermissionError, match="not a valid identity challenge"):
            await delegated.sign(b"attacker-chosen-arbitrary-bytes")
        with pytest.raises(PermissionError, match="not explicitly authorized"):
            await delegated.sign(challenge(domain="wrong"))
        with pytest.raises(PermissionError, match="expired"):
            await delegated.sign(challenge(issued_offset=-61, expires_offset=-1))
        non_finite = json.loads(challenge().decode("utf-8"))
        non_finite["issuedAt"] = float("nan")
        non_finite["expiresAt"] = float("nan")
        with pytest.raises(PermissionError, match="validity is invalid"):
            await delegated.sign(json.dumps(non_finite).encode("utf-8"))
        assert len(bridge.messages) == 1

        no_policy = Identity.from_json(
            owner.to_json(), vault=BridgeIdentityVault(bridge)
        )
        with pytest.raises(PermissionError, match="not explicitly authorized"):
            await no_policy.sign(challenge())
        assert len(bridge.messages) == 1

        async def deny_async(challenge, identity):
            _ = challenge, identity
            return False

        async_denied = Identity.from_json(
            owner.to_json(),
            vault=BridgeIdentityVault(bridge, signing_scope_validator=deny_async),
        )
        with pytest.raises(PermissionError, match="not explicitly authorized"):
            await async_denied.sign(challenge())
        assert len(bridge.messages) == 1

        class ForgingBridge:
            async def sign(self, identity, message):
                _ = identity, message
                return b"x" * 64

        forged = Identity.from_json(
            owner.to_json(),
            vault=BridgeIdentityVault(
                ForgingBridge(),
                signing_scope_validator=lambda challenge, identity: True,
            ),
        )
        with pytest.raises(PermissionError, match="invalid identity signature"):
            await forged.sign(challenge())

    run(scenario())


def test_concurrent_scoped_resolution_creates_exactly_one_instance():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        assert owner is not None
        resolver = CellResolver()
        counts = {"shared": 0, "personal": 0}

        async def shared_factory(requester=None):
            counts["shared"] += 1
            await asyncio.sleep(0.01)
            return GeneralCell(owner=requester)

        async def personal_factory(requester=None):
            counts["personal"] += 1
            await asyncio.sleep(0.01)
            return GeneralCell(owner=requester)

        await resolver.register_named_emit_cell(
            "Shared", factory=shared_factory, scope=CellUsageScope.scaffoldUnique
        )
        await resolver.register_named_emit_cell(
            "Personal", factory=personal_factory, scope=CellUsageScope.identityUnique
        )

        shared = await asyncio.gather(
            *(resolver.cell_at_endpoint("cell:///Shared", owner) for _ in range(40))
        )
        personal = await asyncio.gather(
            *(resolver.cell_at_endpoint("cell:///Personal", owner) for _ in range(40))
        )
        assert len({id(value) for value in shared}) == 1
        assert len({id(value) for value in personal}) == 1
        assert counts == {"shared": 1, "personal": 1}

    run(scenario())


def test_wrong_key_identity_cannot_reuse_owner_scoped_cell_or_remote_bridge():
    async def scenario():
        owner_vault = InMemoryIdentityVault()
        owner = await owner_vault.identity("owner")
        assert owner is not None
        wrong_key_vault = InMemoryIdentityVault()
        wrong_key = Identity(displayName="wrong-key", uuid=owner.uuid)
        await wrong_key_vault.add_identity(wrong_key, "wrong-key")

        resolver = CellResolver(allows_insecure_websockets=True)
        await resolver.register_named_emit_cell(
            "Personal",
            factory=lambda requester=None: GeneralCell(owner=requester),
            scope=CellUsageScope.identityUnique,
        )
        owner_cell = await resolver.cell_at_endpoint("cell:///Personal", owner)
        wrong_key_cell = await resolver.cell_at_endpoint("cell:///Personal", wrong_key)
        assert owner_cell is not wrong_key_cell
        assert owner_cell.owner is owner
        assert wrong_key_cell.owner is wrong_key

        owner_bridge = resolver._remote_bridge("ws://example.test/bridge", owner)
        wrong_key_bridge = resolver._remote_bridge("ws://example.test/bridge", wrong_key)
        assert owner_bridge is not wrong_key_bridge
        assert owner_bridge.identity is owner
        assert wrong_key_bridge.identity is wrong_key

    run(scenario())


def test_keyless_identity_is_rejected_from_identity_scoped_caches():
    async def scenario():
        resolver = CellResolver(allows_insecure_websockets=True)
        await resolver.register_named_emit_cell(
            "Personal",
            factory=lambda requester=None: GeneralCell(owner=requester),
            scope=CellUsageScope.identityUnique,
        )
        first = Identity(displayName="first", uuid="same-keyless-uuid")
        second = Identity(displayName="second", uuid="same-keyless-uuid")

        for identity in (first, second):
            with pytest.raises(ResolverError, match="public signing key"):
                await resolver.cell_at_endpoint("cell:///Personal", identity)
            with pytest.raises(ResolverError, match="public signing key"):
                resolver._remote_bridge("ws://example.test/bridge", identity)

    run(scenario())


def test_cell_mutations_are_serialized_and_flow_order_matches_commits():
    async def scenario():
        cell = GeneralCell()
        cell._storage["counter"] = 0

        async def increment(keypath, value, requester):
            _ = keypath, value, requester
            current = await cell.get("counter")
            await asyncio.sleep(0.001)
            next_value = current + 1
            cell._storage["counter"] = next_value
            cell.push_flow_element(
                FlowElement(
                    title="increment",
                    content={"counter": next_value},
                    topic="counter.increment",
                    origin=cell.uuid,
                )
            )
            return next_value

        cell._set_handlers["counter.increment"] = increment
        results = await asyncio.gather(
            *(cell.set("counter.increment", None) for _ in range(40))
        )
        assert sorted(results) == list(range(1, 41))
        assert await cell.get("counter") == 40
        events = [cell._flow_queue.get_nowait().content["counter"] for _ in range(40)]
        assert events == list(range(1, 41))

    run(scenario())


def test_membership_checks_subject_separately_from_authorized_requester():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        outsider = await InMemoryIdentityVault().identity("outsider")
        assert owner is not None and outsider is not None
        cell = GeneralCell(owner=owner)

        assert await cell.is_member(owner, owner)
        assert not await cell.is_member(outsider, owner)
        assert not await cell.is_member(outsider)
        with pytest.raises(PermissionError, match="did not prove"):
            await cell.is_member(owner, outsider)

    run(scenario())


def test_public_description_uses_redacted_owner_reference():
    async def scenario():
        owner = await InMemoryIdentityVault().identity("owner")
        assert owner is not None
        owner.properties = {
            "private.token": "do-not-publish",
            "homeVaultReference": "vault://private",
        }
        cell = GeneralCell(owner=owner, name="Private")
        description = await cell.advertise()
        exposed_owner = description["contractTemplate"]["owner"]
        assert exposed_owner["uuid"] == owner.uuid
        assert exposed_owner["publicSecureKey"]["compressedKey"] == owner.publicSecureKey
        assert exposed_owner["publicSecureKey"]["algorithm"] == "EdDSA"
        assert exposed_owner["publicSecureKey"]["curveType"] == "Curve25519"
        assert "properties" not in exposed_owner
        assert "private.token" not in json.dumps(description)
        assert "vault://private" not in json.dumps(description)

    run(scenario())


def test_ownerless_public_description_never_promotes_wire_requester_to_owner():
    async def scenario():
        attacker = await InMemoryIdentityVault().identity("attacker")
        assert attacker is not None
        description = await GeneralCell().advertise(attacker)
        contract = description["contractTemplate"]
        assert contract["owner"]["uuid"] == "00000000-0000-0000-0000-000000000000"
        assert contract["owner"]["uuid"] != attacker.uuid
        assert all(signatory["uuid"] != attacker.uuid for signatory in contract["signatories"])

    run(scenario())


def test_public_description_is_deterministic_for_repeated_and_recreated_cell_identity():
    async def scenario():
        cell_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        first_cell = GeneralCell(uuid=cell_uuid, name="Deterministic")
        first = await first_cell.advertise()
        second = await first_cell.advertise()
        recreated = await GeneralCell(uuid=cell_uuid, name="Deterministic").advertise()

        assert first == second
        assert first["contractTemplate"]["uuid"] == recreated["contractTemplate"]["uuid"]

    run(scenario())


def test_concurrent_bridge_signing_never_contaminates_default_request_identity():
    async def scenario():
        default = Identity(displayName="default", uuid="default")
        first_signer = Identity(displayName="one", uuid="one")
        second_signer = Identity(displayName="two", uuid="two")
        both_signs_entered = asyncio.Event()
        release_signs = asyncio.Event()
        observed = []

        async def send(command):
            observed.append((command.cmd, command.identity.uuid if command.identity else None))
            if command.cmd == "sign":
                if sum(1 for cmd, _ in observed if cmd == "sign") == 2:
                    both_signs_entered.set()
                await release_signs.wait()
                return BridgeCommand(
                    "response",
                    TypedValue("signature", b"signature"),
                    command.cid,
                )
            return BridgeCommand("response", TypedValue("string", "ok"), command.cid)

        bridge = BridgeBase(send_command=send, identity=default)
        first_task = asyncio.create_task(bridge.sign(first_signer, b"first"))
        await asyncio.sleep(0)
        second_task = asyncio.create_task(bridge.sign(second_signer, b"second"))
        await asyncio.wait_for(both_signs_entered.wait(), timeout=1)

        assert await bridge.get("public.value") == "ok"
        release_signs.set()
        await asyncio.gather(first_task, second_task)

        assert ("sign", "one") in observed
        assert ("sign", "two") in observed
        assert ("get", "default") in observed
        assert bridge.identity is default

    run(scenario())


def test_exclusive_master_key_creation_fsyncs_new_directory_and_key_entry(tmp_path, monkeypatch):
    key_path = tmp_path / "secrets" / "vault-master.key"
    fsynced = []
    monkeypatch.setattr(identity_module, "_fsync_directory", fsynced.append)

    identity_module._exclusive_secure_create(key_path, b"master-key")

    assert key_path.read_bytes() == b"master-key"
    assert fsynced == [tmp_path, key_path.parent]
