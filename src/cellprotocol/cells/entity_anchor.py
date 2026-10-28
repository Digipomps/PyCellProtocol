from __future__ import annotations

import base64
import time
from typing import Any, Awaitable, Callable, Optional, TypeVar
from uuid import uuid4

from ..general_cell import FlowElement, GeneralCell
from ..identity import proves_identity_control
from ..interop import identity_link as il
from ..interop.models import IdentityPublicKeyDescriptor, WireDecodeError
from ..interop.verify import VerificationFailure
from ..keypath import get_keypath, set_keypath
from ..value import from_json_value

ENTITY_ROOTS = [
    "person",
    "purposes",
    "relations",
    "proofs",
    "signedAgreementEntity",
    "entityRepresentation",
    "agreements",
    "chronicle",
    "bindings",
    "identityLinks",
]

IDENTITY_LINK_ACTIONS = [
    "identityLinks.genesis",
    "identityLinks.approveEnrollment",
    "identityLinks.completeEnrollment",
    "identityLinks.revoke",
]

T = TypeVar("T")


def descriptor_for(identity: Any) -> Optional[IdentityPublicKeyDescriptor]:
    """`IdentityLinkProtocolService.descriptor(for:)` for a Python identity."""
    key = getattr(identity, "publicSecureKey", None)
    if not isinstance(key, str):
        return None
    try:
        raw = base64.b64decode(key, validate=True)
    except ValueError:
        return None
    return IdentityPublicKeyDescriptor(uuid=identity.uuid, public_key=raw, display_name=getattr(identity, "displayName", None))


async def with_identity_signer(identity: Any, build: Callable[[Callable[[bytes], bytes]], T]) -> T:
    """Runs a synchronous builder with an identity whose signing is async.

    The builder runs once to collect what it wants signed and once more with
    the signatures. Ed25519 is deterministic and the payloads do not depend on
    earlier signatures, so both runs build the same thing.
    """
    wanted: list[bytes] = []
    build(lambda payload: wanted.append(payload) or bytes(64))
    signatures = {payload: await identity.sign(payload) for payload in wanted}
    return build(lambda payload: signatures[payload])


class EntityAnchorCell(GeneralCell):
    """The owner's entity, with `identityLinks.*` as in Swift's EntityAnchorCell.

    `identityLinks.genesis` seals the anchor to the owner; `approveEnrollment`
    issues an approval and same-entity credential; `completeEnrollment`
    verifies the full chain (request, approval, credential, presentation) and
    records the link; `revoke` revokes an exact link. Genesis also happens on
    the owner's first `entity.batchPersist`.
    """

    def __init__(
        self,
        owner: Any | None = None,
        name: str = "EntityAnchor",
        uuid: str | None = None,
        clock: Callable[[], float] = time.time,
        new_uuid: Callable[[], str] = lambda: str(uuid4()).upper(),
    ) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self._clock = clock
        self._new_uuid = new_uuid
        self._storage = {root: {} for root in ENTITY_ROOTS}
        self._storage["chronicle"] = []
        for root in ENTITY_ROOTS:
            self.agreement_template.add_grant("rw--", root)
            self._get_handlers[root] = self._get_entity
            self._set_handlers[root] = self._set_entity
        for action in [*IDENTITY_LINK_ACTIONS, "entity.batchPersist"]:
            self._set_handlers[action] = self._set_entity_action

    # -- reads and plain writes ---------------------------------------------

    def _links(self) -> dict[str, Any]:
        return self._storage.setdefault("identityLinks", {})

    def genesis_seal(self) -> Optional[il.EntityGenesisSeal]:
        value = self._links().get("genesis")
        if not isinstance(value, dict):
            return None
        try:
            return il.EntityGenesisSeal.from_wire(value)
        except (WireDecodeError, TypeError, ValueError):
            return None

    async def _get_entity(self, keypath: str, requester: Any | None) -> Any:
        _ = requester
        if keypath in {"identityLinks", "identityLinks.state"}:
            links = self._links()
            return {
                "status": "ready",
                "sealed": self.genesis_seal() is not None,
                "genesis": links.get("genesis"),
                "records": links.get("records", {}),
                "usedApprovalJTIs": links.get("usedApprovalJTIs", {}),
                "summary": "EntityAnchor identityLinks er klar for approveEnrollment, completeEnrollment og revoke.",
            }
        return get_keypath(self._storage, keypath)

    async def _set_entity(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        if il.is_immutable_genesis_keypath(keypath):
            return _link_error(keypath, "genesisKeypathIsImmutable")
        seal = self.genesis_seal()
        if seal is not None and keypath.startswith(il.RECORDS_KEYPATH + ".") and keypath == il.record_keypath(seal.link_id):
            return _link_error(keypath, "genesisKeypathIsImmutable")
        set_keypath(self._storage, keypath, value)
        self._push_entity_event(keypath, value, "entity.identityLinks" if keypath.startswith("identityLinks") else "entity", requester)
        return {"status": "stored", "keypath": keypath}

    async def _set_entity_action(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        if keypath not in IDENTITY_LINK_ACTIONS and keypath != "entity.batchPersist":
            # A keypath below an action, such as identityLinks.genesis.trigger.
            return await self._set_entity(keypath, value, requester)
        payload = from_json_value(value)
        if keypath == "entity.batchPersist":
            return await self._batch_persist(payload, requester)
        try:
            if keypath == "identityLinks.genesis":
                return await self._genesis(payload, requester)
            if keypath == "identityLinks.approveEnrollment":
                return await self._approve(payload, requester)
            if keypath == "identityLinks.completeEnrollment":
                return self._complete(payload, requester)
            if keypath == "identityLinks.revoke":
                return self._revoke(payload, requester)
        except VerificationFailure as failure:
            return _link_error(keypath, failure.code)
        except (WireDecodeError, TypeError, ValueError, KeyError) as error:
            return _link_error(keypath, "bad_payload", str(error))
        return {"status": "error", "message": f"unknown action {keypath}"}

    async def _batch_persist(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        if not isinstance(payload, dict) or not isinstance(payload.get("schema"), str) or not isinstance(payload.get("mutations"), list):
            return {"status": "failed", "error": "invalid entity.batchPersist envelope"}
        owner_proven = await proves_identity_control(requester, self.owner) if self.owner is not None else True
        if self.owner is not None and not owner_proven:
            return {"status": "failed", "error": "requesterMismatch"}
        # Genesis on first need, as in Swift: only a proven owner seals.
        if self.owner is not None and self.genesis_seal() is None:
            await self._perform_genesis(requester, "firstPersist")
        persisted: list[str] = []
        for mutation in payload["mutations"]:
            if not isinstance(mutation, dict) or not isinstance(mutation.get("keypath"), str) or "value" not in mutation:
                return {"status": "failed", "error": "invalid mutation"}
            if il.is_immutable_genesis_keypath(mutation["keypath"]):
                return {"status": "failed", "error": "genesisKeypathIsImmutable"}
            set_keypath(self._storage, mutation["keypath"], mutation["value"])
            persisted.append(mutation["keypath"])
        response = {"status": "persisted", "schema": payload["schema"], "persistedPaths": persisted}
        self._push_entity_event("entity.batchPersist", response, "entity", requester)
        return response

    # -- genesis ------------------------------------------------------------

    async def _genesis(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        trigger = "firstPersist"
        raw = payload.get("trigger") if isinstance(payload, dict) else payload
        if isinstance(raw, str) and raw in il.GENESIS_TRIGGERS:
            trigger = raw
        existing = self.genesis_seal()
        if existing is not None:
            raise il.LinkFailure("alreadySealed", existing.link_id)
        if not await proves_identity_control(requester, self.owner):
            raise il.LinkFailure("initiatorIsNotOwner")
        seal, record = await self._perform_genesis(requester, trigger)
        return {"status": "sealed", "seal": seal.to_wire(), "record": record.to_wire()}

    async def _perform_genesis(self, requester: Any, trigger: str) -> tuple[il.EntityGenesisSeal, il.IdentityLinkRecord]:
        if self.genesis_seal() is not None:
            raise il.LinkFailure("alreadySealed")
        initiator = descriptor_for(requester)
        if initiator is None:
            raise il.LinkFailure("initiatorHasNoSigningKey")
        now = self._clock()
        seal, record = await with_identity_signer(
            requester,
            lambda sign: il.seal_genesis(
                self.uuid, initiator, sign, identity_domain=self.identity_domain or "private", trigger=trigger, now=now
            ),
        )
        seal_wire, record_wire = seal.to_wire(), record.to_wire()
        set_keypath(self._storage, il.SEAL_KEYPATH, seal_wire)
        set_keypath(self._storage, il.record_keypath(record.link_id), record_wire)
        set_keypath(self._storage, f"proofs.identityLinks.{il.safe_record_key(record.link_id)}", {"record": record_wire, "seal": seal_wire})
        self._push_entity_event(il.SEAL_KEYPATH, seal_wire, "entity.identityLinks", requester)
        return seal, record

    # -- enrollment ---------------------------------------------------------

    async def _approve(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        envelope = il.IdentityLinkApprovalEnvelope.from_wire(payload)
        issuer = descriptor_for(requester)
        if issuer is None:
            raise il.LinkFailure("missingRequiredContext", "issuerIdentity")
        now, approval_id, credential_uuid = self._clock(), self._new_uuid(), self._new_uuid()
        package = await with_identity_signer(
            requester,
            lambda sign: il.approve_enrollment(
                envelope, issuer=issuer, signer=sign, now=now, approval_id=approval_id, credential_uuid=credential_uuid
            ),
        )
        package_wire = package.to_wire()
        keypath = f"identityLinks.approvals.{il.safe_record_key(package.approval.approval_id)}"
        set_keypath(self._storage, keypath, package_wire)
        self._push_entity_event(keypath, package_wire, "entity.identityLinks", requester)
        return {"status": "approved", "approvalID": package.approval.approval_id, "approvalPackage": package_wire}

    def _used_approval_jtis(self) -> set[str]:
        used = self._links().get("usedApprovalJTIs", {})
        if not isinstance(used, dict):
            return set()
        return {value if isinstance(value, str) else key for key, value in used.items()}

    def _complete(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        envelope = il.IdentityLinkCompletionEnvelope.from_wire(payload)
        result = il.verify_completion(envelope, now=self._clock(), used_approval_jtis=self._used_approval_jtis())
        record_wire = result.record.to_wire()
        record_key = il.safe_record_key(result.record.link_id)
        record_keypath = f"identityLinks.records.{record_key}"
        proof_keypath = f"proofs.identityLinks.{record_key}"
        set_keypath(self._storage, record_keypath, record_wire)
        set_keypath(
            self._storage,
            proof_keypath,
            {
                "record": record_wire,
                "requestHash": base64.b64encode(result.request_hash).decode("ascii"),
                "approvalJTI": result.approval_jti,
                "credentialID": result.credential_id,
                "presentationID": result.presentation_id,
                "completedAt": result.record.linked_at,
            },
        )
        set_keypath(self._storage, f"identityLinks.usedApprovalJTIs.{il.safe_record_key(result.approval_jti)}", result.approval_jti)
        self._push_entity_event(record_keypath, record_wire, "entity.identityLinks", requester)
        return {
            "status": "completed",
            "record": record_wire,
            "recordKeypath": record_keypath,
            "proofKeypath": proof_keypath,
            "approvalJTI": result.approval_jti,
        }

    def _revoke(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        if isinstance(payload, str):
            link_id = payload
        elif isinstance(payload, dict) and isinstance(payload.get("linkID"), str):
            link_id = payload["linkID"]
        else:
            raise il.LinkFailure("missingRequiredContext", "linkID")
        if il.is_genesis_link(link_id):
            raise il.LinkFailure("cannotRevokeGenesisLink", link_id)
        record_key = il.safe_record_key(link_id)
        record_keypath = f"identityLinks.records.{record_key}"
        stored = get_keypath(self._storage, record_keypath)
        if not isinstance(stored, dict):
            raise il.LinkFailure("recordNotFound", link_id)
        record = il.IdentityLinkRecord.from_wire(stored)
        record = record.replace(status="revoked", revoked_at=il.iso8601(self._clock()))
        record_wire = record.to_wire()
        set_keypath(self._storage, record_keypath, record_wire)
        set_keypath(self._storage, f"proofs.identityLinks.{record_key}.record", record_wire)
        self._push_entity_event(record_keypath, record_wire, "entity.identityLinks", requester)
        return {"status": "revoked", "record": record_wire, "recordKeypath": record_keypath}

    def _push_entity_event(self, keypath: str, value: Any, topic: str, requester: Any | None) -> None:
        self.push_flow_element(
            FlowElement(
                title="Identity link update" if topic == "entity.identityLinks" else "PDS update",
                content={"keypath": keypath, "data": value, "status": "persisted"},
                topic=topic,
                origin=self.uuid,
            )
        )
        _ = requester


def _link_error(keypath: str, code: str, detail: str | None = None) -> dict[str, Any]:
    error = {"status": "error", "keypath": keypath, "code": code, "message": code}
    if detail:
        error["detail"] = detail
    return error
