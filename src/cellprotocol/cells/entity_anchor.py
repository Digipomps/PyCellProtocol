from __future__ import annotations

import re
from typing import Any
from uuid import uuid4

from ..general_cell import FlowElement, GeneralCell
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


class EntityAnchorCell(GeneralCell):
    def __init__(self, owner: Any | None = None, name: str = "EntityAnchor", uuid: str | None = None) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self._storage = {root: {} for root in ENTITY_ROOTS}
        self._storage["chronicle"] = []
        for root in ENTITY_ROOTS:
            self.agreement_template.add_grant("rw--", root)
            self._get_handlers[root] = self._get_entity
            self._set_handlers[root] = self._set_entity
        for action in [
            "identityLinks.approveEnrollment",
            "identityLinks.completeEnrollment",
            "identityLinks.revoke",
            "entity.batchPersist",
        ]:
            self._set_handlers[action] = self._set_entity_action

    async def _get_entity(self, keypath: str, requester: Any | None) -> Any:
        _ = requester
        if keypath in {"identityLinks", "identityLinks.state"}:
            return {
                "status": "ready",
                "records": get_keypath(self._storage, "identityLinks.records") if "records" in self._storage["identityLinks"] else {},
                "usedApprovalJTIs": get_keypath(self._storage, "identityLinks.usedApprovalJTIs") if "usedApprovalJTIs" in self._storage["identityLinks"] else {},
                "summary": "EntityAnchor identityLinks er klar for approveEnrollment, completeEnrollment og revoke.",
            }
        return get_keypath(self._storage, keypath)

    async def _set_entity(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        set_keypath(self._storage, keypath, value)
        self._push_entity_event(keypath, value, "entity", requester)
        return {"status": "stored", "keypath": keypath}

    async def _set_entity_action(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        payload = from_json_value(value)
        if keypath == "entity.batchPersist":
            return await self._batch_persist(payload, requester)
        if keypath == "identityLinks.approveEnrollment":
            return self._approve(payload, requester)
        if keypath == "identityLinks.completeEnrollment":
            return self._complete(payload, requester)
        if keypath == "identityLinks.revoke":
            return self._revoke(payload, requester)
        return {"status": "error", "message": f"unknown action {keypath}"}

    async def _batch_persist(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        if not isinstance(payload, dict) or not isinstance(payload.get("schema"), str) or not isinstance(payload.get("mutations"), list):
            return {"status": "failed", "error": "invalid entity.batchPersist envelope"}
        persisted: list[str] = []
        for mutation in payload["mutations"]:
            if not isinstance(mutation, dict) or not isinstance(mutation.get("keypath"), str) or "value" not in mutation:
                return {"status": "failed", "error": "invalid mutation"}
            set_keypath(self._storage, mutation["keypath"], mutation["value"])
            persisted.append(mutation["keypath"])
        response = {"status": "persisted", "schema": payload["schema"], "persistedPaths": persisted}
        self._push_entity_event("entity.batchPersist", response, "entity", requester)
        return response

    def _approve(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        obj = payload if isinstance(payload, dict) else {}
        approval_id = str(obj.get("approvalID") or obj.get("approvalId") or uuid4())
        approval_package = {
            "approvalID": approval_id,
            "issuerIdentityUUID": getattr(requester, "uuid", None),
            "status": "approved",
            "request": obj,
        }
        key = _safe_key(approval_id)
        keypath = f"identityLinks.approvals.{key}"
        set_keypath(self._storage, keypath, approval_package)
        self._push_entity_event(keypath, approval_package, "entity.identityLinks", requester)
        return {"status": "approved", "approvalID": approval_id, "approvalPackage": approval_package}

    def _complete(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        obj = payload if isinstance(payload, dict) else {}
        link_id = str(obj.get("linkID") or obj.get("linkId") or uuid4())
        approval_jti = str(obj.get("approvalJTI") or obj.get("approvalJti") or obj.get("jti") or uuid4())
        jti_key = _safe_key(approval_jti)
        used = self._storage.setdefault("identityLinks", {}).setdefault("usedApprovalJTIs", {})
        if jti_key in used:
            return {"status": "error", "message": "approval JTI already used"}
        record = {
            "linkID": link_id,
            "entityBinding": obj.get("entityBinding", {}),
            "linkedIdentity": obj.get("linkedIdentity", {}),
            "approvedDomains": obj.get("approvedDomains", []),
            "approvedIdentityContexts": obj.get("approvedIdentityContexts", []),
            "approvedScopes": obj.get("approvedScopes", []),
            "issuerIdentityUUID": getattr(requester, "uuid", None),
            "issuerType": obj.get("issuerType", "entity-anchor"),
            "status": "active",
            "linkedAt": obj.get("linkedAt") or "",
            "lastUsedAt": None,
            "revokedAt": None,
        }
        record_key = _safe_key(link_id)
        record_keypath = f"identityLinks.records.{record_key}"
        proof_keypath = f"proofs.identityLinks.{record_key}"
        set_keypath(self._storage, record_keypath, record)
        set_keypath(self._storage, proof_keypath, {"record": record, "approvalJTI": approval_jti})
        set_keypath(self._storage, f"identityLinks.usedApprovalJTIs.{jti_key}", approval_jti)
        self._push_entity_event(record_keypath, record, "entity.identityLinks", requester)
        return {
            "status": "completed",
            "record": record,
            "recordKeypath": record_keypath,
            "proofKeypath": proof_keypath,
            "approvalJTI": approval_jti,
        }

    def _revoke(self, payload: Any, requester: Any | None) -> dict[str, Any]:
        if isinstance(payload, str):
            link_id = payload
        elif isinstance(payload, dict) and isinstance(payload.get("linkID"), str):
            link_id = payload["linkID"]
        else:
            return {"status": "error", "message": "linkID is required"}
        record_key = _safe_key(link_id)
        record_keypath = f"identityLinks.records.{record_key}"
        record = get_keypath(self._storage, record_keypath)
        if not isinstance(record, dict):
            return {"status": "error", "message": "identity link record not found"}
        record["status"] = "revoked"
        record["revokedAt"] = ""
        set_keypath(self._storage, record_keypath, record)
        set_keypath(self._storage, f"proofs.identityLinks.{record_key}.record", record)
        self._push_entity_event(record_keypath, record, "entity.identityLinks", requester)
        return {"status": "revoked", "record": record, "recordKeypath": record_keypath}

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


def _safe_key(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", value)
