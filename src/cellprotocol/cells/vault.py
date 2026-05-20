from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from ..general_cell import FlowElement, GeneralCell
from ..value import from_json_value


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class VaultNoteRecord:
    id: str
    title: str
    content: str
    slug: str | None = None
    tags: list[str] = field(default_factory=list)
    createdAtEpochMs: int = field(default_factory=_now_ms)
    updatedAtEpochMs: int = field(default_factory=_now_ms)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "slug": self.slug,
            "title": self.title,
            "content": self.content,
            "tags": self.tags,
            "createdAtEpochMs": self.createdAtEpochMs,
            "updatedAtEpochMs": self.updatedAtEpochMs,
        }


class VaultCell(GeneralCell):
    schema_version = "haven.vault.state.v1"
    mutation_schema_version = "haven.vault.mutation.v1"

    def __init__(self, owner: Any | None = None, name: str = "Vault", uuid: str | None = None) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self.notes: dict[str, VaultNoteRecord] = {}
        self.links: list[dict[str, Any]] = []
        self.operations: list[dict[str, Any]] = []
        self.state_version = 0
        self.agreement_template.add_grant("rw--", "vault")
        self._get_handlers["vault.state"] = self._get_state
        for key in [
            "vault.note.create",
            "vault.note.update",
            "vault.note.get",
            "vault.note.list",
            "vault.link.add",
            "vault.links.forward",
            "vault.links.backlinks",
        ]:
            self._set_handlers[key] = self._set_vault

    async def _get_state(self, keypath: str, requester: Any | None) -> dict[str, Any]:
        _ = keypath, requester
        return self._state_payload()

    async def _set_vault(self, keypath: str, value: Any, requester: Any | None) -> dict[str, Any]:
        payload = from_json_value(value)
        if not isinstance(payload, dict):
            return self._error(keypath, "invalid_payload", "Vault payload must be an object")
        if keypath == "vault.note.create":
            return self._create_note(payload, requester)
        if keypath == "vault.note.update":
            return self._update_note(payload, requester)
        if keypath == "vault.note.get":
            return self._get_note(payload)
        if keypath == "vault.note.list":
            return self._list_notes(payload)
        if keypath == "vault.link.add":
            return self._add_link(payload, requester)
        if keypath == "vault.links.forward":
            return self._links(payload, "fromNoteID", "toNoteID")
        if keypath == "vault.links.backlinks":
            return self._links(payload, "toNoteID", "fromNoteID")
        return self._error(keypath, "unknown_operation", keypath)

    def _create_note(self, payload: dict[str, Any], requester: Any | None) -> dict[str, Any]:
        title = _string(payload.get("title"))
        content = _string(payload.get("content"))
        if not title or content is None:
            return self._error("vault.note.create", "field_errors", "title and content are required", {"title": "required", "content": "required"})
        note_id = _string(payload.get("id")) or _string(payload.get("slug")) or str(uuid4())
        now = _now_ms()
        note = VaultNoteRecord(
            id=note_id,
            slug=_string(payload.get("slug")),
            title=title,
            content=content,
            tags=[item for item in payload.get("tags", []) if isinstance(item, str)],
            createdAtEpochMs=now,
            updatedAtEpochMs=now,
        )
        self.notes[note.id] = note
        self._mutate("note.create", "note", note.id, requester)
        return {"status": "ok", "note": note.to_json()}

    def _update_note(self, payload: dict[str, Any], requester: Any | None) -> dict[str, Any]:
        note_id = _string(payload.get("id"))
        if not note_id or note_id not in self.notes:
            return self._error("vault.note.update", "not_found", "note not found")
        note = self.notes[note_id]
        if isinstance(payload.get("title"), str):
            note.title = payload["title"]
        if isinstance(payload.get("content"), str):
            note.content = payload["content"]
        if isinstance(payload.get("tags"), list):
            note.tags = [item for item in payload["tags"] if isinstance(item, str)]
        note.updatedAtEpochMs = _now_ms()
        self._mutate("note.update", "note", note.id, requester)
        return {"status": "ok", "note": note.to_json()}

    def _get_note(self, payload: dict[str, Any]) -> dict[str, Any]:
        note_id = _string(payload.get("id"))
        note = self.notes.get(note_id or "")
        if note is None:
            return self._error("vault.note.get", "not_found", "note not found")
        return {"status": "ok", "note": note.to_json()}

    def _list_notes(self, payload: dict[str, Any]) -> dict[str, Any]:
        notes = list(self.notes.values())
        ids = [item for item in payload.get("ids", []) if isinstance(item, str)]
        if ids:
            wanted = set(ids)
            notes = [note for note in notes if note.id in wanted]
        text = _string(payload.get("text"))
        if text:
            needle = text.lower()
            notes = [note for note in notes if needle in note.title.lower() or needle in note.content.lower()]
        tags = [item for item in payload.get("tags", []) if isinstance(item, str)]
        if tags:
            required = set(tags)
            notes = [note for note in notes if required.issubset(set(note.tags))]
        sort_by = _string(payload.get("sortBy")) or "id"
        reverse = bool(payload.get("descending", False))
        notes.sort(key=lambda note: getattr(note, _sort_field(sort_by)), reverse=reverse)
        offset = int(payload.get("offset", 0) or 0)
        limit = int(payload.get("limit", len(notes)) or len(notes))
        sliced = notes[offset : offset + limit]
        return {"status": "ok", "notes": [note.to_json() for note in sliced], "count": len(sliced)}

    def _add_link(self, payload: dict[str, Any], requester: Any | None) -> dict[str, Any]:
        from_id = _string(payload.get("fromNoteID") or payload.get("from"))
        to_id = _string(payload.get("toNoteID") or payload.get("to"))
        if not from_id or not to_id:
            return self._error("vault.link.add", "field_errors", "fromNoteID and toNoteID are required")
        link = {
            "fromNoteID": from_id,
            "toNoteID": to_id,
            "relationship": _string(payload.get("relationship")) or "wiki",
            "createdAtEpochMs": _now_ms(),
        }
        if link not in self.links:
            self.links.append(link)
            self._mutate("link.add", "link", f"{from_id}->{to_id}", requester)
        return {"status": "ok", "link": link}

    def _links(self, payload: dict[str, Any], source_key: str, target_key: str) -> dict[str, Any]:
        note_id = _string(payload.get("id") or payload.get("noteID") or payload.get("note_id"))
        if not note_id:
            return self._error("vault.links", "field_errors", "id is required")
        links = [link for link in self.links if link[source_key] == note_id]
        return {"status": "ok", "links": links, "ids": [link[target_key] for link in links]}

    def _state_payload(self) -> dict[str, Any]:
        return {
            "status": "ready",
            "cell": self.name,
            "schemaVersion": self.schema_version,
            "stateVersion": self.state_version,
            "noteCount": len(self.notes),
            "linkCount": len(self.links),
            "note_count": len(self.notes),
            "link_count": len(self.links),
            "notes": [note.to_json() for note in sorted(self.notes.values(), key=lambda item: item.id)],
            "links": list(self.links),
            "operations": list(self.operations),
            "updatedAtEpochMs": _now_ms(),
        }

    def _mutate(self, operation: str, record_kind: str, record_id: str, requester: Any | None) -> None:
        self.state_version += 1
        event = {
            "schemaVersion": self.mutation_schema_version,
            "stateVersion": self.state_version,
            "operation": operation,
            "recordKind": record_kind,
            "recordID": record_id,
            "result": "ok",
            "emittedAtEpochMs": _now_ms(),
        }
        self.operations.append(event)
        self.push_flow_element(
            FlowElement(title="VaultMutationEvent", content=event, topic="vault.mutation", origin=self.uuid)
        )
        _ = requester

    def _error(self, operation: str, code: str, message: str, field_errors: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "status": "error",
            "operation": operation,
            "code": code,
            "message": message,
            "field_errors": field_errors or {},
        }


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _sort_field(sort_by: str) -> str:
    return {
        "id": "id",
        "title": "title",
        "createdAt": "createdAtEpochMs",
        "updatedAt": "updatedAtEpochMs",
    }.get(sort_by, "id")
