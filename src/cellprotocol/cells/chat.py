"""Chat between identities on any node: CellBase Swift's `ChatCell` for Python.

Same keypaths and result shapes as Swift for the parts a cross-language chat
needs: messages, participants, audience, the signed invitation artifact and
acceptance (`ChatInvitationProofUtility`), the composer, and the
`chat.message` / `chat.participant` / `chat.status` flow events.

Who may use the cell is decided by its Agreement, as in Swift:

* the owner, proven as for every Python cell;
* anyone holding a contract the cell signed from its Agreement template. The
  owner picks the conditions with `audience.admissionConditions`:
  `invitationAccepted` (the requester presented a signed acceptance of a
  current, unrevoked invitation) or `member` (an accepted invitation, or one
  the owner accepted directly). With conditions, the cell signs a requester's
  contract when they hold; with none, only an owner-approved Agreement admits.
  Every access re-checks the conditions, so revoking an invitation ends access.

Before a guest holds a contract it may read its own `audience.admission.*`
answers and hand a signed artifact and acceptance to
`audience.acceptInvitationArtifact`, which checks both signatures. A member is
recognised by its signing key, as the authenticated bridge checks it on every
command.

Not ported: end-to-end encrypted envelopes (`crypto.*` answer that only
plaintext is supported), rekey tracking, the invitation ledger history and the
demo emitter (`start` / `stop`).
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any, Callable, Optional
from uuid import uuid4

from ..agreement import AUTOMATIC_WHEN_CONDITIONS_MET, OWNER_APPROVAL_REQUIRED, LookupCondition
from ..general_cell import FlowElement, GeneralCell
from ..identity import Identity, proves_identity_control
from ..interop import chat as chat_proofs
from ..interop.models import ChatInvitationAcceptance, ChatInvitationArtifact, IdentityPublicKeyDescriptor, WireDecodeError
from ..interop.verify import Signer, VerificationFailure, invitation_hash, verify_chat_acceptance, verify_chat_invitation
from ..value import from_json_value
from .entity_anchor import descriptor_for, with_identity_signer

ENDPOINT = "cell:///Chat"
DEFAULT_CONTENT_TYPE = "text/plain"
AUDIENCE_MODES = {
    "contextMembers": ("Context members", "Bruk kjente deltakere og kontekstmedlemmer som mottakere."),
    "invitedIdentities": ("Invited identities", "Bruk bare eksplisitt inviterte identities som mottakere."),
    "hybrid": ("Hybrid", "Bruk både kontekstmedlemmer og eksplisitt inviterte identities."),
}
STATUS_LABELS = {"pending": "Pending", "accepted": "Accepted", "declined": "Declined", "revoked": "Revoked"}
AVAILABLE_FORMATS = [
    {"id": "plain", "label": "Plain text", "contentType": "text/plain", "description": "Vanlig tekst uten formattering."},
    {"id": "markdown", "label": "Markdown", "contentType": "text/markdown", "description": "Markdown for overskrifter, lister og lenker."},
]

READ_KEYS = [
    "status", "state", "messages", "participants", "members", "audience", "audience.mode",
    "audience.inheritedRecipients", "audience.invitedRecipients", "audience.resolvedRecipients",
    "audience.invitations", "audience.invitationArtifacts", "compose.body", "compose.contentType",
    "compose.state", "compose.availableFormats", "crypto", "crypto.state",
]
WRITE_KEYS = [
    "audience.mode", "audience.inviteIdentities", "audience.generateInvitationArtifacts",
    "audience.generateInvitationAcceptance", "audience.acceptInvitationArtifact",
    "audience.inspectInvitationArtifact", "audience.acceptInvites", "audience.declineInvites",
    "audience.revokeInvites", "audience.clearInvites", "compose.body", "compose.contentType",
    "sendMessage", "addMessage", "sendComposedMessage", "clearComposer",
]
# Swift ChatCell's Agreement template grants, in the same order.
TEMPLATE_GRANTS = [
    ("r---", "feed"), ("rw--", "chat"), ("rw--", "status"), ("rw--", "state"), ("rw--", "messages"),
    ("rw--", "participants"), ("rw--", "members"), ("rw--", "audience"), ("rw--", "audience.mode"),
    ("r---", "audience.inheritedRecipients"), ("r---", "audience.invitedRecipients"),
    ("r---", "audience.resolvedRecipients"), ("r---", "audience.invitations"), ("r---", "audience.invitationLedger"),
    ("r---", "audience.invitationArtifacts"), ("-w--", "audience.inspectInvitationArtifact"),
    ("rw--", "audience.inviteIdentities"), ("rw--", "audience.generateInvitationArtifacts"),
    ("rw--", "audience.generateInvitationAcceptance"), ("rw--", "audience.acceptInvitationArtifact"),
    ("rw--", "audience.acceptInvites"), ("rw--", "audience.declineInvites"), ("rw--", "audience.revokeInvites"),
    ("rw--", "audience.removeContextMembers"), ("rw--", "audience.clearInvites"), ("rw--", "compose"),
    ("rw--", "compose.body"), ("rw--", "compose.contentType"), ("rw--", "compose.state"), ("rw--", "compose.previewRows"),
    ("r---", "crypto"), ("r---", "crypto.state"), ("r---", "crypto.policy"), ("r---", "crypto.supportedSuites"),
    ("r---", "crypto.recipients"), ("r---", "crypto.membership"), ("r---", "crypto.rekeyStatus"),
    ("r---", "crypto.persistencePolicy"), ("r---", "crypto.persistenceMode"), ("r---", "crypto.encryptedMessages"),
    ("r---", "crypto.draftEnvelope"), ("rw--", "crypto.persistenceMode"), ("rw--", "crypto.requestRekey"),
    ("rw--", "crypto.prepareDraftEnvelope"), ("rw--", "crypto.openEnvelope"), ("rw--", "crypto.clearDraftEnvelope"),
    ("rw--", "crypto.clearEncryptedMessages"), ("rw--", "sendMessage"), ("rw--", "sendComposedMessage"),
    ("rw--", "clearComposer"), ("rw--", "addMessage"), ("rw--", "start"), ("rw--", "stop"),
]
# Conditions an owner can put in the Agreement. Each reads `audience.admission.<name>` on the chat.
ADMISSION_CONDITIONS = ("invitationAccepted", "member")
ADMISSION_KEYS = {f"audience.admission.{name}": name for name in ADMISSION_CONDITIONS}
# Usable before a contract: the admission keys answer only for the requester, and
# an artifact with its acceptance carries the owner's and the invitee's signatures.
OPEN_BEFORE_ADMISSION = {**{key: "r---" for key in ADMISSION_KEYS}, "audience.acceptInvitationArtifact": "-w--", "audience.inspectInvitationArtifact": "-w--"}


def admission_condition(name: str) -> LookupCondition:
    return LookupCondition(keypath=f"target.audience.admission.{name}", expected_value=True)


def _initials(name: str) -> str:
    words = [word for word in name.replace("-", " ").split() if word][:2]
    return "".join(next((ch.upper() for ch in word if ch.isalnum()), "") for word in words)


def _normalized_content_type(raw: Optional[str]) -> str:
    value = (raw or "").strip().lower()
    if value in ("", "plain", "plaintext", "text", "text/plain"):
        return "text/plain"
    if value in ("markdown", "md", "text/markdown"):
        return "text/markdown"
    return value if "/" in value else DEFAULT_CONTENT_TYPE


class _Person:
    """What the cell knows about an identity: uuid, name and signing key."""

    def __init__(self, uuid: str, display_name: str, descriptor: Optional[IdentityPublicKeyDescriptor]) -> None:
        self.uuid, self.display_name, self.descriptor = uuid, display_name, descriptor

    @classmethod
    def from_value(cls, value: Any) -> Optional["_Person"]:
        if isinstance(value, Identity):
            return cls(value.uuid, value.displayName, descriptor_for(value))
        if not isinstance(value, dict):
            return None
        if isinstance(value.get("publicKey"), str) and "algorithm" in value:
            try:
                descriptor = IdentityPublicKeyDescriptor.from_wire(value)
            except (WireDecodeError, TypeError, ValueError, KeyError):
                return None
            return cls(descriptor.uuid, descriptor.display_name or descriptor.uuid, descriptor)
        try:
            identity = Identity.from_json(value)
        except (ValueError, TypeError, KeyError):
            return None
        return cls(identity.uuid, identity.displayName, descriptor_for(identity))

    def matches(self, requester: Any) -> bool:
        if self.descriptor is None or requester is None or getattr(requester, "uuid", None) != self.uuid:
            return False
        key = getattr(requester, "publicSecureKey", None)
        try:
            return isinstance(key, str) and base64.b64decode(key, validate=True) == self.descriptor.public_key
        except ValueError:
            return False

    def public_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"uuid": self.uuid, "displayName": self.display_name}
        if self.descriptor is not None:
            out["publicSecureKey"] = base64.b64encode(self.descriptor.public_key).decode("ascii")
        return out


class ChatCell(GeneralCell):
    """`cell:///Chat`. `signer` defaults to signing with the owner identity's vault."""

    def __init__(
        self,
        owner: Any | None = None,
        *,
        signer: Optional[Signer] = None,
        topic: str = "chat",
        messages_limit: int = 200,
        name: str = "Chat",
        uuid: str | None = None,
        clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = os.urandom,
        new_uuid: Callable[[], str] = lambda: str(uuid4()).upper(),
    ) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)
        self._signer = signer
        self._clock = clock
        self._random_bytes = random_bytes
        self._new_uuid = new_uuid
        self.topic = topic
        self.messages_limit = messages_limit
        self.audience_mode = "hybrid"
        self.persistence_mode = "draftCacheOnly"
        self.messages: list[dict[str, Any]] = []
        self.participants: dict[str, dict[str, Any]] = {}
        self.invitations: dict[str, dict[str, Any]] = {}  # identity uuid -> record
        self.consumed: dict[str, dict[str, Any]] = {}  # invitation id -> consumption
        self.drafts: dict[str, dict[str, str]] = {}
        self._owner_person = _Person.from_value(owner) if owner is not None else None
        for permission, key in TEMPLATE_GRANTS:
            self.agreement_template.add_grant(permission, key)
        for key in READ_KEYS:
            self._get_handlers[key] = self._read
        for key in WRITE_KEYS:
            self._set_handlers[key] = self._write
        for key in ADMISSION_KEYS:
            self._get_handlers[key] = self._admission
        self._get_handlers["audience.admissionConditions"] = self._admission
        self._set_handlers["audience.admissionConditions"] = self._set_admission_conditions

    # -- access ---------------------------------------------------------------

    async def validate_access(self, permission: str, keypath: str, requester: Any | None = None) -> bool:
        if self.owner is None or await proves_identity_control(requester, self.owner):
            return True
        if OPEN_BEFORE_ADMISSION.get(keypath) == permission:
            return True
        if keypath == "audience.admissionConditions" and permission == "-w--":
            return False  # the owner's alone, whatever "audience" grants say
        # As Swift: the dispatcher accepts the exact key or its root, the
        # handler the exact key or "chat".
        root = keypath.split(".", 1)[0]
        dispatch = await self.contract_allows(permission, keypath, requester) or (
            root != keypath and await self.contract_allows(permission, root, requester)
        )
        if not dispatch:
            return False
        return await self.contract_allows(permission, keypath, requester) or await self.contract_allows(permission, "chat", requester)

    def member_for(self, requester: Any) -> Optional[_Person]:
        """The accepted invitee `requester` is, by uuid and signing key. Says who; grants nothing."""
        record = self.invitations.get(getattr(requester, "uuid", None) or "")
        if record is not None and record["status"] == "accepted" and record["person"].matches(requester):
            return record["person"]
        return None

    # -- admission ------------------------------------------------------------

    def admission_condition_holds(self, name: str, requester: Any) -> bool:
        member = self.member_for(requester)
        if member is None:
            return False
        if name == "member":
            return True
        record = self.invitations[member.uuid]
        artifact, acceptance = record["artifact"], record["acceptance"]
        if artifact is None or acceptance is None:
            return False
        consumed = self.consumed.get(artifact.invitation_id)
        if consumed is None or consumed["acceptanceID"] != acceptance.acceptance_id:
            return False
        try:
            verify_chat_invitation(artifact, now=self._clock())
        except VerificationFailure:
            return False
        return True

    def admission_conditions(self) -> list[str]:
        names = []
        for condition in self.agreement_template.conditions:
            name = ADMISSION_KEYS.get(condition.keypath.removeprefix("target."))
            if name is not None:
                names.append(name)
        return names

    def apply_admission_conditions(self, names: list[str]) -> None:
        """Replace the Agreement's conditions; contracts signed under others stop matching."""
        self.agreement_template.conditions = [admission_condition(name) for name in names]
        self.agreement_admission_policy = AUTOMATIC_WHEN_CONDITIONS_MET if names else OWNER_APPROVAL_REQUIRED

    async def _admission(self, keypath: str, requester: Any | None) -> Any:
        if keypath == "audience.admissionConditions":
            if not await self.validate_access("r---", "audience", requester):
                raise PermissionError("Cell access denied: audience")
            return self.admission_conditions()
        return self.admission_condition_holds(ADMISSION_KEYS[keypath], requester)

    async def _set_admission_conditions(self, keypath: str, value: Any, requester: Any | None) -> Any:
        _ = keypath
        value = from_json_value(value)
        if not isinstance(value, list) or not all(isinstance(item, str) and item in ADMISSION_CONDITIONS for item in value):
            return f"error: admission conditions must be a list of {list(ADMISSION_CONDITIONS)}"
        names = list(dict.fromkeys(value))
        self.apply_admission_conditions(names)
        return names

    def _is_owner(self, requester: Any) -> bool:
        return self.owner is not None and requester is not None and getattr(requester, "uuid", None) == self.owner.uuid

    # -- dispatch -------------------------------------------------------------

    async def _read(self, keypath: str, requester: Any | None) -> Any:
        if keypath in ("state", "status", "messages", "participants"):
            update = self._observe(requester, keypath)
            if update:
                self._publish_participant(update)
                self._publish_status()
        if keypath == "status":
            return self.status_summary()
        if keypath == "state":
            return self.state_payload(requester)
        if keypath == "messages":
            return [dict(message) for message in self.messages]
        if keypath in ("participants", "members"):
            return self.participant_rows()
        if keypath == "audience":
            return self.audience_payload(requester)
        if keypath == "audience.mode":
            return self.audience_mode
        if keypath == "audience.inheritedRecipients":
            return [self._recipient(person, "owner" if self._is_owner_person(person) else "context") for person in self._context_people()]
        if keypath == "audience.invitedRecipients":
            return [self._recipient(person, "owner" if self._is_owner_person(person) else "invited") for person in self._invited_people()]
        if keypath == "audience.resolvedRecipients":
            return self._resolved_recipients()
        if keypath == "audience.invitations":
            return self.invitation_rows()
        if keypath == "audience.invitationArtifacts":
            return [
                record["artifact"].to_wire()
                for record in self._sorted_invitations()
                if record["artifact"] is not None and self._artifact_state(record) == "issued"
            ]
        if keypath == "compose.body":
            return self._draft(requester)["body"]
        if keypath == "compose.contentType":
            return self._draft(requester)["contentType"]
        if keypath == "compose.state":
            return self.composer_payload(requester)
        if keypath == "compose.availableFormats":
            return [dict(item) for item in AVAILABLE_FORMATS]
        if keypath in ("crypto", "crypto.state"):
            return self.crypto_payload()
        return None

    async def _write(self, keypath: str, value: Any, requester: Any | None) -> Any:
        value = from_json_value(value)
        if keypath == "audience.mode":
            if value not in AUDIENCE_MODES:
                return "error: unsupported audience mode"
            self.audience_mode = value
            return self.audience_payload(requester)
        if keypath == "audience.inviteIdentities":
            return self.invite_identities(value, requester)
        if keypath == "audience.generateInvitationArtifacts":
            return await self.generate_invitation_artifacts(value)
        if keypath == "audience.generateInvitationAcceptance":
            return await self.generate_invitation_acceptance(value, requester)
        if keypath == "audience.acceptInvitationArtifact":
            return self.accept_invitation_artifact(value, requester)
        if keypath == "audience.inspectInvitationArtifact":
            artifact = _artifact_from(value)
            return "error: invalid invitation artifact payload" if artifact is None else self.inspect(artifact)
        if keypath in ("audience.acceptInvites", "audience.declineInvites", "audience.revokeInvites"):
            status = {"audience.acceptInvites": "accepted", "audience.declineInvites": "declined", "audience.revokeInvites": "revoked"}[keypath]
            return self.update_statuses(value, status, requester)
        if keypath == "audience.clearInvites":
            self.invitations.clear()
            self.consumed.clear()
            return self.audience_payload(requester)
        if keypath == "compose.body":
            self._draft(requester)["body"] = value if isinstance(value, str) else ""
            return self.composer_payload(requester)
        if keypath == "compose.contentType":
            self._draft(requester)["contentType"] = _normalized_content_type(value if isinstance(value, str) else None)
            return self.composer_payload(requester)
        if keypath in ("sendMessage", "addMessage"):
            return self.send_message(value, requester)
        if keypath == "sendComposedMessage":
            if not (value is None or isinstance(value, (bool, dict))):
                return "error: invalid trigger payload"
            draft = self._draft(requester)
            body = draft["body"].strip()
            if not body:
                return "error: empty composer body"
            draft["body"] = ""
            return self._store(body, draft["contentType"], self.topic, requester)
        if keypath == "clearComposer":
            if not (value is None or isinstance(value, (bool, dict))):
                return "error: invalid trigger payload"
            self._draft(requester)["body"] = ""
            return dict(self._draft(requester))
        return None

    # -- signing --------------------------------------------------------------

    async def _signed(self, build: Callable[[Signer], Any]) -> Any:
        if self._signer is not None:
            return build(self._signer)
        return await with_identity_signer(self.owner, build)

    # -- messages -------------------------------------------------------------

    def _now(self) -> str:
        return chat_proofs.timestamp(self._clock())

    def _person_for(self, requester: Any) -> _Person:
        if self._is_owner(requester) and self._owner_person is not None:
            return self._owner_person
        member = self.member_for(requester)
        if member is not None:
            return member
        return _Person(getattr(requester, "uuid", "anonymous"), getattr(requester, "displayName", "Ukjent"), None)

    def send_message(self, value: Any, requester: Any) -> Any:
        if isinstance(value, str):
            body, content_type, topic = value, self._draft(requester)["contentType"], self.topic
        elif isinstance(value, dict):
            body = next((value[key] for key in ("content", "body", "text") if isinstance(value.get(key), str)), None)
            content_type = value.get("contentType") or value.get("format") or self._draft(requester)["contentType"]
            topic = value.get("topic") if isinstance(value.get("topic"), str) else self.topic
        else:
            body = None
        if body is None or not body.strip():
            return "error: invalid chat payload"
        return self._store(body.strip(), _normalized_content_type(content_type), topic, requester)

    def _store(self, body: str, content_type: str, topic: str, requester: Any) -> dict[str, Any]:
        person = self._person_for(requester)
        name = getattr(requester, "displayName", None) or person.display_name
        message = {
            "id": self._new_uuid(),
            "owner": person.public_json(),
            "ownerUUID": person.uuid,
            "ownerDisplayName": name,
            "ownerInitials": _initials(name),
            "content": body,
            "contentPreview": body if len(body) <= 140 else body[:139] + "…",
            "contentType": content_type,
            "formatLabel": "Markdown" if content_type == "text/markdown" else "Plain text",
            "isMarkdown": content_type == "text/markdown",
            "topic": topic,
            "createdAt": self._now(),
            "cryptoState": "plaintextOnly",
            "encryptedCompanionAvailable": False,
        }
        self.messages.append(message)
        if len(self.messages) > self.messages_limit:
            del self.messages[: len(self.messages) - self.messages_limit]
        participant = self._observe(requester, "sentMessage", increment=True)
        self.push_flow_element(FlowElement(title="Chat message", content=dict(message), topic="chat.message", origin=self.uuid, id=message["id"],
                                           properties={"type": "event", "contentType": "object"}))
        if participant:
            self._publish_participant(participant)
        self._publish_status()
        return {"status": "sent", "message": dict(message), "messageCount": len(self.messages), "participantCount": len(self.participants)}

    def _observe(self, requester: Any, action: str, increment: bool = False) -> Optional[dict[str, Any]]:
        if requester is None:
            return None
        person = self._person_for(requester)
        name = getattr(requester, "displayName", None) or person.display_name
        now = self._now()
        record = self.participants.get(person.uuid)
        is_new = record is None
        if record is None:
            record = {"id": person.uuid, "displayName": name, "joinedAt": now, "messageCount": 0}
        renamed = record["displayName"] != name
        record.update(displayName=name, lastSeenAt=now, lastAction=action, presence="messaging" if increment else "present")
        if increment:
            record["messageCount"] += 1
        record["initials"] = _initials(name)
        self.participants[person.uuid] = record
        return dict(record) if (is_new or increment or renamed) else None

    def _publish_participant(self, record: dict[str, Any]) -> None:
        self.push_flow_element(FlowElement(title="Chat participant", content=record, topic="chat.participant", origin=self.uuid, id=record["id"],
                                           properties={"type": "event", "contentType": "object"}))

    def _publish_status(self) -> None:
        self.push_flow_element(FlowElement(title="Chat status", content=self.status_payload(), topic="chat.status", origin=self.uuid,
                                           properties={"type": "event", "contentType": "object"}))

    def _draft(self, requester: Any) -> dict[str, str]:
        key = getattr(requester, "uuid", "anonymous")
        return self.drafts.setdefault(key, {"body": "", "contentType": DEFAULT_CONTENT_TYPE})

    # -- audience and invitations ---------------------------------------------

    def _is_owner_person(self, person: _Person) -> bool:
        return self.owner is not None and person.uuid == self.owner.uuid

    def _people_from(self, value: Any) -> list[_Person]:
        items = value if isinstance(value, list) else [value]
        people = []
        for item in items:
            if isinstance(item, str):
                record = self.invitations.get(item)
                if record is not None:
                    people.append(record["person"])
                continue
            person = _Person.from_value(item)
            if person is not None:
                people.append(person)
        return people

    def invite_identities(self, value: Any, requester: Any) -> dict[str, Any]:
        now = self._now()
        for person in self._people_from(value):
            if self._is_owner_person(person) or person.descriptor is None:
                continue
            existing = self.invitations.get(person.uuid)
            if existing is not None:
                existing["person"] = person
                if existing["status"] != "accepted":
                    existing["status"] = "pending"
                existing.update(source="inviteIdentities", updatedAt=now, acceptance=None)
            else:
                self.invitations[person.uuid] = {
                    "person": person, "status": "pending", "source": "inviteIdentities",
                    "createdAt": now, "updatedAt": now, "artifact": None, "acceptance": None,
                }
        return self.audience_payload(requester)

    def _targets(self, value: Any, allow_true: bool = False) -> Optional[set[str]]:
        """None means invalid; an empty set never comes back (that means all)."""
        if value is None or (allow_true and value is True) or value == []:
            return set(self.invitations)
        if not isinstance(value, list):
            return None
        targets = set()
        for item in value:
            if isinstance(item, str) and item:
                targets.add(item)
            elif (person := _Person.from_value(item)) is not None:
                targets.add(person.uuid)
            else:
                return None
        return targets or None

    async def generate_invitation_artifacts(self, value: Any) -> Any:
        eligible = {uuid for uuid, record in self.invitations.items() if record["status"] != "revoked"}
        targets = self._targets(value, allow_true=True)
        if targets is None:
            return "error: invalid invitation target payload"
        if value not in (None, True, []) and not targets <= eligible:
            return "error: invitation targets must all reference eligible invitation records"
        if self._owner_person is None or self._owner_person.descriptor is None:
            return "error: owner has no signing key"
        artifacts = []
        for uuid in sorted(targets & eligible):
            record = self.invitations[uuid]
            if record["artifact"] is not None and self._artifact_state(record) == "issued":
                artifacts.append(record["artifact"].to_wire())
                continue
            if record["status"] == "declined":
                record["status"] = "pending"
            prior = record["artifact"]
            # Fixed before signing: the owner-identity signer builds twice.
            invitation_id, moment, nonce = self._new_uuid(), self._clock(), self._random_bytes(chat_proofs.NONCE_BYTES)
            artifact = await self._signed(
                lambda sign, record=record: chat_proofs.build_invitation(
                    chat_cell_uuid=self.uuid,
                    topic=self.topic,
                    audience_mode=self.audience_mode,
                    persistence_mode=self.persistence_mode,
                    inviter=self._owner_person.descriptor,
                    invited=record["person"].descriptor,
                    signer=sign,
                    invitation_id=invitation_id,
                    now=moment,
                    random_bytes=lambda n: nonce[:n],
                )
            )
            if prior is not None:
                self.consumed.pop(prior.invitation_id, None)
            record.update(artifact=artifact, acceptance=None, updatedAt=artifact.created_at)
            artifacts.append(artifact.to_wire())
        return artifacts

    async def generate_invitation_acceptance(self, value: Any, requester: Any) -> Any:
        """Signed by this cell's owner, for an artifact that invites the owner (to any chat)."""
        artifact = _artifact_from(value)
        if artifact is None:
            return "error: invalid invitation artifact payload"
        if getattr(requester, "uuid", None) != artifact.invited_identity.uuid or self._owner_person is None:
            return "error: requester does not match invited identity"
        acceptance_id, moment, nonce = self._new_uuid(), self._clock(), self._random_bytes(chat_proofs.NONCE_BYTES)
        try:
            acceptance = await self._signed(
                lambda sign: chat_proofs.build_acceptance(
                    artifact, self._owner_person.descriptor, sign, acceptance_id=acceptance_id, now=moment, random_bytes=lambda n: nonce[:n]
                )
            )
        except VerificationFailure as failure:
            return f"error: {failure.code}"
        return acceptance.to_wire()

    def accept_invitation_artifact(self, value: Any, requester: Any) -> Any:
        payload = value if isinstance(value, dict) else {}
        artifact = _artifact_from(payload.get("artifact", value))
        acceptance = _acceptance_from(payload.get("acceptance"))
        if artifact is None or acceptance is None:
            return "error: invalid invitation artifact acceptance payload"
        moment = self._clock()
        try:
            verify_chat_invitation(artifact, expected_chat_cell_uuid=self.uuid, expected_inviter_uuid=self.owner.uuid if self.owner else None, now=moment)
            verify_chat_acceptance(acceptance, artifact, expected_chat_cell_uuid=self.uuid, now=moment)
        except VerificationFailure as failure:
            return f"error: {failure.code}"
        record = self.invitations.get(artifact.invited_identity.uuid)
        if record is None:
            return "error: invitation record not found for artifact"
        current = record["artifact"]
        if current is None:
            return "error: invitation artifact is no longer active"
        if current.invitation_id != artifact.invitation_id or invitation_hash(current) != invitation_hash(artifact):
            return "error: invitation artifact has been superseded"
        if record["status"] == "revoked":
            return "error: invitation artifact has been revoked"
        if record["status"] == "declined":
            return "error: invitation artifact has been declined"
        now = self._now()
        existing = self.consumed.get(artifact.invitation_id)
        idempotent = False
        if existing is not None:
            if existing["acceptanceID"] != acceptance.acceptance_id:
                return "error: invitation artifact already consumed"
            idempotent = True
        elif any(row["acceptanceID"] == acceptance.acceptance_id for row in self.consumed.values()):
            return "error: acceptance proof already consumed"
        record.update(status="accepted", source="artifactAccepted", updatedAt=now, artifact=artifact, acceptance=acceptance)
        self.consumed[artifact.invitation_id] = {
            "invitationID": artifact.invitation_id,
            "acceptanceID": acceptance.acceptance_id,
            "inviteeIdentityUUID": artifact.invited_identity.uuid,
            "consumedAt": now,
        }
        return {
            "status": "accepted",
            "idempotent": idempotent,
            "invitationID": artifact.invitation_id,
            "acceptanceID": acceptance.acceptance_id,
            "audience": self.audience_payload(requester),
            "invitation": self._invitation_row(record),
        }

    def update_statuses(self, value: Any, status: str, requester: Any) -> Any:
        targets = self._targets(value)
        if targets is None:
            return "error: invalid invitation target payload"
        if not targets <= set(self.invitations):
            return "error: invitation targets must all reference known invitation records"
        now = self._now()
        for uuid in targets:
            self.invitations[uuid].update(status=status, updatedAt=now)
        return self.audience_payload(requester)

    def _artifact_state(self, record: dict[str, Any]) -> str:
        if record["status"] in ("revoked", "declined"):
            return record["status"]
        if record["artifact"] is None:
            return "notIssued"
        if record["acceptance"] is not None:
            return "consumed"
        try:
            verify_chat_invitation(record["artifact"], now=self._clock())
        except VerificationFailure:
            return "expired"
        return "issued"

    def inspect(self, artifact: ChatInvitationArtifact) -> dict[str, Any]:
        record = self.invitations.get(artifact.invited_identity.uuid)
        state = "notFound"
        if record is not None and record["artifact"] is not None:
            if record["artifact"].invitation_id != artifact.invitation_id:
                state = "superseded"
            else:
                state = self._artifact_state(record)
        return {"invitationID": artifact.invitation_id, "state": state, "acceptanceAllowed": state == "issued", "chatCellUUID": artifact.chat_cell_uuid}

    # -- presentation ---------------------------------------------------------

    def _sorted_invitations(self) -> list[dict[str, Any]]:
        return sorted(self.invitations.values(), key=lambda record: (record["status"], record["person"].display_name.lower()))

    def _invitation_row(self, record: dict[str, Any]) -> dict[str, Any]:
        artifact, acceptance, person = record["artifact"], record["acceptance"], record["person"]
        state = self._artifact_state(record)
        return {
            "identityUUID": person.uuid,
            "displayName": person.display_name,
            "status": record["status"],
            "statusLabel": STATUS_LABELS[record["status"]],
            "source": record["source"],
            "createdAt": record["createdAt"],
            "updatedAt": record["updatedAt"],
            "isResolvedRecipient": record["status"] == "accepted",
            "hasKeyAgreementKey": False,
            "hasSigningKey": person.descriptor is not None,
            "artifactAvailable": artifact is not None,
            "artifactInvitationID": artifact.invitation_id if artifact else None,
            "artifactIssuedAt": artifact.created_at if artifact else None,
            "artifactExpiresAt": artifact.expires_at if artifact else None,
            "artifactState": state,
            "artifactAcceptanceAllowed": state == "issued",
            "artifactConsumedAt": acceptance.created_at if acceptance else None,
            "proofBackedAcceptance": acceptance is not None,
            "acceptanceAvailable": acceptance is not None,
            "acceptanceID": acceptance.acceptance_id if acceptance else None,
            "acceptanceCreatedAt": acceptance.created_at if acceptance else None,
        }

    def invitation_rows(self) -> list[dict[str, Any]]:
        return [self._invitation_row(record) for record in self._sorted_invitations()]

    def _context_people(self) -> list[_Person]:
        people = [self._owner_person] if self._owner_person else []
        for row in sorted(self.participants.values(), key=lambda row: row["displayName"].lower()):
            if not any(person.uuid == row["id"] for person in people):
                record = self.invitations.get(row["id"])
                people.append(record["person"] if record else _Person(row["id"], row["displayName"], None))
        return people

    def _invited_people(self) -> list[_Person]:
        people = [self._owner_person] if self._owner_person else []
        for record in sorted(self.invitations.values(), key=lambda record: record["person"].display_name.lower()):
            if record["status"] == "accepted":
                people.append(record["person"])
        return people

    def _recipient(self, person: _Person, source: str) -> dict[str, Any]:
        return {
            "identityUUID": person.uuid,
            "displayName": person.display_name,
            "source": source,
            "isOwner": self._is_owner_person(person),
            "hasKeyAgreementKey": False,
            "hasSigningKey": person.descriptor is not None,
        }

    def _resolved_people(self) -> list[_Person]:
        context, invited = self._context_people(), self._invited_people()
        chosen = {"contextMembers": context, "invitedIdentities": invited}.get(self.audience_mode, context + invited)
        seen, out = set(), []
        for person in chosen:
            if person.uuid not in seen:
                seen.add(person.uuid)
                out.append(person)
        return out

    def _resolved_recipients(self) -> list[dict[str, Any]]:
        context = {person.uuid for person in self._context_people()}
        invited = {person.uuid for person in self._invited_people()}
        rows = []
        for person in self._resolved_people():
            if self._is_owner_person(person):
                source = "owner"
            elif person.uuid in context and person.uuid in invited:
                source = "hybrid"
            elif person.uuid in invited:
                source = "invited"
            else:
                source = "context"
            rows.append(self._recipient(person, source))
        return rows

    def audience_payload(self, requester: Any) -> dict[str, Any]:
        _ = requester
        records = list(self.invitations.values())
        count = lambda status: sum(1 for record in records if record["status"] == status)  # noqa: E731
        label, summary = AUDIENCE_MODES[self.audience_mode]
        return {
            "mode": self.audience_mode,
            "modeLabel": label,
            "summary": summary,
            "inheritedRecipients": [self._recipient(p, "owner" if self._is_owner_person(p) else "context") for p in self._context_people()],
            "invitedRecipients": [self._recipient(p, "owner" if self._is_owner_person(p) else "invited") for p in self._invited_people()],
            "resolvedRecipients": self._resolved_recipients(),
            "invitations": self.invitation_rows(),
            "invitationLedgerCount": len(self.consumed),
            "inheritedCount": max(len(self._context_people()) - 1, 0),
            "invitedCount": count("accepted"),
            "resolvedCount": len(self._resolved_people()),
            "invitationCount": len(records),
            "pendingInviteCount": count("pending"),
            "acceptedInviteCount": count("accepted"),
            "declinedInviteCount": count("declined"),
            "revokedInviteCount": count("revoked"),
            "supportsContextMembers": True,
            "supportsExplicitInvites": True,
            "defaultForEmbeddedComponent": "hybrid",
        }

    def participant_rows(self) -> list[dict[str, Any]]:
        return sorted((dict(row) for row in self.participants.values()), key=lambda row: row["displayName"].lower())

    def status_summary(self) -> str:
        return f"participants: {len(self.participants)} · messages: {len(self.messages)} · topic: {self.topic}"

    def status_payload(self) -> dict[str, Any]:
        latest = self.messages[-1] if self.messages else None
        return {
            "summary": self.status_summary(),
            "topic": self.topic,
            "messageCount": len(self.messages),
            "participantCount": len(self.participants),
            "messagesLimit": self.messages_limit,
            "running": False,
            "latestMessageAt": latest["createdAt"] if latest else None,
            "latestMessagePreview": latest["contentPreview"] if latest else None,
            "latestMessageContentType": latest["contentType"] if latest else None,
        }

    def composer_payload(self, requester: Any) -> dict[str, Any]:
        draft = self._draft(requester)
        return {"body": draft["body"], "contentType": draft["contentType"], "canSend": bool(draft["body"].strip()), "availableFormats": [dict(i) for i in AVAILABLE_FORMATS]}

    def crypto_payload(self) -> dict[str, Any]:
        return {
            "state": "plaintextOnly",
            "supported": False,
            "summary": "Denne noden sender meldinger i klartekst over den autentiserte broen. Krypterte konvolutter er ikke portet.",
            "preferredSuiteID": chat_proofs.DEFAULT_SUITE_ID,
            "persistenceMode": self.persistence_mode,
        }

    def state_payload(self, requester: Any) -> dict[str, Any]:
        return {
            "topic": self.topic,
            "status": self.status_summary(),
            "statusDetail": self.status_payload(),
            "messages": [dict(message) for message in self.messages],
            "participants": self.participant_rows(),
            "members": self.participant_rows(),
            "audience": self.audience_payload(requester),
            "messageCount": len(self.messages),
            "participantCount": len(self.participants),
            "messagesLimit": self.messages_limit,
            "running": False,
            "composer": self.composer_payload(requester),
            "crypto": self.crypto_payload(),
            "availableFormats": [dict(item) for item in AVAILABLE_FORMATS],
        }


def _from_wire(model: type, value: Any) -> Any:
    if isinstance(value, str):
        from ..interop.invite import data_from_base64url
        import json

        data = data_from_base64url(value)
        if data is None:
            return None
        try:
            value = json.loads(data)
        except ValueError:
            return None
    if not isinstance(value, dict):
        return None
    try:
        return model.from_wire(value)
    except (WireDecodeError, TypeError, ValueError, KeyError):
        return None


def _artifact_from(value: Any) -> Optional[ChatInvitationArtifact]:
    if isinstance(value, dict) and "artifact" in value and "invitationID" not in value:
        value = value["artifact"]
    return _from_wire(ChatInvitationArtifact, value)


def _acceptance_from(value: Any) -> Optional[ChatInvitationAcceptance]:
    return _from_wire(ChatInvitationAcceptance, value)
