"""Agreements, conditions and contracts, as CellBase Swift admits with them.

A cell publishes an Agreement template: the grants it offers, the conditions a
requester must meet, and how long a contract lasts. A requester sends back an
Agreement derived from it. The cell signs a contract when the request stays
inside the template, the admission policy allows it, and every condition holds.
Each access then re-checks the contract against the current template and its
conditions, so a condition that stops holding ends access at once.

Wire format is Swift's `Agreement` Codable: grants carry `permission` as
`{"group": bits, "other": bits}`, conditions are `{"type", "condition"}`.
Only `lookup` conditions on `target.` (the cell itself) or `identity.` are
evaluated here; any other condition type fails closed.
"""

from __future__ import annotations

import contextvars
import json
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from uuid import uuid4

from .value import to_json_value

DEFAULT_DURATION = 60 * 60 * 24 * 365
# Swift `Contract.maximumDuration`.
MAXIMUM_DURATION = 60 * 60 * 24 * 365

OWNER_APPROVAL_REQUIRED = "ownerApprovalRequired"
AUTOMATIC_WHEN_CONDITIONS_MET = "automaticWhenConditionsMet"
OWNER_PUBLISHED_READ = "ownerPublishedRead"

# Set while conditions are evaluated. Contracts give no access inside, so a
# condition can never be met by the contract it decides on (as Swift).
evaluating_conditions: contextvars.ContextVar[bool] = contextvars.ContextVar("evaluating_conditions", default=False)

R, W, X, S = 4, 2, 1, 8


def _new_uuid() -> str:
    return str(uuid4()).upper()


def _triplet(text: str) -> int | None:
    bits = 0
    for index, (letter, value) in enumerate((("r", R), ("w", W), ("x", X))):
        char = text[index]
        if char == letter:
            bits |= value
        elif char != "-":
            return None
    return bits


def _quad(text: str) -> int | None:
    bits = _triplet(text[:3])
    if bits is None:
        return None
    if text[3] == "s":
        return bits | S
    return bits if text[3] == "-" else None


def permission_bits(value: Any) -> tuple[int, int] | None:
    """(group, other) bits from a Swift permission object or a string such as `rw--`."""
    if isinstance(value, dict):
        group, other = value.get("group"), value.get("other")
        if isinstance(group, int) and isinstance(other, int) and 0 <= group <= 15 and 0 <= other <= 15:
            return group, other
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    parts = {3: (_triplet, 3), 4: (_quad, 4), 6: (_triplet, 3), 8: (_quad, 4)}.get(len(text))
    if parts is None:
        return None
    parse, width = parts
    group = parse(text[:width])
    other = parse(text[width:]) if len(text) > width else 0
    if group is None or other is None:
        return None
    return group, other


@dataclass
class Grant:
    keypath: str
    permission: str
    uuid: str = field(default_factory=_new_uuid)
    name: str = "Condition grant"

    @property
    def bits(self) -> tuple[int, int]:
        return permission_bits(self.permission) or (0, 0)

    def grants(self, requested: "Grant") -> bool:
        """Swift `Grant.granted`: same keypath, and every requested bit is held."""
        if self.keypath != requested.keypath:
            return False
        group, other = self.bits
        want_group, want_other = requested.bits
        if want_group == 0 or group & want_group != want_group:
            return False
        return want_other == 0 or other & want_other == want_other

    def to_json(self) -> dict[str, Any]:
        group, other = self.bits
        return {"uuid": self.uuid, "name": self.name, "keypath": self.keypath, "permission": {"group": group, "other": other}}

    @classmethod
    def from_json(cls, payload: Any) -> "Grant | None":
        if not isinstance(payload, dict) or not isinstance(payload.get("keypath"), str):
            return None
        bits = permission_bits(payload.get("permission"))
        if bits is None:
            return None
        group, other = bits
        permission = _quad_string(group) + (_quad_string(other) if other else "")
        return cls(
            keypath=payload["keypath"],
            permission=permission,
            uuid=payload.get("uuid") if isinstance(payload.get("uuid"), str) else _new_uuid(),
            name=payload.get("name") if isinstance(payload.get("name"), str) else "Condition grant",
        )


def _quad_string(bits: int) -> str:
    return "".join(letter if bits & value else "-" for letter, value in (("r", R), ("w", W), ("x", X), ("s", S)))


@dataclass
class LookupCondition:
    """Swift `LookupCondition`: the value at `keypath`, read as the requester, equals `expected_value`."""

    keypath: str
    expected_value: Any = True
    name: str = "Lookup condition"
    uuid: str = field(default_factory=_new_uuid)

    def to_json(self) -> dict[str, Any]:
        return {
            "type": "lookup",
            "condition": {"uuid": self.uuid, "name": self.name, "keypath": self.keypath, "expectedValue": to_json_value(self.expected_value)},
        }

    def policy(self) -> str:
        """What two conditions must share to be the same condition (Swift drops only `uuid`)."""
        return json.dumps({"type": "lookup", "name": self.name, "keypath": self.keypath, "expectedValue": to_json_value(self.expected_value)}, sort_keys=True)

    @property
    def enforcing(self) -> bool:
        """Swift `isAuthorizationEnforcingCondition`: only lookups on the target or a resolved cell."""
        keypath = self.keypath.strip()
        return keypath.startswith("target.") or keypath.startswith("resolve.")

    async def is_met(self, target: Any, requester: Any) -> bool:
        if requester is None:
            return False
        keypath = self.keypath.replace("$identity", getattr(requester, "uuid", "missing identity error"))
        keypath = keypath.replace("$target", getattr(target, "uuid", "missing target error"))
        context, _, child = keypath.partition(".")
        if not child:
            return False
        try:
            if context == "target":
                value = await target.get(child, requester)
            elif context == "identity":
                value = await requester.get(child, requester) if hasattr(requester, "get") else None
            else:
                return False
        except Exception:
            return False
        return to_json_value(value) == to_json_value(self.expected_value)


Condition = LookupCondition


def condition_from_json(payload: Any) -> Condition | None:
    if not isinstance(payload, dict) or payload.get("type") != "lookup" or not isinstance(payload.get("condition"), dict):
        return None
    inner = payload["condition"]
    if not isinstance(inner.get("keypath"), str) or "expectedValue" not in inner:
        return None
    return LookupCondition(
        keypath=inner["keypath"],
        expected_value=inner["expectedValue"],
        name=inner.get("name") if isinstance(inner.get("name"), str) else "Lookup condition",
        uuid=inner.get("uuid") if isinstance(inner.get("uuid"), str) else _new_uuid(),
    )


class AgreementTemplate:
    def __init__(self) -> None:
        self.grants: list[Grant] = []
        self.conditions: list[Condition] = []
        self.duration = DEFAULT_DURATION

    def add_grant(self, permission: str, keypath: str) -> None:
        self.grants.append(Grant(keypath=keypath, permission=permission))

    def check_grant(self, requested: Grant) -> bool:
        return any(grant.grants(requested) for grant in self.grants)

    def conditions_match(self, conditions: list[Condition]) -> bool:
        return sorted(c.policy() for c in conditions) == sorted(c.policy() for c in self.conditions) and len(conditions) == len(self.conditions)

    def to_json(self) -> dict[str, Any]:
        return {"grants": [grant.to_json() for grant in self.grants], "conditions": [c.to_json() for c in self.conditions], "duration": self.duration}


@dataclass
class AgreementRequest:
    """An Agreement as a requester sends it."""

    owner: dict[str, Any]
    grants: list[Grant]
    conditions: list[Condition]
    duration: int
    state: str
    uuid: str
    name: str

    @classmethod
    def from_json(cls, payload: Any) -> "AgreementRequest | None":
        if not isinstance(payload, dict) or not isinstance(payload.get("owner"), dict):
            return None
        grants = [Grant.from_json(item) for item in payload.get("grants") or []]
        conditions = [condition_from_json(item) for item in payload.get("conditions") or []]
        duration = payload.get("duration", DEFAULT_DURATION)
        if any(g is None for g in grants) or any(c is None for c in conditions) or not isinstance(duration, int):
            return None
        state = payload.get("state")
        return cls(
            owner=payload["owner"],
            grants=grants,  # type: ignore[arg-type]
            conditions=conditions,  # type: ignore[arg-type]
            duration=duration,
            state=state if isinstance(state, str) else "template",
            uuid=payload.get("uuid") if isinstance(payload.get("uuid"), str) else _new_uuid(),
            name=payload.get("name") if isinstance(payload.get("name"), str) else "Contract name here",
        )


@dataclass
class Contract:
    """A contract the cell signed for one subject. Kept by the cell; access re-checks it."""

    uuid: str
    subject: Any
    grants: list[Grant]
    conditions: list[Condition]
    duration: int
    issued_at: float

    def active(self, now: float) -> bool:
        return self.issued_at <= now < self.issued_at + self.duration


ConditionsHold = Callable[[list[Condition], Any], Awaitable[bool]]


def now() -> float:
    return time.time()
