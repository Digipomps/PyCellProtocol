from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Mapping
from uuid import uuid4

from .value import JSONValue, from_json_value, to_json_value


class ConfigurationError(ValueError):
    pass


SUPPORTED_SKELETON_ELEMENTS: set[str] = {
    "List",
    "Object",
    "Spacer",
    "Image",
    "Text",
    "AttachmentField",
    "FileUpload",
    "TextField",
    "TextArea",
    "HStack",
    "VStack",
    "Reference",
    "Button",
    "Divider",
    "ScrollView",
    "Section",
    "Tabs",
    "ZStack",
    "Grid",
    "Toggle",
    "Picker",
    "Visualization",
}


@dataclass
class SkeletonElement:
    kind: str
    payload: Any

    @classmethod
    def from_json(cls, value: Any) -> "SkeletonElement":
        if isinstance(value, Mapping) and len(value) == 1:
            kind = next(iter(value.keys()))
            if kind in SUPPORTED_SKELETON_ELEMENTS:
                return cls(kind, from_json_value(value[kind]))
        if isinstance(value, Mapping) and "elements" in value:
            return cls("Object", from_json_value(value))
        raise ConfigurationError(f"Unsupported skeleton element: {value!r}")

    def to_json(self) -> dict[str, JSONValue]:
        return {self.kind: to_json_value(self.payload)}

    def keypaths(self) -> set[str]:
        found: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, Mapping):
                for key, value in node.items():
                    if key.endswith("keypath") or key.endswith("Keypath") or key == "keypath":
                        if isinstance(value, str):
                            found.add(value)
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(self.payload)
        return found


@dataclass
class CellConfigurationDiscovery:
    sourceCellEndpoint: str | None = None
    sourceCellName: str | None = None
    purpose: str | None = None
    purposeDescription: str | None = None
    interests: list[str] = field(default_factory=list)
    purposeRefs: list[str] = field(default_factory=list)
    interestRefs: list[str] = field(default_factory=list)
    menuSlots: list[str] = field(default_factory=list)
    localizedText: dict[str, JSONValue] = field(default_factory=dict)

    @classmethod
    def from_json(cls, payload: Mapping[str, Any] | None) -> "CellConfigurationDiscovery":
        if not payload:
            return cls()
        return cls(
            sourceCellEndpoint=_string(payload.get("sourceCellEndpoint")),
            sourceCellName=_string(payload.get("sourceCellName")),
            purpose=_string(payload.get("purpose")),
            purposeDescription=_string(payload.get("purposeDescription")),
            interests=_string_list(payload.get("interests")),
            purposeRefs=_refs(payload.get("purposeRefs")),
            interestRefs=_refs(payload.get("interestRefs")),
            menuSlots=_string_list(payload.get("menuSlots")),
            localizedText=from_json_value(payload.get("localizedText", {})),
        )

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "sourceCellEndpoint": self.sourceCellEndpoint,
            "sourceCellName": self.sourceCellName,
            "purpose": self.purpose,
            "purposeDescription": self.purposeDescription,
            "interests": self.interests,
            "purposeRefs": _refs(self.purposeRefs),
            "interestRefs": _refs(self.interestRefs),
            "menuSlots": self.menuSlots,
            "localizedText": self.localizedText,
        }


@dataclass
class CellReference:
    endpoint: str
    subscribeFeed: bool = True
    label: str = ""
    subscriptions: list["CellReference"] = field(default_factory=list)
    setKeysAndValues: list[Any] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.label}:{self.endpoint}"

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "CellReference":
        endpoint = _string(payload.get("endpoint"))
        if not endpoint:
            raise ConfigurationError("CellReference requires endpoint")
        return cls(
            endpoint=endpoint,
            subscribeFeed=bool(payload.get("subscribeFeed", True)),
            label=_string(payload.get("label")) or "",
            subscriptions=[
                cls.from_json(item)
                for item in payload.get("subscriptions", []) or []
                if isinstance(item, Mapping)
            ],
            setKeysAndValues=from_json_value(payload.get("setKeysAndValues", []) or []),
        )

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "endpoint": self.endpoint,
            "subscribeFeed": self.subscribeFeed,
            "label": self.label,
            "subscriptions": [item.to_json() for item in self.subscriptions],
            "setKeysAndValues": to_json_value(self.setKeysAndValues),
        }


@dataclass
class CellConfiguration:
    name: str
    uuid: str = field(default_factory=lambda: str(uuid4()))
    description: str | None = None
    discovery: CellConfigurationDiscovery = field(default_factory=CellConfigurationDiscovery)
    cellReferences: list[CellReference] = field(default_factory=list)
    skeleton: SkeletonElement | None = field(
        default_factory=lambda: SkeletonElement("Text", {"text": "Hello HAVEN"})
    )

    CURRENT_SKELETON_ELEMENTS: ClassVar[set[str]] = SUPPORTED_SKELETON_ELEMENTS

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "CellConfiguration":
        name = _string(payload.get("name"))
        if not name:
            raise ConfigurationError("CellConfiguration requires name")
        raw_uuid = _string(payload.get("uuid")) or str(uuid4())
        raw_skeleton = payload.get("skeleton")
        return cls(
            name=name,
            uuid=raw_uuid,
            description=_string(payload.get("description")),
            discovery=CellConfigurationDiscovery.from_json(payload.get("discovery")),
            cellReferences=[
                CellReference.from_json(item)
                for item in payload.get("cellReferences", []) or []
                if isinstance(item, Mapping)
            ],
            skeleton=SkeletonElement.from_json(raw_skeleton) if raw_skeleton is not None else None,
        )

    def to_json(self) -> dict[str, JSONValue]:
        output: dict[str, JSONValue] = {
            "uuid": self.uuid,
            "name": self.name,
            "description": self.description,
            "discovery": self.discovery.to_json(),
            "cellReferences": [item.to_json() for item in self.cellReferences],
        }
        if self.skeleton is not None:
            output["skeleton"] = self.skeleton.to_json()
        return output

    def skeleton_keypaths(self) -> set[str]:
        return self.skeleton.keypaths() if self.skeleton else set()


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _refs(value: Any) -> list[str]:
    refs = [item.strip() for item in _string_list(value) if item.strip()]
    return sorted(set(refs))
