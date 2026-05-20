from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SCHEMA_VERSION = "haven.entity-anchor-data.v1"
SUPPORTED_SCOPES = ["all", "profile", "conference", "agreement", "identity", "sprout", "binding", "audit"]


def descriptor(
    path: str,
    title: str,
    description: str,
    value_type: str,
    visibility_class: str,
    scopes: list[str],
    tags: list[str],
    derived: bool = False,
    mutability: str = "read-write",
    source_of_truth: str = "EntityAnchorCell",
    sprout_refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "path": path,
        "title": title,
        "description": description,
        "value_type": value_type,
        "visibility_class": visibility_class,
        "storage_domain": "entity-anchor",
        "owner": "owner",
        "mutability": mutability,
        "source_of_truth": source_of_truth,
        "derived": derived,
        "autocomplete_safe": True,
        "autocomplete_scopes": scopes,
        "tags": tags,
        "sprout_refs": sprout_refs or [],
        "safety_note": "Path metadata is safe for autocomplete; value reads require CellProtocol grants.",
    }


KEYPATHS = [
    descriptor("person", "Person root", "Owner-controlled profile data root.", "object", "private", ["profile"], ["person", "profile"]),
    descriptor("person.displayName", "Display name", "Human-facing display name when explicitly granted or published.", "string", "consent", ["profile"], ["display", "profile"]),
    descriptor("person.contact.email", "Email", "Consent-bound email contact field.", "string", "consent", ["profile"], ["contact", "email"]),
    descriptor("person.contact.endpoints", "Contact endpoints", "Public-safe contact endpoint descriptors.", "array", "consent", ["profile", "binding"], ["contact", "endpoint"]),
    descriptor("purposes", "Purposes root", "Owner purpose and interest preferences.", "object", "private", ["agreement"], ["purpose", "interest"]),
    descriptor("relations", "Relations root", "Local relations, identities, issuers and relation handles.", "object", "private", ["identity", "sprout"], ["relation"]),
    descriptor("relations.identities", "Linked identities", "Local map of identity UUIDs to same-entity evidence.", "object", "private", ["identity", "sprout"], ["identity", "link"], sprout_refs=["EntityLinkContract"]),
    descriptor("proofs", "Proofs root", "Local proof records.", "object", "private", ["identity", "sprout"], ["proof"]),
    descriptor("proofs.identityLinks", "Identity link records", "Accepted local same-entity identity link records.", "object", "private", ["identity", "sprout"], ["identity", "link", "proof"], sprout_refs=["EntityLinkContract"]),
    descriptor("proofs.crossScaffoldContinuity", "Cross-scaffold continuity proofs", "Short-lived scaffold continuity proof records.", "object", "private", ["sprout"], ["continuity", "sprout"], sprout_refs=["CrossScaffoldEntityContinuityProof"]),
    descriptor("signedAgreementEntity", "Signed agreement records", "Canonical signed agreement records.", "object", "private", ["agreement"], ["agreement"]),
    descriptor("entityRepresentation", "Entity representation", "Lightweight matching and navigation representation.", "object", "private", ["binding"], ["representation"]),
    descriptor("agreements", "Agreement indexes", "Derived agreement indexes; do not edit directly.", "object", "private", ["agreement"], ["agreement"], derived=True, mutability="read-only"),
    descriptor("chronicle", "Chronicle", "Owner-local audit and history entries.", "array", "private", ["audit"], ["audit", "history"]),
    descriptor("bindings", "Bindings", "Route and binding metadata for cells and scaffolds.", "object", "private", ["binding"], ["binding"]),
]


SPROUT_MAPPINGS = [
    {
        "sprout_schema_id": "https://haven.local/sprout/schemas/EntityLinkContract.schema.json",
        "sprout_title": "EntityLinkContract",
        "local_entity_paths": ["proofs.identityLinks", "relations.identities"],
    },
    {
        "sprout_schema_id": "https://haven.local/sprout/schemas/CrossScaffoldEntityContinuityProof.schema.json",
        "sprout_title": "CrossScaffoldEntityContinuityProof",
        "local_entity_paths": ["proofs.crossScaffoldContinuity"],
    },
]


def contract() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "title": "EntityAnchorData v1",
        "summary": "Canonical autocomplete and schema registry for owner-local EntityAnchor keypaths. The registry exposes structure only, never stored entity values.",
        "safety": {
            "expose_values": False,
            "exposes_only_static_metadata": True,
            "value_preview_policy": "never",
            "public_endpoint_contains_personal_data": False,
            "notes": [
                "Autocomplete returns keypath descriptors only.",
                "Sprout entity_id values are resolver-scoped evidence fields, not global user identifiers.",
                "Paths marked private or consent still require CellProtocol grants before values can be read.",
            ],
        },
        "autocomplete_policy": {
            "default_scope": "all",
            "max_limit": 50,
            "supported_scopes": SUPPORTED_SCOPES,
            "matching_fields": ["path", "title", "description", "tags"],
        },
        "keypaths": KEYPATHS,
        "sprout_schema_mappings": SPROUT_MAPPINGS,
    }


def keypaths() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "keypaths": KEYPATHS, "count": len(KEYPATHS)}


def autocomplete(
    query: str = "",
    prefix: str = "",
    scope: str = "all",
    include_derived: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    normalized_query = query.strip().lower()
    normalized_prefix = prefix.strip().lower()
    normalized_scope = scope.strip().lower() or "all"
    bounded_limit = max(1, min(int(limit), 50))
    suggestions = []
    for item in KEYPATHS:
        if item["derived"] and not include_derived:
            continue
        if normalized_scope != "all" and normalized_scope not in item["autocomplete_scopes"]:
            continue
        if normalized_prefix and not item["path"].lower().startswith(normalized_prefix):
            continue
        haystack = " ".join([item["path"], item["title"], item["description"], *item["tags"]]).lower()
        if normalized_query and normalized_query not in haystack:
            continue
        suggestions.append(item)
        if len(suggestions) >= bounded_limit:
            break
    return {
        "schema_version": SCHEMA_VERSION,
        "query": query,
        "prefix": prefix,
        "scope": normalized_scope,
        "count": len(suggestions),
        "suggestions": suggestions,
    }


def sprout_map() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "sprout_schema_mappings": SPROUT_MAPPINGS}


def json_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://haven.local/cellscaffold/schemas/EntityAnchorData.v1.schema.json",
        "title": "EntityAnchorData v1",
        "description": "Owner-local EntityAnchor storage shape; structure only.",
        "type": "object",
        "additionalProperties": True,
        "properties": {item["path"].split(".")[0]: {"type": ["object", "array"]} for item in KEYPATHS},
    }
