"""Owner-issued, subject-bound contracts for unconditional Cell agreements."""

import base64
import json
import time
from dataclasses import dataclass, field
from uuid import uuid4

from .identity import Identity, identity_signing_fingerprint, verify_identity_signature

YEAR = 365 * 86400
BITS = (4, 2, 1, 8)


def permission_masks(value):
    if isinstance(value, str):
        value = value.strip()
        if len(value) in (3, 6):
            value = "".join(value[i : i + 3] + "-" for i in range(0, len(value), 3))
    if isinstance(value, str) and len(value) in (4, 8):
        groups = [value[:4], value[4:] or "----"]
        if all(
            c in ("-", label) for group in groups for c, label in zip(group, "rwxs")
        ):
            return tuple(
                sum(bit for bit, c in zip(BITS, group) if c != "-") for group in groups
            )
    if isinstance(value, dict):
        pair = value.get("group"), value.get("other")
        if all(type(n) is int and 0 <= n <= 15 for n in pair):
            return pair
    raise ValueError("Invalid grant permission")


@dataclass
class Grant:
    keypath: str
    permission: str
    uuid: str = field(default_factory=lambda: str(uuid4()))
    name: str = "Condition grant"
    permission_uuid: str = field(default_factory=lambda: str(uuid4()))

    def to_json(self):
        group, other = permission_masks(self.permission)
        return {
            "uuid": self.uuid,
            "name": self.name,
            "keypath": self.keypath,
            "permission": {
                "uuid": self.permission_uuid,
                "group": group,
                "other": other,
            },
        }


def covers(grant, requested):
    if grant["keypath"] != requested["keypath"]:
        return False
    allowed = permission_masks(grant["permission"])
    wanted = permission_masks(requested["permission"])
    return wanted[0] != 0 and all((a & b) == b for a, b in zip(allowed, wanted))


def public_identity(identity):
    result = identity.to_json()
    # A public descriptor omits vault references and private properties. Use
    # integral Foundation dates so Swift re-encoding preserves the signed bytes.
    result["properties"] = {}
    for name in ("publicSecureKey", "publicKeyAgreementSecureKey"):
        if name in result:
            result[name] = {**result[name], "date": int(result[name]["date"])}
    return result


def unconditional(agreement):
    return (
        agreement.get("conditions", []) == []
        and agreement.get("authorizationPolicyBinding") is None
    )


def derive(request, template, owner, subject):
    """Validate against the current template and rebuild the fields we sign."""
    if not isinstance(request, dict) or request.get("state") != "template":
        raise ValueError("Expected an Agreement template")
    if not unconditional(request) or not unconditional(template):
        raise ValueError("Unsupported agreement condition or policy binding")
    presented_owner = Identity.from_json(request["owner"])
    if (presented_owner.uuid, presented_owner.publicSecureKey) != (
        owner.uuid,
        owner.publicSecureKey,
    ):
        raise ValueError("Wrong agreement owner")
    duration = request.get("duration", YEAR)
    if type(duration) is not int or not 0 < duration <= min(template["duration"], YEAR):
        raise ValueError("Invalid agreement duration")
    grants = request["grants"]
    if not isinstance(grants, list) or not grants:
        raise ValueError("Invalid agreement grants")
    derived = []
    for grant in grants:
        if not isinstance(grant, dict) or not any(
            covers(g, grant) for g in template["grants"]
        ):
            raise ValueError("Grant outside template")
        group, other = permission_masks(grant["permission"])
        derived.append(
            {
                "name": "Condition grant",
                "uuid": str(uuid4()),
                "keypath": grant["keypath"],
                "permission": {"uuid": str(uuid4()), "group": group, "other": other},
            }
        )
    return {
        "uuid": str(uuid4()),
        "name": template["name"],
        "state": "signed",
        "owner": public_identity(owner),
        "signatories": [public_identity(owner), public_identity(subject)],
        "grants": derived,
        "duration": duration,
    }


def signing_bytes(contract):
    payload = {
        k: contract[k] for k in ("uuid", "agreement", "domain", "issuedAt", "expiresAt")
    }
    for role in ("issuer", "subject"):
        identity = Identity.from_json(contract[role])
        payload[role + "UUID"] = identity.uuid
        payload[role + "SigningKeyFingerprint"] = identity_signing_fingerprint(identity)
    # Swift Foundation JSONEncoder sortedKeys escapes slashes by default.
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        .replace("/", "\\/")
        .encode()
    )


async def issue(agreement, issuer, subject, domain):
    now = int(time.time())
    contract = {
        "uuid": str(uuid4()),
        "agreement": agreement,
        "domain": domain,
        "issuer": public_identity(issuer),
        "subject": public_identity(subject),
        "issuedAt": now,
        "expiresAt": now + agreement["duration"],
    }
    signature = await issuer.sign(signing_bytes(contract))
    contract["signature"] = base64.b64encode(signature).decode()
    return contract


def valid(contract, owner, subject, domain, template):
    # Installed contracts are local snapshots. Never authorize a caller-supplied
    # contract or trust an issuer carried by the wire without this binding.
    agreement = contract["agreement"]

    def same(wire, identity):
        return (
            wire["uuid"] == identity.uuid
            and Identity.from_json(wire).publicSecureKey == identity.publicSecureKey
        )

    now = time.time()
    return (
        unconditional(template)
        and unconditional(agreement)
        and domain == contract["domain"]
        and same(contract["issuer"], owner)
        and same(contract["subject"], subject)
        and same(agreement["owner"], owner)
        and agreement["state"] == "signed"
        and any(same(s, owner) for s in agreement["signatories"])
        and any(same(s, subject) for s in agreement["signatories"])
        and contract["issuedAt"] <= now <= contract["expiresAt"]
        and 0
        < agreement["duration"]
        == contract["expiresAt"] - contract["issuedAt"]
        <= template["duration"]
        and all(
            any(covers(t, g) for t in template["grants"]) for g in agreement["grants"]
        )
        and verify_identity_signature(
            base64.b64decode(contract["signature"], validate=True),
            signing_bytes(contract),
            owner,
        )
    )
