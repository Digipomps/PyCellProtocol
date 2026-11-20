"""Organizations owned by a group, as CellProtocol Swift does it.

An organization (`EntityKind.organization`) is sealed to a signed
`GovernancePolicy` that names its owners. Which actions one owner may take
alone and which need more is an ownership agreement, and it is data: the
agreement only builds the policy's signing rules. Changing owners or the
agreement is a new policy version in a hash chain, approved under the
previous version's amendment rule. The organization key never changes.

Owners approve a concrete `OrganizationActionProposal` with their own keys.
The organization key (held by the vault) signs role credentials and status
lists only once `evaluate` says a rule holds. A node checks a role
credential locally against a mirrored, signed status list; a missing or
stale mirror gives `unknown`, which fails closed.

Verdicts and error codes are the Swift case names, so every answer can be
compared case by case with `fixtures/interop/v1/org.*`.

Swift sources (CellProtocol `Sources/CellBase/Organization`):
`GovernancePolicy.swift`, `GovernancePolicyEvaluator.swift`,
`OrganizationApproval.swift`, `OwnershipAgreement.swift`,
`OrganizationGenesis.swift`, `OrganizationRoles.swift`; the role access check
follows `VerifiableCredentials/TrustedIssuerCell.swift`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from .canonical import canonical_payload
from .identity_link import VCClaim, VCProof, did_key, iso8601, parse_iso8601, public_key_from_did_key
from .models import (
    IdentityLinkFreshAuthEvidence,
    IdentityPublicKeyDescriptor,
    WireModel,
    _s,
)
from .verify import Signer, VerificationFailure, verify_signature


class OrganizationFailure(VerificationFailure):
    """A Swift `GovernanceEvaluationError`, `OrganizationGenesisError`,
    `GovernancePolicyChainError` or `OwnershipAgreementError` case name."""


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Action classes and roles
# ---------------------------------------------------------------------------

ROLE_ISSUE = "role.issue"
ROLE_REVOKE = "role.revoke"
ROLE_STATUS_PUBLISH = "role.status.publish"
POLICY_AMEND = "policy.amend"
ROLE_ACTIONS = [ROLE_ISSUE, ROLE_REVOKE, ROLE_STATUS_PUBLISH]
WILDCARD_ACTION = "*"

OWNER = "owner"


# ---------------------------------------------------------------------------
# Policy models
# ---------------------------------------------------------------------------


@dataclass
class MonetaryAmount(WireModel):
    minor_units: int
    currency: str

    SPECS = {"minor_units": _s("minorUnits", "int"), "currency": _s("currency")}


@dataclass
class ActionLimits(WireModel):
    max_amount: Optional[MonetaryAmount] = None

    SPECS = {"max_amount": _s("maxAmount", "model", model=MonetaryAmount, optional=True)}


@dataclass
class RoleCount(WireModel):
    role: str
    minimum: int

    SPECS = {"role": _s("role"), "minimum": _s("minimum", "int")}


@dataclass
class ApprovalClause(WireModel):
    requirements: list[RoleCount]
    distinct_persons: bool = True

    SPECS = {
        "requirements": _s("requirements", "models", model=RoleCount),
        "distinct_persons": _s("distinctPersons", "bool"),
    }


@dataclass
class SigningRule(WireModel):
    rule_id: str
    any_of: list[ApprovalClause]
    action_classes: list[str]
    excluded_actions: list[str] = field(default_factory=list)
    limits: Optional[ActionLimits] = None
    requires_fresh_auth: bool = False

    SPECS = {
        "rule_id": _s("ruleID"),
        "any_of": _s("anyOf", "models", model=ApprovalClause),
        "action_classes": _s("actionClasses", "strs"),
        "excluded_actions": _s("excludedActions", "strs"),
        "limits": _s("limits", "model", model=ActionLimits, optional=True),
        "requires_fresh_auth": _s("requiresFreshAuth", "bool"),
    }


@dataclass
class PolicyEvidenceReference(WireModel):
    kind: str
    reference: str

    SPECS = {"kind": _s("kind"), "reference": _s("reference")}


@dataclass
class OrganizationMember(WireModel):
    identity: IdentityPublicKeyDescriptor
    roles: list[str]
    valid_from: str
    valid_until: Optional[str] = None

    SPECS = {
        "identity": _s("identity", "model", model=IdentityPublicKeyDescriptor),
        "roles": _s("roles", "strs"),
        "valid_from": _s("validFrom"),
        "valid_until": _s("validUntil", optional=True),
    }


@dataclass
class GovernancePolicy(WireModel):
    policy_id: str
    version: int
    members: list[OrganizationMember]
    rules: list[SigningRule]
    amendment_rule_id: str
    valid_from: str
    evidence: list[PolicyEvidenceReference] = field(default_factory=list)
    previous_policy_hash: Optional[bytes] = None

    SPECS = {
        "policy_id": _s("policyID"),
        "version": _s("version", "int"),
        "previous_policy_hash": _s("previousPolicyHash", "bytes", optional=True),
        "members": _s("members", "models", model=OrganizationMember),
        "rules": _s("rules", "models", model=SigningRule),
        "amendment_rule_id": _s("amendmentRuleID"),
        "evidence": _s("evidence", "models", model=PolicyEvidenceReference),
        "valid_from": _s("validFrom"),
    }

    def policy_hash(self) -> bytes:
        return sha256(self.canonical_payload())

    def rule(self, rule_id: str) -> Optional[SigningRule]:
        return next((rule for rule in self.rules if rule.rule_id == rule_id), None)

    @property
    def owners(self) -> list[IdentityPublicKeyDescriptor]:
        return [member.identity for member in self.members if OWNER in member.roles]


# ---------------------------------------------------------------------------
# Ownership agreement
# ---------------------------------------------------------------------------

ROLES_RULE_ID = "roller"
GOVERNANCE_RULE_ID = "styring"
AGREEMENT_EVIDENCE_KIND = "ownershipAgreement"


@dataclass(frozen=True)
class OwnerQuorum:
    kind: str  # one | all | atLeast
    minimum: Optional[int] = None

    def required(self, owner_count: int) -> Optional[int]:
        """Owners needed among `owner_count`, or None when it cannot be met."""
        if owner_count < 1:
            return None
        if self.kind == "one":
            return 1
        if self.kind == "all":
            return owner_count
        if self.kind == "atLeast":
            if self.minimum is None or self.minimum < 1 or self.minimum > owner_count:
                return None
            return self.minimum
        return None


ONE = OwnerQuorum("one")
ALL = OwnerQuorum("all")


def at_least(minimum: int) -> OwnerQuorum:
    return OwnerQuorum("atLeast", minimum)


@dataclass(frozen=True)
class OwnershipAgreement:
    template_id: str
    roles: OwnerQuorum
    governance: OwnerQuorum

    def signing_rules(self, owner_count: int) -> list[SigningRule]:
        roles_required = self.roles.required(owner_count)
        if roles_required is None:
            raise OrganizationFailure("quorumCannotBeMet", ROLES_RULE_ID)
        governance_required = self.governance.required(owner_count)
        if governance_required is None:
            raise OrganizationFailure("quorumCannotBeMet", GOVERNANCE_RULE_ID)
        return [
            SigningRule(ROLES_RULE_ID, [ApprovalClause([RoleCount(OWNER, roles_required)])], list(ROLE_ACTIONS)),
            SigningRule(GOVERNANCE_RULE_ID, [ApprovalClause([RoleCount(OWNER, governance_required)])], [POLICY_AMEND]),
        ]


ROLES_ONE_GOVERNANCE_ALL = OwnershipAgreement("roles-one-governance-all", ONE, ALL)
ALL_TWO = OwnershipAgreement("all-two", at_least(2), at_least(2))
ONE_ALONE = OwnershipAgreement("one-alone", ONE, ONE)
TWO_OF_THREE = OwnershipAgreement("two-of-three", at_least(2), at_least(2))
TEMPLATES = [ROLES_ONE_GOVERNANCE_ALL, ALL_TWO, ONE_ALONE, TWO_OF_THREE]


def owner_group_policy(
    *,
    policy_id: str,
    owners: list[IdentityPublicKeyDescriptor],
    agreement: OwnershipAgreement,
    valid_from: str,
    version: int = 1,
    previous_policy_hash: Optional[bytes] = None,
    evidence: Iterable[PolicyEvidenceReference] = (),
    owner_valid_from: Optional[dict[str, str]] = None,
) -> GovernancePolicy:
    """`GovernancePolicy.ownerGroup`."""
    if not owners:
        raise OrganizationFailure("noOwners")
    seen: set[str] = set()
    for owner in owners:
        if owner.uuid in seen:
            raise OrganizationFailure("duplicateOwner", owner.uuid)
        seen.add(owner.uuid)
    starts = owner_valid_from or {}
    return GovernancePolicy(
        policy_id=policy_id,
        version=version,
        previous_policy_hash=previous_policy_hash,
        members=[OrganizationMember(owner, [OWNER], starts.get(owner.uuid, valid_from)) for owner in owners],
        rules=agreement.signing_rules(len(owners)),
        amendment_rule_id=GOVERNANCE_RULE_ID,
        evidence=[PolicyEvidenceReference(AGREEMENT_EVIDENCE_KIND, agreement.template_id), *evidence],
        valid_from=valid_from,
    )


# ---------------------------------------------------------------------------
# Proposals and approvals
# ---------------------------------------------------------------------------


@dataclass
class OrganizationActionProposal(WireModel):
    proposal_id: str
    organization_anchor_id: str
    policy_hash: bytes
    action_class: str
    payload_hash: bytes
    payload_summary: str
    audience: str
    created_at: str
    expires_at: str
    nonce: bytes
    proposer: IdentityPublicKeyDescriptor
    amount: Optional[MonetaryAmount] = None
    version: int = 1

    SPECS = {
        "version": _s("version", "int"),
        "proposal_id": _s("proposalID"),
        "organization_anchor_id": _s("organizationAnchorID"),
        "policy_hash": _s("policyHash", "bytes"),
        "action_class": _s("actionClass"),
        "payload_hash": _s("payloadHash", "bytes"),
        "payload_summary": _s("payloadSummary"),
        "amount": _s("amount", "model", model=MonetaryAmount, optional=True),
        "audience": _s("audience"),
        "created_at": _s("createdAt"),
        "expires_at": _s("expiresAt"),
        "nonce": _s("nonce", "bytes"),
        "proposer": _s("proposer", "model", model=IdentityPublicKeyDescriptor),
    }

    def proposal_hash(self) -> bytes:
        return sha256(self.canonical_payload())


@dataclass
class OrganizationApproval(WireModel):
    proposal_hash: bytes
    approver: IdentityPublicKeyDescriptor
    role: str
    decision: str  # approve | reject
    approved_at: str
    fresh_auth_evidence: Optional[IdentityLinkFreshAuthEvidence] = None
    signature: Optional[bytes] = None
    version: int = 1

    SPECS = {
        "version": _s("version", "int"),
        "proposal_hash": _s("proposalHash", "bytes"),
        "approver": _s("approver", "model", model=IdentityPublicKeyDescriptor),
        "role": _s("role"),
        "decision": _s("decision"),
        "approved_at": _s("approvedAt"),
        "fresh_auth_evidence": _s("freshAuthEvidence", "model", model=IdentityLinkFreshAuthEvidence, optional=True),
        "signature": _s("signature", "bytes", optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("signature",)

    def signature_is_valid(self) -> bool:
        return verify_signature(self.signature, self.canonical_payload(), self.approver)

    @classmethod
    def signed(
        cls,
        proposal: OrganizationActionProposal,
        approver: IdentityPublicKeyDescriptor,
        signer: Signer,
        approved_at: str,
        role: str = OWNER,
        decision: str = "approve",
    ) -> "OrganizationApproval":
        approval = cls(proposal.proposal_hash(), approver, role, decision, approved_at)
        approval.signature = signer(approval.canonical_payload())
        return approval


@dataclass
class ApprovalBundle(WireModel):
    proposal: OrganizationActionProposal
    approvals: list[OrganizationApproval]

    SPECS = {
        "proposal": _s("proposal", "model", model=OrganizationActionProposal),
        "approvals": _s("approvals", "models", model=OrganizationApproval),
    }


# ---------------------------------------------------------------------------
# Evaluator (GovernancePolicyEvaluator): pure, fails closed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GovernanceEvaluation:
    rule_id: str
    clause_index: int
    approver_uuids: list[str]

    @property
    def verdict(self) -> str:
        return f"met:{self.rule_id}:{self.clause_index}"


def _date(text: str) -> datetime:
    moment = parse_iso8601(text)
    if moment is None:
        raise OrganizationFailure("malformedTimestamp", text)
    return moment


def _moment(now: float | datetime) -> datetime:
    if isinstance(now, datetime):
        return now
    return datetime.fromtimestamp(now, tz=timezone.utc)


def evaluate(policy: GovernancePolicy, bundle: ApprovalBundle, now: float | datetime) -> GovernanceEvaluation:
    """`GovernancePolicyEvaluator.evaluate`: the rule and clause that bind the
    organization, or the first reason they do not. Nonce replay and fresh-auth
    evidence verification belong to the vault, not here."""
    moment = _moment(now)
    proposal = bundle.proposal
    if policy.policy_hash() != proposal.policy_hash:
        raise OrganizationFailure("policyHashMismatch")
    if not _date(proposal.created_at) <= moment:
        raise OrganizationFailure("proposalNotYetValid")
    if not moment <= _date(proposal.expires_at):
        raise OrganizationFailure("proposalExpired")

    proposal_hash = proposal.proposal_hash()
    valid: list[tuple[OrganizationMember, OrganizationApproval]] = []
    for approval in bundle.approvals:
        who = approval.approver.uuid
        if approval.proposal_hash != proposal_hash:
            raise OrganizationFailure("approvalForOtherProposal", who)
        if not approval.signature_is_valid():
            raise OrganizationFailure("approvalSignatureInvalid", who)
        member = next((m for m in policy.members if m.identity == approval.approver), None)
        if member is None:
            raise OrganizationFailure("approverNotMember", who)
        if approval.role not in member.roles:
            raise OrganizationFailure("approverLacksRole", who)
        approved_at = _date(approval.approved_at)
        if not (_date(member.valid_from) <= approved_at and (member.valid_until is None or approved_at <= _date(member.valid_until))):
            raise OrganizationFailure("approverNotValidAt", who)
        if approval.decision == "reject":
            raise OrganizationFailure("rejected", who)
        valid.append((member, approval))

    candidates = [
        rule for rule in policy.rules
        if proposal.action_class in rule.action_classes or WILDCARD_ACTION in rule.action_classes
    ]
    if not candidates:
        raise OrganizationFailure("noRuleCoversAction", proposal.action_class)

    first_gate: Optional[OrganizationFailure] = None
    first: Optional[OrganizationFailure] = None
    for rule in candidates:
        try:
            return _evaluate_rule(rule, proposal, valid)
        except OrganizationFailure as failure:
            if failure.code != "clauseNotSatisfied" and first_gate is None:
                first_gate = failure
            if first is None:
                first = failure
    raise first_gate or first or OrganizationFailure("noRuleCoversAction", proposal.action_class)


def _evaluate_rule(
    rule: SigningRule,
    proposal: OrganizationActionProposal,
    approvals: list[tuple[OrganizationMember, OrganizationApproval]],
) -> GovernanceEvaluation:
    # One vote per person per role. A person approving twice counts once.
    roles_by_person: dict[str, set[str]] = {}
    for member, approval in approvals:
        roles_by_person.setdefault(member.identity.uuid, set()).add(approval.role)

    match: Optional[tuple[int, set[str]]] = None
    for index, clause in enumerate(rule.any_of):
        people = _satisfiers(clause, roles_by_person)
        if people is not None:
            match = (index, people)
            break
    if match is None:
        raise OrganizationFailure("clauseNotSatisfied", rule.rule_id)
    if proposal.action_class in rule.excluded_actions:
        raise OrganizationFailure("actionExcluded", rule.rule_id)
    if rule.limits is not None and rule.limits.max_amount is not None:
        limit = rule.limits.max_amount
        amount = proposal.amount
        if amount is None or amount.currency != limit.currency or amount.minor_units > limit.minor_units:
            raise OrganizationFailure("amountExceedsLimit", rule.rule_id)
    if rule.requires_fresh_auth:
        for _, approval in approvals:
            if approval.fresh_auth_evidence is None:
                raise OrganizationFailure("freshAuthRequired", approval.approver.uuid)
    return GovernanceEvaluation(rule.rule_id, match[0], sorted(match[1]))


def _satisfiers(clause: ApprovalClause, roles_by_person: dict[str, set[str]]) -> Optional[set[str]]:
    if not all(requirement.minimum >= 1 for requirement in clause.requirements):
        return None
    slots = [requirement.role for requirement in clause.requirements for _ in range(requirement.minimum)]
    people = sorted(roles_by_person.items())
    used: set[str] = set()

    def fill(index: int) -> bool:
        if index == len(slots):
            return True
        for person, roles in people:
            if slots[index] not in roles:
                continue
            if clause.distinct_persons and person in used:
                continue
            inserted = person not in used
            used.add(person)
            if fill(index + 1):
                return True
            if inserted:
                used.discard(person)
        return False

    return set(used) if fill(0) else None


def bundle_verdict(policy: GovernancePolicy, bundle: ApprovalBundle, now: float | datetime) -> str:
    try:
        return evaluate(policy, bundle, now).verdict
    except OrganizationFailure as failure:
        return failure.code


# ---------------------------------------------------------------------------
# Genesis and the policy chain
# ---------------------------------------------------------------------------


@dataclass
class OrganizationFounderSignature(WireModel):
    founder: IdentityPublicKeyDescriptor
    signed_at: str
    signature: bytes

    SPECS = {
        "founder": _s("founder", "model", model=IdentityPublicKeyDescriptor),
        "signed_at": _s("signedAt"),
        "signature": _s("signature", "bytes"),
    }


@dataclass
class OrganizationGenesisSeal(WireModel):
    anchor_id: str
    display_name: str
    initial_policy_hash: bytes
    custodian_key: IdentityPublicKeyDescriptor
    founders: list[IdentityPublicKeyDescriptor]
    sealed_at: str
    signatures: list[OrganizationFounderSignature] = field(default_factory=list)
    legal_identifier: Optional[str] = None
    kind: str = "organization"
    version: int = 1

    SPECS = {
        "version": _s("version", "int"),
        "kind": _s("kind"),
        "anchor_id": _s("anchorID"),
        "display_name": _s("displayName"),
        "legal_identifier": _s("legalIdentifier", optional=True),
        "initial_policy_hash": _s("initialPolicyHash", "bytes"),
        "custodian_key": _s("custodianKey", "model", model=IdentityPublicKeyDescriptor),
        "founders": _s("founders", "models", model=IdentityPublicKeyDescriptor),
        "sealed_at": _s("sealedAt"),
        "signatures": _s("signatures", "models", model=OrganizationFounderSignature),
    }
    EXCLUDED_FROM_SIGNATURE = ("signatures",)

    def seal_hash(self) -> bytes:
        return sha256(self.canonical_payload())

    def sign(self, founder: IdentityPublicKeyDescriptor, signer: Signer, signed_at: str) -> None:
        if founder not in self.founders:
            raise OrganizationFailure("unexpectedSigner", founder.uuid)
        signature = signer(self.canonical_payload())
        self.signatures = [entry for entry in self.signatures if entry.founder != founder]
        self.signatures.append(OrganizationFounderSignature(founder, signed_at, signature))

    def verify(self, initial_policy: GovernancePolicy) -> None:
        """`OrganizationGenesisSeal.verify(initialPolicy:)`. Fails closed."""
        if self.kind != "organization" or not self.founders:
            raise OrganizationFailure("noFounders")
        if initial_policy.version != 1:
            raise OrganizationFailure("initialPolicyMustBeVersionOne")
        if initial_policy.previous_policy_hash is not None:
            raise OrganizationFailure("initialPolicyHasPredecessor")
        if initial_policy.policy_hash() != self.initial_policy_hash:
            raise OrganizationFailure("policyHashMismatch")
        owners = initial_policy.owners
        for founder in self.founders:
            if founder not in owners:
                raise OrganizationFailure("founderNotOwner", founder.uuid)
        for owner in owners:
            if owner not in self.founders:
                raise OrganizationFailure("ownerNotFounder", owner.uuid)
        payload = self.canonical_payload()
        for entry in self.signatures:
            if entry.founder not in self.founders:
                raise OrganizationFailure("unexpectedSigner", entry.founder.uuid)
        for founder in self.founders:
            entry = next((item for item in self.signatures if item.founder == founder), None)
            if entry is None:
                raise OrganizationFailure("founderSignatureMissing", founder.uuid)
            if not verify_signature(entry.signature, payload, founder):
                raise OrganizationFailure("founderSignatureInvalid", founder.uuid)


def seal_verdict(seal: OrganizationGenesisSeal, initial_policy: GovernancePolicy) -> str:
    try:
        seal.verify(initial_policy)
    except OrganizationFailure as failure:
        return failure.code
    return "valid"


def amendment_summary(current: GovernancePolicy, nxt: GovernancePolicy) -> str:
    """`GovernancePolicyAmendment.summary`: plain Norwegian, from the policies only."""
    before = {owner.uuid for owner in current.owners}
    after = {owner.uuid for owner in nxt.owners}
    added = [owner.display_name or owner.uuid for owner in nxt.owners if owner.uuid not in before]
    removed = [owner.display_name or owner.uuid for owner in current.owners if owner.uuid not in after]
    parts = [f"Policy v{current.version} → v{nxt.version}."]
    if added:
        parts.append(f"Ny eier: {', '.join(added)}.")
    if removed:
        parts.append(f"Fjernet eier: {', '.join(removed)}.")
    agreement_before = next((e.reference for e in current.evidence if e.kind == AGREEMENT_EVIDENCE_KIND), None)
    agreement_after = next((e.reference for e in nxt.evidence if e.kind == AGREEMENT_EVIDENCE_KIND), None)
    if agreement_before != agreement_after and agreement_after is not None:
        parts.append(f"Eierskapsavtale: {agreement_after}.")
    return " ".join(parts)


def amendment_proposal(
    current: GovernancePolicy,
    nxt: GovernancePolicy,
    *,
    organization_anchor_id: str,
    proposer: IdentityPublicKeyDescriptor,
    proposal_id: str,
    created_at: str,
    expires_at: str,
    nonce: bytes,
) -> OrganizationActionProposal:
    return OrganizationActionProposal(
        proposal_id=proposal_id,
        organization_anchor_id=organization_anchor_id,
        policy_hash=current.policy_hash(),
        action_class=POLICY_AMEND,
        payload_hash=nxt.policy_hash(),
        payload_summary=amendment_summary(current, nxt),
        audience=organization_anchor_id,
        created_at=created_at,
        expires_at=expires_at,
        nonce=nonce,
        proposer=proposer,
    )


def _decision_time(bundle: ApprovalBundle) -> datetime:
    times = [moment for moment in (parse_iso8601(a.approved_at) for a in bundle.approvals) if moment is not None]
    if times:
        return max(times)
    return parse_iso8601(bundle.proposal.created_at) or datetime.min.replace(tzinfo=timezone.utc)


def verify_amendment(current: GovernancePolicy, nxt: GovernancePolicy, bundle: ApprovalBundle, organization_anchor_id: str) -> None:
    """`GovernancePolicyChain.verify(step:replacing:organizationAnchorID:)`."""
    proposal = bundle.proposal
    if nxt.policy_id != current.policy_id:
        raise OrganizationFailure("policyIDChanged")
    if nxt.version != current.version + 1:
        raise OrganizationFailure("versionNotNext")
    if nxt.previous_policy_hash != current.policy_hash():
        raise OrganizationFailure("previousHashMismatch")
    if proposal.organization_anchor_id != organization_anchor_id:
        raise OrganizationFailure("proposalNotForThisOrganization")
    if proposal.action_class != POLICY_AMEND:
        raise OrganizationFailure("proposalIsNotAnAmendment", proposal.action_class)
    if proposal.policy_hash != current.policy_hash():
        raise OrganizationFailure("proposalNotUnderPreviousPolicy")
    if proposal.payload_hash != nxt.policy_hash():
        raise OrganizationFailure("payloadIsNotTheNewPolicy")
    try:
        evaluation = evaluate(current, bundle, _decision_time(bundle))
    except OrganizationFailure as failure:
        raise OrganizationFailure("approvalsRefused", failure.code) from failure
    if evaluation.rule_id != current.amendment_rule_id:
        raise OrganizationFailure("amendmentRuleNotUsed", evaluation.rule_id)


def verify_chain(
    seal: OrganizationGenesisSeal,
    initial_policy: GovernancePolicy,
    amendments: Iterable[tuple[GovernancePolicy, ApprovalBundle]],
) -> GovernancePolicy:
    """`GovernancePolicyChain.verify`: the policy in force, or the first failure."""
    seal.verify(initial_policy)
    current = initial_policy
    for nxt, bundle in amendments:
        verify_amendment(current, nxt, bundle, seal.anchor_id)
        current = nxt
    return current


# ---------------------------------------------------------------------------
# Role credentials and status lists
# ---------------------------------------------------------------------------

GENERIC_ROLE_TYPE = "OrganizationRoleCredential"
FIELD_ORGANIZATION = "organization"
FIELD_ROLE = "role"
FIELD_COHORT = "cohort"
FIELD_VALID_UNTIL = "validUntil"
FIELD_POLICY_HASH = "policyHash"
VC_CONTEXT = ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"]


def unsigned_role_credential(
    *,
    organization_anchor_id: str,
    credential_type: str,
    custodian: IdentityPublicKeyDescriptor,
    subject: IdentityPublicKeyDescriptor,
    role: str,
    cohort: Optional[str],
    valid_until: str,
    policy_hash: bytes,
    issued_at: float,
    claim_uuid: str,
) -> VCClaim:
    """`OrganizationRoleCredential.unsigned`: what the owners approve."""
    import base64

    body: dict[str, Any] = {
        FIELD_ORGANIZATION: organization_anchor_id,
        FIELD_ROLE: role,
        FIELD_VALID_UNTIL: valid_until,
        FIELD_POLICY_HASH: base64.b64encode(policy_hash).decode("ascii"),
        "id": did_key(subject),
    }
    if cohort is not None:
        body[FIELD_COHORT] = cohort
    return VCClaim(
        context=list(VC_CONTEXT),
        id=f"cell:///identity/{subject.uuid}/claims/{claim_uuid}",
        type=["VerifiableCredential", GENERIC_ROLE_TYPE, credential_type],
        issuer=did_key(custodian),
        issuance_date=iso8601(issued_at),
        credential_subject=body,
        proof=VCProof(type="Ed25519Signature2020", created=iso8601(issued_at),
                      proof_purpose="assertionMethod", verification_method=custodian.uuid),
    )


def role_payload_hash(claim: VCClaim) -> bytes:
    return sha256(claim.unsigned_bytes())


def role_summary(claim: VCClaim, display_name: str) -> str:
    """`OrganizationRoleCredential.summary`: what the owner is shown."""
    subject = claim.credential_subject

    def text(key: str) -> Optional[str]:
        value = subject.get(key)
        return value if isinstance(value, str) else None

    out = f"{display_name} gir rollen «{text(FIELD_ROLE) or '?'}» til {text('id') or '?'}"
    cohort = text(FIELD_COHORT)
    if cohort is not None:
        out += f" i kullet {cohort}"
    return out + f", gyldig til {text(FIELD_VALID_UNTIL) or '?'}."


def _descriptor_from_did(did: str) -> Optional[IdentityPublicKeyDescriptor]:
    try:
        curve, key = public_key_from_did_key(did)
    except ValueError:
        return None
    algorithm = {"Curve25519": "EdDSA", "P256": "ECDSA"}.get(curve)
    if algorithm is None:
        return None
    return IdentityPublicKeyDescriptor(uuid=did, public_key=key, algorithm=algorithm, curve_type=curve)


def verify_role_credential(claim: VCClaim) -> bool:
    """`VCClaim.verify()`: the key comes from the issuer's did:key."""
    if not isinstance(claim.issuer, str):
        return False
    descriptor = _descriptor_from_did(claim.issuer)
    if descriptor is None:
        return False
    expected = {"Curve25519": "Ed25519Signature2020", "P256": "EcdsaSecp256r1Signature2019"}[descriptor.curve_type]
    return (
        claim.proof.proof_purpose == "assertionMethod"
        and 0 < len(claim.proof.signature_data) <= 512
        and claim.proof.type == expected
        and verify_signature(claim.proof.signature_data, claim.unsigned_bytes(), descriptor)
    )


@dataclass
class OrganizationRoleStatusList(WireModel):
    organization_anchor_id: str
    issuer_did: str
    sequence: int
    issued_at: str
    revoked_credential_ids: list[str]
    signature: Optional[bytes] = None
    version: int = 1

    SPECS = {
        "version": _s("version", "int"),
        "organization_anchor_id": _s("organizationAnchorID"),
        "issuer_did": _s("issuerDID"),
        "sequence": _s("sequence", "int"),
        "issued_at": _s("issuedAt"),
        "revoked_credential_ids": _s("revokedCredentialIDs", "strs"),
        "signature": _s("signature", "bytes", optional=True),
    }
    EXCLUDED_FROM_SIGNATURE = ("signature",)

    @classmethod
    def make(cls, *, organization_anchor_id: str, issuer_did: str, sequence: int, issued_at: str,
             revoked_credential_ids: Iterable[str]) -> "OrganizationRoleStatusList":
        """Like the Swift initializer: revoked ids deduplicated and sorted."""
        return cls(organization_anchor_id, issuer_did, sequence, issued_at, sorted(set(revoked_credential_ids)))

    def payload_hash(self) -> bytes:
        return sha256(self.canonical_payload())

    def signature_is_valid(self) -> bool:
        descriptor = _descriptor_from_did(self.issuer_did)
        return descriptor is not None and verify_signature(self.signature, self.canonical_payload(), descriptor)

    def summary(self, display_name: str, newly_revoked: list[str]) -> str:
        return (f"{display_name} trekker tilbake {len(newly_revoked)} rolle(r): "
                f"{', '.join(sorted(newly_revoked))}. Statusliste nr. {self.sequence}.")


DEFAULT_MAXIMUM_AGE = 600.0


class CredentialStatusRegistry:
    """The node's mirror of each issuer's latest status list. Checks are local."""

    def __init__(self) -> None:
        self._mirrors: dict[str, tuple[OrganizationRoleStatusList, float]] = {}

    def accept(self, status_list: OrganizationRoleStatusList, now: float) -> None:
        if not status_list.signature_is_valid():
            raise OrganizationFailure("signatureInvalid")
        current = self._mirrors.get(status_list.issuer_did)
        if current is not None:
            if current[0] == status_list:
                self._mirrors[status_list.issuer_did] = (current[0], now)
                return
            if status_list.sequence <= current[0].sequence:
                raise OrganizationFailure("sequenceNotNewer", f"{current[0].sequence}>={status_list.sequence}")
        self._mirrors[status_list.issuer_did] = (status_list, now)

    def has_mirror(self, issuer_did: str) -> bool:
        return issuer_did in self._mirrors

    def status(self, issuer_did: str, credential_id: str, now: float, maximum_age: float = DEFAULT_MAXIMUM_AGE) -> str:
        mirror = self._mirrors.get(issuer_did)
        if mirror is None or now - mirror[1] > maximum_age:
            return "unknown"
        return "revoked" if credential_id in mirror[0].revoked_credential_ids else "valid"


# ---------------------------------------------------------------------------
# Role access (the TrustedIssuer checks a role condition depends on)
# ---------------------------------------------------------------------------

HARD_FAILURES = {
    "issuer_not_registered_or_inactive",
    "issuer_context_not_allowed",
    "vc_type_missing",
    "vc_issuer_mismatch",
    "vc_credential_subject_missing",
    "revocation_check_failed",
    "revocation_check_unsupported",
    "revocation_status_unknown",
    "vc_subject_validity_expired",
    "claim_subject_path_missing",
    "claim_predicate_not_met",
    "subject_binding_missing",
    "subject_binding_mismatch",
    "vc_signature_invalid",
}


def subject_valid_until(subject: dict[str, Any]) -> tuple[bool, Optional[float]]:
    """(present, epoch). Present but unreadable gives (True, None): fails closed.
    A plain date means the end of that day in UTC."""
    if FIELD_VALID_UNTIL not in subject:
        return False, None
    raw = subject[FIELD_VALID_UNTIL]
    if not isinstance(raw, str):
        return True, None
    moment = parse_iso8601(raw)
    if moment is not None:
        return True, moment.timestamp()
    try:
        day = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return True, None
    if len(raw) != 10:
        return True, None
    return True, (day + timedelta(seconds=86_399)).timestamp()


@dataclass(frozen=True)
class RoleAccessDecision:
    decision: str  # trusted | untrusted
    reasons: list[str]


def role_access(
    claim: VCClaim,
    *,
    trusted_issuers: dict[str, list[str]],
    context_id: str,
    requester_did: str,
    required_type: str,
    expected_role: str,
    registry: CredentialStatusRegistry,
    now: float,
    require_revocation_check: bool = True,
) -> RoleAccessDecision:
    """Does `claim` open a cell whose Agreement condition asks for `expected_role`?

    Mirrors the TrustedIssuerCell checks a `ProvedClaimCondition` relies on:
    issuer registered for the context, credential type, signature, subject
    binding, the signed `validUntil`, the mirrored status list, and the role.
    The same reason codes as Swift; any hard failure makes it untrusted.
    """
    reasons: list[str] = []
    issuer = claim.issuer if isinstance(claim.issuer, str) else None
    contexts = trusted_issuers.get(issuer or "")
    if contexts is None:
        return RoleAccessDecision("untrusted", ["issuer_not_registered_or_inactive"])
    if context_id not in contexts:
        return RoleAccessDecision("untrusted", ["issuer_context_not_allowed"])
    if required_type not in claim.type:
        reasons.append("vc_type_missing")
    subject = claim.credential_subject
    present, until = subject_valid_until(subject)
    if present:
        reasons.append("vc_subject_validity_ok" if until is not None and until >= now else "vc_subject_validity_expired")
    if require_revocation_check:
        if issuer is not None and registry.has_mirror(issuer) and isinstance(claim.id, str):
            status = registry.status(issuer, claim.id, now)
            reasons.append({"valid": "revocation_status_valid", "revoked": "revocation_check_failed",
                            "unknown": "revocation_status_unknown"}[status])
        else:
            reasons.append("revocation_check_unsupported")
    if FIELD_ROLE not in subject:
        reasons.append("claim_subject_path_missing")
    elif subject[FIELD_ROLE] != expected_role:
        reasons.append("claim_predicate_not_met")
    subject_id = subject.get("id")
    if not isinstance(subject_id, str) or not subject_id:
        reasons.append("subject_binding_missing")
    elif subject_id != requester_did:
        reasons.append("subject_binding_mismatch")
    reasons.append("vc_signature_valid" if verify_role_credential(claim) else "vc_signature_invalid")
    reasons.sort()
    trusted = not any(reason in HARD_FAILURES for reason in reasons)
    return RoleAccessDecision("trusted" if trusted else "untrusted", reasons)


ORGANIZATION_WIRE_TYPES: dict[str, type[WireModel]] = {
    cls.__name__: cls
    for cls in (
        GovernancePolicy,
        OrganizationGenesisSeal,
        OrganizationActionProposal,
        OrganizationApproval,
        ApprovalBundle,
        OrganizationRoleStatusList,
    )
}
