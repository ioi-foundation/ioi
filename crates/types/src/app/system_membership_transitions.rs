//! Named membership transitions for a live bounded System (M2 root child).
//!
//! The membership plane owns the observed side of the desired-versus-observed
//! topology: node admission, readiness attestation, catch-up advancement, role
//! promotion, drain, and removal compile as strict compare-and-swap steps over
//! the exact durable membership record set. Desired topology is a distinct
//! owner-authorized record and never fabricates any observed field; every
//! admission input here is resolved from trusted server truth, never asserted
//! by the caller (INV-37). Writer authority is deliberately not admissible in
//! this family: writer promotion belongs to the governed writer-epoch
//! transition family with fencing and continuity CAS.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;

use super::system_activation::{jcs_hash, namespace, required_string};

/// Registered desired-topology contract (the DESIRED side).
pub const DESIRED_TOPOLOGY_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-desired-topology/v1";
/// Registered per-node observed membership record contract.
pub const NODE_MEMBERSHIP_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-node-membership/v1";
/// Registered membership compare-and-swap transition contract.
pub const MEMBERSHIP_TRANSITION_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-membership-transition/v1";

/// Content root domain of one timeless node membership record revision.
pub const MEMBERSHIP_RECORD_HASH_PROFILE: &str =
    "ioi.autonomous-system-node-membership-record-jcs-sha256.v1";
/// Content root domain of the live membership record set.
pub const MEMBERSHIP_SET_HASH_PROFILE: &str = "ioi.autonomous-system-membership-set-jcs-sha256.v1";
/// Operation commitment domain over the closed governed effect.
pub const MEMBERSHIP_OPERATION_HASH_PROFILE: &str =
    "ioi.autonomous-system-membership-operation-commitment-jcs-sha256.v1";
/// Content root domain of one admitted desired-topology record.
pub const DESIRED_TOPOLOGY_HASH_PROFILE: &str =
    "ioi.autonomous-system-desired-topology-jcs-sha256.v1";

const NODE_ROLES: [&str; 11] = [
    "admission_writer",
    "hot_standby",
    "state_replica",
    "projection_replica",
    "execution_worker",
    "artifact_replica",
    "verifier",
    "availability_witness",
    "gateway",
    "authority_member",
    "consensus_member",
];

/// Roles that admission may declare. Authority-bearing roles require a
/// governed promotion; the writer role is never admissible in this plane.
const ADMISSION_REFUSED_ROLES: [&str; 3] =
    ["admission_writer", "authority_member", "consensus_member"];

/// Named M2 membership operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipTransitionOp {
    /// Admit one authenticated node into the observed membership set.
    AdmitNode,
    /// Record an evidence-bound readiness posture for an admitted node.
    AttestReadiness,
    /// Advance the node's resolved catch-up watermark and verified root.
    AdvanceCatchup,
    /// Promote one governed non-writer role under a fresh one-use lease.
    PromoteRole,
    /// Open governed drain without removing the node.
    DrainNode,
    /// Remove a draining node; its final record survives as evidence.
    RemoveNode,
}

impl MembershipTransitionOp {
    /// Every membership operation in stable order.
    pub const ALL: [Self; 6] = [
        Self::AdmitNode,
        Self::AttestReadiness,
        Self::AdvanceCatchup,
        Self::PromoteRole,
        Self::DrainNode,
        Self::RemoveNode,
    ];

    /// Stable wire operation name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdmitNode => "admit_node",
            Self::AttestReadiness => "attest_readiness",
            Self::AdvanceCatchup => "advance_catchup",
            Self::PromoteRole => "promote_role",
            Self::DrainNode => "drain_node",
            Self::RemoveNode => "remove_node",
        }
    }

    /// Parse a stable wire operation name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == value)
    }

    /// Exact one-operation wallet scope.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::AdmitNode => "scope:autonomous_system.membership.admit_node",
            Self::AttestReadiness => "scope:autonomous_system.membership.attest_readiness",
            Self::AdvanceCatchup => "scope:autonomous_system.membership.advance_catchup",
            Self::PromoteRole => "scope:autonomous_system.membership.promote_role",
            Self::DrainNode => "scope:autonomous_system.membership.drain_node",
            Self::RemoveNode => "scope:autonomous_system.membership.remove_node",
        }
    }

    fn admits_predecessor(self, predecessor: Option<&str>) -> bool {
        match self {
            Self::AdmitNode => predecessor.is_none(),
            Self::AttestReadiness | Self::AdvanceCatchup => {
                matches!(predecessor, Some("admitted" | "active"))
            }
            Self::PromoteRole => predecessor == Some("active"),
            Self::DrainNode => matches!(predecessor, Some("admitted" | "active")),
            Self::RemoveNode => predecessor == Some("draining"),
        }
    }
}

/// Closed caller declaration. Fields irrelevant to the named operation are
/// rejected rather than silently ignored, so one operation cannot smuggle
/// another operation's evidence or lease.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipTransitionDeclaration {
    /// Exact node identity inside the System namespace.
    pub node_id: String,
    /// Caller's compare-and-swap view of the current membership set root.
    pub expected_membership_root: String,
    /// Per-transition evidence refs.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Admitting owner principal (admission only).
    #[serde(default)]
    pub node_owner_ref: Option<String>,
    /// Initial non-authority roles (admission only).
    #[serde(default)]
    pub roles: Vec<String>,
    /// Membership lease (admission only).
    #[serde(default)]
    pub membership_lease_ref: Option<String>,
    /// Node attestations (admission only).
    #[serde(default)]
    pub node_attestation_refs: Vec<String>,
    /// Declared posture, `ready` or `degraded` (attestation only).
    #[serde(default)]
    pub declared_readiness: Option<String>,
    /// Ref of the server-resolved readiness attestation (attestation only).
    #[serde(default)]
    pub readiness_attestation_ref: Option<String>,
    /// Declared watermark; must equal the resolved receipt (advance only).
    #[serde(default)]
    pub catchup_operation_offset: Option<u64>,
    /// Ref of the server-resolved catch-up receipt (advance only).
    #[serde(default)]
    pub catchup_receipt_ref: Option<String>,
    /// Governed target role (promotion only).
    #[serde(default)]
    pub target_role: Option<String>,
    /// Fresh one-use role lease (promotion only).
    #[serde(default)]
    pub role_lease_ref: Option<String>,
}

/// Exact durable identity coordinates resolved by the server, never the caller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MembershipIdentityBinding {
    /// Canonical System identity.
    pub system_id: String,
    /// Admitted genesis ref.
    pub genesis_ref: String,
    /// Live governing authority.
    pub source_governing_authority_ref: String,
    /// Live admitted deployment-profile revision ref.
    pub deployment_profile_ref: String,
    /// Live admitted deployment-profile revision root.
    pub deployment_profile_root: String,
    /// Live admitted constitution root.
    pub admitted_constitution_root: String,
    /// Live admitted manifest root.
    pub admitted_manifest_root: String,
}

/// Durable membership log head resolved from committed transitions only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MembershipLogHead {
    /// Last committed membership sequence; zero before the first admission.
    pub sequence: u64,
    /// Current membership set root derived from durable records.
    pub membership_root: String,
}

/// Pure server-derived plan for one named membership transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledMembershipTransitionPlan {
    /// Named operation.
    pub op: MembershipTransitionOp,
    /// Monotonic membership sequence.
    pub sequence: u64,
    /// Exact node identity.
    pub node_id: String,
    /// Exact node membership record identity.
    pub node_membership_ref: String,
    /// Predecessor record status, absent only at admission.
    pub predecessor_status: Option<String>,
    /// Derived resulting record status.
    pub resulting_status: String,
    /// Compare-and-swap predecessor membership set root.
    pub predecessor_membership_root: String,
    /// Derived resulting membership set root.
    pub resulting_membership_root: String,
    /// Predecessor record revision root, absent only at admission.
    pub predecessor_record_root: Option<String>,
    /// Derived resulting record revision root.
    pub resulting_record_root: String,
    /// Timeless resulting record body (volatile time fields null).
    pub resulting_record: Value,
    /// Closed effect authorized by wallet.network.
    pub authority_effect: Value,
}

fn canonical_ref(value: &str, prefixes: &[&str]) -> bool {
    !value.chars().any(char::is_whitespace)
        && value.len() <= 256
        && prefixes.iter().any(|prefix| value.starts_with(prefix))
}

fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn ensure_distinct(values: &[String], label: &str) -> Result<(), String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != values.len() {
        return Err(format!("{label} contains duplicate refs"));
    }
    Ok(())
}

/// Timeless material of one record revision: volatile observation timestamps
/// are outside the content root so the root is derivable before the wallet
/// clock exists and recomputable from any stored revision.
pub fn membership_record_root(record: &Value) -> Result<String, String> {
    let mut timeless = record.clone();
    if let Some(assignments) = timeless
        .get_mut("role_assignments")
        .and_then(Value::as_array_mut)
    {
        for assignment in assignments {
            assignment["valid_from"] = Value::Null;
        }
    }
    timeless["synchronization"]["verified_at"] = Value::Null;
    timeless["observation"]["last_heartbeat_at"] = Value::Null;
    timeless["observation"]["last_observed_at"] = Value::Null;
    timeless["observation"]["observation_expires_at"] = Value::Null;
    jcs_hash(&json!({
        "domain": MEMBERSHIP_RECORD_HASH_PROFILE,
        "record": timeless,
    }))
}

/// Set root over the exact live member records, sorted by node identity.
pub fn membership_set_root(system_id: &str, records: &[Value]) -> Result<String, String> {
    let mut members = Vec::with_capacity(records.len());
    for record in records {
        members.push((
            required_string(record, "/node_id")?.to_owned(),
            membership_record_root(record)?,
        ));
    }
    members.sort();
    let members: Vec<Value> = members
        .into_iter()
        .map(|(node_id, record_root)| json!({"node_id": node_id, "record_root": record_root}))
        .collect();
    jcs_hash(&json!({
        "domain": MEMBERSHIP_SET_HASH_PROFILE,
        "system_id": system_id,
        "members": members,
    }))
}

/// Content root of one admitted desired-topology record.
pub fn desired_topology_root(topology: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": DESIRED_TOPOLOGY_HASH_PROFILE,
        "topology": topology,
    }))
}

fn validate_declaration(
    op: MembershipTransitionOp,
    declaration: &MembershipTransitionDeclaration,
) -> Result<(), String> {
    ensure_distinct(&declaration.evidence_refs, "transition evidence")?;
    ensure_distinct(&declaration.node_attestation_refs, "node attestations")?;
    ensure_distinct(&declaration.roles, "declared roles")?;
    let evidence_prefixes = &["evidence://", "receipt://", "artifact://", "attestation://"][..];
    if declaration
        .evidence_refs
        .iter()
        .any(|value| !canonical_ref(value, evidence_prefixes))
    {
        return Err("transition evidence contains a non-canonical ref".to_owned());
    }
    if !canonical_hash(&declaration.expected_membership_root) {
        return Err("expected membership root is not canonical".to_owned());
    }

    let only = |allowed: &[&str]| {
        let present = [
            ("node_owner_ref", declaration.node_owner_ref.is_some()),
            ("roles", !declaration.roles.is_empty()),
            (
                "membership_lease_ref",
                declaration.membership_lease_ref.is_some(),
            ),
            (
                "node_attestation_refs",
                !declaration.node_attestation_refs.is_empty(),
            ),
            (
                "declared_readiness",
                declaration.declared_readiness.is_some(),
            ),
            (
                "readiness_attestation_ref",
                declaration.readiness_attestation_ref.is_some(),
            ),
            (
                "catchup_operation_offset",
                declaration.catchup_operation_offset.is_some(),
            ),
            (
                "catchup_receipt_ref",
                declaration.catchup_receipt_ref.is_some(),
            ),
            ("target_role", declaration.target_role.is_some()),
            ("role_lease_ref", declaration.role_lease_ref.is_some()),
        ];
        present
            .into_iter()
            .find(|(name, set)| *set && !allowed.contains(name))
            .map(|(name, _)| name)
    };
    let allowed = match op {
        MembershipTransitionOp::AdmitNode => &[
            "node_owner_ref",
            "roles",
            "membership_lease_ref",
            "node_attestation_refs",
        ][..],
        MembershipTransitionOp::AttestReadiness => {
            &["declared_readiness", "readiness_attestation_ref"][..]
        }
        MembershipTransitionOp::AdvanceCatchup => {
            &["catchup_operation_offset", "catchup_receipt_ref"][..]
        }
        MembershipTransitionOp::PromoteRole => &["target_role", "role_lease_ref"][..],
        MembershipTransitionOp::DrainNode | MembershipTransitionOp::RemoveNode => &[][..],
    };
    if let Some(field) = only(allowed) {
        return Err(format!("{field} is not admitted for {}", op.as_str()));
    }
    match op {
        MembershipTransitionOp::AdmitNode => {
            let owner_ok = declaration
                .node_owner_ref
                .as_deref()
                .is_some_and(|value| canonical_ref(value, &["wallet://", "org://", "project://"]));
            let lease_ok = declaration
                .membership_lease_ref
                .as_deref()
                .is_some_and(|value| canonical_ref(value, &["lease://"]));
            if !owner_ok || !lease_ok {
                return Err(
                    "admission requires a canonical node owner and membership lease".to_owned(),
                );
            }
            if declaration.roles.is_empty()
                || declaration
                    .roles
                    .iter()
                    .any(|role| !NODE_ROLES.contains(&role.as_str()))
            {
                return Err("admission requires roles from the closed node-role enum".to_owned());
            }
            if let Some(role) = declaration
                .roles
                .iter()
                .find(|role| ADMISSION_REFUSED_ROLES.contains(&role.as_str()))
            {
                return Err(format!(
                    "admission cannot declare authority-bearing role '{role}'"
                ));
            }
            if declaration
                .node_attestation_refs
                .iter()
                .any(|value| !canonical_ref(value, evidence_prefixes))
            {
                return Err("node attestations contain a non-canonical ref".to_owned());
            }
        }
        MembershipTransitionOp::AttestReadiness => {
            if !matches!(
                declaration.declared_readiness.as_deref(),
                Some("ready" | "degraded")
            ) {
                return Err("attestation requires a declared ready or degraded posture".to_owned());
            }
            if declaration
                .readiness_attestation_ref
                .as_deref()
                .is_none_or(|value| !canonical_ref(value, evidence_prefixes))
            {
                return Err("attestation requires one canonical attestation ref".to_owned());
            }
        }
        MembershipTransitionOp::AdvanceCatchup => {
            if declaration.catchup_operation_offset.is_none()
                || declaration
                    .catchup_receipt_ref
                    .as_deref()
                    .is_none_or(|value| !canonical_ref(value, &["receipt://"]))
            {
                return Err(
                    "catch-up requires the declared watermark and its receipt ref".to_owned(),
                );
            }
        }
        MembershipTransitionOp::PromoteRole => {
            let role_ok = declaration
                .target_role
                .as_deref()
                .is_some_and(|role| NODE_ROLES.contains(&role));
            let lease_ok = declaration
                .role_lease_ref
                .as_deref()
                .is_some_and(|value| canonical_ref(value, &["lease://"]));
            if !role_ok || !lease_ok {
                return Err("promotion requires a closed-enum role and a role lease".to_owned());
            }
        }
        MembershipTransitionOp::DrainNode | MembershipTransitionOp::RemoveNode => {}
    }
    Ok(())
}

fn validate_desired_topology(
    desired_topology: &Value,
    binding: &MembershipIdentityBinding,
) -> Result<String, String> {
    validate_architecture_contract(DESIRED_TOPOLOGY_CONTRACT, desired_topology)
        .map_err(|error| format!("desired topology is invalid: {error}"))?;
    if desired_topology.get("system_id").and_then(Value::as_str) != Some(&binding.system_id) {
        return Err("desired topology does not belong to this System".to_owned());
    }
    if desired_topology.get("status").and_then(Value::as_str) != Some("declared") {
        return Err("desired topology is not the declared record".to_owned());
    }
    if desired_topology
        .get("deployment_profile_ref")
        .and_then(Value::as_str)
        != Some(&binding.deployment_profile_ref)
        || desired_topology
            .get("deployment_profile_root")
            .and_then(Value::as_str)
            != Some(&binding.deployment_profile_root)
    {
        return Err(
            "desired topology is not bound to the live deployment profile revision".to_owned(),
        );
    }
    if desired_topology
        .get("asserts_observed_truth")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("desired topology may never assert observed truth".to_owned());
    }
    desired_topology_root(desired_topology)
}

fn node_record<'a>(records: &'a [Value], node_id: &str) -> Option<&'a Value> {
    records
        .iter()
        .find(|record| record.get("node_id").and_then(Value::as_str) == Some(node_id))
}

fn validate_current_records(
    records: &[Value],
    system_id: &str,
    node_namespace_prefix: &str,
) -> Result<(), String> {
    let mut seen = Vec::new();
    for record in records {
        validate_architecture_contract(NODE_MEMBERSHIP_CONTRACT, record)
            .map_err(|error| format!("durable membership record is invalid: {error}"))?;
        let node_id = required_string(record, "/node_id")?;
        if required_string(record, "/system_id")? != system_id {
            return Err("durable membership record detaches from the identity System".to_owned());
        }
        if !node_id.starts_with(node_namespace_prefix) {
            return Err("durable membership record names a foreign node".to_owned());
        }
        if matches!(
            required_string(record, "/status")?,
            "left" | "revoked" | "failed_closed"
        ) {
            return Err("durable live set retains a terminal membership record".to_owned());
        }
        seen.push(node_id.to_owned());
    }
    let count = seen.len();
    seen.sort();
    seen.dedup();
    if seen.len() != count {
        return Err("durable live set holds duplicate node identities".to_owned());
    }
    Ok(())
}

fn attested_readiness(
    declaration: &MembershipTransitionDeclaration,
    node: &Value,
    trusted_readiness_attestation: Option<&Value>,
) -> Result<String, String> {
    let attestation = trusted_readiness_attestation
        .ok_or("readiness attestation is not resolvable from durable truth")?;
    let declared = declaration
        .declared_readiness
        .as_deref()
        .ok_or("declared readiness is absent")?;
    if attestation.get("attestation_ref").and_then(Value::as_str)
        != declaration.readiness_attestation_ref.as_deref()
    {
        return Err("resolved attestation does not match the declared attestation ref".to_owned());
    }
    let bound_node = attestation.get("node_id").and_then(Value::as_str);
    let bound_epoch = attestation.get("membership_epoch").and_then(Value::as_u64);
    let node_epoch = node.get("membership_epoch").and_then(Value::as_u64);
    if bound_node != Some(required_string(node, "/node_id")?) || bound_epoch != node_epoch {
        return Err("readiness attestation is not bound to the admitted node identity".to_owned());
    }
    let current_root = node
        .pointer("/synchronization/verified_state_root")
        .and_then(Value::as_str);
    let attested_root = attestation
        .get("verified_state_root")
        .and_then(Value::as_str);
    if current_root.is_none() || attested_root != current_root {
        return Err(
            "readiness attestation is not bound to the node's current verified state root"
                .to_owned(),
        );
    }
    let attested = attestation
        .get("readiness")
        .and_then(Value::as_str)
        .ok_or("resolved attestation carries no readiness posture")?;
    if attested != declared {
        return Err(format!(
            "declared readiness '{declared}' contradicts the resolved attestation '{attested}'"
        ));
    }
    Ok(attested.to_owned())
}

/// Compile one named membership operation from exact durable owner inputs.
#[allow(clippy::too_many_arguments)]
pub fn compile_membership_transition_plan(
    op: MembershipTransitionOp,
    binding: &MembershipIdentityBinding,
    desired_topology: &Value,
    current_records: &[Value],
    head: &MembershipLogHead,
    consumed_role_lease_refs: &[String],
    declaration: &MembershipTransitionDeclaration,
    trusted_readiness_attestation: Option<&Value>,
    trusted_catchup_receipt: Option<&Value>,
) -> Result<CompiledMembershipTransitionPlan, String> {
    let ns = namespace(&binding.system_id)?;
    validate_declaration(op, declaration)?;
    let desired_root = validate_desired_topology(desired_topology, binding)?;
    let node_prefix = format!("node://{ns}/");
    validate_current_records(current_records, &binding.system_id, &node_prefix)?;

    // Branch 1 — foreign node: identity outside the System namespace.
    let node_tail = declaration
        .node_id
        .strip_prefix(node_prefix.as_str())
        .filter(|tail| {
            !tail.is_empty() && tail.len() <= 128 && !tail.chars().any(char::is_whitespace)
        })
        .ok_or("node identity is outside the System namespace")?;

    // Branch 2 / 7 — stale root and drain/removal races: strict CAS over the
    // exact derived durable set root.
    let derived_root = membership_set_root(&binding.system_id, current_records)?;
    if derived_root != head.membership_root {
        return Err("durable membership truth does not recompute to its committed root".to_owned());
    }
    if declaration.expected_membership_root != derived_root {
        return Err("stale predecessor membership root".to_owned());
    }

    if trusted_readiness_attestation.is_some() && op != MembershipTransitionOp::AttestReadiness {
        return Err("readiness attestation supplied to a non-attestation operation".to_owned());
    }
    if trusted_catchup_receipt.is_some() && op != MembershipTransitionOp::AdvanceCatchup {
        return Err("catch-up receipt supplied to a non-advance operation".to_owned());
    }

    let current = node_record(current_records, &declaration.node_id);
    let predecessor_status = current
        .map(|record| required_string(record, "/status").map(str::to_owned))
        .transpose()?;
    if !op.admits_predecessor(predecessor_status.as_deref()) {
        return Err(match &predecessor_status {
            Some(status) => format!("{} cannot lawfully leave {status}", op.as_str()),
            None => format!("{} requires an admitted member node", op.as_str()),
        });
    }
    let predecessor_record_root = current.map(membership_record_root).transpose()?;
    let sequence = head.sequence.checked_add(1).ok_or("sequence overflow")?;
    let node_membership_ref = format!("node-membership://{ns}/node/{node_tail}");

    let catchup_floor = desired_topology
        .pointer("/catchup_floor/minimum_operation_offset")
        .and_then(Value::as_u64)
        .ok_or("desired topology lacks its catch-up floor")?;

    let mut declared_readiness: Option<String> = None;
    let mut verified_state_root: Option<String> = None;

    let resulting_record = match op {
        MembershipTransitionOp::AdmitNode => {
            let roles: Vec<Value> = declaration
                .roles
                .iter()
                .map(|role| {
                    json!({
                        "role": role,
                        "role_scope_refs": [],
                        "authority_grant_refs": [],
                        "role_lease_ref": Value::Null,
                        "admitted_epoch": sequence,
                        "valid_from": Value::Null,
                        "expires_at": Value::Null,
                    })
                })
                .collect();
            json!({
                "schema_version": "ioi.autonomous-system-node-membership.v1",
                "node_membership_id": node_membership_ref,
                "system_id": binding.system_id,
                "deployment_profile_ref": binding.deployment_profile_ref,
                "node_id": declaration.node_id,
                "node_owner_ref": declaration.node_owner_ref,
                "membership_epoch": sequence,
                "membership_lease_ref": declaration.membership_lease_ref,
                "role_assignments": roles,
                "failure_domain_refs": [],
                "failure_independence_evidence_refs": [],
                "node_attestation_refs": declaration.node_attestation_refs,
                "conformance_profile_refs": [],
                "admission": {
                    "proposal_ref": format!("proposal://{ns}/membership/sequence/{sequence}"),
                    "decision_ref": format!("decision://{ns}/membership/sequence/{sequence}"),
                    "admitted_constitution_root": binding.admitted_constitution_root,
                    "admitted_manifest_root": binding.admitted_manifest_root,
                    "admitted_deployment_profile_root": binding.deployment_profile_root,
                },
                "synchronization": {
                    "checkpoint_ref": Value::Null,
                    "operation_offset": 0,
                    "verified_state_root": Value::Null,
                    "catchup_receipt_ref": Value::Null,
                    "verified_at": Value::Null,
                },
                "writer_fencing": {
                    "writer_epoch": Value::Null,
                    "writer_epoch_transition_ref": Value::Null,
                    "writer_epoch_transition_hash": Value::Null,
                    "writer_lease_ref": Value::Null,
                    "promotion_receipt_ref": Value::Null,
                },
                "observation": {
                    "readiness": "unknown",
                    "health_observation_ref": Value::Null,
                    "heartbeat_ref": Value::Null,
                    "readiness_evidence_refs": [],
                    "last_heartbeat_at": Value::Null,
                    "last_observed_at": Value::Null,
                    "observation_expires_at": Value::Null,
                },
                "status": "admitted",
            })
        }
        MembershipTransitionOp::AttestReadiness => {
            let node = current.expect("attestation predecessor was admitted");
            let attested = attested_readiness(declaration, node, trusted_readiness_attestation)?;
            // Branch 4 — skipped catch-up: ready is not claimable below the
            // declared floor of the admitted desired topology.
            if attested == "ready" {
                let offset = node
                    .pointer("/synchronization/operation_offset")
                    .and_then(Value::as_u64)
                    .ok_or("membership record lacks its catch-up watermark")?;
                if offset < catchup_floor {
                    return Err(
                        "readiness cannot be claimed before the declared catch-up floor".to_owned(),
                    );
                }
            }
            declared_readiness = Some(attested.clone());
            let mut record = node.clone();
            let attestation_ref = declaration
                .readiness_attestation_ref
                .clone()
                .expect("declaration was validated");
            let mut evidence = vec![json!(attestation_ref)];
            for reference in &declaration.evidence_refs {
                if !evidence.iter().any(|held| held == reference) {
                    evidence.push(json!(reference));
                }
            }
            record["observation"]["readiness"] = json!(attested);
            record["observation"]["readiness_evidence_refs"] = Value::Array(evidence);
            record["observation"]["last_observed_at"] = Value::Null;
            record["observation"]["observation_expires_at"] = Value::Null;
            // Branch 6 — degraded posture honesty: degraded is recorded as
            // degraded and never widens the status ladder.
            if attested == "ready" {
                record["status"] = json!("active");
            }
            record
        }
        MembershipTransitionOp::AdvanceCatchup => {
            let node = current.expect("advance predecessor was admitted");
            let receipt = trusted_catchup_receipt
                .ok_or("catch-up receipt is not resolvable from durable truth")?;
            if receipt.get("receipt_ref").and_then(Value::as_str)
                != declaration.catchup_receipt_ref.as_deref()
            {
                return Err(
                    "resolved catch-up receipt does not match the declared receipt ref".to_owned(),
                );
            }
            if receipt.get("node_id").and_then(Value::as_str) != Some(declaration.node_id.as_str())
            {
                return Err("catch-up receipt is not bound to the admitted node".to_owned());
            }
            let receipt_offset = receipt
                .get("operation_offset")
                .and_then(Value::as_u64)
                .ok_or("catch-up receipt carries no watermark")?;
            if Some(receipt_offset) != declaration.catchup_operation_offset {
                return Err("declared watermark contradicts the resolved receipt".to_owned());
            }
            let receipt_root = receipt
                .get("verified_state_root")
                .and_then(Value::as_str)
                .filter(|value| canonical_hash(value))
                .ok_or("catch-up receipt carries no canonical verified state root")?;
            let current_offset = node
                .pointer("/synchronization/operation_offset")
                .and_then(Value::as_u64)
                .ok_or("membership record lacks its catch-up watermark")?;
            if receipt_offset < current_offset {
                return Err("catch-up watermark cannot regress".to_owned());
            }
            verified_state_root = Some(receipt_root.to_owned());
            let mut record = node.clone();
            record["synchronization"]["operation_offset"] = json!(receipt_offset);
            record["synchronization"]["verified_state_root"] = json!(receipt_root);
            record["synchronization"]["catchup_receipt_ref"] =
                json!(declaration.catchup_receipt_ref);
            record["synchronization"]["verified_at"] = Value::Null;
            // A new verified root invalidates any prior readiness claim; the
            // posture reverts to syncing until re-attested against this root.
            record["observation"]["readiness"] = json!("syncing");
            record
        }
        MembershipTransitionOp::PromoteRole => {
            let node = current.expect("promotion predecessor was active");
            let target_role = declaration
                .target_role
                .as_deref()
                .expect("declaration was validated");
            // Writer authority is structurally not admissible here.
            if target_role == "admission_writer" {
                return Err(
                    "writer promotion requires a governed writer-epoch transition; it is not \
                     admissible in the membership plane"
                        .to_owned(),
                );
            }
            // Branch 6 — degraded posture honesty for promotion.
            if node
                .pointer("/observation/readiness")
                .and_then(Value::as_str)
                != Some("ready")
            {
                return Err("cannot promote a node whose observed posture is not ready".to_owned());
            }
            // Branch 4 — the catch-up floor also gates promotion.
            let offset = node
                .pointer("/synchronization/operation_offset")
                .and_then(Value::as_u64)
                .ok_or("membership record lacks its catch-up watermark")?;
            if offset < catchup_floor {
                return Err(
                    "promotion cannot be claimed before the declared catch-up floor".to_owned(),
                );
            }
            // Branch 5 — role-lease replay: a consumed or live lease never
            // authorizes another promotion.
            let lease = declaration
                .role_lease_ref
                .as_deref()
                .expect("declaration was validated");
            let live_lease = current_records.iter().any(|record| {
                record
                    .get("role_assignments")
                    .and_then(Value::as_array)
                    .is_some_and(|assignments| {
                        assignments.iter().any(|assignment| {
                            assignment.get("role_lease_ref").and_then(Value::as_str) == Some(lease)
                        })
                    })
                    || record.get("membership_lease_ref").and_then(Value::as_str) == Some(lease)
            });
            if consumed_role_lease_refs.iter().any(|held| held == lease) || live_lease {
                return Err("role lease is already consumed".to_owned());
            }
            let already_held = node
                .get("role_assignments")
                .and_then(Value::as_array)
                .is_some_and(|assignments| {
                    assignments.iter().any(|assignment| {
                        assignment.get("role").and_then(Value::as_str) == Some(target_role)
                    })
                });
            if already_held {
                return Err("node already holds the target role".to_owned());
            }
            let epoch = node
                .get("membership_epoch")
                .and_then(Value::as_u64)
                .ok_or("membership record lacks its epoch")?;
            let mut record = node.clone();
            record["role_assignments"]
                .as_array_mut()
                .ok_or("membership record lacks role assignments")?
                .push(json!({
                    "role": target_role,
                    "role_scope_refs": [],
                    "authority_grant_refs": [],
                    "role_lease_ref": lease,
                    "admitted_epoch": epoch,
                    "valid_from": Value::Null,
                    "expires_at": Value::Null,
                }));
            record
        }
        MembershipTransitionOp::DrainNode => {
            let node = current.expect("drain predecessor was admitted");
            let mut record = node.clone();
            record["status"] = json!("draining");
            record
        }
        MembershipTransitionOp::RemoveNode => {
            let node = current.expect("removal predecessor was draining");
            let mut record = node.clone();
            record["status"] = json!("left");
            if let Some(assignments) = record
                .get_mut("role_assignments")
                .and_then(Value::as_array_mut)
            {
                for assignment in assignments {
                    assignment["role_lease_ref"] = Value::Null;
                }
            }
            record
        }
    };
    validate_architecture_contract(NODE_MEMBERSHIP_CONTRACT, &resulting_record)
        .map_err(|error| format!("resulting membership record is invalid: {error}"))?;
    let resulting_record_root = membership_record_root(&resulting_record)?;
    let resulting_status = required_string(&resulting_record, "/status")?.to_owned();

    // Resulting live set: replace (or remove) this node's entry only.
    let mut resulting_set: Vec<Value> = current_records
        .iter()
        .filter(|record| {
            record.get("node_id").and_then(Value::as_str) != Some(declaration.node_id.as_str())
        })
        .cloned()
        .collect();
    if op != MembershipTransitionOp::RemoveNode {
        resulting_set.push(resulting_record.clone());
    }
    let resulting_membership_root = membership_set_root(&binding.system_id, &resulting_set)?;

    let membership_epoch = resulting_record
        .get("membership_epoch")
        .and_then(Value::as_u64)
        .ok_or("resulting record lacks its epoch")?;
    let mut authority_effect = json!({
        "schema_version": "ioi.autonomous-system-membership-authority-effect.v1",
        "op": op.as_str(),
        "required_scope": op.required_scope(),
        "sequence": sequence,
        "system_id": binding.system_id,
        "genesis_ref": binding.genesis_ref,
        "source_governing_authority_ref": binding.source_governing_authority_ref,
        "node_membership_ref": node_membership_ref,
        "node_id": declaration.node_id,
        "node_owner_ref": resulting_record["node_owner_ref"],
        "membership_epoch": membership_epoch,
        "deployment_profile_ref": binding.deployment_profile_ref,
        "deployment_profile_root": binding.deployment_profile_root,
        "desired_topology_ref": desired_topology["desired_topology_id"],
        "desired_topology_root": desired_root,
        "predecessor_status": predecessor_status,
        "resulting_status": resulting_status,
        "predecessor_membership_root": derived_root,
        "resulting_membership_root": resulting_membership_root,
        "predecessor_record_root": predecessor_record_root,
        "resulting_record_root": resulting_record_root,
        "declared_readiness": declared_readiness,
        "readiness_attestation_ref": declaration.readiness_attestation_ref,
        "catchup_operation_offset": declaration.catchup_operation_offset,
        "catchup_receipt_ref": declaration.catchup_receipt_ref,
        "verified_state_root": verified_state_root,
        "target_role": declaration.target_role,
        "role_lease_ref": declaration.role_lease_ref,
        "evidence_refs": declaration.evidence_refs,
        "desired_topology_is_observed_truth": false,
        "writer_authority_admitted": false,
        "authority_widened": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": MEMBERSHIP_OPERATION_HASH_PROFILE,
        "effect": authority_effect,
    }))?;
    authority_effect["operation_commitment"] = json!(operation_commitment);

    Ok(CompiledMembershipTransitionPlan {
        op,
        sequence,
        node_id: declaration.node_id.clone(),
        node_membership_ref: required_string(&authority_effect, "/node_membership_ref")?.to_owned(),
        predecessor_status,
        resulting_status: required_string(&authority_effect, "/resulting_status")?.to_owned(),
        predecessor_membership_root: derived_root,
        resulting_membership_root,
        predecessor_record_root,
        resulting_record_root,
        resulting_record,
        authority_effect,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    fn fixture(path: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path),
        )
        .expect(path)
    }

    fn binding() -> MembershipIdentityBinding {
        MembershipIdentityBinding {
            system_id: "system://acme/system-alpha".into(),
            genesis_ref: "genesis://acme/system-alpha".into(),
            source_governing_authority_ref: "org://acme/research".into(),
            deployment_profile_ref: format!(
                "deployment-profile://acme/system-alpha/revision/sha256:{}",
                "a".repeat(64)
            ),
            deployment_profile_root: format!("sha256:{}", "d".repeat(64)),
            admitted_constitution_root: h(0x0b),
            admitted_manifest_root: h(0x0c),
        }
    }

    fn desired() -> Value {
        fixture("autonomous-system-desired-topology-v1/positive-declared.json")
    }

    fn head_for(records: &[Value], sequence: u64) -> MembershipLogHead {
        MembershipLogHead {
            sequence,
            membership_root: membership_set_root("system://acme/system-alpha", records)
                .expect("set root"),
        }
    }

    fn base_declaration(node_id: &str, records: &[Value]) -> MembershipTransitionDeclaration {
        MembershipTransitionDeclaration {
            node_id: node_id.into(),
            expected_membership_root: membership_set_root("system://acme/system-alpha", records)
                .expect("set root"),
            evidence_refs: vec![],
            node_owner_ref: None,
            roles: vec![],
            membership_lease_ref: None,
            node_attestation_refs: vec![],
            declared_readiness: None,
            readiness_attestation_ref: None,
            catchup_operation_offset: None,
            catchup_receipt_ref: None,
            target_role: None,
            role_lease_ref: None,
        }
    }

    fn admit_declaration(records: &[Value]) -> MembershipTransitionDeclaration {
        MembershipTransitionDeclaration {
            node_owner_ref: Some("wallet://acme/node-owner".into()),
            roles: vec!["state_replica".into()],
            membership_lease_ref: Some("lease://acme/system-alpha/membership/alpha-node-1".into()),
            node_attestation_refs: vec!["attestation://acme/alpha-node-1/boot".into()],
            evidence_refs: vec!["evidence://acme/system-alpha/membership/admit/alpha-node-1".into()],
            ..base_declaration("node://acme/system-alpha/alpha-node-1", records)
        }
    }

    fn compile(
        op: MembershipTransitionOp,
        records: &[Value],
        sequence: u64,
        consumed: &[String],
        declaration: &MembershipTransitionDeclaration,
        attestation: Option<&Value>,
        receipt: Option<&Value>,
    ) -> Result<CompiledMembershipTransitionPlan, String> {
        compile_membership_transition_plan(
            op,
            &binding(),
            &desired(),
            records,
            &head_for(records, sequence),
            consumed,
            declaration,
            attestation,
            receipt,
        )
    }

    fn catchup_receipt(offset: u64) -> Value {
        json!({
            "receipt_ref": "receipt://acme/system-alpha/catchup/alpha-node-1/7",
            "node_id": "node://acme/system-alpha/alpha-node-1",
            "operation_offset": offset,
            "verified_state_root": h(0x0e),
        })
    }

    fn attestation_for(record: &Value, readiness: &str) -> Value {
        json!({
            "attestation_ref": "attestation://acme/alpha-node-1/readiness/7",
            "node_id": record["node_id"],
            "membership_epoch": record["membership_epoch"],
            "verified_state_root": record["synchronization"]["verified_state_root"],
            "readiness": readiness,
        })
    }

    /// Walk admit -> advance -> attest(ready) and return the live record set.
    fn ready_member() -> (Vec<Value>, u64) {
        let plan = compile(
            MembershipTransitionOp::AdmitNode,
            &[],
            0,
            &[],
            &admit_declaration(&[]),
            None,
            None,
        )
        .expect("admit");
        let records = vec![plan.resulting_record];

        let mut advance = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        advance.catchup_operation_offset = Some(7);
        advance.catchup_receipt_ref =
            Some("receipt://acme/system-alpha/catchup/alpha-node-1/7".into());
        let plan = compile(
            MembershipTransitionOp::AdvanceCatchup,
            &records,
            1,
            &[],
            &advance,
            None,
            Some(&catchup_receipt(7)),
        )
        .expect("advance");
        let records = vec![plan.resulting_record];

        let mut attest = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        attest.declared_readiness = Some("ready".into());
        attest.readiness_attestation_ref =
            Some("attestation://acme/alpha-node-1/readiness/7".into());
        let attestation = attestation_for(&records[0], "ready");
        let plan = compile(
            MembershipTransitionOp::AttestReadiness,
            &records,
            2,
            &[],
            &attest,
            Some(&attestation),
            None,
        )
        .expect("attest ready");
        assert_eq!(plan.resulting_status, "active");
        (vec![plan.resulting_record], 3)
    }

    #[test]
    fn scopes_are_distinct_and_never_reuse_lifecycle_or_continuity_families() {
        let mut scopes: Vec<_> = MembershipTransitionOp::ALL
            .into_iter()
            .map(MembershipTransitionOp::required_scope)
            .collect();
        scopes.sort();
        scopes.dedup();
        assert_eq!(scopes.len(), MembershipTransitionOp::ALL.len());
        assert!(scopes.iter().all(|scope| {
            scope.starts_with("scope:autonomous_system.membership.")
                && !scope.starts_with("scope:autonomous_system.lifecycle.")
                && !scope.starts_with("scope:autonomous_system.continuity.")
        }));
    }

    // Branch 1 — foreign node.
    #[test]
    fn admission_refuses_a_node_outside_the_system_namespace() {
        let mut declaration = admit_declaration(&[]);
        declaration.node_id = "node://mallory/other-system/intruder".into();
        assert!(compile(
            MembershipTransitionOp::AdmitNode,
            &[],
            0,
            &[],
            &declaration,
            None,
            None,
        )
        .unwrap_err()
        .contains("outside the System namespace"));
    }

    // Branch 2 — stale predecessor membership root.
    #[test]
    fn stale_predecessor_membership_root_is_refused() {
        let mut declaration = admit_declaration(&[]);
        declaration.expected_membership_root = h(0x99);
        assert!(compile(
            MembershipTransitionOp::AdmitNode,
            &[],
            0,
            &[],
            &declaration,
            None,
            None,
        )
        .unwrap_err()
        .contains("stale predecessor membership root"));
    }

    // Branch 3 — forged readiness: an attestation not bound to the admitted
    // identity, epoch, or current verified root never compiles.
    #[test]
    fn forged_readiness_attestation_is_refused() {
        let plan = compile(
            MembershipTransitionOp::AdmitNode,
            &[],
            0,
            &[],
            &admit_declaration(&[]),
            None,
            None,
        )
        .expect("admit");
        let records = vec![plan.resulting_record];
        let mut attest = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        attest.declared_readiness = Some("ready".into());
        attest.readiness_attestation_ref =
            Some("attestation://acme/alpha-node-1/readiness/7".into());

        // No verified root exists yet, so any root-bearing attestation is forged.
        let mut forged = attestation_for(&records[0], "ready");
        forged["verified_state_root"] = json!(h(0x77));
        assert!(compile(
            MembershipTransitionOp::AttestReadiness,
            &records,
            1,
            &[],
            &attest,
            Some(&forged),
            None,
        )
        .unwrap_err()
        .contains("current verified state root"));

        // A foreign node binding is refused even with a matching root shape.
        let mut advance = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        advance.catchup_operation_offset = Some(7);
        advance.catchup_receipt_ref =
            Some("receipt://acme/system-alpha/catchup/alpha-node-1/7".into());
        let advanced = compile(
            MembershipTransitionOp::AdvanceCatchup,
            &records,
            1,
            &[],
            &advance,
            None,
            Some(&catchup_receipt(7)),
        )
        .expect("advance");
        let records = vec![advanced.resulting_record];
        let mut attest = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        attest.declared_readiness = Some("ready".into());
        attest.readiness_attestation_ref =
            Some("attestation://acme/alpha-node-1/readiness/7".into());
        let mut foreign = attestation_for(&records[0], "ready");
        foreign["node_id"] = json!("node://acme/system-alpha/other-node");
        assert!(compile(
            MembershipTransitionOp::AttestReadiness,
            &records,
            2,
            &[],
            &attest,
            Some(&foreign),
            None,
        )
        .unwrap_err()
        .contains("admitted node identity"));
    }

    // Branch 4 — skipped catch-up: ready below the declared floor is refused.
    #[test]
    fn readiness_cannot_be_claimed_before_the_declared_catchup_floor() {
        let plan = compile(
            MembershipTransitionOp::AdmitNode,
            &[],
            0,
            &[],
            &admit_declaration(&[]),
            None,
            None,
        )
        .expect("admit");
        let records = vec![plan.resulting_record];
        let mut advance = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        advance.catchup_operation_offset = Some(3);
        advance.catchup_receipt_ref =
            Some("receipt://acme/system-alpha/catchup/alpha-node-1/7".into());
        let advanced = compile(
            MembershipTransitionOp::AdvanceCatchup,
            &records,
            1,
            &[],
            &advance,
            None,
            Some(&catchup_receipt(3)),
        )
        .expect("advance below floor");
        let records = vec![advanced.resulting_record];
        let mut attest = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        attest.declared_readiness = Some("ready".into());
        attest.readiness_attestation_ref =
            Some("attestation://acme/alpha-node-1/readiness/7".into());
        let attestation = attestation_for(&records[0], "ready");
        assert!(compile(
            MembershipTransitionOp::AttestReadiness,
            &records,
            2,
            &[],
            &attest,
            Some(&attestation),
            None,
        )
        .unwrap_err()
        .contains("declared catch-up floor"));
    }

    // Branch 5 — role-lease replay.
    #[test]
    fn promotion_refuses_a_consumed_role_lease() {
        let (records, sequence) = ready_member();
        let mut promote = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        promote.target_role = Some("hot_standby".into());
        promote.role_lease_ref = Some("lease://acme/system-alpha/role/replayed".into());
        let consumed = vec!["lease://acme/system-alpha/role/replayed".to_owned()];
        assert!(compile(
            MembershipTransitionOp::PromoteRole,
            &records,
            sequence,
            &consumed,
            &promote,
            None,
            None,
        )
        .unwrap_err()
        .contains("role lease is already consumed"));

        // The same fresh lease is single-use: once held live, it never
        // authorizes a second promotion.
        let mut fresh = promote.clone();
        fresh.role_lease_ref = Some("lease://acme/system-alpha/role/fresh".into());
        let promoted = compile(
            MembershipTransitionOp::PromoteRole,
            &records,
            sequence,
            &[],
            &fresh,
            None,
            None,
        )
        .expect("fresh promotion");
        let records = vec![promoted.resulting_record];
        let mut replay = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        replay.target_role = Some("verifier".into());
        replay.role_lease_ref = Some("lease://acme/system-alpha/role/fresh".into());
        assert!(compile(
            MembershipTransitionOp::PromoteRole,
            &records,
            sequence + 1,
            &[],
            &replay,
            None,
            None,
        )
        .unwrap_err()
        .contains("role lease is already consumed"));
    }

    // Branch 6 — degraded posture honesty.
    #[test]
    fn degraded_posture_is_recorded_honestly_and_blocks_promotion() {
        let plan = compile(
            MembershipTransitionOp::AdmitNode,
            &[],
            0,
            &[],
            &admit_declaration(&[]),
            None,
            None,
        )
        .expect("admit");
        let records = vec![plan.resulting_record];
        let mut advance = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        advance.catchup_operation_offset = Some(7);
        advance.catchup_receipt_ref =
            Some("receipt://acme/system-alpha/catchup/alpha-node-1/7".into());
        let advanced = compile(
            MembershipTransitionOp::AdvanceCatchup,
            &records,
            1,
            &[],
            &advance,
            None,
            Some(&catchup_receipt(7)),
        )
        .expect("advance");
        let records = vec![advanced.resulting_record];

        // Declaring ready over a degraded attestation is refused.
        let mut attest = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        attest.declared_readiness = Some("ready".into());
        attest.readiness_attestation_ref =
            Some("attestation://acme/alpha-node-1/readiness/7".into());
        let degraded = attestation_for(&records[0], "degraded");
        assert!(compile(
            MembershipTransitionOp::AttestReadiness,
            &records,
            2,
            &[],
            &attest,
            Some(&degraded),
            None,
        )
        .unwrap_err()
        .contains("contradicts the resolved attestation"));

        // Declaring degraded records degraded and never widens the ladder.
        let mut honest = attest.clone();
        honest.declared_readiness = Some("degraded".into());
        let plan = compile(
            MembershipTransitionOp::AttestReadiness,
            &records,
            2,
            &[],
            &honest,
            Some(&degraded),
            None,
        )
        .expect("degraded attest");
        assert_eq!(plan.resulting_status, "admitted");
        assert_eq!(
            plan.resulting_record["observation"]["readiness"],
            "degraded"
        );

        // A degraded node cannot be promoted.
        let records = vec![plan.resulting_record];
        let mut promote = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        promote.target_role = Some("hot_standby".into());
        promote.role_lease_ref = Some("lease://acme/system-alpha/role/fresh".into());
        assert!(compile(
            MembershipTransitionOp::PromoteRole,
            &records,
            3,
            &[],
            &promote,
            None,
            None,
        )
        .unwrap_err()
        .contains("cannot lawfully leave admitted"));
    }

    // Branch 7 — drain/removal race settled by strict CAS.
    #[test]
    fn drain_and_removal_races_are_settled_by_strict_cas() {
        let (records, sequence) = ready_member();
        let pre_drain_root =
            membership_set_root("system://acme/system-alpha", &records).expect("root");
        let drain = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        let drained = compile(
            MembershipTransitionOp::DrainNode,
            &records,
            sequence,
            &[],
            &drain,
            None,
            None,
        )
        .expect("drain");
        assert_eq!(drained.resulting_status, "draining");
        let records = vec![drained.resulting_record];

        // The racing second drain still cites the pre-drain root: stale, refused.
        let mut racing = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        racing.expected_membership_root = pre_drain_root;
        assert!(compile(
            MembershipTransitionOp::DrainNode,
            &records,
            sequence + 1,
            &[],
            &racing,
            None,
            None,
        )
        .unwrap_err()
        .contains("stale predecessor membership root"));

        // Draining cannot be drained again even with the fresh root.
        let fresh = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        assert!(compile(
            MembershipTransitionOp::DrainNode,
            &records,
            sequence + 1,
            &[],
            &fresh,
            None,
            None,
        )
        .unwrap_err()
        .contains("cannot lawfully leave draining"));

        // Removal is admissible only from draining, and the removed node
        // leaves the resulting set while its record survives as evidence.
        let remove = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        let removed = compile(
            MembershipTransitionOp::RemoveNode,
            &records,
            sequence + 1,
            &[],
            &remove,
            None,
            None,
        )
        .expect("remove");
        assert_eq!(removed.resulting_status, "left");
        assert_eq!(
            removed.resulting_membership_root,
            membership_set_root("system://acme/system-alpha", &[]).expect("empty root")
        );
    }

    #[test]
    fn writer_promotion_is_not_admissible_in_the_membership_plane() {
        let (records, sequence) = ready_member();
        let mut promote = base_declaration("node://acme/system-alpha/alpha-node-1", &records);
        promote.target_role = Some("admission_writer".into());
        promote.role_lease_ref = Some("lease://acme/system-alpha/role/fresh".into());
        assert!(compile(
            MembershipTransitionOp::PromoteRole,
            &records,
            sequence,
            &[],
            &promote,
            None,
            None,
        )
        .unwrap_err()
        .contains("governed writer-epoch transition"));
        let mut admit = admit_declaration(&[]);
        admit.roles = vec!["admission_writer".into()];
        assert!(compile(
            MembershipTransitionOp::AdmitNode,
            &[],
            0,
            &[],
            &admit,
            None,
            None,
        )
        .unwrap_err()
        .contains("authority-bearing role"));
    }
}
