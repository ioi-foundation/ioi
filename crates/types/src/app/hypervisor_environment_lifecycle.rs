//! M2 environment lifecycle plane: owner-bound route binding, manifest-complete
//! backup, staged restore with forward-only activation, and durable cleanup
//! obligations.
//!
//! Every admission input here is resolved from trusted server truth, never
//! asserted by the caller (INV-37): observed route facts, artifact digest
//! censuses, activation heads, and committed stage progress are all server
//! resolved. Each falsifiable-claim dimension refuses with its named reason
//! and never advances state: route drift and owner drift are refusals over the
//! declared binding, never silent adoption; incomplete restoration (a missing
//! manifest row or a digest mismatch) refuses restore; a plan bound to a
//! superseded binding or head refuses activation; a completed stage is never
//! re-entered; parent or provider loss escalates a cleanup obligation and can
//! never erase it; and no closing disposition exists without a receipt.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;

use super::system_activation::{jcs_hash, required_string};

/// Registered owner-bound route binding contract.
pub const ROUTE_BINDING_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-environment-route-binding/v1";
/// Registered manifest-complete backup contract.
pub const ENVIRONMENT_BACKUP_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-environment-backup/v1";
/// Registered staged restore/activation plan contract.
pub const CHANGE_PLAN_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-change-plan/v1";
/// Registered durable cleanup obligation contract.
pub const CLEANUP_OBLIGATION_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-resource-cleanup-obligation/v1";

/// Content domain of one immutable route-binding revision commitment
/// (must match the registered invariant's material recipe exactly).
pub const ROUTE_BINDING_COMMITMENT_PROFILE: &str =
    "ioi.hypervisor-environment-route-binding-commitment-jcs-sha256.v1";
/// Content domain of a backup's manifest commitment.
pub const BACKUP_MANIFEST_PROFILE: &str =
    "ioi.hypervisor-environment-backup-manifest-jcs-sha256.v1";
/// Content domain of one immutable change-plan commitment.
pub const CHANGE_PLAN_COMMITMENT_PROFILE: &str =
    "ioi.hypervisor-change-plan-commitment-jcs-sha256.v1";
/// Content domain of one cleanup-obligation revision root.
pub const OBLIGATION_REVISION_PROFILE: &str =
    "ioi.hypervisor-resource-cleanup-obligation-revision-jcs-sha256.v1";
/// Content domain of whole-record artifact roots for plane families.
pub const ENVIRONMENT_ARTIFACT_PROFILE: &str =
    "ioi.hypervisor-environment-lifecycle-artifact-jcs-sha256.v1";
/// Content domain of the derived live plane set root.
pub const ENVIRONMENT_PLANE_SET_PROFILE: &str =
    "ioi.hypervisor-environment-lifecycle-set-jcs-sha256.v1";
/// Operation commitment domain over one closed governed effect.
pub const ENVIRONMENT_OPERATION_PROFILE: &str =
    "ioi.hypervisor-environment-lifecycle-operation-commitment-jcs-sha256.v1";

/// Every named refusal dimension of the plane's falsifiable claim.
pub const ENVIRONMENT_REFUSAL_DIMENSIONS: [&str; 8] = [
    "route_drift",
    "owner_drift",
    "incomplete_restoration",
    "stale_activation",
    "backward_stage",
    "parent_loss",
    "provider_loss",
    "unreceipted_close",
];

/// The closed, ordered restore stage ladder.
pub const CHANGE_PLAN_STAGE_LADDER: [&str; 5] = [
    "read_only_preflight",
    "restore_apply",
    "post_restore_validation",
    "activation",
    "cleanup_reconciliation",
];

/// Named M2 environment lifecycle operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentLifecycleOp {
    /// Declare one immutable owner-bound route-binding revision (CAS lineage).
    DeclareRouteBinding,
    /// Record one manifest-complete backup from a resolved artifact census.
    RecordBackup,
    /// Declare one immutable staged restore/activation plan.
    DeclareChangePlan,
    /// Advance the exact next undischarged plan stage (forward-only).
    AdvanceChangePlanStage,
    /// Open one durable cleanup obligation.
    OpenCleanupObligation,
    /// Close an obligation through a receipted disposition.
    SatisfyCleanupObligation,
    /// Escalate an obligation on parent or provider loss (never erases).
    EscalateCleanupObligation,
}

impl EnvironmentLifecycleOp {
    /// Every operation in stable order.
    pub const ALL: [Self; 7] = [
        Self::DeclareRouteBinding,
        Self::RecordBackup,
        Self::DeclareChangePlan,
        Self::AdvanceChangePlanStage,
        Self::OpenCleanupObligation,
        Self::SatisfyCleanupObligation,
        Self::EscalateCleanupObligation,
    ];

    /// Stable wire operation name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeclareRouteBinding => "declare_route_binding",
            Self::RecordBackup => "record_backup",
            Self::DeclareChangePlan => "declare_change_plan",
            Self::AdvanceChangePlanStage => "advance_change_plan_stage",
            Self::OpenCleanupObligation => "open_cleanup_obligation",
            Self::SatisfyCleanupObligation => "satisfy_cleanup_obligation",
            Self::EscalateCleanupObligation => "escalate_cleanup_obligation",
        }
    }

    /// Parse a stable wire operation name.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == value)
    }

    /// Exact one-operation wallet scope, disjoint from every prior family.
    pub fn required_scope(self) -> &'static str {
        match self {
            Self::DeclareRouteBinding => "scope:hypervisor_environment.declare_route_binding",
            Self::RecordBackup => "scope:hypervisor_environment.record_backup",
            Self::DeclareChangePlan => "scope:hypervisor_environment.declare_change_plan",
            Self::AdvanceChangePlanStage => {
                "scope:hypervisor_environment.advance_change_plan_stage"
            }
            Self::OpenCleanupObligation => "scope:hypervisor_environment.open_cleanup_obligation",
            Self::SatisfyCleanupObligation => {
                "scope:hypervisor_environment.satisfy_cleanup_obligation"
            }
            Self::EscalateCleanupObligation => {
                "scope:hypervisor_environment.escalate_cleanup_obligation"
            }
        }
    }

    /// The canonical operation-log entry kind this operation appends
    /// (`OperationLogEntry` vocabulary, environment family).
    pub fn entry_kind(self) -> &'static str {
        match self {
            Self::DeclareRouteBinding => "environment.route_binding_proposed",
            Self::RecordBackup => "environment.backup_completed",
            Self::DeclareChangePlan => "change_plan.prepared",
            Self::AdvanceChangePlanStage => "change_plan.applied",
            Self::OpenCleanupObligation => "environment.cleanup_obligation_opened",
            Self::SatisfyCleanupObligation => "environment.cleanup_completed",
            Self::EscalateCleanupObligation => "environment.cleanup_escalated",
        }
    }
}

/// The one local estate this daemon governs environments for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentEstateBinding {
    /// Estate namespace (the plane is estate-scoped, not System-scoped).
    pub estate_namespace: String,
    /// Trusted daemon identity.
    pub daemon_ref: String,
}

/// Durable plane log head resolved from committed transitions only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentLifecycleLogHead {
    /// Last committed sequence; zero before the first operation.
    pub sequence: u64,
    /// Current derived plane set root.
    pub plane_root: String,
}

/// A total admit/refuse verdict with a named dimension on every refusal.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvironmentVerdict {
    /// Whether the evaluated claim is admitted.
    pub admitted: bool,
    /// Named refusal dimension, absent only on admit.
    pub refusal_dimension: Option<&'static str>,
    /// Human-readable refusal reason, absent only on admit.
    pub refusal_reason: Option<String>,
}

impl EnvironmentVerdict {
    fn refuse(dimension: &'static str, reason: impl Into<String>) -> Self {
        debug_assert!(ENVIRONMENT_REFUSAL_DIMENSIONS.contains(&dimension));
        Self {
            admitted: false,
            refusal_dimension: Some(dimension),
            refusal_reason: Some(reason.into()),
        }
    }

    fn admit() -> Self {
        Self {
            admitted: true,
            refusal_dimension: None,
            refusal_reason: None,
        }
    }
}

fn err(dimension: &'static str, reason: impl Into<String>) -> String {
    debug_assert!(ENVIRONMENT_REFUSAL_DIMENSIONS.contains(&dimension));
    format!("{dimension}: {}", reason.into())
}

fn opt_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Immutable route-binding commitment: every field except route_binding_hash,
/// exactly as the registered invariant recomputes it.
pub fn route_binding_commitment(binding: &Value) -> Result<String, String> {
    let mut material = binding
        .as_object()
        .cloned()
        .ok_or("route binding is not an object")?;
    material.remove("route_binding_hash");
    material.insert("domain".to_owned(), json!(ROUTE_BINDING_COMMITMENT_PROFILE));
    jcs_hash(&Value::Object(material))
}

/// Immutable change-plan commitment: every field except plan_hash, exactly as
/// the registered invariant recomputes it. State roots, receipts,
/// observations, execution output, and refusal reasons are never members.
pub fn change_plan_commitment(plan: &Value) -> Result<String, String> {
    let mut material = plan
        .as_object()
        .cloned()
        .ok_or("change plan is not an object")?;
    material.remove("plan_hash");
    material.insert("domain".to_owned(), json!(CHANGE_PLAN_COMMITMENT_PROFILE));
    jcs_hash(&Value::Object(material))
}

/// Backup manifest commitment over the exact digest rows, exactly as the
/// registered invariant recomputes it.
pub fn backup_manifest_root(backup: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": BACKUP_MANIFEST_PROFILE,
        "backup_ref": required_string(backup, "/backup_ref")?,
        "environment_ref": required_string(backup, "/environment_ref")?,
        "source_state_root_ref": required_string(backup, "/source_state_root_ref")?,
        "rows": backup.get("manifest_rows").cloned().unwrap_or(json!([])),
    }))
}

/// Content root of one cleanup-obligation revision.
pub fn obligation_revision_root(obligation: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": OBLIGATION_REVISION_PROFILE,
        "record": obligation,
    }))
}

/// Whole-record artifact root for plane records (bindings, backups, plans).
pub fn environment_artifact_root(record: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": ENVIRONMENT_ARTIFACT_PROFILE,
        "artifact": record,
    }))
}

/// Derived set root over the live plane records, sorted per family by root.
pub fn environment_plane_root(
    estate_namespace: &str,
    bindings: &[Value],
    backups: &[Value],
    plans: &[Value],
    obligations: &[Value],
) -> Result<String, String> {
    let mut families = Vec::with_capacity(4);
    for (family, records, root_of) in [
        (
            "route_bindings",
            bindings,
            environment_artifact_root as fn(&Value) -> Result<String, String>,
        ),
        ("backups", backups, environment_artifact_root),
        ("change_plans", plans, environment_artifact_root),
        ("cleanup_obligations", obligations, obligation_revision_root),
    ] {
        let mut roots = records.iter().map(root_of).collect::<Result<Vec<_>, _>>()?;
        roots.sort();
        families.push(json!({"family": family, "roots": roots}));
    }
    jcs_hash(&json!({
        "domain": ENVIRONMENT_PLANE_SET_PROFILE,
        "estate_namespace": estate_namespace,
        "families": families,
    }))
}

/// Route identity is the declared tuple; two bindings for one identity form a
/// compare-and-swap lineage, never a fork.
pub fn route_identity(binding: &Value) -> Result<String, String> {
    let hostname = required_string(binding, "/hostname_or_address")?;
    let path = opt_str(binding, "/path_prefix").unwrap_or("");
    let protocol = required_string(binding, "/target_protocol")?;
    Ok(format!("{protocol}://{hostname}{path}"))
}

/// The one current head revision per route identity: the revision no
/// successor cites. Two uncited revisions for one identity are a fork.
pub fn route_binding_head<'a>(
    bindings: &'a [Value],
    identity: &str,
) -> Result<Option<&'a Value>, String> {
    let mut mine = Vec::new();
    for binding in bindings {
        if route_identity(binding)? == identity {
            mine.push(binding);
        }
    }
    let cited: Vec<&str> = mine
        .iter()
        .filter_map(|binding| opt_str(binding, "/predecessor_route_binding_ref"))
        .collect();
    let mut heads: Vec<&Value> = mine
        .into_iter()
        .filter(|binding| {
            opt_str(binding, "/route_binding_ref")
                .is_some_and(|reference| !cited.contains(&reference))
        })
        .collect();
    match heads.len() {
        0 => Ok(None),
        1 => Ok(Some(heads.remove(0))),
        _ => Err("two route-binding revisions both claim the identity head".to_owned()),
    }
}

/// Compile one declared route-binding revision against the durable binding
/// set. Lineage is strict compare-and-swap; ownership never silently
/// re-parents; the observed side never enters this function (INV-37: this is
/// the declared record only).
pub fn compile_route_binding_declaration(
    estate: &EnvironmentEstateBinding,
    current_bindings: &[Value],
    declared: &Value,
) -> Result<Value, String> {
    validate_architecture_contract(ROUTE_BINDING_CONTRACT, declared)
        .map_err(|error| format!("declared route binding is invalid: {error}"))?;
    let identity = route_identity(declared)?;
    let head = route_binding_head(current_bindings, &identity)?;
    match head {
        None => {
            if opt_str(declared, "/predecessor_route_binding_ref").is_some() {
                return Err(
                    "genesis route binding for a new identity cannot cite a predecessor".to_owned(),
                );
            }
        }
        Some(head) => {
            let head_ref = required_string(head, "/route_binding_ref")?;
            if opt_str(declared, "/predecessor_route_binding_ref") != Some(head_ref) {
                return Err(err(
                    "stale_activation",
                    format!(
                        "successor must cite the exact current head revision '{head_ref}' for \
                         route identity '{identity}'"
                    ),
                ));
            }
            if opt_str(declared, "/expected_active_head_ref") != Some(head_ref) {
                return Err(err(
                    "stale_activation",
                    "successor expected active head departs the current head revision",
                ));
            }
            let head_generation = head
                .get("activation_generation")
                .and_then(Value::as_u64)
                .ok_or("head revision lacks its activation generation")?;
            let declared_generation = declared
                .get("activation_generation")
                .and_then(Value::as_u64)
                .ok_or("declared revision lacks its activation generation")?;
            if declared_generation != head_generation + 1 {
                return Err(err(
                    "stale_activation",
                    "successor activation generation must be exactly one above the head",
                ));
            }
            // Ownership is bound: a successor revision never silently
            // re-parents the route to a different principal or System.
            if opt_str(declared, "/owner_principal_ref") != opt_str(head, "/owner_principal_ref")
                || declared.get("system_ref") != head.get("system_ref")
            {
                return Err(err(
                    "owner_drift",
                    "successor revision re-parents the route away from its declared owner",
                ));
            }
        }
    }
    let _ = &estate.estate_namespace;
    Ok(declared.clone())
}

/// Evaluate a server-resolved route observation against the declared active
/// binding. TOTAL: every input produces a verdict; every refusal names its
/// dimension. The observed binding is never adopted — no code path exists
/// from an observation to a declared revision.
pub fn evaluate_route_binding_observation(
    declared: &Value,
    observed: &Value,
) -> EnvironmentVerdict {
    let field = |value: &Value, pointer: &str| -> String {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    // Owner drift: the observed owner or System departs the declared binding.
    if field(observed, "/observed_owner_principal_ref") != field(declared, "/owner_principal_ref") {
        return EnvironmentVerdict::refuse(
            "owner_drift",
            "observed route owner departs the declared owning principal; the observed binding \
             is refused, never adopted",
        );
    }
    if observed.get("observed_system_ref") != declared.get("system_ref") {
        return EnvironmentVerdict::refuse(
            "owner_drift",
            "observed route System departs the declared owning System",
        );
    }
    // Route drift classes over the declared identity and target.
    if field(observed, "/hostname_or_address") != field(declared, "/hostname_or_address")
        || observed.get("path_prefix") != declared.get("path_prefix")
        || field(observed, "/target_protocol") != field(declared, "/target_protocol")
    {
        return EnvironmentVerdict::refuse(
            "route_drift",
            "unexpected_exposure: an observed route-shaped surface departs every declared \
             route identity",
        );
    }
    if field(observed, "/observed_target_endpoint_ref") != field(declared, "/target_endpoint_ref") {
        return EnvironmentVerdict::refuse(
            "route_drift",
            "dns_divergence: observed resolution no longer matches the bound target",
        );
    }
    if observed
        .get("observed_tls_at_or_above_floor")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return EnvironmentVerdict::refuse(
            "route_drift",
            "tls_downgrade_observed: traffic observed below the bound TLS floor",
        );
    }
    if observed
        .get("observed_certificate_matches_binding")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return EnvironmentVerdict::refuse(
            "route_drift",
            "certificate_divergence: observed certificate chain departs the binding",
        );
    }
    if observed
        .get("observed_provider_records_match")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return EnvironmentVerdict::refuse(
            "route_drift",
            "provider_record_divergence: provider-side route records depart the binding",
        );
    }
    if observed
        .get("observed_endpoint_reachable")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return EnvironmentVerdict::refuse(
            "route_drift",
            "endpoint_unreachable: bound endpoint fails observation while the binding is active",
        );
    }
    EnvironmentVerdict::admit()
}

/// Caller-declared backup intent. The manifest is never caller material: rows
/// are resolved from the server-side artifact digest census (INV-37).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupDeclaration {
    /// Owner-allocated backup tail inside the estate namespace.
    pub backup_tail: String,
    /// Declared trigger from the closed enum.
    pub trigger: String,
    /// Target environment.
    pub environment_ref: String,
    /// Optional originating change plan or schedule.
    #[serde(default)]
    pub schedule_or_change_plan_ref: Option<String>,
}

/// Compile one manifest-complete backup record from the server-resolved
/// capture: the daemon-admitted source state root and the resolved
/// per-artifact digest census. A capture with zero resolved artifacts cannot
/// compile a complete backup.
#[allow(clippy::too_many_arguments)]
pub fn compile_backup_record(
    estate: &EnvironmentEstateBinding,
    declaration: &BackupDeclaration,
    resolved_source_state_root: &str,
    resolved_artifact_rows: &[Value],
    system_ref: Option<&str>,
    receipt_ref: &str,
) -> Result<Value, String> {
    if resolved_artifact_rows.is_empty() {
        return Err(err(
            "incomplete_restoration",
            "a complete backup requires at least one resolved artifact digest row",
        ));
    }
    let mut rows = Vec::with_capacity(resolved_artifact_rows.len());
    let mut refs = Vec::with_capacity(resolved_artifact_rows.len());
    for row in resolved_artifact_rows {
        let artifact_ref = required_string(row, "/artifact_ref")?;
        let digest = required_string(row, "/sha256")?;
        let size = row
            .get("size_bytes")
            .and_then(Value::as_u64)
            .ok_or("resolved artifact row lacks its byte length")?;
        let role = opt_str(row, "/role").unwrap_or("environment_backup_payload");
        rows.push(json!({
            "artifact_ref": artifact_ref,
            "sha256": digest,
            "size_bytes": size,
            "role": role,
        }));
        refs.push(json!(artifact_ref));
    }
    let backup_ref = format!(
        "environment-backup://{}/{}",
        estate.estate_namespace, declaration.backup_tail
    );
    let mut backup = json!({
        "schema_version": "ioi.hypervisor-environment-backup.v1",
        "backup_ref": backup_ref,
        "environment_ref": declaration.environment_ref,
        "session_ref": Value::Null,
        "system_ref": system_ref,
        "work_subject_ref": Value::Null,
        "backup_policy_ref": format!("policy://{}/backups/standard", estate.estate_namespace),
        "trigger": declaration.trigger,
        "actor_ref": estate.daemon_ref,
        "schedule_or_change_plan_ref": declaration.schedule_or_change_plan_ref,
        "source_state_root_ref": format!("state-root://{resolved_source_state_root}"),
        "source_object_head_refs": [],
        "source_checkpoint_or_suffix_boundary_refs": [],
        "capture_profile_ref": format!("policy://{}/backups/capture", estate.estate_namespace),
        "execution_substrate_ref": estate.daemon_ref,
        "destination_ref": format!("storage://{}/provider-materials", estate.estate_namespace),
        "custody_profile_ref": format!("policy://{}/backups/custody", estate.estate_namespace),
        "artifact_refs": refs,
        "manifest_artifact_ref": Value::Null,
        "manifest_root": Value::Null,
        "manifest_artifact_count": rows.len(),
        "manifest_rows": rows,
        "content_commitment_refs": [
            format!(
                "commitment://{}/backup/{}",
                estate.estate_namespace, declaration.backup_tail
            )
        ],
        "encryption_ref": Value::Null,
        "key_epoch_ref": Value::Null,
        "retention_policy_ref": format!("policy://{}/backups/retention", estate.estate_namespace),
        "expires_at": Value::Null,
        "hold_refs": [],
        "authority_requirement_refs": [],
        "authority_grant_refs": [],
        "daemon_operation_refs": [],
        "provider_operation_refs": [],
        "lifecycle_head_ref": format!(
            "agentgres://lifecycle-head/{}/backup/{}",
            estate.estate_namespace, declaration.backup_tail
        ),
        "status": "complete",
        "evidence_refs": [],
        "receipt_refs": [receipt_ref],
    });
    let manifest_root = backup_manifest_root(&backup)?;
    backup["manifest_root"] = json!(manifest_root);
    validate_architecture_contract(ENVIRONMENT_BACKUP_CONTRACT, &backup)
        .map_err(|error| format!("compiled backup record is invalid: {error}"))?;
    Ok(backup)
}

fn resolve_backup<'a>(backups: &'a [Value], backup_ref: &str) -> Option<&'a Value> {
    backups
        .iter()
        .find(|backup| opt_str(backup, "/backup_ref") == Some(backup_ref))
}

/// Compile one declared change plan against durable truth: the source backup
/// is referenced only through its manifest commitment, the activation binding
/// must cite the exact current route-binding head and generation, and the
/// stage ladder must be the closed ordered set.
pub fn compile_change_plan_declaration(
    estate: &EnvironmentEstateBinding,
    declared: &Value,
    current_backups: &[Value],
    current_bindings: &[Value],
    current_plans: &[Value],
) -> Result<Value, String> {
    validate_architecture_contract(CHANGE_PLAN_CONTRACT, declared)
        .map_err(|error| format!("declared change plan is invalid: {error}"))?;
    let plan_ref = required_string(declared, "/plan_ref")?;
    if current_plans
        .iter()
        .any(|plan| opt_str(plan, "/plan_ref") == Some(plan_ref))
    {
        return Err(format!("change plan '{plan_ref}' already exists"));
    }

    // Stage ladder: contiguous ascending indexes over the closed ordered
    // ladder, each kind at most once, restore_apply and activation present.
    let steps = declared
        .get("steps")
        .and_then(Value::as_array)
        .ok_or("change plan lacks its steps")?;
    let mut last_rank: Option<usize> = None;
    for (position, step) in steps.iter().enumerate() {
        let index = step
            .get("step_index")
            .and_then(Value::as_u64)
            .ok_or("plan step lacks its index")?;
        if index != (position as u64) + 1 {
            return Err("plan stage indexes must be contiguous and ascending from one".to_owned());
        }
        let kind = required_string(step, "/kind")?;
        let rank = CHANGE_PLAN_STAGE_LADDER
            .iter()
            .position(|candidate| *candidate == kind)
            .ok_or("plan stage kind is outside the closed ladder")?;
        if last_rank.is_some_and(|previous| rank <= previous) {
            return Err(err(
                "backward_stage",
                "plan stages must follow the closed ladder order without repetition",
            ));
        }
        last_rank = Some(rank);
    }
    for required_kind in ["restore_apply", "activation"] {
        if !steps
            .iter()
            .any(|step| opt_str(step, "/kind") == Some(required_kind))
        {
            return Err(format!(
                "an environment_restore plan requires a {required_kind} stage"
            ));
        }
    }

    // Restore binding: only through the durable backup's manifest commitment.
    let source_backup_ref = required_string(declared, "/restore/source_backup_ref")?;
    let backup = resolve_backup(current_backups, source_backup_ref).ok_or(format!(
        "source backup '{source_backup_ref}' is not resolvable from durable truth"
    ))?;
    if opt_str(backup, "/status") != Some("complete") {
        return Err(err(
            "incomplete_restoration",
            "only a complete backup is eligible restore material",
        ));
    }
    let manifest_root = required_string(backup, "/manifest_root")?;
    if required_string(declared, "/restore/restore_manifest_root")? != manifest_root {
        return Err(err(
            "incomplete_restoration",
            "restore staging must reference the backup through its exact manifest commitment",
        ));
    }
    if required_string(
        declared,
        "/restore/source_root_and_head_expectations/source_state_root_ref",
    )? != required_string(backup, "/source_state_root_ref")?
    {
        return Err(err(
            "incomplete_restoration",
            "restore source-root expectation departs the backup's captured state root",
        ));
    }

    // Activation binding: the exact current route-binding head and generation.
    let candidate_ref = required_string(declared, "/activation/candidate_ref")?;
    let head = current_route_head_for_candidate(current_bindings, candidate_ref)?;
    let head_ref = required_string(head, "/route_binding_ref")?;
    if candidate_ref != head_ref {
        return Err(err(
            "stale_activation",
            format!(
                "plan candidate '{candidate_ref}' is superseded; the current head is '{head_ref}'"
            ),
        ));
    }
    let head_generation = head
        .get("activation_generation")
        .and_then(Value::as_u64)
        .ok_or("head revision lacks its activation generation")?;
    if declared
        .pointer("/activation/candidate_generation")
        .and_then(Value::as_u64)
        != Some(head_generation)
    {
        return Err(err(
            "stale_activation",
            "plan candidate generation departs the current head generation",
        ));
    }
    let _ = &estate.estate_namespace;
    Ok(declared.clone())
}

/// Resolve the current head for the route identity a candidate revision names.
fn current_route_head_for_candidate<'a>(
    bindings: &'a [Value],
    candidate_ref: &str,
) -> Result<&'a Value, String> {
    let candidate = bindings
        .iter()
        .find(|binding| opt_str(binding, "/route_binding_ref") == Some(candidate_ref))
        .ok_or(format!(
            "candidate '{candidate_ref}' is not a durable route-binding revision"
        ))?;
    let identity = route_identity(candidate)?;
    route_binding_head(bindings, &identity)?
        .ok_or(format!("route identity '{identity}' has no head revision"))
}

/// Server-resolved evidence for one stage advancement (INV-37: all resolved,
/// never caller-asserted).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StageEvidence {
    /// Resolved per-artifact digests for the restore stage.
    pub resolved_artifact_digests: Vec<Value>,
    /// Resolved evidence refs discharging the stage's requirements.
    pub resolved_evidence_refs: Vec<String>,
}

/// One compiled forward-only stage advancement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledStageAdvance {
    /// Exact plan ref.
    pub plan_ref: String,
    /// Discharged stage index.
    pub stage_index: u64,
    /// Discharged stage kind.
    pub stage_kind: String,
    /// Canonical activation outcome for this advancement.
    pub activation_outcome: String,
    /// Resulting active head after an activation stage, unchanged otherwise.
    pub resulting_active_head_ref: Option<String>,
    /// Evidence refs discharged with the stage.
    pub evidence_refs: Vec<String>,
}

/// Advance the exact next undischarged stage of an immutable plan.
///
/// Forward-only: a committed stage index refuses re-entry (`backward_stage`),
/// a skipped stage refuses, restore discharges only when every backup
/// manifest row verifies against the resolved digest census
/// (`incomplete_restoration` on a missing row or digest mismatch), and
/// activation refuses when the plan is bound to a superseded head or
/// generation (`stale_activation`, outcome `refused_superseded`).
#[allow(clippy::too_many_arguments)]
pub fn compile_stage_advance(
    plan: &Value,
    committed_stage_indexes: &[u64],
    requested_stage_index: u64,
    evidence: &StageEvidence,
    current_backups: &[Value],
    current_bindings: &[Value],
) -> Result<CompiledStageAdvance, String> {
    validate_architecture_contract(CHANGE_PLAN_CONTRACT, plan)
        .map_err(|error| format!("durable change plan is invalid: {error}"))?;
    let plan_ref = required_string(plan, "/plan_ref")?;
    let steps = plan
        .get("steps")
        .and_then(Value::as_array)
        .ok_or("change plan lacks its steps")?;
    if committed_stage_indexes.contains(&requested_stage_index) {
        return Err(err(
            "backward_stage",
            format!(
                "stage {requested_stage_index} of '{plan_ref}' is already discharged and can \
                 never be re-entered"
            ),
        ));
    }
    let next = (committed_stage_indexes.iter().max().copied().unwrap_or(0)) + 1;
    if requested_stage_index != next {
        return Err(err(
            "backward_stage",
            format!(
                "stages advance forward-only: the next undischarged stage of '{plan_ref}' is \
                 {next}, not {requested_stage_index}"
            ),
        ));
    }
    let step = steps
        .iter()
        .find(|step| step.get("step_index").and_then(Value::as_u64) == Some(requested_stage_index))
        .ok_or(format!(
            "plan '{plan_ref}' declares no stage {requested_stage_index}"
        ))?;
    let kind = required_string(step, "/kind")?.to_owned();

    // Per-stage declared evidence requirements must be discharged by resolved
    // evidence, never by caller assertion.
    let requirements = step
        .get("evidence_requirement_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for requirement in &requirements {
        let requirement = requirement.as_str().unwrap_or("");
        if !evidence
            .resolved_evidence_refs
            .iter()
            .any(|held| held == requirement)
        {
            return Err(format!(
                "stage {requested_stage_index} requirement '{requirement}' is not resolvable \
                 from durable evidence"
            ));
        }
    }

    let mut resulting_active_head_ref = None;
    let mut activation_outcome = "not_attempted".to_owned();
    match kind.as_str() {
        "restore_apply" => {
            let source_backup_ref = required_string(plan, "/restore/source_backup_ref")?;
            let backup = resolve_backup(current_backups, source_backup_ref).ok_or(format!(
                "source backup '{source_backup_ref}' is not resolvable from durable truth"
            ))?;
            if required_string(backup, "/manifest_root")?
                != required_string(plan, "/restore/restore_manifest_root")?
            {
                return Err(err(
                    "incomplete_restoration",
                    "the durable backup manifest commitment departs the plan binding",
                ));
            }
            let rows = backup
                .get("manifest_rows")
                .and_then(Value::as_array)
                .ok_or("durable backup lacks its manifest rows")?;
            let declared_count = backup
                .get("manifest_artifact_count")
                .and_then(Value::as_u64)
                .ok_or("durable backup lacks its declared artifact count")?;
            if rows.len() as u64 != declared_count {
                return Err(err(
                    "incomplete_restoration",
                    "the durable backup manifest is missing a declared row",
                ));
            }
            for row in rows {
                let artifact_ref = required_string(row, "/artifact_ref")?;
                let expected = required_string(row, "/sha256")?;
                let resolved = evidence
                    .resolved_artifact_digests
                    .iter()
                    .find(|candidate| opt_str(candidate, "/artifact_ref") == Some(artifact_ref));
                let Some(resolved) = resolved else {
                    return Err(err(
                        "incomplete_restoration",
                        format!(
                            "manifest row '{artifact_ref}' has no resolved artifact bytes; a \
                             missing row can never restore partially"
                        ),
                    ));
                };
                if opt_str(resolved, "/sha256") != Some(expected) {
                    return Err(err(
                        "incomplete_restoration",
                        format!(
                            "resolved digest for '{artifact_ref}' departs the manifest \
                             commitment; substituted bytes never restore"
                        ),
                    ));
                }
            }
        }
        "activation" => {
            let candidate_ref = required_string(plan, "/activation/candidate_ref")?;
            let head = current_route_head_for_candidate(current_bindings, candidate_ref)?;
            let head_ref = required_string(head, "/route_binding_ref")?;
            let head_generation = head
                .get("activation_generation")
                .and_then(Value::as_u64)
                .ok_or("head revision lacks its activation generation")?;
            let plan_generation = plan
                .pointer("/activation/candidate_generation")
                .and_then(Value::as_u64);
            if candidate_ref != head_ref || plan_generation != Some(head_generation) {
                return Err(err(
                    "stale_activation",
                    format!(
                        "activation_outcome refused_superseded: plan '{plan_ref}' is bound to a \
                         superseded revision and can never advance or reclaim the active head"
                    ),
                ));
            }
            activation_outcome = "advanced".to_owned();
            resulting_active_head_ref = Some(head_ref.to_owned());
        }
        _ => {}
    }

    Ok(CompiledStageAdvance {
        plan_ref: plan_ref.to_owned(),
        stage_index: requested_stage_index,
        stage_kind: kind,
        activation_outcome,
        resulting_active_head_ref,
        evidence_refs: evidence.resolved_evidence_refs.clone(),
    })
}

const OPEN_OBLIGATION_STATUSES: [&str; 4] =
    ["pending", "retry_scheduled", "blocked", "reconciling"];
const CLOSING_OBLIGATION_STATUSES: [&str; 3] = ["completed", "quarantined", "abandoned"];

/// Compile the opening revision of a durable cleanup obligation.
pub fn compile_cleanup_open(declared: &Value) -> Result<Value, String> {
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, declared)
        .map_err(|error| format!("declared cleanup obligation is invalid: {error}"))?;
    if declared.get("revision").and_then(Value::as_u64) != Some(1)
        || !declared
            .get("predecessor_obligation_root")
            .is_some_and(Value::is_null)
    {
        return Err("an opening obligation is revision one with a null predecessor".to_owned());
    }
    if opt_str(declared, "/status") != Some("pending") {
        return Err("an opening obligation starts pending".to_owned());
    }
    Ok(declared.clone())
}

/// Close an obligation through a receipted disposition. An absent receipt is
/// an `unreceipted_close` refusal: no closing status exists without one.
pub fn compile_cleanup_satisfy(
    current: &Value,
    closing_status: &str,
    disposition_receipt_ref: Option<&str>,
    evidence_refs: &[String],
) -> Result<Value, String> {
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, current)
        .map_err(|error| format!("durable cleanup obligation is invalid: {error}"))?;
    if !CLOSING_OBLIGATION_STATUSES.contains(&closing_status) {
        return Err(format!(
            "'{closing_status}' is not an admitted closing disposition"
        ));
    }
    let status = required_string(current, "/status")?;
    if !OPEN_OBLIGATION_STATUSES.contains(&status) && status != "escalated" {
        return Err(format!(
            "a {status} obligation admits no further disposition"
        ));
    }
    let Some(receipt_ref) = disposition_receipt_ref else {
        return Err(err(
            "unreceipted_close",
            "an obligation can never close without a receipted disposition",
        ));
    };
    if !receipt_ref.starts_with("receipt://") {
        return Err(err(
            "unreceipted_close",
            "the closing disposition requires a canonical receipt ref",
        ));
    }
    let mut successor = current.clone();
    successor["status"] = json!(closing_status);
    successor["predecessor_obligation_root"] = json!(obligation_revision_root(current)?);
    successor["revision"] = json!(
        current
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or("obligation lacks its revision")?
            + 1
    );
    successor["escalation"] = Value::Null;
    let receipts = successor["receipt_refs"]
        .as_array_mut()
        .ok_or("obligation lacks its receipt refs")?;
    receipts.push(json!(receipt_ref));
    let evidence = successor["evidence_refs"]
        .as_array_mut()
        .ok_or("obligation lacks its evidence refs")?;
    for reference in evidence_refs {
        if !evidence.iter().any(|held| held == reference) {
            evidence.push(json!(reference));
        }
    }
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, &successor)
        .map_err(|error| format!("closing obligation revision is invalid: {error}"))?;
    Ok(successor)
}

/// Escalate an open obligation on parent or provider loss. Escalation
/// preserves every resource identity commitment: loss can never erase,
/// shrink, or close the obligation.
pub fn compile_cleanup_escalate(
    current: &Value,
    escalation_reason: &str,
    lost_parent_ref: &str,
    evidence_refs: &[String],
) -> Result<Value, String> {
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, current)
        .map_err(|error| format!("durable cleanup obligation is invalid: {error}"))?;
    let dimension: &'static str = match escalation_reason {
        "parent_loss" => "parent_loss",
        "provider_loss" => "provider_loss",
        other => return Err(format!("'{other}' is not an admitted escalation reason")),
    };
    let status = required_string(current, "/status")?;
    if !OPEN_OBLIGATION_STATUSES.contains(&status) {
        return Err(format!(
            "a {status} obligation is not open and admits no escalation"
        ));
    }
    if evidence_refs.is_empty() {
        return Err(err(
            dimension,
            "escalation requires the loss evidence it preserves",
        ));
    }
    // The lost parent must actually be a parent of this obligation, resolved
    // from the durable record, never from the caller's claim alone.
    let is_parent = [
        "/environment_ref",
        "/session_ref",
        "/originating_plan_ref",
        "/originating_execution_ref",
        "/provider_ref",
    ]
    .iter()
    .any(|pointer| opt_str(current, pointer) == Some(lost_parent_ref));
    if !is_parent {
        return Err(err(
            dimension,
            format!("'{lost_parent_ref}' is not a durable parent or provider of this obligation"),
        ));
    }
    let mut successor = current.clone();
    successor["status"] = json!("escalated");
    successor["predecessor_obligation_root"] = json!(obligation_revision_root(current)?);
    successor["revision"] = json!(
        current
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or("obligation lacks its revision")?
            + 1
    );
    successor["escalation"] = json!({
        "escalation_reason": escalation_reason,
        "lost_parent_ref": lost_parent_ref,
        "evidence_refs": evidence_refs,
    });
    // Escalation preserves the exact resource custody rows.
    if successor.get("resource_refs") != current.get("resource_refs") {
        return Err(err(
            dimension,
            "escalation may never mutate resource custody",
        ));
    }
    validate_architecture_contract(CLEANUP_OBLIGATION_CONTRACT, &successor)
        .map_err(|error| format!("escalated obligation revision is invalid: {error}"))?;
    Ok(successor)
}

/// The observed loss of a parent object escalates every open obligation bound
/// to it and returns the successor revisions. Nothing is ever removed: the
/// output covers every input obligation, closed ones byte-identical.
pub fn apply_parent_loss(
    obligations: &[Value],
    escalation_reason: &str,
    lost_parent_ref: &str,
    evidence_refs: &[String],
) -> Result<Vec<Value>, String> {
    let mut survivors = Vec::with_capacity(obligations.len());
    for obligation in obligations {
        let status = required_string(obligation, "/status")?;
        let is_parent = [
            "/environment_ref",
            "/session_ref",
            "/originating_plan_ref",
            "/originating_execution_ref",
            "/provider_ref",
        ]
        .iter()
        .any(|pointer| opt_str(obligation, pointer) == Some(lost_parent_ref));
        if is_parent && OPEN_OBLIGATION_STATUSES.contains(&status) {
            survivors.push(compile_cleanup_escalate(
                obligation,
                escalation_reason,
                lost_parent_ref,
                evidence_refs,
            )?);
        } else {
            survivors.push(obligation.clone());
        }
    }
    Ok(survivors)
}

/// The live plane state rebuilt from durable transitions only.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EnvironmentPlaneState {
    /// Every durable route-binding revision (immutable, lineage-linked).
    pub bindings: Vec<Value>,
    /// Every durable backup record.
    pub backups: Vec<Value>,
    /// Every durable immutable plan.
    pub plans: Vec<Value>,
    /// Committed stage indexes per plan ref.
    pub committed_stages: Vec<(String, Vec<u64>)>,
    /// The head revision of every cleanup obligation.
    pub obligations: Vec<Value>,
    /// Current active route head per identity (`identity`, `head ref`).
    pub active_heads: Vec<(String, String)>,
}

impl EnvironmentPlaneState {
    /// Committed stage indexes for one plan.
    pub fn stages_for(&self, plan_ref: &str) -> Vec<u64> {
        self.committed_stages
            .iter()
            .find(|(held, _)| held == plan_ref)
            .map(|(_, stages)| stages.clone())
            .unwrap_or_default()
    }
}

/// Pure replay over committed transitions and a record loader. This is the
/// restart path: no rebuildable head or projection record is consulted, only
/// immutable durable truth, and the derived plane root must recompute at
/// every step.
pub fn replay_environment_lifecycle(
    estate_namespace: &str,
    transitions: &[Value],
    load_record: &dyn Fn(&str, &str) -> Result<Option<Value>, String>,
) -> Result<(EnvironmentPlaneState, EnvironmentLifecycleLogHead), String> {
    let mut ordered: Vec<&Value> = transitions
        .iter()
        .filter(|value| {
            value.get("estate_namespace").and_then(Value::as_str) == Some(estate_namespace)
        })
        .collect();
    ordered.sort_by_key(|value| value.get("sequence").and_then(Value::as_u64).unwrap_or(0));
    let mut state = EnvironmentPlaneState::default();
    let mut sequence = 0u64;
    let mut expected_predecessor = environment_plane_root(estate_namespace, &[], &[], &[], &[])?;
    for transition in ordered {
        let this_sequence = transition
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or("committed transition lacks its sequence")?;
        if this_sequence != sequence + 1 {
            return Err("environment lifecycle log is not contiguous".to_owned());
        }
        if opt_str(transition, "/predecessor_plane_root") != Some(expected_predecessor.as_str()) {
            return Err("environment lifecycle log breaks its compare-and-swap chain".to_owned());
        }
        let op = EnvironmentLifecycleOp::parse(required_string(transition, "/op")?)
            .ok_or("committed transition names an unknown operation")?;
        let family = required_string(transition, "/record_family")?;
        let record_root = required_string(transition, "/record_root")?;
        let record = load_record(family, record_root)?
            .ok_or("committed transition lacks its durable record")?;
        let recomputed = if family == "hypervisor-resource-cleanup-obligations" {
            obligation_revision_root(&record)?
        } else {
            environment_artifact_root(&record)?
        };
        if recomputed != record_root {
            return Err("durable record does not recompute to its committed root".to_owned());
        }
        match op {
            EnvironmentLifecycleOp::DeclareRouteBinding => state.bindings.push(record),
            EnvironmentLifecycleOp::RecordBackup => state.backups.push(record),
            EnvironmentLifecycleOp::DeclareChangePlan => {
                let plan_ref = required_string(&record, "/plan_ref")?.to_owned();
                state.committed_stages.push((plan_ref, Vec::new()));
                state.plans.push(record);
            }
            EnvironmentLifecycleOp::AdvanceChangePlanStage => {
                let advance: CompiledStageAdvance = serde_json::from_value(record.clone())
                    .map_err(|error| format!("stage advance record is invalid: {error}"))?;
                let stages = state
                    .committed_stages
                    .iter_mut()
                    .find(|(held, _)| *held == advance.plan_ref)
                    .ok_or("stage advance names an unknown plan")?;
                if stages.1.contains(&advance.stage_index) {
                    return Err(err(
                        "backward_stage",
                        "replay found a re-entered stage; the log is not admissible",
                    ));
                }
                stages.1.push(advance.stage_index);
                if let Some(head_ref) = &advance.resulting_active_head_ref {
                    let plan = state
                        .plans
                        .iter()
                        .find(|plan| opt_str(plan, "/plan_ref") == Some(&advance.plan_ref))
                        .ok_or("stage advance names an unknown plan")?;
                    let candidate_ref = required_string(plan, "/activation/candidate_ref")?;
                    let candidate = state
                        .bindings
                        .iter()
                        .find(|binding| {
                            opt_str(binding, "/route_binding_ref") == Some(candidate_ref)
                        })
                        .ok_or("activation names an unknown binding revision")?;
                    let identity = route_identity(candidate)?;
                    state.active_heads.retain(|(held, _)| held != &identity);
                    state.active_heads.push((identity, head_ref.clone()));
                }
            }
            EnvironmentLifecycleOp::OpenCleanupObligation => state.obligations.push(record),
            EnvironmentLifecycleOp::SatisfyCleanupObligation
            | EnvironmentLifecycleOp::EscalateCleanupObligation => {
                let obligation_ref = required_string(&record, "/cleanup_obligation_ref")?;
                let held = state
                    .obligations
                    .iter_mut()
                    .find(|held| opt_str(held, "/cleanup_obligation_ref") == Some(obligation_ref))
                    .ok_or("obligation revision names an unknown obligation")?;
                if record.get("predecessor_obligation_root")
                    != Some(&json!(obligation_revision_root(held)?))
                {
                    return Err(
                        "obligation revision breaks its compare-and-swap lineage".to_owned()
                    );
                }
                *held = record;
            }
        }
        let derived = environment_plane_root(
            estate_namespace,
            &state.bindings,
            &state.backups,
            &state.plans,
            &state.obligations,
        )?;
        if opt_str(transition, "/resulting_plane_root") != Some(derived.as_str()) {
            return Err("replayed plane state does not recompute the committed root".to_owned());
        }
        expected_predecessor = derived;
        sequence = this_sequence;
    }
    Ok((
        state,
        EnvironmentLifecycleLogHead {
            sequence,
            plane_root: expected_predecessor,
        },
    ))
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

    fn estate() -> EnvironmentEstateBinding {
        EnvironmentEstateBinding {
            estate_namespace: "local".into(),
            daemon_ref: "runtime://local/daemon".into(),
        }
    }

    fn genesis_binding() -> Value {
        fixture("hypervisor-environment-route-binding-v1/positive-declared.json")
    }

    fn successor_binding() -> Value {
        fixture("hypervisor-environment-route-binding-v1/positive-successor.json")
    }

    fn observation_for(binding: &Value) -> Value {
        json!({
            "observation_ref": "evidence://local/routes/api.acme.example/observation/1",
            "hostname_or_address": binding["hostname_or_address"],
            "path_prefix": binding["path_prefix"],
            "target_protocol": binding["target_protocol"],
            "observed_target_endpoint_ref": binding["target_endpoint_ref"],
            "observed_owner_principal_ref": binding["owner_principal_ref"],
            "observed_system_ref": binding["system_ref"],
            "observed_tls_at_or_above_floor": true,
            "observed_certificate_matches_binding": true,
            "observed_provider_records_match": true,
            "observed_endpoint_reachable": true,
        })
    }

    fn digest_rows() -> Vec<Value> {
        vec![
            json!({
                "artifact_ref": format!("artifact://environment-backup-payload/{}", "11".repeat(8)),
                "sha256": h(0x21),
                "size_bytes": 4096,
                "role": "environment_backup_payload",
            }),
            json!({
                "artifact_ref": format!("artifact://environment-backup-payload/{}", "22".repeat(8)),
                "sha256": h(0x22),
                "size_bytes": 1024,
                "role": "workspace_snapshot",
            }),
        ]
    }

    fn compiled_backup() -> Value {
        compile_backup_record(
            &estate(),
            &BackupDeclaration {
                backup_tail: "env-alpha/2026-07-28/0001".into(),
                trigger: "pre_change".into(),
                environment_ref: "environment://local/env-alpha".into(),
                schedule_or_change_plan_ref: Some(
                    "change-plan://local/env-alpha/restore/0001".into(),
                ),
            },
            &h(0x0e),
            &digest_rows(),
            Some("system://acme/system-alpha"),
            "receipt://local/env-alpha/backup/0001",
        )
        .expect("backup compiles")
    }

    fn plan_for(backup: &Value, binding: &Value) -> Value {
        let mut plan = fixture("hypervisor-change-plan-v1/positive-restore-declared.json");
        plan["restore"]["source_backup_ref"] = backup["backup_ref"].clone();
        plan["restore"]["restore_manifest_root"] = backup["manifest_root"].clone();
        plan["restore"]["source_root_and_head_expectations"]["source_state_root_ref"] =
            backup["source_state_root_ref"].clone();
        plan["activation"]["candidate_ref"] = binding["route_binding_ref"].clone();
        plan["activation"]["expected_active_head_ref"] = Value::Null;
        plan["activation"]["candidate_generation"] = binding["activation_generation"].clone();
        plan["plan_hash"] = json!(change_plan_commitment(&plan).expect("plan hash"));
        plan
    }

    fn evidence_for(plan: &Value, stage_index: u64, backup: &Value) -> StageEvidence {
        let step = plan["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .find(|step| step["step_index"] == json!(stage_index))
            .expect("stage")
            .clone();
        let resolved: Vec<String> = step["evidence_requirement_refs"]
            .as_array()
            .expect("requirements")
            .iter()
            .map(|value| value.as_str().expect("ref").to_owned())
            .collect();
        StageEvidence {
            resolved_artifact_digests: backup["manifest_rows"].as_array().expect("rows").clone(),
            resolved_evidence_refs: resolved,
        }
    }

    #[test]
    fn scopes_are_distinct_and_never_reuse_prior_families() {
        let mut scopes: Vec<_> = EnvironmentLifecycleOp::ALL
            .into_iter()
            .map(EnvironmentLifecycleOp::required_scope)
            .collect();
        scopes.sort();
        scopes.dedup();
        assert_eq!(scopes.len(), EnvironmentLifecycleOp::ALL.len());
        assert!(scopes.iter().all(|scope| {
            scope.starts_with("scope:hypervisor_environment.")
                && !scope.starts_with("scope:autonomous_system.")
                && !scope.starts_with("scope:hypervisoros.")
        }));
        for op in EnvironmentLifecycleOp::ALL {
            assert!(
                super::super::system_membership_transitions::MembershipTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
        }
    }

    #[test]
    fn route_binding_lineage_is_strict_cas_and_never_forks() {
        let genesis = genesis_binding();
        let compiled =
            compile_route_binding_declaration(&estate(), &[], &genesis).expect("genesis compiles");
        assert_eq!(compiled, genesis);

        // A second genesis for the same identity refuses: the head must be cited.
        let error =
            compile_route_binding_declaration(&estate(), &[genesis.clone()], &genesis).unwrap_err();
        assert!(
            error.contains("cannot cite a predecessor") || error.contains("head"),
            "{error}"
        );

        let successor = successor_binding();
        compile_route_binding_declaration(&estate(), &[genesis.clone()], &successor)
            .expect("successor compiles");

        // With the successor admitted, re-declaring against the old head is stale.
        let stale = successor_binding();
        let error =
            compile_route_binding_declaration(&estate(), &[genesis.clone(), successor], &stale)
                .unwrap_err();
        assert!(error.starts_with("stale_activation"), "{error}");
    }

    // Dimension: owner drift at declaration (silent re-parenting refused).
    #[test]
    fn successor_that_reparents_the_route_is_refused_as_owner_drift() {
        let genesis = genesis_binding();
        let mut hostile = successor_binding();
        hostile["owner_principal_ref"] = json!("org://mallory/takeover");
        hostile["route_binding_hash"] =
            json!(route_binding_commitment(&hostile).expect("commitment"));
        let error = compile_route_binding_declaration(&estate(), &[genesis], &hostile).unwrap_err();
        assert!(error.starts_with("owner_drift"), "{error}");
    }

    // Dimensions: route drift and owner drift at observation. The declared
    // binding is never mutated and the observed binding is never adopted.
    #[test]
    fn route_and_owner_drift_observations_refuse_and_never_adopt() {
        let declared = genesis_binding();
        let before = serde_json::to_string(&declared).expect("bytes");

        let admitted = evaluate_route_binding_observation(&declared, &observation_for(&declared));
        assert!(admitted.admitted);

        let mut dns = observation_for(&declared);
        dns["observed_target_endpoint_ref"] = json!("endpoint://mallory/hijack");
        let verdict = evaluate_route_binding_observation(&declared, &dns);
        assert_eq!(verdict.refusal_dimension, Some("route_drift"));
        assert!(verdict
            .refusal_reason
            .as_deref()
            .unwrap()
            .contains("dns_divergence"));

        let mut tls = observation_for(&declared);
        tls["observed_tls_at_or_above_floor"] = json!(false);
        let verdict = evaluate_route_binding_observation(&declared, &tls);
        assert_eq!(verdict.refusal_dimension, Some("route_drift"));

        let mut owner = observation_for(&declared);
        owner["observed_owner_principal_ref"] = json!("org://mallory/takeover");
        let verdict = evaluate_route_binding_observation(&declared, &owner);
        assert_eq!(verdict.refusal_dimension, Some("owner_drift"));

        // The declared binding is byte-identical after every evaluation.
        assert_eq!(serde_json::to_string(&declared).expect("bytes"), before);
    }

    #[test]
    fn compiled_backup_is_manifest_complete_and_validates_the_contract() {
        let backup = compiled_backup();
        assert_eq!(backup["status"], "complete");
        assert_eq!(backup["manifest_artifact_count"], 2);
        assert_eq!(
            backup["manifest_root"],
            json!(backup_manifest_root(&backup).expect("root"))
        );
        // An empty capture can never compile a complete backup.
        let error = compile_backup_record(
            &estate(),
            &BackupDeclaration {
                backup_tail: "env-alpha/empty".into(),
                trigger: "manual".into(),
                environment_ref: "environment://local/env-alpha".into(),
                schedule_or_change_plan_ref: None,
            },
            &h(0x0e),
            &[],
            None,
            "receipt://local/env-alpha/backup/0002",
        )
        .unwrap_err();
        assert!(error.starts_with("incomplete_restoration"), "{error}");
    }

    #[test]
    fn change_plan_binds_the_backup_only_through_its_manifest_commitment() {
        let backup = compiled_backup();
        let binding = genesis_binding();
        let plan = plan_for(&backup, &binding);
        compile_change_plan_declaration(
            &estate(),
            &plan,
            &[backup.clone()],
            &[binding.clone()],
            &[],
        )
        .expect("plan compiles");

        // A substituted manifest commitment refuses.
        let mut forged = plan.clone();
        forged["restore"]["restore_manifest_root"] = json!(h(0x66));
        forged["plan_hash"] = json!(change_plan_commitment(&forged).expect("hash"));
        let error = compile_change_plan_declaration(
            &estate(),
            &forged,
            &[backup.clone()],
            &[binding.clone()],
            &[],
        )
        .unwrap_err();
        assert!(error.starts_with("incomplete_restoration"), "{error}");

        // A plan citing a superseded binding revision is stale at declaration.
        let successor = successor_binding();
        let error = compile_change_plan_declaration(
            &estate(),
            &plan,
            &[backup],
            &[binding, successor],
            &[],
        )
        .unwrap_err();
        assert!(error.starts_with("stale_activation"), "{error}");
    }

    // Dimension: incomplete restoration — missing row AND digest mismatch.
    #[test]
    fn incomplete_restoration_refuses_missing_row_and_digest_mismatch() {
        let backup = compiled_backup();
        let binding = genesis_binding();
        let plan = plan_for(&backup, &binding);
        let bindings = vec![binding];
        let backups = vec![backup.clone()];
        let preflight = evidence_for(&plan, 1, &backup);
        compile_stage_advance(&plan, &[], 1, &preflight, &backups, &bindings)
            .expect("preflight discharges");

        // Missing row: one resolved artifact vanished from the census.
        let mut missing = evidence_for(&plan, 2, &backup);
        missing.resolved_artifact_digests.pop();
        let error =
            compile_stage_advance(&plan, &[1], 2, &missing, &backups, &bindings).unwrap_err();
        assert!(error.starts_with("incomplete_restoration"), "{error}");
        assert!(error.contains("no resolved artifact bytes"), "{error}");

        // Digest mismatch: substituted bytes never restore.
        let mut substituted = evidence_for(&plan, 2, &backup);
        substituted.resolved_artifact_digests[0]["sha256"] = json!(h(0x77));
        let error =
            compile_stage_advance(&plan, &[1], 2, &substituted, &backups, &bindings).unwrap_err();
        assert!(error.starts_with("incomplete_restoration"), "{error}");
        assert!(error.contains("departs the manifest commitment"), "{error}");

        // A dropped manifest row inside the durable backup itself refuses too.
        let mut hollow = backup.clone();
        hollow["manifest_rows"].as_array_mut().expect("rows").pop();
        let error = compile_stage_advance(
            &plan,
            &[1],
            2,
            &evidence_for(&plan, 2, &backup),
            &[hollow],
            &bindings,
        )
        .unwrap_err();
        assert!(error.contains("invalid") || error.starts_with("incomplete_restoration"));
    }

    // Dimension: backward stage — no stage may re-enter a completed stage.
    #[test]
    fn backward_and_skipped_stage_transitions_are_refused() {
        let backup = compiled_backup();
        let binding = genesis_binding();
        let plan = plan_for(&backup, &binding);
        let bindings = vec![binding];
        let backups = vec![backup.clone()];

        // Re-entering the discharged preflight stage refuses.
        let error = compile_stage_advance(
            &plan,
            &[1, 2],
            1,
            &evidence_for(&plan, 1, &backup),
            &backups,
            &bindings,
        )
        .unwrap_err();
        assert!(error.starts_with("backward_stage"), "{error}");
        assert!(error.contains("never be re-entered"), "{error}");

        // Skipping ahead refuses: stages advance forward-only, one at a time.
        let error = compile_stage_advance(
            &plan,
            &[1],
            4,
            &evidence_for(&plan, 4, &backup),
            &backups,
            &bindings,
        )
        .unwrap_err();
        assert!(error.starts_with("backward_stage"), "{error}");
    }

    // Dimension: stale activation — a plan bound to a superseded binding
    // revision can never advance or reclaim the active head.
    #[test]
    fn stale_activation_refuses_superseded_plans() {
        let backup = compiled_backup();
        let genesis = genesis_binding();
        let plan = plan_for(&backup, &genesis);
        let backups = vec![backup.clone()];

        // While the genesis head is current, activation advances.
        let advance = compile_stage_advance(
            &plan,
            &[1, 2, 3],
            4,
            &evidence_for(&plan, 4, &backup),
            &backups,
            &[genesis.clone()],
        )
        .expect("activation advances");
        assert_eq!(advance.activation_outcome, "advanced");
        assert_eq!(
            advance.resulting_active_head_ref.as_deref(),
            genesis["route_binding_ref"].as_str()
        );

        // After a newer admitted successor, the same plan refuses.
        let successor = successor_binding();
        let error = compile_stage_advance(
            &plan,
            &[1, 2, 3],
            4,
            &evidence_for(&plan, 4, &backup),
            &backups,
            &[genesis, successor],
        )
        .unwrap_err();
        assert!(error.starts_with("stale_activation"), "{error}");
        assert!(error.contains("refused_superseded"), "{error}");
    }

    // Dimensions: parent loss and provider loss escalate, never erase.
    #[test]
    fn parent_and_provider_loss_escalate_obligations_and_never_erase_them() {
        let open = fixture("hypervisor-resource-cleanup-obligation-v1/positive-open.json");
        let obligations = vec![open.clone()];

        let after_parent_loss = apply_parent_loss(
            &obligations,
            "parent_loss",
            "environment://local/env-alpha",
            &["evidence://local/env-alpha/deletion".to_owned()],
        )
        .expect("parent loss escalates");
        assert_eq!(after_parent_loss.len(), obligations.len());
        assert_eq!(after_parent_loss[0]["status"], "escalated");
        assert_eq!(
            after_parent_loss[0]["escalation"]["escalation_reason"],
            "parent_loss"
        );
        // The resource custody rows survive byte-exactly.
        assert_eq!(after_parent_loss[0]["resource_refs"], open["resource_refs"]);

        let after_provider_loss = apply_parent_loss(
            &obligations,
            "provider_loss",
            "provider-account://pacc_route_edge",
            &["evidence://local/pacc_route_edge/revoked".to_owned()],
        )
        .expect("provider loss escalates");
        assert_eq!(after_provider_loss[0]["status"], "escalated");
        assert_eq!(
            after_provider_loss[0]["escalation"]["escalation_reason"],
            "provider_loss"
        );

        // A foreign ref is not a parent: the loss claim itself is refused.
        let error = compile_cleanup_escalate(
            &open,
            "parent_loss",
            "environment://mallory/other",
            &["evidence://mallory/claim".to_owned()],
        )
        .unwrap_err();
        assert!(error.starts_with("parent_loss"), "{error}");
    }

    // Dimension: unreceipted close — no closing disposition without a receipt.
    #[test]
    fn an_obligation_can_never_close_without_a_receipted_disposition() {
        let open = fixture("hypervisor-resource-cleanup-obligation-v1/positive-open.json");
        let error = compile_cleanup_satisfy(&open, "completed", None, &[]).unwrap_err();
        assert!(error.starts_with("unreceipted_close"), "{error}");

        let closed = compile_cleanup_satisfy(
            &open,
            "completed",
            Some("receipt://local/env-alpha/cleanup/0001"),
            &["evidence://local/env-alpha/cleanup/absent".to_owned()],
        )
        .expect("receipted close");
        assert_eq!(closed["status"], "completed");
        assert_eq!(closed["revision"], 2);
        assert_eq!(
            closed["predecessor_obligation_root"],
            json!(obligation_revision_root(&open).expect("root"))
        );

        // A closed obligation admits no further disposition.
        let error = compile_cleanup_satisfy(
            &closed,
            "abandoned",
            Some("receipt://local/env-alpha/cleanup/0002"),
            &[],
        )
        .unwrap_err();
        assert!(error.contains("no further disposition"), "{error}");
    }

    #[test]
    fn registered_fixtures_recompute_their_commitments() {
        let binding = genesis_binding();
        assert_eq!(
            binding["route_binding_hash"],
            json!(route_binding_commitment(&binding).expect("commitment"))
        );
        let plan = fixture("hypervisor-change-plan-v1/positive-restore-declared.json");
        assert_eq!(
            plan["plan_hash"],
            json!(change_plan_commitment(&plan).expect("commitment"))
        );
        let backup = fixture("hypervisor-environment-backup-v1/positive-complete.json");
        assert_eq!(
            backup["manifest_root"],
            json!(backup_manifest_root(&backup).expect("root"))
        );
    }
}
