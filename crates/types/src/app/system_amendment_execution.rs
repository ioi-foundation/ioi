//! Protected constitutional amendment execution (M1.5c).
//!
//! The declaration family (`ioi.autonomous-system-constitution-amendment.v1`)
//! states what changes; this module owns the machine floor that decides
//! whether an approved declaration may execute on the live chain: the
//! canonical predecessor→successor diff, the unamendable-path floor, the
//! semver lineage rule, and (in the plan compiler) the closed amendment
//! authority effect. Amendment never alters operational status and never
//! touches the fourteen operational ops in
//! [`super::system_lifecycle_transitions`].

use serde_json::{json, Value};

use super::system_activation::{
    jcs_hash, namespace, required_string, UnverifiedCommittedSystemLifecycleStep,
};
use super::system_lifecycle_transitions::{
    predecessor_state_facts, required_effect_string, validate_activation_identity,
    ProtectedLifecycleStatus, LIFECYCLE_STATE_HASH_PROFILE,
};

/// Constitution fields excluded from the amendable body: lineage and
/// admission coordinates change only through their own rules, never as a
/// diff. `version` and `predecessor_constitution_ref` are verified by the
/// lineage checks instead; the rest may never differ at all.
pub const STRUCTURAL_CONSTITUTION_FIELDS: [&str; 8] = [
    "schema_version",
    "constitution_id",
    "system_id",
    "version",
    "predecessor_constitution_ref",
    "constitution_root",
    "activation_receipt_ref",
    "status",
];

/// The M1 machine-protected subtree: amending the amendment rules is a
/// distinct, not-yet-implemented path, so every `/governance/...` pointer is
/// refused outright. Clause-ref semantic mappings beyond this floor remain
/// declared governance evidence, not machine truth.
pub const MACHINE_PROTECTED_POINTER_PREFIX: &str = "/governance";

/// Canonical JSON-pointer diff between two constitution bodies.
///
/// Walks both values structurally and returns the sorted, deduplicated set
/// of RFC 6901 pointers at which they differ. Object differences recurse to
/// the deepest differing member (an added or removed key yields the pointer
/// of that key); arrays are compared as whole leaves (any inequality yields
/// the array's own pointer) so reordering cannot masquerade as an untouched
/// path. Structural fields are excluded at the top level only.
pub fn canonical_constitution_diff(predecessor: &Value, successor: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    diff_into(predecessor, successor, "", true, &mut paths);
    paths.sort();
    paths.dedup();
    paths
}

fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn diff_into(a: &Value, b: &Value, pointer: &str, top: bool, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(map_a), Value::Object(map_b)) => {
            let mut keys: Vec<&String> = map_a.keys().chain(map_b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                if top && STRUCTURAL_CONSTITUTION_FIELDS.contains(&key.as_str()) {
                    continue;
                }
                let child = format!("{pointer}/{}", escape_token(key));
                match (map_a.get(key), map_b.get(key)) {
                    (Some(va), Some(vb)) => diff_into(va, vb, &child, false, out),
                    _ => out.push(child),
                }
            }
        }
        _ => {
            if a != b {
                out.push(if pointer.is_empty() {
                    "/".to_owned()
                } else {
                    pointer.to_owned()
                });
            }
        }
    }
}

/// Strict semver ordering for the constitution `version` lineage rule.
///
/// Accepts exactly `MAJOR.MINOR.PATCH` with plain non-negative integers (no
/// pre-release or build tags: constitution versions are governance lineage,
/// not software releases). Returns an error for any malformed input rather
/// than guessing.
pub fn semver_strictly_greater(successor: &str, predecessor: &str) -> Result<bool, String> {
    Ok(parse_semver(successor)? > parse_semver(predecessor)?)
}

fn parse_semver(text: &str) -> Result<(u64, u64, u64), String> {
    let mut parts = text.split('.');
    let mut next = |name: &str| -> Result<u64, String> {
        let piece = parts
            .next()
            .ok_or_else(|| format!("constitution version lacks a {name} component: {text}"))?;
        if piece.is_empty() || piece.len() > 9 || !piece.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "constitution version {name} component is not a plain integer: {text}"
            ));
        }
        if piece.len() > 1 && piece.starts_with('0') {
            return Err(format!(
                "constitution version {name} component has a leading zero: {text}"
            ));
        }
        piece
            .parse::<u64>()
            .map_err(|_| format!("constitution version {name} component overflows: {text}"))
    };
    let triple = (next("major")?, next("minor")?, next("patch")?);
    if parts.next().is_some() {
        return Err(format!(
            "constitution version has more than three components: {text}"
        ));
    }
    Ok(triple)
}

/// True when `pointer` falls under the machine-protected floor: any
/// `/governance` path (subtree self-protection) — structural fields never
/// appear in a diff at all because [`canonical_constitution_diff`] excludes
/// them before comparison.
pub fn pointer_is_machine_protected(pointer: &str) -> bool {
    pointer == MACHINE_PROTECTED_POINTER_PREFIX || pointer.starts_with("/governance/")
}

/// JCS domain for the amendment-declaration root.
pub(crate) const AMENDMENT_DECLARATION_HASH_PROFILE: &str =
    "ioi.autonomous-system-constitution-amendment-jcs-sha256.v1";
/// JCS domain for the external-governance approval decision that makes a
/// declaration eligible for execution. This is deliberately distinct from
/// the later wallet-backed execution decision.
pub(crate) const AMENDMENT_APPROVAL_DECISION_HASH_PROFILE: &str =
    "ioi.autonomous-system-constitution-amendment-approval-decision-jcs-sha256.v1";
/// JCS domain for a constitution's authoritative root. This is the SAME
/// profile-candidate recipe genesis and activation already use, so the
/// chain, the active profile set, and the amendment families all name a
/// constitution by one value. The body's own `constitution_root` field is a
/// declared, non-authoritative field (it cannot hold this root without
/// self-reference) and is carried verbatim across revisions.
pub(crate) const CONSTITUTION_HASH_PROFILE: &str =
    "ioi.autonomous-system-profile-candidate-jcs-sha256.v1";
/// JCS domain for the changed-path set commitment.
pub(crate) const CHANGED_PATHS_HASH_PROFILE: &str =
    "ioi.autonomous-system-amendment-changed-paths-jcs-sha256.v1";
/// JCS domain for the successor active-profile-set (v2) root.
pub(crate) const ACTIVE_PROFILE_SET_V2_HASH_PROFILE: &str =
    "ioi.autonomous-system-active-profile-set-jcs-sha256.v2";
/// JCS domain for the amendment-execution operation commitment.
const AMENDMENT_COMMITMENT_HASH_PROFILE: &str =
    "ioi.autonomous-system-amendment-execution-commitment-jcs-sha256.v1";
/// Wire schema of the closed amendment authority effect.
const AMENDMENT_AUTHORITY_EFFECT_SCHEMA: &str =
    "ioi.autonomous-system-amendment-execution-authority-effect.v1";
/// The single amendment op name and its exact wallet scope.
pub const AMENDMENT_OP: &str = "amend_constitution";
/// Exact wallet.network scope for amendment execution; no
/// `scope:autonomous_system.lifecycle.*` grant may satisfy it.
pub const AMENDMENT_REQUIRED_SCOPE: &str = "scope:autonomous_system.lifecycle.amend_constitution";

/// Compiled amendment-execution plan: every root the commit will persist,
/// derived server-side from committed truth plus the proposed declaration
/// and successor body.
#[derive(Debug, Clone)]
pub struct CompiledAmendmentExecutionPlan {
    /// Committed sequence (predecessor sequence plus one; always >= 3).
    pub sequence: u64,
    /// Operational status, unchanged by amendment (active or paused).
    pub status: ProtectedLifecycleStatus,
    /// Explicitly unverified predecessor step artifacts.
    pub previous_step: UnverifiedCommittedSystemLifecycleStep,
    /// The verbatim approved declaration (retained evidence).
    pub amendment: Value,
    /// Recomputed declaration root.
    pub amendment_root: String,
    /// The external-governance decision approving this exact declaration.
    pub approval_decision: Value,
    /// Recomputed approval-decision root.
    pub approval_decision_root: String,
    /// The successor constitution exactly as it will persist.
    pub successor_constitution: Value,
    /// Recomputed successor constitution root.
    pub successor_constitution_root: String,
    /// The canonical computed diff (sorted RFC 6901 pointers).
    pub changed_field_paths: Vec<String>,
    /// Commitment over the computed diff.
    pub changed_field_paths_commitment: String,
    /// Semantic successor active-profile-set (v2; admitted_by slots empty).
    pub successor_profile_set: Value,
    /// Recomputed successor profile-set root.
    pub successor_profile_set_root: String,
    /// Semantic resulting lifecycle-state projection (downstream slots empty).
    pub semantic_state: Value,
    /// Exact resulting lifecycle-state root.
    pub resulting_state_root: String,
    /// Closed server-derived authority effect.
    pub authority_effect: Value,
}

fn required_field<'a>(value: &'a Value, name: &str, what: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("{what} lacks {name}"))
}

fn canonical_hash_or_err(value: &str, what: &str) -> Result<(), String> {
    if value.strip_prefix("sha256:").map(str::len) != Some(64) {
        return Err(format!("{what} is not a canonical hash"));
    }
    Ok(())
}

fn string_array(value: &Value, name: &str, what: &str) -> Result<Vec<String>, String> {
    let items = value
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{what} lacks {name}"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("{what} {name} carries a non-string entry"))
        })
        .collect()
}

/// Resolve the explicit M1 pointer protections, with a narrow migration for
/// constitutions admitted before `protected_field_paths` existed. Legacy
/// clause references are never silently dropped: every reference must have a
/// known deterministic pointer meaning or amendment fails closed.
fn constitution_protected_paths(governance: &Value) -> Result<Vec<String>, String> {
    if governance.get("protected_field_paths").is_some() {
        return string_array(
            governance,
            "protected_field_paths",
            "predecessor constitution governance",
        );
    }
    let clauses = string_array(
        governance,
        "protected_clause_refs",
        "predecessor constitution governance",
    )?;
    clauses
        .into_iter()
        .map(|clause| {
            if clause.ends_with("/purpose") {
                Ok("/declared_purpose".to_owned())
            } else {
                Err(format!(
                    "legacy protected clause {clause} has no deterministic field-path migration"
                ))
            }
        })
        .collect()
}

fn pointer_covered_by(pointer: &str, protected: &str) -> bool {
    pointer == protected
        || pointer.starts_with(&format!("{protected}/"))
        || protected.starts_with(&format!("{pointer}/"))
}

/// The authoritative root of a constitution body: the profile-candidate
/// recipe genesis and activation already use, over the WHOLE body.
///
/// One constitution therefore has exactly one root everywhere it is named
/// (chain head, active profile set, amendment declaration, substrate key).
pub fn constitution_candidate_root(constitution: &Value) -> Result<String, String> {
    if !constitution.is_object() {
        return Err("constitution is not an object".to_owned());
    }
    jcs_hash(&json!({
        "domain": CONSTITUTION_HASH_PROFILE,
        "kind": "constitution",
        "candidate": constitution,
    }))
}

/// Recompute the declaration root over the verbatim proposed declaration.
pub fn amendment_declaration_root(amendment: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": AMENDMENT_DECLARATION_HASH_PROFILE,
        "amendment": amendment,
    }))
}

/// Recompute an external-governance amendment approval decision. The root
/// field is excluded from its own material; every other closed field is
/// retained, so the decision cannot be copied across declarations, profiles,
/// evidence sets, or authority requirements.
pub fn amendment_approval_decision_root(decision: &Value) -> Result<String, String> {
    let mut material = decision
        .as_object()
        .cloned()
        .ok_or("amendment approval decision is not an object")?;
    material.remove("decision_root");
    material.insert(
        "domain".to_owned(),
        Value::String(AMENDMENT_APPROVAL_DECISION_HASH_PROFILE.to_owned()),
    );
    jcs_hash(&Value::Object(material))
}

/// Recompute the changed-path commitment over the computed canonical diff.
pub fn changed_paths_commitment(paths: &[String]) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": CHANGED_PATHS_HASH_PROFILE,
        "changed_field_paths": paths,
    }))
}

/// Recompute a successor active-profile-set (v2) root: the invariant
/// material, which excludes the admitted_by navigation slots.
pub fn active_profile_set_v2_root(set: &Value) -> Result<String, String> {
    let field = |name: &str| {
        set.get(name)
            .cloned()
            .ok_or_else(|| format!("active profile set lacks {name}"))
    };
    jcs_hash(&json!({
        "domain": ACTIVE_PROFILE_SET_V2_HASH_PROFILE,
        "active_profile_set_ref": field("active_profile_set_ref")?,
        "system_id": field("system_id")?,
        "genesis_ref": field("genesis_ref")?,
        "profile_bundle_root": field("profile_bundle_root")?,
        "supersedes_profile_set_ref": field("supersedes_profile_set_ref")?,
        "supersedes_profile_set_root": field("supersedes_profile_set_root")?,
        "constitution": field("constitution")?,
        "deployment": field("deployment")?,
        "ordering_admission_finality": field("ordering_admission_finality")?,
        "oracle_evidence_profiles": field("oracle_evidence_profiles")?,
        "lifecycle_continuity": field("lifecycle_continuity")?,
        "network_enrollment": field("network_enrollment")?,
        "status": field("status")?,
    }))
}

/// Compile one constitutional amendment execution over the live chain.
///
/// The caller supplies committed truth (activation identity effect, exact
/// predecessor step, chain head root, the chain's active constitution root,
/// and the currently active profile set) plus the proposed declaration,
/// the predecessor constitution body, and the successor body as it should
/// persist. Everything else is derived here; nothing caller-supplied is
/// trusted beyond exact-match verification against that committed truth.
#[allow(clippy::too_many_arguments)]
pub fn compile_amendment_execution_plan(
    activation_effect: &Value,
    previous_step: &UnverifiedCommittedSystemLifecycleStep,
    chain_head_root: &str,
    chain_constitution_root: &str,
    activation_receipt_ref: &str,
    amendment: &Value,
    approval_decision: &Value,
    approval_authority_evidence_root: &str,
    predecessor_constitution: &Value,
    successor_constitution: &Value,
    predecessor_profile_set: &Value,
) -> Result<CompiledAmendmentExecutionPlan, String> {
    validate_activation_identity(activation_effect)?;
    canonical_hash_or_err(chain_head_root, "predecessor chain head root")?;
    canonical_hash_or_err(chain_constitution_root, "chain constitution root")?;
    canonical_hash_or_err(
        approval_authority_evidence_root,
        "approval authority evidence root",
    )?;
    if !activation_receipt_ref.starts_with("receipt://") {
        return Err("active chain carries a non-canonical activation receipt ref".to_owned());
    }

    let system_id = required_effect_string(activation_effect, "system_id")?;
    let (predecessor_state_ref, predecessor_sequence, status) =
        predecessor_state_facts(&previous_step.state)?;
    if required_string(&previous_step.state, "/system_id")? != system_id {
        return Err("predecessor state detaches from the identity System".to_owned());
    }
    if !matches!(
        status,
        ProtectedLifecycleStatus::Active | ProtectedLifecycleStatus::Paused
    ) {
        return Err(format!(
            "constitutional amendment cannot execute from {}",
            status.as_str(),
        ));
    }
    let sequence = predecessor_sequence
        .checked_add(1)
        .filter(|next| *next >= 3)
        .ok_or("resulting sequence is not three or later")?;

    // Declaration discipline: execution consumes an already-approved
    // declaration. The wallet-backed decision minted later authorizes the
    // chain effect; it must never substitute for the constitution's external
    // governance decision that approved the declaration itself.
    if required_field(amendment, "schema_version", "amendment declaration")?
        != "ioi.autonomous-system-constitution-amendment.v1"
    {
        return Err("amendment declaration carries a foreign schema_version".to_owned());
    }
    if required_field(amendment, "status", "amendment declaration")? != "approved" {
        return Err("only an approved amendment declaration may execute".to_owned());
    }
    if required_field(amendment, "system_id", "amendment declaration")? != system_id {
        return Err("amendment declaration detaches from the identity System".to_owned());
    }
    let amendment_id = required_field(amendment, "amendment_id", "amendment declaration")?;
    if !amendment_id.starts_with("constitution-amendment://") {
        return Err("amendment declaration id is not a constitution-amendment ref".to_owned());
    }
    if required_field(
        amendment,
        "predecessor_constitution_root",
        "amendment declaration",
    )? != chain_constitution_root
    {
        return Err(
            "amendment declaration does not bind the chain's active constitution".to_owned(),
        );
    }
    let declaration_decision_ref =
        required_field(amendment, "decision_ref", "approved amendment declaration")?;

    // Predecessor constitution: the supplied body must BE the constitution
    // the chain names, proven by recomputing its authoritative root.
    if constitution_candidate_root(predecessor_constitution)? != chain_constitution_root {
        return Err("predecessor constitution does not recompute to the chain's root".to_owned());
    }
    if required_field(
        predecessor_constitution,
        "system_id",
        "predecessor constitution",
    )? != system_id
    {
        return Err("predecessor constitution detaches from the identity System".to_owned());
    }
    let predecessor_constitution_id = required_field(
        predecessor_constitution,
        "constitution_id",
        "predecessor constitution",
    )?;
    if required_field(
        amendment,
        "predecessor_constitution_ref",
        "amendment declaration",
    )? != predecessor_constitution_id
    {
        return Err("amendment declaration names a different predecessor constitution".to_owned());
    }

    // The active constitution, never the request, owns amendment governance.
    let governance = predecessor_constitution
        .get("governance")
        .and_then(Value::as_object)
        .ok_or("predecessor constitution lacks governance")?;
    if governance.get("amendment_mode").and_then(Value::as_str) != Some("external_governance_only")
    {
        return Err("active constitution does not admit external-governance amendment".to_owned());
    }
    if governance.get("agent_may_commit_amendment") != Some(&Value::Bool(false)) {
        return Err("active constitution does not forbid agent amendment commit".to_owned());
    }
    let governing_profile = governance
        .get("amendment_decision_profile_ref")
        .and_then(Value::as_str)
        .ok_or("active constitution lacks amendment_decision_profile_ref")?;
    if required_field(
        amendment,
        "governing_decision_profile_ref",
        "amendment declaration",
    )? != governing_profile
    {
        return Err("amendment declaration names a foreign governance decision profile".to_owned());
    }
    let execution_authority =
        required_effect_string(activation_effect, "source_governing_authority_ref")?;
    if execution_authority.starts_with("system://") || execution_authority.starts_with("agent://") {
        return Err(
            "agent or System principal may not commit a constitutional amendment".to_owned(),
        );
    }
    let governance_owners = string_array(
        &Value::Object(governance.clone()),
        "governance_owner_refs",
        "predecessor constitution governance",
    )?;
    let accountable = string_array(
        &Value::Object(governance.clone()),
        "accountable_principal_refs",
        "predecessor constitution governance",
    )?;
    if !governance_owners
        .iter()
        .chain(accountable.iter())
        .any(|value| value == execution_authority)
    {
        return Err("execution authority is not an accountable constitutional governor".to_owned());
    }

    // Successor lineage.
    if required_field(
        successor_constitution,
        "system_id",
        "successor constitution",
    )? != system_id
    {
        return Err("successor constitution detaches from the identity System".to_owned());
    }
    let successor_constitution_id = required_field(
        successor_constitution,
        "constitution_id",
        "successor constitution",
    )?;
    if successor_constitution_id == predecessor_constitution_id {
        return Err("successor constitution reuses the predecessor identity".to_owned());
    }
    if required_field(
        successor_constitution,
        "predecessor_constitution_ref",
        "successor constitution",
    )? != predecessor_constitution_id
    {
        return Err("successor constitution does not name its predecessor".to_owned());
    }
    if required_field(successor_constitution, "status", "successor constitution")? != "active" {
        return Err("successor constitution must persist as active".to_owned());
    }
    let predecessor_version = required_field(
        predecessor_constitution,
        "version",
        "predecessor constitution",
    )?;
    let successor_version =
        required_field(successor_constitution, "version", "successor constitution")?;
    if !semver_strictly_greater(successor_version, predecessor_version)? {
        return Err(format!(
            "successor version {successor_version} does not advance {predecessor_version}",
        ));
    }
    if required_field(
        amendment,
        "proposed_successor_constitution_ref",
        "amendment declaration",
    )? != successor_constitution_id
    {
        return Err("amendment declaration names a different successor constitution".to_owned());
    }
    let successor_constitution_root = constitution_candidate_root(successor_constitution)?;
    if successor_constitution_root == chain_constitution_root {
        return Err("successor constitution is byte-identical to the predecessor".to_owned());
    }
    // The body's own `constitution_root` field cannot hold this root without
    // self-reference; it is structural (diff-excluded) and must be carried
    // verbatim so the successor never restates a different self-claim.
    if successor_constitution.get("constitution_root")
        != predecessor_constitution.get("constitution_root")
    {
        return Err(
            "successor constitution must carry the predecessor's declared constitution_root field"
                .to_owned(),
        );
    }
    if required_field(
        amendment,
        "proposed_successor_constitution_root",
        "amendment declaration",
    )? != successor_constitution_root
    {
        return Err("amendment declaration does not bind the recomputed successor root".to_owned());
    }
    // All diff-excluded structural fields must be enforced explicitly. The
    // identity, version, predecessor ref, root, system id, and status checks
    // above cover seven fields; activation receipt continuity closes the
    // eighth instead of letting it disappear from the canonical diff. The
    // admitted genesis body is a draft and therefore carries null here; an
    // active successor must bind the sequence-two receipt proven by the
    // operation log, never a caller-selected value.
    if successor_constitution
        .get("activation_receipt_ref")
        .and_then(Value::as_str)
        != Some(activation_receipt_ref)
    {
        return Err(
            "successor constitution does not bind the committed activation_receipt_ref".to_owned(),
        );
    }

    // The canonical diff is the truth; the declaration must state it exactly
    // and may not touch the machine floor or its own declared protections.
    let changed_field_paths =
        canonical_constitution_diff(predecessor_constitution, successor_constitution);
    if changed_field_paths.is_empty() {
        return Err("amendment changes nothing amendable".to_owned());
    }
    let mut declared = string_array(amendment, "changed_field_paths", "amendment declaration")?;
    declared.sort();
    declared.dedup();
    if declared != changed_field_paths {
        return Err(format!(
            "declared changed paths do not equal the canonical diff (declared {declared:?}, computed {changed_field_paths:?})",
        ));
    }
    let mut protected = constitution_protected_paths(&Value::Object(governance.clone()))?;
    protected.sort();
    protected.dedup();
    let mut declared_protected =
        string_array(amendment, "protected_field_paths", "amendment declaration")?;
    declared_protected.sort();
    declared_protected.dedup();
    if declared_protected != protected {
        return Err(
            "declared protected paths do not equal committed constitution truth".to_owned(),
        );
    }
    for pointer in &changed_field_paths {
        if pointer_is_machine_protected(pointer) {
            return Err(format!("{pointer} is machine-protected in M1"));
        }
        if let Some(shield) = protected.iter().find(|p| pointer_covered_by(pointer, p)) {
            return Err(format!("{pointer} is protected by declared path {shield}"));
        }
    }
    let changed_field_paths_commitment = changed_paths_commitment(&changed_field_paths)?;

    // Current profile set: must be the predecessor state's exact set and
    // must pin the constitution being amended.
    let state_set_ref = required_string(&previous_step.state, "/active_profile_set_ref")?;
    let state_set_root = required_string(&previous_step.state, "/active_profile_set_root")?;
    if required_field(
        predecessor_profile_set,
        "active_profile_set_ref",
        "active profile set",
    )? != state_set_ref
    {
        return Err("supplied profile set is not the predecessor state's set".to_owned());
    }
    if required_field(predecessor_profile_set, "system_id", "active profile set")? != system_id {
        return Err("active profile set detaches from the identity System".to_owned());
    }
    let set_constitution = predecessor_profile_set
        .get("constitution")
        .and_then(Value::as_object)
        .ok_or("active profile set lacks its constitution entry")?;
    if set_constitution
        .get("candidate_profile_root")
        .and_then(Value::as_str)
        != Some(chain_constitution_root)
    {
        return Err("active profile set does not pin the constitution being amended".to_owned());
    }

    // Mint the successor set: constitution entry swaps, everything else is
    // carried verbatim.
    let carried = |name: &str| {
        predecessor_profile_set
            .get(name)
            .cloned()
            .ok_or_else(|| format!("active profile set lacks {name}"))
    };
    let successor_set_ref = format!(
        "active-profile-set://{}/sequence/{}",
        namespace(system_id)?,
        sequence,
    );
    let mut successor_profile_set = json!({
        "schema_version": "ioi.autonomous-system-active-profile-set.v2",
        "active_profile_set_ref": successor_set_ref,
        "active_profile_set_root": Value::Null,
        "system_id": system_id,
        "genesis_ref": carried("genesis_ref")?,
        "profile_bundle_root": carried("profile_bundle_root")?,
        "supersedes_profile_set_ref": state_set_ref,
        "supersedes_profile_set_root": state_set_root,
        "constitution": {
            "candidate_profile_ref": successor_constitution_id,
            "candidate_profile_root": successor_constitution_root,
            "admitted_posture": "active",
        },
        "deployment": carried("deployment")?,
        "ordering_admission_finality": carried("ordering_admission_finality")?,
        "oracle_evidence_profiles": carried("oracle_evidence_profiles")?,
        "lifecycle_continuity": carried("lifecycle_continuity")?,
        "network_enrollment": carried("network_enrollment")?,
        "admitted_by_transition_ref": Value::Null,
        "admitted_by_receipt_ref": Value::Null,
        "status": "active",
    });
    let successor_profile_set_root = active_profile_set_v2_root(&successor_profile_set)?;
    successor_profile_set["active_profile_set_root"] =
        Value::String(successor_profile_set_root.clone());

    // Resulting lifecycle state: status unchanged, successor set coordinates.
    let lifecycle_state_ref = format!(
        "system-lifecycle-state://{}/sequence/{}",
        namespace(system_id)?,
        sequence,
    );
    let state_material = json!({
        "domain": LIFECYCLE_STATE_HASH_PROFILE,
        "lifecycle_state_ref": lifecycle_state_ref,
        "system_id": system_id,
        "sequence": sequence,
        "status": status.as_str(),
        "predecessor_state_root": previous_step.state_root,
        "active_profile_set_ref": successor_set_ref,
        "active_profile_set_root": successor_profile_set_root,
    });
    let resulting_state_root = jcs_hash(&state_material)?;
    let semantic_state = json!({
        "schema_version": "ioi.autonomous-system-lifecycle-state.v1",
        "lifecycle_state_ref": lifecycle_state_ref,
        "lifecycle_state_root": resulting_state_root,
        "system_id": system_id,
        "sequence": sequence,
        "status": status.as_str(),
        "predecessor_state_root": previous_step.state_root,
        "transition_ref": Value::Null,
        "transition_root": Value::Null,
        "transition_receipt_ref": Value::Null,
        "transition_receipt_root": Value::Null,
        "active_profile_set_ref": successor_set_ref,
        "active_profile_set_root": successor_profile_set_root,
        "chain_ref": required_effect_string(activation_effect, "chain_ref")?,
        "created_at": Value::Null,
    });

    let amendment_root = amendment_declaration_root(amendment)?;
    if required_field(
        approval_decision,
        "schema_version",
        "amendment approval decision",
    )? != "ioi.autonomous-system-constitution-amendment-approval-decision.v1"
    {
        return Err("amendment approval decision carries a foreign schema_version".to_owned());
    }
    if required_field(approval_decision, "outcome", "amendment approval decision")? != "approved" {
        return Err("amendment approval decision is not approved".to_owned());
    }
    if required_field(
        approval_decision,
        "decision_ref",
        "amendment approval decision",
    )? != declaration_decision_ref
        || required_field(
            approval_decision,
            "amendment_ref",
            "amendment approval decision",
        )? != amendment_id
        || required_field(
            approval_decision,
            "amendment_root",
            "amendment approval decision",
        )? != amendment_root
        || required_field(
            approval_decision,
            "proposal_ref",
            "amendment approval decision",
        )? != required_field(amendment, "proposal_ref", "amendment declaration")?
        || required_field(
            approval_decision,
            "system_id",
            "amendment approval decision",
        )? != system_id
        || required_field(
            approval_decision,
            "governing_decision_profile_ref",
            "amendment approval decision",
        )? != governing_profile
        || required_field(
            approval_decision,
            "predecessor_constitution_root",
            "amendment approval decision",
        )? != chain_constitution_root
        || required_field(
            approval_decision,
            "successor_constitution_root",
            "amendment approval decision",
        )? != successor_constitution_root
        || required_field(
            approval_decision,
            "changed_field_paths_commitment",
            "amendment approval decision",
        )? != changed_field_paths_commitment
    {
        return Err("amendment approval decision does not bind the exact declaration".to_owned());
    }
    let mut approval_evidence = string_array(
        approval_decision,
        "evidence_refs",
        "amendment approval decision",
    )?;
    let mut declaration_evidence =
        string_array(amendment, "evidence_refs", "amendment declaration")?;
    approval_evidence.sort();
    declaration_evidence.sort();
    let mut approval_requirements = string_array(
        approval_decision,
        "authority_requirement_refs",
        "amendment approval decision",
    )?;
    let mut declaration_requirements = string_array(
        amendment,
        "authority_requirement_refs",
        "amendment declaration",
    )?;
    approval_requirements.sort();
    declaration_requirements.sort();
    if approval_evidence != declaration_evidence
        || approval_requirements != declaration_requirements
    {
        return Err(
            "amendment approval decision changes evidence or authority requirements".to_owned(),
        );
    }
    let approval_decision_root = amendment_approval_decision_root(approval_decision)?;
    if required_field(
        approval_decision,
        "decision_root",
        "amendment approval decision",
    )? != approval_decision_root
    {
        return Err("amendment approval decision root does not recompute".to_owned());
    }

    let mut effect = json!({
        "schema_version": AMENDMENT_AUTHORITY_EFFECT_SCHEMA,
        "op": AMENDMENT_OP,
        "required_scope": AMENDMENT_REQUIRED_SCOPE,
        "sequence": sequence,
        "irreversibility": "one_way",
        "system_id": system_id,
        "genesis_ref": required_effect_string(activation_effect, "genesis_ref")?,
        "source_governing_authority_ref":
            required_effect_string(activation_effect, "source_governing_authority_ref")?,
        "home_domain_ref": required_effect_string(activation_effect, "home_domain_ref")?,
        "home_domain_commitment":
            required_effect_string(activation_effect, "home_domain_commitment")?,
        "home_domain_binding_ref":
            required_effect_string(activation_effect, "home_domain_binding_ref")?,
        "home_domain_binding_root":
            required_effect_string(activation_effect, "home_domain_binding_root")?,
        "policy_root": required_effect_string(activation_effect, "policy_root")?,
        "module_registry_root":
            required_effect_string(activation_effect, "module_registry_root")?,
        "upgrade_policy_ref": required_effect_string(activation_effect, "upgrade_policy_ref")?,
        "deployment_profile_ref":
            required_effect_string(activation_effect, "deployment_profile_ref")?,
        "deployment_profile_root":
            required_effect_string(activation_effect, "deployment_profile_root")?,
        "predecessor_constitution_root": chain_constitution_root,
        "successor_constitution_root": successor_constitution_root,
        "changed_field_paths_commitment": changed_field_paths_commitment,
        "predecessor_status": status.as_str(),
        "predecessor_state_ref": predecessor_state_ref,
        "predecessor_state_root": previous_step.state_root,
        "predecessor_proposal_root": previous_step.proposal_root,
        "predecessor_decision_root": previous_step.decision_root,
        "predecessor_transition_root": previous_step.transition_root,
        "predecessor_receipt_root": previous_step.receipt_root,
        "predecessor_chain_head_root": chain_head_root,
        "resulting_status": status.as_str(),
        "resulting_state_ref": semantic_state["lifecycle_state_ref"],
        "resulting_state_root": resulting_state_root,
        "active_profile_set_ref": successor_set_ref,
        "active_profile_set_root": successor_profile_set_root,
        "chain_ref": required_effect_string(activation_effect, "chain_ref")?,
        "live_chain_created": false,
        "node_membership_created": false,
        "runtime_effect_admitted": false,
        "network_effect_admitted": false,
        "constitution_changed": true,
        "profile_set_changed": true,
        "operation_commitment": Value::Null,
    });
    // Bind the exact governance declaration this effect executes. Set after
    // the literal so the json! macro stays within its expansion limit.
    effect["amendment_root"] = Value::String(amendment_root.clone());
    effect["approval_decision_root"] = Value::String(approval_decision_root.clone());
    effect["approval_authority_evidence_root"] =
        Value::String(approval_authority_evidence_root.to_owned());
    effect["operation_commitment"] = Value::String(amendment_operation_commitment(&effect)?);

    Ok(CompiledAmendmentExecutionPlan {
        sequence,
        status,
        previous_step: previous_step.clone(),
        amendment: amendment.clone(),
        amendment_root,
        approval_decision: approval_decision.clone(),
        approval_decision_root,
        successor_constitution: successor_constitution.clone(),
        successor_constitution_root,
        changed_field_paths,
        changed_field_paths_commitment: required_field(
            &effect,
            "changed_field_paths_commitment",
            "amendment effect",
        )?
        .to_owned(),
        successor_profile_set,
        successor_profile_set_root,
        semantic_state,
        resulting_state_root,
        authority_effect: effect,
    })
}

fn amendment_operation_commitment(effect: &Value) -> Result<String, String> {
    let field = |name: &str| {
        effect
            .get(name)
            .cloned()
            .ok_or_else(|| format!("amendment authority effect lacks {name}"))
    };
    jcs_hash(&json!({
        "domain": AMENDMENT_COMMITMENT_HASH_PROFILE,
        "op": field("op")?,
        "required_scope": field("required_scope")?,
        "sequence": field("sequence")?,
        "irreversibility": field("irreversibility")?,
        "system_id": field("system_id")?,
        "genesis_ref": field("genesis_ref")?,
        "source_governing_authority_ref": field("source_governing_authority_ref")?,
        "home_domain_ref": field("home_domain_ref")?,
        "home_domain_commitment": field("home_domain_commitment")?,
        "policy_root": field("policy_root")?,
        "module_registry_root": field("module_registry_root")?,
        "amendment_root": field("amendment_root")?,
        "approval_decision_root": field("approval_decision_root")?,
        "approval_authority_evidence_root": field("approval_authority_evidence_root")?,
        "predecessor_constitution_root": field("predecessor_constitution_root")?,
        "successor_constitution_root": field("successor_constitution_root")?,
        "changed_field_paths_commitment": field("changed_field_paths_commitment")?,
        "predecessor_status": field("predecessor_status")?,
        "predecessor_state_root": field("predecessor_state_root")?,
        "predecessor_chain_head_root": field("predecessor_chain_head_root")?,
        "resulting_status": field("resulting_status")?,
        "resulting_state_ref": field("resulting_state_ref")?,
        "resulting_state_root": field("resulting_state_root")?,
        "active_profile_set_ref": field("active_profile_set_ref")?,
        "active_profile_set_root": field("active_profile_set_root")?,
        "chain_ref": field("chain_ref")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diff_is_canonical_sorted_and_structural_blind() {
        let predecessor = json!({
            "schema_version": "ioi.autonomous-system-constitution.v1",
            "version": "1.0.0",
            "declared_purpose": "serve",
            "normative_constraints": {"spend_ceiling": 5, "region": "us"},
            "shutdown": {"grace_seconds": 30},
        });
        let successor = json!({
            "schema_version": "ioi.autonomous-system-constitution.v2-tampered",
            "version": "1.1.0",
            "declared_purpose": "serve",
            "normative_constraints": {"spend_ceiling": 9, "region": "us", "added": true},
            "shutdown": {"grace_seconds": 30},
        });
        // schema_version and version differences are structurally excluded.
        assert_eq!(
            canonical_constitution_diff(&predecessor, &successor),
            vec![
                "/normative_constraints/added".to_owned(),
                "/normative_constraints/spend_ceiling".to_owned(),
            ],
        );
    }

    #[test]
    fn removed_and_added_keys_yield_their_own_pointers() {
        let a = json!({"body": {"kept": 1, "removed": 2}});
        let b = json!({"body": {"kept": 1, "added": 3}});
        assert_eq!(
            canonical_constitution_diff(&a, &b),
            vec!["/body/added".to_owned(), "/body/removed".to_owned()],
        );
    }

    #[test]
    fn arrays_are_whole_leaves_so_reorder_is_a_difference() {
        let a = json!({"invariants": ["x", "y"]});
        let b = json!({"invariants": ["y", "x"]});
        assert_eq!(
            canonical_constitution_diff(&a, &b),
            vec!["/invariants".to_owned()],
        );
    }

    #[test]
    fn escaped_pointer_tokens_round_trip() {
        let a = json!({"odd/key~name": 1});
        let b = json!({"odd/key~name": 2});
        assert_eq!(
            canonical_constitution_diff(&a, &b),
            vec!["/odd~1key~0name".to_owned()],
        );
    }

    #[test]
    fn semver_lineage_is_strict_and_rejects_malformed() {
        assert!(semver_strictly_greater("1.1.0", "1.0.9").unwrap());
        assert!(semver_strictly_greater("2.0.0", "1.999999999.999999999").unwrap());
        assert!(!semver_strictly_greater("1.0.0", "1.0.0").unwrap());
        assert!(!semver_strictly_greater("1.0.0", "1.0.1").unwrap());
        for bad in [
            "1.0",
            "1.0.0.0",
            "1.0.-1",
            "v1.0.0",
            "1.0.01",
            "1..0",
            "1.0.0-rc1",
        ] {
            assert!(semver_strictly_greater(bad, "1.0.0").is_err(), "{bad}");
        }
    }

    use super::super::system_activation::UnverifiedCommittedSystemLifecycleStep;

    fn h(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    fn activation_effect() -> Value {
        json!({
            "schema_version": "ioi.autonomous-system-lifecycle-authority-effect.v1",
            "operation": "activate",
            "sequence": 2,
            "system_id": "system://fixture/alpha",
            "genesis_ref": "genesis://fixture/alpha",
            "source_governing_authority_ref": "wallet://fixture/governing",
            "home_domain_ref": "home-domain://fixture/alpha",
            "home_domain_commitment": h(0x11),
            "home_domain_binding_ref": "system-home-domain-binding://fixture/alpha",
            "home_domain_binding_root": h(0x12),
            "policy_root": h(0x13),
            "module_registry_root": h(0x14),
            "upgrade_policy_ref": "policy://fixture/upgrade",
            "deployment_profile_ref": "deployment-profile://fixture/alpha",
            "deployment_profile_root": h(0x15),
            "active_profile_set_ref": "active-profile-set://fixture/alpha",
            "active_profile_set_root": h(0x16),
            "chain_ref": "autonomous-system-chain://fixture/alpha",
            "live_chain_created": true,
            "node_membership_created": false,
            "runtime_effect_admitted": false,
            "network_effect_admitted": false,
        })
    }

    fn step(sequence: u64, status: &str) -> UnverifiedCommittedSystemLifecycleStep {
        UnverifiedCommittedSystemLifecycleStep {
            proposal: json!({}),
            decision: json!({}),
            state: json!({
                "lifecycle_state_ref":
                    format!("system-lifecycle-state://fixture/alpha/{sequence}"),
                "system_id": "system://fixture/alpha",
                "sequence": sequence,
                "status": status,
                "active_profile_set_ref": "active-profile-set://fixture/alpha",
                "active_profile_set_root": h(0x16),
            }),
            transition: json!({}),
            receipt: json!({}),
            state_root: h(0x21),
            proposal_root: h(0x22),
            decision_root: h(0x23),
            transition_root: h(0x24),
            receipt_root: h(0x25),
        }
    }

    fn constitution(
        id: &str,
        version: &str,
        root: &str,
        predecessor_ref: &str,
        status: &str,
    ) -> Value {
        json!({
            "schema_version": "ioi.autonomous-system-constitution.v1",
            "constitution_id": id,
            "system_id": "system://fixture/alpha",
            "version": version,
            "predecessor_constitution_ref": predecessor_ref,
            "declared_purpose": "serve the fixture estate",
            "normative_constraints": {
                "spend_ceiling": 5,
                "invariant_refs": ["constraint://fixture/immutable", "constraint://fixture/mutable"],
            },
            "agency_boundary": {"may_execute": false},
            "governance": {
                "governance_owner_refs": ["wallet://fixture/governing"],
                "accountable_principal_refs": ["wallet://fixture/governing"],
                "amendment_mode": "external_governance_only",
                "amendment_decision_profile_ref": "policy://fixture/governance/amendments",
                "agent_may_commit_amendment": false,
                "protected_clause_refs": ["constitution-clause://fixture/purpose"],
                "protected_field_paths": [
                    "/declared_purpose",
                    "/normative_constraints/invariant_refs/0"
                ],
            },
            "protected_profile_governance": {"deployment_constraint_ref": "constraint://fixture/deploy"},
            "shutdown": {"grace_seconds": 30},
            "activation_receipt_ref": "receipt://fixture/activation",
            "public_commitment_ref": "commitment://fixture/public",
            "status": status,
            "constitution_root": root,
        })
    }

    fn fixture_pair() -> (Value, Value) {
        let predecessor = constitution(
            "constitution://fixture/alpha/1",
            "1.0.0",
            &h(0x41),
            "constitution://fixture/root-lineage",
            "active",
        );
        let mut successor = constitution(
            "constitution://fixture/alpha/2",
            "1.1.0",
            "",
            "constitution://fixture/alpha/1",
            "active",
        );
        successor["normative_constraints"]["spend_ceiling"] = json!(9);
        // Declared self-root is structural and carried verbatim.
        successor["constitution_root"] = predecessor["constitution_root"].clone();
        (predecessor, successor)
    }

    fn declaration(predecessor: &Value, successor: &Value) -> Value {
        json!({
            "schema_version": "ioi.autonomous-system-constitution-amendment.v1",
            "amendment_id": "constitution-amendment://fixture/alpha/1",
            "system_id": "system://fixture/alpha",
            "predecessor_constitution_ref": predecessor["constitution_id"],
            "predecessor_constitution_root": constitution_candidate_root(predecessor).unwrap(),
            "proposed_successor_constitution_ref": successor["constitution_id"],
            "proposed_successor_constitution_root": constitution_candidate_root(successor).unwrap(),
            "changed_field_paths": ["/normative_constraints/spend_ceiling"],
            "protected_field_paths": [
                "/declared_purpose",
                "/normative_constraints/invariant_refs/0"
            ],
            "governing_decision_profile_ref": "policy://fixture/governance/amendments",
            "proposal_ref": "proposal://fixture/alpha/amendment/1",
            "evidence_refs": ["evidence://fixture/alpha/amendment/1"],
            "authority_requirement_refs": ["authority-requirement://fixture/governance/amend"],
            "proposed_by_ref": "governance://fixture/alpha",
            "decision_ref": "decision://fixture/alpha/amendment/1",
            "status": "approved",
        })
    }

    fn approval_decision(predecessor: &Value, successor: &Value, amendment: &Value) -> Value {
        let paths = canonical_constitution_diff(predecessor, successor);
        let mut decision = json!({
            "schema_version": "ioi.autonomous-system-constitution-amendment-approval-decision.v1",
            "decision_ref": amendment["decision_ref"],
            "decision_root": Value::Null,
            "amendment_ref": amendment["amendment_id"],
            "amendment_root": amendment_declaration_root(amendment).unwrap(),
            "proposal_ref": amendment["proposal_ref"],
            "system_id": amendment["system_id"],
            "governing_decision_profile_ref": amendment["governing_decision_profile_ref"],
            "predecessor_constitution_root": amendment["predecessor_constitution_root"],
            "successor_constitution_root": amendment["proposed_successor_constitution_root"],
            "changed_field_paths_commitment": changed_paths_commitment(&paths).unwrap(),
            "evidence_refs": amendment["evidence_refs"],
            "authority_requirement_refs": amendment["authority_requirement_refs"],
            "outcome": "approved",
            "decided_at": "2026-07-23T12:00:00Z",
        });
        decision["decision_root"] = json!(amendment_approval_decision_root(&decision).unwrap());
        decision
    }

    fn profile_set(constitution_root: &str) -> Value {
        json!({
            "schema_version": "ioi.autonomous-system-active-profile-set.v1",
            "active_profile_set_ref": "active-profile-set://fixture/alpha",
            "active_profile_set_root": h(0x16),
            "system_id": "system://fixture/alpha",
            "genesis_ref": "genesis://fixture/alpha",
            "profile_bundle_root": h(0x42),
            "constitution": {
                "candidate_profile_ref": "constitution://fixture/alpha/1",
                "candidate_profile_root": constitution_root,
                "admitted_posture": "active",
            },
            "deployment": {"candidate_profile_ref": "deployment-profile://fixture/alpha", "candidate_profile_root": h(0x15), "admitted_posture": "active"},
            "ordering_admission_finality": {"candidate_profile_ref": "ordering://fixture/alpha", "candidate_profile_root": h(0x43), "admitted_posture": "active"},
            "oracle_evidence_profiles": [],
            "lifecycle_continuity": {"candidate_profile_ref": "lifecycle://fixture/alpha", "candidate_profile_root": h(0x44), "admitted_posture": "active"},
            "network_enrollment": Value::Null,
            "status": "active",
        })
    }

    fn compile_fixture(
        status: &str,
        mutate: impl FnOnce(&mut Value, &mut Value, &mut Value, &mut Value),
    ) -> Result<CompiledAmendmentExecutionPlan, String> {
        let (predecessor, successor) = fixture_pair();
        let mut amendment = declaration(&predecessor, &successor);
        let mut predecessor = predecessor;
        let mut successor = successor;
        let chain_constitution_root = constitution_candidate_root(&predecessor).unwrap();
        let mut set = profile_set(&chain_constitution_root);
        mutate(&mut amendment, &mut predecessor, &mut successor, &mut set);
        let decision = approval_decision(&predecessor, &successor, &amendment);
        compile_amendment_execution_plan(
            &activation_effect(),
            &step(7, status),
            &h(0x31),
            &chain_constitution_root,
            "receipt://fixture/activation",
            &amendment,
            &decision,
            &h(0x32),
            &predecessor,
            &successor,
            &set,
        )
    }

    fn compile_fixture_with_approval_mutation(
        mutate: impl FnOnce(&mut Value),
    ) -> Result<CompiledAmendmentExecutionPlan, String> {
        let (predecessor, successor) = fixture_pair();
        let amendment = declaration(&predecessor, &successor);
        let chain_constitution_root = constitution_candidate_root(&predecessor).unwrap();
        let set = profile_set(&chain_constitution_root);
        let mut decision = approval_decision(&predecessor, &successor, &amendment);
        mutate(&mut decision);
        compile_amendment_execution_plan(
            &activation_effect(),
            &step(7, "active"),
            &h(0x31),
            &chain_constitution_root,
            "receipt://fixture/activation",
            &amendment,
            &decision,
            &h(0x32),
            &predecessor,
            &successor,
            &set,
        )
    }

    #[test]
    fn approved_amendment_compiles_with_deterministic_roots() {
        let plan = compile_fixture("active", |_, _, _, _| {}).unwrap();
        assert_eq!(plan.sequence, 8);
        assert_eq!(plan.status.as_str(), "active");
        assert_eq!(
            plan.changed_field_paths,
            vec!["/normative_constraints/spend_ceiling".to_owned()],
        );
        let again = compile_fixture("active", |_, _, _, _| {}).unwrap();
        assert_eq!(plan.resulting_state_root, again.resulting_state_root);
        assert_eq!(plan.authority_effect, again.authority_effect);
        assert_eq!(
            plan.successor_profile_set_root,
            again.successor_profile_set_root
        );
        // Status is unchanged and the effect claims exactly its authorized change.
        assert_eq!(plan.authority_effect["resulting_status"], json!("active"));
        assert_eq!(plan.authority_effect["constitution_changed"], json!(true));
        assert_eq!(plan.authority_effect["profile_set_changed"], json!(true));
        assert_eq!(
            plan.authority_effect["runtime_effect_admitted"],
            json!(false)
        );
        // The successor set swaps only the constitution entry.
        assert_eq!(
            plan.successor_profile_set["constitution"]["candidate_profile_root"],
            json!(plan.successor_constitution_root),
        );
        assert_eq!(
            plan.successor_profile_set["deployment"]["candidate_profile_root"],
            json!(h(0x15)),
        );
        assert_eq!(
            plan.successor_profile_set["supersedes_profile_set_root"],
            json!(h(0x16)),
        );
        // The resulting state carries the successor set, not the frozen one.
        assert_eq!(
            plan.semantic_state["active_profile_set_root"],
            json!(plan.successor_profile_set_root),
        );
    }

    #[test]
    fn paused_predecessor_compiles_and_others_refuse() {
        assert!(compile_fixture("paused", |_, _, _, _| {}).is_ok());
        for refused in [
            "suspended",
            "dormant",
            "recovering",
            "quarantined",
            "retired",
            "degraded",
        ] {
            let error = compile_fixture(refused, |_, _, _, _| {}).unwrap_err();
            assert!(error.contains("cannot execute from"), "{refused}: {error}");
        }
    }

    #[test]
    fn declared_diff_must_equal_computed_diff_in_both_directions() {
        let overdeclared = compile_fixture("active", |amendment, _, _, _| {
            amendment["changed_field_paths"] = json!([
                "/normative_constraints/spend_ceiling",
                "/shutdown/grace_seconds"
            ]);
        })
        .unwrap_err();
        assert!(overdeclared.contains("do not equal the canonical diff"));

        let underdeclared = compile_fixture("active", |amendment, _, successor, _| {
            successor["shutdown"]["grace_seconds"] = json!(60);
            let root = constitution_candidate_root(successor).unwrap();
            amendment["proposed_successor_constitution_root"] = json!(root);
        })
        .unwrap_err();
        assert!(underdeclared.contains("do not equal the canonical diff"));
    }

    #[test]
    fn machine_floor_and_declared_protections_refuse() {
        let governance = compile_fixture("active", |amendment, _, successor, _| {
            successor["governance"]["agent_may_commit_amendment"] = json!(true);
            let root = constitution_candidate_root(successor).unwrap();
            amendment["proposed_successor_constitution_root"] = json!(root);
            amendment["changed_field_paths"] = json!([
                "/governance/agent_may_commit_amendment",
                "/normative_constraints/spend_ceiling",
            ]);
        })
        .unwrap_err();
        assert!(governance.contains("machine-protected"), "{governance}");

        let declared = compile_fixture("active", |amendment, _, successor, _| {
            successor["declared_purpose"] = json!("serve something else");
            let root = constitution_candidate_root(successor).unwrap();
            amendment["proposed_successor_constitution_root"] = json!(root);
            amendment["changed_field_paths"] =
                json!(["/declared_purpose", "/normative_constraints/spend_ceiling"]);
        })
        .unwrap_err();
        assert!(
            declared.contains("protected by declared path"),
            "{declared}"
        );

        let understated = compile_fixture("active", |amendment, _, _, _| {
            amendment["protected_field_paths"] = json!([]);
        })
        .unwrap_err();
        assert!(
            understated.contains("do not equal committed constitution truth"),
            "{understated}",
        );

        let protected_array_element = compile_fixture("active", |amendment, _, successor, _| {
            successor["normative_constraints"]["invariant_refs"] = json!([
                "constraint://fixture/replaced",
                "constraint://fixture/mutable"
            ]);
            amendment["proposed_successor_constitution_root"] =
                json!(constitution_candidate_root(successor).unwrap());
            amendment["changed_field_paths"] = json!([
                "/normative_constraints/invariant_refs",
                "/normative_constraints/spend_ceiling"
            ]);
        })
        .unwrap_err();
        assert!(
            protected_array_element
                .contains("protected by declared path /normative_constraints/invariant_refs/0"),
            "{protected_array_element}",
        );
    }

    #[test]
    fn legacy_clause_protection_migrates_fail_closed() {
        let mut legacy = constitution(
            "constitution://fixture/alpha/1",
            "1.0.0",
            &h(1),
            "constitution://fixture/root-lineage",
            "active",
        );
        legacy["governance"]
            .as_object_mut()
            .unwrap()
            .remove("protected_field_paths");
        assert_eq!(
            constitution_protected_paths(&legacy["governance"]).unwrap(),
            vec!["/declared_purpose"]
        );

        legacy["governance"]["protected_clause_refs"] =
            json!(["constitution-clause://fixture/unknown"]);
        let unknown = constitution_protected_paths(&legacy["governance"]).unwrap_err();
        assert!(
            unknown.contains("has no deterministic field-path migration"),
            "{unknown}"
        );
    }

    #[test]
    fn external_approval_must_bind_the_exact_declaration() {
        let wrong_profile = compile_fixture_with_approval_mutation(|decision| {
            decision["governing_decision_profile_ref"] = json!("policy://foreign/profile");
            decision["decision_root"] = json!(amendment_approval_decision_root(decision).unwrap());
        })
        .unwrap_err();
        assert!(
            wrong_profile.contains("does not bind the exact declaration"),
            "{wrong_profile}",
        );

        let wrong_evidence = compile_fixture_with_approval_mutation(|decision| {
            decision["evidence_refs"] = json!(["evidence://foreign/approval"]);
            decision["decision_root"] = json!(amendment_approval_decision_root(decision).unwrap());
        })
        .unwrap_err();
        assert!(
            wrong_evidence.contains("changes evidence or authority requirements"),
            "{wrong_evidence}",
        );

        let root_tamper = compile_fixture_with_approval_mutation(|decision| {
            decision["decision_root"] = json!(h(0x70));
        })
        .unwrap_err();
        assert!(
            root_tamper.contains("root does not recompute"),
            "{root_tamper}"
        );

        let (predecessor, successor) = fixture_pair();
        let mut substituted = declaration(&predecessor, &successor);
        let decision = approval_decision(&predecessor, &successor, &substituted);
        substituted["proposed_by_ref"] = json!("governance://fixture/substitute");
        let chain_constitution_root = constitution_candidate_root(&predecessor).unwrap();
        let error = compile_amendment_execution_plan(
            &activation_effect(),
            &step(7, "active"),
            &h(0x31),
            &chain_constitution_root,
            "receipt://fixture/activation",
            &substituted,
            &decision,
            &h(0x32),
            &predecessor,
            &successor,
            &profile_set(&chain_constitution_root),
        )
        .unwrap_err();
        assert!(
            error.contains("does not bind the exact declaration"),
            "{error}",
        );
    }

    #[test]
    fn lineage_rules_refuse_smuggled_successors() {
        let stale_version = compile_fixture("active", |amendment, _, successor, _| {
            successor["version"] = json!("1.0.0");
            let root = constitution_candidate_root(successor).unwrap();
            amendment["proposed_successor_constitution_root"] = json!(root);
        })
        .unwrap_err();
        assert!(stale_version.contains("does not advance"));

        // A successor restating a different declared self-root is refused:
        // that field is structural and must be carried verbatim.
        let tampered_root = compile_fixture("active", |_, _, successor, _| {
            successor["constitution_root"] = json!(h(0x66));
        })
        .unwrap_err();
        assert!(
            tampered_root.contains("must carry the predecessor's declared constitution_root"),
            "{tampered_root}",
        );

        let swapped_activation_receipt = compile_fixture("active", |amendment, _, successor, _| {
            successor["activation_receipt_ref"] = json!("receipt://foreign/activation");
            amendment["proposed_successor_constitution_root"] =
                json!(constitution_candidate_root(successor).unwrap());
        })
        .unwrap_err();
        assert!(
            swapped_activation_receipt.contains("activation_receipt_ref"),
            "{swapped_activation_receipt}",
        );

        // A predecessor body that does not recompute to the chain's root is
        // refused even when every declared field looks coherent.
        let foreign_body = compile_fixture("active", |_, predecessor, _, _| {
            predecessor["declared_purpose"] = json!("a different constitution");
        })
        .unwrap_err();
        assert!(
            foreign_body.contains("does not recompute to the chain's root"),
            "{foreign_body}",
        );

        let identity_reuse = compile_fixture("active", |amendment, _, successor, _| {
            successor["constitution_id"] = json!("constitution://fixture/alpha/1");
            let root = constitution_candidate_root(successor).unwrap();
            amendment["proposed_successor_constitution_root"] = json!(root);
        })
        .unwrap_err();
        assert!(identity_reuse.contains("reuses the predecessor identity"));

        // A declaration binding a foreign root refuses at the declaration
        // layer; a predecessor body that does not carry the chain root
        // refuses at the constitution layer even when the declaration lies
        // consistently about only one of them.
        let foreign_declaration = compile_fixture("active", |amendment, _, _, _| {
            amendment["predecessor_constitution_root"] = json!(h(0x67));
        })
        .unwrap_err();
        assert!(
            foreign_declaration.contains("does not bind the chain's active constitution"),
            "{foreign_declaration}",
        );

        // Any predecessor-body edit breaks its recomputation against the
        // chain root, including one to the declared self-root field.
        let tampered_predecessor = compile_fixture("active", |_, predecessor, _, _| {
            predecessor["constitution_root"] = json!(h(0x67));
        })
        .unwrap_err();
        assert!(
            tampered_predecessor.contains("does not recompute to the chain's root"),
            "{tampered_predecessor}",
        );
    }

    #[test]
    fn declaration_discipline_refuses_unapproved_or_foreign() {
        let proposed = compile_fixture("active", |amendment, _, _, _| {
            amendment["status"] = json!("proposed");
        })
        .unwrap_err();
        assert!(proposed.contains("only an approved amendment declaration"));

        let unbound_set = compile_fixture("active", |_, _, _, set| {
            set["constitution"]["candidate_profile_root"] = json!(h(0x68));
        })
        .unwrap_err();
        assert!(unbound_set.contains("does not pin the constitution being amended"));

        let nothing = compile_fixture("active", |amendment, _, successor, _| {
            successor["normative_constraints"]["spend_ceiling"] = json!(5);
            let root = constitution_candidate_root(successor).unwrap();
            amendment["proposed_successor_constitution_root"] = json!(root);
            amendment["changed_field_paths"] = json!([]);
        })
        .unwrap_err();
        assert!(nothing.contains("changes nothing amendable"), "{nothing}");
    }

    #[test]
    fn commitment_is_tamper_sensitive() {
        let plan = compile_fixture("active", |_, _, _, _| {}).unwrap();
        let mut tampered = plan.authority_effect.clone();
        tampered["successor_constitution_root"] = json!(h(0x69));
        let original = plan.authority_effect["operation_commitment"]
            .as_str()
            .unwrap();
        let recomputed = super::amendment_operation_commitment(&tampered).unwrap();
        assert_ne!(original, recomputed);
    }

    #[test]
    fn governance_subtree_is_machine_protected() {
        assert!(pointer_is_machine_protected("/governance"));
        assert!(pointer_is_machine_protected("/governance/amendment_mode"));
        assert!(pointer_is_machine_protected(
            "/governance/protected_clause_refs"
        ));
        assert!(!pointer_is_machine_protected("/governance_adjacent"));
        assert!(!pointer_is_machine_protected("/declared_purpose"));
        assert!(!pointer_is_machine_protected(
            "/normative_constraints/spend_ceiling"
        ));
    }
}
