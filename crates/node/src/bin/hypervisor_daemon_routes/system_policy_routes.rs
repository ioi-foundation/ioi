//! Decision-time consumer for one System's active constitutional profile set.
//!
//! The active-profile-set is the sole selector. Candidate bodies remain in the
//! admitted genesis (or the constitution content-addressed family); this loader
//! recomputes every selected candidate root before a runtime may use it.

use serde_json::{json, Value};

use super::system_activation_routes::{jcs_hash, required_string, validate_contract, verr};

const CONSTITUTION_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-constitution/v1";
const ORDERING_CONTRACT: &str = "schema://ioi/foundations/ordering-admission-finality-profile/v1";
const ORACLE_CONTRACT: &str = "schema://ioi/foundations/oracle-evidence-profile/v1";
const LIFECYCLE_CONTRACT: &str = "schema://ioi/foundations/lifecycle-continuity-profile/v1";
const ACTIVE_SET_V1_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-active-profile-set/v1";
const ACTIVE_SET_V2_CONTRACT: &str =
    "schema://ioi/foundations/autonomous-system-active-profile-set/v2";
const PROFILE_CANDIDATE_DOMAIN: &str = "ioi.autonomous-system-profile-candidate-jcs-sha256.v1";

type VErr = (String, String);

/// Exact, root-verified policy bodies selected by the current lifecycle state.
pub(crate) struct ActiveSystemPolicies {
    pub system_id: String,
    pub constitution: Value,
    pub ordering_profile: Value,
    pub oracle_profiles: Vec<Value>,
    pub lifecycle_profile: Value,
    pub active_profile_set: Value,
}

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn candidate_root(kind: &str, body: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({
        "domain": PROFILE_CANDIDATE_DOMAIN,
        "kind": kind,
        "candidate": body,
    }))
}

fn bind_entry(
    entry: &Value,
    body: &Value,
    kind: &str,
    id_field: &str,
    contract: &str,
    system_id: &str,
) -> Result<(), VErr> {
    validate_contract(contract, body, kind)?;
    if required(body, "/system_id")? != system_id {
        return Err(verr(
            "system_policy_artifact_mismatch",
            format!("selected {kind} belongs to another System"),
        ));
    }
    let body_ref = required(body, &format!("/{id_field}"))?;
    if required(entry, "/candidate_profile_ref")? != body_ref {
        return Err(verr(
            "system_policy_artifact_mismatch",
            format!("active profile set does not bind the selected {kind} identity"),
        ));
    }
    if required(entry, "/candidate_profile_root")? != candidate_root(kind, body)? {
        return Err(verr(
            "system_policy_artifact_mismatch",
            format!("active profile set does not bind the selected {kind} body"),
        ));
    }
    if entry.get("admitted_posture").and_then(Value::as_str) != Some("active") {
        return Err(verr(
            "system_policy_artifact_mismatch",
            format!("selected {kind} is not admitted active"),
        ));
    }
    Ok(())
}

/// Resolve and verify the exact constitution, ordering, oracle, and lifecycle
/// policy bodies selected by the current chain head.
pub(crate) fn load_active_system_policies(
    data_dir: &str,
    key: &str,
) -> Result<ActiveSystemPolicies, VErr> {
    let admission = super::system_genesis_routes::load_verified_admission_by_key(data_dir, key)?
        .ok_or_else(|| verr("system_policy_not_found", "no admitted genesis exists"))?;
    let (system_id, exact) = super::system_amendment_routes::load_amendment_source(data_dir, key)?;
    bind_active_system_policies(&admission.record, &system_id, &exact)
}

/// The active constitution names the CONSTITUTED governance owner; a committed named-continuity
/// succession transfers governing authority to `resulting_governing_authority_ref` without
/// amending the constitution (succession is a continuity transition under its own scope, not an
/// amendment). Ownership is therefore consistent when the constitution and the chain head agree,
/// OR when the chain head's single owner is exactly the governing authority the committed
/// lifecycle state carries (the succession wrote both; every later protected transition under the
/// successor — pause, resume, … — keeps both, while the status moves on from `successor_governed`).
/// Every other disagreement refuses — a chain head naming an owner the committed state does not
/// is not governance truth.
/// (2026-09-08: the 2026-08-25 policy consumer compared the two verbatim and refused every
/// protected transition after a completed succession; the M1.5d held journey found it.)
pub(crate) fn governance_ownership_consistent(
    constitution: &Value,
    chain_head: &Value,
    lifecycle_state: &Value,
) -> Result<(), VErr> {
    let constituted = constitution.pointer("/governance/governance_owner_refs");
    let chain_owners = chain_head.get("governance_owner_refs");
    if constituted == chain_owners {
        return Ok(());
    }
    let single_chain_owner = chain_owners
        .and_then(Value::as_array)
        .filter(|owners| owners.len() == 1)
        .and_then(|owners| owners[0].as_str());
    let state_owner = lifecycle_state
        .get("governing_authority_ref")
        .and_then(Value::as_str);
    if single_chain_owner.is_some() && single_chain_owner == state_owner {
        return Ok(());
    }
    Err(verr(
        "system_policy_constitution_refused",
        "active constitution and chain disagree on governance ownership",
    ))
}

/// Bind already-loaded lifecycle truth to its selected immutable policy bodies.
/// This function performs no discovery, so source loaders may enforce it
/// without creating a second store or a recursive load path.
pub(crate) fn bind_active_system_policies(
    genesis_record: &Value,
    system_id: &str,
    exact: &super::system_amendment_routes::AmendmentSource,
) -> Result<ActiveSystemPolicies, VErr> {
    let set = &exact.predecessor_profile_set;
    let set_contract = match set.get("schema_version").and_then(Value::as_str) {
        Some("ioi.autonomous-system-active-profile-set.v1") => ACTIVE_SET_V1_CONTRACT,
        Some("ioi.autonomous-system-active-profile-set.v2") => ACTIVE_SET_V2_CONTRACT,
        _ => {
            return Err(verr(
                "system_policy_artifact_invalid",
                "active profile set has no supported contract identity",
            ))
        }
    };
    validate_contract(set_contract, set, "active profile set")?;
    if required(set, "/system_id")? != *system_id {
        return Err(verr(
            "system_policy_artifact_mismatch",
            "active profile set belongs to another System",
        ));
    }

    bind_entry(
        &set["constitution"],
        &exact.predecessor_constitution,
        "constitution",
        "constitution_id",
        CONSTITUTION_CONTRACT,
        system_id,
    )?;
    governance_ownership_consistent(
        &exact.predecessor_constitution,
        &exact.chain_head,
        &exact.previous_step.state,
    )?;

    let bundle = genesis_record
        .get("initial_profile_bundle")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            verr(
                "system_policy_artifact_mismatch",
                "admitted genesis lacks its initial profile bundle",
            )
        })?;
    let ordering = bundle.get("ordering_profile").cloned().ok_or_else(|| {
        verr(
            "system_policy_artifact_mismatch",
            "admitted genesis lacks its ordering profile body",
        )
    })?;
    bind_entry(
        &set["ordering_admission_finality"],
        &ordering,
        "ordering_admission_finality",
        "ordering_profile_id",
        ORDERING_CONTRACT,
        system_id,
    )?;

    let oracle_bodies = bundle
        .get("oracle_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_policy_artifact_mismatch",
                "admitted genesis oracle profile bodies are not an array",
            )
        })?;
    let oracle_entries = set
        .get("oracle_evidence_profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_policy_artifact_mismatch",
                "active profile set oracle entries are not an array",
            )
        })?;
    if oracle_entries.len() != oracle_bodies.len() {
        return Err(verr(
            "system_policy_artifact_mismatch",
            "active profile set and admitted oracle body cardinalities differ",
        ));
    }
    let mut oracles = Vec::with_capacity(oracle_entries.len());
    for entry in oracle_entries {
        let selected_ref = required(entry, "/candidate_profile_ref")?;
        let mut matches = oracle_bodies.iter().filter(|body| {
            body.get("oracle_evidence_profile_id")
                .and_then(Value::as_str)
                == Some(selected_ref.as_str())
        });
        let body = matches.next().ok_or_else(|| {
            verr(
                "system_policy_artifact_mismatch",
                "active oracle profile has no admitted candidate body",
            )
        })?;
        if matches.next().is_some() {
            return Err(verr(
                "system_policy_artifact_mismatch",
                "active oracle profile identity is ambiguous",
            ));
        }
        bind_entry(
            entry,
            body,
            "oracle_evidence",
            "oracle_evidence_profile_id",
            ORACLE_CONTRACT,
            system_id,
        )?;
        oracles.push(body.clone());
    }

    let lifecycle = bundle.get("lifecycle_profile").cloned().ok_or_else(|| {
        verr(
            "system_policy_artifact_mismatch",
            "admitted genesis lacks its lifecycle profile body",
        )
    })?;
    bind_entry(
        &set["lifecycle_continuity"],
        &lifecycle,
        "lifecycle_continuity",
        "lifecycle_profile_id",
        LIFECYCLE_CONTRACT,
        system_id,
    )?;

    Ok(ActiveSystemPolicies {
        system_id: system_id.to_owned(),
        constitution: exact.predecessor_constitution.clone(),
        ordering_profile: ordering,
        oracle_profiles: oracles,
        lifecycle_profile: lifecycle,
        active_profile_set: set.clone(),
    })
}

/// The current writer/fencing implementation is deliberately a single-writer
/// plane. Other declared ordering profiles require their profile-native path.
pub(crate) fn require_single_writer_plane(profile: &Value) -> Result<(), VErr> {
    let kind = required(profile, "/profile")?;
    if !matches!(
        kind.as_str(),
        "single_authority" | "replicated_single_authority"
    ) {
        return Err(verr(
            "system_policy_ordering_profile_refused",
            format!("ordering profile '{kind}' cannot use the single-writer transition plane"),
        ));
    }
    for (pointer, label) in [
        ("/ordering/writer_epoch_required", "writer epochs"),
        ("/ordering/fencing_required", "writer fencing"),
        (
            "/admission/require_expected_predecessor_root",
            "expected predecessor admission",
        ),
        (
            "/cryptographic_continuity/require_monotonic_sequence",
            "monotonic sequence",
        ),
        (
            "/cryptographic_continuity/require_expected_predecessor_commitment",
            "expected predecessor commitment",
        ),
        (
            "/cryptographic_continuity/require_resulting_state_root",
            "resulting state root",
        ),
        (
            "/cryptographic_continuity/require_receipt_root",
            "receipt root",
        ),
    ] {
        if profile.pointer(pointer).and_then(Value::as_bool) != Some(true) {
            return Err(verr(
                "system_policy_ordering_profile_refused",
                format!("active ordering profile does not require {label}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_single_writer_profile_refuses_the_single_writer_plane() {
        let profile = json!({"profile":"bft_consensus"});
        assert_eq!(
            require_single_writer_plane(&profile).unwrap_err().0,
            "system_policy_ordering_profile_refused"
        );
    }

    #[test]
    fn a_completed_succession_transfers_governance_without_amending_the_constitution() {
        let constitution =
            json!({ "governance": { "governance_owner_refs": ["org://acme/research"] } });
        let state = json!({ "governing_authority_ref": "org://acme/successor-authority" });
        // Constituted owner still governing: consistent.
        assert!(governance_ownership_consistent(
            &constitution,
            &json!({ "status": "active", "governance_owner_refs": ["org://acme/research"] }),
            &json!({ "governing_authority_ref": "org://acme/research" }),
        )
        .is_ok());
        // A committed succession: the chain head's single owner is exactly the lifecycle state's
        // governing authority — consistent without an amendment, and it stays consistent through
        // the successor's later protected transitions (pause → status "paused", owners unchanged).
        for status in ["successor_governed", "paused", "suspended", "active"] {
            assert!(governance_ownership_consistent(
                &constitution,
                &json!({ "status": status, "governance_owner_refs": ["org://acme/successor-authority"] }),
                &state,
            )
            .is_ok(), "{status}");
        }
        // Every other disagreement refuses by name: a chain owner the committed state does not
        // carry, two owners, or a state with no governing authority at all.
        for chain_head in [
            json!({ "status": "successor_governed", "governance_owner_refs": ["org://attacker"] }),
            json!({ "status": "successor_governed", "governance_owner_refs": ["org://acme/successor-authority", "org://attacker"] }),
        ] {
            assert_eq!(
                governance_ownership_consistent(&constitution, &chain_head, &state)
                    .unwrap_err()
                    .0,
                "system_policy_constitution_refused",
                "{chain_head}"
            );
        }
        assert_eq!(
            governance_ownership_consistent(
                &constitution,
                &json!({ "status": "active", "governance_owner_refs": ["org://acme/successor-authority"] }),
                &json!({}),
            )
            .unwrap_err()
            .0,
            "system_policy_constitution_refused"
        );
    }

    #[test]
    fn selected_body_mutation_breaks_its_active_root() {
        let mut body: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/oracle-evidence-profile-v1/positive-fail-closed.json"
        )))
        .unwrap();
        let root = candidate_root("oracle_evidence", &body).unwrap();
        body["missing_or_stale_evidence_mode"] = json!("pause");
        assert_ne!(root, candidate_root("oracle_evidence", &body).unwrap());
    }
}
