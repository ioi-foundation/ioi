//! Generic protected operational lifecycle transitions (M1.5 m1-5b) —
//! helper layer.
//!
//! This module CONTINUES the proven activation runtime at sequence three or
//! later: the same durable families for proposals, decisions, transitions,
//! and authority evidence; a new lifecycle-state family for the
//! post-activation states; operation-log continuation under the v2 general
//! contract; and chain revisions over the already-general chain contract.
//! Nothing here mints a parallel authority or persistence path.
//!
//! 4b-1 scope: discovery/loaders and pure artifact builders with unit tests.
//! The route handlers, sealed intents, and daemon registration land in 4b-2.

use ioi_types::app::system_activation::UnverifiedCommittedSystemLifecycleStep;
use ioi_types::app::system_lifecycle_transitions::{
    compile_protected_transition_plan, CompiledProtectedTransitionPlan, ProtectedTransitionOp,
};
use serde_json::Value;

use super::system_activation_routes::{
    canonical_hash_str, enumerate_family, load_required_exact, required_string, verr,
    ACTIVATION_RECEIPT_DIR, AUTHORITY_EVIDENCE_DIR, CHAIN_DIR, DECISION_DIR, OPERATION_LOG_DIR,
    PROPOSAL_DIR, STATE_DIR, TRANSITION_DIR,
};

type VErr = (String, String);

/// Post-activation lifecycle states (`ioi.autonomous-system-lifecycle-state.v1`).
pub(crate) const LIFECYCLE_STATE_DIR: &str = "autonomous-system-lifecycle-states";
/// Protected-transition receipts (LifecycleTransitionReceipt family, sequence >= 3).
pub(crate) const PROTECTED_RECEIPT_DIR: &str = "autonomous-system-protected-transition-receipts";
/// Sealed protected-transition intents (single family; the op rides the tail).
pub(crate) const PROTECTED_INTENT_DIR: &str = "autonomous-system-protected-transition-intents";

/// The exact truth a protected transition compiles against, reconstructed
/// from durable records only — never from the caller.
pub(crate) struct ProtectedTransitionSource {
    /// Committed sequence-two activation effect (identity carrier).
    pub activation_effect: Value,
    /// Predecessor step artifacts at chain-head sequence.
    pub previous_step: UnverifiedCommittedSystemLifecycleStep,
    /// The current chain head revision (highest `latest_sequence`).
    pub chain_head: Value,
    /// The current operation log revision matching the chain head.
    pub operation_log: Value,
}

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

/// Load the current chain head revision for `system_id`: the unique chain
/// record carrying the highest `latest_sequence`. Duplicate heads at the
/// same sequence are corruption and refuse.
pub(crate) fn load_chain_head(data_dir: &str, system_id: &str) -> Result<Value, VErr> {
    select_chain_head(enumerate_family(data_dir, CHAIN_DIR)?, system_id)
}

/// Pure head selection over enumerated chain revisions: the head is the
/// unique revision with the highest `latest_sequence` for the System;
/// duplicate heads at that sequence are corruption and refuse.
fn select_chain_head(
    records: Vec<(String, Value)>,
    system_id: &str,
) -> Result<Value, VErr> {
    let mut best: Option<(u64, Value)> = None;
    let mut duplicate_at: Option<u64> = None;
    for (_tail, value) in records {
        if value.get("system_id").and_then(Value::as_str) != Some(system_id) {
            continue;
        }
        let sequence = value
            .get("latest_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_invalid",
                    "chain revision lacks latest_sequence",
                )
            })?;
        match &best {
            Some((current, _)) if *current == sequence => duplicate_at = Some(sequence),
            Some((current, _)) if *current > sequence => {}
            _ => {
                best = Some((sequence, value));
                if duplicate_at == Some(sequence) {
                    duplicate_at = None;
                }
            }
        }
    }
    if let Some(sequence) = duplicate_at {
        if best.as_ref().is_some_and(|(head, _)| *head == sequence) {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                format!("two chain revisions both claim head sequence {sequence}"),
            ));
        }
    }
    best.map(|(_, value)| value).ok_or_else(|| {
        verr(
            "system_lifecycle_not_found",
            "no live chain revision exists for this System",
        )
    })
}

/// Load the operation-log revision bound by the chain head.
pub(crate) fn load_log_for_chain(data_dir: &str, chain: &Value) -> Result<Value, VErr> {
    let log_root = required(chain, "/operation_log_root")?;
    let tail = format!(
        "asol_{}",
        log_root
            .strip_prefix("sha256:")
            .filter(|tail| tail.len() == 64)
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_artifact_invalid",
                    "chain head carries a non-canonical operation_log_root",
                )
            })?
    );
    load_required_exact(data_dir, OPERATION_LOG_DIR, &tail)?.ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_mismatch",
            "chain head binds an operation log that is not durably admitted",
        )
    })
}

fn record_by_root(
    data_dir: &str,
    family: &str,
    prefix: &str,
    root: &str,
    label: &str,
) -> Result<Value, VErr> {
    if !canonical_hash_str(root) {
        return Err(verr(
            "system_lifecycle_artifact_invalid",
            format!("{label} root is not canonical"),
        ));
    }
    let tail = format!("{prefix}{}", &root[7..]);
    load_required_exact(data_dir, family, &tail)?.ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_mismatch",
            format!("{label} bound by the head is not durably admitted"),
        )
    })
}

/// Reconstruct the predecessor step exactly as the operation-log head binds
/// it: proposal/decision/transition/receipt/state, each loaded content-
/// addressed by the roots the head entry committed.
pub(crate) fn load_previous_step(
    data_dir: &str,
    log: &Value,
) -> Result<UnverifiedCommittedSystemLifecycleStep, VErr> {
    let head = log.get("head_entry").ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_invalid",
            "operation log lacks a head entry",
        )
    })?;
    let sequence = head.get("sequence").and_then(Value::as_u64).ok_or_else(|| {
        verr(
            "system_lifecycle_artifact_invalid",
            "operation-log head lacks a sequence",
        )
    })?;
    let proposal_root = required(head, "/proposal_root")?;
    let decision_root = required(head, "/decision_root")?;
    let transition_root = required(head, "/transition_root")?;
    let receipt_root = required(head, "/receipt_root")?;
    let state_root = required(head, "/state_root")?;
    let state_family = if sequence == 2 { STATE_DIR } else { LIFECYCLE_STATE_DIR };
    let receipt = if sequence == 2 {
        record_by_root(
            data_dir,
            ACTIVATION_RECEIPT_DIR,
            "asar_",
            &receipt_root,
            "activation receipt",
        )?
    } else {
        record_by_root(
            data_dir,
            PROTECTED_RECEIPT_DIR,
            "asptr_",
            &receipt_root,
            "protected receipt",
        )?
    };
    Ok(UnverifiedCommittedSystemLifecycleStep {
        proposal: record_by_root(data_dir, PROPOSAL_DIR, "aslp_", &proposal_root, "proposal")?,
        decision: record_by_root(data_dir, DECISION_DIR, "aslad_", &decision_root, "decision")?,
        state: record_by_root(data_dir, state_family, "asls_", &state_root, "state")?,
        transition: record_by_root(
            data_dir,
            TRANSITION_DIR,
            "aslt_",
            &transition_root,
            "transition",
        )?,
        receipt,
        state_root,
        proposal_root,
        decision_root,
        transition_root,
        receipt_root,
    })
}

/// Load the committed sequence-two activation effect (the identity carrier)
/// from the durably admitted authority evidence.
pub(crate) fn load_activation_effect(data_dir: &str, system_id: &str) -> Result<Value, VErr> {
    let mut matches = Vec::new();
    for (_tail, value) in enumerate_family(data_dir, AUTHORITY_EVIDENCE_DIR)? {
        if value.get("system_id").and_then(Value::as_str) == Some(system_id)
            && value.get("sequence").and_then(Value::as_u64) == Some(2)
            && value.get("operation").and_then(Value::as_str) == Some("activate")
        {
            matches.push(value);
        }
    }
    if matches.len() != 1 {
        return Err(verr(
            if matches.is_empty() {
                "system_lifecycle_not_found"
            } else {
                "system_lifecycle_artifact_mismatch"
            },
            format!(
                "expected exactly one converged activation authority evidence, found {}",
                matches.len()
            ),
        ));
    }
    matches
        .remove(0)
        .get("authorized_effect")
        .cloned()
        .filter(|effect| !effect.is_null())
        .ok_or_else(|| {
            verr(
                "system_lifecycle_artifact_invalid",
                "activation authority evidence lacks the committed effect",
            )
        })
}

/// Reconstruct the complete durable truth a protected transition compiles
/// against, and cross-check that chain head, operation log, and predecessor
/// step agree before any compile happens.
pub(crate) fn load_protected_source(
    data_dir: &str,
    system_id: &str,
) -> Result<ProtectedTransitionSource, VErr> {
    let chain_head = load_chain_head(data_dir, system_id)?;
    let operation_log = load_log_for_chain(data_dir, &chain_head)?;
    let previous_step = load_previous_step(data_dir, &operation_log)?;
    for (pointer, label) in [
        ("/latest_state_root", "state"),
        ("/latest_transition_root", "transition"),
        ("/latest_receipt_root", "receipt"),
    ] {
        let chain_value = required(&chain_head, pointer)?;
        let log_value = required(&operation_log, pointer)?;
        if chain_value != log_value {
            return Err(verr(
                "system_lifecycle_artifact_mismatch",
                format!("chain head and operation log disagree on the latest {label} root"),
            ));
        }
    }
    if required(&chain_head, "/latest_state_root")? != previous_step.state_root {
        return Err(verr(
            "system_lifecycle_artifact_mismatch",
            "reconstructed predecessor step detaches from the chain head",
        ));
    }
    let activation_effect = load_activation_effect(data_dir, system_id)?;
    Ok(ProtectedTransitionSource {
        activation_effect,
        previous_step,
        chain_head,
        operation_log,
    })
}

/// Compile a protected transition from durable truth only.
pub(crate) fn compile_from_source(
    op: ProtectedTransitionOp,
    source: &ProtectedTransitionSource,
) -> Result<CompiledProtectedTransitionPlan, VErr> {
    let chain_head_root = required(&source.chain_head, "/chain_root")?;
    compile_protected_transition_plan(
        op,
        &source.activation_effect,
        &source.previous_step,
        &chain_head_root,
    )
    .map_err(|error| verr("system_lifecycle_plan_invalid", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn revision(system: &str, sequence: u64, marker: &str) -> (String, Value) {
        (
            format!("asc_{marker}"),
            json!({"system_id": system, "latest_sequence": sequence, "marker": marker}),
        )
    }

    #[test]
    fn head_selection_takes_the_highest_sequence_for_the_system() {
        let head = select_chain_head(
            vec![
                revision("system://a", 2, "two"),
                revision("system://a", 4, "four"),
                revision("system://b", 9, "foreign"),
                revision("system://a", 3, "three"),
            ],
            "system://a",
        )
        .expect("head");
        assert_eq!(head["marker"], "four");
    }

    #[test]
    fn duplicate_heads_at_the_top_sequence_refuse() {
        let error = select_chain_head(
            vec![
                revision("system://a", 3, "left"),
                revision("system://a", 3, "right"),
                revision("system://a", 2, "old"),
            ],
            "system://a",
        )
        .expect_err("duplicate heads");
        assert_eq!(error.0, "system_lifecycle_artifact_mismatch");
    }

    #[test]
    fn superseded_duplicates_below_the_head_do_not_refuse() {
        let head = select_chain_head(
            vec![
                revision("system://a", 3, "left"),
                revision("system://a", 3, "right"),
                revision("system://a", 5, "head"),
            ],
            "system://a",
        )
        .expect("head above duplicates");
        assert_eq!(head["marker"], "head");
    }

    #[test]
    fn missing_system_refuses_not_found() {
        let error = select_chain_head(vec![revision("system://b", 2, "b")], "system://a")
            .expect_err("no chain");
        assert_eq!(error.0, "system_lifecycle_not_found");
    }
}
