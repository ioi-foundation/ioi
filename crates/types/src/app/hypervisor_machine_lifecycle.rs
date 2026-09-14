//! M09.11 machine-lifecycle admission: one versioned operation vocabulary, a capability matrix
//! that is consulted rather than assumed, and a receipt that can say "I do not know".
//!
//! This is the kernel behind ACC-20 clauses 3, 4 and 7. It holds no routes, no backend clients and
//! no I/O: an operation and the capability declaration it names go in, a verdict comes out, and a
//! receipt is compiled from the verdict rather than from the caller's hopes.
//!
//! THREE THINGS THIS FILE REFUSES TO DO, each because the journey names the failure.
//!
//! It never accepts a backend's word for a verb. The operation member is a closed sixteen-value
//! vocabulary in the contract, and a backend that calls reboot `restart` widens nothing — support
//! is expressed by the capability matrix declaring the cell supported, never by adding a verb.
//!
//! It never treats a capability declaration as current because it was named. `capability_declaration_hash`
//! must equal the hash of the declaration actually resolved, or the cell has DRIFTED under the
//! operation between admission and effect — the exact case clause 4 requires to refuse before
//! effect, and the exact case a ref alone cannot see.
//!
//! It never converts an unknown outcome into a known one. `MachineEffectOutcome::Ambiguous` compiles
//! a receipt whose `result` is `ambiguous` with a typed reason, because an external completion the
//! daemon could not confirm is neither a success nor a refusal, and a vocabulary that cannot say so
//! forces an invented answer.

use serde_json::{json, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;

use super::system_activation::{jcs_hash, required_string};

/// Registered versioned machine operation.
pub const MACHINE_OPERATION_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-machine-operation/v1";
/// Registered machine operation receipt.
pub const MACHINE_OPERATION_RECEIPT_CONTRACT: &str =
    "schema://ioi/components/hypervisor/hypervisor-machine-operation-receipt/v1";

/// Canon's minimum lifecycle vocabulary, in canon's order. Held here as well as in the contract
/// because the kernel must be able to answer "is this a verb at all" without a schema round-trip,
/// and because a drift between the two is exactly the kind of thing a test can catch.
pub const MACHINE_OPERATION_VOCABULARY: [&str; 16] = [
    "discover",
    "define",
    "import",
    "create",
    "start",
    "stop",
    "pause",
    "resume",
    "reboot",
    "open_console",
    "close_console",
    "snapshot",
    "clone",
    "restore",
    "migrate",
    "delete",
];

/// Every named refusal dimension. A refusal that is not one of these is a bug, not a new reason.
pub const MACHINE_REFUSAL_DIMENSIONS: [&str; 7] = [
    "operation_contract_invalid",
    "operation_not_in_vocabulary",
    "capability_declaration_not_resolved",
    "capability_declaration_drifted",
    "capability_cell_unsupported",
    "expected_head_stale",
    "operation_already_applied",
];

/// A total admit/refuse verdict with a named dimension on every refusal.
#[derive(Debug, Clone, PartialEq)]
pub struct MachineVerdict {
    /// Whether the operation is admitted for effect.
    pub admitted: bool,
    /// Named refusal dimension, absent only on admit.
    pub refusal_dimension: Option<&'static str>,
    /// Human-readable detail, absent only on admit.
    pub refusal_reason: Option<String>,
}

impl MachineVerdict {
    fn refuse(dimension: &'static str, reason: impl Into<String>) -> Self {
        debug_assert!(MACHINE_REFUSAL_DIMENSIONS.contains(&dimension));
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

/// What actually happened once an admitted operation reached the backend.
#[derive(Debug, Clone, PartialEq)]
pub enum MachineEffectOutcome {
    /// The backend confirmed completion.
    Succeeded {
        /// The backend's own operation identity, carried as EVIDENCE only.
        backend_native_operation_id: Option<String>,
        /// Desired generation AFTER the effect.
        desired_generation_after: u64,
        /// Observed generation after the effect. May trail the desired one; saying so is the point.
        observed_generation_after: u64,
    },
    /// The daemon could not confirm whether the effect happened.
    ///
    /// This is not a failure mode of the vocabulary; it is a fact the vocabulary must be able to
    /// state. Reconciliation is owed, and inventing either answer here would remove the obligation.
    Ambiguous {
        /// The backend's own operation identity, when it managed to report one before going quiet.
        backend_native_operation_id: Option<String>,
        /// The typed reason the outcome could not be confirmed. Reconciliation is owed against it.
        reason: String,
    },
}

/// Admit or refuse one operation against the capability declaration it names.
///
/// `resolved_declaration` is the declaration the DAEMON resolved, never one the caller supplied:
/// the operation carries a ref and a hash, and this proves the resolved declaration is the one the
/// operation was written against before any cell is read from it.
///
/// `observed_head` is the canonical head as the server sees it now. A stale `expected_head` refuses
/// rather than proceeding, because a duplicate or reordered request that proceeded on a stale head
/// is exactly the double effect clause 7 forbids.
pub fn admit_machine_operation(
    operation: &Value,
    resolved_declaration: &Value,
    observed_head: &str,
    already_applied_idempotency_hashes: &[String],
) -> MachineVerdict {
    if let Err(error) = validate_architecture_contract(MACHINE_OPERATION_CONTRACT, operation) {
        return MachineVerdict::refuse("operation_contract_invalid", error);
    }
    let verb = match required_string(operation, "/operation") {
        Ok(value) => value,
        Err(error) => return MachineVerdict::refuse("operation_contract_invalid", error),
    };
    // Belt and braces with the contract's enum ON PURPOSE: if the two ever disagree, the kernel
    // refuses rather than admitting a verb the vocabulary does not contain.
    if !MACHINE_OPERATION_VOCABULARY.contains(&verb) {
        return MachineVerdict::refuse(
            "operation_not_in_vocabulary",
            format!("'{verb}' is not one of canon's sixteen lifecycle operations"),
        );
    }

    let declared_ref = match required_string(operation, "/capability_declaration_ref") {
        Ok(value) => value,
        Err(error) => return MachineVerdict::refuse("operation_contract_invalid", error),
    };
    let resolved_ref = resolved_declaration
        .get("capability_declaration_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if resolved_ref.is_empty() || resolved_ref != declared_ref {
        return MachineVerdict::refuse(
            "capability_declaration_not_resolved",
            format!(
                "operation names capability declaration '{declared_ref}', resolved '{resolved_ref}'"
            ),
        );
    }

    // THE DRIFT CHECK. Not "did we find a declaration" but "is it the one this operation was
    // written against". A ref alone cannot answer that, which is why canon binds the hash too.
    let declared_hash = match required_string(operation, "/capability_declaration_hash") {
        Ok(value) => value,
        Err(error) => return MachineVerdict::refuse("operation_contract_invalid", error),
    };
    // `jcs_hash` already returns the `sha256:` prefix; prefixing again produced `sha256:sha256:…`
    // and the contract's pattern caught it, which is the pattern doing its job.
    let resolved_hash = match jcs_hash(resolved_declaration) {
        Ok(hash) => hash,
        Err(error) => return MachineVerdict::refuse("capability_declaration_not_resolved", error),
    };
    if resolved_hash.as_str() != declared_hash {
        return MachineVerdict::refuse(
            "capability_declaration_drifted",
            format!("declaration hash is {resolved_hash}, operation was admitted against {declared_hash}"),
        );
    }

    // THE CAPABILITY MATRIX IS CONSULTED, NOT ASSUMED. An absent cell is unsupported: silence from
    // a backend is not permission, and a lowest-common-denominator default would be the
    // "simulated success" the journey's negative clauses refuse outright.
    let supported = resolved_declaration
        .pointer(&format!("/cells/{verb}/supported"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !supported {
        let reason = resolved_declaration
            .pointer(&format!("/cells/{verb}/unsupported_reason"))
            .and_then(Value::as_str)
            .unwrap_or("capability_cell_unsupported");
        return MachineVerdict::refuse(
            "capability_cell_unsupported",
            format!("backend does not support '{verb}': {reason}"),
        );
    }

    let expected_head = match required_string(operation, "/expected_head") {
        Ok(value) => value,
        Err(error) => return MachineVerdict::refuse("operation_contract_invalid", error),
    };
    if expected_head != observed_head {
        return MachineVerdict::refuse(
            "expected_head_stale",
            format!("operation expects head {expected_head}, server head is {observed_head}"),
        );
    }

    // IDEMPOTENCY IS A REFUSAL, NOT A SILENT SECOND EFFECT. A replayed request converges by being
    // told it already happened; running it again would be the double effect clause 7 forbids.
    let idempotency = match required_string(operation, "/idempotency_key_hash") {
        Ok(value) => value,
        Err(error) => return MachineVerdict::refuse("operation_contract_invalid", error),
    };
    if already_applied_idempotency_hashes
        .iter()
        .any(|applied| applied == idempotency)
    {
        return MachineVerdict::refuse(
            "operation_already_applied",
            format!("idempotency key {idempotency} has already been applied"),
        );
    }

    MachineVerdict::admit()
}

/// Compile the receipt for a REFUSED operation. The refusal never reached a backend, so there is no
/// backend operation to name and the generations do not move — stating otherwise would describe an
/// effect that was prevented.
pub fn compile_refusal_receipt(
    operation: &Value,
    receipt_ref: &str,
    verdict: &MachineVerdict,
    desired_generation_before: u64,
    observed_generation_before: u64,
    verifier_profile_ref: &str,
) -> Result<Value, String> {
    if verdict.admitted {
        return Err("compile_refusal_receipt called on an admitted verdict".into());
    }
    let receipt = json!({
        "schema_version": "ioi.hypervisor.machine-operation-receipt.v1",
        "receipt_ref": receipt_ref,
        "operation_ref": required_string(operation, "/operation_ref")?,
        "admitted_request_hash": jcs_hash(operation)?,
        "backend_native_operation_id": Value::Null,
        "desired_generation_before": desired_generation_before,
        "desired_generation_after": desired_generation_before,
        "observed_generation_before": observed_generation_before,
        "observed_generation_after": observed_generation_before,
        "result": "refused",
        "result_reason": verdict.refusal_dimension.unwrap_or("capability_cell_unsupported"),
        "consequence_receipt_refs": [],
        "verifier_profile_ref": verifier_profile_ref,
    });
    validate_architecture_contract(MACHINE_OPERATION_RECEIPT_CONTRACT, &receipt)?;
    Ok(receipt)
}

/// Compile the receipt for an operation that reached a backend.
///
/// The ambiguous arm is the reason this function exists at all: it produces a receipt that records
/// what is known and names what is not, rather than resolving the uncertainty by choosing.
pub fn compile_effect_receipt(
    operation: &Value,
    receipt_ref: &str,
    outcome: &MachineEffectOutcome,
    desired_generation_before: u64,
    observed_generation_before: u64,
    consequence_receipt_refs: &[String],
    verifier_profile_ref: &str,
) -> Result<Value, String> {
    let (native, desired_after, observed_after, result, reason) = match outcome {
        MachineEffectOutcome::Succeeded {
            backend_native_operation_id,
            desired_generation_after,
            observed_generation_after,
        } => (
            backend_native_operation_id.clone(),
            *desired_generation_after,
            *observed_generation_after,
            "succeeded",
            None,
        ),
        MachineEffectOutcome::Ambiguous {
            backend_native_operation_id,
            reason,
        } => (
            backend_native_operation_id.clone(),
            // AN AMBIGUOUS OUTCOME MOVES NEITHER GENERATION. The daemon does not know whether the
            // effect landed, and advancing a generation would be the claim it cannot make.
            desired_generation_before,
            observed_generation_before,
            "ambiguous",
            Some(reason.clone()),
        ),
    };
    let receipt = json!({
        "schema_version": "ioi.hypervisor.machine-operation-receipt.v1",
        "receipt_ref": receipt_ref,
        "operation_ref": required_string(operation, "/operation_ref")?,
        "admitted_request_hash": jcs_hash(operation)?,
        "backend_native_operation_id": native.map(Value::from).unwrap_or(Value::Null),
        "desired_generation_before": desired_generation_before,
        "desired_generation_after": desired_after,
        "observed_generation_before": observed_generation_before,
        "observed_generation_after": observed_after,
        "result": result,
        "result_reason": reason.map(Value::from).unwrap_or(Value::Null),
        "consequence_receipt_refs": consequence_receipt_refs,
        "verifier_profile_ref": verifier_profile_ref,
    });
    validate_architecture_contract(MACHINE_OPERATION_RECEIPT_CONTRACT, &receipt)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H_HEAD: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const H_KEY: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn declaration(verb: &str, supported: bool) -> Value {
        json!({
            "capability_declaration_ref": "machine-capability-declaration://cap_01",
            "cells": { verb: { "supported": supported, "unsupported_reason": "backend_lacks_live_migration" } }
        })
    }

    fn operation(verb: &str, declaration: &Value) -> Value {
        let hash = jcs_hash(declaration).unwrap();
        json!({
            "schema_version": "ioi.hypervisor.machine-operation.v1",
            "operation_ref": "machine-operation://mop_01",
            "operation": verb,
            "workload_ref": "virtual-machine-workload://vm_01",
            "desired_generation": 7,
            "expected_head": H_HEAD,
            "owner_ref": "principal://owner_01",
            "environment_ref": "environment://env_01",
            "backend_registration_ref": "machine-backend-registration://bk_01",
            "capability_declaration_ref": "machine-capability-declaration://cap_01",
            "capability_declaration_hash": hash,
            "affected_image_bindings": [],
            "affected_volume_bindings": [],
            "affected_network_bindings": [],
            "affected_device_bindings": [],
            "authority_refs": ["authority://wallet_network_01"],
            "policy_refs": [],
            "idempotency_key_hash": H_KEY,
            "cleanup_obligation_ref": Value::Null,
            "durability_boundary_ref": "durability-boundary://declared_01",
            "observation_boundary_ref": "observation-boundary://declared_01"
        })
    }

    #[test]
    fn a_supported_cell_on_a_current_declaration_is_admitted() {
        let declaration = declaration("start", true);
        let verdict =
            admit_machine_operation(&operation("start", &declaration), &declaration, H_HEAD, &[]);
        assert!(verdict.admitted, "{verdict:?}");
    }

    #[test]
    fn the_vocabulary_is_canons_sixteen_verbs_in_canons_order() {
        // The kernel's copy and the contract's enum must not drift apart. If they ever do, the
        // kernel refuses rather than admitting a verb the vocabulary does not contain — but the
        // right time to find out is here.
        assert_eq!(MACHINE_OPERATION_VOCABULARY.len(), 16);
        assert_eq!(MACHINE_OPERATION_VOCABULARY[0], "discover");
        assert_eq!(MACHINE_OPERATION_VOCABULARY[15], "delete");
        for verb in MACHINE_OPERATION_VOCABULARY {
            let declaration = declaration(verb, true);
            assert!(
                admit_machine_operation(&operation(verb, &declaration), &declaration, H_HEAD, &[])
                    .admitted,
                "'{verb}' is in canon's vocabulary and must be admissible"
            );
        }
    }

    #[test]
    fn a_backend_alias_is_not_a_canonical_verb() {
        let declaration = declaration("restart", true);
        // The contract's enum refuses it first; the kernel would refuse it too. Both, on purpose.
        let verdict = admit_machine_operation(
            &operation("restart", &declaration),
            &declaration,
            H_HEAD,
            &[],
        );
        assert!(!verdict.admitted);
        assert!(
            matches!(
                verdict.refusal_dimension,
                Some("operation_contract_invalid") | Some("operation_not_in_vocabulary")
            ),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_declaration_that_drifted_under_the_operation_refuses_before_effect() {
        // THE CASE A REF ALONE CANNOT SEE. Same ref, different bytes: the cell moved between
        // admission and effect, which is exactly what the journey requires to refuse.
        let admitted_against = declaration("start", true);
        let operation = operation("start", &admitted_against);
        let mut drifted = admitted_against.clone();
        drifted["cells"]["start"]["supported"] = json!(false);
        let verdict = admit_machine_operation(&operation, &drifted, H_HEAD, &[]);
        assert!(!verdict.admitted);
        assert_eq!(
            verdict.refusal_dimension,
            Some("capability_declaration_drifted")
        );
    }

    #[test]
    fn an_unsupported_cell_refuses_and_an_absent_cell_is_unsupported() {
        let declared_unsupported = declaration("migrate", false);
        let verdict = admit_machine_operation(
            &operation("migrate", &declared_unsupported),
            &declared_unsupported,
            H_HEAD,
            &[],
        );
        assert_eq!(
            verdict.refusal_dimension,
            Some("capability_cell_unsupported")
        );
        assert!(verdict
            .refusal_reason
            .unwrap()
            .contains("backend_lacks_live_migration"));

        // SILENCE IS NOT PERMISSION. A declaration with no cell for the verb refuses too — a
        // lowest-common-denominator default would be the simulated success the journey refuses.
        let silent = json!({ "capability_declaration_ref": "machine-capability-declaration://cap_01", "cells": {} });
        let verdict = admit_machine_operation(&operation("migrate", &silent), &silent, H_HEAD, &[]);
        assert_eq!(
            verdict.refusal_dimension,
            Some("capability_cell_unsupported")
        );
    }

    #[test]
    fn a_stale_head_and_a_replayed_key_both_refuse_rather_than_taking_effect_twice() {
        let declaration = declaration("stop", true);
        let op = operation("stop", &declaration);
        let stale = admit_machine_operation(
            &op,
            &declaration,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            &[],
        );
        assert_eq!(stale.refusal_dimension, Some("expected_head_stale"));

        let replayed = admit_machine_operation(&op, &declaration, H_HEAD, &[H_KEY.to_string()]);
        assert_eq!(
            replayed.refusal_dimension,
            Some("operation_already_applied")
        );
    }

    #[test]
    fn a_refusal_receipt_names_no_backend_operation_and_moves_no_generation() {
        let declaration = declaration("migrate", false);
        let op = operation("migrate", &declaration);
        let verdict = admit_machine_operation(&op, &declaration, H_HEAD, &[]);
        let receipt = compile_refusal_receipt(
            &op,
            "machine-operation-receipt://mor_01",
            &verdict,
            6,
            6,
            "verifier-profile://workstation_hosted_v1",
        )
        .expect("a refusal receipt is a valid receipt");
        assert_eq!(receipt["result"], json!("refused"));
        assert_eq!(
            receipt["result_reason"],
            json!("capability_cell_unsupported")
        );
        assert_eq!(
            receipt["backend_native_operation_id"],
            Value::Null,
            "a refusal that never reached a backend must not name a backend operation"
        );
        assert_eq!(receipt["desired_generation_after"], json!(6));
        assert_eq!(receipt["observed_generation_after"], json!(6));
    }

    #[test]
    fn an_ambiguous_outcome_moves_neither_generation_and_says_why() {
        // THE POINT OF THE THIRD MEMBER. The daemon does not know whether the effect landed, so it
        // advances nothing and records what it could not confirm — rather than choosing an answer.
        let declaration = declaration("create", true);
        let op = operation("create", &declaration);
        let receipt = compile_effect_receipt(
            &op,
            "machine-operation-receipt://mor_02",
            &MachineEffectOutcome::Ambiguous {
                backend_native_operation_id: Some("op-99".into()),
                reason: "external_completion_unconfirmed".into(),
            },
            6,
            6,
            &[],
            "verifier-profile://workstation_hosted_v1",
        )
        .expect("an ambiguous receipt is a valid receipt");
        assert_eq!(receipt["result"], json!("ambiguous"));
        assert_eq!(
            receipt["result_reason"],
            json!("external_completion_unconfirmed")
        );
        assert_eq!(receipt["desired_generation_after"], json!(6));
        assert_eq!(receipt["observed_generation_after"], json!(6));
    }

    #[test]
    fn a_succeeded_receipt_may_record_observed_trailing_desired() {
        let declaration = declaration("start", true);
        let op = operation("start", &declaration);
        let receipt = compile_effect_receipt(
            &op,
            "machine-operation-receipt://mor_03",
            &MachineEffectOutcome::Succeeded {
                backend_native_operation_id: None,
                desired_generation_after: 7,
                observed_generation_after: 6,
            },
            6,
            6,
            &[],
            "verifier-profile://workstation_hosted_v1",
        )
        .expect("a success receipt is a valid receipt");
        assert_eq!(receipt["result"], json!("succeeded"));
        assert_eq!(receipt["result_reason"], Value::Null);
        // Admitted and not yet landed. A runtime that could not say this would be reporting
        // intentions as state.
        assert_eq!(receipt["desired_generation_after"], json!(7));
        assert_eq!(receipt["observed_generation_after"], json!(6));
    }
}
