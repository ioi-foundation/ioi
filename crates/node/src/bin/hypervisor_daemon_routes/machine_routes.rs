//! M09.11 — the durable machine-operation plane: submit a versioned operation, admit it against the
//! backend's CURRENT capability declaration, and record what happened.
//!
//! ACC-20 clause 5 is the shape of this file: authority and effects do not move into clients. A
//! client submits a PROPOSAL; the daemon resolves the capability declaration, admits or refuses,
//! mints the canonical identity, and writes the records. Three things a caller therefore cannot do:
//!
//!   * CHOOSE THE OPERATION'S IDENTITY. `operation_ref` is minted here from the workload, the verb
//!     and a nonce. A caller-chosen id is a caller-chosen record, and canon already says the
//!     backend's own id is evidence and never identity — the same applies to the client's.
//!   * SUPPLY THE CAPABILITY DECLARATION. The request carries the ref and hash it was WRITTEN
//!     against; the daemon resolves the declaration itself and the kernel compares. A caller that
//!     supplied the declaration would be grading its own homework.
//!   * OBSERVE A REFUSAL WITHOUT A RECEIPT. A refusal is an outcome, so it gets a receipt at once.
//!
//! WHAT THIS SLICE DELIBERATELY DOES NOT DO. There is no executor yet, so an ADMITTED operation is
//! persisted as admitted and awaiting effect, with no receipt. That is the honest record: a receipt
//! naming a result would be describing an effect nothing attempted. The refusal path, by contrast,
//! is complete — which is why the tests here are mostly about refusals.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::HeaderMap;
use axum::Json;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use ioi_types::app::hypervisor_machine_lifecycle::{
    admit_machine_operation, admitted_request_hash, compile_effect_receipt,
    compile_refusal_receipt, execute_reference_operation, MachineVerdict,
    MACHINE_OPERATION_CONTRACT,
};
use serde_json::{json, Value};

use crate::{read_record_dir, AppError, DaemonState};

/// Path-safe id, matching the convention the environment plane already uses for record ids.
fn safe_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Durable operation proposals, admitted or refused.
pub(crate) const MACHINE_OPERATION_RECORDS: &str = "machine-operations";
/// Durable receipts. Separate from the operations on purpose: a receipt is evidence ABOUT an
/// operation and outlives any projection of it.
pub(crate) const MACHINE_RECEIPT_RECORDS: &str = "machine-operation-receipts";
/// Durable backend capability declarations, written by whatever registered the backend.
pub(crate) const MACHINE_CAPABILITY_RECORDS: &str = "machine-capability-declarations";

/// The verifier profile this daemon's own admission evidence is produced under. Named on every
/// receipt because ACC-20 clause 10 keeps the hosted and attached matrices separate and evidence
/// from one may not promote the other.
const DAEMON_VERIFIER_PROFILE: &str = "verifier-profile://hypervisor/machine-admission/v1";

/// Resolve the CURRENT capability declaration for a ref. Server truth: never the caller's copy.
pub(crate) fn resolve_capability_declaration(
    data_dir: &str,
    declaration_ref: &str,
) -> Option<Value> {
    read_record_dir(data_dir, MACHINE_CAPABILITY_RECORDS)
        .into_iter()
        .find(|record| record["declaration_ref"].as_str() == Some(declaration_ref))
}

/// Canonical identity, minted here. Deterministic in its workload and verb, unique by nonce, so two
/// distinct proposals for the same verb are two records rather than one overwriting the other.
fn mint_operation_ref(workload_id: &str, verb: &str) -> String {
    format!(
        "machine-operation://hypervisor/{}/{verb}/{}",
        safe_id(workload_id),
        uuid::Uuid::new_v4().simple()
    )
}

fn receipt_ref_for(operation_ref: &str) -> String {
    format!(
        "machine-operation-receipt://hypervisor/{}",
        operation_ref.rsplit('/').next().unwrap_or("unknown")
    )
}

/// The workload's canonical head, DERIVED FROM SERVER TRUTH rather than held in memory or taken
/// from the request. It is the admitted-request hash of the most recent admitted operation, so each
/// admitted operation advances it by construction and a caller that acted on a stale view says so
/// in `expected_head` and is refused. A workload with no admitted operation yet has the genesis
/// head, which is a real value rather than an absence — a caller must still state it.
///
/// This is deliberately derived and not stored: a head kept in `DaemonState` would be memory the
/// restart case is required to reconstruct anyway, and reconstructing it from the records IS the
/// reconstruction.
pub(crate) const MACHINE_GENESIS_HEAD: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn observed_head_for(data_dir: &str, workload_ref: &str) -> String {
    // PER WORKLOAD. A head derived from every workload's operations would move under machine A
    // because machine B was started, and every caller of A would then be refused as stale for a
    // reason that had nothing to do with A.
    read_record_dir(data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .filter(|record| {
            record["operation"]["workload_ref"].as_str() == Some(workload_ref)
                && record["admission"]["admitted"].as_bool() == Some(true)
        })
        .filter_map(|record| record["admitted_request_hash"].as_str().map(str::to_owned))
        .last()
        .unwrap_or_else(|| MACHINE_GENESIS_HEAD.to_owned())
}

/// The workload's generations as last OBSERVED, from its receipts. A workload with no succeeded
/// receipt is at generation zero, which is a state rather than an absence.
///
/// Read from receipts and not from the operations, because a generation is a fact about EFFECT:
/// an admitted operation that came back ambiguous advanced nothing, and reading the operation
/// records would have it advance the moment it was admitted.
fn current_generations(data_dir: &str, workload_ref: &str) -> (u64, u64) {
    let operations = read_record_dir(data_dir, MACHINE_OPERATION_RECORDS);
    let receipt_for = |receipt: &Value| -> bool {
        let operation_ref = receipt["operation_ref"].as_str().unwrap_or_default();
        operations.iter().any(|record| {
            record["operation_ref"].as_str() == Some(operation_ref)
                && record["operation"]["workload_ref"].as_str() == Some(workload_ref)
        })
    };
    read_record_dir(data_dir, MACHINE_RECEIPT_RECORDS)
        .into_iter()
        .filter(|receipt| receipt["result"].as_str() == Some("succeeded") && receipt_for(receipt))
        .filter_map(|receipt| {
            Some((
                receipt["desired_generation_after"].as_u64()?,
                receipt["observed_generation_after"].as_u64()?,
            ))
        })
        .last()
        .unwrap_or((0, 0))
}

/// Every idempotency hash already applied for this workload. Read from the durable record set
/// rather than from memory, so a restart cannot forget that something already happened — which is
/// the whole of ACC-20 clause 7's duplicate case.
fn applied_idempotency_hashes(data_dir: &str, workload_ref: &str) -> Vec<String> {
    read_record_dir(data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .filter(|record| {
            record["operation"]["workload_ref"].as_str() == Some(workload_ref)
                && record["admission"]["admitted"].as_bool() == Some(true)
        })
        .filter_map(|record| {
            record["operation"]["idempotency_key_hash"]
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

/// Submit one machine operation for admission.
pub(crate) async fn handle_machine_operation_submit(
    State(st): State<Arc<DaemonState>>,
    AxumPath(workload_id): AxumPath<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, AppError> {
    // Bytes, not `Json<Value>`: the body extractor runs BEFORE the handler, so a caller sending
    // nothing would be refused for its content type rather than answered for who it is.
    let _ = &headers;
    let Ok(proposal) = serde_json::from_slice::<Value>(&body) else {
        return Ok(Json(
            json!({ "ok": false, "reason": "operation_proposal_unparsable" }),
        ));
    };

    let verb = proposal["operation"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let operation_ref = mint_operation_ref(&workload_id, &verb);
    let mut operation = proposal.clone();
    // IDENTITY IS MINTED HERE, overwriting whatever the caller sent. A proposal is a request for an
    // operation, not an operation.
    operation["operation_ref"] = json!(operation_ref);

    if let Err(error) = validate_architecture_contract(MACHINE_OPERATION_CONTRACT, &operation) {
        return Ok(Json(json!({
            "ok": false,
            "reason": "operation_contract_invalid",
            "detail": error,
        })));
    }

    let declaration_ref = operation["capability_declaration_ref"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let Some(declaration) = resolve_capability_declaration(&st.data_dir, &declaration_ref) else {
        // An unresolvable declaration is a REFUSAL WITH A RECEIPT, not a 404: the caller proposed
        // an operation against a backend declaration this daemon does not have, and that is an
        // outcome worth recording rather than a routing accident.
        let verdict = admit_machine_operation(&operation, &json!({}), "", &[]);
        let receipt_ref = receipt_ref_for(&operation_ref);
        let receipt = compile_refusal_receipt(
            &operation,
            &receipt_ref,
            &verdict,
            0,
            0,
            DAEMON_VERIFIER_PROFILE,
        )
        .map_err(|error| AppError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, error))?;
        persist_operation(&st.data_dir, &operation, &verdict, Some(&receipt));
        return Ok(Json(json!({
            "ok": false,
            "operation_ref": operation_ref,
            "reason": verdict.refusal_dimension,
            "receipt_ref": receipt_ref,
        })));
    };

    let workload_ref = operation["workload_ref"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let observed_head = observed_head_for(&st.data_dir, &workload_ref);
    let applied = applied_idempotency_hashes(&st.data_dir, &workload_ref);

    let verdict = admit_machine_operation(&operation, &declaration, &observed_head, &applied);
    if !verdict.admitted {
        let receipt_ref = receipt_ref_for(&operation_ref);
        let receipt = compile_refusal_receipt(
            &operation,
            &receipt_ref,
            &verdict,
            0,
            0,
            DAEMON_VERIFIER_PROFILE,
        )
        .map_err(|error| AppError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, error))?;
        persist_operation(&st.data_dir, &operation, &verdict, Some(&receipt));
        return Ok(Json(json!({
            "ok": false,
            "operation_ref": operation_ref,
            "reason": verdict.refusal_dimension,
            "detail": verdict.refusal_reason,
            "receipt_ref": receipt_ref,
        })));
    }

    // ADMITTED. Whether it can be EXECUTED is a separate question with an honest answer either way.
    let (desired_before, observed_before) = current_generations(&st.data_dir, &workload_ref);
    match execute_reference_operation(&operation, &declaration) {
        Ok(outcome) => {
            let receipt_ref = receipt_ref_for(&operation_ref);
            let receipt = compile_effect_receipt(
                &operation,
                &receipt_ref,
                &outcome,
                desired_before,
                observed_before,
                &[],
                DAEMON_VERIFIER_PROFILE,
            )
            .map_err(|error| AppError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, error))?;
            let result = receipt["result"].as_str().unwrap_or("succeeded").to_owned();
            persist_operation(&st.data_dir, &operation, &verdict, Some(&receipt));
            Ok(Json(json!({
                "ok": true,
                "operation_ref": operation_ref,
                "state": result,
                "receipt_ref": receipt_ref,
            })))
        }
        Err(reason) => {
            // NO EXECUTOR FOR THIS BACKEND. A real (live or declared) backend is admitted and left
            // awaiting effect with NO receipt, because this daemon has nothing that can act on it
            // yet and a receipt naming a result would describe an effect nothing attempted. The
            // reference executor refusing here is the fence working, not a failure.
            persist_operation(&st.data_dir, &operation, &verdict, None);
            Ok(Json(json!({
                "ok": true,
                "operation_ref": operation_ref,
                "state": "admitted_awaiting_effect",
                "detail": reason,
                "receipt_ref": Value::Null,
            })))
        }
    }
}

fn persist_operation(
    data_dir: &str,
    operation: &Value,
    verdict: &MachineVerdict,
    receipt: Option<&Value>,
) {
    let operation_ref = operation["operation_ref"].as_str().unwrap_or_default();
    let record = json!({
        "operation_ref": operation_ref,
        "operation": operation,
        // Stored, not recomputed on read: the head this operation advances the workload to is the
        // SAME hash the receipt binds, from the same definition in the kernel.
        "admitted_request_hash": admitted_request_hash(operation).unwrap_or_default(),
        "admission": {
            "admitted": verdict.admitted,
            "refusal_dimension": verdict.refusal_dimension,
            "refusal_reason": verdict.refusal_reason,
        },
        "state": if verdict.admitted { "admitted_awaiting_effect" } else { "refused" },
        "receipt_ref": receipt.map(|r| r["receipt_ref"].clone()).unwrap_or(Value::Null),
    });
    let id = operation_ref.rsplit('/').next().unwrap_or("unknown");
    let _ =
        super::durable_fs::persist_record_durable(data_dir, MACHINE_OPERATION_RECORDS, id, &record);
    if let Some(receipt) = receipt {
        let _ = super::durable_fs::persist_record_durable(
            data_dir,
            MACHINE_RECEIPT_RECORDS,
            id,
            receipt,
        );
    }
}

/// Read every operation recorded for one workload, newest first by record order.
pub(crate) async fn handle_machine_operations_list(
    State(st): State<Arc<DaemonState>>,
    AxumPath(workload_id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let prefix = format!("/hypervisor/{}/", safe_id(&workload_id));
    let operations: Vec<Value> = read_record_dir(&st.data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .filter(|record| {
            record["operation_ref"]
                .as_str()
                .is_some_and(|value| value.contains(&prefix))
        })
        .collect();
    Ok(Json(json!({
        "ok": true,
        "workload": workload_id,
        "operations": operations,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ioi-machine-routes-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("temp data dir");
        dir
    }

    fn write(data_dir: &std::path::Path, family: &str, id: &str, record: &Value) {
        super::super::durable_fs::persist_record_durable(
            data_dir.to_str().unwrap(),
            family,
            id,
            record,
        )
        .expect("durable write");
    }

    fn admitted_record(workload: &str, hash: &str, key: &str) -> Value {
        json!({
            "operation_ref": format!("machine-operation://hypervisor/{workload}/start/{key}"),
            "operation": { "workload_ref": workload, "idempotency_key_hash": key },
            "admission": { "admitted": true, "refusal_dimension": Value::Null, "refusal_reason": Value::Null },
            "admitted_request_hash": hash,
            "state": "admitted_awaiting_effect",
            "receipt_ref": Value::Null,
        })
    }

    #[test]
    fn a_workload_with_no_admitted_operation_has_the_genesis_head_not_an_absence() {
        let dir = temp_dir();
        assert_eq!(
            observed_head_for(dir.to_str().unwrap(), "virtual-machine-workload://vm_a"),
            MACHINE_GENESIS_HEAD,
            "a caller must still state a head; there is no 'no head yet' that admits anything"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_workloads_head_does_not_move_because_another_workload_acted() {
        // THE DEFECT THIS TEST EXISTS FOR. The first cut derived the head from every receipt in the
        // estate, so starting machine B would have made every caller of machine A stale — refused
        // for a reason that had nothing to do with A.
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        let head_a = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let head_b = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "a1",
            &admitted_record("virtual-machine-workload://vm_a", head_a, "k1"),
        );
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "b1",
            &admitted_record("virtual-machine-workload://vm_b", head_b, "k2"),
        );

        assert_eq!(
            observed_head_for(d, "virtual-machine-workload://vm_a"),
            head_a
        );
        assert_eq!(
            observed_head_for(d, "virtual-machine-workload://vm_b"),
            head_b
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn applied_keys_are_read_from_durable_records_so_a_restart_cannot_forget_them() {
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "a1",
            &admitted_record(
                "virtual-machine-workload://vm_a",
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "key-one",
            ),
        );
        // A REFUSED operation's key was never applied, so replaying it must not be blocked.
        let mut refused = admitted_record(
            "virtual-machine-workload://vm_a",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "key-two",
        );
        refused["admission"]["admitted"] = json!(false);
        write(&dir, MACHINE_OPERATION_RECORDS, "a2", &refused);

        let applied = applied_idempotency_hashes(d, "virtual-machine-workload://vm_a");
        assert!(applied.contains(&"key-one".to_string()));
        assert!(
            !applied.contains(&"key-two".to_string()),
            "a refused operation never took effect, so its key is not spent"
        );
        // And another workload's key is not this workload's.
        assert!(applied_idempotency_hashes(d, "virtual-machine-workload://vm_b").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_declaration_is_resolved_by_its_own_ref_from_server_records() {
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        write(
            &dir,
            MACHINE_CAPABILITY_RECORDS,
            "cap1",
            &json!({ "declaration_ref": "capability://backend/local-kvm/1", "supported_operations": ["start"] }),
        );
        assert!(resolve_capability_declaration(d, "capability://backend/local-kvm/1").is_some());
        assert!(
            resolve_capability_declaration(d, "capability://backend/absent/1").is_none(),
            "an unresolvable declaration is a refusal with a receipt, never a silent default"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generations_come_from_receipts_and_an_ambiguous_outcome_advances_nothing() {
        // A generation is a fact about EFFECT. Reading the OPERATION records would advance it the
        // moment something was admitted, which is the difference between reporting state and
        // reporting intentions.
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        let workload = "virtual-machine-workload://vm_a";
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "a1",
            &admitted_record(
                workload,
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "k1",
            ),
        );
        assert_eq!(
            current_generations(d, workload),
            (0, 0),
            "no succeeded receipt yet"
        );

        let op_ref = format!("machine-operation://hypervisor/{workload}/start/k1");
        write(
            &dir,
            MACHINE_RECEIPT_RECORDS,
            "a1",
            &json!({
                "operation_ref": op_ref, "result": "succeeded",
                "desired_generation_after": 7, "observed_generation_after": 7,
            }),
        );
        // The receipt must be tied to an operation of THIS workload; the record above is.
        let mut record = admitted_record(
            workload,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "k1",
        );
        record["operation_ref"] = json!(op_ref);
        write(&dir, MACHINE_OPERATION_RECORDS, "a1", &record);
        assert_eq!(current_generations(d, workload), (7, 7));

        // An AMBIGUOUS receipt advances nothing, so the workload stays where it was.
        write(
            &dir,
            MACHINE_RECEIPT_RECORDS,
            "a2",
            &json!({
                "operation_ref": op_ref, "result": "ambiguous",
                "desired_generation_after": 7, "observed_generation_after": 7,
            }),
        );
        assert_eq!(current_generations(d, workload), (7, 7));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_operation_ref_is_minted_and_never_the_callers() {
        let first = mint_operation_ref("vm a/../b", "start");
        let second = mint_operation_ref("vm a/../b", "start");
        // Assert the PROPERTY, not a hand-counted string: the workload segment carries no path
        // separators, spaces or dots, whatever the caller named the machine. (The first version of
        // this assertion miscounted the underscores and failed on correct code.)
        let workload_segment = first
            .trim_start_matches("machine-operation://hypervisor/")
            .split('/')
            .next()
            .unwrap();
        assert!(
            workload_segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "the workload segment is path-safe: {workload_segment}"
        );
        assert!(first.starts_with("machine-operation://hypervisor/"));
        assert!(
            first.contains("/start/"),
            "the verb is part of the identity: {first}"
        );
        assert_ne!(
            first, second,
            "two proposals are two operations, not one overwriting the other"
        );
    }
}
