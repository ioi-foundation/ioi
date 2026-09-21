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
//!
//! M08.15 (R-215) adds the two things a CLIENT needs and must not build for itself:
//!
//!   * A READ MODEL. `GET /v1/hypervisor/machines` is the inventory and
//!     `GET /v1/hypervisor/machines/:workload` is one workload's spine — head, desired and observed
//!     generations and phases, the declaration it is bound to, its operations in chain order, its
//!     receipts and cleanup obligations — DERIVED FROM THE RECORDS ON EVERY READ by the same
//!     functions the submit path admits with. The first client of this plane (the M09.11 gate)
//!     re-derived the head from the operation list on its own; that is the parallel bookkeeping
//!     ACC-20 clause 2 forbids, and the cure is a daemon that answers the question.
//!   * IDENTITY. A proposal is admitted under a resolved principal or not at all: an anonymous
//!     submit is refused 401 `request_principal_required` before the contract is even validated,
//!     and the record carries `submitted_by` as the DAEMON resolved it, never as the caller said.
//!     The read lanes keep the estate's loopback convenience; a mutation does not.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use ioi_types::app::hypervisor_machine_lifecycle::{
    admit_machine_operation, admitted_request_hash, compile_effect_receipt,
    compile_refusal_receipt, execute_reference_operation, refuse_forked_head, MachineVerdict,
    MACHINE_OPERATION_CONTRACT,
};
use serde_json::{json, Value};

use super::lifecycle_routes::resolve_principal;
use crate::{iso_now, read_record_dir, AppError, DaemonState};

/// The vocabulary members that SET a phase, and the phase each sets. Everything else — a snapshot,
/// a console session, a migration — leaves the phase where it was. One table, consulted by both
/// the desired readout (over admitted operations) and the observed readout (over succeeded
/// receipts), so the two can never disagree about what a verb means.
fn phase_after(verb: &str, previous: &str) -> String {
    match verb {
        "discover" | "define" | "import" | "create" => "defined".to_owned(),
        "start" | "resume" | "reboot" => "running".to_owned(),
        "stop" => "stopped".to_owned(),
        "pause" => "paused".to_owned(),
        "delete" => "deleted".to_owned(),
        _ => previous.to_owned(),
    }
}

/// A workload with no recorded operation has no phase — a real value the read model states rather
/// than an absence a client would have to invent a word for.
const MACHINE_PHASE_NONE: &str = "unrecorded";

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

fn observed_head_for(data_dir: &str, workload_ref: &str) -> Result<String, String> {
    // THE HEAD IS THE ONE NO SUCCESSOR CITES — the estate's own fork rule, the same one route
    // bindings use. The first cut took `.last()` over `read_record_dir`, which iterates
    // `std::fs::read_dir` with NO ORDERING: the head was whichever record the filesystem happened
    // to hand back last, so it was non-deterministic and a caller could be refused as stale for
    // having quoted the head it was just given. The conformance gate caught it on its first run.
    let admitted: Vec<Value> = read_record_dir(data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .filter(|record| {
            record["operation"]["workload_ref"].as_str() == Some(workload_ref)
                && record["admission"]["admitted"].as_bool() == Some(true)
        })
        .collect();
    if admitted.is_empty() {
        return Ok(MACHINE_GENESIS_HEAD.to_owned());
    }
    let cited: std::collections::HashSet<&str> = admitted
        .iter()
        .filter_map(|record| record["previous_head"].as_str())
        .collect();
    let heads: Vec<&str> = admitted
        .iter()
        .filter_map(|record| record["admitted_request_hash"].as_str())
        .filter(|hash| !cited.contains(hash))
        .collect();
    match heads.as_slice() {
        [single] => Ok((*single).to_owned()),
        [] => {
            Err("every admitted operation is cited as a predecessor — the chain has no head".into())
        }
        many => Err(format!(
            "{} uncited heads for this workload — a fork, not a history",
            many.len()
        )),
    }
}

/// The workload's generations as last OBSERVED, from its receipts. A workload with no succeeded
/// receipt is at generation zero, which is a state rather than an absence.
///
/// Read from receipts and not from the operations, because a generation is a fact about EFFECT:
/// an admitted operation that came back ambiguous advanced nothing, and reading the operation
/// records would have it advance the moment it was admitted.
///
/// IN CHAIN ORDER (M08.15). The first cut took `.last()` over `read_record_dir`, which iterates the
/// directory with NO ORDERING — the same defect R-130 found in the head derivation, one function
/// down. With two succeeded receipts the "last" one was whichever the filesystem handed back last,
/// so a workload at generation 2 read back at generation 1 on some runs and not others; the
/// composition gate caught it on its first full run. The generations are now those of the LAST
/// SUCCEEDED receipt along the admitted chain, which is deterministic because the chain is.
fn current_generations(data_dir: &str, workload_ref: &str) -> (u64, u64) {
    let receipts = read_record_dir(data_dir, MACHINE_RECEIPT_RECORDS);
    admitted_chain(data_dir, workload_ref)
        .iter()
        .filter_map(|record| {
            let operation_ref = record["operation_ref"].as_str()?;
            receipts.iter().find(|receipt| {
                receipt["operation_ref"].as_str() == Some(operation_ref)
                    && receipt["result"].as_str() == Some("succeeded")
            })
        })
        .filter_map(|receipt| {
            Some((
                receipt["desired_generation_after"].as_u64()?,
                receipt["observed_generation_after"].as_u64()?,
            ))
        })
        .last()
        .unwrap_or((0, 0))
}

/// The workload's ADMITTED operations in chain order, genesis first: each admitted record names the
/// head it advanced from, so the chain is walked without a clock, a counter or a sorted directory.
/// A fork (two records advancing from one head) ends the walk there — nothing past a fork is on
/// the chain, because picking a side would be choosing which history is real.
pub(crate) fn admitted_chain(data_dir: &str, workload_ref: &str) -> Vec<Value> {
    let admitted: Vec<Value> = read_record_dir(data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .filter(|record| {
            record["operation"]["workload_ref"].as_str() == Some(workload_ref)
                && record["admission"]["admitted"].as_bool() == Some(true)
        })
        .collect();
    let mut chain: Vec<Value> = Vec::new();
    let mut cursor = MACHINE_GENESIS_HEAD.to_owned();
    loop {
        let successors: Vec<&Value> = admitted
            .iter()
            .filter(|record| record["previous_head"].as_str() == Some(cursor.as_str()))
            .collect();
        match successors.as_slice() {
            [single] => {
                let next = single["admitted_request_hash"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                chain.push((*single).clone());
                if next.is_empty() || chain.len() > admitted.len() {
                    break;
                }
                cursor = next;
            }
            _ => break,
        }
    }
    chain
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
) -> Result<(StatusCode, Json<Value>), AppError> {
    // Bytes, not `Json<Value>`: the body extractor runs BEFORE the handler, so a caller sending
    // nothing would be refused for its content type rather than answered for who it is.
    //
    // IDENTITY FIRST (M08.15). A machine operation is a mutation, and the estate's rule for a
    // mutating route is a resolved principal or a 401 — the loopback `user://local-operator`
    // convenience belongs to READ lanes. The first cut of this handler ignored the headers
    // outright, so an anonymous proposal was admitted and recorded as nobody's; the App lane and
    // an admitted extension made that reachable from a browser, which is exactly the
    // authority-bypass ACC-20 clause 9 asks a gate to go red on.
    let Some(principal) = resolve_principal(&st.data_dir, &headers) else {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "ok": false,
                "reason": "request_principal_required",
                "error": { "code": "request_principal_required", "message": "a machine operation is admitted under a resolved principal; this request carried none" },
            })),
        ));
    };
    let submitted_by = principal
        .get("principal_id")
        .and_then(Value::as_str)
        .map(|id| format!("user://{id}"))
        .unwrap_or_else(|| "user://unresolved".to_owned());
    let Ok(proposal) = serde_json::from_slice::<Value>(&body) else {
        return Ok((
            StatusCode::OK,
            Json(json!({ "ok": false, "reason": "operation_proposal_unparsable" })),
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
        return Ok((
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "reason": "operation_contract_invalid",
                "detail": error,
            })),
        ));
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
        persist_operation(
            &st.data_dir,
            &operation,
            &verdict,
            Some(&receipt),
            MACHINE_GENESIS_HEAD,
            &submitted_by,
        );
        return Ok((
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "operation_ref": operation_ref,
                "reason": verdict.refusal_dimension,
                "receipt_ref": receipt_ref,
            })),
        ));
    };

    let workload_ref = operation["workload_ref"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let observed_head = match observed_head_for(&st.data_dir, &workload_ref) {
        Ok(head) => head,
        Err(detail) => {
            // A FORK IS NOT A STALE HEAD, and refusing it as one would hide it. Nothing is admitted
            // while two histories are uncited: picking one would be choosing which is real.
            let verdict = refuse_forked_head(detail);
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
            persist_operation(
                &st.data_dir,
                &operation,
                &verdict,
                Some(&receipt),
                MACHINE_GENESIS_HEAD,
                &submitted_by,
            );
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "ok": false,
                    "operation_ref": operation_ref,
                    "reason": verdict.refusal_dimension,
                    "detail": verdict.refusal_reason,
                    "receipt_ref": receipt_ref,
                })),
            ));
        }
    };
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
        persist_operation(
            &st.data_dir,
            &operation,
            &verdict,
            Some(&receipt),
            &observed_head,
            &submitted_by,
        );
        return Ok((
            StatusCode::OK,
            Json(json!({
                "ok": false,
                "operation_ref": operation_ref,
                "reason": verdict.refusal_dimension,
                "detail": verdict.refusal_reason,
                "receipt_ref": receipt_ref,
            })),
        ));
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
            persist_operation(
                &st.data_dir,
                &operation,
                &verdict,
                Some(&receipt),
                &observed_head,
                &submitted_by,
            );
            Ok((
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "operation_ref": operation_ref,
                    "state": result,
                    "receipt_ref": receipt_ref,
                })),
            ))
        }
        Err(reason) => {
            // NO EXECUTOR FOR THIS BACKEND. A real (live or declared) backend is admitted and left
            // awaiting effect with NO receipt, because this daemon has nothing that can act on it
            // yet and a receipt naming a result would describe an effect nothing attempted. The
            // reference executor refusing here is the fence working, not a failure.
            persist_operation(
                &st.data_dir,
                &operation,
                &verdict,
                None,
                &observed_head,
                &submitted_by,
            );
            Ok((
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "operation_ref": operation_ref,
                    "state": "admitted_awaiting_effect",
                    "detail": reason,
                    "receipt_ref": Value::Null,
                })),
            ))
        }
    }
}

fn persist_operation(
    data_dir: &str,
    operation: &Value,
    verdict: &MachineVerdict,
    receipt: Option<&Value>,
    previous_head: &str,
    submitted_by: &str,
) {
    let operation_ref = operation["operation_ref"].as_str().unwrap_or_default();
    let record = json!({
        "operation_ref": operation_ref,
        "operation": operation,
        // WHO, as the daemon resolved it from the session — never a member of the proposal, which
        // the contract closes against extra fields anyway. And WHEN, so refusals (which advance no
        // head and therefore sit on no chain) still read back in a stable order.
        "submitted_by": submitted_by,
        "submitted_at": iso_now(),
        // Stored, not recomputed on read: the head this operation advances the workload to is the
        // SAME hash the receipt binds, from the same definition in the kernel.
        "admitted_request_hash": admitted_request_hash(operation).unwrap_or_default(),
        // The predecessor this operation was admitted against. The head is the hash NO record cites
        // here, which is deterministic without a clock, a counter or a sorted directory read.
        "previous_head": previous_head,
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

/// The workload id the operation refs carry: the path-safe segment after the plane prefix.
fn workload_id_of(operation_ref: &str) -> Option<&str> {
    operation_ref
        .strip_prefix("machine-operation://hypervisor/")
        .and_then(|rest| rest.split('/').next())
        .filter(|segment| !segment.is_empty())
}

/// ONE WORKLOAD'S SPINE, derived from the records on every read. `None` when no record names the
/// workload — unknown is not empty.
///
/// What is derived and how, stated once here because a client reading it must not re-derive it:
///   head              — `observed_head_for` (the admitted hash no successor cites); a fork reads
///                       back as `head: null` with `head_error`, never as one of the two heads;
///   generations       — `current_generations` (from SUCCEEDED receipts, never from operations);
///   desired_phase     — `phase_after` folded over the admitted chain in chain order;
///   observed_phase    — `phase_after` folded over the same chain, moving only where the
///                       operation's receipt says `succeeded`;
///   operations        — the admitted chain in order (genesis → head) followed by the refused
///                       proposals by submission time, each with its record members and receipt ref;
///   declaration       — the ref and hash the LAST admitted operation was written against, with
///                       the resolved declaration's evidence mode (or null if it no longer resolves).
pub(crate) fn machine_spine(data_dir: &str, workload_ref: &str) -> Option<Value> {
    let records: Vec<Value> = read_record_dir(data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .filter(|record| record["operation"]["workload_ref"].as_str() == Some(workload_ref))
        .collect();
    if records.is_empty() {
        return None;
    }
    let receipts: Vec<Value> = read_record_dir(data_dir, MACHINE_RECEIPT_RECORDS);
    let receipt_for = |operation_ref: &str| -> Option<&Value> {
        receipts
            .iter()
            .find(|receipt| receipt["operation_ref"].as_str() == Some(operation_ref))
    };

    // The admitted chain, walked from genesis by the same function the generations use.
    let admitted: Vec<&Value> = records
        .iter()
        .filter(|record| record["admission"]["admitted"].as_bool() == Some(true))
        .collect();
    let chain_owned = admitted_chain(data_dir, workload_ref);
    let chain: Vec<&Value> = chain_owned.iter().collect();
    let mut refused: Vec<&Value> = records
        .iter()
        .filter(|record| record["admission"]["admitted"].as_bool() != Some(true))
        .collect();
    refused.sort_by(|left, right| {
        let key = |record: &Value| {
            (
                record["submitted_at"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                record["operation_ref"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        };
        key(left).cmp(&key(right))
    });

    let mut desired_phase = MACHINE_PHASE_NONE.to_owned();
    let mut observed_phase = MACHINE_PHASE_NONE.to_owned();
    for record in &chain {
        let verb = record["operation"]["operation"]
            .as_str()
            .unwrap_or_default();
        desired_phase = phase_after(verb, &desired_phase);
        let succeeded = record["operation_ref"]
            .as_str()
            .and_then(receipt_for)
            .is_some_and(|receipt| receipt["result"].as_str() == Some("succeeded"));
        if succeeded {
            observed_phase = phase_after(verb, &observed_phase);
        }
    }

    let project = |record: &Value| -> Value {
        let operation_ref = record["operation_ref"].as_str().unwrap_or_default();
        let receipt = receipt_for(operation_ref);
        json!({
            "operation_ref": operation_ref,
            "operation": record["operation"]["operation"],
            "desired_generation": record["operation"]["desired_generation"],
            "expected_head": record["operation"]["expected_head"],
            "state": record["state"],
            "admitted": record["admission"]["admitted"],
            "refusal_dimension": record["admission"]["refusal_dimension"],
            "refusal_reason": record["admission"]["refusal_reason"],
            "previous_head": record["previous_head"],
            "admitted_request_hash": record["admitted_request_hash"],
            "receipt_ref": record["receipt_ref"],
            "result": receipt.map(|r| r["result"].clone()).unwrap_or(Value::Null),
            "submitted_by": record["submitted_by"],
            "submitted_at": record["submitted_at"],
            "capability_declaration_ref": record["operation"]["capability_declaration_ref"],
            "capability_declaration_hash": record["operation"]["capability_declaration_hash"],
            "cleanup_obligation_ref": record["operation"]["cleanup_obligation_ref"],
        })
    };
    // Admitted records the walk did not reach — the two sides of a fork — are still operations the
    // daemon admitted, and a read model that dropped them would hide the fork it just reported.
    let chained: std::collections::HashSet<&str> = chain
        .iter()
        .filter_map(|record| record["operation_ref"].as_str())
        .collect();
    let mut unchained: Vec<&Value> = admitted
        .iter()
        .copied()
        .filter(|record| {
            !record["operation_ref"]
                .as_str()
                .is_some_and(|r| chained.contains(r))
        })
        .collect();
    unchained.sort_by_key(|record| {
        record["operation_ref"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    });
    let operations: Vec<Value> = chain
        .iter()
        .map(|record| project(record))
        .chain(unchained.iter().map(|record| project(record)))
        .chain(refused.iter().map(|record| project(record)))
        .collect();
    let operation_receipts: Vec<Value> = operations
        .iter()
        .filter_map(|operation| operation["operation_ref"].as_str().and_then(receipt_for))
        .cloned()
        .collect();
    let cleanup_obligation_refs: Vec<Value> = chain
        .iter()
        .filter_map(|record| {
            let value = &record["operation"]["cleanup_obligation_ref"];
            (!value.is_null()).then(|| value.clone())
        })
        .collect();

    let (head, head_error) = match observed_head_for(data_dir, workload_ref) {
        Ok(head) => (Value::String(head), Value::Null),
        Err(detail) => (Value::Null, Value::String(detail)),
    };
    let (desired_generation, observed_generation) = current_generations(data_dir, workload_ref);
    let bound = chain.last().copied();
    let declaration_ref = bound
        .and_then(|record| record["operation"]["capability_declaration_ref"].as_str())
        .unwrap_or_default()
        .to_owned();
    let declaration = if declaration_ref.is_empty() {
        None
    } else {
        resolve_capability_declaration(data_dir, &declaration_ref)
    };
    let workload_id = records
        .first()
        .and_then(|record| record["operation_ref"].as_str())
        .and_then(workload_id_of)
        .unwrap_or_default()
        .to_owned();
    Some(json!({
        "workload_ref": workload_ref,
        "workload_id": workload_id,
        "head": head,
        "head_error": head_error,
        "desired_generation": desired_generation,
        "observed_generation": observed_generation,
        "desired_phase": desired_phase,
        "observed_phase": observed_phase,
        "backend_registration_ref": bound.map(|r| r["operation"]["backend_registration_ref"].clone()).unwrap_or(Value::Null),
        "capability_declaration_ref": if declaration_ref.is_empty() { Value::Null } else { Value::String(declaration_ref.clone()) },
        "capability_declaration_hash": bound.map(|r| r["operation"]["capability_declaration_hash"].clone()).unwrap_or(Value::Null),
        "capability_declaration_resolves": declaration.is_some(),
        "evidence_mode": declaration.as_ref().map(|d| d["evidence_mode"].clone()).unwrap_or(Value::Null),
        "operation_count": operations.len(),
        "admitted_count": chain.len(),
        "refused_count": refused.len(),
        "receipt_count": operation_receipts.len(),
        "operations": operations,
        "receipts": operation_receipts,
        "cleanup_obligation_refs": cleanup_obligation_refs,
        "derived_from": {
            "operation_records": MACHINE_OPERATION_RECORDS,
            "receipt_records": MACHINE_RECEIPT_RECORDS,
            "declaration_records": MACHINE_CAPABILITY_RECORDS,
            "rule": "head = the admitted hash no successor cites; generations from succeeded receipts; phases folded over the admitted chain (observed moves only on a succeeded receipt)",
        },
    }))
}

/// The inventory: every workload the records name, each as its spine. Ordered by workload ref so
/// two clients reading it list the same machines in the same order.
pub(crate) fn machine_inventory(data_dir: &str) -> Vec<Value> {
    let mut workload_refs: Vec<String> = read_record_dir(data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .filter_map(|record| {
            record["operation"]["workload_ref"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    workload_refs.sort();
    workload_refs.dedup();
    workload_refs
        .iter()
        .filter_map(|workload_ref| machine_spine(data_dir, workload_ref))
        .collect()
}

/// GET /v1/hypervisor/machines — the inventory, derived on read.
pub(crate) async fn handle_machines_list(
    State(st): State<Arc<DaemonState>>,
) -> Result<Json<Value>, AppError> {
    let machines = machine_inventory(&st.data_dir);
    Ok(Json(json!({
        "ok": true,
        "count": machines.len(),
        "machines": machines,
    })))
}

/// GET /v1/hypervisor/machines/:workload — one workload's spine, or a typed 404. The path segment
/// is the path-safe id the operation refs carry; the record's own `workload_ref` is what it resolves
/// to, so the same machine reads back under the same identity from every client.
pub(crate) async fn handle_machine_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(workload_id): AxumPath<String>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let wanted = safe_id(&workload_id);
    let workload_ref = read_record_dir(&st.data_dir, MACHINE_OPERATION_RECORDS)
        .into_iter()
        .find(|record| {
            record["operation_ref"]
                .as_str()
                .and_then(workload_id_of)
                .is_some_and(|id| id == wanted)
        })
        .and_then(|record| {
            record["operation"]["workload_ref"]
                .as_str()
                .map(str::to_owned)
        });
    let Some(spine) = workload_ref.and_then(|r| machine_spine(&st.data_dir, &r)) else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "code": "machine_workload_unknown",
                "workload": workload_id,
            })),
        ));
    };
    Ok((
        StatusCode::OK,
        Json(json!({ "ok": true, "machine": spine })),
    ))
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
            observed_head_for(dir.to_str().unwrap(), "virtual-machine-workload://vm_a").unwrap(),
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
            observed_head_for(d, "virtual-machine-workload://vm_a").unwrap(),
            head_a
        );
        assert_eq!(
            observed_head_for(d, "virtual-machine-workload://vm_b").unwrap(),
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
    fn the_head_is_the_one_no_successor_cites_and_a_fork_refuses() {
        // THE DEFECT THIS TEST EXISTS FOR. The first cut took `.last()` over `read_record_dir`,
        // which iterates the directory with NO ORDERING — so the head was whichever record the
        // filesystem happened to return last, and a caller could be refused as stale for quoting
        // the head it had just been given. The conformance gate caught it on its first run.
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        let workload = "virtual-machine-workload://vm_a";
        let h1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let h2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        let mut first = admitted_record(workload, h1, "k1");
        first["previous_head"] = json!(MACHINE_GENESIS_HEAD);
        write(&dir, MACHINE_OPERATION_RECORDS, "a1", &first);
        let mut second = admitted_record(workload, h2, "k2");
        second["operation_ref"] = json!("machine-operation://hypervisor/vm_a/start/k2");
        second["previous_head"] = json!(h1);
        write(&dir, MACHINE_OPERATION_RECORDS, "a2", &second);

        // h1 IS cited by h2, so the head is h2 — whatever order the directory hands them back.
        assert_eq!(observed_head_for(d, workload).unwrap(), h2);

        // A FORK: a third admitted operation citing the same predecessor as h2.
        let h3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let mut branch = admitted_record(workload, h3, "k3");
        branch["operation_ref"] = json!("machine-operation://hypervisor/vm_a/start/k3");
        branch["previous_head"] = json!(h1);
        write(&dir, MACHINE_OPERATION_RECORDS, "a3", &branch);
        let error = observed_head_for(d, workload).expect_err("two uncited heads is a fork");
        assert!(error.contains("fork"), "{error}");
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
        // ON THE CHAIN: generations are read along the admitted chain (M08.15), so the record
        // names the head it advanced from, as every record the daemon writes does.
        record["previous_head"] = json!(MACHINE_GENESIS_HEAD);
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

    fn chained_record(workload: &str, verb: &str, previous: &str, hash: &str, key: &str) -> Value {
        let mut record = admitted_record(workload, hash, key);
        record["operation_ref"] =
            json!(format!("machine-operation://hypervisor/vm_r/{verb}/{key}"));
        record["operation"]["operation"] = json!(verb);
        record["operation"]["desired_generation"] = json!(1);
        record["operation"]["capability_declaration_ref"] = json!("capability://backend/ref/1");
        record["operation"]["capability_declaration_hash"] =
            json!(format!("sha256:{}", "a".repeat(64)));
        record["previous_head"] = json!(previous);
        record["submitted_by"] = json!("user://p_1");
        record["submitted_at"] = json!("2026-09-20T00:00:00Z");
        record
    }

    fn succeeded_receipt(operation_ref: &str, id: &str, generation: u64) -> Value {
        json!({
            "receipt_ref": format!("machine-operation-receipt://hypervisor/{id}"),
            "operation_ref": operation_ref,
            "result": "succeeded",
            "result_reason": Value::Null,
            "desired_generation_before": generation - 1, "desired_generation_after": generation,
            "observed_generation_before": generation - 1, "observed_generation_after": generation,
        })
    }

    #[test]
    fn the_spine_is_derived_from_the_records_in_chain_order_and_unknown_is_not_empty() {
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        let workload = "virtual-machine-workload://vm_r";
        let genesis = MACHINE_GENESIS_HEAD;
        let h1 = format!("sha256:{}", "1".repeat(64));
        let h2 = format!("sha256:{}", "2".repeat(64));
        // Written OUT of chain order on purpose: the read model must order by the chain, not by
        // the directory.
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "k2",
            &chained_record(workload, "start", &h1, &h2, "k2"),
        );
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "k1",
            &chained_record(workload, "create", genesis, &h1, "k1"),
        );
        // A refused proposal sits on no chain and reads back after the chain.
        let mut refused = chained_record(workload, "stop", &h2, "", "k3");
        refused["admission"] = json!({ "admitted": false, "refusal_dimension": "expected_head_stale", "refusal_reason": "stale" });
        refused["state"] = json!("refused");
        refused["receipt_ref"] = json!("machine-operation-receipt://hypervisor/k3");
        write(&dir, MACHINE_OPERATION_RECORDS, "k3", &refused);
        // Only the CREATE succeeded; the START is admitted and awaiting effect (no receipt).
        write(
            &dir,
            MACHINE_RECEIPT_RECORDS,
            "k1",
            &succeeded_receipt("machine-operation://hypervisor/vm_r/create/k1", "k1", 1),
        );

        let spine = machine_spine(d, workload).expect("the workload is recorded");
        assert_eq!(
            spine["head"],
            json!(h2),
            "the head is the admitted hash no successor cites"
        );
        assert_eq!(
            spine["desired_phase"],
            json!("running"),
            "desired folds over the ADMITTED chain"
        );
        assert_eq!(
            spine["observed_phase"],
            json!("defined"),
            "observed moves only on a SUCCEEDED receipt"
        );
        assert_eq!(
            (
                spine["desired_generation"].as_u64(),
                spine["observed_generation"].as_u64()
            ),
            (Some(1), Some(1))
        );
        let verbs: Vec<&str> = spine["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["operation"].as_str().unwrap())
            .collect();
        assert_eq!(
            verbs,
            vec!["create", "start", "stop"],
            "chain order, then the refused proposal"
        );
        assert_eq!(
            spine["operations"][2]["refusal_dimension"],
            json!("expected_head_stale")
        );
        assert_eq!(
            spine["operations"][0]["submitted_by"],
            json!("user://p_1"),
            "who, as recorded"
        );
        assert_eq!(spine["receipt_count"], json!(1));
        assert_eq!(
            spine["capability_declaration_ref"],
            json!("capability://backend/ref/1")
        );
        assert_eq!(
            spine["capability_declaration_resolves"],
            json!(false),
            "no declaration record was written here"
        );
        assert_eq!(spine["workload_id"], json!("vm_r"));
        assert!(
            machine_spine(d, "virtual-machine-workload://vm_nobody").is_none(),
            "unknown, not empty"
        );
        let inventory = machine_inventory(d);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0]["workload_ref"], json!(workload));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generations_follow_the_chain_not_the_directory_order() {
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        let workload = "virtual-machine-workload://vm_r";
        let h1 = format!("sha256:{}", "1".repeat(64));
        let h2 = format!("sha256:{}", "2".repeat(64));
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "a-first",
            &chained_record(workload, "create", MACHINE_GENESIS_HEAD, &h1, "a-first"),
        );
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "b-second",
            &chained_record(workload, "start", &h1, &h2, "b-second"),
        );
        // The receipt for the SECOND operation is written under a name that sorts FIRST, and the
        // first operation's receipt under a name that sorts last: a directory-order derivation
        // reads generation 1, the chain reads generation 2.
        write(
            &dir,
            MACHINE_RECEIPT_RECORDS,
            "0-start",
            &succeeded_receipt(
                "machine-operation://hypervisor/vm_r/start/b-second",
                "0-start",
                2,
            ),
        );
        write(
            &dir,
            MACHINE_RECEIPT_RECORDS,
            "z-create",
            &succeeded_receipt(
                "machine-operation://hypervisor/vm_r/create/a-first",
                "z-create",
                1,
            ),
        );
        assert_eq!(current_generations(d, workload), (2, 2));
        let spine = machine_spine(d, workload).expect("recorded");
        assert_eq!(spine["observed_generation"], json!(2));
        assert_eq!(spine["observed_phase"], json!("running"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fork_reads_back_as_no_head_with_the_reason_never_as_one_of_the_two() {
        let dir = temp_dir();
        let d = dir.to_str().unwrap();
        let workload = "virtual-machine-workload://vm_r";
        let ha = format!("sha256:{}", "a".repeat(64));
        let hb = format!("sha256:{}", "b".repeat(64));
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "ka",
            &chained_record(workload, "create", MACHINE_GENESIS_HEAD, &ha, "ka"),
        );
        write(
            &dir,
            MACHINE_OPERATION_RECORDS,
            "kb",
            &chained_record(workload, "create", MACHINE_GENESIS_HEAD, &hb, "kb"),
        );
        let spine = machine_spine(d, workload).expect("recorded");
        assert!(spine["head"].is_null());
        assert!(spine["head_error"].as_str().unwrap().contains("fork"));
        assert_eq!(
            spine["admitted_count"],
            json!(0),
            "a forked chain has no walkable head — nothing is on the chain"
        );
        assert_eq!(
            spine["operation_count"],
            json!(2),
            "both admitted sides of the fork are still listed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn phases_move_only_on_the_verbs_that_set_them() {
        assert_eq!(phase_after("create", MACHINE_PHASE_NONE), "defined");
        assert_eq!(phase_after("start", "defined"), "running");
        assert_eq!(
            phase_after("snapshot", "running"),
            "running",
            "a snapshot leaves the phase alone"
        );
        assert_eq!(
            phase_after("migrate", "running"),
            "running",
            "so does an ambiguous migration"
        );
        assert_eq!(phase_after("stop", "running"), "stopped");
        assert_eq!(phase_after("delete", "stopped"), "deleted");
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
