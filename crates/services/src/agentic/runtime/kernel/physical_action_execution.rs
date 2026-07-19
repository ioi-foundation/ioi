//! Reference physical-action execution choke point and receipt chain.
//!
//! This module deliberately stops short of claiming a mounted native controller path. It proves
//! the final shape: exact command bytes are hash-bound into a fresh physical-action admission,
//! the admitted record is passed directly to one typed controller invoker, same-body retries are
//! replayed without reinvocation, and the normalized effect becomes a tamper-evident chained
//! receipt. Production adapters must preserve this ordering and persist the idempotency/receipt
//! ledger in Agentgres or the physical-runtime owner before CPAS-9/10 can be claimed estate-wide.

use super::runtime_physical_action_intent_admission::RuntimePhysicalActionIntentAdmissionCore;
use ioi_types::app::generated::architecture_contracts::ReceiptEnvelopeV1;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const PHYSICAL_ACTION_EXECUTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.physical-action-execution-request.v1";
pub const PHYSICAL_ACTION_EXECUTION_RECEIPT_SCHEMA_VERSION: &str =
    "ioi.physical-action-execution-receipt.v1";
pub const PHYSICAL_ACTION_EXECUTION_RECEIPT_PROFILE_REF: &str =
    "schema://ioi/foundations/physical-action-execution-receipt/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalActionExecutionRequest {
    pub schema_version: String,
    pub idempotency_key: String,
    pub admission_request: Value,
    pub command_payload: Value,
    pub expected_command_payload_hash: String,
    pub state_root_before: String,
    #[serde(default)]
    pub previous_execution_receipt_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PhysicalResourceGroupBinding {
    pub group_revision_ref: String,
    pub membership_closure_hash: String,
    pub unit_refs: Vec<String>,
    pub controller_binding_refs: Vec<String>,
    pub sensor_refs: Vec<String>,
    pub actuator_refs: Vec<String>,
    pub physical_zone_refs: Vec<String>,
    pub emergency_stop_authority_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalWorkSubjectBinding {
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalControllerInvocation {
    pub idempotency_key: String,
    pub intent_id: String,
    pub actor_id: String,
    pub task_id: Option<String>,
    pub authority_ref: String,
    pub requested_primitives: Vec<String>,
    pub requested_scopes: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub physical_action_policy_ref: String,
    pub target_system_ref: String,
    pub resource_group_bindings: Vec<PhysicalResourceGroupBinding>,
    pub emergency_stop_authority_ref: String,
    pub controller_binding_ref: String,
    pub command_schema_ref: String,
    pub command_payload: Value,
    pub command_payload_hash: String,
    pub runtime_graph_manifest_ref: String,
    pub runtime_graph_manifest_hash: String,
    pub safety_envelope_ref: String,
    pub safety_envelope_hash: String,
    pub assurance_evidence_bundle_ref: String,
    pub assurance_evidence_bundle_hash: String,
    pub active_writer_lease_ref: String,
    pub active_writer_fencing_epoch: u64,
    pub active_writer_fencing_token_hash: String,
    pub graph_timing_chain_ref: String,
    pub graph_timing_chain_hash: String,
    pub state_root_before: String,
    pub preflight_receipt_refs: Vec<String>,
    pub sensor_evidence_receipt_refs: Vec<String>,
    pub segment_commitment_receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalControllerEffectStatus {
    Committed,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalControllerDispatchPosture {
    NotDispatchedProven,
    DispatchedObserved,
    DispatchAmbiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalControllerOutcome {
    pub effect_status: PhysicalControllerEffectStatus,
    pub dispatch_posture: PhysicalControllerDispatchPosture,
    pub controller_operation_ref: String,
    #[serde(default)]
    pub dispatch_evidence_receipt_refs: Vec<String>,
    #[serde(default)]
    pub controller_receipt_refs: Vec<String>,
    #[serde(default)]
    pub state_root_after: Option<String>,
}

pub trait PhysicalControllerInvoker {
    /// Return the exact controller binding represented by this adapter instance. This is a typed
    /// reference-identity check, not cryptographic hardware identity proof.
    fn controller_binding_ref(&self) -> &str;

    /// Invoke one already-admitted command. Implementations must propagate the supplied
    /// idempotency key to their effect boundary and report dispatch posture plus evidence. The
    /// reference core never blindly retries an interrupted in-flight invocation.
    fn invoke(&mut self, invocation: &PhysicalControllerInvocation) -> PhysicalControllerOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalActionExecutionReceiptBody {
    pub idempotency_key: String,
    pub execution_request_hash: String,
    pub admission_id: String,
    pub admission_record_hash: String,
    pub work_subject: PhysicalWorkSubjectBinding,
    pub target_system_ref: String,
    pub resource_group_bindings: Vec<PhysicalResourceGroupBinding>,
    pub emergency_stop_authority_ref: String,
    pub controller_binding_ref: String,
    pub runtime_graph_manifest_ref: String,
    pub runtime_graph_manifest_hash: String,
    pub safety_envelope_ref: String,
    pub safety_envelope_hash: String,
    pub assurance_evidence_bundle_ref: String,
    pub assurance_evidence_bundle_hash: String,
    pub active_writer_lease_ref: String,
    pub active_writer_fencing_epoch: u64,
    pub active_writer_fencing_token_hash: String,
    pub graph_timing_chain_ref: String,
    pub graph_timing_chain_hash: String,
    pub command_schema_ref: String,
    pub command_payload_hash: String,
    pub preflight_receipt_refs: Vec<String>,
    pub sensor_evidence_receipt_refs: Vec<String>,
    pub segment_commitment_receipt_refs: Vec<String>,
    pub controller_operation_ref: String,
    pub dispatch_posture: PhysicalControllerDispatchPosture,
    pub dispatch_evidence_receipt_refs: Vec<String>,
    pub controller_receipt_refs: Vec<String>,
    pub outcome_normalization_error_codes: Vec<String>,
    pub effect_status: PhysicalControllerEffectStatus,
    pub state_root_before: String,
    pub state_root_after: Option<String>,
    pub previous_execution_receipt_hash: Option<String>,
    pub executed_at: String,
    pub incident_refs: Vec<String>,
    pub reconciliation_state: String,
    pub agentgres_operation_refs: Vec<String>,
    pub assurance_stage: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalActionExecutionReceiptBundle {
    pub schema_version: String,
    pub receipt_envelope: ReceiptEnvelopeV1,
    pub body: PhysicalActionExecutionReceiptBody,
    pub body_hash: String,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalActionExecutionResult {
    pub receipt: PhysicalActionExecutionReceiptBundle,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalActionExecutionError {
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl PhysicalActionExecutionError {
    fn new(code: impl Into<String>, message: impl Into<String>, details: Value) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StoredExecution {
    Prepared {
        request_hash: String,
        prepared_at: String,
    },
    Completed {
        request_hash: String,
        result: PhysicalActionExecutionResult,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalActionExecutionCore {
    executions: BTreeMap<String, StoredExecution>,
    chain_head: Option<String>,
}

impl PhysicalActionExecutionCore {
    pub fn chain_head(&self) -> Option<&str> {
        self.chain_head.as_deref()
    }

    pub fn execute<I: PhysicalControllerInvoker>(
        &mut self,
        request: &PhysicalActionExecutionRequest,
        now_iso: &str,
        invoker: &mut I,
    ) -> Result<PhysicalActionExecutionResult, PhysicalActionExecutionError> {
        require_nonempty(&request.idempotency_key, "idempotency_key")?;
        require_rfc3339(now_iso, "executed_at")?;
        let request_hash = jcs_hash(request)?;

        if let Some(stored) = self.executions.get(&request.idempotency_key) {
            let stored_request_hash = match stored {
                StoredExecution::Prepared { request_hash, .. }
                | StoredExecution::Completed { request_hash, .. } => request_hash,
            };
            if stored_request_hash != &request_hash {
                return Err(PhysicalActionExecutionError::new(
                    "physical_action_execution_idempotency_conflict",
                    "The idempotency key was already admitted with a different execution body.",
                    json!({
                        "idempotency_key": request.idempotency_key,
                        "stored_request_hash": stored_request_hash,
                        "received_request_hash": request_hash,
                    }),
                ));
            }
            return match stored {
                StoredExecution::Prepared { prepared_at, .. } => {
                    Err(PhysicalActionExecutionError::new(
                        "physical_action_execution_reconciliation_required",
                        "The same physical action was prepared and may have crossed the controller boundary; blind retry is forbidden until reconciled.",
                        json!({
                            "idempotency_key": request.idempotency_key,
                            "request_hash": request_hash,
                            "prepared_at": prepared_at,
                        }),
                    ))
                }
                StoredExecution::Completed { result, .. } => {
                    let mut replay = result.clone();
                    replay.replayed = true;
                    Ok(replay)
                }
            };
        }

        if let Some((prepared_key, StoredExecution::Prepared { prepared_at, .. })) = self
            .executions
            .iter()
            .find(|(_, execution)| matches!(execution, StoredExecution::Prepared { .. }))
        {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_chain_reconciliation_required",
                "A prior physical invocation may have crossed the effect boundary; the receipt chain is frozen until reconciliation.",
                json!({
                    "prepared_idempotency_key": prepared_key,
                    "prepared_at": prepared_at,
                }),
            ));
        }

        if request.schema_version != PHYSICAL_ACTION_EXECUTION_REQUEST_SCHEMA_VERSION {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_schema_unsupported",
                "The physical execution request schema is not supported.",
                json!({
                    "expected": PHYSICAL_ACTION_EXECUTION_REQUEST_SCHEMA_VERSION,
                    "received": request.schema_version,
                }),
            ));
        }
        require_nonempty(&request.state_root_before, "state_root_before")?;
        let admitted_state_root =
            required_path_string(&request.admission_request, &["state_root"])?;
        if admitted_state_root != request.state_root_before {
            return Err(binding_mismatch(
                "state_root_before",
                &request.state_root_before,
                &admitted_state_root,
            ));
        }
        require_hash(
            &request.expected_command_payload_hash,
            "expected_command_payload_hash",
        )?;
        if let Some(previous) = &request.previous_execution_receipt_hash {
            require_hash(previous, "previous_execution_receipt_hash")?;
        }
        if request.previous_execution_receipt_hash.as_deref() != self.chain_head.as_deref() {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_receipt_head_conflict",
                "A new physical execution must extend the exact current receipt-chain head.",
                json!({
                    "expected_previous_execution_receipt_hash": self.chain_head,
                    "received_previous_execution_receipt_hash": request.previous_execution_receipt_hash,
                }),
            ));
        }

        let computed_command_hash = jcs_hash(&request.command_payload)?;
        if computed_command_hash != request.expected_command_payload_hash {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_command_hash_mismatch",
                "The command payload does not match its declared canonical SHA-256 hash.",
                json!({
                    "expected_command_payload_hash": request.expected_command_payload_hash,
                    "computed_command_payload_hash": computed_command_hash,
                }),
            ));
        }

        let bound_command_hash =
            required_path_string(&request.admission_request, &["command_payload_hash"])?;
        if bound_command_hash != computed_command_hash {
            return Err(binding_mismatch(
                "command_payload_hash",
                &computed_command_hash,
                &bound_command_hash,
            ));
        }
        let bound_idempotency_key =
            required_path_string(&request.admission_request, &["controller_idempotency_key"])?;
        if bound_idempotency_key != request.idempotency_key {
            return Err(binding_mismatch(
                "controller_idempotency_key",
                &request.idempotency_key,
                &bound_idempotency_key,
            ));
        }
        let execution_phase =
            required_path_string(&request.admission_request, &["execution_phase"])?;
        if execution_phase != "preflight_verified" {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_preflight_phase_required",
                "The final invoker choke point accepts only a freshly preflight-verified intent.",
                json!({ "received_execution_phase": execution_phase }),
            ));
        }

        // The planner call is the final admission gate. Only pure extraction and construction of
        // the typed invocation occur between this decision and the one controller call below.
        let mut fresh_admission_request = request.admission_request.clone();
        fresh_admission_request["admitted_at"] = Value::String(now_iso.to_string());
        let admission = RuntimePhysicalActionIntentAdmissionCore
            .admit(&fresh_admission_request, now_iso)
            .map_err(|error| {
                PhysicalActionExecutionError::new(error.code, error.message, error.details)
            })?;

        if admission.get("decision").and_then(Value::as_str) != Some("admitted")
            || admission
                .get("live_physical_execution")
                .and_then(Value::as_bool)
                != Some(true)
            || admission.get("simulation_only").and_then(Value::as_bool) != Some(false)
        {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_final_admission_invalid",
                "The final physical-action admission did not authorize live execution.",
                json!({}),
            ));
        }

        let invocation =
            invocation_from_admission(&admission, request, computed_command_hash.clone())?;
        if invoker.controller_binding_ref() != invocation.controller_binding_ref {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_controller_binding_mismatch",
                "The selected controller adapter does not represent the controller binding admitted for this action.",
                json!({
                    "admitted_controller_binding_ref": invocation.controller_binding_ref,
                    "invoker_controller_binding_ref": invoker.controller_binding_ref(),
                }),
            ));
        }
        self.executions.insert(
            request.idempotency_key.clone(),
            StoredExecution::Prepared {
                request_hash: request_hash.clone(),
                prepared_at: now_iso.to_string(),
            },
        );
        let (outcome, outcome_normalization_error_codes) =
            normalize_outcome(invoker.invoke(&invocation), &request.idempotency_key);

        let admission_record_hash = jcs_hash(&admission)?;
        let effect_status = outcome.effect_status;
        let receipt_id = format!(
            "receipt://physical-action/execution/{}",
            request_hash.trim_start_matches("sha256:")
        );
        let body = PhysicalActionExecutionReceiptBody {
            idempotency_key: request.idempotency_key.clone(),
            execution_request_hash: request_hash.clone(),
            admission_id: required_path_string(&admission, &["admission_id"])?,
            admission_record_hash: admission_record_hash.clone(),
            work_subject: PhysicalWorkSubjectBinding {
                kind: "physical_action_intent".to_string(),
                reference: required_path_string(&admission, &["intent_id"])?,
            },
            target_system_ref: invocation.target_system_ref.clone(),
            resource_group_bindings: invocation.resource_group_bindings.clone(),
            emergency_stop_authority_ref: invocation.emergency_stop_authority_ref.clone(),
            controller_binding_ref: invocation.controller_binding_ref.clone(),
            runtime_graph_manifest_ref: invocation.runtime_graph_manifest_ref.clone(),
            runtime_graph_manifest_hash: invocation.runtime_graph_manifest_hash.clone(),
            safety_envelope_ref: invocation.safety_envelope_ref.clone(),
            safety_envelope_hash: invocation.safety_envelope_hash.clone(),
            assurance_evidence_bundle_ref: invocation.assurance_evidence_bundle_ref.clone(),
            assurance_evidence_bundle_hash: invocation.assurance_evidence_bundle_hash.clone(),
            active_writer_lease_ref: invocation.active_writer_lease_ref.clone(),
            active_writer_fencing_epoch: invocation.active_writer_fencing_epoch,
            active_writer_fencing_token_hash: invocation.active_writer_fencing_token_hash.clone(),
            graph_timing_chain_ref: invocation.graph_timing_chain_ref.clone(),
            graph_timing_chain_hash: invocation.graph_timing_chain_hash.clone(),
            command_schema_ref: invocation.command_schema_ref.clone(),
            command_payload_hash: invocation.command_payload_hash.clone(),
            preflight_receipt_refs: invocation.preflight_receipt_refs.clone(),
            sensor_evidence_receipt_refs: invocation.sensor_evidence_receipt_refs.clone(),
            segment_commitment_receipt_refs: invocation.segment_commitment_receipt_refs.clone(),
            controller_operation_ref: outcome.controller_operation_ref.clone(),
            dispatch_posture: outcome.dispatch_posture,
            dispatch_evidence_receipt_refs: outcome.dispatch_evidence_receipt_refs.clone(),
            controller_receipt_refs: outcome.controller_receipt_refs.clone(),
            outcome_normalization_error_codes,
            effect_status,
            state_root_before: invocation.state_root_before.clone(),
            state_root_after: outcome.state_root_after.clone(),
            previous_execution_receipt_hash: request.previous_execution_receipt_hash.clone(),
            executed_at: now_iso.to_string(),
            incident_refs: Vec::new(),
            reconciliation_state: match effect_status {
                PhysicalControllerEffectStatus::Committed => "confirmed",
                PhysicalControllerEffectStatus::Rejected => "failed",
                PhysicalControllerEffectStatus::Unknown => "ambiguous_effect",
            }
            .to_string(),
            agentgres_operation_refs: Vec::new(),
            assurance_stage: "attested".to_string(),
        };
        let physical_body_hash = jcs_hash(&body)?;
        let receipt_envelope = build_receipt_envelope(
            &receipt_id,
            &invocation,
            &body,
            &request_hash,
            &physical_body_hash,
            &admission_record_hash,
            now_iso,
        );
        let body_hash = physical_receipt_body_hash(&receipt_envelope, &body)?;
        let receipt_hash = physical_receipt_bundle_hash(&receipt_envelope, &body)?;
        let receipt = PhysicalActionExecutionReceiptBundle {
            schema_version: PHYSICAL_ACTION_EXECUTION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_envelope,
            body,
            body_hash,
            receipt_hash: receipt_hash.clone(),
        };
        verify_physical_action_execution_receipt(
            &receipt,
            request.previous_execution_receipt_hash.as_deref(),
        )?;

        let result = PhysicalActionExecutionResult {
            receipt,
            replayed: false,
        };
        self.executions.insert(
            request.idempotency_key.clone(),
            StoredExecution::Completed {
                request_hash,
                result: result.clone(),
            },
        );
        self.chain_head = Some(receipt_hash);
        Ok(result)
    }
}

pub fn verify_physical_action_execution_receipt(
    receipt: &PhysicalActionExecutionReceiptBundle,
    expected_previous_receipt_hash: Option<&str>,
) -> Result<(), PhysicalActionExecutionError> {
    if receipt.schema_version != PHYSICAL_ACTION_EXECUTION_RECEIPT_SCHEMA_VERSION {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_schema_unsupported",
            "The physical execution receipt schema is not supported.",
            json!({ "received": receipt.schema_version }),
        ));
    }
    let body = &receipt.body;
    let envelope = &receipt.receipt_envelope;
    let expected_receipt_id = format!(
        "receipt://physical-action/execution/{}",
        body.execution_request_hash.trim_start_matches("sha256:")
    );
    let physical_body_hash = jcs_hash(body)?;
    if body.work_subject.kind != "physical_action_intent"
        || !body.work_subject.reference.starts_with("intent://")
        || envelope.receipt_id != expected_receipt_id
        || envelope.receipt_type != "physical_action_execution"
        || envelope.receipt_profile_ref != PHYSICAL_ACTION_EXECUTION_RECEIPT_PROFILE_REF
        || envelope.input_hash.as_deref() != Some(body.execution_request_hash.as_str())
        || envelope.output_hash.as_deref() != Some(physical_body_hash.as_str())
        || envelope.policy_hash.as_deref() != Some(body.safety_envelope_hash.as_str())
        || envelope.primitive_capabilities.is_empty()
        || envelope.authority_scopes.is_empty()
        || envelope.evidence_bundle_refs.is_empty()
    {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_identity_invalid",
            "The base ReceiptEnvelope and physical-action body are not exactly cross-bound.",
            json!({}),
        ));
    }
    if !is_canonical_protocol_principal(&envelope.actor_id)
        || envelope.attested_boundary_fact_refs.is_empty()
    {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_envelope_invalid",
            "The closed base ReceiptEnvelope has an invalid actor or no attested boundary facts.",
            json!({ "actor_id": envelope.actor_id }),
        ));
    }
    let profile_target_present = body.resource_group_bindings.iter().any(|binding| {
        binding.unit_refs.contains(&body.target_system_ref)
            || binding.actuator_refs.contains(&body.target_system_ref)
    });
    let profile_controller_present = body.resource_group_bindings.iter().any(|binding| {
        binding
            .controller_binding_refs
            .contains(&body.controller_binding_ref)
    });
    let profile_emergency_stop_present = body.resource_group_bindings.iter().any(|binding| {
        binding
            .emergency_stop_authority_refs
            .contains(&body.emergency_stop_authority_ref)
    });
    if !(profile_target_present && profile_controller_present && profile_emergency_stop_present) {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_resource_closure_invalid",
            "The receipt profile does not preserve the exact expanded physical resource closure.",
            json!({}),
        ));
    }
    let expected_reconciliation = match body.effect_status {
        PhysicalControllerEffectStatus::Committed => "confirmed",
        PhysicalControllerEffectStatus::Rejected => "failed",
        PhysicalControllerEffectStatus::Unknown => "ambiguous_effect",
    };
    if body.reconciliation_state != expected_reconciliation {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_reconciliation_invalid",
            "The reconciliation state widens or contradicts the normalized controller effect.",
            json!({
                "effect_status": body.effect_status,
                "expected_reconciliation_state": expected_reconciliation,
                "received_reconciliation_state": body.reconciliation_state,
            }),
        ));
    }
    let dispatch_consistent = match body.effect_status {
        PhysicalControllerEffectStatus::Committed => {
            body.dispatch_posture == PhysicalControllerDispatchPosture::DispatchedObserved
                && !body.dispatch_evidence_receipt_refs.is_empty()
                && !body.controller_receipt_refs.is_empty()
                && body
                    .state_root_after
                    .as_deref()
                    .is_some_and(|root| !root.trim().is_empty())
                && body.outcome_normalization_error_codes.is_empty()
        }
        PhysicalControllerEffectStatus::Rejected => {
            body.dispatch_posture == PhysicalControllerDispatchPosture::NotDispatchedProven
                && !body.dispatch_evidence_receipt_refs.is_empty()
                && body.state_root_after.is_none()
                && body.outcome_normalization_error_codes.is_empty()
        }
        PhysicalControllerEffectStatus::Unknown => true,
    };
    if !dispatch_consistent {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_dispatch_inconsistent",
            "The claimed physical effect is not supported by the required dispatch posture and evidence.",
            json!({ "effect_status": body.effect_status, "dispatch_posture": body.dispatch_posture }),
        ));
    }
    if body.previous_execution_receipt_hash.as_deref() != expected_previous_receipt_hash {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_predecessor_mismatch",
            "The receipt does not extend the expected physical execution chain head.",
            json!({
                "expected": expected_previous_receipt_hash,
                "received": body.previous_execution_receipt_hash,
            }),
        ));
    }
    let computed_body_hash = physical_receipt_body_hash(envelope, body)?;
    if computed_body_hash != receipt.body_hash {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_body_hash_mismatch",
            "The canonical ReceiptEnvelope and physical body bundle hash is invalid.",
            json!({ "expected": receipt.body_hash, "computed": computed_body_hash }),
        ));
    }
    let computed_receipt_hash = physical_receipt_bundle_hash(envelope, body)?;
    if computed_receipt_hash != receipt.receipt_hash {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_hash_mismatch",
            "The physical execution receipt domain-separated hash is invalid.",
            json!({ "expected": receipt.receipt_hash, "computed": computed_receipt_hash }),
        ));
    }
    let receipt_value = serde_json::to_value(receipt).map_err(hash_error)?;
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        PHYSICAL_ACTION_EXECUTION_RECEIPT_PROFILE_REF,
        &receipt_value,
    )
    .map_err(|error| {
        PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_contract_invalid",
            "The physical execution receipt does not satisfy its registered machine contract.",
            json!({ "error": error }),
        )
    })?;
    Ok(())
}

fn build_receipt_envelope(
    receipt_id: &str,
    invocation: &PhysicalControllerInvocation,
    body: &PhysicalActionExecutionReceiptBody,
    request_hash: &str,
    physical_body_hash: &str,
    admission_record_hash: &str,
    now_iso: &str,
) -> ReceiptEnvelopeV1 {
    let mut facts = BTreeSet::new();
    facts.insert(body.admission_id.clone());
    facts.insert(body.controller_binding_ref.clone());
    facts.insert(body.runtime_graph_manifest_ref.clone());
    facts.insert(body.safety_envelope_ref.clone());
    facts.insert(body.active_writer_lease_ref.clone());
    for binding in &body.resource_group_bindings {
        facts.insert(binding.group_revision_ref.clone());
    }
    facts.extend(body.preflight_receipt_refs.iter().cloned());
    facts.extend(body.sensor_evidence_receipt_refs.iter().cloned());
    facts.extend(body.dispatch_evidence_receipt_refs.iter().cloned());
    facts.extend(body.controller_receipt_refs.iter().cloned());

    ReceiptEnvelopeV1 {
        receipt_id: receipt_id.to_string(),
        receipt_type: "physical_action_execution".to_string(),
        receipt_profile_ref: PHYSICAL_ACTION_EXECUTION_RECEIPT_PROFILE_REF.to_string(),
        attested_boundary_fact_refs: facts.into_iter().collect(),
        claim_scope_ref: Some(invocation.physical_action_policy_ref.clone()),
        run_id: None,
        task_id: invocation.task_id.clone(),
        actor_id: invocation.actor_id.clone(),
        input_hash: Some(request_hash.to_string()),
        output_hash: Some(physical_body_hash.to_string()),
        policy_hash: Some(body.safety_envelope_hash.clone()),
        authority_grant_id: invocation
            .authority_ref
            .starts_with("grant://")
            .then(|| invocation.authority_ref.clone()),
        primitive_capabilities: invocation.requested_primitives.clone(),
        authority_scopes: invocation.requested_scopes.clone(),
        artifact_refs: invocation.artifact_refs.clone(),
        evidence_bundle_refs: vec![format!(
            "evidence://physical-action/admission/{}",
            admission_record_hash.trim_start_matches("sha256:")
        )],
        verification_ref: None,
        acceptance_ref: None,
        adjudication_ref: None,
        settlement_ref: None,
        timestamp: now_iso.to_string(),
        signature: None,
        public_commitment_ref: None,
    }
}

fn physical_receipt_body_hash(
    envelope: &ReceiptEnvelopeV1,
    body: &PhysicalActionExecutionReceiptBody,
) -> Result<String, PhysicalActionExecutionError> {
    jcs_hash(&json!({
        "receipt_envelope": envelope,
        "body": body,
    }))
}

fn physical_receipt_bundle_hash(
    envelope: &ReceiptEnvelopeV1,
    body: &PhysicalActionExecutionReceiptBody,
) -> Result<String, PhysicalActionExecutionError> {
    let material = json!({
        "receipt_envelope": envelope,
        "body": body,
    });
    Ok(domain_hash(
        PHYSICAL_ACTION_EXECUTION_RECEIPT_SCHEMA_VERSION,
        &serde_jcs::to_vec(&material).map_err(hash_error)?,
    ))
}

fn is_canonical_protocol_principal(value: &str) -> bool {
    [
        "system://",
        "user://",
        "wallet://",
        "org://",
        "project://",
        "domain://",
        "worker://",
        "agent://",
        "service://",
        "provider://",
        "policy://",
        "governance://",
        "runtime://",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn invocation_from_admission(
    admission: &Value,
    request: &PhysicalActionExecutionRequest,
    command_payload_hash: String,
) -> Result<PhysicalControllerInvocation, PhysicalActionExecutionError> {
    let resource_group_bindings =
        required_resource_group_bindings(admission, &["resource_group_bindings"])?;
    let preflight_receipt_refs =
        required_receipt_ref_array(admission, &["preflight_receipt_refs"], true)?;
    let sensor_evidence_receipt_refs =
        required_receipt_ref_array(admission, &["sensor_evidence_receipt_refs"], true)?;
    let segment_commitment_receipt_refs =
        required_receipt_ref_array(admission, &["segment_commitment_receipt_refs"], false)?;
    let actor_id = required_path_string(admission, &["actor_id"])?;
    if !is_canonical_protocol_principal(&actor_id) {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_actor_ref_invalid",
            "Physical execution receipts require a canonical protocol principal using a :// reference.",
            json!({ "actor_id": actor_id }),
        ));
    }
    let requested_primitives =
        required_prefixed_ref_array(admission, &["requested_primitives"], &["prim:"], true)?;
    let requested_scopes =
        required_prefixed_ref_array(admission, &["requested_scopes"], &["scope:"], true)?;
    let artifact_refs =
        required_prefixed_ref_array(admission, &["artifact_refs"], &["artifact://"], false)?;
    let active_writer_fencing_epoch = required_path_u64(
        admission,
        &[
            "deployment_assurance",
            "writer_and_restart_assurance",
            "active_writer_fencing_epoch",
        ],
    )?;
    let invocation = PhysicalControllerInvocation {
        idempotency_key: request.idempotency_key.clone(),
        intent_id: required_path_string(admission, &["intent_id"])?,
        actor_id,
        task_id: optional_path_string(admission, &["task_id"])?,
        authority_ref: required_path_string(admission, &["authority_ref"])?,
        requested_primitives,
        requested_scopes,
        artifact_refs,
        physical_action_policy_ref: required_path_string(
            admission,
            &["physical_action_policy_ref"],
        )?,
        target_system_ref: required_path_string(admission, &["target_system_ref"])?,
        resource_group_bindings,
        emergency_stop_authority_ref: required_path_string(
            admission,
            &["emergency_stop_authority_ref"],
        )?,
        controller_binding_ref: required_path_string(admission, &["controller_binding_ref"])?,
        command_schema_ref: required_path_string(admission, &["command_schema_ref"])?,
        command_payload: request.command_payload.clone(),
        command_payload_hash,
        runtime_graph_manifest_ref: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "deployment_binding",
                "runtime_graph_manifest_ref",
            ],
        )?,
        runtime_graph_manifest_hash: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "deployment_binding",
                "runtime_graph_manifest_hash",
            ],
        )?,
        safety_envelope_ref: required_path_string(admission, &["safety_envelope_ref"])?,
        safety_envelope_hash: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "deployment_binding",
                "safety_envelope_hash",
            ],
        )?,
        assurance_evidence_bundle_ref: required_path_string(
            admission,
            &["deployment_assurance", "assurance_evidence_bundle_ref"],
        )?,
        assurance_evidence_bundle_hash: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "deployment_binding",
                "assurance_evidence_bundle_hash",
            ],
        )?,
        active_writer_lease_ref: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "writer_and_restart_assurance",
                "active_writer_lease_ref",
            ],
        )?,
        active_writer_fencing_epoch,
        active_writer_fencing_token_hash: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "writer_and_restart_assurance",
                "active_writer_fencing_token_hash",
            ],
        )?,
        graph_timing_chain_ref: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "runtime_assurance_timing",
                "graph_timing_chain_ref",
            ],
        )?,
        graph_timing_chain_hash: required_path_string(
            admission,
            &[
                "deployment_assurance",
                "runtime_assurance_timing",
                "graph_timing_chain_hash",
            ],
        )?,
        state_root_before: request.state_root_before.clone(),
        preflight_receipt_refs,
        sensor_evidence_receipt_refs,
        segment_commitment_receipt_refs,
    };
    validate_invocation_resource_closure(&invocation)?;
    Ok(invocation)
}

fn validate_invocation_resource_closure(
    invocation: &PhysicalControllerInvocation,
) -> Result<(), PhysicalActionExecutionError> {
    let target_present = invocation.resource_group_bindings.iter().any(|binding| {
        binding.unit_refs.contains(&invocation.target_system_ref)
            || binding
                .actuator_refs
                .contains(&invocation.target_system_ref)
    });
    let controller_present = invocation.resource_group_bindings.iter().any(|binding| {
        binding
            .controller_binding_refs
            .contains(&invocation.controller_binding_ref)
    });
    let emergency_stop_present = invocation.resource_group_bindings.iter().any(|binding| {
        binding
            .emergency_stop_authority_refs
            .contains(&invocation.emergency_stop_authority_ref)
    });
    if target_present && controller_present && emergency_stop_present {
        Ok(())
    } else {
        Err(PhysicalActionExecutionError::new(
            "physical_action_execution_resource_closure_mismatch",
            "The expanded resource-group closure does not contain the exact target, controller, and emergency-stop bindings.",
            json!({
                "target_present": target_present,
                "controller_present": controller_present,
                "emergency_stop_present": emergency_stop_present,
            }),
        ))
    }
}

fn normalize_outcome(
    mut outcome: PhysicalControllerOutcome,
    idempotency_key: &str,
) -> (PhysicalControllerOutcome, Vec<String>) {
    let mut errors = BTreeSet::new();
    if !outcome.controller_operation_ref.starts_with("effect://") {
        errors.insert("controller_operation_ref_invalid".to_string());
        let fallback_hash = hash_bytes(idempotency_key.as_bytes());
        outcome.controller_operation_ref = format!(
            "effect://controller/ambiguous/{}",
            fallback_hash.trim_start_matches("sha256:")
        );
    }

    let mut valid_receipts = BTreeSet::new();
    for reference in outcome.controller_receipt_refs {
        if reference.starts_with("receipt://") {
            valid_receipts.insert(reference);
        } else {
            errors.insert("controller_receipt_ref_invalid".to_string());
        }
    }
    outcome.controller_receipt_refs = valid_receipts.into_iter().collect();
    let mut valid_dispatch_evidence = BTreeSet::new();
    for reference in outcome.dispatch_evidence_receipt_refs {
        if reference.starts_with("receipt://") {
            valid_dispatch_evidence.insert(reference);
        } else {
            errors.insert("dispatch_evidence_receipt_ref_invalid".to_string());
        }
    }
    outcome.dispatch_evidence_receipt_refs = valid_dispatch_evidence.into_iter().collect();

    match outcome.effect_status {
        PhysicalControllerEffectStatus::Committed => {
            if outcome.dispatch_posture != PhysicalControllerDispatchPosture::DispatchedObserved {
                errors.insert("committed_dispatch_observation_missing".to_string());
            }
            if outcome.dispatch_evidence_receipt_refs.is_empty() {
                errors.insert("committed_dispatch_evidence_missing".to_string());
            }
            if outcome.controller_receipt_refs.is_empty() {
                errors.insert("committed_controller_receipt_missing".to_string());
            }
            if outcome
                .state_root_after
                .as_deref()
                .is_none_or(|root| root.trim().is_empty())
            {
                errors.insert("committed_state_root_missing".to_string());
            }
        }
        PhysicalControllerEffectStatus::Rejected => {
            if outcome.dispatch_posture != PhysicalControllerDispatchPosture::NotDispatchedProven {
                errors.insert("rejected_not_dispatched_proof_missing".to_string());
            }
            if outcome.dispatch_evidence_receipt_refs.is_empty() {
                errors.insert("rejected_dispatch_evidence_missing".to_string());
            }
            if outcome.state_root_after.is_some() {
                errors.insert("rejected_state_root_after_forbidden".to_string());
            }
        }
        PhysicalControllerEffectStatus::Unknown => {}
    }

    if !errors.is_empty() {
        // Once the invoker has been called, malformed or incomplete adapter output cannot be
        // returned as a pre-effect denial: the effect may already exist. Preserve the attempt as
        // an explicit unknown effect and force reconciliation.
        outcome.effect_status = PhysicalControllerEffectStatus::Unknown;
        outcome.dispatch_posture = PhysicalControllerDispatchPosture::DispatchAmbiguous;
    }
    (outcome, errors.into_iter().collect())
}

fn required_path_string(
    value: &Value,
    path: &[&str],
) -> Result<String, PhysicalActionExecutionError> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment).ok_or_else(|| {
            PhysicalActionExecutionError::new(
                "physical_action_execution_binding_missing",
                "The final admission record is missing a required execution binding.",
                json!({ "path": path.join(".") }),
            )
        })?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            PhysicalActionExecutionError::new(
                "physical_action_execution_binding_invalid",
                "A required final-admission execution binding is not a nonempty string.",
                json!({ "path": path.join(".") }),
            )
        })
}

fn optional_path_string(
    value: &Value,
    path: &[&str],
) -> Result<Option<String>, PhysicalActionExecutionError> {
    let current = value_at_path(value, path)?;
    if current.is_null() {
        return Ok(None);
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| Some(value.to_string()))
        .ok_or_else(|| {
            PhysicalActionExecutionError::new(
                "physical_action_execution_binding_invalid",
                "An optional final-admission execution binding is neither null nor a nonempty string.",
                json!({ "path": path.join(".") }),
            )
        })
}

fn required_path_u64(value: &Value, path: &[&str]) -> Result<u64, PhysicalActionExecutionError> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment).ok_or_else(|| {
            PhysicalActionExecutionError::new(
                "physical_action_execution_binding_missing",
                "The final admission record is missing a required execution binding.",
                json!({ "path": path.join(".") }),
            )
        })?;
    }
    current.as_u64().ok_or_else(|| {
        PhysicalActionExecutionError::new(
            "physical_action_execution_binding_invalid",
            "A required final-admission execution binding is not a nonnegative integer.",
            json!({ "path": path.join(".") }),
        )
    })
}

fn value_at_path<'a>(
    value: &'a Value,
    path: &[&str],
) -> Result<&'a Value, PhysicalActionExecutionError> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment).ok_or_else(|| {
            PhysicalActionExecutionError::new(
                "physical_action_execution_binding_missing",
                "The final admission record is missing a required execution binding.",
                json!({ "path": path.join(".") }),
            )
        })?;
    }
    Ok(current)
}

fn required_resource_group_bindings(
    value: &Value,
    path: &[&str],
) -> Result<Vec<PhysicalResourceGroupBinding>, PhysicalActionExecutionError> {
    let bindings = value_at_path(value, path)?.as_array().ok_or_else(|| {
        PhysicalActionExecutionError::new(
            "physical_action_execution_resource_group_binding_invalid",
            "Physical execution requires an array of exact resource-group bindings.",
            json!({ "path": path.join(".") }),
        )
    })?;
    if bindings.is_empty() {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_resource_group_binding_required",
            "Physical execution requires at least one exact resource-group binding.",
            json!({}),
        ));
    }
    let mut out = BTreeSet::new();
    for (index, binding) in bindings.iter().enumerate() {
        let group_revision_ref = required_path_string(binding, &["group_revision_ref"])?;
        if !group_revision_ref.starts_with("embodied-resource-group-revision://") {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_resource_group_binding_invalid",
                "The resource-group revision uses an invalid reference.",
                json!({ "index": index, "group_revision_ref": group_revision_ref }),
            ));
        }
        let membership_closure_hash = required_path_string(binding, &["membership_closure_hash"])?;
        require_hash(&membership_closure_hash, "membership_closure_hash")?;
        let unit_refs = required_prefixed_ref_array(
            binding,
            &["unit_refs"],
            &[
                "robot://",
                "drone://",
                "device://",
                "facility://",
                "facility-system://",
                "vehicle://",
            ],
            true,
        )?;
        let controller_binding_refs = required_prefixed_ref_array(
            binding,
            &["controller_binding_refs"],
            &["controller-binding://"],
            true,
        )?;
        let sensor_refs =
            required_prefixed_ref_array(binding, &["sensor_refs"], &["sensor://"], true)?;
        let actuator_refs =
            required_prefixed_ref_array(binding, &["actuator_refs"], &["actuator://"], true)?;
        let physical_zone_refs =
            required_prefixed_ref_array(binding, &["physical_zone_refs"], &["zone://"], true)?;
        let emergency_stop_authority_refs = required_prefixed_ref_array(
            binding,
            &["emergency_stop_authority_refs"],
            &["estop://"],
            true,
        )?;
        if !out.insert(PhysicalResourceGroupBinding {
            group_revision_ref,
            membership_closure_hash,
            unit_refs,
            controller_binding_refs,
            sensor_refs,
            actuator_refs,
            physical_zone_refs,
            emergency_stop_authority_refs,
        }) {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_resource_group_binding_duplicated",
                "A physical execution resource-group binding is duplicated.",
                json!({ "index": index }),
            ));
        }
    }
    Ok(out.into_iter().collect())
}

fn required_receipt_ref_array(
    value: &Value,
    path: &[&str],
    nonempty: bool,
) -> Result<Vec<String>, PhysicalActionExecutionError> {
    let items = value_at_path(value, path)?.as_array().ok_or_else(|| {
        PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_binding_invalid",
            "A physical execution receipt binding must be an array.",
            json!({ "path": path.join(".") }),
        )
    })?;
    if nonempty && items.is_empty() {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_receipt_binding_required",
            "The physical execution is missing required preflight or sensor evidence.",
            json!({ "path": path.join(".") }),
        ));
    }
    let mut refs = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let Some(reference) = item
            .as_str()
            .filter(|reference| reference.starts_with("receipt://"))
        else {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_receipt_binding_invalid",
                "Physical execution evidence must use receipt:// references.",
                json!({ "path": path.join("."), "index": index }),
            ));
        };
        refs.insert(reference.to_string());
    }
    Ok(refs.into_iter().collect())
}

fn required_prefixed_ref_array(
    value: &Value,
    path: &[&str],
    allowed_prefixes: &[&str],
    nonempty: bool,
) -> Result<Vec<String>, PhysicalActionExecutionError> {
    let items = value_at_path(value, path)?.as_array().ok_or_else(|| {
        PhysicalActionExecutionError::new(
            "physical_action_execution_ref_array_invalid",
            "A bound physical execution reference collection must be an array.",
            json!({ "path": path.join("."), "allowed_prefixes": allowed_prefixes }),
        )
    })?;
    if nonempty && items.is_empty() {
        return Err(PhysicalActionExecutionError::new(
            "physical_action_execution_ref_array_required",
            "A required physical execution reference collection is empty.",
            json!({ "path": path.join(".") }),
        ));
    }
    let mut refs = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let Some(reference) = item.as_str().map(str::trim).filter(|value| {
            !value.is_empty()
                && allowed_prefixes
                    .iter()
                    .any(|prefix| value.starts_with(prefix))
        }) else {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_ref_array_invalid",
                "A physical execution reference uses an invalid scheme.",
                json!({
                    "path": path.join("."),
                    "index": index,
                    "allowed_prefixes": allowed_prefixes,
                }),
            ));
        };
        if !refs.insert(reference.to_string()) {
            return Err(PhysicalActionExecutionError::new(
                "physical_action_execution_ref_array_duplicated",
                "A physical execution reference collection contains a duplicate.",
                json!({ "path": path.join("."), "index": index, "reference": reference }),
            ));
        }
    }
    Ok(refs.into_iter().collect())
}

fn binding_mismatch(field: &str, expected: &str, received: &str) -> PhysicalActionExecutionError {
    PhysicalActionExecutionError::new(
        "physical_action_execution_binding_mismatch",
        "The controller invocation does not match the command binding admitted for execution.",
        json!({ "field": field, "expected": expected, "received": received }),
    )
}

fn require_nonempty(value: &str, field: &str) -> Result<(), PhysicalActionExecutionError> {
    if value.trim().is_empty() {
        Err(PhysicalActionExecutionError::new(
            "physical_action_execution_field_required",
            "A required physical execution field is empty.",
            json!({ "field": field }),
        ))
    } else {
        Ok(())
    }
}

fn require_rfc3339(value: &str, field: &str) -> Result<(), PhysicalActionExecutionError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|error| {
            PhysicalActionExecutionError::new(
                "physical_action_execution_timestamp_invalid",
                "A physical execution timestamp must be RFC 3339.",
                json!({ "field": field, "value": value, "error": error.to_string() }),
            )
        })
}

fn require_hash(value: &str, field: &str) -> Result<(), PhysicalActionExecutionError> {
    let digest = value.strip_prefix("sha256:").unwrap_or_default();
    if digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(PhysicalActionExecutionError::new(
            "physical_action_execution_hash_invalid",
            "A physical execution hash must use sha256:<64 hex characters>.",
            json!({ "field": field }),
        ))
    }
}

fn jcs_hash<T: Serialize>(value: &T) -> Result<String, PhysicalActionExecutionError> {
    let encoded = serde_jcs::to_vec(value).map_err(hash_error)?;
    Ok(hash_bytes(&encoded))
}

fn hash_error(error: serde_json::Error) -> PhysicalActionExecutionError {
    PhysicalActionExecutionError::new(
        "physical_action_execution_canonicalization_failed",
        "The physical execution object could not be encoded with canonical JCS JSON.",
        json!({ "error": error.to_string() }),
    )
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn domain_hash(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::runtime_physical_action_intent_admission::physical_action_test_request;

    #[derive(Default)]
    struct RecordingInvoker {
        calls: usize,
        status: Option<PhysicalControllerEffectStatus>,
    }

    impl PhysicalControllerInvoker for RecordingInvoker {
        fn controller_binding_ref(&self) -> &str {
            "controller-binding://carwash/bay-3/humanoid-1/v1"
        }

        fn invoke(
            &mut self,
            invocation: &PhysicalControllerInvocation,
        ) -> PhysicalControllerOutcome {
            self.calls += 1;
            let effect_status = self
                .status
                .unwrap_or(PhysicalControllerEffectStatus::Committed);
            let (dispatch_posture, dispatch_evidence_receipt_refs, state_root_after) =
                match effect_status {
                    PhysicalControllerEffectStatus::Committed => (
                        PhysicalControllerDispatchPosture::DispatchedObserved,
                        vec!["receipt://controller/carwash/dispatch-observed-001".to_string()],
                        Some("state_root:physical:carwash:002".to_string()),
                    ),
                    PhysicalControllerEffectStatus::Rejected => (
                        PhysicalControllerDispatchPosture::NotDispatchedProven,
                        vec!["receipt://controller/carwash/not-dispatched-001".to_string()],
                        None,
                    ),
                    PhysicalControllerEffectStatus::Unknown => (
                        PhysicalControllerDispatchPosture::DispatchAmbiguous,
                        Vec::new(),
                        None,
                    ),
                };
            PhysicalControllerOutcome {
                effect_status,
                dispatch_posture,
                controller_operation_ref: format!(
                    "effect://controller/{}",
                    invocation.idempotency_key.replace(':', "/")
                ),
                dispatch_evidence_receipt_refs,
                controller_receipt_refs: vec![
                    "receipt://controller/carwash/command-001".to_string()
                ],
                state_root_after,
            }
        }
    }

    fn request(idempotency_key: &str, previous: Option<String>) -> PhysicalActionExecutionRequest {
        let payload = json!({
            "primitive": "grasp",
            "target": "vehicle-door-handle",
            "maximum_force_n": 24,
        });
        let payload_hash = jcs_hash(&payload).unwrap();
        let mut admission_request = physical_action_test_request();
        admission_request["execution_phase"] = json!("preflight_verified");
        admission_request["command_payload_hash"] = json!(payload_hash);
        admission_request["controller_idempotency_key"] = json!(idempotency_key);
        PhysicalActionExecutionRequest {
            schema_version: PHYSICAL_ACTION_EXECUTION_REQUEST_SCHEMA_VERSION.to_string(),
            idempotency_key: idempotency_key.to_string(),
            admission_request,
            command_payload: payload,
            expected_command_payload_hash: payload_hash,
            state_root_before: "state_root:physical:carwash:001".to_string(),
            previous_execution_receipt_hash: previous,
        }
    }

    #[test]
    fn final_gate_invokes_once_and_same_body_replays_without_reinvocation() {
        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = RecordingInvoker::default();
        let request = request("physical-command:carwash:001", None);

        let first = core
            .execute(&request, "2026-07-16T12:00:00Z", &mut invoker)
            .expect("fresh final admission and invocation");
        assert!(!first.replayed);
        assert_eq!(invoker.calls, 1);
        assert_eq!(
            first.receipt.body.command_payload_hash,
            request.expected_command_payload_hash
        );
        assert_eq!(first.receipt.body.active_writer_fencing_epoch, 7);
        verify_physical_action_execution_receipt(&first.receipt, None).unwrap();

        let replay = core
            .execute(&request, "2026-07-16T12:30:00Z", &mut invoker)
            .expect("same body replay");
        assert!(replay.replayed);
        assert_eq!(replay.receipt, first.receipt);
        assert_eq!(invoker.calls, 1);
    }

    #[test]
    fn every_pre_invocation_denial_proves_zero_controller_calls() {
        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = RecordingInvoker::default();

        let mut bad_hash = request("physical-command:carwash:bad-hash", None);
        bad_hash.expected_command_payload_hash = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            core.execute(&bad_hash, "2026-07-16T12:00:00Z", &mut invoker)
                .unwrap_err()
                .code,
            "physical_action_execution_command_hash_mismatch"
        );

        let mut denied = request("physical-command:carwash:denied", None);
        denied.admission_request["emergency_stop_tested"] = json!(false);
        assert_eq!(
            core.execute(&denied, "2026-07-16T12:00:00Z", &mut invoker)
                .unwrap_err()
                .code,
            "physical_action_emergency_stop_test_required"
        );
        assert_eq!(invoker.calls, 0);
    }

    #[test]
    fn changed_body_under_same_idempotency_key_conflicts_without_reinvocation() {
        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = RecordingInvoker::default();
        let request = request("physical-command:carwash:conflict", None);
        core.execute(&request, "2026-07-16T12:00:00Z", &mut invoker)
            .unwrap();

        let mut changed = request.clone();
        changed.state_root_before = "state_root:physical:carwash:other".to_string();
        assert_eq!(
            core.execute(&changed, "2026-07-16T12:30:00Z", &mut invoker)
                .unwrap_err()
                .code,
            "physical_action_execution_idempotency_conflict"
        );
        assert_eq!(invoker.calls, 1);
    }

    #[test]
    fn new_execution_must_extend_exact_receipt_head_and_tamper_is_detected() {
        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = RecordingInvoker::default();
        let first = core
            .execute(
                &request("physical-command:carwash:chain-1", None),
                "2026-07-16T12:00:00Z",
                &mut invoker,
            )
            .unwrap();

        let wrong_previous = format!("sha256:{}", "f".repeat(64));
        assert_eq!(
            core.execute(
                &request("physical-command:carwash:chain-2", Some(wrong_previous)),
                "2026-07-16T12:30:00Z",
                &mut invoker,
            )
            .unwrap_err()
            .code,
            "physical_action_execution_receipt_head_conflict"
        );
        assert_eq!(invoker.calls, 1);

        let second = core
            .execute(
                &request(
                    "physical-command:carwash:chain-2",
                    Some(first.receipt.receipt_hash.clone()),
                ),
                "2026-07-16T12:30:00Z",
                &mut invoker,
            )
            .unwrap();
        assert_eq!(invoker.calls, 2);
        verify_physical_action_execution_receipt(
            &second.receipt,
            Some(&first.receipt.receipt_hash),
        )
        .unwrap();

        let mut tampered = second.receipt;
        tampered.body.active_writer_fencing_epoch += 1;
        assert_eq!(
            verify_physical_action_execution_receipt(&tampered, Some(&first.receipt.receipt_hash),)
                .unwrap_err()
                .code,
            "physical_action_execution_receipt_identity_invalid"
        );
    }

    #[test]
    fn unknown_controller_effect_remains_unknown_in_receipt() {
        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = RecordingInvoker {
            calls: 0,
            status: Some(PhysicalControllerEffectStatus::Unknown),
        };
        let result = core
            .execute(
                &request("physical-command:carwash:unknown", None),
                "2026-07-16T12:00:00Z",
                &mut invoker,
            )
            .unwrap();
        assert_eq!(
            result.receipt.body.effect_status,
            PhysicalControllerEffectStatus::Unknown
        );
    }

    #[test]
    fn malformed_post_invocation_outcome_becomes_receipted_unknown_not_lost_error() {
        struct MalformedInvoker {
            calls: usize,
        }
        impl PhysicalControllerInvoker for MalformedInvoker {
            fn controller_binding_ref(&self) -> &str {
                "controller-binding://carwash/bay-3/humanoid-1/v1"
            }

            fn invoke(
                &mut self,
                _invocation: &PhysicalControllerInvocation,
            ) -> PhysicalControllerOutcome {
                self.calls += 1;
                PhysicalControllerOutcome {
                    effect_status: PhysicalControllerEffectStatus::Committed,
                    dispatch_posture: PhysicalControllerDispatchPosture::DispatchAmbiguous,
                    controller_operation_ref: "not-an-effect-ref".to_string(),
                    dispatch_evidence_receipt_refs: Vec::new(),
                    controller_receipt_refs: vec!["not-a-receipt".to_string()],
                    state_root_after: None,
                }
            }
        }

        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = MalformedInvoker { calls: 0 };
        let result = core
            .execute(
                &request("physical-command:carwash:malformed-outcome", None),
                "2026-07-16T12:00:00Z",
                &mut invoker,
            )
            .expect("post-invocation evidence must survive as unknown");
        assert_eq!(invoker.calls, 1);
        assert_eq!(
            result.receipt.body.effect_status,
            PhysicalControllerEffectStatus::Unknown
        );
        assert_eq!(result.receipt.body.reconciliation_state, "ambiguous_effect");
        assert_eq!(
            result.receipt.body.outcome_normalization_error_codes.len(),
            6
        );
        assert!(result
            .receipt
            .body
            .controller_operation_ref
            .starts_with("effect://controller/ambiguous/"));
    }

    #[test]
    fn state_root_and_expanded_resource_closure_are_exact_pre_invocation_bindings() {
        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = RecordingInvoker::default();

        let mut state_substitution = request("physical-command:carwash:state-substitution", None);
        state_substitution.state_root_before = "state_root:physical:carwash:foreign".to_string();
        assert_eq!(
            core.execute(&state_substitution, "2026-07-16T12:00:00Z", &mut invoker,)
                .unwrap_err()
                .code,
            "physical_action_execution_binding_mismatch"
        );

        let mut controller_substitution =
            request("physical-command:carwash:group-substitution", None);
        controller_substitution.admission_request["resource_group_bindings"][0]
            ["controller_binding_refs"] = json!(["controller-binding://carwash/bay-3/foreign/v1"]);
        assert_eq!(
            core.execute(
                &controller_substitution,
                "2026-07-16T12:00:00Z",
                &mut invoker,
            )
            .unwrap_err()
            .code,
            "physical_action_resource_group_controller_binding_mismatch"
        );
        assert_eq!(invoker.calls, 0);
    }

    #[test]
    fn execution_carries_canonical_facility_system_refs_and_refuses_legacy_writes() {
        let mut canonical_core = PhysicalActionExecutionCore::default();
        let mut canonical_invoker = RecordingInvoker::default();
        let mut canonical = request("physical-command:carwash:canonical-facility", None);
        canonical.admission_request["resource_group_bindings"][0]["unit_refs"] = json!([
            "robot://bay-3/humanoid-1",
            "facility-system://carwash/bay-3"
        ]);
        let result = canonical_core
            .execute(&canonical, "2026-07-16T12:00:00Z", &mut canonical_invoker)
            .expect("canonical facility-system refs survive final admission and execution");
        assert_eq!(canonical_invoker.calls, 1);
        assert!(result.receipt.body.resource_group_bindings[0]
            .unit_refs
            .iter()
            .any(|reference| reference == "facility-system://carwash/bay-3"));

        let mut legacy_core = PhysicalActionExecutionCore::default();
        let mut legacy_invoker = RecordingInvoker::default();
        let mut legacy = request("physical-command:carwash:legacy-facility", None);
        legacy.admission_request["resource_group_bindings"][0]["unit_refs"] = json!([
            "robot://bay-3/humanoid-1",
            "facility_system://carwash/bay-3"
        ]);
        let error = legacy_core
            .execute(&legacy, "2026-07-16T12:00:00Z", &mut legacy_invoker)
            .expect_err("read-only legacy aliases must not cross the execution boundary");
        assert_eq!(error.code, "physical_action_deployment_assurance_invalid");
        assert_eq!(legacy_invoker.calls, 0);
    }

    #[test]
    fn foreign_controller_adapter_is_refused_before_invocation() {
        struct ForeignInvoker {
            calls: usize,
        }
        impl PhysicalControllerInvoker for ForeignInvoker {
            fn controller_binding_ref(&self) -> &str {
                "controller-binding://carwash/bay-3/foreign/v1"
            }

            fn invoke(
                &mut self,
                _invocation: &PhysicalControllerInvocation,
            ) -> PhysicalControllerOutcome {
                self.calls += 1;
                panic!("foreign adapter must never be invoked")
            }
        }

        let mut core = PhysicalActionExecutionCore::default();
        let mut invoker = ForeignInvoker { calls: 0 };
        let error = core
            .execute(
                &request("physical-command:carwash:foreign-controller", None),
                "2026-07-16T12:00:00Z",
                &mut invoker,
            )
            .unwrap_err();
        assert_eq!(
            error.code,
            "physical_action_execution_controller_binding_mismatch"
        );
        assert_eq!(invoker.calls, 0);
    }

    #[test]
    fn interrupted_prepared_execution_survives_restart_and_never_blindly_reinvokes() {
        struct PanickingInvoker {
            calls: usize,
        }
        impl PhysicalControllerInvoker for PanickingInvoker {
            fn controller_binding_ref(&self) -> &str {
                "controller-binding://carwash/bay-3/humanoid-1/v1"
            }

            fn invoke(
                &mut self,
                _invocation: &PhysicalControllerInvocation,
            ) -> PhysicalControllerOutcome {
                self.calls += 1;
                panic!("simulated process loss after crossing controller boundary")
            }
        }

        let interrupted_request = request("physical-command:carwash:interrupted", None);
        let mut core = PhysicalActionExecutionCore::default();
        let mut panicking = PanickingInvoker { calls: 0 };
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = core.execute(&interrupted_request, "2026-07-16T12:00:00Z", &mut panicking);
        }));
        assert!(panic.is_err());
        assert_eq!(panicking.calls, 1);

        let snapshot = serde_json::to_vec(&core).expect("serializable prepared ledger");
        let mut restored: PhysicalActionExecutionCore =
            serde_json::from_slice(&snapshot).expect("restore prepared ledger");
        let mut retry_invoker = RecordingInvoker::default();
        let retry = restored
            .execute(
                &interrupted_request,
                "2026-07-16T12:01:00Z",
                &mut retry_invoker,
            )
            .unwrap_err();
        assert_eq!(
            retry.code,
            "physical_action_execution_reconciliation_required"
        );
        assert_eq!(retry_invoker.calls, 0);

        let other = restored
            .execute(
                &request("physical-command:carwash:other", None),
                "2026-07-16T12:02:00Z",
                &mut retry_invoker,
            )
            .unwrap_err();
        assert_eq!(
            other.code,
            "physical_action_execution_chain_reconciliation_required"
        );
        assert_eq!(retry_invoker.calls, 0);
    }

    #[test]
    fn rejection_without_not_dispatched_proof_is_normalized_to_unknown() {
        struct FalseRejectingInvoker;
        impl PhysicalControllerInvoker for FalseRejectingInvoker {
            fn controller_binding_ref(&self) -> &str {
                "controller-binding://carwash/bay-3/humanoid-1/v1"
            }

            fn invoke(
                &mut self,
                _invocation: &PhysicalControllerInvocation,
            ) -> PhysicalControllerOutcome {
                PhysicalControllerOutcome {
                    effect_status: PhysicalControllerEffectStatus::Rejected,
                    dispatch_posture: PhysicalControllerDispatchPosture::DispatchAmbiguous,
                    controller_operation_ref: "effect://controller/carwash/false-rejection"
                        .to_string(),
                    dispatch_evidence_receipt_refs: Vec::new(),
                    controller_receipt_refs: Vec::new(),
                    state_root_after: None,
                }
            }
        }

        let mut core = PhysicalActionExecutionCore::default();
        let result = core
            .execute(
                &request("physical-command:carwash:false-rejection", None),
                "2026-07-16T12:00:00Z",
                &mut FalseRejectingInvoker,
            )
            .unwrap();
        assert_eq!(
            result.receipt.body.effect_status,
            PhysicalControllerEffectStatus::Unknown
        );
        assert_eq!(
            result.receipt.body.dispatch_posture,
            PhysicalControllerDispatchPosture::DispatchAmbiguous
        );
        assert!(result
            .receipt
            .body
            .outcome_normalization_error_codes
            .contains(&"rejected_not_dispatched_proof_missing".to_string()));
        assert!(result
            .receipt
            .body
            .outcome_normalization_error_codes
            .contains(&"rejected_dispatch_evidence_missing".to_string()));
    }
}
