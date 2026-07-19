//! Physical-action-intent admission planner.
//!
//! A Rust-owned physical-action admission boundary. The original request-shape normalization is a
//! faithful port of the retired JS `admitPhysicalActionIntent`, while the deployment-assurance
//! checks are intentionally stricter: live, hard-real-time, or E1+ claims fail closed unless the
//! request binds exact graph/deployment/ODD/timing/input/switch/writer evidence.
//!
//! GOTCHA: `optional_positive_integer` mirrors JS `Number(value)` coercion exactly (the
//! `js_number_coerce` helper): true→1, false→0, "0x10"→16, "0o17"→15, [250]→250 (array →
//! String → ToNumber), {}→NaN, "  10  "→10, ""→null. STATUS varies: field-shape helpers
//! (required/enum/prefix/target/actor/positive-integer) reject HTTP 400; policy assertions
//! (`admissionError`/requireRefs) reject HTTP 403. `requirePrefix` rejects with a per-field
//! `..._{field}_invalid` code (details key = the dynamic field name).

use serde_json::{json, Map, Value};

pub const PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.runtime.physical_action_intent_admission.v2";

const ASSURANCE_EVIDENCE_LEVELS: &[&str] = &["E0", "E1", "E2", "E3"];
const EXECUTION_TIMING_CLASSES: &[&str] =
    &["best_effort", "bounded_soft_realtime", "hard_realtime"];
const TIMING_EVIDENCE_MODES: &[&str] = &["bounded_soft_tail", "hard_realtime_analytic"];
const ODD_STATES: &[&str] = &["inside", "exiting", "outside", "unknown"];
const ODD_EXIT_RESPONSES: &[&str] = &[
    "deny_new_commands",
    "switch_to_recovery",
    "safe_stop",
    "emergency_stop",
    "operator_handoff",
];
const SAFETY_INPUT_SOURCE_KINDS: &[&str] =
    &["learned", "deterministic", "hardware_interlock", "fused"];
const SAFETY_INPUT_ASSURANCE_POSTURES: &[&str] = &[
    "unassured_supplemental",
    "assured_independent",
    "assured_diverse",
];
const RESTART_POSTURES: &[&str] = &[
    "no_restart_since_admission",
    "restarted_inactive_unarmed_and_readmitted",
];
const STANDBY_WRITER_POSTURES: &[&str] = &["absent", "fenced_inactive", "safe_takeover_tested"];
const TELEOP_LINK_STATES: &[&str] = &["healthy", "degraded", "lost", "unknown"];
const TELEOP_DEADMAN_STATES: &[&str] = &["asserted", "released", "stale", "unknown"];
const TELEOP_AUTH_STATES: &[&str] = &["verified", "expired", "revoked", "unknown"];
const TELEOP_LOSS_RESPONSES: &[&str] = &[
    "hold_position",
    "switch_to_recovery",
    "safe_stop",
    "emergency_stop",
];

const ACTION_KINDS: &[&str] = &[
    "navigation",
    "manipulation",
    "vehicle_adjacent",
    "drone_flight",
    "facility_control",
    "tool_use",
    "access_control",
    "sensor_override",
    "emergency_stop_test",
    "other",
];

const SUPERVISION_MODES: &[&str] = &[
    "autonomous",
    "monitored",
    "human_on_loop",
    "human_in_loop",
    "manual_confirm_each_action",
];

const EXECUTION_PHASES: &[&str] = &[
    "intent_proposed",
    "preflight_verified",
    "command_issued",
    "stopped",
    "completed",
    "incident_opened",
];

const TARGET_PREFIXES: &[&str] = &[
    "robot://",
    "facility://",
    "vehicle://",
    "device://",
    "drone://",
    "actuator://",
];

const ACTOR_PREFIXES: &[&str] = &["worker:", "worker://", "service_engine:", "runtime:"];

const RETIRED_ALIASES: &[&str] = &[
    "intentId",
    "actorId",
    "targetSystemRef",
    "actionKind",
    "riskClass",
    "physicalActionPolicyRef",
    "safetyEnvelopeRef",
    "emergencyStopAuthorityRef",
    "sensorEvidenceReceiptRefs",
    "actuatorCommandReceiptRefs",
    "agentgresOperationRefs",
];

#[derive(Debug, Clone)]
pub struct RuntimePhysicalActionIntentAdmissionError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimePhysicalActionIntentAdmissionError {
    fn new(status: u16, code: String, message: String, details: Value) -> Self {
        Self {
            status,
            code,
            message,
            details,
        }
    }
}

type AdmitResult<T> = Result<T, RuntimePhysicalActionIntentAdmissionError>;

#[derive(Default)]
pub struct RuntimePhysicalActionIntentAdmissionCore;

impl RuntimePhysicalActionIntentAdmissionCore {
    pub fn admit(&self, request: &Value, now_iso: &str) -> AdmitResult<Value> {
        assert_no_retired_aliases(request)?;

        let intent_id = required_string(request.get("intent_id"), "intent_id")?;
        let actor_id = required_string(request.get("actor_id"), "actor_id")?;
        let task_id = optional_value(request.get("task_id"));
        let domain_ref = optional_value(request.get("domain_ref"));
        let target_system_ref =
            required_string(request.get("target_system_ref"), "target_system_ref")?;
        let resource_group_bindings =
            validate_resource_group_bindings(request.get("resource_group_bindings"))?;
        let action_kind = enum_value(request.get("action_kind"), "action_kind", ACTION_KINDS)?;
        let risk_class = optional_value(request.get("risk_class"))
            .unwrap_or_else(|| "physical_action".to_string());
        let execution_phase = enum_value(
            Some(&default_value(
                request.get("execution_phase"),
                "preflight_verified",
            )),
            "execution_phase",
            EXECUTION_PHASES,
        )?;
        let requested_primitives = unique_strings_raw(request.get("requested_primitives"));
        let requested_scopes = unique_strings_raw(request.get("requested_scopes"));
        let physical_action_policy_ref = required_string(
            request.get("physical_action_policy_ref"),
            "physical_action_policy_ref",
        )?;
        let safety_envelope_ref =
            required_string(request.get("safety_envelope_ref"), "safety_envelope_ref")?;
        let human_supervision_policy_ref =
            optional_value(request.get("human_supervision_policy_ref"));
        let supervision_mode = enum_value(
            Some(&default_value(request.get("supervision_mode"), "monitored")),
            "supervision_mode",
            SUPERVISION_MODES,
        )?;
        let human_supervisor_refs = unique_strings_raw(request.get("human_supervisor_refs"));
        let emergency_stop_authority_ref = required_string(
            request.get("emergency_stop_authority_ref"),
            "emergency_stop_authority_ref",
        )?;
        let emergency_stop_tested =
            boolean_value(request.get("emergency_stop_tested")).unwrap_or(false);
        let emergency_stop_max_latency_ms =
            optional_positive_integer(request.get("emergency_stop_max_latency_ms"))?;
        let sensor_evidence_receipt_refs =
            unique_strings_raw(request.get("sensor_evidence_receipt_refs"));
        let actuator_command_receipt_refs =
            unique_strings_raw(request.get("actuator_command_receipt_refs"));
        let preflight_receipt_refs = unique_strings_raw(request.get("preflight_receipt_refs"));
        let segment_commitment_receipt_refs =
            unique_strings_raw(request.get("segment_commitment_receipt_refs"));
        let incident_policy_ref =
            required_string(request.get("incident_policy_ref"), "incident_policy_ref")?;
        let rollback_or_compensation_policy_ref =
            optional_value(request.get("rollback_or_compensation_policy_ref"));
        let wallet_approval_ref = optional_value(request.get("wallet_approval_ref"));
        let authority_ref =
            optional_value(request.get("authority_ref")).or_else(|| wallet_approval_ref.clone());
        let policy_refs = unique_strings_raw(request.get("policy_refs"));
        let receipt_refs = unique_strings_raw(request.get("receipt_refs"));
        let agentgres_operation_refs = unique_strings_raw(request.get("agentgres_operation_refs"));
        let artifact_refs = unique_strings_raw(request.get("artifact_refs"));
        let state_root = optional_value(request.get("state_root"));
        let execution_channel = optional_value(request.get("execution_channel"));
        let command_schema_ref = optional_value(request.get("command_schema_ref"));
        let command_payload_hash = optional_value(request.get("command_payload_hash"));
        let controller_binding_ref = optional_value(request.get("controller_binding_ref"));
        let controller_idempotency_key = optional_value(request.get("controller_idempotency_key"));
        let simulation_only = boolean_value(request.get("simulation_only")).unwrap_or(false);
        let generic_tool_call = boolean_value(request.get("generic_tool_call")).unwrap_or(false);
        let asserted_assurance_evidence_level = enum_value(
            Some(&default_value(
                request.get("asserted_assurance_evidence_level"),
                "E0",
            )),
            "asserted_assurance_evidence_level",
            ASSURANCE_EVIDENCE_LEVELS,
        )?;
        let execution_timing_class = enum_value(
            Some(&default_value(
                request.get("execution_timing_class"),
                "bounded_soft_realtime",
            )),
            "execution_timing_class",
            EXECUTION_TIMING_CLASSES,
        )?;

        // assertPhysicalActionAdmission — prefixes (400) then policy assertions (403).
        require_prefix(&intent_id, "intent://", "intent_id")?;
        require_actor_ref(&actor_id)?;
        require_target_prefix(&target_system_ref)?;
        require_prefix(
            &physical_action_policy_ref,
            "policy://",
            "physical_action_policy_ref",
        )?;
        require_prefix(&safety_envelope_ref, "safety://", "safety_envelope_ref")?;
        require_prefix(
            &emergency_stop_authority_ref,
            "estop://",
            "emergency_stop_authority_ref",
        )?;
        require_prefix(&incident_policy_ref, "policy://", "incident_policy_ref")?;
        if let Some(ref supervision_policy) = human_supervision_policy_ref {
            require_prefix(
                supervision_policy,
                "supervision://",
                "human_supervision_policy_ref",
            )?;
        }
        if risk_class != "physical_action" {
            return Err(authority_error(
                "physical_action_risk_class_required",
                "Actuator-affecting work must be classified as risk_class physical_action.",
                json!({ "risk_class": risk_class }),
            ));
        }
        if generic_tool_call || execution_channel.as_deref() == Some("tool.invoke") {
            return Err(authority_error(
                "physical_action_generic_tool_call_blocked",
                "No actuator command is a generic tool call; physical actions require the physical-action admission lifecycle.",
                json!({ "execution_channel": execution_channel, "generic_tool_call": generic_tool_call }),
            ));
        }
        if simulation_only && execution_phase != "intent_proposed" {
            return Err(authority_error(
                "physical_action_simulation_not_execution_receipt",
                "Simulation-only evidence cannot be admitted as a physical actuator execution.",
                json!({ "execution_phase": execution_phase }),
            ));
        }
        require_refs(&requested_primitives, "requested_primitives")?;
        require_refs(&requested_scopes, "requested_scopes")?;
        if !requested_primitives
            .iter()
            .any(|reference| reference.starts_with("prim:physical."))
        {
            return Err(authority_error(
                "physical_action_primitive_required",
                "Physical-action admission requires a prim:physical.* primitive.",
                json!({ "requested_primitives": requested_primitives }),
            ));
        }
        if !requested_scopes
            .iter()
            .any(|reference| reference.starts_with("scope:physical."))
        {
            return Err(authority_error(
                "physical_action_scope_required",
                "Physical-action admission requires a scope:physical.* scope.",
                json!({ "requested_scopes": requested_scopes }),
            ));
        }
        if !emergency_stop_tested {
            return Err(authority_error(
                "physical_action_emergency_stop_test_required",
                "Physical-action admission requires a currently tested EmergencyStopAuthority.",
                json!({ "emergency_stop_tested": emergency_stop_tested }),
            ));
        }
        if let Some(latency) = emergency_stop_max_latency_ms {
            if latency > 1000.0 {
                return Err(authority_error(
                    "physical_action_emergency_stop_latency_exceeded",
                    "Physical-action emergency stop latency must remain within the admitted safety envelope.",
                    json!({ "emergency_stop_max_latency_ms": latency_to_json(latency) }),
                ));
            }
        }
        require_refs(
            &sensor_evidence_receipt_refs,
            "sensor_evidence_receipt_refs",
        )?;
        for reference in &sensor_evidence_receipt_refs {
            require_prefix(reference, "receipt://", "sensor_evidence_receipt_refs")?;
        }
        if execution_phase == "command_issued" || execution_phase == "completed" {
            require_refs(
                &actuator_command_receipt_refs,
                "actuator_command_receipt_refs",
            )?;
        }
        for reference in &actuator_command_receipt_refs {
            require_prefix(reference, "receipt://", "actuator_command_receipt_refs")?;
        }
        if matches!(
            supervision_mode.as_str(),
            "human_in_loop" | "manual_confirm_each_action"
        ) && (human_supervisor_refs.is_empty() || wallet_approval_ref.is_none())
        {
            return Err(authority_error(
                "physical_action_human_supervision_authority_required",
                "Human-in-loop physical action requires supervisor refs and wallet approval.",
                json!({ "supervision_mode": supervision_mode }),
            ));
        }
        if authority_ref.is_none() {
            return Err(authority_error(
                "physical_action_authority_ref_required",
                "Physical-action admission requires wallet authority or approval.",
                json!({ "authority_ref": authority_ref }),
            ));
        }
        require_refs(&policy_refs, "policy_refs")?;
        require_refs(&receipt_refs, "receipt_refs")?;
        require_refs(&agentgres_operation_refs, "agentgres_operation_refs")?;

        let live_physical_execution = !simulation_only && execution_phase != "intent_proposed";
        if live_physical_execution {
            if resource_group_bindings.is_empty() {
                return Err(missing_execution_binding("resource_group_bindings"));
            }
            if state_root.is_none() {
                return Err(missing_execution_binding("state_root"));
            }
            require_refs(&preflight_receipt_refs, "preflight_receipt_refs")?;
            for reference in &preflight_receipt_refs {
                require_prefix(reference, "receipt://", "preflight_receipt_refs")?;
            }
            for reference in &segment_commitment_receipt_refs {
                require_prefix(reference, "receipt://", "segment_commitment_receipt_refs")?;
            }
            let command_schema_ref = command_schema_ref
                .as_deref()
                .ok_or_else(|| missing_execution_binding("command_schema_ref"))?;
            require_prefix(command_schema_ref, "action-schema://", "command_schema_ref")?;
            let command_payload_hash = command_payload_hash
                .as_deref()
                .ok_or_else(|| missing_execution_binding("command_payload_hash"))?;
            require_sha256_hash(command_payload_hash, "command_payload_hash")?;
            let controller_binding_ref = controller_binding_ref
                .as_deref()
                .ok_or_else(|| missing_execution_binding("controller_binding_ref"))?;
            require_prefix(
                controller_binding_ref,
                "controller-binding://",
                "controller_binding_ref",
            )?;
            if controller_idempotency_key.is_none() {
                return Err(missing_execution_binding("controller_idempotency_key"));
            }
            require_resource_group_member(
                &resource_group_bindings,
                &["unit_refs", "actuator_refs"],
                &target_system_ref,
                "physical_action_resource_group_target_mismatch",
            )?;
            require_resource_group_member(
                &resource_group_bindings,
                &["controller_binding_refs"],
                controller_binding_ref,
                "physical_action_resource_group_controller_binding_mismatch",
            )?;
            require_resource_group_member(
                &resource_group_bindings,
                &["emergency_stop_authority_refs"],
                &emergency_stop_authority_ref,
                "physical_action_resource_group_emergency_stop_mismatch",
            )?;
        }
        let assurance_required = assurance_level_rank(&asserted_assurance_evidence_level) >= 1
            || execution_timing_class == "hard_realtime"
            || live_physical_execution;
        let deployment_assurance = validate_deployment_assurance(
            request,
            assurance_required,
            &asserted_assurance_evidence_level,
            &execution_timing_class,
            &target_system_ref,
            &safety_envelope_ref,
            controller_binding_ref.as_deref().unwrap_or_default(),
        )?;

        let admission_id = optional_value(request.get("admission_id")).unwrap_or_else(|| {
            format!(
                "physical-action-admission:{}:{}",
                safe_id(&intent_id),
                safe_id(&action_kind)
            )
        });
        let admitted_at =
            optional_value(request.get("admitted_at")).unwrap_or_else(|| now_iso.to_string());

        // Keep the response construction in bounded chunks. A single `json!`
        // object with every admission field exceeds serde_json's default macro
        // recursion depth and can prevent the entire services crate from
        // compiling even though the wire shape itself is valid.
        let mut admission = json!({
            "schema_version": PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION,
            "admission_id": admission_id,
            "intent_id": intent_id,
            "actor_id": actor_id,
            "task_id": task_id,
            "domain_ref": domain_ref,
            "target_system_ref": target_system_ref,
            "resource_group_bindings": resource_group_bindings,
            "action_kind": action_kind,
            "risk_class": "physical_action",
            "execution_phase": execution_phase,
            "requested_primitives": requested_primitives,
            "requested_scopes": requested_scopes,
            "physical_action_policy_ref": physical_action_policy_ref,
            "safety_envelope_ref": safety_envelope_ref,
            "human_supervision_policy_ref": human_supervision_policy_ref,
            "supervision_mode": supervision_mode,
            "human_supervisor_refs": human_supervisor_refs,
            "emergency_stop_authority_ref": emergency_stop_authority_ref,
            "emergency_stop_tested": emergency_stop_tested,
            "emergency_stop_max_latency_ms": emergency_stop_max_latency_ms.map(latency_to_json).unwrap_or(Value::Null),
        });
        let evidence_and_authority = json!({
            "sensor_evidence_receipt_refs": sensor_evidence_receipt_refs,
            "actuator_command_receipt_refs": actuator_command_receipt_refs,
            "preflight_receipt_refs": preflight_receipt_refs,
            "segment_commitment_receipt_refs": segment_commitment_receipt_refs,
            "incident_policy_ref": incident_policy_ref,
            "rollback_or_compensation_policy_ref": rollback_or_compensation_policy_ref,
            "wallet_approval_ref": wallet_approval_ref,
            "authority_ref": authority_ref,
            "policy_refs": policy_refs,
            "receipt_refs": receipt_refs,
            "agentgres_operation_refs": agentgres_operation_refs,
            "artifact_refs": artifact_refs,
            "state_root": state_root,
            "execution_channel": execution_channel,
            "command_schema_ref": command_schema_ref,
            "command_payload_hash": command_payload_hash,
            "controller_binding_ref": controller_binding_ref,
            "controller_idempotency_key": controller_idempotency_key,
            "decision": "admitted",
            "requiresDaemonGate": true,
            "generic_tool_call_blocked": true,
        });
        let assurance_and_runtime = json!({
            "simulation_only": simulation_only,
            "live_physical_execution": live_physical_execution,
            "asserted_assurance_evidence_level": asserted_assurance_evidence_level,
            "execution_timing_class": execution_timing_class,
            "deployment_assurance": deployment_assurance,
            "admitted_at": admitted_at,
            "runtimeTruthSource": "daemon-runtime",
        });
        let admission_object = admission
            .as_object_mut()
            .expect("physical-action admission response is an object");
        admission_object.extend(
            evidence_and_authority
                .as_object()
                .expect("physical-action evidence response is an object")
                .clone(),
        );
        admission_object.extend(
            assurance_and_runtime
                .as_object()
                .expect("physical-action assurance response is an object")
                .clone(),
        );
        Ok(admission)
    }
}

fn validate_deployment_assurance(
    request: &Value,
    required: bool,
    asserted_evidence_level: &str,
    execution_timing_class: &str,
    target_system_ref: &str,
    safety_envelope_ref: &str,
    controller_binding_ref: &str,
) -> AdmitResult<Value> {
    if !required {
        return Ok(json!({
            "required": false,
            "reason": "proposal_only_e0_non_hard_realtime",
        }));
    }

    let deployment = required_assurance_object(request, "deployment_assurance")?;
    let supported_evidence_level = required_assurance_enum(
        deployment,
        "supported_evidence_level",
        ASSURANCE_EVIDENCE_LEVELS,
    )?;
    if assurance_level_rank(&supported_evidence_level)
        < assurance_level_rank(asserted_evidence_level)
    {
        return Err(authority_error(
            "physical_action_assurance_evidence_level_overclaim",
            "The asserted physical assurance evidence level exceeds the level supported by the bound deployment evidence.",
            json!({
                "asserted_assurance_evidence_level": asserted_evidence_level,
                "supported_evidence_level": supported_evidence_level,
            }),
        ));
    }

    let assurance_evidence_bundle_ref = required_assurance_ref(
        deployment,
        "assurance_evidence_bundle_ref",
        &["assurance-evidence://"],
    )?;
    required_assurance_hash(deployment, "assurance_evidence_bundle_hash")?;
    require_assurance_binding(
        deployment,
        "target_system_ref",
        target_system_ref,
        "physical_action_deployment_target_mismatch",
    )?;
    require_assurance_binding(
        deployment,
        "safety_envelope_ref",
        safety_envelope_ref,
        "physical_action_deployment_safety_envelope_mismatch",
    )?;
    required_assurance_hash(deployment, "safety_envelope_hash")?;
    required_assurance_ref(
        deployment,
        "runtime_graph_manifest_ref",
        &["embodied-runtime-graph-manifest://"],
    )?;
    required_assurance_hash(deployment, "runtime_graph_manifest_hash")?;
    let operational_design_domain_ref = required_assurance_ref(
        deployment,
        "operational_design_domain_ref",
        &["policy://", "artifact://"],
    )?;
    let operational_design_domain_hash =
        required_assurance_hash(deployment, "operational_design_domain_hash")?;
    required_assurance_ref(deployment, "hardware_configuration_ref", &["artifact://"])?;
    required_assurance_hash(deployment, "hardware_configuration_hash")?;
    required_assurance_ref(deployment, "controller_firmware_ref", &["artifact://"])?;
    required_assurance_hash(deployment, "controller_firmware_hash")?;
    let deployment_controller_binding_ref = required_assurance_ref(
        deployment,
        "controller_binding_ref",
        &["controller-binding://"],
    )?;
    require_assurance_binding(
        deployment,
        "controller_binding_ref",
        controller_binding_ref,
        "physical_action_controller_binding_mismatch",
    )?;
    required_assurance_ref(
        deployment,
        "safety_monitor_ref",
        &["module://", "controller://", "artifact://"],
    )?;
    required_assurance_hash(deployment, "safety_monitor_hash")?;
    required_assurance_ref(
        deployment,
        "command_switch_ref",
        &["module://", "controller://", "artifact://"],
    )?;
    required_assurance_hash(deployment, "command_switch_hash")?;
    required_assurance_ref(
        deployment,
        "recovery_controller_ref",
        &["module://", "controller://", "artifact://"],
    )?;
    required_assurance_hash(deployment, "recovery_controller_hash")?;
    required_assurance_ref(
        deployment,
        "recoverable_region_evidence_ref",
        &["artifact://", "evidence://", "assurance-evidence://"],
    )?;
    required_assurance_hash(deployment, "recoverable_region_evidence_hash")?;
    let minimum_recoverable_margin =
        required_nonnegative_number(deployment, "minimum_recoverable_margin")?;
    let current_recoverable_margin =
        required_nonnegative_number(deployment, "current_recoverable_margin")?;
    if current_recoverable_margin < minimum_recoverable_margin {
        return Err(authority_error(
            "physical_action_recoverable_region_margin_insufficient",
            "The current deployment state is outside the admitted recoverable-region margin.",
            json!({
                "minimum_recoverable_margin": minimum_recoverable_margin,
                "current_recoverable_margin": current_recoverable_margin,
            }),
        ));
    }
    required_assurance_string(deployment, "recoverable_margin_unit")?;
    required_assurance_ref(deployment, "switch_proof_test_receipt_ref", &["receipt://"])?;
    let switch_proof_test_age_ms =
        required_nonnegative_integer(deployment, "switch_proof_test_age_ms")?;
    let switch_proof_test_max_age_ms =
        required_positive_integer(deployment, "switch_proof_test_max_age_ms")?;
    if switch_proof_test_age_ms > switch_proof_test_max_age_ms {
        return Err(authority_error(
            "physical_action_switch_proof_test_stale",
            "The command-switch proof test is older than the cadence admitted by the SafetyEnvelope.",
            json!({
                "switch_proof_test_age_ms": switch_proof_test_age_ms,
                "switch_proof_test_max_age_ms": switch_proof_test_max_age_ms,
            }),
        ));
    }
    required_assurance_ref(deployment, "safe_switch_receipt_ref", &["receipt://"])?;
    required_assurance_ref(
        deployment,
        "recovery_entry_test_receipt_ref",
        &["receipt://"],
    )?;

    let timing = required_assurance_object(request, "runtime_assurance_timing")?;
    let monitor_period_us = required_positive_integer(timing, "monitor_period_us")?;
    let monitor_jitter_us = required_nonnegative_integer(timing, "monitor_jitter_us")?;
    let total_bound_us = required_positive_integer(timing, "total_observation_to_switch_bound_us")?;
    let demonstrated_us =
        required_positive_integer(timing, "demonstrated_observation_to_switch_bound_us")?;
    if demonstrated_us > total_bound_us {
        return Err(authority_error(
            "physical_action_observation_to_switch_bound_exceeded",
            "The demonstrated observation-to-safe-switch path is later than the admitted total bound.",
            json!({
                "demonstrated_observation_to_switch_bound_us": demonstrated_us,
                "total_observation_to_switch_bound_us": total_bound_us,
            }),
        ));
    }
    if monitor_period_us.saturating_add(monitor_jitter_us) > total_bound_us {
        return Err(authority_error(
            "physical_action_monitor_release_bound_exceeded",
            "Monitor period plus release jitter exceeds the admitted observation-to-safe-switch bound.",
            json!({
                "monitor_period_us": monitor_period_us,
                "monitor_jitter_us": monitor_jitter_us,
                "total_observation_to_switch_bound_us": total_bound_us,
            }),
        ));
    }
    required_assurance_ref(timing, "graph_timing_chain_ref", &["artifact://"])?;
    required_assurance_hash(timing, "graph_timing_chain_hash")?;
    let timing_evidence_mode =
        required_assurance_enum(timing, "evidence_mode", TIMING_EVIDENCE_MODES)?;
    if execution_timing_class == "hard_realtime" && timing_evidence_mode != "hard_realtime_analytic"
    {
        return Err(authority_error(
            "physical_action_hard_realtime_analytic_evidence_required",
            "Hard-real-time physical admission requires graph-scoped analytic schedulability and WCET evidence.",
            json!({ "evidence_mode": timing_evidence_mode }),
        ));
    }
    match timing_evidence_mode.as_str() {
        "hard_realtime_analytic" => {
            required_assurance_ref(
                timing,
                "analytic_schedulability_evidence_ref",
                &["artifact://", "evidence://"],
            )?;
            required_assurance_hash(timing, "analytic_schedulability_evidence_hash")?;
        }
        "bounded_soft_tail" => {
            required_assurance_ref(
                timing,
                "tail_latency_evidence_ref",
                &["artifact://", "evidence://"],
            )?;
            required_assurance_hash(timing, "tail_latency_evidence_hash")?;
            required_assurance_string(timing, "tail_percentile")?;
            required_positive_integer(timing, "tail_sample_count")?;
        }
        _ => unreachable!("validated timing evidence mode"),
    }

    let odd = required_assurance_object(request, "operational_design_domain_assurance")?;
    require_assurance_binding(
        odd,
        "operational_design_domain_ref",
        &operational_design_domain_ref,
        "physical_action_operational_design_domain_binding_mismatch",
    )?;
    require_assurance_binding(
        odd,
        "operational_design_domain_hash",
        &operational_design_domain_hash,
        "physical_action_operational_design_domain_binding_mismatch",
    )?;
    let odd_state = required_assurance_enum(odd, "state", ODD_STATES)?;
    let odd_exit_response = required_assurance_enum(odd, "exit_response", ODD_EXIT_RESPONSES)?;
    required_positive_integer(odd, "exit_response_deadline_ms")?;
    let operator_takeover_budget_ms =
        required_positive_integer(odd, "operator_takeover_budget_ms")?;
    required_assurance_ref(odd, "current_compliance_receipt_ref", &["receipt://"])?;
    let odd_monitor_refs = required_assurance_string_array(odd, "monitor_refs")?;
    if odd_monitor_refs.is_empty() {
        return Err(missing_assurance_field("monitor_refs"));
    }
    for monitor_ref in &odd_monitor_refs {
        require_assurance_ref_value(
            monitor_ref,
            "monitor_refs",
            &["module://", "controller://", "artifact://"],
        )?;
    }
    let attribute_measurements = odd
        .get("attribute_measurements")
        .and_then(Value::as_array)
        .ok_or_else(|| missing_assurance_field("attribute_measurements"))?;
    if attribute_measurements.is_empty() {
        return Err(missing_assurance_field("attribute_measurements"));
    }
    let mut attribute_outside = false;
    for (index, measurement) in attribute_measurements.iter().enumerate() {
        let Some(measurement) = measurement.as_object() else {
            return Err(invalid_assurance_field(
                "attribute_measurements",
                json!({ "index": index }),
            ));
        };
        required_assurance_string(measurement, "attribute")?;
        required_assurance_string(measurement, "unit")?;
        required_assurance_ref(measurement, "monitor_ref", &["module://", "controller://"])?;
        required_assurance_ref(measurement, "measurement_receipt_ref", &["receipt://"])?;
        let observed = required_finite_number(measurement, "observed_value")?;
        let permitted_min = required_finite_number(measurement, "permitted_min")?;
        let permitted_max = required_finite_number(measurement, "permitted_max")?;
        if permitted_min > permitted_max || observed < permitted_min || observed > permitted_max {
            attribute_outside = true;
        }
    }
    if odd_state != "inside" || attribute_outside {
        return Err(authority_error(
            "physical_action_operational_design_domain_exit",
            "Live physical admission is denied because the measured operating state is exiting or outside the admitted ODD.",
            json!({
                "state": odd_state,
                "attribute_outside": attribute_outside,
                "exit_response": odd_exit_response,
            }),
        ));
    }

    let safety_inputs = required_assurance_array(request, "safety_input_bindings")?;
    if safety_inputs.is_empty() {
        return Err(missing_assurance_field("safety_input_bindings"));
    }
    let mut assured_non_learned_input = false;
    for (index, input) in safety_inputs.iter().enumerate() {
        let Some(input) = input.as_object() else {
            return Err(invalid_assurance_field(
                "safety_input_bindings",
                json!({ "index": index }),
            ));
        };
        required_assurance_ref(
            input,
            "stream_contract_ref",
            &["physical-stream-contract://"],
        )?;
        required_assurance_hash(input, "stream_contract_hash")?;
        required_assurance_ref(input, "producer_ref", &["sensor://", "controller://"])?;
        required_assurance_ref(input, "failure_domain_ref", &["failure-domain://"])?;
        required_assurance_ref(input, "current_evidence_receipt_ref", &["receipt://"])?;
        let source_kind = required_assurance_enum(input, "source_kind", SAFETY_INPUT_SOURCE_KINDS)?;
        let assurance_posture =
            required_assurance_enum(input, "assurance_posture", SAFETY_INPUT_ASSURANCE_POSTURES)?;
        if assurance_posture != "unassured_supplemental" {
            required_assurance_ref(
                input,
                "assurance_evidence_ref",
                &["artifact://", "evidence://", "assurance-evidence://"],
            )?;
            required_assurance_hash(input, "assurance_evidence_hash")?;
        }
        if source_kind != "learned" && assurance_posture != "unassured_supplemental" {
            assured_non_learned_input = true;
        }
    }
    if !assured_non_learned_input {
        return Err(authority_error(
            "physical_action_assured_safety_input_required",
            "Unassured learned sensing may be supplemental but cannot be the sole input to the physical safety monitor or switch.",
            json!({ "safety_input_count": safety_inputs.len() }),
        ));
    }

    let writer = required_assurance_object(request, "writer_and_restart_assurance")?;
    let restart_posture = required_assurance_enum(writer, "restart_posture", RESTART_POSTURES)?;
    required_assurance_ref(writer, "restart_unarmed_receipt_ref", &["receipt://"])?;
    let active_writer_state = required_assurance_string(writer, "active_writer_state")?;
    if active_writer_state != "exclusive_active" {
        return Err(authority_error(
            "physical_action_exclusive_writer_required",
            "Physical admission requires exactly one fenced active actuator writer.",
            json!({ "active_writer_state": active_writer_state }),
        ));
    }
    required_assurance_ref(writer, "active_writer_lease_ref", &["resource-lease://"])?;
    required_nonnegative_integer(writer, "active_writer_fencing_epoch")?;
    required_assurance_hash(writer, "active_writer_fencing_token_hash")?;
    let standby_writer_posture =
        required_assurance_enum(writer, "standby_writer_posture", STANDBY_WRITER_POSTURES)?;
    let standby_writer_refs = required_assurance_string_array(writer, "standby_writer_refs")?;
    for standby_ref in &standby_writer_refs {
        require_assurance_ref_value(
            standby_ref,
            "standby_writer_refs",
            &["local_control_supervisor://"],
        )?;
    }
    if standby_writer_posture == "absent" && !standby_writer_refs.is_empty() {
        return Err(invalid_assurance_field(
            "standby_writer_posture",
            json!({ "standby_writer_refs": standby_writer_refs }),
        ));
    }
    if standby_writer_posture != "absent" {
        if standby_writer_refs.is_empty() {
            return Err(missing_assurance_field("standby_writer_refs"));
        }
        required_assurance_ref(writer, "standby_safe_takeover_receipt_ref", &["receipt://"])?;
    }

    let teleoperation = match request.get("teleoperation_assurance") {
        None | Some(Value::Null) => Value::Null,
        Some(value) => {
            let Some(teleop) = value.as_object() else {
                return Err(invalid_assurance_field(
                    "teleoperation_assurance",
                    json!({}),
                ));
            };
            let active = required_boolean(teleop, "active")?;
            if active {
                required_assurance_ref(
                    teleop,
                    "link_contract_ref",
                    &["physical-stream-contract://"],
                )?;
                required_assurance_hash(teleop, "link_contract_hash")?;
                required_assurance_ref(
                    teleop,
                    "operator_authority_ref",
                    &["grant://", "approval://"],
                )?;
                required_assurance_ref(teleop, "authentication_receipt_ref", &["receipt://"])?;
                required_assurance_ref(
                    teleop,
                    "deadman_contract_ref",
                    &["policy://", "artifact://"],
                )?;
                required_assurance_ref(teleop, "deadman_receipt_ref", &["receipt://"])?;
                required_assurance_ref(teleop, "arbitration_policy_ref", &["policy://"])?;
                required_assurance_enum(teleop, "on_link_loss", TELEOP_LOSS_RESPONSES)?;
                let link_state = required_assurance_enum(teleop, "link_state", TELEOP_LINK_STATES)?;
                let auth_state =
                    required_assurance_enum(teleop, "authentication_state", TELEOP_AUTH_STATES)?;
                let deadman_state =
                    required_assurance_enum(teleop, "deadman_state", TELEOP_DEADMAN_STATES)?;
                if link_state != "healthy" {
                    return Err(authority_error(
                        "physical_action_teleoperation_link_unavailable",
                        "Teleoperation cannot remain admitted after its bounded control link degrades or is lost.",
                        json!({ "link_state": link_state }),
                    ));
                }
                if auth_state != "verified" {
                    return Err(authority_error(
                        "physical_action_teleoperation_authentication_invalid",
                        "Teleoperation requires current verified operator authentication and authority.",
                        json!({ "authentication_state": auth_state }),
                    ));
                }
                if deadman_state != "asserted" {
                    return Err(authority_error(
                        "physical_action_teleoperation_deadman_not_asserted",
                        "Teleoperation requires a current asserted deadman signal.",
                        json!({ "deadman_state": deadman_state }),
                    ));
                }
                let observed_round_trip_ms =
                    required_nonnegative_integer(teleop, "observed_round_trip_ms")?;
                let max_round_trip_ms = required_positive_integer(teleop, "max_round_trip_ms")?;
                if observed_round_trip_ms > max_round_trip_ms {
                    return Err(authority_error(
                        "physical_action_teleoperation_link_latency_exceeded",
                        "Teleoperation link latency exceeds its admitted control bound.",
                        json!({
                            "observed_round_trip_ms": observed_round_trip_ms,
                            "max_round_trip_ms": max_round_trip_ms,
                        }),
                    ));
                }
                let teleop_takeover_budget_ms =
                    required_positive_integer(teleop, "operator_takeover_budget_ms")?;
                if teleop_takeover_budget_ms > operator_takeover_budget_ms {
                    return Err(authority_error(
                        "physical_action_operator_takeover_budget_exceeded",
                        "The teleoperation takeover budget exceeds the bound admitted by the operating-domain assurance.",
                        json!({
                            "teleoperation_operator_takeover_budget_ms": teleop_takeover_budget_ms,
                            "odd_operator_takeover_budget_ms": operator_takeover_budget_ms,
                        }),
                    ));
                }
            }
            value.clone()
        }
    };

    Ok(json!({
        "required": true,
        "asserted_evidence_level": asserted_evidence_level,
        "supported_evidence_level": supported_evidence_level,
        "assurance_evidence_bundle_ref": assurance_evidence_bundle_ref,
        "controller_binding_ref": deployment_controller_binding_ref,
        "deployment_binding": Value::Object(deployment.clone()),
        "runtime_assurance_timing": Value::Object(timing.clone()),
        "operational_design_domain_assurance": Value::Object(odd.clone()),
        "safety_input_bindings": safety_inputs,
        "writer_and_restart_assurance": Value::Object(writer.clone()),
        "teleoperation_assurance": teleoperation,
        "restart_posture": restart_posture,
    }))
}

fn assurance_level_rank(level: &str) -> u8 {
    match level {
        "E0" => 0,
        "E1" => 1,
        "E2" => 2,
        "E3" => 3,
        _ => 0,
    }
}

fn required_assurance_object<'a>(
    value: &'a Value,
    field: &str,
) -> AdmitResult<&'a Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| missing_assurance_field(field))
}

fn required_assurance_array<'a>(value: &'a Value, field: &str) -> AdmitResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| missing_assurance_field(field))
}

fn required_assurance_string_array(
    object: &Map<String, Value>,
    field: &str,
) -> AdmitResult<Vec<String>> {
    let Some(items) = object.get(field).and_then(Value::as_array) else {
        return Err(missing_assurance_field(field));
    };
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(item) = item.as_str().filter(|item| !item.trim().is_empty()) else {
            return Err(invalid_assurance_field(field, json!({ "index": index })));
        };
        out.push(item.to_string());
    }
    Ok(out)
}

fn required_assurance_string(object: &Map<String, Value>, field: &str) -> AdmitResult<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| missing_assurance_field(field))
}

fn required_assurance_enum(
    object: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> AdmitResult<String> {
    let value = required_assurance_string(object, field)?;
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(invalid_assurance_field(
            field,
            json!({ "value": value, "allowed_values": allowed }),
        ))
    }
}

fn required_assurance_ref(
    object: &Map<String, Value>,
    field: &str,
    allowed_prefixes: &[&str],
) -> AdmitResult<String> {
    let value = required_assurance_string(object, field)?;
    require_assurance_ref_value(&value, field, allowed_prefixes)?;
    Ok(value)
}

fn require_assurance_ref_value(
    value: &str,
    field: &str,
    allowed_prefixes: &[&str],
) -> AdmitResult<()> {
    if allowed_prefixes
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        Ok(())
    } else {
        Err(invalid_assurance_field(
            field,
            json!({ "value": value, "allowed_prefixes": allowed_prefixes }),
        ))
    }
}

fn validate_resource_group_bindings(value: Option<&Value>) -> AdmitResult<Vec<Value>> {
    let Some(bindings) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut normalized = Vec::with_capacity(bindings.len());
    let mut seen = std::collections::BTreeSet::new();
    for (index, binding) in bindings.iter().enumerate() {
        let Some(binding) = binding.as_object() else {
            return Err(invalid_assurance_field(
                "resource_group_bindings",
                json!({ "index": index, "required": "object" }),
            ));
        };
        let group_revision_ref = required_assurance_ref(
            binding,
            "group_revision_ref",
            &["embodied-resource-group-revision://"],
        )?;
        let membership_closure_hash = required_assurance_hash(binding, "membership_closure_hash")?;
        let unit_refs = required_resource_group_ref_array(
            binding,
            "unit_refs",
            &[
                "robot://",
                "drone://",
                "device://",
                "facility://",
                "facility-system://",
                "vehicle://",
            ],
        )?;
        let controller_binding_refs = required_resource_group_ref_array(
            binding,
            "controller_binding_refs",
            &["controller-binding://"],
        )?;
        let sensor_refs =
            required_resource_group_ref_array(binding, "sensor_refs", &["sensor://"])?;
        let actuator_refs =
            required_resource_group_ref_array(binding, "actuator_refs", &["actuator://"])?;
        let physical_zone_refs =
            required_resource_group_ref_array(binding, "physical_zone_refs", &["zone://"])?;
        let emergency_stop_authority_refs = required_resource_group_ref_array(
            binding,
            "emergency_stop_authority_refs",
            &["estop://"],
        )?;
        if !seen.insert(group_revision_ref.clone()) {
            return Err(invalid_assurance_field(
                "resource_group_bindings",
                json!({ "index": index, "duplicate_group_revision_ref": group_revision_ref }),
            ));
        }
        normalized.push(json!({
            "group_revision_ref": group_revision_ref,
            "membership_closure_hash": membership_closure_hash,
            "unit_refs": unit_refs,
            "controller_binding_refs": controller_binding_refs,
            "sensor_refs": sensor_refs,
            "actuator_refs": actuator_refs,
            "physical_zone_refs": physical_zone_refs,
            "emergency_stop_authority_refs": emergency_stop_authority_refs,
        }));
    }
    Ok(normalized)
}

fn required_resource_group_ref_array(
    binding: &Map<String, Value>,
    field: &str,
    allowed_prefixes: &[&str],
) -> AdmitResult<Vec<String>> {
    let Some(items) = binding.get(field).and_then(Value::as_array) else {
        return Err(missing_assurance_field(field));
    };
    if items.is_empty() {
        return Err(missing_assurance_field(field));
    }
    let mut refs = std::collections::BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let Some(reference) = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Err(invalid_assurance_field(field, json!({ "index": index })));
        };
        require_assurance_ref_value(reference, field, allowed_prefixes)?;
        if !refs.insert(reference.to_string()) {
            return Err(invalid_assurance_field(
                field,
                json!({ "index": index, "duplicate_ref": reference }),
            ));
        }
    }
    Ok(refs.into_iter().collect())
}

fn require_resource_group_member(
    bindings: &[Value],
    fields: &[&str],
    required_ref: &str,
    code: &str,
) -> AdmitResult<()> {
    let contains = bindings.iter().any(|binding| {
        fields.iter().any(|field| {
            binding
                .get(*field)
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|reference| reference.as_str() == Some(required_ref))
                })
        })
    });
    if contains {
        Ok(())
    } else {
        Err(authority_error(
            code,
            "The expanded embodied-resource-group closure does not contain an exact live-action binding.",
            json!({ "required_ref": required_ref, "searched_fields": fields }),
        ))
    }
}

fn required_assurance_hash(object: &Map<String, Value>, field: &str) -> AdmitResult<String> {
    let value = required_assurance_string(object, field)?;
    if is_sha256_hash(&value) {
        Ok(value)
    } else {
        Err(invalid_assurance_field(
            field,
            json!({ "required_format": "sha256:<64 hex characters>" }),
        ))
    }
}

fn is_sha256_hash(value: &str) -> bool {
    let digest = value.strip_prefix("sha256:").unwrap_or_default();
    digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn require_sha256_hash(value: &str, field: &str) -> AdmitResult<()> {
    if is_sha256_hash(value) {
        Ok(())
    } else {
        Err(RuntimePhysicalActionIntentAdmissionError::new(
            400,
            format!("physical_action_{field}_invalid"),
            format!("Physical-action {field} must use sha256:<64 hex characters>."),
            json!({ "field": field, "required_format": "sha256:<64 hex characters>" }),
        ))
    }
}

fn required_positive_integer(object: &Map<String, Value>, field: &str) -> AdmitResult<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid_assurance_field(field, json!({ "required": "positive_integer" })))
}

fn required_nonnegative_integer(object: &Map<String, Value>, field: &str) -> AdmitResult<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_assurance_field(field, json!({ "required": "nonnegative_integer" })))
}

fn required_boolean(object: &Map<String, Value>, field: &str) -> AdmitResult<bool> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid_assurance_field(field, json!({ "required": "boolean" })))
}

fn required_finite_number(object: &Map<String, Value>, field: &str) -> AdmitResult<f64> {
    object
        .get(field)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or_else(|| invalid_assurance_field(field, json!({ "required": "finite_number" })))
}

fn required_nonnegative_number(object: &Map<String, Value>, field: &str) -> AdmitResult<f64> {
    required_finite_number(object, field).and_then(|value| {
        if value >= 0.0 {
            Ok(value)
        } else {
            Err(invalid_assurance_field(
                field,
                json!({ "required": "nonnegative_number" }),
            ))
        }
    })
}

fn require_assurance_binding(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
    code: &str,
) -> AdmitResult<()> {
    let actual = required_assurance_string(object, field)?;
    if actual == expected {
        Ok(())
    } else {
        Err(authority_error(
            code,
            "Deployment assurance evidence is not bound to the exact physical admission subject.",
            json!({ "field": field, "expected": expected, "actual": actual }),
        ))
    }
}

fn missing_assurance_field(field: &str) -> RuntimePhysicalActionIntentAdmissionError {
    authority_error(
        "physical_action_deployment_assurance_required",
        "Live, hard-real-time, and E1+ physical admission requires exact deployment-bound assurance evidence.",
        json!({ "missing_field": field }),
    )
}

fn missing_execution_binding(field: &str) -> RuntimePhysicalActionIntentAdmissionError {
    authority_error(
        "physical_action_execution_binding_required",
        "Live physical admission requires an exact command, controller, and idempotency binding before invocation.",
        json!({ "missing_field": field }),
    )
}

fn invalid_assurance_field(
    field: &str,
    details: Value,
) -> RuntimePhysicalActionIntentAdmissionError {
    authority_error(
        "physical_action_deployment_assurance_invalid",
        "Deployment-bound physical assurance evidence is malformed or internally inconsistent.",
        json!({ "field": field, "details": details }),
    )
}

/// Serialize a validated positive-integer-valued f64 as a JSON number (integer when it fits i64,
/// matching JSON.stringify's full-decimal rendering). Values beyond i64 (absurd latencies, error-
/// detail-only) fall back to f64 — serde cannot emit them as a JSON integer without arbitrary
/// precision.
fn latency_to_json(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9_223_372_036_854_775_808.0 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

fn default_value(value: Option<&Value>, fallback: &str) -> Value {
    match value {
        None | Some(Value::Null) => Value::String(fallback.to_string()),
        Some(value) => value.clone(),
    }
}

fn assert_no_retired_aliases(request: &Value) -> AdmitResult<()> {
    let empty = Map::new();
    let object = request.as_object().unwrap_or(&empty);
    let retired: Vec<String> = RETIRED_ALIASES
        .iter()
        .filter(|alias| object.contains_key(**alias))
        .map(|alias| alias.to_string())
        .collect();
    if retired.is_empty() {
        return Ok(());
    }
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_request_aliases_retired".to_string(),
        "Physical-action admission accepts only canonical snake_case request fields.".to_string(),
        json!({ "retired_aliases": retired }),
    ))
}

/// Mirror JS `enumValue` — optionalString (trim) + membership; 400 `_invalid`; dynamic field key.
fn enum_value(value: Option<&Value>, field: &str, allowed: &[&str]) -> AdmitResult<String> {
    let normalized = optional_value(value);
    match &normalized {
        Some(value) if allowed.contains(&value.as_str()) => Ok(value.clone()),
        _ => {
            let mut details = Map::new();
            details.insert(
                field.to_string(),
                normalized.map(Value::String).unwrap_or(Value::Null),
            );
            details.insert("allowed_values".to_string(), json!(allowed));
            Err(RuntimePhysicalActionIntentAdmissionError::new(
                400,
                format!("physical_action_{field}_invalid"),
                format!("Physical-action admission requires a valid {field}."),
                Value::Object(details),
            ))
        }
    }
}

/// Mirror JS `requiredString` — optionalString then 400 `_required`.
fn required_string(value: Option<&Value>, field: &str) -> AdmitResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimePhysicalActionIntentAdmissionError::new(
            400,
            format!("physical_action_{field}_required"),
            format!("Physical-action admission requires {field}."),
            json!({ "field": field }),
        )
    })
}

/// Mirror JS `requirePrefix` — 400 `_{field}_invalid`; details `{[field]: value}`.
fn require_prefix(value: &str, prefix: &str, field: &str) -> AdmitResult<()> {
    if value.starts_with(prefix) {
        return Ok(());
    }
    let mut details = Map::new();
    details.insert(field.to_string(), Value::String(value.to_string()));
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        format!("physical_action_{field}_invalid"),
        format!("Physical-action {field} must start with {prefix}."),
        Value::Object(details),
    ))
}

fn require_target_prefix(value: &str) -> AdmitResult<()> {
    if TARGET_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return Ok(());
    }
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_target_system_ref_invalid".to_string(),
        "Physical-action target_system_ref must identify a robot, facility, vehicle, device, drone, or actuator.".to_string(),
        json!({ "target_system_ref": value, "allowed_prefixes": TARGET_PREFIXES }),
    ))
}

fn require_actor_ref(value: &str) -> AdmitResult<()> {
    if ACTOR_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return Ok(());
    }
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_actor_id_invalid".to_string(),
        "Physical-action actor_id must identify a worker, service engine, or runtime.".to_string(),
        json!({ "actor_id": value, "allowed_prefixes": ACTOR_PREFIXES }),
    ))
}

fn require_refs(refs: &[String], field: &str) -> AdmitResult<()> {
    if !refs.is_empty() {
        return Ok(());
    }
    Err(authority_error(
        &format!("physical_action_{field}_required"),
        &format!("Physical-action admission requires {field}."),
        json!({ "field": field }),
    ))
}

fn authority_error(
    code: &str,
    message: &str,
    details: Value,
) -> RuntimePhysicalActionIntentAdmissionError {
    RuntimePhysicalActionIntentAdmissionError::new(
        403,
        code.to_string(),
        message.to_string(),
        details,
    )
}

/// Mirror JS `optionalPositiveInteger`: null/undefined/"" → None; Number(value) coercion; must be
/// a positive integer else 400 (details carry the ORIGINAL raw value).
fn optional_positive_integer(value: Option<&Value>) -> AdmitResult<Option<f64>> {
    let raw = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(string)) if string.is_empty() => return Ok(None),
        Some(value) => value,
    };
    let number = js_number_coerce(raw);
    if number.is_finite() && number.fract() == 0.0 && number > 0.0 {
        return Ok(Some(number));
    }
    Err(RuntimePhysicalActionIntentAdmissionError::new(
        400,
        "physical_action_emergency_stop_max_latency_ms_invalid".to_string(),
        "Physical-action emergency_stop_max_latency_ms must be a positive integer when supplied."
            .to_string(),
        json!({ "emergency_stop_max_latency_ms": raw }),
    ))
}

/// Mirror JS `Number(value)` (ToNumber): bool→0/1; number verbatim; string via ToNumber(string);
/// array → ToNumber(String(array)); object → NaN.
fn js_number_coerce(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(boolean) => {
            if *boolean {
                1.0
            } else {
                0.0
            }
        }
        Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
        Value::String(string) => js_string_to_number(string),
        Value::Array(_) => js_string_to_number(&js_string_coerce(value)),
        Value::Object(_) => f64::NAN,
    }
}

/// Mirror JS ToNumber(string): trim; ""→0; ±Infinity; 0x/0o/0b radix; else a decimal literal
/// (rejecting any char outside [0-9 + - . e E] so "inf"/"nan"/"1_0" → NaN, matching JS).
fn js_string_to_number(string: &str) -> f64 {
    let trimmed = js_trim(string);
    if trimmed.is_empty() {
        return 0.0;
    }
    match trimmed {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if let Some(radix_value) = parse_radix_literal(trimmed) {
        return radix_value;
    }
    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, '+' | '-' | '.' | 'e' | 'E'))
    {
        trimmed.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

/// JS numeric string non-decimal radix literals: 0x.. (16), 0o.. (8), 0b.. (2). No sign allowed.
fn parse_radix_literal(trimmed: &str) -> Option<f64> {
    let lowered_prefix = trimmed.get(0..2)?.to_ascii_lowercase();
    let radix = match lowered_prefix.as_str() {
        "0x" => 16,
        "0o" => 8,
        "0b" => 2,
        _ => return None,
    };
    let digits = &trimmed[2..];
    if digits.is_empty() {
        return Some(f64::NAN);
    }
    match u128::from_str_radix(digits, radix) {
        Ok(value) => Some(value as f64),
        Err(_) => Some(f64::NAN),
    }
}

/// Mirror JS `optionalString`: String(value).trim(), None when null/absent/blank. Uses the
/// ECMAScript trim set (js_trim), not Rust's Unicode White_Space (which differs on U+FEFF/U+0085).
fn optional_value(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => {
            let coerced = js_string_coerce(value);
            let trimmed = js_trim(&coerced);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    }
}

/// JS `String.prototype.trim` whitespace set: WhiteSpace (TAB/VT/FF/SP/NBSP/ZWNBSP + Unicode Zs)
/// ∪ LineTerminator (LF/CR/LS/PS). NOTE this differs from Rust's `char::is_whitespace`
/// (Unicode White_Space): JS trims U+FEFF (BOM) but NOT U+0085 (NEL); Rust is the reverse.
fn is_js_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

/// Mirror JS `booleanValue`: true/false or "true"/"false" (case-insensitive), else None.
fn boolean_value(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) => match value.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Mirror the LOCAL `uniqueStrings(normalizeArray(value))`: truthy raw items, `String()`-coerced
/// (NO trim), drop blanks, first-seen dedup. Non-array → empty.
fn unique_strings_raw(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !is_truthy(item) {
            continue;
        }
        let coerced = js_string_coerce(item);
        if coerced.is_empty() {
            continue;
        }
        if !out.contains(&coerced) {
            out.push(coerced);
        }
    }
    out
}

/// JS truthiness for filter(Boolean): null/false/0/""/NaN falsy; objects+arrays truthy.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(boolean) => *boolean,
        Value::Number(number) => number.as_f64().map(|float| float != 0.0).unwrap_or(false),
        Value::String(string) => !string.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// Mirror JS `String(value)`: scalars exactly; arrays comma-join coerced elements (null→empty);
/// objects → "[object Object]". Numbers via the ECMAScript Number→String algorithm.
fn js_string_coerce(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => js_number_to_string(number.as_f64().unwrap_or(0.0)),
        Value::String(string) => string.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string_coerce(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// Mirror ECMAScript `Number::toString` (base 10) for a finite f64.
fn js_number_to_string(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    let negative = value < 0.0;
    let magnitude = value.abs();
    let exp_form = format!("{magnitude:e}");
    let (mantissa, exp_str) = exp_form.split_once('e').unwrap_or((exp_form.as_str(), "0"));
    let exp: i32 = exp_str.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|ch| *ch != '.').collect();
    let k = digits.len() as i32;
    let n = exp + 1;

    let body = if k <= n && n <= 21 {
        let mut out = digits;
        for _ in 0..(n - k) {
            out.push('0');
        }
        out
    } else if 0 < n && n <= 21 {
        let (head, tail) = digits.split_at(n as usize);
        format!("{head}.{tail}")
    } else if -6 < n && n <= 0 {
        let mut out = String::from("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
        out
    } else {
        let mut chars = digits.chars();
        let first = chars.next().unwrap_or('0');
        let rest: String = chars.collect();
        let mut out = String::new();
        out.push(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(&rest);
        }
        out.push('e');
        let e = n - 1;
        if e >= 0 {
            out.push('+');
            out.push_str(&e.to_string());
        } else {
            out.push('-');
            out.push_str(&(-e).to_string());
        }
        out
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}

/// Mirror the SHARED `safeId`: collapse runs outside [A-Za-z0-9_.-] to a single `_`.
fn safe_id(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_run = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

#[cfg(test)]
pub(crate) fn physical_action_test_request() -> Value {
    tests::base_request()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: char) -> String {
        format!("sha256:{}", seed.to_string().repeat(64))
    }

    pub(super) fn base_request() -> Value {
        let mut request = json!({
            "intent_id": "intent://physical/carwash/prep-vehicle-001",
            "actor_id": "worker://carwash-prep-humanoid",
            "task_id": "task://carwash/prep-vehicle-001",
            "domain_ref": "domain://carwash/vehicle-prep",
            "target_system_ref": "robot://bay-3/humanoid-1",
            "resource_group_bindings": [{
                "group_revision_ref": "embodied-resource-group-revision://carwash/bay-3/v1",
                "membership_closure_hash": hash('a'),
                "unit_refs": ["robot://bay-3/humanoid-1"],
                "controller_binding_refs": ["controller-binding://carwash/bay-3/humanoid-1/v1"],
                "sensor_refs": ["sensor://carwash/bay-3/light-curtain"],
                "actuator_refs": ["actuator://carwash/bay-3/humanoid-1/arm"],
                "physical_zone_refs": ["zone://carwash/bay-3"],
                "emergency_stop_authority_refs": ["estop://carwash/bay-3"],
            }],
            "action_kind": "manipulation",
            "risk_class": "physical_action",
            "execution_phase": "command_issued",
            "requested_primitives": ["prim:physical.actuate"],
            "requested_scopes": ["scope:physical.actuate"],
            "physical_action_policy_ref": "policy://physical/carwash-prep",
            "safety_envelope_ref": "safety://carwash/bay-3",
            "human_supervision_policy_ref": "supervision://carwash/on-loop",
            "supervision_mode": "human_on_loop",
            "human_supervisor_refs": ["user://operator/bay-3"],
            "emergency_stop_authority_ref": "estop://carwash/bay-3",
            "emergency_stop_tested": true,
            "emergency_stop_max_latency_ms": 250,
            "sensor_evidence_receipt_refs": ["receipt://sensor/bay-3/preflight"],
            "actuator_command_receipt_refs": ["receipt://actuator/bay-3/prep-command"],
            "preflight_receipt_refs": ["receipt://physical/carwash/preflight-001"],
            "segment_commitment_receipt_refs": [],
            "incident_policy_ref": "policy://physical/incidents/carwash",
            "rollback_or_compensation_policy_ref": "policy://physical/compensation/carwash",
            "wallet_approval_ref": "approval://wallet/physical-action/carwash",
            "authority_ref": "grant://wallet/physical-action/carwash",
            "policy_refs": ["policy://physical/carwash-prep", "policy://physical/incidents/carwash"],
            "receipt_refs": ["receipt://sensor/bay-3/preflight", "receipt://actuator/bay-3/prep-command"],
            "agentgres_operation_refs": ["agentgres://operation/physical-action/carwash/prep-vehicle-001"],
            "artifact_refs": ["artifact://sensor-video/bay-3/preflight"],
            "state_root": "state_root:physical:carwash:001",
            "execution_channel": "physical_action_adapter",
            "command_schema_ref": "action-schema://carwash/manipulation/v1",
            "command_payload_hash": hash('0'),
            "controller_binding_ref": "controller-binding://carwash/bay-3/humanoid-1/v1",
            "controller_idempotency_key": "physical-command:carwash:prep-vehicle-001",
            "asserted_assurance_evidence_level": "E1",
            "execution_timing_class": "bounded_soft_realtime",
        });
        request["deployment_assurance"] = json!({
            "supported_evidence_level": "E1",
            "assurance_evidence_bundle_ref": "assurance-evidence://carwash/bay-3/deployment",
            "assurance_evidence_bundle_hash": hash('a'),
            "target_system_ref": "robot://bay-3/humanoid-1",
            "safety_envelope_ref": "safety://carwash/bay-3",
            "safety_envelope_hash": hash('b'),
            "runtime_graph_manifest_ref": "embodied-runtime-graph-manifest://carwash/bay-3/v1",
            "runtime_graph_manifest_hash": hash('c'),
            "operational_design_domain_ref": "policy://odd/carwash/bay-3",
            "operational_design_domain_hash": hash('d'),
            "hardware_configuration_ref": "artifact://hardware/carwash/bay-3/v1",
            "hardware_configuration_hash": hash('e'),
            "controller_firmware_ref": "artifact://firmware/carwash/bay-3/v1",
            "controller_firmware_hash": hash('f'),
            "controller_binding_ref": "controller-binding://carwash/bay-3/humanoid-1/v1",
            "safety_monitor_ref": "module://safety/carwash-monitor/v1",
            "safety_monitor_hash": hash('1'),
            "command_switch_ref": "controller://safety/carwash-switch/v1",
            "command_switch_hash": hash('2'),
            "recovery_controller_ref": "controller://safety/carwash-recovery/v1",
            "recovery_controller_hash": hash('3'),
            "recoverable_region_evidence_ref": "evidence://safety/carwash/recoverable-region/v1",
            "recoverable_region_evidence_hash": hash('4'),
            "minimum_recoverable_margin": 0.15,
            "current_recoverable_margin": 0.42,
            "recoverable_margin_unit": "normalized_safe_set_distance",
            "switch_proof_test_receipt_ref": "receipt://safety/carwash/switch-proof-test",
            "switch_proof_test_age_ms": 3_600_000,
            "switch_proof_test_max_age_ms": 86_400_000,
            "safe_switch_receipt_ref": "receipt://safety/carwash/safe-switch",
            "recovery_entry_test_receipt_ref": "receipt://safety/carwash/recovery-entry",
        });
        request["runtime_assurance_timing"] = json!({
            "monitor_period_us": 5_000,
            "monitor_jitter_us": 500,
            "total_observation_to_switch_bound_us": 25_000,
            "demonstrated_observation_to_switch_bound_us": 18_000,
            "graph_timing_chain_ref": "artifact://timing/carwash/bay-3/chain-v1",
            "graph_timing_chain_hash": hash('5'),
            "evidence_mode": "bounded_soft_tail",
            "tail_latency_evidence_ref": "evidence://timing/carwash/bay-3/tail-v1",
            "tail_latency_evidence_hash": hash('6'),
            "tail_percentile": "p9999",
            "tail_sample_count": 1_000_000,
        });
        request["operational_design_domain_assurance"] = json!({
            "operational_design_domain_ref": "policy://odd/carwash/bay-3",
            "operational_design_domain_hash": hash('d'),
            "state": "inside",
            "exit_response": "switch_to_recovery",
            "exit_response_deadline_ms": 100,
            "operator_takeover_budget_ms": 2_000,
            "current_compliance_receipt_ref": "receipt://odd/carwash/bay-3/current",
            "monitor_refs": ["module://odd/carwash-monitor/v1"],
            "attribute_measurements": [{
                "attribute": "human_separation_distance",
                "unit": "m",
                "monitor_ref": "module://odd/carwash-monitor/v1",
                "measurement_receipt_ref": "receipt://odd/carwash/bay-3/human-distance",
                "observed_value": 2.4,
                "permitted_min": 1.5,
                "permitted_max": 10.0,
            }],
        });
        request["safety_input_bindings"] = json!([{
            "stream_contract_ref": "physical-stream-contract://carwash/light-curtain/v1",
            "stream_contract_hash": hash('7'),
            "producer_ref": "sensor://carwash/bay-3/light-curtain",
            "failure_domain_ref": "failure-domain://carwash/safety-plc",
            "current_evidence_receipt_ref": "receipt://sensor/carwash/light-curtain/current",
            "source_kind": "hardware_interlock",
            "assurance_posture": "assured_independent",
            "assurance_evidence_ref": "evidence://sensor/carwash/light-curtain/assurance",
            "assurance_evidence_hash": hash('8'),
        }]);
        request["writer_and_restart_assurance"] = json!({
            "restart_posture": "no_restart_since_admission",
            "restart_unarmed_receipt_ref": "receipt://runtime/carwash/restart-unarmed",
            "active_writer_state": "exclusive_active",
            "active_writer_lease_ref": "resource-lease://carwash/bay-3/actuator-writer",
            "active_writer_fencing_epoch": 7,
            "active_writer_fencing_token_hash": hash('9'),
            "standby_writer_posture": "safe_takeover_tested",
            "standby_writer_refs": ["local_control_supervisor://carwash/bay-3/standby"],
            "standby_safe_takeover_receipt_ref": "receipt://runtime/carwash/standby-takeover-test",
        });
        request["teleoperation_assurance"] = json!({ "active": false });
        request
    }

    #[test]
    fn admits_physical_action() {
        let admission = RuntimePhysicalActionIntentAdmissionCore
            .admit(&base_request(), "2026-06-17T18:00:00.000Z")
            .expect("admitted");
        assert_eq!(
            admission["schema_version"],
            PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(
            admission["admission_id"],
            "physical-action-admission:intent_physical_carwash_prep-vehicle-001:manipulation"
        );
        assert_eq!(admission["risk_class"], "physical_action");
        assert_eq!(admission["decision"], "admitted");
        assert_eq!(admission["requiresDaemonGate"], true);
        assert_eq!(admission["generic_tool_call_blocked"], true);
        assert_eq!(admission["emergency_stop_max_latency_ms"], json!(250));
    }

    #[test]
    fn blocks_generic_tool_call() {
        let mut request = base_request();
        request["execution_channel"] = json!("tool.invoke");
        request["generic_tool_call"] = json!(true);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "physical_action_generic_tool_call_blocked");
    }

    #[test]
    fn requires_tested_emergency_stop() {
        let mut request = base_request();
        request["emergency_stop_tested"] = json!(false);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.code, "physical_action_emergency_stop_test_required");
        assert_eq!(error.status, 403);
    }

    #[test]
    fn requires_sensor_evidence() {
        let mut request = base_request();
        request["sensor_evidence_receipt_refs"] = json!([]);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "physical_action_sensor_evidence_receipt_refs_required"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn blocks_simulation_only_execution() {
        let mut request = base_request();
        request["simulation_only"] = json!(true);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "physical_action_simulation_not_execution_receipt"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn live_execution_requires_exact_command_and_controller_binding() {
        let mut request = base_request();
        request
            .as_object_mut()
            .unwrap()
            .remove("command_payload_hash");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("live execution must bind the exact command payload");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "physical_action_execution_binding_required");

        let mut mismatch = base_request();
        mismatch["deployment_assurance"]["controller_binding_ref"] =
            json!("controller-binding://carwash/bay-3/different-controller/v1");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&mismatch, "now")
            .expect_err("controller binding substitution must fail closed");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "physical_action_controller_binding_mismatch");
    }

    #[test]
    fn manual_confirm_requires_supervisors() {
        let mut request = base_request();
        request["supervision_mode"] = json!("manual_confirm_each_action");
        request["human_supervisor_refs"] = json!([]);
        request["wallet_approval_ref"] = Value::Null;
        request["authority_ref"] = Value::Null;
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "physical_action_human_supervision_authority_required"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn optional_positive_integer_coercion() {
        // true→1, "0x10"→16, [250]→250, "  10  "→10
        assert_eq!(js_number_coerce(&json!(true)), 1.0);
        assert_eq!(js_number_coerce(&json!("0x10")), 16.0);
        assert_eq!(js_number_coerce(&json!([250])), 250.0);
        assert_eq!(js_number_coerce(&json!("  10  ")), 10.0);
        assert_eq!(js_number_coerce(&json!("0o17")), 15.0);
        assert!(js_number_coerce(&json!({})).is_nan());
        assert!(js_number_coerce(&json!("abc")).is_nan());
        // "" early-returns None
        assert_eq!(optional_positive_integer(Some(&json!(""))).unwrap(), None);
        assert_eq!(optional_positive_integer(None).unwrap(), None);
        // 2.5 → not integer → err
        assert!(optional_positive_integer(Some(&json!(2.5))).is_err());
        // []→0 → not >0 → err
        assert!(optional_positive_integer(Some(&json!([]))).is_err());
    }

    #[test]
    fn latency_over_1000_blocked() {
        let mut request = base_request();
        request["emergency_stop_max_latency_ms"] = json!(1500);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(
            error.code,
            "physical_action_emergency_stop_latency_exceeded"
        );
        assert_eq!(error.status, 403);
    }

    #[test]
    fn bad_intent_prefix_is_400() {
        let mut request = base_request();
        request["intent_id"] = json!("nope://x");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "physical_action_intent_id_invalid");
    }

    #[test]
    fn js_trim_matches_ecmascript_whitespace_set() {
        // JS trims U+FEFF (BOM) but NOT U+0085 (NEL); Rust's is_whitespace is the reverse.
        assert_eq!(js_trim("\u{FEFF}intent://x\u{FEFF}"), "intent://x");
        assert_eq!(js_trim("\u{0085}x\u{0085}"), "\u{0085}x\u{0085}"); // NEL not trimmed
        assert_eq!(js_trim("\u{00A0}x\u{2028}"), "x"); // NBSP + LS trimmed
                                                       // Number("﻿10") === 10 (BOM trimmed before parse).
        assert_eq!(js_number_coerce(&json!("\u{FEFF}10")), 10.0);
    }

    #[test]
    fn latency_to_json_renders_integers() {
        assert_eq!(latency_to_json(250.0), json!(250));
        assert_eq!(latency_to_json(1e16), json!(10_000_000_000_000_000i64));
        // 2^53 renders as a full integer, not 9007199254740992.0
        assert_eq!(
            latency_to_json(9_007_199_254_740_992.0),
            json!(9_007_199_254_740_992i64)
        );
    }

    #[test]
    fn rejects_retired_aliases() {
        let mut request = base_request();
        request["intentId"] = json!("legacy");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("retired");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "physical_action_request_aliases_retired");
    }

    #[test]
    fn rejects_unassured_learned_sensing_as_the_only_safety_input() {
        let mut request = base_request();
        request["safety_input_bindings"] = json!([{
            "stream_contract_ref": "physical-stream-contract://carwash/learned-vision/v1",
            "stream_contract_hash": hash('a'),
            "producer_ref": "sensor://carwash/bay-3/learned-vision",
            "failure_domain_ref": "failure-domain://carwash/autonomy-gpu",
            "current_evidence_receipt_ref": "receipt://sensor/carwash/learned-vision/current",
            "source_kind": "learned",
            "assurance_posture": "unassured_supplemental",
        }]);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("unassured learned sensing must not be the sole safety input");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "physical_action_assured_safety_input_required");
    }

    #[test]
    fn rejects_late_safe_switch() {
        let mut request = base_request();
        request["runtime_assurance_timing"]["demonstrated_observation_to_switch_bound_us"] =
            json!(30_000);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("late safe switch must fail closed");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "physical_action_observation_to_switch_bound_exceeded"
        );
    }

    #[test]
    fn rejects_operational_design_domain_exit() {
        let mut request = base_request();
        request["operational_design_domain_assurance"]["state"] = json!("outside");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("ODD exit must invoke the declared response, not admit motion");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "physical_action_operational_design_domain_exit");
    }

    #[test]
    fn rejects_lost_teleoperation_link() {
        let mut request = base_request();
        request["teleoperation_assurance"] = json!({
            "active": true,
            "link_contract_ref": "physical-stream-contract://teleop/carwash/bay-3/v1",
            "link_contract_hash": hash('b'),
            "operator_authority_ref": "grant://teleop/carwash/operator-1",
            "authentication_receipt_ref": "receipt://teleop/carwash/auth",
            "deadman_contract_ref": "policy://teleop/carwash/deadman",
            "deadman_receipt_ref": "receipt://teleop/carwash/deadman",
            "arbitration_policy_ref": "policy://teleop/carwash/arbitration",
            "on_link_loss": "safe_stop",
            "link_state": "lost",
            "authentication_state": "verified",
            "deadman_state": "asserted",
            "observed_round_trip_ms": 25,
            "max_round_trip_ms": 100,
            "operator_takeover_budget_ms": 1_000,
        });
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("lost teleoperation link must fail closed");
        assert_eq!(error.status, 403);
        assert_eq!(error.code, "physical_action_teleoperation_link_unavailable");
    }

    #[test]
    fn rejects_assurance_evidence_level_overclaim() {
        let mut request = base_request();
        request["asserted_assurance_evidence_level"] = json!("E2");
        request["deployment_assurance"]["supported_evidence_level"] = json!("E1");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "now")
            .expect_err("evidence level overclaim must fail closed");
        assert_eq!(error.status, 403);
        assert_eq!(
            error.code,
            "physical_action_assurance_evidence_level_overclaim"
        );
    }

    #[test]
    fn live_admission_requires_exact_state_root() {
        let mut request = base_request();
        request
            .as_object_mut()
            .expect("request object")
            .remove("state_root");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "2026-07-16T12:00:00Z")
            .expect_err("live action without a state root must fail closed");
        assert_eq!(error.code, "physical_action_execution_binding_required");
        assert_eq!(error.details["missing_field"], "state_root");
    }

    #[test]
    fn live_admission_requires_expanded_resource_group_leaves() {
        let mut request = base_request();
        request["resource_group_bindings"][0]
            .as_object_mut()
            .expect("resource-group binding")
            .remove("sensor_refs");
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "2026-07-16T12:00:00Z")
            .expect_err("a closure hash cannot replace expanded physical members");
        assert_eq!(error.code, "physical_action_deployment_assurance_required");
        assert_eq!(error.details["missing_field"], "sensor_refs");
    }

    #[test]
    fn live_admission_rejects_controller_outside_expanded_group_closure() {
        let mut request = base_request();
        request["resource_group_bindings"][0]["controller_binding_refs"] =
            json!(["controller-binding://carwash/bay-3/foreign/v1"]);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&request, "2026-07-16T12:00:00Z")
            .expect_err("foreign controller must not be smuggled behind a closure hash");
        assert_eq!(
            error.code,
            "physical_action_resource_group_controller_binding_mismatch"
        );
    }

    #[test]
    fn facility_system_refs_use_hyphenated_canonical_writes_only() {
        let mut canonical = base_request();
        canonical["resource_group_bindings"][0]["unit_refs"] = json!([
            "robot://bay-3/humanoid-1",
            "facility-system://carwash/bay-3"
        ]);
        let admission = RuntimePhysicalActionIntentAdmissionCore
            .admit(&canonical, "2026-07-16T12:00:00Z")
            .expect("canonical facility-system refs are admitted");
        assert!(admission["resource_group_bindings"][0]["unit_refs"]
            .as_array()
            .expect("unit refs")
            .iter()
            .any(|reference| reference == "facility-system://carwash/bay-3"));

        let mut legacy = base_request();
        legacy["resource_group_bindings"][0]["unit_refs"] = json!([
            "robot://bay-3/humanoid-1",
            "facility_system://carwash/bay-3"
        ]);
        let error = RuntimePhysicalActionIntentAdmissionCore
            .admit(&legacy, "2026-07-16T12:00:00Z")
            .expect_err("read-only legacy aliases must not enter a new admission");
        assert_eq!(error.code, "physical_action_deployment_assurance_invalid");
        assert_eq!(error.details["field"], "unit_refs");
    }
}
