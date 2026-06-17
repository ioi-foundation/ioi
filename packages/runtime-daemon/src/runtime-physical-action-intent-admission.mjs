import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.physical_action_intent_admission.v1";

const ACTION_KINDS = new Set([
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
]);

const SUPERVISION_MODES = new Set([
  "autonomous",
  "monitored",
  "human_on_loop",
  "human_in_loop",
  "manual_confirm_each_action",
]);

const EXECUTION_PHASES = new Set([
  "intent_proposed",
  "preflight_verified",
  "command_issued",
  "stopped",
  "completed",
  "incident_opened",
]);

const RETIRED_ALIASES = [
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

export function admitPhysicalActionIntent(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const intentId = requiredString(request.intent_id, "intent_id");
  const actorId = requiredString(request.actor_id, "actor_id");
  const taskId = optionalString(request.task_id) ?? null;
  const domainRef = optionalString(request.domain_ref) ?? null;
  const targetSystemRef = requiredString(
    request.target_system_ref,
    "target_system_ref",
  );
  const actionKind = enumValue(request.action_kind, "action_kind", ACTION_KINDS);
  const riskClass = optionalString(request.risk_class) ?? "physical_action";
  const executionPhase = enumValue(
    request.execution_phase ?? "preflight_verified",
    "execution_phase",
    EXECUTION_PHASES,
  );
  const requestedPrimitives = uniqueStrings(
    normalizeArray(request.requested_primitives),
  );
  const requestedScopes = uniqueStrings(normalizeArray(request.requested_scopes));
  const physicalActionPolicyRef = requiredString(
    request.physical_action_policy_ref,
    "physical_action_policy_ref",
  );
  const safetyEnvelopeRef = requiredString(
    request.safety_envelope_ref,
    "safety_envelope_ref",
  );
  const humanSupervisionPolicyRef =
    optionalString(request.human_supervision_policy_ref) ?? null;
  const supervisionMode = enumValue(
    request.supervision_mode ?? "monitored",
    "supervision_mode",
    SUPERVISION_MODES,
  );
  const humanSupervisorRefs = uniqueStrings(
    normalizeArray(request.human_supervisor_refs),
  );
  const emergencyStopAuthorityRef = requiredString(
    request.emergency_stop_authority_ref,
    "emergency_stop_authority_ref",
  );
  const emergencyStopTested =
    booleanValue(request.emergency_stop_tested) ?? false;
  const emergencyStopMaxLatencyMs = optionalPositiveInteger(
    request.emergency_stop_max_latency_ms,
  );
  const sensorEvidenceReceiptRefs = uniqueStrings(
    normalizeArray(request.sensor_evidence_receipt_refs),
  );
  const actuatorCommandReceiptRefs = uniqueStrings(
    normalizeArray(request.actuator_command_receipt_refs),
  );
  const incidentPolicyRef = requiredString(
    request.incident_policy_ref,
    "incident_policy_ref",
  );
  const rollbackOrCompensationPolicyRef =
    optionalString(request.rollback_or_compensation_policy_ref) ?? null;
  const walletApprovalRef = optionalString(request.wallet_approval_ref) ?? null;
  const authorityRef = optionalString(request.authority_ref) ?? walletApprovalRef;
  const policyRefs = uniqueStrings(normalizeArray(request.policy_refs));
  const receiptRefs = uniqueStrings(normalizeArray(request.receipt_refs));
  const agentgresOperationRefs = uniqueStrings(
    normalizeArray(request.agentgres_operation_refs),
  );
  const artifactRefs = uniqueStrings(normalizeArray(request.artifact_refs));
  const stateRoot = optionalString(request.state_root) ?? null;
  const executionChannel = optionalString(request.execution_channel) ?? null;
  const simulationOnly = booleanValue(request.simulation_only) ?? false;
  const genericToolCall = booleanValue(request.generic_tool_call) ?? false;

  assertPhysicalActionAdmission({
    intentId,
    actorId,
    targetSystemRef,
    riskClass,
    executionPhase,
    requestedPrimitives,
    requestedScopes,
    physicalActionPolicyRef,
    safetyEnvelopeRef,
    humanSupervisionPolicyRef,
    supervisionMode,
    humanSupervisorRefs,
    emergencyStopAuthorityRef,
    emergencyStopTested,
    emergencyStopMaxLatencyMs,
    sensorEvidenceReceiptRefs,
    actuatorCommandReceiptRefs,
    incidentPolicyRef,
    walletApprovalRef,
    authorityRef,
    policyRefs,
    receiptRefs,
    agentgresOperationRefs,
    executionChannel,
    simulationOnly,
    genericToolCall,
  });

  const admissionId =
    optionalString(request.admission_id) ??
    `physical-action-admission:${safeId(intentId)}:${safeId(actionKind)}`;

  return {
    schema_version: PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    intent_id: intentId,
    actor_id: actorId,
    task_id: taskId,
    domain_ref: domainRef,
    target_system_ref: targetSystemRef,
    action_kind: actionKind,
    risk_class: "physical_action",
    execution_phase: executionPhase,
    requested_primitives: requestedPrimitives,
    requested_scopes: requestedScopes,
    physical_action_policy_ref: physicalActionPolicyRef,
    safety_envelope_ref: safetyEnvelopeRef,
    human_supervision_policy_ref: humanSupervisionPolicyRef,
    supervision_mode: supervisionMode,
    human_supervisor_refs: humanSupervisorRefs,
    emergency_stop_authority_ref: emergencyStopAuthorityRef,
    emergency_stop_tested: emergencyStopTested,
    emergency_stop_max_latency_ms: emergencyStopMaxLatencyMs,
    sensor_evidence_receipt_refs: sensorEvidenceReceiptRefs,
    actuator_command_receipt_refs: actuatorCommandReceiptRefs,
    incident_policy_ref: incidentPolicyRef,
    rollback_or_compensation_policy_ref: rollbackOrCompensationPolicyRef,
    wallet_approval_ref: walletApprovalRef,
    authority_ref: authorityRef,
    policy_refs: policyRefs,
    receipt_refs: receiptRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    artifact_refs: artifactRefs,
    state_root: stateRoot,
    execution_channel: executionChannel,
    decision: "admitted",
    requiresDaemonGate: true,
    generic_tool_call_blocked: true,
    simulation_only: simulationOnly,
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    runtimeTruthSource: "daemon-runtime",
  };
}

function assertPhysicalActionAdmission({
  intentId,
  actorId,
  targetSystemRef,
  riskClass,
  executionPhase,
  requestedPrimitives,
  requestedScopes,
  physicalActionPolicyRef,
  safetyEnvelopeRef,
  humanSupervisionPolicyRef,
  supervisionMode,
  humanSupervisorRefs,
  emergencyStopAuthorityRef,
  emergencyStopTested,
  emergencyStopMaxLatencyMs,
  sensorEvidenceReceiptRefs,
  actuatorCommandReceiptRefs,
  incidentPolicyRef,
  walletApprovalRef,
  authorityRef,
  policyRefs,
  receiptRefs,
  agentgresOperationRefs,
  executionChannel,
  simulationOnly,
  genericToolCall,
}) {
  requirePrefix(intentId, "intent://", "intent_id");
  requireActorRef(actorId);
  requireTargetPrefix(targetSystemRef);
  requirePrefix(physicalActionPolicyRef, "policy://", "physical_action_policy_ref");
  requirePrefix(safetyEnvelopeRef, "safety://", "safety_envelope_ref");
  requirePrefix(emergencyStopAuthorityRef, "estop://", "emergency_stop_authority_ref");
  requirePrefix(incidentPolicyRef, "policy://", "incident_policy_ref");
  if (humanSupervisionPolicyRef) {
    requirePrefix(
      humanSupervisionPolicyRef,
      "supervision://",
      "human_supervision_policy_ref",
    );
  }
  if (riskClass !== "physical_action") {
    throw admissionError({
      code: "physical_action_risk_class_required",
      message:
        "Actuator-affecting work must be classified as risk_class physical_action.",
      details: { risk_class: riskClass },
    });
  }
  if (genericToolCall || executionChannel === "tool.invoke") {
    throw admissionError({
      code: "physical_action_generic_tool_call_blocked",
      message:
        "No actuator command is a generic tool call; physical actions require the physical-action admission lifecycle.",
      details: { execution_channel: executionChannel, generic_tool_call: genericToolCall },
    });
  }
  if (simulationOnly && executionPhase !== "intent_proposed") {
    throw admissionError({
      code: "physical_action_simulation_not_execution_receipt",
      message:
        "Simulation-only evidence cannot be admitted as a physical actuator execution.",
      details: { execution_phase: executionPhase },
    });
  }
  requireRefs(requestedPrimitives, "requested_primitives");
  requireRefs(requestedScopes, "requested_scopes");
  if (!requestedPrimitives.some((ref) => ref.startsWith("prim:physical."))) {
    throw admissionError({
      code: "physical_action_primitive_required",
      message: "Physical-action admission requires a prim:physical.* primitive.",
      details: { requested_primitives: requestedPrimitives },
    });
  }
  if (!requestedScopes.some((ref) => ref.startsWith("scope:physical."))) {
    throw admissionError({
      code: "physical_action_scope_required",
      message: "Physical-action admission requires a scope:physical.* scope.",
      details: { requested_scopes: requestedScopes },
    });
  }
  if (!emergencyStopTested) {
    throw admissionError({
      code: "physical_action_emergency_stop_test_required",
      message:
        "Physical-action admission requires a currently tested EmergencyStopAuthority.",
      details: { emergency_stop_tested: emergencyStopTested },
    });
  }
  if (emergencyStopMaxLatencyMs !== null && emergencyStopMaxLatencyMs > 1000) {
    throw admissionError({
      code: "physical_action_emergency_stop_latency_exceeded",
      message:
        "Physical-action emergency stop latency must remain within the admitted safety envelope.",
      details: { emergency_stop_max_latency_ms: emergencyStopMaxLatencyMs },
    });
  }
  requireRefs(sensorEvidenceReceiptRefs, "sensor_evidence_receipt_refs");
  sensorEvidenceReceiptRefs.forEach((ref) =>
    requirePrefix(ref, "receipt://", "sensor_evidence_receipt_refs"),
  );
  if (executionPhase === "command_issued" || executionPhase === "completed") {
    requireRefs(actuatorCommandReceiptRefs, "actuator_command_receipt_refs");
  }
  actuatorCommandReceiptRefs.forEach((ref) =>
    requirePrefix(ref, "receipt://", "actuator_command_receipt_refs"),
  );
  if (
    ["human_in_loop", "manual_confirm_each_action"].includes(supervisionMode) &&
    (humanSupervisorRefs.length === 0 || !walletApprovalRef)
  ) {
    throw admissionError({
      code: "physical_action_human_supervision_authority_required",
      message:
        "Human-in-loop physical action requires supervisor refs and wallet approval.",
      details: { supervision_mode: supervisionMode },
    });
  }
  if (!authorityRef) {
    throw admissionError({
      code: "physical_action_authority_ref_required",
      message: "Physical-action admission requires wallet authority or approval.",
      details: { authority_ref: authorityRef },
    });
  }
  requireRefs(policyRefs, "policy_refs");
  requireRefs(receiptRefs, "receipt_refs");
  requireRefs(agentgresOperationRefs, "agentgres_operation_refs");
}

function requireTargetPrefix(value) {
  const prefixes = [
    "robot://",
    "facility://",
    "vehicle://",
    "device://",
    "drone://",
    "actuator://",
  ];
  if (prefixes.some((prefix) => value.startsWith(prefix))) return;
  throw runtimeError({
    status: 400,
    code: "physical_action_target_system_ref_invalid",
    message:
      "Physical-action target_system_ref must identify a robot, facility, vehicle, device, drone, or actuator.",
    details: { target_system_ref: value, allowed_prefixes: prefixes },
  });
}

function requireActorRef(value) {
  const prefixes = ["worker:", "worker://", "service_engine:", "runtime:"];
  if (prefixes.some((prefix) => value.startsWith(prefix))) return;
  throw runtimeError({
    status: 400,
    code: "physical_action_actor_id_invalid",
    message:
      "Physical-action actor_id must identify a worker, service engine, or runtime.",
    details: { actor_id: value, allowed_prefixes: prefixes },
  });
}

function requireRefs(refs, field) {
  if (refs.length > 0) return;
  throw admissionError({
    code: `physical_action_${field}_required`,
    message: `Physical-action admission requires ${field}.`,
    details: { field },
  });
}

function requirePrefix(value, prefix, field) {
  if (value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `physical_action_${field}_invalid`,
    message: `Physical-action ${field} must start with ${prefix}.`,
    details: { [field]: value },
  });
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = RETIRED_ALIASES.filter((field) => Object.hasOwn(body, field));
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "physical_action_request_aliases_retired",
    message:
      "Physical-action admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `physical_action_${field}_invalid`,
      message: `Physical-action admission requires a valid ${field}.`,
      details: {
        [field]: normalized ?? null,
        allowed_values: [...allowedValues],
      },
    });
  }
  return normalized;
}

function requiredString(value, field) {
  const normalized = optionalString(value);
  if (!normalized) {
    throw runtimeError({
      status: 400,
      code: `physical_action_${field}_required`,
      message: `Physical-action admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function optionalPositiveInteger(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  if (Number.isInteger(number) && number > 0) return number;
  throw runtimeError({
    status: 400,
    code: "physical_action_emergency_stop_max_latency_ms_invalid",
    message:
      "Physical-action emergency_stop_max_latency_ms must be a positive integer when supplied.",
    details: { emergency_stop_max_latency_ms: value },
  });
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value)).filter(Boolean))];
}

function admissionError(error) {
  return runtimeError({ status: 403, ...error });
}
