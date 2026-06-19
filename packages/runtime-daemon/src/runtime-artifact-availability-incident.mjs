import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION =
  "ioi.runtime.artifact_availability_incident.v1";

export const ARTIFACT_AVAILABILITY_AGENTGRES_OPERATION_SCHEMA_VERSION =
  "ioi.agentgres.artifact_availability_incident_operation.v1";

const INCIDENT_KINDS = new Set([
  "missing",
  "unavailable",
  "invalid_hash",
  "invalid_cid",
  "decrypt_failed",
  "backend_unavailable",
  "stale_replica",
]);

const LIFECYCLE_STATES = new Set([
  "opened",
  "fallback_attempted",
  "repaired",
  "quarantined",
  "unrecoverable",
  "closed",
]);

const RETIRED_ALIASES = [
  "artifactRef",
  "payloadRef",
  "backendRef",
  "repairReceiptRefs",
  "agentgresOperationRefs",
  "lifecycleState",
  "expectedHash",
  "observedHash",
];

export function admitArtifactAvailabilityIncident(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const artifactRef = requiredString(request.artifact_ref, "artifact_ref");
  const payloadRef = requiredString(request.payload_ref, "payload_ref");
  const backendRef = requiredString(request.backend_ref, "backend_ref");
  const incidentKind = enumValue(
    request.incident_kind,
    "incident_kind",
    INCIDENT_KINDS,
  );
  const lifecycleState = enumValue(
    request.lifecycle_state ?? "opened",
    "lifecycle_state",
    LIFECYCLE_STATES,
  );
  const expectedHash = optionalString(request.expected_hash) ?? null;
  const observedHash = optionalString(request.observed_hash) ?? null;
  const expectedCid = optionalString(request.expected_cid) ?? null;
  const observedCid = optionalString(request.observed_cid) ?? null;
  const agentgresOperationRefs = uniqueRefs(request.agentgres_operation_refs);
  const repairReceiptRefs = uniqueRefs(request.repair_receipt_refs);
  const incidentReceiptRefs = uniqueRefs(request.incident_receipt_refs);
  const fallbackBackendRefs = uniqueRefs(request.fallback_backend_refs);
  const quarantineRefs = uniqueRefs(request.quarantine_refs);
  const affectedObjectRefs = uniqueRefs(request.affected_object_refs);
  const verificationRefs = uniqueRefs(request.verification_refs);
  const restoreImportRefs = uniqueRefs(request.restore_import_refs);
  const payloadBytesMutated =
    booleanValue(request.payload_bytes_mutated) ?? false;

  assertIncidentAdmission({
    artifactRef,
    payloadRef,
    backendRef,
    incidentKind,
    lifecycleState,
    expectedHash,
    observedHash,
    expectedCid,
    observedCid,
    agentgresOperationRefs,
    repairReceiptRefs,
    incidentReceiptRefs,
    fallbackBackendRefs,
    quarantineRefs,
    affectedObjectRefs,
    verificationRefs,
    restoreImportRefs,
    payloadBytesMutated,
  });

  const incidentId =
    optionalString(request.incident_id) ??
    `artifact-availability-incident:${safeId(artifactRef)}:${safeId(incidentKind)}`;

  const admittedIncident = {
    schema_version: ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION,
    incident_id: incidentId,
    artifact_ref: artifactRef,
    payload_ref: payloadRef,
    backend_ref: backendRef,
    incident_kind: incidentKind,
    lifecycle_state: lifecycleState,
    expected_hash: expectedHash,
    observed_hash: observedHash,
    expected_cid: expectedCid,
    observed_cid: observedCid,
    agentgres_operation_refs: agentgresOperationRefs,
    repair_receipt_refs: repairReceiptRefs,
    incident_receipt_refs: incidentReceiptRefs,
    fallback_backend_refs: fallbackBackendRefs,
    quarantine_refs: quarantineRefs,
    affected_object_refs: affectedObjectRefs,
    verification_refs: verificationRefs,
    restore_import_refs: restoreImportRefs,
    payload_bytes_mutated: payloadBytesMutated,
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    runtimeTruthSource: "daemon-runtime",
  };

  return {
    ...admittedIncident,
    agentgres_operation: buildArtifactAvailabilityIncidentAgentgresOperation(
      admittedIncident,
    ),
  };
}

export function buildArtifactAvailabilityIncidentAgentgresOperation(
  incident = {},
) {
  const record = objectRecord(incident);
  if (
    !record ||
    record.schema_version !== ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION ||
    record.runtimeTruthSource !== "daemon-runtime"
  ) {
    throw runtimeError({
      status: 400,
      code: "artifact_availability_agentgres_operation_incident_required",
      message:
        "Artifact availability Agentgres operation requires an admitted daemon incident.",
      details: {
        expected_schema_version: ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION,
      },
    });
  }

  const incidentId = requiredString(record.incident_id, "incident_id");
  const agentgresOperationRefs = uniqueRefs(record.agentgres_operation_refs);
  const incidentReceiptRefs = uniqueRefs(record.incident_receipt_refs);
  const repairReceiptRefs = uniqueRefs(record.repair_receipt_refs);
  const verificationRefs = uniqueRefs(record.verification_refs);
  const restoreImportRefs = uniqueRefs(record.restore_import_refs);
  const affectedObjectRefs = uniqueRefs(record.affected_object_refs);
  requireRefs(agentgresOperationRefs, "agentgres_operation_refs");
  requireRefs(incidentReceiptRefs, "incident_receipt_refs");
  requireRefs(affectedObjectRefs, "affected_object_refs");

  const operationRef = agentgresOperationRefs[0];
  return {
    schema_version: ARTIFACT_AVAILABILITY_AGENTGRES_OPERATION_SCHEMA_VERSION,
    operation_ref: operationRef,
    operation_kind: "artifact_availability_incident",
    incident_id: incidentId,
    artifact_ref: requiredString(record.artifact_ref, "artifact_ref"),
    payload_ref: requiredString(record.payload_ref, "payload_ref"),
    backend_ref: requiredString(record.backend_ref, "backend_ref"),
    lifecycle_state: requiredString(record.lifecycle_state, "lifecycle_state"),
    incident_kind: requiredString(record.incident_kind, "incident_kind"),
    affected_object_refs: affectedObjectRefs,
    incident_receipt_refs: incidentReceiptRefs,
    repair_receipt_refs: repairReceiptRefs,
    verification_refs: verificationRefs,
    restore_import_refs: restoreImportRefs,
    fallback_backend_refs: uniqueRefs(record.fallback_backend_refs),
    quarantine_refs: uniqueRefs(record.quarantine_refs),
    payload_bytes_mutated: booleanValue(record.payload_bytes_mutated) ?? false,
    restore_validity:
      restoreImportRefs.length > 0
        ? "restore_import_refs_bound"
        : "no_restore_import",
    state_root: `agentgres://state-root/artifact-availability-incident/${safeId(
      incidentId,
    )}`,
    receipt_refs: uniqueRefs([
      ...incidentReceiptRefs,
      ...repairReceiptRefs,
    ]),
    runtimeTruthSource: "daemon-runtime",
    agentgresTruthSource: "agentgres-operation",
  };
}

function assertIncidentAdmission({
  artifactRef,
  payloadRef,
  backendRef,
  incidentKind,
  lifecycleState,
  expectedHash,
  observedHash,
  expectedCid,
  observedCid,
  agentgresOperationRefs,
  repairReceiptRefs,
  incidentReceiptRefs,
  fallbackBackendRefs,
  quarantineRefs,
  affectedObjectRefs,
  verificationRefs,
  restoreImportRefs,
  payloadBytesMutated,
}) {
  requirePrefix(artifactRef, "artifact://", "artifact_ref");
  requirePrefix(payloadRef, "payload://", "payload_ref");
  requirePrefix(backendRef, "storage://", "backend_ref");
  requireRefs(agentgresOperationRefs, "agentgres_operation_refs");
  requireRefs(incidentReceiptRefs, "incident_receipt_refs");
  if (affectedObjectRefs.length === 0) {
    throw admissionError({
      code: "artifact_availability_affected_object_refs_required",
      message:
        "Artifact availability incidents must bind affected Agentgres object refs or projections.",
      details: { artifact_ref: artifactRef },
    });
  }

  if (incidentKind === "invalid_hash" && (!expectedHash || !observedHash)) {
    throw admissionError({
      code: "artifact_availability_hash_evidence_required",
      message:
        "Invalid-hash incidents require expected_hash and observed_hash evidence.",
      details: { expected_hash: expectedHash, observed_hash: observedHash },
    });
  }
  if (incidentKind === "invalid_cid" && (!expectedCid || !observedCid)) {
    throw admissionError({
      code: "artifact_availability_cid_evidence_required",
      message:
        "Invalid-CID incidents require expected_cid and observed_cid evidence.",
      details: { expected_cid: expectedCid, observed_cid: observedCid },
    });
  }

  if (["repaired", "closed"].includes(lifecycleState)) {
    requireRefs(repairReceiptRefs, "repair_receipt_refs");
    requireRefs(verificationRefs, "verification_refs");
  }
  if (lifecycleState === "fallback_attempted") {
    requireRefs(fallbackBackendRefs, "fallback_backend_refs");
  }
  if (lifecycleState === "quarantined") {
    requireRefs(quarantineRefs, "quarantine_refs");
  }
  if (lifecycleState === "repaired" && restoreImportRefs.length === 0) {
    throw admissionError({
      code: "artifact_availability_restore_import_ref_required",
      message:
        "Repaired artifact availability incidents require restore/import refs.",
      details: { lifecycle_state: lifecycleState },
    });
  }
  if (payloadBytesMutated && repairReceiptRefs.length === 0) {
    throw admissionError({
      code: "artifact_availability_silent_payload_mutation_blocked",
      message:
        "Payload bytes cannot be silently replaced or mutated without a repair receipt.",
      details: { payload_bytes_mutated: payloadBytesMutated },
    });
  }
}

function requireRefs(refs, field) {
  if (refs.length > 0) return;
  throw admissionError({
    code: `artifact_availability_${field}_required`,
    message: `Artifact availability incident requires ${field}.`,
    details: { field },
  });
}

function requirePrefix(value, prefix, field) {
  if (value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `artifact_availability_${field}_invalid`,
    message: `Artifact availability ${field} must start with ${prefix}.`,
    details: { [field]: value },
  });
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = RETIRED_ALIASES.filter((field) => Object.hasOwn(body, field));
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "artifact_availability_request_aliases_retired",
    message:
      "Artifact availability incident admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `artifact_availability_${field}_invalid`,
      message: `Artifact availability incident requires a valid ${field}.`,
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
      code: `artifact_availability_${field}_required`,
      message: `Artifact availability incident requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function uniqueRefs(value) {
  return [...new Set(normalizeArray(value).map((item) => String(item).trim()).filter(Boolean))];
}

function admissionError({ code, message, details }) {
  return runtimeError({
    status: 403,
    code,
    message,
    details,
  });
}
