import { eventStreamIdForThread } from "../runtime-identifiers.mjs";
import { runtimeError } from "../runtime-http-utils.mjs";
import { normalizeArray, objectRecord, optionalString } from "../runtime-value-helpers.mjs";

const MANAGED_SESSION_INSPECTION_EVIDENCE_REFS = [
  "runtime_managed_session_projection_rust_owned",
  "managed_session_inspection_js_facade_retired",
  "agentgres_managed_session_truth_required",
];

const MANAGED_SESSION_CONTROL_EVIDENCE_REFS = [
  "runtime_managed_session_control_rust_owned",
  "runtime_managed_session_control_event_rust_owned",
  "managed_session_control_js_facade_retired",
  "agentgres_managed_session_truth_required",
];

function stringRefs(values) {
  return normalizeArray(values).map((value) => String(value)).filter(Boolean);
}

function managedSessionProjectionRunner(store, request = {}, deps = {}) {
  const runner = deps.contextPolicyRunner ?? store?.contextPolicyRunner;
  if (runner?.projectRuntimeManagedSessionProjection) return runner;
  throw runtimeError({
    status: 501,
    code: "runtime_managed_session_projection_rust_core_required",
    message: "Managed session inspection requires direct Rust daemon-core projection.",
    details: {
      rust_core_boundary: "runtime.managed_session_control",
      operation: "managed_session_inspection",
      operation_kind: "managed_session.inspect",
      projection_kind: request.projection_kind ?? null,
      thread_id: request.thread_id ?? null,
      evidence_refs: MANAGED_SESSION_INSPECTION_EVIDENCE_REFS,
    },
  });
}

function managedSessionControlRunner(store, request = {}, deps = {}) {
  const runner = deps.contextPolicyRunner ?? store?.contextPolicyRunner;
  if (
    runner?.planRuntimeManagedSessionControl &&
    typeof store?.appendRuntimeEvent === "function"
  ) {
    return runner;
  }
  throw runtimeError({
    status: 501,
    code: "runtime_managed_session_control_rust_core_required",
    message: "Managed session control requires direct Rust daemon-core planning and runtime-event admission.",
    details: {
      rust_core_boundary: "runtime.managed_session_control",
      operation: "managed_session_control",
      operation_kind: "managed_session.control",
      thread_id: request.thread_id ?? null,
      managed_session_id: request.managed_session_id ?? null,
      evidence_refs: MANAGED_SESSION_CONTROL_EVIDENCE_REFS,
    },
  });
}

function collectionRecords(value) {
  if (Array.isArray(value)) return value;
  if (value instanceof Map) return [...value.values()];
  const record = objectRecord(value);
  if (!record) return [];
  for (const key of ["sessions", "managed_sessions", "records"]) {
    if (Array.isArray(record[key])) return record[key];
  }
  return Object.values(record);
}

function recordSessionId(record = {}) {
  return optionalString(record.managed_session_id ?? record.id);
}

function recordThreadMatches(record = {}, threadId) {
  const recordThread = optionalString(record.thread_id);
  return !recordThread || recordThread === threadId;
}

async function managedSessionCandidatesForThread(store, threadId) {
  let source = null;
  if (typeof store?.managedSessionsForThread === "function") {
    source = await store.managedSessionsForThread(threadId);
  } else if (typeof store?.managedSessionProjectionForThread === "function") {
    source = await store.managedSessionProjectionForThread(threadId);
  } else if (store?.managedSessions) {
    source = store.managedSessions;
  }
  return collectionRecords(source)
    .map((value) => objectRecord(value))
    .filter(Boolean)
    .filter((record) => recordSessionId(record))
    .filter((record) => recordThreadMatches(record, threadId))
    .map((record) => ({
      ...record,
      managed_session_id: recordSessionId(record),
      thread_id: optionalString(record.thread_id) ?? threadId,
    }));
}

function managedSessionControlRequestPayload(request = {}) {
  const payload = {};
  for (const key of [
    "source",
    "workspace_root",
    "turn_id",
    "event_id",
    "event_seed",
    "idempotency_key",
    "receipt_refs",
    "policy_decision_refs",
    "artifact_refs",
    "fixture_profile",
    "reason",
    "requested_by",
    "created_at",
  ]) {
    if (Object.hasOwn(request, key)) payload[key] = request[key];
  }
  return payload;
}

function assertManagedSessionProjectionResult(result = {}, { threadId, projectionKind }) {
  const record = objectRecord(result);
  const projectedKind = optionalString(record?.projection_kind) ?? projectionKind;
  const projection = record?.projection;
  if (record?.operation_kind !== "managed_session.inspect") {
    throw runtimeError({
      status: 502,
      code: "runtime_managed_session_projection_operation_kind_invalid",
      message: "Rust managed-session projection returned an invalid operation kind.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
      },
    });
  }
  if (record?.thread_id && record.thread_id !== threadId) {
    throw runtimeError({
      status: 502,
      code: "runtime_managed_session_projection_thread_mismatch",
      message: "Rust managed-session projection returned a different thread.",
      details: {
        thread_id: threadId,
        projected_thread_id: record.thread_id,
      },
    });
  }
  const validProjection =
    (["list", "inspect"].includes(projectedKind) && Array.isArray(projection)) ||
    (projectedKind === "summary" && objectRecord(projection));
  if (record?.status !== "projected" || !validProjection) {
    throw runtimeError({
      status: 502,
      code: "runtime_managed_session_projection_invalid",
      message: "Rust managed-session projection returned an invalid projection.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        projection_kind: projectedKind ?? null,
        thread_id: threadId,
      },
    });
  }
  return record;
}

function assertManagedSessionControlPlan(planned = {}, { threadId, selectedId }) {
  const record = objectRecord(planned);
  const event = objectRecord(record?.event);
  if (record?.operation_kind !== "managed_session.control") {
    throw runtimeError({
      status: 502,
      code: "runtime_managed_session_control_operation_kind_invalid",
      message: "Rust managed-session control returned an invalid operation kind.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
      },
    });
  }
  if (record?.managed_session_id !== selectedId) {
    throw runtimeError({
      status: 502,
      code: "runtime_managed_session_control_id_mismatch",
      message: "Rust managed-session control returned a different managed session id.",
      details: {
        thread_id: threadId,
        managed_session_id: selectedId,
        planned_managed_session_id: record?.managed_session_id ?? null,
      },
    });
  }
  if (!event) {
    throw runtimeError({
      status: 502,
      code: "runtime_managed_session_control_event_missing",
      message: "Rust managed-session control planning did not return a runtime event.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
        managed_session_id: selectedId,
      },
    });
  }
  return event;
}

export async function inspectManagedSessionsForThread(store, threadId, request = {}, deps = {}) {
  const normalizedRequest = objectRecord(request) ?? {};
  const projectionKind = optionalString(normalizedRequest.projection_kind) ?? "list";
  const runner = managedSessionProjectionRunner(store, {
    projection_kind: projectionKind,
    thread_id: threadId,
  }, deps);
  const sessions = await managedSessionCandidatesForThread(store, threadId);
  const result = await runner.projectRuntimeManagedSessionProjection({
    operation: "managed_session_inspection",
    operation_kind: "managed_session.inspect",
    projection_kind: projectionKind,
    thread_id: threadId,
    source: "runtime.managed_session_state",
    projection: { sessions },
    evidence_refs: MANAGED_SESSION_INSPECTION_EVIDENCE_REFS,
  });
  return assertManagedSessionProjectionResult(result, { threadId, projectionKind });
}

export async function controlManagedSessionForThread(store, threadId, request = {}, deps = {}) {
  const normalizedRequest = objectRecord(request) ?? {};
  const runner = managedSessionControlRunner(store, {
    thread_id: threadId,
    managed_session_id: optionalString(normalizedRequest.managed_session_id) ?? null,
  }, deps);
  const selectedId = optionalString(normalizedRequest.managed_session_id);
  if (!selectedId) {
    throw runtimeError({
      status: 400,
      code: "runtime_managed_session_control_id_required",
      message: "Managed session control requires managed_session_id.",
      details: {
        thread_id: threadId,
        evidence_refs: MANAGED_SESSION_CONTROL_EVIDENCE_REFS,
      },
    });
  }
  const sessions = await managedSessionCandidatesForThread(store, threadId);
  const currentSession = sessions.find((record) => recordSessionId(record) === selectedId) ?? {
    managed_session_id: selectedId,
    thread_id: threadId,
  };
  const planned = await runner.planRuntimeManagedSessionControl({
    operation: "managed_session_control",
    operation_kind: "managed_session.control",
    thread_id: threadId,
    event_stream_id: eventStreamIdForThread(threadId),
    managed_session_id: selectedId,
    control_state: optionalString(normalizedRequest.control_state) ?? null,
    reason: optionalString(normalizedRequest.reason) ?? null,
    event_seed:
      optionalString(normalizedRequest.event_seed) ??
      optionalString(normalizedRequest.created_at) ??
      null,
    managed_session: currentSession,
    request: managedSessionControlRequestPayload(normalizedRequest),
    receipt_refs: stringRefs(normalizedRequest.receipt_refs),
    policy_decision_refs: stringRefs(normalizedRequest.policy_decision_refs),
    evidence_refs: MANAGED_SESSION_CONTROL_EVIDENCE_REFS,
  });
  const event = assertManagedSessionControlPlan(planned, { threadId, selectedId });
  return store.appendRuntimeEvent(event);
}
