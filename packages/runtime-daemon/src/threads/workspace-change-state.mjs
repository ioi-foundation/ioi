import { eventStreamIdForThread } from "../runtime-identifiers.mjs";
import { runtimeError } from "../runtime-http-utils.mjs";
import { normalizeArray, objectRecord, optionalString } from "../runtime-value-helpers.mjs";

const WORKSPACE_CHANGE_INSPECTION_EVIDENCE_REFS = [
  "runtime_workspace_change_projection_rust_owned",
  "workspace_change_inspection_js_facade_retired",
  "agentgres_workspace_change_truth_required",
];

const WORKSPACE_CHANGE_CONTROL_EVIDENCE_REFS = [
  "runtime_workspace_change_control_rust_owned",
  "runtime_workspace_change_control_event_rust_owned",
  "workspace_change_control_js_facade_retired",
  "agentgres_workspace_change_truth_required",
];

function stringRefs(values) {
  return normalizeArray(values).map((value) => String(value)).filter(Boolean);
}

function workspaceChangeProjectionRunner(store, request = {}, deps = {}) {
  const runner = deps.contextPolicyCore ?? store?.contextPolicyCore;
  if (runner?.projectRuntimeWorkspaceChangeProjection) return runner;
  throw runtimeError({
    status: 501,
    code: "runtime_workspace_change_projection_rust_core_required",
    message: "Workspace change inspection requires direct Rust daemon-core projection.",
    details: {
      rust_core_boundary: "runtime.workspace_change_control",
      operation: "workspace_change_inspection",
      operation_kind: "workspace_change.inspect",
      projection_kind: request.projection_kind ?? null,
      thread_id: request.thread_id ?? null,
      evidence_refs: WORKSPACE_CHANGE_INSPECTION_EVIDENCE_REFS,
    },
  });
}

function workspaceChangeControlRunner(store, request = {}, deps = {}) {
  const runner = deps.contextPolicyCore ?? store?.contextPolicyCore;
  if (
    runner?.planRuntimeWorkspaceChangeControl &&
    typeof store?.appendRuntimeEvent === "function"
  ) {
    return runner;
  }
  throw runtimeError({
    status: 501,
    code: "runtime_workspace_change_control_rust_core_required",
    message: "Workspace change control requires direct Rust daemon-core planning and runtime-event admission.",
    details: {
      rust_core_boundary: "runtime.workspace_change_control",
      operation: "workspace_change_control",
      operation_kind: "workspace_change.control",
      thread_id: request.thread_id ?? null,
      workspace_change_id: request.workspace_change_id ?? null,
      evidence_refs: WORKSPACE_CHANGE_CONTROL_EVIDENCE_REFS,
    },
  });
}

function collectionRecords(value) {
  if (Array.isArray(value)) return value;
  if (value instanceof Map) return [...value.values()];
  const record = objectRecord(value);
  if (!record) return [];
  for (const key of ["changes", "workspace_changes", "records"]) {
    if (Array.isArray(record[key])) return record[key];
  }
  return Object.values(record);
}

function recordChangeId(record = {}) {
  return optionalString(record.workspace_change_id ?? record.change_id ?? record.id);
}

function recordThreadMatches(record = {}, threadId) {
  const recordThread = optionalString(record.thread_id);
  return !recordThread || recordThread === threadId;
}

async function workspaceChangeCandidatesForThread(store, threadId) {
  let source = null;
  if (typeof store?.workspaceChangesForThread === "function") {
    source = await store.workspaceChangesForThread(threadId);
  } else if (typeof store?.workspaceChangeProjectionForThread === "function") {
    source = await store.workspaceChangeProjectionForThread(threadId);
  } else if (store?.workspaceChanges) {
    source = store.workspaceChanges;
  }
  return collectionRecords(source)
    .map((value) => objectRecord(value))
    .filter(Boolean)
    .filter((record) => recordChangeId(record))
    .filter((record) => recordThreadMatches(record, threadId))
    .map((record) => ({
      ...record,
      workspace_change_id: recordChangeId(record),
      thread_id: optionalString(record.thread_id) ?? threadId,
    }));
}

function workspaceChangeControlRequestPayload(request = {}) {
  const payload = {};
  for (const key of [
    "source",
    "workspace_root",
    "turn_id",
    "event_id",
    "event_seed",
    "idempotency_key",
    "expected_head_ref",
    "state_root_ref",
    "receipt_refs",
    "policy_decision_refs",
    "artifact_refs",
    "rollback_refs",
    "fixture_profile",
    "reason",
    "requested_by",
    "created_at",
  ]) {
    if (Object.hasOwn(request, key)) payload[key] = request[key];
  }
  return payload;
}

function assertWorkspaceChangeProjectionResult(result = {}, { threadId, projectionKind }) {
  const record = objectRecord(result);
  const projectedKind = optionalString(record?.projection_kind) ?? projectionKind;
  const projection = record?.projection;
  if (record?.operation_kind !== "workspace_change.inspect") {
    throw runtimeError({
      status: 502,
      code: "runtime_workspace_change_projection_operation_kind_invalid",
      message: "Rust workspace-change projection returned an invalid operation kind.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
      },
    });
  }
  if (record?.thread_id && record.thread_id !== threadId) {
    throw runtimeError({
      status: 502,
      code: "runtime_workspace_change_projection_thread_mismatch",
      message: "Rust workspace-change projection returned a different thread.",
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
      code: "runtime_workspace_change_projection_invalid",
      message: "Rust workspace-change projection returned an invalid projection.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        projection_kind: projectedKind ?? null,
        thread_id: threadId,
      },
    });
  }
  return record;
}

function assertWorkspaceChangeControlPlan(planned = {}, { threadId, selectedId }) {
  const record = objectRecord(planned);
  const event = objectRecord(record?.event);
  if (record?.operation_kind !== "workspace_change.control") {
    throw runtimeError({
      status: 502,
      code: "runtime_workspace_change_control_operation_kind_invalid",
      message: "Rust workspace-change control returned an invalid operation kind.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
      },
    });
  }
  if (record?.workspace_change_id !== selectedId) {
    throw runtimeError({
      status: 502,
      code: "runtime_workspace_change_control_id_mismatch",
      message: "Rust workspace-change control returned a different change id.",
      details: {
        thread_id: threadId,
        workspace_change_id: selectedId,
        planned_workspace_change_id: record?.workspace_change_id ?? null,
      },
    });
  }
  if (!event) {
    throw runtimeError({
      status: 502,
      code: "runtime_workspace_change_control_event_missing",
      message: "Rust workspace-change control planning did not return a runtime event.",
      details: {
        operation_kind: record?.operation_kind ?? null,
        thread_id: threadId,
        workspace_change_id: selectedId,
      },
    });
  }
  return event;
}

export async function inspectWorkspaceChangeReviewsForThread(store, threadId, request = {}, deps = {}) {
  const normalizedRequest = objectRecord(request) ?? {};
  const projectionKind = optionalString(normalizedRequest.projection_kind) ?? "list";
  const runner = workspaceChangeProjectionRunner(store, {
    projection_kind: projectionKind,
    thread_id: threadId,
  }, deps);
  const changes = await workspaceChangeCandidatesForThread(store, threadId);
  const result = await runner.projectRuntimeWorkspaceChangeProjection({
    operation: "workspace_change_inspection",
    operation_kind: "workspace_change.inspect",
    projection_kind: projectionKind,
    thread_id: threadId,
    source: "runtime.workspace_change_state",
    projection: { changes },
    evidence_refs: WORKSPACE_CHANGE_INSPECTION_EVIDENCE_REFS,
  });
  return assertWorkspaceChangeProjectionResult(result, { threadId, projectionKind });
}

export async function controlWorkspaceChangeForThread(store, threadId, request = {}, deps = {}) {
  const normalizedRequest = objectRecord(request) ?? {};
  const runner = workspaceChangeControlRunner(store, {
    thread_id: threadId,
    workspace_change_id: optionalString(normalizedRequest.workspace_change_id) ?? null,
  }, deps);
  const selectedId = optionalString(normalizedRequest.workspace_change_id);
  if (!selectedId) {
    throw runtimeError({
      status: 400,
      code: "runtime_workspace_change_control_id_required",
      message: "Workspace change control requires workspace_change_id.",
      details: {
        thread_id: threadId,
        evidence_refs: WORKSPACE_CHANGE_CONTROL_EVIDENCE_REFS,
      },
    });
  }
  const changes = await workspaceChangeCandidatesForThread(store, threadId);
  const currentChange = changes.find((record) => recordChangeId(record) === selectedId) ?? {
    workspace_change_id: selectedId,
    thread_id: threadId,
    lifecycle: "unknown",
  };
  const planned = await runner.planRuntimeWorkspaceChangeControl({
    operation: "workspace_change_control",
    operation_kind: "workspace_change.control",
    thread_id: threadId,
    event_stream_id: eventStreamIdForThread(threadId),
    workspace_change_id: selectedId,
    control_state: optionalString(normalizedRequest.control_state) ?? null,
    reason: optionalString(normalizedRequest.reason) ?? null,
    event_seed:
      optionalString(normalizedRequest.event_seed) ??
      optionalString(normalizedRequest.created_at) ??
      null,
    workspace_change: currentChange,
    request: workspaceChangeControlRequestPayload(normalizedRequest),
    receipt_refs: stringRefs(normalizedRequest.receipt_refs),
    policy_decision_refs: stringRefs(normalizedRequest.policy_decision_refs),
    evidence_refs: WORKSPACE_CHANGE_CONTROL_EVIDENCE_REFS,
  });
  const event = assertWorkspaceChangeControlPlan(planned, { threadId, selectedId });
  return store.appendRuntimeEvent(event);
}
