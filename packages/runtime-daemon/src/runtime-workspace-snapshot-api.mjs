import {
  WORKSPACE_RESTORE_PREVIEW_NODE_ID,
} from "./runtime-contract-constants.mjs";
import {
  runtimeError as defaultRuntimeError,
} from "./runtime-http-utils.mjs";
import { commitRuntimeArtifactRecord } from "./runtime-artifact-state-commit.mjs";
import { normalizeArray, objectRecord, optionalString } from "./runtime-value-helpers.mjs";

const RETIRED_WORKSPACE_RESTORE_REQUEST_ALIASES = [
  "workflowGraphId",
  "workflowNodeId",
  "idempotencyKey",
  "approvalDecision",
  "policyDecision",
  "confirmRestoreApply",
  "applyConfirmed",
  "approvalGranted",
  "allowConflicts",
  "overrideConflicts",
  "restoreConflictPolicy",
  "conflictPolicy",
  "restorePolicy",
];

const CANONICAL_WORKSPACE_RESTORE_REQUEST_FIELDS = [
  "workflow_graph_id",
  "workflow_node_id",
  "idempotency_key",
  "approval_decision",
  "policy_decision",
  "confirm_restore_apply",
  "apply_confirmed",
  "approval_granted",
  "allow_conflicts",
  "override_conflicts",
  "restore_conflict_policy",
  "conflict_policy",
  "restore_policy",
];

export function createRuntimeWorkspaceSnapshotApi(deps = {}) {
  const {
    runtimeError = defaultRuntimeError,
    runtimeThreadEventAdmissionForThread = null,
    workspaceRestoreCore = null,
  } = deps;

  function throwWorkspaceSnapshotRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_workspace_snapshot_rust_core_required",
      message: "Runtime workspace snapshot and restore lifecycle/projection requires direct Rust daemon-core admission, persistence, and projection.",
      details: {
        rust_core_boundary: "runtime.workspace_snapshot",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  function prepareWorkspaceSnapshotForPatch(
    _store,
    { threadId, turnId, workspaceRoot, toolCallId, workflowGraphId, workflowNodeId, result = {} } = {},
  ) {
    if (!result?.applied) return null;
    if (typeof workspaceRestoreCore?.captureSnapshotFiles !== "function") {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_patch_capture", "workspace_snapshot.capture", {
        thread_id: threadId,
        turn_id: turnId || null,
        workspace_root: workspaceRoot,
        tool_call_id: toolCallId ?? null,
        workflow_graph_id: workflowGraphId ?? null,
        workflow_node_id: workflowNodeId ?? null,
        changed_file_count: normalizeArray(result.changed_files).length,
        snapshot_draft_count: normalizeArray(result.workspace_snapshot_drafts).length,
        evidence_refs: [
          "workspace_snapshot_js_capture_facade_retired",
          "rust_daemon_core_workspace_snapshot_admission_required",
          "agentgres_workspace_snapshot_truth_required",
        ],
      });
    }
    const capture = workspaceRestoreCore.captureSnapshotFiles({
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      tool_call_id: toolCallId ?? null,
      workflow_graph_id: workflowGraphId ?? null,
      workflow_node_id: workflowNodeId ?? null,
      changed_files: snapshotChangedFilesForPatch(result),
      content_drafts: snapshotContentDraftsForPatch(result),
      max_content_bytes: result.max_content_bytes,
    });
    const record = capture?.snapshot_record ?? null;
    if (!record?.snapshot_id) {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_capture_record", "workspace_snapshot.capture", {
        thread_id: threadId,
        turn_id: turnId || null,
        workspace_root: workspaceRoot,
        tool_call_id: toolCallId ?? null,
        workflow_graph_id: workflowGraphId ?? null,
        workflow_node_id: workflowNodeId ?? null,
        changed_file_count: normalizeArray(result.changed_files).length,
        snapshot_draft_count: normalizeArray(result.workspace_snapshot_drafts).length,
        evidence_refs: [
          "rust_daemon_core_workspace_snapshot_record_required",
          "agentgres_workspace_snapshot_truth_required",
        ],
      });
    }
    const receiptRefs = normalizeArray(record.receipt_refs);
    const artifactRefs = normalizeArray(record.artifact_refs);
    if (!receiptRefs.length || !artifactRefs.length) {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_capture_refs", "workspace_snapshot.capture", {
        thread_id: threadId,
        turn_id: turnId || null,
        workspace_root: workspaceRoot,
        tool_call_id: toolCallId ?? null,
        workflow_graph_id: workflowGraphId ?? null,
        workflow_node_id: workflowNodeId ?? null,
        snapshot_id: record.snapshot_id,
        receipt_ref_count: receiptRefs.length,
        artifact_ref_count: artifactRefs.length,
        evidence_refs: [
          "rust_daemon_core_workspace_snapshot_receipt_binding_required",
          "agentgres_workspace_snapshot_artifact_truth_required",
        ],
      });
    }
    const snapshotArtifactCommit = materializeWorkspaceSnapshotArtifact(_store, {
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      tool_call_id: toolCallId ?? null,
      workflow_graph_id: workflowGraphId ?? null,
      workflow_node_id: workflowNodeId ?? null,
      snapshot: record,
      snapshot_artifact: objectRecord(capture?.snapshot_artifact),
      artifact_id: artifactRefs[0],
      receipt_id: receiptRefs[0],
    });
    const admittedEvent = appendWorkspaceSnapshotEvent(_store, {
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId ?? null,
      workflow_node_id: workflowNodeId ?? null,
      snapshot: record,
      snapshot_event: objectRecord(capture?.snapshot_event),
    });
    return {
      capture,
      record: {
        ...record,
        receipt_refs: receiptRefs,
        artifact_refs: artifactRefs,
      },
      snapshot_artifact_commit: snapshotArtifactCommit,
      event: admittedEvent,
    };
  }

  function snapshotChangedFilesForPatch(result = {}) {
    return normalizeArray(result.changed_files).map((entry) => ({
      path: optionalString(entry?.path) ?? "",
      created: Boolean(entry?.created),
      before_hash: optionalString(entry?.before_hash),
      after_hash: optionalString(entry?.after_hash),
      before_exists: Boolean(entry?.before_exists),
      after_exists: Object.hasOwn(entry, "after_exists") ? Boolean(entry.after_exists) : undefined,
      before_size_bytes: finiteNumber(entry?.before_size_bytes),
      after_size_bytes: finiteNumber(entry?.after_size_bytes),
      before_mtime_ms: finiteNumber(entry?.before_mtime_ms),
      after_mtime_ms: finiteNumber(entry?.after_mtime_ms),
    }));
  }

  function snapshotContentDraftsForPatch(result = {}) {
    return normalizeArray(result.workspace_snapshot_drafts).map((entry) => ({
      path: optionalString(entry?.path) ?? "",
      before_content: typeof entry?.before_content === "string" ? entry.before_content : undefined,
      after_content: typeof entry?.after_content === "string" ? entry.after_content : undefined,
      encoding: optionalString(entry?.encoding) ?? "utf8",
    }));
  }

  function finiteNumber(value) {
    if (value === null || value === undefined || value === "") return undefined;
    const number = Number(value);
    return Number.isFinite(number) ? number : undefined;
  }

  function materializeWorkspaceSnapshotArtifact(
    store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      tool_call_id: toolCallId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot,
      snapshot_artifact: snapshotArtifact,
      artifact_id: artifactId,
      receipt_id: receiptId,
    } = {},
  ) {
    return commitWorkspaceSnapshotArtifact(store, {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      tool_call_id: toolCallId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: snapshot?.snapshot_id ?? null,
      artifact_id: artifactId,
      receipt_id: receiptId,
      artifact: objectRecord(snapshotArtifact),
    });
  }

  function appendWorkspaceSnapshotEvent(
    store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot,
      snapshot_event: snapshotEvent,
    } = {},
  ) {
    if (!snapshot?.snapshot_id) return null;
    return admitWorkspaceSnapshotEvent(store, {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: snapshot.snapshot_id,
      event: objectRecord(snapshotEvent),
    });
  }

  function commitWorkspaceSnapshotArtifact(
    store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      tool_call_id: toolCallId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      artifact,
    } = {},
  ) {
    const plannedArtifactId = optionalString(artifact?.id ?? artifact?.artifact_id);
    if (!artifact || !plannedArtifactId || (artifactId && plannedArtifactId !== artifactId)) {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_artifact_materialization", "artifact.workspace_snapshot", {
        thread_id: threadId,
        turn_id: turnId,
        workspace_root: workspaceRoot,
        tool_call_id: toolCallId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        snapshot_id: snapshotId,
        artifact_id: artifactId ?? null,
        planned_artifact_id: plannedArtifactId ?? null,
        receipt_id: receiptId,
        evidence_refs: [
          "rust_daemon_core_workspace_snapshot_artifact_required",
          "agentgres_workspace_snapshot_artifact_truth_required",
          "workspace_snapshot_artifact_js_materializer_retired",
        ],
      });
    }
    try {
      return commitRuntimeArtifactRecord(store, artifact, "artifact.workspace_snapshot");
    } catch (error) {
      throw runtimeError({
        status: 502,
        code: "runtime_workspace_snapshot_artifact_admission_invalid",
        message:
          "Rust Agentgres artifact-state admission rejected the workspace snapshot artifact record.",
        details: {
          rust_core_boundary: "runtime.workspace_snapshot",
          operation: "workspace_snapshot_artifact_materialization",
          operation_kind: "artifact.workspace_snapshot",
          thread_id: threadId,
          turn_id: turnId,
          workspace_root: workspaceRoot,
          tool_call_id: toolCallId,
          workflow_graph_id: workflowGraphId,
          workflow_node_id: workflowNodeId,
          snapshot_id: snapshotId,
          artifact_id: plannedArtifactId,
          receipt_id: receiptId,
          cause: error?.message ?? String(error),
          evidence_refs: [
            "rust_daemon_core_workspace_snapshot_artifact_required",
            "agentgres_workspace_snapshot_artifact_truth_required",
            "workspace_snapshot_artifact_js_materializer_retired",
          ],
        },
      });
    }
  }

  function admitWorkspaceSnapshotEvent(
    store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: snapshotId,
      event,
    } = {},
  ) {
    if (!event?.event_stream_id || !event?.event_kind || !event?.idempotency_key) {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_event_append", "workspace_snapshot.event", {
        thread_id: threadId,
        turn_id: turnId || "",
        workspace_root: workspaceRoot,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        snapshot_id: snapshotId,
        planned_event_id: event?.event_id ?? null,
        evidence_refs: [
          "rust_daemon_core_workspace_snapshot_event_required",
          "agentgres_workspace_snapshot_event_truth_required",
          "workspace_snapshot_event_js_append_retired",
        ],
      });
    }
    const admit =
      typeof runtimeThreadEventAdmissionForThread === "function"
        ? runtimeThreadEventAdmissionForThread
        : store?.admitRuntimeThreadEventForThread;
    if (typeof admit !== "function") {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_event_append", "workspace_snapshot.event", {
        thread_id: threadId,
        turn_id: turnId || "",
        workspace_root: workspaceRoot,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        snapshot_id: snapshotId,
        planned_event_id: event.event_id ?? null,
        evidence_refs: [
          "rust_daemon_core_workspace_snapshot_event_required",
          "agentgres_workspace_snapshot_event_truth_required",
          "workspace_snapshot_event_js_append_retired",
        ],
      });
    }
    const admittedEvent = objectRecord(admit(store, { event }));
    if (!admittedEvent?.event_id) {
      throw runtimeError({
        status: 502,
        code: "runtime_workspace_snapshot_event_admission_invalid",
        message:
          "Rust Agentgres runtime-event admission did not return the workspace snapshot event record.",
        details: {
          rust_core_boundary: "runtime.workspace_snapshot",
          operation: "workspace_snapshot_event_append",
          operation_kind: "workspace_snapshot.event",
          thread_id: threadId,
          snapshot_id: snapshotId,
          planned_event_id: event.event_id ?? null,
          evidence_refs: [
            "rust_daemon_core_workspace_snapshot_event_required",
            "agentgres_workspace_snapshot_event_truth_required",
            "workspace_snapshot_event_js_append_retired",
          ],
        },
      });
    }
    return admittedEvent;
  }

  function listWorkspaceSnapshots(store, threadId) {
    void store;
    if (typeof workspaceRestoreCore?.projectWorkspaceSnapshotList !== "function") {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_list", "workspace_snapshot.list", {
        thread_id: threadId,
        evidence_refs: [
          "workspace_snapshot_list_js_projection_retired",
          "rust_daemon_core_workspace_snapshot_projection_required",
          "agentgres_workspace_snapshot_projection_truth_required",
        ],
      });
    }
    return requireWorkspaceSnapshotProjection(
      workspaceRestoreCore.projectWorkspaceSnapshotList({
        thread_id: threadId,
      }),
      "workspace_snapshot_list",
      "workspace_snapshot.list",
      { thread_id: threadId },
    );
  }

  function previewWorkspaceSnapshotRestore(store, threadId, snapshotId, request = {}) {
    assertCanonicalWorkspaceRestoreRequestBody(request);
    const normalizedSnapshotId = optionalString(snapshotId);
    if (!normalizedSnapshotId) {
      throw runtimeError({
        status: 400,
        code: "workspace_snapshot_id_required",
        message: "Restore preview requires a workspace snapshot id.",
        details: { thread_id: threadId },
      });
    }
    const workflowGraphId = optionalString(request.workflow_graph_id) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key);
    if (typeof workspaceRestoreCore?.previewSnapshotRestore !== "function") {
      throwWorkspaceSnapshotRustCoreRequired("workspace_restore_preview", "workspace_restore.preview", {
        thread_id: threadId,
        snapshot_id: normalizedSnapshotId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        idempotency_key: idempotencyKey ?? null,
        evidence_refs: [
          "workspace_restore_preview_js_facade_retired",
          "rust_daemon_core_workspace_restore_preview_required",
          "agentgres_workspace_restore_preview_truth_required",
        ],
      });
    }
    const preview = requireWorkspaceRestorePreview(
      workspaceRestoreCore.previewSnapshotRestore({
        ...canonicalWorkspaceRestoreRequest(request),
        thread_id: threadId,
        snapshot_id: normalizedSnapshotId,
        workspace_root: workspaceRootForThread(store, threadId),
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        idempotency_key: idempotencyKey ?? null,
      }),
      {
        thread_id: threadId,
        snapshot_id: normalizedSnapshotId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        idempotency_key: idempotencyKey ?? null,
      },
    );
    return finalizeWorkspaceRestorePreview(store, preview, {
      thread_id: threadId,
      snapshot_id: normalizedSnapshotId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      idempotency_key: idempotencyKey ?? null,
    });
  }

  function applyWorkspaceSnapshotRestore(store, threadId, snapshotId, request = {}) {
    assertCanonicalWorkspaceRestoreRequestBody(request);
    const normalizedSnapshotId = optionalString(snapshotId);
    if (!normalizedSnapshotId) {
      throw runtimeError({
        status: 400,
        code: "workspace_snapshot_id_required",
        message: "Restore apply requires a workspace snapshot id.",
        details: { thread_id: threadId },
      });
    }
    const workflowGraphId = optionalString(request.workflow_graph_id) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key);
    if (typeof workspaceRestoreCore?.applySnapshotRestore !== "function") {
      throwWorkspaceSnapshotRustCoreRequired("workspace_restore_apply", "workspace_restore.apply", {
        thread_id: threadId,
        snapshot_id: normalizedSnapshotId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        idempotency_key: idempotencyKey ?? null,
        evidence_refs: [
          "workspace_restore_apply_js_facade_retired",
          "rust_daemon_core_workspace_restore_apply_required",
          "agentgres_workspace_restore_apply_truth_required",
        ],
      });
    }
    const apply = requireWorkspaceRestoreApply(
      workspaceRestoreCore.applySnapshotRestore({
        ...canonicalWorkspaceRestoreRequest(request),
        thread_id: threadId,
        snapshot_id: normalizedSnapshotId,
        workspace_root: workspaceRootForThread(store, threadId),
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        idempotency_key: idempotencyKey ?? null,
      }),
      {
        thread_id: threadId,
        snapshot_id: normalizedSnapshotId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        idempotency_key: idempotencyKey ?? null,
      },
    );
    return finalizeWorkspaceRestoreApply(store, apply, {
      thread_id: threadId,
      snapshot_id: normalizedSnapshotId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      idempotency_key: idempotencyKey ?? null,
    });
  }

  function assertCanonicalWorkspaceRestoreRequestBody(request = {}) {
    const retiredAliases = RETIRED_WORKSPACE_RESTORE_REQUEST_ALIASES.filter((field) =>
      Object.prototype.hasOwnProperty.call(request, field),
    );
    if (retiredAliases.length === 0) return;
    throw runtimeError({
      status: 400,
      code: "workspace_restore_request_aliases_retired",
      message: "Workspace restore request aliases are retired; use canonical snake_case fields.",
      details: {
        retired_aliases: retiredAliases,
        canonical_fields: CANONICAL_WORKSPACE_RESTORE_REQUEST_FIELDS,
      },
    });
  }

  function workspaceSnapshotContentPackage(store, threadId, snapshotId) {
    void store;
    if (typeof workspaceRestoreCore?.projectWorkspaceSnapshotContentPackage !== "function") {
      throwWorkspaceSnapshotRustCoreRequired(
        "workspace_snapshot_content_package",
        "workspace_snapshot.content_package",
        {
          thread_id: threadId,
          snapshot_id: snapshotId,
          evidence_refs: [
            "workspace_snapshot_content_package_js_projection_retired",
            "rust_daemon_core_workspace_snapshot_content_package_required",
            "agentgres_workspace_snapshot_artifact_truth_required",
          ],
        },
      );
    }
    return requireWorkspaceSnapshotProjection(
      workspaceRestoreCore.projectWorkspaceSnapshotContentPackage({
        thread_id: threadId,
        snapshot_id: snapshotId,
      }),
      "workspace_snapshot_content_package",
      "workspace_snapshot.content_package",
      { thread_id: threadId, snapshot_id: snapshotId },
    );
  }

  function requireWorkspaceSnapshotProjection(envelope, operation, operationKind, details = {}) {
    const projection = objectRecord(envelope?.projection);
    if (projection) return projection;
    throwWorkspaceSnapshotRustCoreRequired(operation, operationKind, {
      ...details,
      evidence_refs: [
        "rust_daemon_core_workspace_snapshot_projection_required",
        "agentgres_workspace_snapshot_projection_truth_required",
      ],
    });
  }

  function requireWorkspaceRestorePreview(envelope, details = {}) {
    const preview = objectRecord(envelope?.restore_preview);
    if (preview) return preview;
    throwWorkspaceSnapshotRustCoreRequired("workspace_restore_preview", "workspace_restore.preview", {
      ...details,
      evidence_refs: [
        "workspace_restore_preview_js_facade_retired",
        "rust_daemon_core_workspace_restore_preview_required",
        "agentgres_workspace_restore_preview_truth_required",
      ],
    });
  }

  function requireWorkspaceRestoreApply(envelope, details = {}) {
    const apply = objectRecord(envelope?.restore_apply);
    if (apply) return apply;
    throwWorkspaceSnapshotRustCoreRequired("workspace_restore_apply", "workspace_restore.apply", {
      ...details,
      evidence_refs: [
        "workspace_restore_apply_js_facade_retired",
        "rust_daemon_core_workspace_restore_apply_required",
        "agentgres_workspace_restore_apply_truth_required",
      ],
    });
  }

  function canonicalWorkspaceRestoreRequest(request = {}) {
    return CANONICAL_WORKSPACE_RESTORE_REQUEST_FIELDS.reduce((record, field) => {
      if (Object.prototype.hasOwnProperty.call(request, field)) {
        record[field] = request[field];
      }
      return record;
    }, {});
  }

  function workspaceRootForThread(store, threadId) {
    const agent = typeof store?.agentForThread === "function" ? store.agentForThread(threadId) : null;
    return optionalString(agent?.cwd) ?? optionalString(store?.defaultCwd) ?? null;
  }

  function materializeWorkspaceRestorePreviewArtifact(
    store,
    {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      preview,
    } = {},
  ) {
    return commitWorkspaceRestoreArtifact(store, {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      artifact: objectRecord(preview?.restore_preview_artifact),
      operation_kind: "artifact.workspace_restore_preview",
      operation: "workspace_restore_artifact_materialization",
      operation_kind_detail: "artifact.restore-preview",
    });
  }

  function materializeWorkspaceRestoreApplyArtifact(
    store,
    {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      apply,
    } = {},
  ) {
    return commitWorkspaceRestoreArtifact(store, {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      artifact: objectRecord(apply?.restore_apply_artifact),
      operation_kind: "artifact.workspace_restore_apply",
      operation: "workspace_restore_artifact_materialization",
      operation_kind_detail: "artifact.restore-apply",
    });
  }

  function commitWorkspaceRestoreArtifact(
    store,
    {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      artifact,
      operation_kind: artifactOperationKind,
      operation,
      operation_kind_detail: operationKindDetail,
    },
  ) {
    const plannedArtifactId = optionalString(artifact?.id ?? artifact?.artifact_id);
    if (!artifact || !plannedArtifactId || (artifactId && plannedArtifactId !== artifactId)) {
      throwWorkspaceSnapshotRustCoreRequired(operation, operationKindDetail, {
        thread_id: threadId,
        workspace_root: workspaceRoot,
        snapshot_id: snapshotId,
        artifact_id: artifactId ?? null,
        planned_artifact_id: plannedArtifactId ?? null,
        receipt_id: receiptId,
        evidence_refs: [
          "rust_daemon_core_workspace_restore_artifact_required",
          "agentgres_workspace_restore_artifact_truth_required",
        ],
      });
    }
    try {
      return commitRuntimeArtifactRecord(store, artifact, artifactOperationKind);
    } catch (error) {
      throw runtimeError({
        status: 502,
        code: "runtime_workspace_restore_artifact_admission_invalid",
        message:
          "Rust Agentgres artifact-state admission rejected the workspace restore artifact record.",
        details: {
          rust_core_boundary: "runtime.workspace_snapshot",
          operation,
          operation_kind: operationKindDetail,
          thread_id: threadId,
          workspace_root: workspaceRoot,
          snapshot_id: snapshotId,
          artifact_id: plannedArtifactId,
          receipt_id: receiptId,
          cause: error?.message ?? String(error),
          evidence_refs: [
            "rust_daemon_core_workspace_restore_artifact_required",
            "agentgres_workspace_restore_artifact_truth_required",
          ],
        },
      });
    }
  }

  function appendWorkspaceRestorePreviewEvent(
    store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      preview,
    } = {},
  ) {
    return admitWorkspaceRestoreEvent(store, {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: preview?.snapshot_id ?? null,
      status: preview?.preview_status ?? null,
      event: objectRecord(preview?.restore_preview_event),
      operation: "workspace_restore_preview_event_append",
      operation_kind: "workspace_restore.preview.event",
    });
  }

  function appendWorkspaceRestoreApplyEvent(
    store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      apply,
    } = {},
  ) {
    return admitWorkspaceRestoreEvent(store, {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: apply?.snapshot_id ?? null,
      status: apply?.apply_status ?? null,
      event: objectRecord(apply?.restore_apply_event),
      operation: "workspace_restore_apply_event_append",
      operation_kind: "workspace_restore.apply.event",
    });
  }

  function finalizeWorkspaceRestorePreview(store, preview, details = {}) {
    const artifactCommit = materializeWorkspaceRestorePreviewArtifact(store, {
      ...details,
      workspace_root: workspaceRootForThread(store, details.thread_id),
      artifact_id: preview?.restore_preview_artifact?.id ?? preview?.artifact_refs?.[0],
      receipt_id: preview?.restore_preview_artifact?.receipt_id ?? preview?.receipt_refs?.[0],
      preview,
    });
    const admittedEvent = appendWorkspaceRestorePreviewEvent(store, {
      ...details,
      workspace_root: workspaceRootForThread(store, details.thread_id),
      preview,
    });
    return {
      ...preview,
      restore_preview_artifact_commit: artifactCommit,
      restore_preview_event: admittedEvent,
      event: admittedEvent,
    };
  }

  function finalizeWorkspaceRestoreApply(store, apply, details = {}) {
    const artifactCommit = materializeWorkspaceRestoreApplyArtifact(store, {
      ...details,
      workspace_root: workspaceRootForThread(store, details.thread_id),
      artifact_id: apply?.restore_apply_artifact?.id ?? apply?.artifact_refs?.[0],
      receipt_id: apply?.restore_apply_artifact?.receipt_id ?? apply?.receipt_refs?.[0],
      apply,
    });
    const admittedEvent = appendWorkspaceRestoreApplyEvent(store, {
      ...details,
      workspace_root: workspaceRootForThread(store, details.thread_id),
      apply,
    });
    return {
      ...apply,
      restore_apply_artifact_commit: artifactCommit,
      restore_apply_event: admittedEvent,
      event: admittedEvent,
    };
  }

  function admitWorkspaceRestoreEvent(
    store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: snapshotId,
      status,
      event,
      operation,
      operation_kind: operationKind,
    } = {},
  ) {
    if (!event?.event_id || !event?.event_stream_id || !event?.event_kind) {
      throwWorkspaceSnapshotRustCoreRequired(operation, operationKind, {
        thread_id: threadId,
        turn_id: turnId || "",
        workspace_root: workspaceRoot,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        snapshot_id: snapshotId,
        status: status ?? null,
        planned_event_id: event?.event_id ?? null,
        evidence_refs: [
          "rust_daemon_core_workspace_restore_event_required",
          "agentgres_workspace_restore_event_truth_required",
        ],
      });
    }
    const admit =
      typeof runtimeThreadEventAdmissionForThread === "function"
        ? runtimeThreadEventAdmissionForThread
        : store?.admitRuntimeThreadEventForThread;
    if (typeof admit !== "function") {
      throwWorkspaceSnapshotRustCoreRequired(operation, operationKind, {
        thread_id: threadId,
        turn_id: turnId || "",
        workspace_root: workspaceRoot,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        snapshot_id: snapshotId,
        status: status ?? null,
        planned_event_id: event.event_id,
        evidence_refs: [
          "rust_daemon_core_workspace_restore_event_required",
          "agentgres_workspace_restore_event_truth_required",
        ],
      });
    }
    const admittedEvent = objectRecord(admit(store, { event }));
    if (!admittedEvent?.event_id) {
      throw runtimeError({
        status: 502,
        code: "runtime_workspace_restore_event_admission_invalid",
        message:
          "Rust Agentgres runtime-event admission did not return the workspace restore event record.",
        details: {
          rust_core_boundary: "runtime.workspace_snapshot",
          operation,
          operation_kind: operationKind,
          thread_id: threadId,
          snapshot_id: snapshotId,
          planned_event_id: event.event_id,
          evidence_refs: [
            "rust_daemon_core_workspace_restore_event_required",
            "agentgres_workspace_restore_event_truth_required",
          ],
        },
      });
    }
    return admittedEvent;
  }

  return {
    appendWorkspaceRestoreApplyEvent,
    appendWorkspaceRestorePreviewEvent,
    appendWorkspaceSnapshotEvent,
    applyWorkspaceSnapshotRestore,
    listWorkspaceSnapshots,
    materializeWorkspaceRestoreApplyArtifact,
    materializeWorkspaceRestorePreviewArtifact,
    materializeWorkspaceSnapshotArtifact,
    prepareWorkspaceSnapshotForPatch,
    previewWorkspaceSnapshotRestore,
    workspaceSnapshotContentPackage,
  };
}
