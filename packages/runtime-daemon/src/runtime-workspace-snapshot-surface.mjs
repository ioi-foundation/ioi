import {
  WORKSPACE_RESTORE_PREVIEW_NODE_ID,
} from "./runtime-contract-constants.mjs";
import {
  runtimeError as defaultRuntimeError,
} from "./runtime-http-utils.mjs";
import { normalizeArray, optionalString } from "./runtime-value-helpers.mjs";

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

export function createRuntimeWorkspaceSnapshotSurface(deps = {}) {
  const {
    runtimeError = defaultRuntimeError,
    workspaceRestoreRunner = null,
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
    if (typeof workspaceRestoreRunner?.captureSnapshotFiles !== "function") {
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
    const capture = workspaceRestoreRunner.captureSnapshotFiles({
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
    return {
      capture,
      record: {
        ...record,
        receipt_refs: receiptRefs,
        artifact_refs: artifactRefs,
      },
      event: capture?.snapshot_event ?? null,
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
    _store,
    { threadId, toolCallId, workspaceRoot, snapshot, artifactPayload, artifactId, receiptId } = {},
  ) {
    throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_artifact_materialization", "artifact.workspace_snapshot", {
      thread_id: threadId,
      tool_call_id: toolCallId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshot?.snapshot_id ?? artifactPayload?.snapshot_id ?? null,
      artifact_id: artifactId ?? null,
      receipt_id: receiptId,
      evidence_refs: [
        "workspace_snapshot_artifact_js_materializer_retired",
        "rust_daemon_core_workspace_snapshot_artifact_required",
        "agentgres_workspace_snapshot_artifact_truth_required",
      ],
    });
  }

  function appendWorkspaceSnapshotEvent(
    _store,
    { threadId, turnId, workspaceRoot, workflowGraphId, snapshot, sourceToolEvent } = {},
  ) {
    if (!snapshot?.snapshot_id) return null;
    throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_event_append", "workspace_snapshot.event", {
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId ?? snapshot.trigger?.workflow_graph_id ?? null,
      snapshot_id: snapshot.snapshot_id,
      source_tool_call_id: sourceToolEvent?.tool_call_id ?? snapshot.trigger?.tool_call_id ?? null,
      source_tool_event_id: sourceToolEvent?.event_id ?? null,
      evidence_refs: [
        "workspace_snapshot_event_js_append_retired",
        "rust_daemon_core_workspace_snapshot_event_required",
        "agentgres_workspace_snapshot_event_truth_required",
      ],
    });
  }

  function listWorkspaceSnapshots(store, threadId) {
    void store;
    if (typeof workspaceRestoreRunner?.listSnapshots !== "function") {
      throwWorkspaceSnapshotRustCoreRequired("workspace_snapshot_list", "workspace_snapshot.list", {
        thread_id: threadId,
        evidence_refs: [
          "workspace_snapshot_list_js_projection_retired",
          "rust_daemon_core_workspace_snapshot_projection_required",
          "agentgres_workspace_snapshot_projection_truth_required",
        ],
      });
    }
    return workspaceRestoreRunner.listSnapshots({
      thread_id: threadId,
    });
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
    if (typeof workspaceRestoreRunner?.previewSnapshotRestore !== "function") {
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
    return workspaceRestoreRunner.previewSnapshotRestore({
      ...canonicalWorkspaceRestoreRequest(request),
      thread_id: threadId,
      snapshot_id: normalizedSnapshotId,
      workspace_root: workspaceRootForThread(store, threadId),
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
    if (typeof workspaceRestoreRunner?.applySnapshotRestore !== "function") {
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
    return workspaceRestoreRunner.applySnapshotRestore({
      ...canonicalWorkspaceRestoreRequest(request),
      thread_id: threadId,
      snapshot_id: normalizedSnapshotId,
      workspace_root: workspaceRootForThread(store, threadId),
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
    if (typeof workspaceRestoreRunner?.workspaceSnapshotContentPackage !== "function") {
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
    return workspaceRestoreRunner.workspaceSnapshotContentPackage({
      thread_id: threadId,
      snapshot_id: snapshotId,
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
    return materializeWorkspaceRestoreArtifact(store, {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      value: preview,
      toolName: "workspace.restore_preview",
      name: "workspace-restore-preview.json",
      channel: "restore-preview",
      redaction: "workspace_restore_preview",
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
    return materializeWorkspaceRestoreArtifact(store, {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      value: apply,
      toolName: "workspace.restore_apply",
      name: "workspace-restore-apply.json",
      channel: "restore-apply",
      redaction: "workspace_restore_apply",
    });
  }

  function materializeWorkspaceRestoreArtifact(
    _store,
    {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      value,
      toolName,
      name,
      channel,
      redaction,
    },
  ) {
    throwWorkspaceSnapshotRustCoreRequired("workspace_restore_artifact_materialization", `artifact.${channel}`, {
      thread_id: threadId,
      workspace_root: workspaceRoot,
      snapshot_id: snapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      tool_name: toolName ?? null,
      artifact_name: name ?? null,
      channel: channel ?? null,
      redaction: redaction ?? null,
      has_value: Boolean(value),
      evidence_refs: [
        "workspace_restore_artifact_js_materializer_retired",
        "rust_daemon_core_workspace_restore_artifact_required",
        "agentgres_workspace_restore_artifact_truth_required",
      ],
    });
  }

  function appendWorkspaceRestorePreviewEvent(
    _store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      preview,
    } = {},
  ) {
    throwWorkspaceSnapshotRustCoreRequired("workspace_restore_preview_event_append", "workspace_restore.preview.event", {
      thread_id: threadId,
      turn_id: turnId || "",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: preview?.snapshot_id ?? null,
      preview_status: preview?.preview_status ?? null,
      evidence_refs: [
        "workspace_restore_preview_event_js_append_retired",
        "rust_daemon_core_workspace_restore_preview_event_required",
        "agentgres_workspace_restore_preview_event_truth_required",
      ],
    });
  }

  function appendWorkspaceRestoreApplyEvent(
    _store,
    {
      thread_id: threadId,
      turn_id: turnId,
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      apply,
    } = {},
  ) {
    throwWorkspaceSnapshotRustCoreRequired("workspace_restore_apply_event_append", "workspace_restore.apply.event", {
      thread_id: threadId,
      turn_id: turnId || "",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      snapshot_id: apply?.snapshot_id ?? null,
      apply_status: apply?.apply_status ?? null,
      evidence_refs: [
        "workspace_restore_apply_event_js_append_retired",
        "rust_daemon_core_workspace_restore_apply_event_required",
        "agentgres_workspace_restore_apply_event_truth_required",
      ],
    });
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
