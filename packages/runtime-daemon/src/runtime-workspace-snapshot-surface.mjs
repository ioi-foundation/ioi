import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
  WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
  WORKSPACE_RESTORE_PREVIEW_NODE_ID,
  WORKSPACE_SNAPSHOT_NODE_ID,
  WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";
import {
  notFound as defaultNotFound,
  runtimeError as defaultRuntimeError,
} from "./runtime-http-utils.mjs";
import { commitRuntimeArtifactRecord } from "./runtime-artifact-state-commit.mjs";
import {
  WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
  WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
  parseJsonObject,
  workspaceRestoreOperationCounts,
} from "./workspace-restore.mjs";
import { doctorHash, normalizeArray, optionalString, safeId } from "./runtime-value-helpers.mjs";

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
    now = () => new Date().toISOString(),
    notFound = defaultNotFound,
    runtimeError = defaultRuntimeError,
    workspaceRestoreRunner,
  } = deps;

  function prepareWorkspaceSnapshotForPatch(
    store,
    { threadId, turnId, workspaceRoot, toolCallId, workflowGraphId, workflowNodeId, result = {} } = {},
  ) {
    if (!result?.applied) return null;
    const capture = captureWorkspaceSnapshotFiles({
      changedFiles: result.changed_files,
      contentDrafts: result.workspace_snapshot_drafts,
    });
    const files = capture.files;
    const contentFiles = capture.content_files ?? [];
    if (!files.length) return null;
    const capturedFileCount = Number(capture.captured_file_count ?? 0) || 0;
    const omittedFileCount = Number(capture.omitted_file_count ?? 0) || 0;
    const previewSupported = omittedFileCount === 0;
    const core = {
      schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot",
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      snapshot_kind: "pre_post_touched_files",
      trigger: {
        tool_name: "file.apply_patch",
        tool_call_id: toolCallId,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
      },
      file_count: files.length,
      changed_file_count: files.filter((file) => file.changed).length,
      created_file_count: files.filter((file) => file.created).length,
      deleted_file_count: files.filter((file) => file.deleted).length,
      files,
      capture: {
        status: previewSupported ? "content_captured" : "partial_content",
        max_content_bytes: WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
        captured_file_count: capturedFileCount,
        omitted_file_count: omittedFileCount,
      },
      restore: {
        status: previewSupported ? "content_captured" : "partial_content",
        preview_supported: previewSupported,
        apply_supported: previewSupported,
        reason: previewSupported ? "restore_apply_requires_approval" : "snapshot_content_capture_incomplete",
      },
      redaction: {
        profile: "workspace_snapshot_content_artifact",
        content_included: false,
        content_artifact_included: true,
        paths_included: true,
      },
      evidence_refs: ["workspace_snapshot_content", "file.apply_patch", toolCallId].filter(Boolean),
    };
    const snapshotHash = doctorHash(JSON.stringify(core));
    const snapshotId = `workspace_snapshot_${safeId(toolCallId)}_${snapshotHash.slice(0, 12)}`;
    const receiptId = `receipt_${snapshotId}`;
    const artifactId = `artifact_${safeId(snapshotId)}_content`;
    const record = {
      ...core,
      snapshot_id: snapshotId,
      snapshot_hash: snapshotHash,
      receipt_refs: [receiptId],
      artifact_refs: [artifactId],
      content_artifact_refs: [artifactId],
      summary: `Workspace snapshot recorded ${files.length} changed file(s) for ${toolCallId}.`,
    };
    const artifactPayload = {
      schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot_content",
      snapshot_id: snapshotId,
      snapshot_hash: snapshotHash,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      trigger: record.trigger,
      capture: record.capture,
      restore: record.restore,
      snapshot: record,
      files: contentFiles,
    };
    const artifactRecord = materializeWorkspaceSnapshotArtifact(store, {
      threadId,
      toolCallId,
      workspaceRoot,
      snapshot: record,
      artifactPayload,
      artifactId,
      receiptId,
    });
    return {
      record,
      artifactRecord,
    };
  }

  function materializeWorkspaceSnapshotArtifact(
    store,
    { threadId, toolCallId, workspaceRoot, snapshot, artifactPayload, artifactId, receiptId } = {},
  ) {
    const createdAt = now();
    const content = JSON.stringify(artifactPayload ?? snapshot, null, 2);
    const artifactRecord = {
      schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      id: artifactId,
      thread_id: threadId,
      tool_name: "file.apply_patch",
      tool_call_id: toolCallId,
      workspace_root: workspaceRoot,
      name: "workspace-snapshot-content.json",
      channel: "workspace-snapshot",
      media_type: "application/json",
      redaction: "workspace_snapshot_content_artifact",
      receipt_id: receiptId,
      content,
      content_bytes: Buffer.byteLength(content, "utf8"),
      content_hash: doctorHash(content),
      created_at: createdAt,
    };
    store.codingArtifacts.set(artifactRecord.id, artifactRecord);
    commitRuntimeArtifactRecord(store, artifactRecord, "artifact.workspace_snapshot");
    return artifactRecord;
  }

  function appendWorkspaceSnapshotEvent(
    store,
    { threadId, turnId, workspaceRoot, workflowGraphId, snapshot, sourceToolEvent } = {},
  ) {
    if (!snapshot?.snapshot_id) return null;
    const payloadSummary = {
      schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      event_kind: "WorkspaceSnapshotCreated",
      snapshot_id: snapshot.snapshot_id,
      snapshot_hash: snapshot.snapshot_hash,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      snapshot_kind: snapshot.snapshot_kind,
      file_count: snapshot.file_count,
      changed_file_count: snapshot.changed_file_count,
      created_file_count: snapshot.created_file_count,
      deleted_file_count: snapshot.deleted_file_count,
      restore_status: snapshot.restore?.status ?? "metadata_only",
      restore_preview_supported: Boolean(snapshot.restore?.preview_supported),
      restore_apply_supported: Boolean(snapshot.restore?.apply_supported),
      source_tool_name: "file.apply_patch",
      source_tool_call_id: sourceToolEvent?.tool_call_id ?? snapshot.trigger?.tool_call_id ?? null,
      source_tool_event_id: sourceToolEvent?.event_id ?? null,
      source_workflow_node_id: snapshot.trigger?.workflow_node_id ?? null,
      files: snapshot.files,
      receipt_refs: snapshot.receipt_refs,
      artifact_refs: snapshot.artifact_refs,
      summary: snapshot.summary,
      snapshot,
    };
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:workspace-snapshot:${safeId(snapshot.snapshot_id)}`,
      idempotency_key: `thread:${threadId}:workspace-snapshot:${snapshot.snapshot_id}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceSnapshot.Created",
      event_kind: "workspace.snapshot.created",
      status: "completed",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId ?? snapshot.trigger?.workflow_graph_id ?? null,
      workflow_node_id: WORKSPACE_SNAPSHOT_NODE_ID,
      component_kind: "workspace_snapshot",
      tool_call_id: sourceToolEvent?.tool_call_id ?? snapshot.trigger?.tool_call_id ?? null,
      artifact_refs: snapshot.artifact_refs,
      receipt_refs: snapshot.receipt_refs,
      rollback_refs: [snapshot.snapshot_id],
      payload_schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
  }

  function listWorkspaceSnapshots(store, threadId) {
    store.agentForThread(threadId);
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const snapshots = stream.events
      .filter((event) => event.event_kind === "workspace.snapshot.created")
      .map((event) => event.payload_summary?.snapshot ?? event.payload_summary)
      .filter((snapshot) => snapshot && typeof snapshot === "object" && !Array.isArray(snapshot));
    return {
      schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot_list",
      thread_id: threadId,
      snapshot_count: snapshots.length,
      snapshots,
    };
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
    const agent = store.agentForThread(threadId);
    const workflowGraphId = optionalString(request.workflow_graph_id) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key);
    const snapshotPackage = workspaceSnapshotContentPackage(store, threadId, normalizedSnapshotId);
    const operations = previewWorkspaceRestoreOperations({
      workspace_root: agent.cwd,
      files: snapshotPackage.files,
    });
    if (!operations.length) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_preview_empty",
        message: "Restore preview could not find content-backed files in the snapshot.",
        details: { thread_id: threadId, snapshot_id: normalizedSnapshotId },
      });
    }
    const readyCount = operations.filter((operation) => operation.status === "ready").length;
    const noopCount = operations.filter((operation) => operation.status === "noop").length;
    const conflictCount = operations.filter((operation) => operation.status === "conflict").length;
    const blockedCount = operations.filter((operation) => operation.status === "blocked").length;
    const previewStatus = conflictCount || blockedCount ? "blocked" : "ready";
    const receiptId = `receipt_workspace_restore_preview_${safeId(normalizedSnapshotId)}_${doctorHash(
      JSON.stringify(operations.map((operation) => [operation.path, operation.status, operation.current_hash])),
    ).slice(0, 12)}`;
    const artifactId = `artifact_workspace_restore_preview_${safeId(normalizedSnapshotId)}_${doctorHash(receiptId).slice(0, 12)}`;
    const snapshotTurnId = snapshotPackage.snapshot?.turn_id ?? null;
    const snapshotHash = snapshotPackage.snapshot?.snapshot_hash ?? null;
    const result = {
      schema_version: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_restore_preview",
      thread_id: threadId,
      turn_id: snapshotTurnId,
      workspace_root: agent.cwd,
      snapshot_id: normalizedSnapshotId,
      snapshot_hash: snapshotHash,
      preview_status: previewStatus,
      preview_supported: blockedCount === 0,
      apply_supported: previewStatus === "ready",
      restore_apply_supported: previewStatus === "ready",
      file_count: operations.length,
      ready_count: readyCount,
      noop_count: noopCount,
      conflict_count: conflictCount,
      blocked_count: blockedCount,
      operations,
      receipt_refs: [receiptId],
      artifact_refs: [artifactId],
      rollback_refs: [normalizedSnapshotId],
      idempotency_key: idempotencyKey,
      summary:
        previewStatus === "ready"
          ? `Restore preview ready for ${operations.length} file(s) from ${normalizedSnapshotId}.`
          : `Restore preview blocked for ${normalizedSnapshotId}: ${conflictCount} conflict(s), ${blockedCount} blocked file(s).`,
    };
    const artifactRecord = materializeWorkspaceRestorePreviewArtifact(store, {
      thread_id: threadId,
      workspace_root: agent.cwd,
      snapshot_id: normalizedSnapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      preview: result,
    });
    const event = appendWorkspaceRestorePreviewEvent(store, {
      thread_id: threadId,
      turn_id: result.turn_id,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      preview: {
        ...result,
        artifact_refs: [artifactRecord.id],
      },
    });
    return {
      ...result,
      artifact_refs: [artifactRecord.id],
      event,
      restore_preview_event: event,
    };
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
    const agent = store.agentForThread(threadId);
    const workflowGraphId = optionalString(request.workflow_graph_id) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key);
    const snapshotPackage = workspaceSnapshotContentPackage(store, threadId, normalizedSnapshotId);
    const previewOperations = previewWorkspaceRestoreOperations({
      workspace_root: agent.cwd,
      files: snapshotPackage.files,
    });
    if (!previewOperations.length) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_apply_empty",
        message: "Restore apply could not find content-backed files in the snapshot.",
        details: { thread_id: threadId, snapshot_id: normalizedSnapshotId },
      });
    }
    const gatePolicyPlan = planWorkspaceRestoreApplyPolicy({
      snapshot_id: normalizedSnapshotId,
      request,
      operations: previewOperations,
    });
    const approval = gatePolicyPlan.approval;
    const allowConflicts = Boolean(gatePolicyPlan.allow_conflicts);
    const conflictPolicy = gatePolicyPlan.conflict_policy ?? "clean_preview_only";
    const hardBlocked = Boolean(gatePolicyPlan.hard_blocked);
    const conflictBlocked = Boolean(gatePolicyPlan.conflict_blocked);
    let operations = previewOperations.map((operation) => ({
      ...operation,
      apply_status: "blocked",
      apply_reason: workspaceRestoreOperationApplyReason(gatePolicyPlan, operation),
    }));
    if (approval.satisfied && !hardBlocked && !conflictBlocked) {
      operations = applyWorkspaceRestoreOperations({
        workspace_root: agent.cwd,
        files: snapshotPackage.files,
        allow_conflicts: allowConflicts,
      });
    }
    const counts = workspaceRestoreOperationCounts(operations);
    const finalPolicyPlan = planWorkspaceRestoreApplyPolicy({
      snapshot_id: normalizedSnapshotId,
      request,
      counts,
      hard_blocked: hardBlocked,
      conflict_blocked: conflictBlocked,
    });
    const applyStatus = finalPolicyPlan.apply_status;
    const previewStatus = counts.conflict_count || counts.blocked_count ? "blocked" : "ready";
    const policyDecisionRefs = normalizeArray(
      finalPolicyPlan.policy_decision_refs,
    );
    const receiptId = `receipt_workspace_restore_apply_${safeId(normalizedSnapshotId)}_${doctorHash(
      JSON.stringify(operations.map((operation) => [
        operation.path,
        operation.apply_status,
        operation.applied_hash,
      ])),
    ).slice(0, 12)}`;
    const artifactId = `artifact_workspace_restore_apply_${safeId(normalizedSnapshotId)}_${doctorHash(receiptId).slice(0, 12)}`;
    const snapshotTurnId = snapshotPackage.snapshot?.turn_id ?? null;
    const snapshotHash = snapshotPackage.snapshot?.snapshot_hash ?? null;
    const result = {
      schema_version: WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_restore_apply",
      thread_id: threadId,
      turn_id: snapshotTurnId,
      workspace_root: agent.cwd,
      snapshot_id: normalizedSnapshotId,
      snapshot_hash: snapshotHash,
      preview_status: previewStatus,
      apply_status: applyStatus,
      apply_supported: applyStatus !== "blocked" && applyStatus !== "failed",
      restore_apply_supported: applyStatus !== "blocked" && applyStatus !== "failed",
      approval_required: true,
      approval_satisfied: approval.satisfied,
      conflict_policy: conflictPolicy,
      file_count: counts.file_count,
      ready_count: counts.ready_count,
      noop_count: counts.noop_count,
      conflict_count: counts.conflict_count,
      blocked_count: counts.blocked_count,
      applied_count: counts.applied_count,
      apply_noop_count: counts.apply_noop_count,
      apply_blocked_count: counts.apply_blocked_count,
      failed_count: counts.failed_count,
      operations,
      policy: {
        status: applyStatus === "blocked" ? "blocked" : "allowed",
        approval_required: true,
        approval_satisfied: approval.satisfied,
        approval_source: approval.source,
        conflict_policy: conflictPolicy,
      },
      policy_decision_refs: policyDecisionRefs,
      receipt_refs: [receiptId],
      artifact_refs: [artifactId],
      rollback_refs: [normalizedSnapshotId],
      idempotency_key: idempotencyKey,
      summary: finalPolicyPlan.summary,
    };
    const artifactRecord = materializeWorkspaceRestoreApplyArtifact(store, {
      thread_id: threadId,
      workspace_root: agent.cwd,
      snapshot_id: normalizedSnapshotId,
      artifact_id: artifactId,
      receipt_id: receiptId,
      apply: result,
    });
    const event = appendWorkspaceRestoreApplyEvent(store, {
      thread_id: threadId,
      turn_id: result.turn_id,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      apply: {
        ...result,
        artifact_refs: [artifactRecord.id],
      },
    });
    return {
      ...result,
      artifact_refs: [artifactRecord.id],
      event,
      restore_apply_event: event,
    };
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

  function planWorkspaceRestoreApplyPolicy({
    snapshot_id: snapshotId,
    request = {},
    operations = null,
    counts = null,
    hard_blocked: hardBlocked = null,
    conflict_blocked: conflictBlocked = null,
  } = {}) {
    if (!workspaceRestoreRunner?.planApplyPolicy) {
      throw runtimeError({
        status: 502,
        code: "workspace_restore_bridge_unconfigured",
        message: "Workspace restore requires the Rust workspace restore bridge.",
        details: { snapshot_id: snapshotId },
      });
    }
    const policyRequest = {
      ...(request && typeof request === "object" && !Array.isArray(request) ? request : {}),
      snapshot_id: snapshotId,
    };
    if (Array.isArray(operations)) {
      policyRequest.operations = operations.map((operation) => ({
        path: operation.path,
        status: operation.status,
        blocked_reason: operation.blocked_reason ?? null,
      }));
    }
    if (counts) {
      policyRequest.counts = workspaceRestoreCountsForPolicy(counts);
    }
    if (typeof hardBlocked === "boolean") {
      policyRequest.hard_blocked = hardBlocked;
    }
    if (typeof conflictBlocked === "boolean") {
      policyRequest.conflict_blocked = conflictBlocked;
    }
    const plan = workspaceRestoreRunner.planApplyPolicy(policyRequest);
    const approval = plan?.approval && typeof plan.approval === "object" ? plan.approval : null;
    const applyStatus = plan?.apply_status;
    if (!approval || typeof approval.satisfied !== "boolean") {
      throw runtimeError({
        status: 502,
        code: "workspace_restore_bridge_invalid_plan",
        message: "Rust workspace restore policy bridge returned an invalid approval plan.",
        details: { snapshot_id: snapshotId },
      });
    }
    if (counts && !optionalString(applyStatus)) {
      throw runtimeError({
        status: 502,
        code: "workspace_restore_bridge_invalid_status",
        message: "Rust workspace restore policy bridge returned an invalid apply status.",
        details: { snapshot_id: snapshotId },
      });
    }
    if (counts && !optionalString(plan?.summary)) {
      throw runtimeError({
        status: 502,
        code: "workspace_restore_bridge_invalid_summary",
        message: "Rust workspace restore policy bridge returned an invalid apply summary.",
        details: { snapshot_id: snapshotId },
      });
    }
    return plan;
  }

  function previewWorkspaceRestoreOperations({ workspace_root: workspaceRoot, files } = {}) {
    if (!workspaceRestoreRunner?.previewOperations) {
      throw runtimeError({
        status: 502,
        code: "workspace_restore_bridge_unconfigured",
        message: "Workspace restore preview requires the Rust workspace restore bridge.",
        details: { workspace_root: workspaceRoot },
      });
    }
    return normalizeArray(
      workspaceRestoreRunner.previewOperations({
        workspace_root: workspaceRoot,
        files,
        max_diff_bytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
      }),
    );
  }

  function applyWorkspaceRestoreOperations({ workspace_root: workspaceRoot, files, allow_conflicts: allowConflicts } = {}) {
    if (!workspaceRestoreRunner?.applyOperations) {
      throw runtimeError({
        status: 502,
        code: "workspace_restore_bridge_unconfigured",
        message: "Workspace restore apply requires the Rust workspace restore bridge.",
        details: { workspace_root: workspaceRoot },
      });
    }
    return normalizeArray(
      workspaceRestoreRunner.applyOperations({
        workspace_root: workspaceRoot,
        files,
        max_diff_bytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
        allow_conflicts: Boolean(allowConflicts),
      }),
    );
  }

  function captureWorkspaceSnapshotFiles({ changedFiles, contentDrafts } = {}) {
    if (!workspaceRestoreRunner?.captureSnapshotFiles) {
      throw runtimeError({
        status: 502,
        code: "workspace_restore_bridge_unconfigured",
        message: "Workspace snapshot capture requires the Rust workspace restore bridge.",
        details: {},
      });
    }
    return workspaceRestoreRunner.captureSnapshotFiles({
      changed_files: normalizeArray(changedFiles),
      content_drafts: normalizeArray(contentDrafts),
      max_content_bytes: WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
    });
  }

  function workspaceRestoreOperationApplyReason(policyPlan, operation) {
    const pathValue = optionalString(operation?.path);
    const entries = normalizeArray(policyPlan?.operation_policies);
    const policy = entries.find((entry) => optionalString(entry?.path) === pathValue);
    const reason = optionalString(policy?.apply_reason);
    if (reason) return reason;
    throw runtimeError({
      status: 502,
      code: "workspace_restore_bridge_missing_operation_reason",
      message: "Rust workspace restore policy bridge did not return an apply reason for a restore operation.",
      details: { path: pathValue },
    });
  }

  function workspaceRestoreCountsForPolicy(counts = {}) {
    return {
      file_count: Number(counts.file_count ?? 0) || 0,
      ready_count: Number(counts.ready_count ?? 0) || 0,
      noop_count: Number(counts.noop_count ?? 0) || 0,
      conflict_count: Number(counts.conflict_count ?? 0) || 0,
      blocked_count: Number(counts.blocked_count ?? 0) || 0,
      applied_count: Number(counts.applied_count ?? 0) || 0,
      apply_noop_count: Number(counts.apply_noop_count ?? 0) || 0,
      apply_blocked_count: Number(counts.apply_blocked_count ?? 0) || 0,
      failed_count: Number(counts.failed_count ?? 0) || 0,
    };
  }

  function workspaceSnapshotContentPackage(store, threadId, snapshotId) {
    const matches = [...store.codingArtifacts.values()]
      .filter((artifactRecord) => artifactRecord.thread_id === threadId && artifactRecord.channel === "workspace-snapshot")
      .map((artifactRecord) => {
        const parsed = parseJsonObject(artifactRecord.content);
        const parsedSnapshotId =
          parsed?.snapshot_id ??
          parsed?.snapshot?.snapshot_id;
        return parsedSnapshotId === snapshotId ? { artifactRecord, parsed } : null;
      })
      .filter(Boolean);
    const match = matches[0];
    if (!match) {
      throw notFound(`Workspace snapshot not found: ${snapshotId}`, { threadId, snapshotId });
    }
    const snapshot = match.parsed.snapshot ?? match.parsed;
    if (!snapshot?.restore?.preview_supported) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_preview_unavailable",
        message: "Workspace snapshot does not contain enough captured content for restore preview.",
        details: {
          threadId,
          snapshotId,
          restoreStatus: snapshot?.restore?.status ?? "unknown",
        },
      });
    }
    return {
      artifactRecord: match.artifactRecord,
      snapshot,
      files: normalizeArray(match.parsed.files),
    };
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
    store,
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
    const createdAt = now();
    const content = JSON.stringify(value, null, 2);
    const artifactRecord = {
      schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      id: artifactId,
      thread_id: threadId,
      tool_name: toolName,
      tool_call_id: snapshotId,
      workspace_root: workspaceRoot,
      name,
      channel,
      media_type: "application/json",
      redaction,
      receipt_id: receiptId,
      content,
      content_bytes: Buffer.byteLength(content, "utf8"),
      content_hash: doctorHash(content),
      created_at: createdAt,
    };
    store.codingArtifacts.set(artifactRecord.id, artifactRecord);
    commitRuntimeArtifactRecord(store, artifactRecord, `artifact.${channel}`);
    return artifactRecord;
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
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId || "",
      item_id: `${turnId || threadId}:item:workspace-restore-preview:${safeId(preview.snapshot_id)}`,
      idempotency_key:
        optionalString(preview.idempotency_key) ??
        `thread:${threadId}:workspace-restore-preview:${preview.snapshot_id}:${doctorHash(
          JSON.stringify(preview.operations),
        ).slice(0, 12)}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceRestore.Previewed",
      event_kind: "workspace.restore.previewed",
      status: preview.preview_status === "ready" ? "completed" : "blocked",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "restore_gate",
      tool_call_id: preview.snapshot_id,
      artifact_refs: preview.artifact_refs,
      receipt_refs: preview.receipt_refs,
      rollback_refs: preview.rollback_refs,
      payload_schema_version: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      payload_summary: {
        ...preview,
        event_kind: "WorkspaceRestorePreview",
      },
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
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId || "",
      item_id: `${turnId || threadId}:item:workspace-restore-apply:${safeId(apply.snapshot_id)}`,
      idempotency_key:
        optionalString(apply.idempotency_key) ??
        `thread:${threadId}:workspace-restore-apply:${apply.snapshot_id}:${doctorHash(
          JSON.stringify(apply.operations),
        ).slice(0, 12)}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceRestore.Applied",
      event_kind: "workspace.restore.applied",
      status: apply.apply_status === "blocked" ? "blocked" : apply.apply_status === "failed" ? "failed" : "completed",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "restore_gate",
      tool_call_id: apply.snapshot_id,
      artifact_refs: apply.artifact_refs,
      receipt_refs: apply.receipt_refs,
      rollback_refs: apply.rollback_refs,
      policy_decision_refs: apply.policy_decision_refs,
      payload_schema_version: WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
      payload_summary: {
        ...apply,
        event_kind: "WorkspaceRestoreApply",
      },
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
