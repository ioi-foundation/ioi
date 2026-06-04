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
  writeJson as defaultWriteJson,
} from "./runtime-http-utils.mjs";
import {
  WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
  WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
  parseJsonObject,
  workspaceRestoreApplyOperations,
  workspaceRestoreOperationCounts,
  workspaceRestorePreviewOperation,
  workspaceSnapshotContentDraftsByPath,
  workspaceSnapshotFileForPatch,
} from "./workspace-restore.mjs";
import { doctorHash, normalizeArray, optionalString, safeId } from "./runtime-value-helpers.mjs";

export function createRuntimeWorkspaceSnapshotSurface(deps = {}) {
  const {
    now = () => new Date().toISOString(),
    notFound = defaultNotFound,
    runtimeError = defaultRuntimeError,
    writeJson = defaultWriteJson,
    workspaceRestoreApplyAllowsConflicts,
    workspaceRestoreApplyApprovalForRequest,
    workspaceRestoreApplyBlockedReason,
    workspaceRestoreApplyPolicyDecisionRefs,
    workspaceRestoreApplyStatus,
    workspaceRestoreApplySummary,
  } = deps;

  function prepareWorkspaceSnapshotForPatch(
    store,
    { threadId, turnId, workspaceRoot, toolCallId, workflowGraphId, workflowNodeId, result = {} } = {},
  ) {
    if (!result?.applied) return null;
    const contentDraftsByPath = workspaceSnapshotContentDraftsByPath(
      result.workspaceSnapshotDrafts ?? result.workspace_snapshot_drafts,
    );
    const captureRecords = normalizeArray(result.changedFiles)
      .filter((entry) => optionalString(entry?.path))
      .map((entry) =>
        workspaceSnapshotFileForPatch(entry, contentDraftsByPath.get(optionalString(entry?.path) ?? ""), {
          maxContentBytes: WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
        }),
      );
    const files = captureRecords.map((capture) => capture.publicFile);
    const contentFiles = captureRecords.map((capture) => capture.contentFile);
    if (!files.length) return null;
    const capturedFileCount = captureRecords.filter((capture) => capture.contentCaptured).length;
    const omittedFileCount = captureRecords.length - capturedFileCount;
    const previewSupported = omittedFileCount === 0;
    const core = {
      schemaVersion: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot",
      threadId,
      turnId: turnId || null,
      workspaceRoot,
      snapshotKind: "pre_post_touched_files",
      trigger: {
        toolName: "file.apply_patch",
        toolCallId,
        workflowGraphId,
        workflowNodeId,
      },
      fileCount: files.length,
      changedFileCount: files.filter((file) => file.changed).length,
      createdFileCount: files.filter((file) => file.created).length,
      deletedFileCount: files.filter((file) => file.deleted).length,
      files,
      capture: {
        status: previewSupported ? "content_captured" : "partial_content",
        maxContentBytes: WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES,
        capturedFileCount,
        omittedFileCount,
      },
      restore: {
        status: previewSupported ? "content_captured" : "partial_content",
        previewSupported,
        applySupported: previewSupported,
        reason: previewSupported ? "restore_apply_requires_approval" : "snapshot_content_capture_incomplete",
      },
      redaction: {
        profile: "workspace_snapshot_content_artifact",
        contentIncluded: false,
        contentArtifactIncluded: true,
        pathsIncluded: true,
      },
      evidenceRefs: ["workspace_snapshot_content", "file.apply_patch", toolCallId].filter(Boolean),
    };
    const snapshotHash = doctorHash(JSON.stringify(core));
    const snapshotId = `workspace_snapshot_${safeId(toolCallId)}_${snapshotHash.slice(0, 12)}`;
    const receiptId = `receipt_${snapshotId}`;
    const artifactId = `artifact_${safeId(snapshotId)}_content`;
    const record = {
      ...core,
      snapshotId,
      snapshot_id: snapshotId,
      snapshotHash,
      snapshot_hash: snapshotHash,
      receiptRefs: [receiptId],
      receipt_refs: [receiptId],
      artifactRefs: [artifactId],
      artifact_refs: [artifactId],
      contentArtifactRefs: [artifactId],
      content_artifact_refs: [artifactId],
      summary: `Workspace snapshot recorded ${files.length} changed file(s) for ${toolCallId}.`,
    };
    const artifactPayload = {
      schemaVersion: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot_content",
      snapshotId,
      snapshot_id: snapshotId,
      snapshotHash,
      snapshot_hash: snapshotHash,
      threadId,
      thread_id: threadId,
      turnId: turnId || null,
      turn_id: turnId || null,
      workspaceRoot,
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
      schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      id: artifactId,
      thread_id: threadId,
      threadId,
      tool_name: "file.apply_patch",
      toolName: "file.apply_patch",
      tool_call_id: toolCallId,
      toolCallId,
      workspace_root: workspaceRoot,
      workspaceRoot,
      name: "workspace-snapshot-content.json",
      channel: "workspace-snapshot",
      media_type: "application/json",
      mediaType: "application/json",
      redaction: "workspace_snapshot_content_artifact",
      receipt_id: receiptId,
      receiptId,
      content,
      content_bytes: Buffer.byteLength(content, "utf8"),
      contentBytes: Buffer.byteLength(content, "utf8"),
      content_hash: doctorHash(content),
      contentHash: doctorHash(content),
      created_at: createdAt,
      createdAt,
    };
    store.codingArtifacts.set(artifactRecord.id, artifactRecord);
    writeJson(store.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
    return artifactRecord;
  }

  function appendWorkspaceSnapshotEvent(
    store,
    { threadId, turnId, workspaceRoot, workflowGraphId, snapshot, sourceToolEvent } = {},
  ) {
    if (!snapshot?.snapshotId) return null;
    const payloadSummary = {
      schema_version: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      event_kind: "WorkspaceSnapshotCreated",
      snapshot_id: snapshot.snapshotId,
      snapshot_hash: snapshot.snapshotHash,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: workspaceRoot,
      snapshot_kind: snapshot.snapshotKind,
      file_count: snapshot.fileCount,
      changed_file_count: snapshot.changedFileCount,
      created_file_count: snapshot.createdFileCount,
      deleted_file_count: snapshot.deletedFileCount,
      restore_status: snapshot.restore?.status ?? "metadata_only",
      restore_preview_supported: Boolean(snapshot.restore?.previewSupported),
      restore_apply_supported: Boolean(snapshot.restore?.applySupported),
      source_tool_name: "file.apply_patch",
      source_tool_call_id: sourceToolEvent?.tool_call_id ?? snapshot.trigger?.toolCallId ?? null,
      source_tool_event_id: sourceToolEvent?.event_id ?? null,
      source_workflow_node_id: snapshot.trigger?.workflowNodeId ?? null,
      files: snapshot.files,
      receipt_refs: snapshot.receiptRefs,
      artifact_refs: snapshot.artifactRefs,
      summary: snapshot.summary,
      snapshot,
    };
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:workspace-snapshot:${safeId(snapshot.snapshotId)}`,
      idempotency_key: `thread:${threadId}:workspace-snapshot:${snapshot.snapshotId}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceSnapshot.Created",
      event_kind: "workspace.snapshot.created",
      status: "completed",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId ?? snapshot.trigger?.workflowGraphId ?? null,
      workflow_node_id: WORKSPACE_SNAPSHOT_NODE_ID,
      component_kind: "workspace_snapshot",
      tool_call_id: sourceToolEvent?.tool_call_id ?? snapshot.trigger?.toolCallId ?? null,
      artifact_refs: snapshot.artifactRefs,
      receipt_refs: snapshot.receiptRefs,
      rollback_refs: [snapshot.snapshotId],
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
      schemaVersion: WORKSPACE_SNAPSHOT_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_snapshot_list",
      threadId,
      thread_id: threadId,
      snapshotCount: snapshots.length,
      snapshot_count: snapshots.length,
      snapshots,
    };
  }

  function previewWorkspaceSnapshotRestore(store, threadId, snapshotId, request = {}) {
    const agent = store.agentForThread(threadId);
    const normalizedSnapshotId = optionalString(snapshotId);
    if (!normalizedSnapshotId) {
      throw runtimeError({
        status: 400,
        code: "workspace_snapshot_id_required",
        message: "Restore preview requires a workspace snapshot id.",
        details: { threadId },
      });
    }
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key ?? request.idempotencyKey);
    const snapshotPackage = workspaceSnapshotContentPackage(store, threadId, normalizedSnapshotId);
    const operations = normalizeArray(snapshotPackage.files).map((file) =>
      workspaceRestorePreviewOperation({
        workspaceRoot: agent.cwd,
        file,
        maxDiffBytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
      }),
    );
    if (!operations.length) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_preview_empty",
        message: "Restore preview could not find content-backed files in the snapshot.",
        details: { threadId, snapshotId: normalizedSnapshotId },
      });
    }
    const readyCount = operations.filter((operation) => operation.status === "ready").length;
    const noopCount = operations.filter((operation) => operation.status === "noop").length;
    const conflictCount = operations.filter((operation) => operation.status === "conflict").length;
    const blockedCount = operations.filter((operation) => operation.status === "blocked").length;
    const previewStatus = conflictCount || blockedCount ? "blocked" : "ready";
    const receiptId = `receipt_workspace_restore_preview_${safeId(normalizedSnapshotId)}_${doctorHash(
      JSON.stringify(operations.map((operation) => [operation.path, operation.status, operation.currentHash])),
    ).slice(0, 12)}`;
    const artifactId = `artifact_workspace_restore_preview_${safeId(normalizedSnapshotId)}_${doctorHash(receiptId).slice(0, 12)}`;
    const result = {
      schemaVersion: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      schema_version: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_restore_preview",
      threadId,
      thread_id: threadId,
      turnId: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      turn_id: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      workspaceRoot: agent.cwd,
      workspace_root: agent.cwd,
      snapshotId: normalizedSnapshotId,
      snapshot_id: normalizedSnapshotId,
      snapshotHash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      snapshot_hash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      previewStatus,
      preview_status: previewStatus,
      previewSupported: blockedCount === 0,
      preview_supported: blockedCount === 0,
      applySupported: previewStatus === "ready",
      apply_supported: previewStatus === "ready",
      restoreApplySupported: previewStatus === "ready",
      restore_apply_supported: previewStatus === "ready",
      fileCount: operations.length,
      file_count: operations.length,
      readyCount,
      ready_count: readyCount,
      noopCount,
      noop_count: noopCount,
      conflictCount,
      conflict_count: conflictCount,
      blockedCount,
      blocked_count: blockedCount,
      operations,
      receiptRefs: [receiptId],
      receipt_refs: [receiptId],
      artifactRefs: [artifactId],
      artifact_refs: [artifactId],
      rollbackRefs: [normalizedSnapshotId],
      rollback_refs: [normalizedSnapshotId],
      idempotencyKey,
      idempotency_key: idempotencyKey,
      summary:
        previewStatus === "ready"
          ? `Restore preview ready for ${operations.length} file(s) from ${normalizedSnapshotId}.`
          : `Restore preview blocked for ${normalizedSnapshotId}: ${conflictCount} conflict(s), ${blockedCount} blocked file(s).`,
    };
    const artifactRecord = materializeWorkspaceRestorePreviewArtifact(store, {
      threadId,
      workspaceRoot: agent.cwd,
      snapshotId: normalizedSnapshotId,
      artifactId,
      receiptId,
      preview: result,
    });
    const event = appendWorkspaceRestorePreviewEvent(store, {
      threadId,
      turnId: result.turnId,
      workspaceRoot: agent.cwd,
      workflowGraphId,
      workflowNodeId,
      preview: {
        ...result,
        artifactRefs: [artifactRecord.id],
        artifact_refs: [artifactRecord.id],
      },
    });
    return {
      ...result,
      artifactRefs: [artifactRecord.id],
      artifact_refs: [artifactRecord.id],
      event,
      restore_preview_event: event,
      restorePreviewEvent: event,
    };
  }

  function applyWorkspaceSnapshotRestore(store, threadId, snapshotId, request = {}) {
    const agent = store.agentForThread(threadId);
    const normalizedSnapshotId = optionalString(snapshotId);
    if (!normalizedSnapshotId) {
      throw runtimeError({
        status: 400,
        code: "workspace_snapshot_id_required",
        message: "Restore apply requires a workspace snapshot id.",
        details: { threadId },
      });
    }
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? WORKSPACE_RESTORE_PREVIEW_NODE_ID;
    const idempotencyKey = optionalString(request.idempotency_key ?? request.idempotencyKey);
    const approval = workspaceRestoreApplyApprovalForRequest(request);
    const allowConflicts = workspaceRestoreApplyAllowsConflicts(request);
    const conflictPolicy = allowConflicts ? "override_conflicts" : "clean_preview_only";
    const snapshotPackage = workspaceSnapshotContentPackage(store, threadId, normalizedSnapshotId);
    const previewOperations = normalizeArray(snapshotPackage.files).map((file) =>
      workspaceRestorePreviewOperation({
        workspaceRoot: agent.cwd,
        file,
        maxDiffBytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
      }),
    );
    if (!previewOperations.length) {
      throw runtimeError({
        status: 409,
        code: "workspace_restore_apply_empty",
        message: "Restore apply could not find content-backed files in the snapshot.",
        details: { threadId, snapshotId: normalizedSnapshotId },
      });
    }
    const previewCounts = workspaceRestoreOperationCounts(previewOperations);
    const hardBlocked = previewCounts.blockedCount > 0;
    const conflictBlocked = previewCounts.conflictCount > 0 && !allowConflicts;
    let operations = previewOperations.map((operation) => ({
      ...operation,
      applyStatus: "blocked",
      apply_status: "blocked",
      applyReason: workspaceRestoreApplyBlockedReason(operation, {
        approvalSatisfied: approval.satisfied,
        allowConflicts,
        hardBlocked,
        conflictBlocked,
      }),
      apply_reason: workspaceRestoreApplyBlockedReason(operation, {
        approvalSatisfied: approval.satisfied,
        allowConflicts,
        hardBlocked,
        conflictBlocked,
      }),
    }));
    if (approval.satisfied && !hardBlocked && !conflictBlocked) {
      operations = workspaceRestoreApplyOperations({
        workspaceRoot: agent.cwd,
        files: snapshotPackage.files,
        maxDiffBytes: WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES,
        allowConflicts,
      });
    }
    const counts = workspaceRestoreOperationCounts(operations);
    const applyStatus = workspaceRestoreApplyStatus(counts);
    const previewStatus = counts.conflictCount || counts.blockedCount ? "blocked" : "ready";
    const policyDecisionRefs = workspaceRestoreApplyPolicyDecisionRefs({
      snapshotId: normalizedSnapshotId,
      approval,
      allowConflicts,
      hardBlocked,
      conflictBlocked,
      applyStatus,
    });
    const receiptId = `receipt_workspace_restore_apply_${safeId(normalizedSnapshotId)}_${doctorHash(
      JSON.stringify(operations.map((operation) => [
        operation.path,
        operation.applyStatus ?? operation.apply_status,
        operation.appliedHash ?? operation.applied_hash,
      ])),
    ).slice(0, 12)}`;
    const artifactId = `artifact_workspace_restore_apply_${safeId(normalizedSnapshotId)}_${doctorHash(receiptId).slice(0, 12)}`;
    const result = {
      schemaVersion: WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
      schema_version: WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION,
      object: "ioi.runtime_workspace_restore_apply",
      threadId,
      thread_id: threadId,
      turnId: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      turn_id: snapshotPackage.snapshot?.turnId ?? snapshotPackage.snapshot?.turn_id ?? null,
      workspaceRoot: agent.cwd,
      workspace_root: agent.cwd,
      snapshotId: normalizedSnapshotId,
      snapshot_id: normalizedSnapshotId,
      snapshotHash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      snapshot_hash: snapshotPackage.snapshot?.snapshotHash ?? snapshotPackage.snapshot?.snapshot_hash ?? null,
      previewStatus,
      preview_status: previewStatus,
      applyStatus,
      apply_status: applyStatus,
      applySupported: applyStatus !== "blocked" && applyStatus !== "failed",
      apply_supported: applyStatus !== "blocked" && applyStatus !== "failed",
      restoreApplySupported: applyStatus !== "blocked" && applyStatus !== "failed",
      restore_apply_supported: applyStatus !== "blocked" && applyStatus !== "failed",
      approvalRequired: true,
      approval_required: true,
      approvalSatisfied: approval.satisfied,
      approval_satisfied: approval.satisfied,
      conflictPolicy,
      conflict_policy: conflictPolicy,
      fileCount: counts.fileCount,
      file_count: counts.fileCount,
      readyCount: counts.readyCount,
      ready_count: counts.readyCount,
      noopCount: counts.noopCount,
      noop_count: counts.noopCount,
      conflictCount: counts.conflictCount,
      conflict_count: counts.conflictCount,
      blockedCount: counts.blockedCount,
      blocked_count: counts.blockedCount,
      appliedCount: counts.appliedCount,
      applied_count: counts.appliedCount,
      applyNoopCount: counts.applyNoopCount,
      apply_noop_count: counts.applyNoopCount,
      applyBlockedCount: counts.applyBlockedCount,
      apply_blocked_count: counts.applyBlockedCount,
      failedCount: counts.failedCount,
      failed_count: counts.failedCount,
      operations,
      policy: {
        status: applyStatus === "blocked" ? "blocked" : "allowed",
        approvalRequired: true,
        approvalSatisfied: approval.satisfied,
        approvalSource: approval.source,
        conflictPolicy,
      },
      policy_decision_refs: policyDecisionRefs,
      policyDecisionRefs,
      receiptRefs: [receiptId],
      receipt_refs: [receiptId],
      artifactRefs: [artifactId],
      artifact_refs: [artifactId],
      rollbackRefs: [normalizedSnapshotId],
      rollback_refs: [normalizedSnapshotId],
      idempotencyKey,
      idempotency_key: idempotencyKey,
      summary: workspaceRestoreApplySummary({
        snapshotId: normalizedSnapshotId,
        applyStatus,
        counts,
        approval,
        allowConflicts,
      }),
    };
    const artifactRecord = materializeWorkspaceRestoreApplyArtifact(store, {
      threadId,
      workspaceRoot: agent.cwd,
      snapshotId: normalizedSnapshotId,
      artifactId,
      receiptId,
      apply: result,
    });
    const event = appendWorkspaceRestoreApplyEvent(store, {
      threadId,
      turnId: result.turnId,
      workspaceRoot: agent.cwd,
      workflowGraphId,
      workflowNodeId,
      apply: {
        ...result,
        artifactRefs: [artifactRecord.id],
        artifact_refs: [artifactRecord.id],
      },
    });
    return {
      ...result,
      artifactRefs: [artifactRecord.id],
      artifact_refs: [artifactRecord.id],
      event,
      restore_apply_event: event,
      restoreApplyEvent: event,
    };
  }

  function workspaceSnapshotContentPackage(store, threadId, snapshotId) {
    const matches = [...store.codingArtifacts.values()]
      .filter((artifactRecord) => artifactRecord.thread_id === threadId && artifactRecord.channel === "workspace-snapshot")
      .map((artifactRecord) => {
        const parsed = parseJsonObject(artifactRecord.content);
        const parsedSnapshotId =
          parsed?.snapshotId ??
          parsed?.snapshot_id ??
          parsed?.snapshot?.snapshotId ??
          parsed?.snapshot?.snapshot_id;
        return parsedSnapshotId === snapshotId ? { artifactRecord, parsed } : null;
      })
      .filter(Boolean);
    const match = matches[0];
    if (!match) {
      throw notFound(`Workspace snapshot not found: ${snapshotId}`, { threadId, snapshotId });
    }
    const snapshot = match.parsed.snapshot ?? match.parsed;
    if (!snapshot?.restore?.previewSupported) {
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
    { threadId, workspaceRoot, snapshotId, artifactId, receiptId, preview } = {},
  ) {
    return materializeWorkspaceRestoreArtifact(store, {
      threadId,
      workspaceRoot,
      snapshotId,
      artifactId,
      receiptId,
      value: preview,
      toolName: "workspace.restore_preview",
      name: "workspace-restore-preview.json",
      channel: "restore-preview",
      redaction: "workspace_restore_preview",
    });
  }

  function materializeWorkspaceRestoreApplyArtifact(
    store,
    { threadId, workspaceRoot, snapshotId, artifactId, receiptId, apply } = {},
  ) {
    return materializeWorkspaceRestoreArtifact(store, {
      threadId,
      workspaceRoot,
      snapshotId,
      artifactId,
      receiptId,
      value: apply,
      toolName: "workspace.restore_apply",
      name: "workspace-restore-apply.json",
      channel: "restore-apply",
      redaction: "workspace_restore_apply",
    });
  }

  function materializeWorkspaceRestoreArtifact(
    store,
    { threadId, workspaceRoot, snapshotId, artifactId, receiptId, value, toolName, name, channel, redaction },
  ) {
    const createdAt = now();
    const content = JSON.stringify(value, null, 2);
    const artifactRecord = {
      schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      id: artifactId,
      thread_id: threadId,
      threadId,
      tool_name: toolName,
      toolName,
      tool_call_id: snapshotId,
      toolCallId: snapshotId,
      workspace_root: workspaceRoot,
      workspaceRoot,
      name,
      channel,
      media_type: "application/json",
      mediaType: "application/json",
      redaction,
      receipt_id: receiptId,
      receiptId,
      content,
      content_bytes: Buffer.byteLength(content, "utf8"),
      contentBytes: Buffer.byteLength(content, "utf8"),
      content_hash: doctorHash(content),
      contentHash: doctorHash(content),
      created_at: createdAt,
      createdAt,
    };
    store.codingArtifacts.set(artifactRecord.id, artifactRecord);
    writeJson(store.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
    return artifactRecord;
  }

  function appendWorkspaceRestorePreviewEvent(
    store,
    { threadId, turnId, workspaceRoot, workflowGraphId, workflowNodeId, preview } = {},
  ) {
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId || "",
      item_id: `${turnId || threadId}:item:workspace-restore-preview:${safeId(preview.snapshotId)}`,
      idempotency_key:
        optionalString(preview.idempotency_key ?? preview.idempotencyKey) ??
        `thread:${threadId}:workspace-restore-preview:${preview.snapshotId}:${doctorHash(
          JSON.stringify(preview.operations),
        ).slice(0, 12)}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceRestore.Previewed",
      event_kind: "workspace.restore.previewed",
      status: preview.previewStatus === "ready" ? "completed" : "blocked",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "restore_gate",
      tool_call_id: preview.snapshotId,
      artifact_refs: preview.artifactRefs,
      receipt_refs: preview.receiptRefs,
      rollback_refs: preview.rollbackRefs,
      payload_schema_version: WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION,
      payload_summary: {
        ...preview,
        event_kind: "WorkspaceRestorePreview",
      },
    });
  }

  function appendWorkspaceRestoreApplyEvent(
    store,
    { threadId, turnId, workspaceRoot, workflowGraphId, workflowNodeId, apply } = {},
  ) {
    return store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId || "",
      item_id: `${turnId || threadId}:item:workspace-restore-apply:${safeId(apply.snapshotId)}`,
      idempotency_key:
        optionalString(apply.idempotency_key ?? apply.idempotencyKey) ??
        `thread:${threadId}:workspace-restore-apply:${apply.snapshotId}:${doctorHash(
          JSON.stringify(apply.operations),
        ).slice(0, 12)}`,
      source: "runtime_auto",
      source_event_kind: "WorkspaceRestore.Applied",
      event_kind: "workspace.restore.applied",
      status: apply.applyStatus === "blocked" ? "blocked" : apply.applyStatus === "failed" ? "failed" : "completed",
      actor: "runtime",
      workspace_root: workspaceRoot,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "restore_gate",
      tool_call_id: apply.snapshotId,
      artifact_refs: apply.artifactRefs,
      receipt_refs: apply.receiptRefs,
      rollback_refs: apply.rollbackRefs,
      policy_decision_refs: apply.policyDecisionRefs,
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
