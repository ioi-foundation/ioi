import { CODING_TOOL_RESULT_SCHEMA_VERSION, retiredArtifactReadRangeAliases } from "./coding-tools.mjs";
import { commitRuntimeArtifactRecord } from "./runtime-artifact-state-commit.mjs";
import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  TERMINAL_EVENT_TYPES,
} from "./runtime-contract-constants.mjs";
import {
  notFound as defaultNotFound,
  policyError as defaultPolicyError,
  runtimeError as defaultRuntimeError,
} from "./runtime-http-utils.mjs";
import { createRuntimeCodingToolResultHelpers } from "./runtime-coding-tool-results.mjs";
import {
  doctorHash,
  normalizeArray,
  optionalString,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

const {
  codingToolArtifactMetadata,
  codingToolArtifactReadResult,
  codingToolCommandStreamRequested,
} = createRuntimeCodingToolResultHelpers({
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  TERMINAL_EVENT_TYPES,
  doctorHash,
  normalizeArray,
  optionalString,
  uniqueStrings,
});

export function createRuntimeCodingToolArtifactSurface(deps = {}) {
  const {
    codingToolCommandStreamAdmissionForThread = null,
    contextPolicyRunner = null,
    notFound = defaultNotFound,
    policyError = defaultPolicyError,
    runtimeError = defaultRuntimeError,
  } = deps;

  function throwCodingToolArtifactRustCoreRequired(operation, operationKind, details = {}) {
    throw runtimeError({
      status: 501,
      code: "runtime_coding_tool_artifact_rust_core_required",
      message: "Runtime coding-tool artifact mutation requires direct Rust daemon-core admission and persistence.",
      details: {
        rust_core_boundary: "runtime.coding_tool_artifact",
        operation,
        operation_kind: operationKind,
        ...details,
      },
    });
  }

  function codingToolArtifactDraftPlanner(store, request = {}) {
    const runner = store?.contextPolicyRunner ?? contextPolicyRunner;
    if (typeof runner?.planRuntimeCodingToolArtifactDrafts === "function") return runner;
    throwCodingToolArtifactRustCoreRequired("coding_tool_artifact_draft_materialization", "artifact.coding_tool_draft", {
      ...request,
      evidence_refs: [
        "coding_tool_artifact_draft_js_materializer_retired",
        "rust_daemon_core_artifact_draft_plan_required",
        "agentgres_artifact_state_truth_required",
      ],
    });
  }

  function assertArtifactStateCommitAvailable(store, request = {}) {
    if (typeof store?.commitRuntimeArtifactState === "function") return;
    throwCodingToolArtifactRustCoreRequired("coding_tool_artifact_draft_materialization", "artifact.coding_tool_draft", {
      ...request,
      source: "runtime.coding_tool_artifact_surface.agentgres_commit",
      evidence_refs: [
        "coding_tool_artifact_draft_js_materializer_retired",
        "rust_daemon_core_artifact_draft_plan_required",
        "agentgres_artifact_state_truth_required",
      ],
    });
  }

  function materializeCodingToolArtifactDrafts(
    store,
    { threadId, toolId, toolCallId, workspaceRoot, result, receiptId },
  ) {
    const artifactDrafts = normalizeArray(result?.artifact_drafts);
    if (!artifactDrafts.length) return [];
    const requestContext = {
      thread_id: threadId ?? null,
      tool_name: toolId ?? null,
      tool_call_id: toolCallId ?? null,
      workspace_root: workspaceRoot ?? null,
      receipt_id: receiptId ?? null,
      artifact_draft_count: artifactDrafts.length,
    };
    const runner = codingToolArtifactDraftPlanner(store, requestContext);
    assertArtifactStateCommitAvailable(store, requestContext);
    const canonicalResult = {
      ...(objectRecord(result) ?? {}),
      artifact_drafts: artifactDrafts,
    };
    delete canonicalResult.artifactDrafts;
    delete canonicalResult.artifactRefs;
    const plan = runner.planRuntimeCodingToolArtifactDrafts({
      operation: "coding_tool_artifact_draft_materialization",
      operation_kind: "artifact.coding_tool_draft",
      thread_id: threadId ?? null,
      tool_id: toolId ?? null,
      tool_call_id: toolCallId ?? null,
      workspace_root: workspaceRoot ?? null,
      receipt_id: receiptId ?? null,
      receipt_refs: uniqueStrings([...normalizeArray(result?.receipt_refs), receiptId].filter(Boolean)),
      result: canonicalResult,
      artifact_drafts: artifactDrafts,
      evidence_refs: [
        "coding_tool_artifact_draft_rust_owned",
        "coding_tool_artifact_draft_js_materializer_retired",
        "rust_daemon_core_artifact_draft_plan_required",
        "agentgres_artifact_state_truth_required",
      ],
    });
    const artifactRecords = normalizeArray(plan?.artifact_records);
    if (
      plan?.operation_kind !== "artifact.coding_tool_draft" ||
      artifactRecords.length !== artifactDrafts.length ||
      artifactRecords.some((record) => !record?.id || !normalizeArray(record?.receipt_refs).length)
    ) {
      throw runtimeError({
        status: 502,
        code: "runtime_coding_tool_artifact_draft_plan_invalid",
        message: "Rust daemon-core coding-tool artifact draft plan did not return valid artifact records.",
        details: {
          rust_core_boundary: "runtime.coding_tool_artifact",
          operation: "coding_tool_artifact_draft_materialization",
          operation_kind: "artifact.coding_tool_draft",
          thread_id: threadId ?? null,
          tool_name: toolId ?? null,
          tool_call_id: toolCallId ?? null,
          planned_operation_kind: plan?.operation_kind ?? null,
          planned_artifact_count: artifactRecords.length,
          expected_artifact_count: artifactDrafts.length,
        },
      });
    }
    const committedArtifacts = [];
    for (const artifactRecord of artifactRecords) {
      try {
        const commit = commitRuntimeArtifactRecord(store, artifactRecord, plan.operation_kind);
        const committedArtifact = {
          ...artifactRecord,
          artifact_state_commit: commit,
          artifact_state_commit_hash: commit.commit_hash,
          artifact_state_object_ref: commit.object_ref,
        };
        store.codingArtifacts.set(committedArtifact.id, committedArtifact);
        committedArtifacts.push(committedArtifact);
      } catch (error) {
        throw runtimeError({
          status: 502,
          code: "runtime_coding_tool_artifact_agentgres_commit_failed",
          message: "Rust Agentgres artifact-state admission rejected the coding-tool artifact record.",
          details: {
            rust_core_boundary: "runtime.coding_tool_artifact",
            operation: "coding_tool_artifact_draft_materialization",
            operation_kind: "artifact.coding_tool_draft",
            artifact_id: artifactRecord?.id ?? null,
            cause: error?.message ?? String(error),
            evidence_refs: [
              "coding_tool_artifact_draft_rust_owned",
              "rust_daemon_core_artifact_draft_plan_required",
              "agentgres_artifact_state_truth_required",
            ],
          },
        });
      }
    }
    return committedArtifacts;
  }

  function readCodingToolArtifact(store, threadId, artifactId, range = {}) {
    assertNoRetiredArtifactReadRangeAliases(range, { threadId, artifactId, operation: "artifact.read" });
    const artifactRecord = store.codingArtifacts.get(artifactId);
    if (!artifactRecord) throw notFound(`Artifact not found: ${artifactId}`, { thread_id: threadId, artifact_id: artifactId });
    if (artifactRecord.thread_id && artifactRecord.thread_id !== threadId) {
      throw policyError("Artifact read blocked outside the owning runtime thread.", {
        thread_id: threadId,
        artifact_id: artifactId,
        owner_thread_id: artifactRecord.thread_id,
      });
    }
    return codingToolArtifactReadResult(artifactRecord, range);
  }

  function retrieveCodingToolResult(store, threadId, query = {}) {
    assertNoRetiredArtifactReadRangeAliases(query.range, { threadId, operation: "tool.retrieve_result" });
    if (query.artifact_id) {
      return {
        ...readCodingToolArtifact(store, threadId, query.artifact_id, query.range),
        shell_fallback_used: false,
      };
    }
    const toolCallId = optionalString(query.tool_call_id);
    if (!toolCallId) {
      throw runtimeError({
        status: 400,
        code: "tool_retrieve_result_target_required",
        message: "tool.retrieve_result requires a tool_call_id or artifact_id.",
        details: { thread_id: threadId },
      });
    }
    const artifacts = [...store.codingArtifacts.values()]
      .filter((artifactRecord) => artifactRecord.thread_id === threadId && artifactRecord.tool_call_id === toolCallId)
      .sort((left, right) => String(left.channel ?? "").localeCompare(String(right.channel ?? "")));
    if (!artifacts.length) {
      throw notFound(`Tool result artifact not found: ${toolCallId}`, {
        thread_id: threadId,
        tool_call_id: toolCallId,
      });
    }
    const channel = optionalString(query.channel);
    const artifactRecord = artifacts.find((item) => item.channel === channel) ?? artifacts[0];
    return {
      ...codingToolArtifactReadResult(artifactRecord, query.range),
      tool_call_id: toolCallId,
      available_artifacts: artifacts.map(codingToolArtifactMetadata),
      shell_fallback_used: false,
    };
  }

  function assertNoRetiredArtifactReadRangeAliases(range = {}, details = {}) {
    const retiredAliases = retiredArtifactReadRangeAliases(range);
    if (retiredAliases.length === 0) return;
    throw runtimeError({
      status: 400,
      code: "artifact_read_range_aliases_retired",
      message: "Artifact read range aliases are retired; use canonical offset_bytes, length_bytes, or max_bytes.",
      details: {
        ...details,
        retired_aliases: retiredAliases,
      },
    });
  }

  function objectRecord(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  }

  function admitCodingToolCommandStreamEvents(
    store,
    {
      agent,
      threadId,
      turnId,
      toolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
      request = {},
      result = {},
      status = "completed",
      receiptRefs = [],
      artifactRefs = [],
    } = {},
  ) {
    if (!codingToolCommandStreamRequested(request)) return [];
    if (typeof codingToolCommandStreamAdmissionForThread !== "function") {
      throwCodingToolArtifactRustCoreRequired("coding_tool_command_stream_event_admission", "runtime.coding_tool_command_stream", {
        thread_id: threadId ?? null,
        turn_id: turnId ?? null,
        tool_name: toolId ?? null,
        tool_call_id: toolCallId ?? null,
        workspace_root: agent?.cwd ?? null,
        workflow_graph_id: workflowGraphId ?? null,
        workflow_node_id: workflowNodeId ?? null,
        receipt_refs: uniqueStrings(receiptRefs),
        artifact_refs: uniqueStrings(artifactRefs),
        evidence_refs: [
          "coding_tool_command_stream_js_event_append_retired",
          "rust_daemon_core_command_stream_receipt_required",
          "agentgres_command_stream_expected_head_required",
        ],
      });
    }
    const admission = codingToolCommandStreamAdmissionForThread(store, {
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId ?? null,
      turn_id: turnId ?? null,
      tool_id: toolId ?? null,
      tool_call_id: toolCallId ?? null,
      workspace_root: agent?.cwd ?? null,
      workflow_graph_id: workflowGraphId ?? null,
      workflow_node_id: workflowNodeId ?? null,
      source: request.source,
      status,
      request,
      result,
      receipt_refs: uniqueStrings(receiptRefs),
      artifact_refs: uniqueStrings(artifactRefs),
    });
    return normalizeArray(admission?.events ?? admission);
  }

  function materializeVisualGuiObservationArtifacts(_store, { threadId, toolId, toolCallId, workspaceRoot, input } = {}) {
    throwCodingToolArtifactRustCoreRequired("computer_use_visual_observation_artifact_materialization", "artifact.visual_observation", {
      thread_id: threadId ?? null,
      tool_name: toolId ?? null,
      tool_call_id: toolCallId ?? null,
      workspace_root: workspaceRoot ?? null,
      has_screenshot_path: Boolean(input?.screenshot_path),
      has_som_path: Boolean(input?.som_path),
      has_ax_path: Boolean(input?.ax_path),
      evidence_refs: [
        "visual_observation_artifact_js_materializer_retired",
        "rust_daemon_core_visual_artifact_admission_required",
        "agentgres_visual_artifact_state_truth_required",
      ],
    });
  }

  return {
    admitCodingToolCommandStreamEvents,
    materializeCodingToolArtifactDrafts,
    materializeVisualGuiObservationArtifacts,
    readCodingToolArtifact,
    retrieveCodingToolResult,
  };
}
