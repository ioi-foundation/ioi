import { CODING_TOOL_RESULT_SCHEMA_VERSION, retiredArtifactReadRangeAliases } from "./coding-tools.mjs";
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
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

const {
  codingToolArtifactMetadata,
  codingToolArtifactReadResult,
  codingToolCommandStreamChunks,
  codingToolCommandStreamRequested,
} = createRuntimeCodingToolResultHelpers({
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  TERMINAL_EVENT_TYPES,
  doctorHash,
  normalizeArray,
  optionalString,
  safeId,
  uniqueStrings,
});

export function createRuntimeCodingToolArtifactSurface(deps = {}) {
  const {
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

  function materializeCodingToolArtifactDrafts(
    _store,
    { threadId, toolId, toolCallId, workspaceRoot, result, receiptId },
  ) {
    throwCodingToolArtifactRustCoreRequired("coding_tool_artifact_draft_materialization", "artifact.coding_tool_draft", {
      thread_id: threadId ?? null,
      tool_name: toolId ?? null,
      tool_call_id: toolCallId ?? null,
      workspace_root: workspaceRoot ?? null,
      receipt_id: receiptId ?? null,
      artifact_draft_count: normalizeArray(result?.artifact_drafts).length,
      evidence_refs: [
        "coding_tool_artifact_draft_js_materializer_retired",
        "rust_daemon_core_artifact_admission_required",
        "agentgres_artifact_state_truth_required",
      ],
    });
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

  function appendCodingToolCommandStreamEvents(
    _store,
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
    const chunks = codingToolCommandStreamChunks(result);
    if (chunks.length === 0) return [];
    throwCodingToolArtifactRustCoreRequired("coding_tool_command_stream_event_append", "artifact.command_stream", {
      thread_id: threadId ?? null,
      turn_id: turnId ?? null,
      tool_name: toolId ?? null,
      tool_call_id: toolCallId ?? null,
      workspace_root: agent?.cwd ?? null,
      workflow_graph_id: workflowGraphId ?? null,
      workflow_node_id: workflowNodeId ?? null,
      stream_chunk_count: chunks.length,
      receipt_refs: uniqueStrings(receiptRefs),
      artifact_refs: uniqueStrings(artifactRefs),
      evidence_refs: [
        "coding_tool_command_stream_js_event_append_retired",
        "rust_daemon_core_command_stream_receipt_required",
        "agentgres_command_stream_expected_head_required",
      ],
    });
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
    appendCodingToolCommandStreamEvents,
    materializeCodingToolArtifactDrafts,
    materializeVisualGuiObservationArtifacts,
    readCodingToolArtifact,
    retrieveCodingToolResult,
  };
}
