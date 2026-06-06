import fs from "node:fs";
import path from "node:path";

import { CODING_TOOL_RESULT_SCHEMA_VERSION } from "./coding-tools.mjs";
import { firstOptionalString, snakeCaseKey, visualGuiMediaTypeForPath } from "./computer-use-inputs.mjs";
import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES,
  TERMINAL_EVENT_TYPES,
} from "./runtime-contract-constants.mjs";
import {
  notFound as defaultNotFound,
  policyError as defaultPolicyError,
  runtimeError as defaultRuntimeError,
  writeJson as defaultWriteJson,
} from "./runtime-http-utils.mjs";
import { createRuntimeCodingToolResultHelpers } from "./runtime-coding-tool-results.mjs";
import {
  doctorHash,
  normalizeArray,
  operatorControlSource,
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
    now = () => new Date().toISOString(),
    notFound = defaultNotFound,
    policyError = defaultPolicyError,
    runtimeError = defaultRuntimeError,
    writeJson = defaultWriteJson,
    maxVisualArtifactBytes = COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES,
  } = deps;

  function materializeCodingToolArtifactDrafts(
    store,
    { threadId, toolId, toolCallId, workspaceRoot, result, receiptId },
  ) {
    const drafts = normalizeArray(result?.artifactDrafts ?? result?.artifact_drafts);
    const createdAt = now();
    return drafts
      .map((draft, index) => {
        if (!draft || typeof draft !== "object" || Array.isArray(draft)) return null;
        const content = String(draft.content ?? "");
        const channel = optionalString(draft.channel) ?? `artifact-${index + 1}`;
        const mediaType = optionalString(draft.mediaType ?? draft.media_type) ?? "text/plain";
        const contentBytes = Buffer.byteLength(content, "utf8");
        const contentHash = doctorHash(content);
        const artifactRecord = {
          schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
          schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
          id: `artifact_coding_tool_${safeId(toolCallId)}_${safeId(channel)}`,
          thread_id: threadId,
          threadId,
          tool_name: toolId,
          toolName: toolId,
          tool_call_id: toolCallId,
          toolCallId,
          workspace_root: workspaceRoot,
          workspaceRoot,
          name: optionalString(draft.name) ?? `${safeId(toolId)}-${channel}.txt`,
          channel,
          media_type: mediaType,
          mediaType,
          redaction: optionalString(draft.redaction) ?? "none",
          receipt_id: receiptId,
          receiptId,
          content,
          content_bytes: contentBytes,
          contentBytes,
          content_hash: contentHash,
          contentHash,
          created_at: createdAt,
          createdAt,
        };
        store.codingArtifacts.set(artifactRecord.id, artifactRecord);
        writeJson(store.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
        return artifactRecord;
      })
      .filter(Boolean);
  }

  function readCodingToolArtifact(store, threadId, artifactId, range = {}) {
    const artifactRecord = store.codingArtifacts.get(artifactId);
    if (!artifactRecord) throw notFound(`Artifact not found: ${artifactId}`, { threadId, artifactId });
    if (artifactRecord.thread_id && artifactRecord.thread_id !== threadId) {
      throw policyError("Artifact read blocked outside the owning runtime thread.", {
        threadId,
        artifactId,
        ownerThreadId: artifactRecord.thread_id,
      });
    }
    return codingToolArtifactReadResult(artifactRecord, range);
  }

  function retrieveCodingToolResult(store, threadId, query = {}) {
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
        details: { threadId },
      });
    }
    const artifacts = [...store.codingArtifacts.values()]
      .filter((artifactRecord) => artifactRecord.thread_id === threadId && artifactRecord.tool_call_id === toolCallId)
      .sort((left, right) => String(left.channel ?? "").localeCompare(String(right.channel ?? "")));
    if (!artifacts.length) {
      throw notFound(`Tool result artifact not found: ${toolCallId}`, { threadId, toolCallId });
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

  function appendCodingToolCommandStreamEvents(
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
    const streamId = `command_stream_${safeId(toolCallId)}`;
    const chunks = codingToolCommandStreamChunks(result);
    if (chunks.length === 0) return [];
    const events = [];
    let chunkSeq = 0;
    for (const chunk of chunks) {
      chunkSeq += 1;
      events.push(store.appendRuntimeEvent({
        event_stream_id: eventStreamIdForThread(threadId),
        thread_id: threadId,
        turn_id: turnId,
        item_id: `${turnId || threadId}:item:command-stream:${doctorHash(`${toolCallId}:${chunk.channel}:${chunkSeq}`).slice(0, 12)}`,
        idempotency_key: `thread:${threadId}:command-stream:${toolCallId}:${chunk.channel}:${chunkSeq}`,
        source: operatorControlSource(request.source),
        source_event_kind: "CodingTool.Stream",
        event_kind: "COMMAND_STREAM",
        status: "streaming",
        actor: "runtime",
        workspace_root: agent.cwd,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        component_kind: "terminal_stream",
        tool_call_id: toolCallId,
        tool_name: toolId,
        artifact_refs: artifactRefs,
        receipt_refs: uniqueStrings(receiptRefs),
        rollback_refs: [],
        payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
        payload_summary: {
          schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
          event_kind: "COMMAND_STREAM",
          stream_id: streamId,
          streamId,
          stream_seq: chunkSeq,
          streamSeq: chunkSeq,
          channel: chunk.channel,
          output_text: chunk.text,
          outputText: chunk.text,
          is_final: false,
          isFinal: false,
          command: optionalString(result?.command) ?? toolId,
          tool_name: toolId,
          tool_call_id: toolCallId,
          truncated: Boolean(result?.truncated),
          status,
          artifact_refs: artifactRefs,
          artifactRefs,
          receipt_refs: uniqueStrings(receiptRefs),
          receiptRefs: uniqueStrings(receiptRefs),
        },
      }));
    }
    events.push(store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:command-stream:${doctorHash(`${toolCallId}:final`).slice(0, 12)}`,
      idempotency_key: `thread:${threadId}:command-stream:${toolCallId}:final`,
      source: operatorControlSource(request.source),
      source_event_kind: "CodingTool.Stream",
      event_kind: "COMMAND_STREAM",
      status: "completed",
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "terminal_stream",
      tool_call_id: toolCallId,
      tool_name: toolId,
      artifact_refs: artifactRefs,
      receipt_refs: uniqueStrings(receiptRefs),
      rollback_refs: [],
      payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      payload_summary: {
        schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
        event_kind: "COMMAND_STREAM",
        stream_id: streamId,
        streamId,
        stream_seq: chunkSeq + 1,
        streamSeq: chunkSeq + 1,
        channel: "control",
        output_text: "",
        outputText: "",
        is_final: true,
        isFinal: true,
        command: optionalString(result?.command) ?? toolId,
        tool_name: toolId,
        tool_call_id: toolCallId,
        truncated: Boolean(result?.truncated),
        status,
        artifact_refs: artifactRefs,
        artifactRefs,
        receipt_refs: uniqueStrings(receiptRefs),
        receiptRefs: uniqueStrings(receiptRefs),
      },
    }));
    return events;
  }

  function materializeVisualGuiObservationArtifacts(store, { threadId, toolId, toolCallId, workspaceRoot, input }) {
    const specs = [
      {
        pathKeys: ["screenshotPath", "screenshot_path", "screenshotFile", "screenshot_file"],
        refKey: "screenshotRef",
        channel: "visual-gui-screenshot",
        defaultName: "visual-gui-screenshot.png",
        defaultMediaType: "image/png",
      },
      {
        pathKeys: ["somPath", "som_path", "setOfMarksPath", "set_of_marks_path"],
        refKey: "somRef",
        channel: "visual-gui-som",
        defaultName: "visual-gui-som.json",
        defaultMediaType: "application/json",
      },
      {
        pathKeys: ["axPath", "ax_path", "accessibilityTreePath", "accessibility_tree_path"],
        refKey: "axRef",
        channel: "visual-gui-ax",
        defaultName: "visual-gui-ax.json",
        defaultMediaType: "application/json",
      },
    ];
    const createdAt = now();
    const metadata = {};
    const artifactRefs = [];
    const artifacts = [];
    for (const spec of specs) {
      const explicitRef = optionalString(input[spec.refKey] ?? input[snakeCaseKey(spec.refKey)]);
      if (explicitRef) continue;
      const sourcePath = firstOptionalString(spec.pathKeys.map((key) => input[key]));
      if (!sourcePath) continue;
      const resolvedPath = path.resolve(workspaceRoot ?? process.cwd(), sourcePath);
      let contentBuffer;
      try {
        contentBuffer = fs.readFileSync(resolvedPath);
      } catch (error) {
        throw runtimeError({
          status: 400,
          code: "computer_use_visual_artifact_unreadable",
          message: `Visual GUI observation artifact could not be read for ${spec.channel}.`,
          details: {
            channel: spec.channel,
            sourcePathHash: doctorHash(resolvedPath),
            error: error?.code ?? error?.message ?? "read_failed",
          },
        });
      }
      if (contentBuffer.byteLength > maxVisualArtifactBytes) {
        throw runtimeError({
          status: 413,
          code: "computer_use_visual_artifact_too_large",
          message: `Visual GUI observation artifact exceeds ${maxVisualArtifactBytes} bytes.`,
          details: {
            channel: spec.channel,
            sourcePathHash: doctorHash(resolvedPath),
            contentBytes: contentBuffer.byteLength,
            maxBytes: maxVisualArtifactBytes,
          },
        });
      }
      const content = contentBuffer.toString("base64");
      const extension = path.extname(resolvedPath);
      const mediaType =
        optionalString(input[`${spec.refKey}MediaType`] ?? input[`${snakeCaseKey(spec.refKey)}_media_type`]) ??
        visualGuiMediaTypeForPath(resolvedPath) ??
        spec.defaultMediaType;
      const artifactId = `artifact_computer_use_visual_${safeId(toolCallId)}_${safeId(spec.channel)}`;
      const receiptId = `receipt_${safeId(toolCallId)}_${safeId(spec.channel)}`;
      const artifactRecord = {
        schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
        schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
        id: artifactId,
        thread_id: threadId,
        threadId,
        tool_name: toolId,
        toolName: toolId,
        tool_call_id: toolCallId,
        toolCallId,
        workspace_root: workspaceRoot,
        workspaceRoot,
        name: extension ? `${spec.channel}${extension}` : spec.defaultName,
        channel: spec.channel,
        media_type: mediaType,
        mediaType,
        encoding: "base64",
        redaction: "local_redacted_artifacts",
        receipt_id: receiptId,
        receiptId,
        content,
        content_bytes: contentBuffer.byteLength,
        contentBytes: contentBuffer.byteLength,
        content_hash: doctorHash(content),
        contentHash: doctorHash(content),
        source_path_hash: doctorHash(resolvedPath),
        sourcePathHash: doctorHash(resolvedPath),
        source_path_included: false,
        sourcePathIncluded: false,
        created_at: createdAt,
        createdAt,
      };
      store.codingArtifacts.set(artifactRecord.id, artifactRecord);
      writeJson(store.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
      metadata[spec.refKey] = artifactId;
      artifactRefs.push(artifactId);
      artifacts.push(artifactRecord);
    }
    return { metadata, artifactRefs, artifacts };
  }

  return {
    appendCodingToolCommandStreamEvents,
    materializeCodingToolArtifactDrafts,
    materializeVisualGuiObservationArtifacts,
    readCodingToolArtifact,
    retrieveCodingToolResult,
  };
}
