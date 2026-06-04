export function createRuntimeCodingToolResultHelpers({
  CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  TERMINAL_EVENT_TYPES,
  normalizeArray,
  uniqueStrings,
  optionalString,
  doctorHash,
  safeId,
}) {
  function codingToolResultWithoutDrafts(result = {}, artifacts = []) {
    if (!result || typeof result !== "object" || Array.isArray(result)) return result;
    const publicResult = { ...result };
    delete publicResult.artifactDrafts;
    delete publicResult.artifact_drafts;
    delete publicResult.workspaceSnapshotDrafts;
    delete publicResult.workspace_snapshot_drafts;
    if (artifacts.length) {
      publicResult.artifactRefs = uniqueStrings([
        ...normalizeArray(publicResult.artifactRefs),
        ...artifacts.map((artifactRecord) => artifactRecord.id),
      ]);
      publicResult.artifacts = artifacts.map(codingToolArtifactMetadata);
    }
    return publicResult;
  }

  function codingToolCommandStreamRequested(request = {}) {
    return (
      request.streamOutput === true ||
      request.stream_output === true ||
      request.commandStream === true ||
      request.command_stream === true ||
      request.input?.streamOutput === true ||
      request.input?.stream_output === true
    );
  }

  function codingToolCommandStreamChunks(result = {}) {
    const chunks = [];
    for (const channel of ["stdout", "stderr"]) {
      const text = optionalString(result?.[channel]);
      if (!text) continue;
      for (const chunk of splitCommandStreamText(text)) {
        chunks.push({ channel, text: chunk });
      }
    }
    return chunks;
  }

  function splitCommandStreamText(text) {
    const maxChars = 800;
    const chunks = [];
    for (let offset = 0; offset < text.length; offset += maxChars) {
      chunks.push(text.slice(offset, offset + maxChars));
    }
    return chunks;
  }

  function codingToolArtifactMetadata(artifactRecord = {}) {
    return {
      schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      artifactId: artifactRecord.id,
      artifactRef: artifactRecord.id,
      threadId: artifactRecord.thread_id ?? artifactRecord.threadId ?? null,
      toolName: artifactRecord.tool_name ?? artifactRecord.toolName ?? null,
      toolCallId: artifactRecord.tool_call_id ?? artifactRecord.toolCallId ?? null,
      name: artifactRecord.name ?? null,
      channel: artifactRecord.channel ?? null,
      mediaType: artifactRecord.media_type ?? artifactRecord.mediaType ?? "text/plain",
      contentBytes: Number(artifactRecord.content_bytes ?? artifactRecord.contentBytes ?? 0),
      contentHash: artifactRecord.content_hash ?? artifactRecord.contentHash ?? null,
      receiptId: artifactRecord.receipt_id ?? artifactRecord.receiptId ?? null,
      redaction: artifactRecord.redaction ?? "none",
      createdAt: artifactRecord.created_at ?? artifactRecord.createdAt ?? null,
    };
  }

  function codingToolArtifactReadResult(artifactRecord = {}, range = {}) {
    const content = String(artifactRecord.content ?? "");
    const buffer = Buffer.from(content, "utf8");
    const offsetBytes = Math.max(0, Math.min(buffer.byteLength, Number(range.offsetBytes ?? range.offset_bytes ?? 0) || 0));
    const lengthLimit = Math.max(1, Number(range.lengthBytes ?? range.length_bytes ?? range.maxBytes ?? range.max_bytes ?? 64 * 1024) || 64 * 1024);
    const chunk = buffer.subarray(offsetBytes, Math.min(buffer.byteLength, offsetBytes + lengthLimit));
    const text = chunk.toString("utf8");
    const metadata = codingToolArtifactMetadata(artifactRecord);
    return {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      ...metadata,
      artifactRefs: [artifactRecord.id].filter(Boolean),
      offsetBytes,
      lengthBytes: chunk.byteLength,
      totalBytes: buffer.byteLength,
      content: text,
      contentHash: doctorHash(text),
      fullContentHash: metadata.contentHash,
      truncated: offsetBytes + chunk.byteLength < buffer.byteLength,
      receiptRefs: [`receipt_artifact_read_${safeId(artifactRecord.id)}_${doctorHash(`${offsetBytes}:${chunk.byteLength}`).slice(0, 12)}`],
      shellFallbackUsed: false,
    };
  }

  function terminalCount(events) {
    return events.filter((event) => TERMINAL_EVENT_TYPES.has(event.type)).length;
  }

  return {
    codingToolArtifactMetadata,
    codingToolArtifactReadResult,
    codingToolCommandStreamChunks,
    codingToolCommandStreamRequested,
    codingToolResultWithoutDrafts,
    splitCommandStreamText,
    terminalCount,
  };
}
