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
    delete publicResult.artifactRefs;
    delete publicResult.artifactDrafts;
    delete publicResult.artifact_drafts;
    delete publicResult.workspaceSnapshotDrafts;
    delete publicResult.workspace_snapshot_drafts;
    if (artifacts.length) {
      publicResult.artifact_refs = uniqueStrings([
        ...normalizeArray(publicResult.artifact_refs),
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
      schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
      artifact_id: artifactRecord.id,
      thread_id: artifactRecord.thread_id ?? null,
      tool_name: artifactRecord.tool_name ?? null,
      tool_call_id: artifactRecord.tool_call_id ?? null,
      name: artifactRecord.name ?? null,
      channel: artifactRecord.channel ?? null,
      media_type: artifactRecord.media_type ?? "text/plain",
      content_bytes: Number(artifactRecord.content_bytes ?? 0),
      content_hash: artifactRecord.content_hash ?? null,
      receipt_id: artifactRecord.receipt_id ?? null,
      redaction: artifactRecord.redaction ?? "none",
      created_at: artifactRecord.created_at ?? null,
    };
  }

  function codingToolArtifactReadResult(artifactRecord = {}, range = {}) {
    const content = String(artifactRecord.content ?? "");
    const buffer = Buffer.from(content, "utf8");
    const offsetBytes = Math.max(0, Math.min(buffer.byteLength, Number(range.offset_bytes ?? 0) || 0));
    const lengthLimit = Math.max(1, Number(range.length_bytes ?? range.max_bytes ?? 64 * 1024) || 64 * 1024);
    const chunk = buffer.subarray(offsetBytes, Math.min(buffer.byteLength, offsetBytes + lengthLimit));
    const text = chunk.toString("utf8");
    const metadata = codingToolArtifactMetadata(artifactRecord);
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      ...metadata,
      artifact_refs: [artifactRecord.id].filter(Boolean),
      offset_bytes: offsetBytes,
      length_bytes: chunk.byteLength,
      total_bytes: buffer.byteLength,
      content: text,
      content_hash: doctorHash(text),
      full_content_hash: metadata.content_hash,
      truncated: offsetBytes + chunk.byteLength < buffer.byteLength,
      receipt_refs: [`receipt_artifact_read_${safeId(artifactRecord.id)}_${doctorHash(`${offsetBytes}:${chunk.byteLength}`).slice(0, 12)}`],
      shell_fallback_used: false,
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
