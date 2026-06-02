function createStudioAgentFinalHandoffStreamer({
  crypto,
  studioPostRuntimeMessage,
  stringValue,
  chunkDelayMs = 12,
  settleDelayMs = 650,
} = {}) {
  function streamChunks(text = "") {
    const source = stringValue?.(text) || String(text || "");
    if (!source) {
      return [];
    }
    const chunks = [];
    const chunkSize = 96;
    let index = 0;
    while (index < source.length) {
      let end = Math.min(source.length, index + chunkSize);
      if (end < source.length) {
        const softBreak = source.lastIndexOf(" ", end);
        if (softBreak > index + 32) {
          end = softBreak + 1;
        }
      }
      chunks.push(source.slice(index, end));
      index = end;
    }
    return chunks;
  }

  async function streamStudioAgentFinalHandoff(text = "", { prompt = "", turnId = "", sourceRefs = [], workRecord = null } = {}) {
    const content = (stringValue?.(text) || String(text || "")).trim();
    if (!content) {
      return null;
    }
    const stableTurnId = (stringValue?.(turnId) || String(turnId || "")).trim();
    const streamId = `agent-final-${stableTurnId || "turn"}-${crypto.randomUUID()}`;
    const chunks = streamChunks(content);
    const basePayload = {
      streamId,
      prompt,
      presentation: "agent_final_handoff",
      ...(Array.isArray(sourceRefs) && sourceRefs.length ? { sourceRefs } : {}),
      ...(workRecord && typeof workRecord === "object" ? { workRecord } : {}),
      runtimeAuthority: "daemon-owned",
    };
    studioPostRuntimeMessage("assistantStreamStart", basePayload);
    for (const delta of chunks) {
      studioPostRuntimeMessage("assistantStreamDelta", {
        ...basePayload,
        delta,
      });
      await new Promise((resolve) => setTimeout(resolve, chunkDelayMs));
    }
    studioPostRuntimeMessage("assistantStreamComplete", {
      ...basePayload,
      text: content,
    });
    await new Promise((resolve) => setTimeout(resolve, settleDelayMs));
    return {
      streamId,
      chunkCount: chunks.length,
      text: content,
      completed: true,
    };
  }

  return {
    streamStudioAgentFinalHandoff,
    streamChunks,
  };
}

module.exports = {
  createStudioAgentFinalHandoffStreamer,
};
