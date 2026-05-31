function createStudioAgentAnswerStreamProjector({
  getStudioRuntimeProjection,
  studioPostRuntimeMessage,
  stringValue,
}) {
  function projection() {
    return getStudioRuntimeProjection();
  }

  function reset() {
    const state = projection();
    state.daemonAnswerStreamId = null;
    state.daemonAnswerStreamText = "";
    state.daemonAnswerStreamChunkCount = 0;
    state.daemonAnswerStreamObserved = false;
    state.daemonAnswerStreamCompleted = false;
    state.daemonAnswerStreamHeldPrefix = "";
    state.daemonAnswerStreamForwarding = false;
    state.daemonAnswerStreamSuppressed = false;
  }

  function eventPayload(event = {}) {
    return event.payload_summary || event.payloadSummary || event.payload || event.data || {};
  }

  function streamIdFromEvent(event = {}, payload = eventPayload(event)) {
    const state = projection();
    const sessionId = stringValue(payload.session_id || payload.sessionId || event.session_id || event.sessionId);
    const turnId = stringValue(event.turn_id || event.turnId || state.turnId);
    const source = (turnId || sessionId) ? `${turnId || "turn"}-${sessionId || "session"}` : "current";
    const safe = source.replace(/[^a-z0-9_.:-]+/gi, "-").replace(/^-+|-+$/g, "") || "current";
    return `agent-answer-${safe}`;
  }

  function deltaFromEvent(event = {}, payload = eventPayload(event)) {
    const value =
      payload.delta ??
      payload.token ??
      payload.text ??
      event.delta ??
      event.token ??
      event.text;
    return typeof value === "string" ? value : "";
  }

  function isArtifactGenerationPresentation(presentation = "") {
    return stringValue(presentation).toLowerCase() === "artifact_generation";
  }

  function htmlDocumentPrefixReady(text = "") {
    const normalized = stringValue(text).trimStart().toLowerCase();
    return normalized.startsWith("<!doctype html") || normalized.startsWith("<html");
  }

  function projectDelta(event = {}, options = {}) {
    const state = projection();
    const payload = eventPayload(event);
    let delta = deltaFromEvent(event, payload);
    if (!delta) return false;

    const streamId = streamIdFromEvent(event, payload);
    const presentation = stringValue(options.presentation || payload.presentation, "agent_final_handoff");
    const fileName = stringValue(options.fileName || payload.fileName || payload.sourceFileName);
    if (state.daemonAnswerStreamId !== streamId) {
      state.daemonAnswerStreamId = streamId;
      state.daemonAnswerStreamText = "";
      state.daemonAnswerStreamChunkCount = 0;
      state.daemonAnswerStreamCompleted = false;
      state.daemonAnswerStreamHeldPrefix = "";
      state.daemonAnswerStreamForwarding = false;
      state.daemonAnswerStreamSuppressed = false;
      studioPostRuntimeMessage("assistantStreamStart", {
        streamId,
        presentation,
        ...(fileName ? { fileName } : {}),
        runtimeAuthority: "daemon-owned",
      });
    }
    if (isArtifactGenerationPresentation(presentation) && !state.daemonAnswerStreamForwarding) {
      state.daemonAnswerStreamHeldPrefix += delta;
      if (htmlDocumentPrefixReady(state.daemonAnswerStreamHeldPrefix)) {
        state.daemonAnswerStreamForwarding = true;
        delta = state.daemonAnswerStreamHeldPrefix;
        state.daemonAnswerStreamHeldPrefix = "";
      } else {
        if (state.daemonAnswerStreamHeldPrefix.length > 512) {
          state.daemonAnswerStreamSuppressed = true;
        }
        return false;
      }
    }
    if (isArtifactGenerationPresentation(presentation) && state.daemonAnswerStreamSuppressed && !state.daemonAnswerStreamForwarding) {
      return false;
    }
    state.daemonAnswerStreamObserved = true;
    state.runtimeCockpit.modelBackedStreamingObserved = true;
    state.daemonAnswerStreamText += delta;
    state.daemonAnswerStreamChunkCount += 1;
    studioPostRuntimeMessage("assistantStreamDelta", {
      streamId,
      delta,
      presentation,
      ...(fileName ? { fileName } : {}),
      runtimeAuthority: "daemon-owned",
    });
    return true;
  }

  function complete(textFallback = "", options = {}) {
    const state = projection();
    if (state.daemonAnswerStreamCompleted) return null;

    const streamId = state.daemonAnswerStreamId || "agent-answer-current";
    const text = stringValue(state.daemonAnswerStreamText, stringValue(textFallback));
    const presentation = stringValue(options.presentation, "agent_final_handoff");
    const fileName = stringValue(options.fileName);
    if (!state.daemonAnswerStreamObserved && !text) return null;
    if (!state.daemonAnswerStreamObserved) {
      state.daemonAnswerStreamId = streamId;
      studioPostRuntimeMessage("assistantStreamStart", {
        streamId,
        presentation,
        ...(fileName ? { fileName } : {}),
        runtimeAuthority: "daemon-owned",
      });
    }
    studioPostRuntimeMessage("assistantStreamComplete", {
      streamId,
      text,
      presentation,
      ...(fileName ? { fileName } : {}),
      runtimeAuthority: "daemon-owned",
    });
    state.daemonAnswerStreamCompleted = true;
    return {
      streamId,
      text,
      chunkCount: state.daemonAnswerStreamChunkCount,
      agentFinalHandoff: true,
      runtimeAuthority: "daemon-owned",
      daemonAnswerDeltaStream: true,
      presentation,
      ...(fileName ? { fileName } : {}),
    };
  }

  return { complete, projectDelta, reset };
}

module.exports = {
  createStudioAgentAnswerStreamProjector,
};
