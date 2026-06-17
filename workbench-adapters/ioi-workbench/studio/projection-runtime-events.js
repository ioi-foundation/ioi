"use strict";

function createStudioRuntimeEventProjection({
  appendStudioReceipts,
  classifyStudioRuntimeEvent,
  getStudioRuntimeProjection,
  normalizeReceiptRefs,
}) {
  function appendStudioTimeline(label, detail, status = "ready", extra = {}) {
    const projection = getStudioRuntimeProjection();
    projection.timeline.push({
      label,
      detail,
      status,
      at: new Date().toISOString(),
      ...extra,
    });
  }

  function appendStudioRuntimeEvent(event, fallbackKind = "runtime.event") {
    if (!event || typeof event !== "object") {
      return;
    }
    const projection = getStudioRuntimeProjection();
    const normalized = {
      id: event.event_id || event.eventId || event.id || `${fallbackKind}.${Date.now()}`,
      kind: event.event_kind || event.eventKind || event.kind || fallbackKind,
      status: event.status || event.payload_summary?.status || "observed",
      summary:
        event.summary ||
        event.payload_summary?.summary ||
        event.payload_summary?.result_summary ||
        event.payload_summary?.input_summary ||
        "",
      receiptRefs: normalizeReceiptRefs(event),
      raw: event,
    };
    normalized.visibility = classifyStudioRuntimeEvent(normalized);
    projection.runtimeEvents.push(normalized);
    if (normalized.receiptRefs.length > 0) {
      appendStudioReceipts(normalized.receiptRefs.map((id) => ({
        id,
        kind: normalized.kind,
        summary: normalized.summary || "Daemon runtime event receipt.",
      })));
    }
  }

  function appendStudioReceiptsFromResponse(response, kind, summary) {
    appendStudioReceipts(
      normalizeReceiptRefs(response).map((id) => ({
        id,
        kind,
        summary,
      })),
    );
  }

  function recomputeStudioRuntimeCockpitAchieved() {
    const projection = getStudioRuntimeProjection();
    const cockpit = projection.runtimeCockpit || {};
    cockpit.achieved = Boolean(
      cockpit.modelBackedStreamingObserved &&
      cockpit.realDaemonToolProposalObserved &&
      cockpit.policyLeaseDialogObserved &&
      cockpit.policyDeniedActionDidNotExecute &&
      cockpit.sandboxCommandOutputStreamObserved &&
      cockpit.sandboxCommandReceiptObserved &&
      cockpit.inlineDiffOverlayObserved &&
      cockpit.hunkNavigationObserved &&
      cockpit.hunkAcceptRejectReceiptsObserved &&
      cockpit.stopResumeObserved &&
      cockpit.diagnosticsTestGateObserved &&
      cockpit.receiptTimelinePerStepObserved &&
      cockpit.replayStepDetailObserved &&
      cockpit.projectionOnlyRuntimeRejected &&
      cockpit.browserStatusObserved &&
      cockpit.workerStatusObserved
    );
    projection.runtimeCockpit = cockpit;
    return cockpit.achieved;
  }

  return {
    appendStudioReceiptsFromResponse,
    appendStudioRuntimeEvent,
    appendStudioTimeline,
    recomputeStudioRuntimeCockpitAchieved,
  };
}

module.exports = {
  createStudioRuntimeEventProjection,
};
