"use strict";

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function refreshStudioReplayStepsFromProjection(studioRuntimeProjection) {
  if (!studioRuntimeProjection || typeof studioRuntimeProjection !== "object") {
    return;
  }
  studioRuntimeProjection.replaySteps = [
    ...firstArray(studioRuntimeProjection.runtimeEvents).slice(-8).map((event) => ({
      id: event.id,
      kind: event.kind,
      status: event.status,
      summary: event.summary,
    })),
    ...firstArray(studioRuntimeProjection.receipts).slice(-8).map((receipt) => ({
      id: receipt.id,
      kind: receipt.kind,
      status: "receipted",
      summary: receipt.summary,
    })),
  ].slice(-12);
  studioRuntimeProjection.runtimeCockpit = studioRuntimeProjection.runtimeCockpit || {};
  studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
    firstArray(studioRuntimeProjection.receipts).length > 0;
  studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
    firstArray(studioRuntimeProjection.replaySteps).length > 0;
}

module.exports = {
  refreshStudioReplayStepsFromProjection,
};
