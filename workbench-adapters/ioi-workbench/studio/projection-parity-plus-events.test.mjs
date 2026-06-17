import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioParityPlusEventProjection } = require("./projection-parity-plus-events.js");

function projection() {
  return {
    engineReconnectBanners: [],
    sessionBrainPanels: [],
    trajectoryReplayPanels: [],
    chatResponsibilityContracts: [],
    securityScanPanels: [],
    workerContributionTraces: [],
    safeModeToolSuppressionPanels: [],
    onboardingDiagnosticsPanels: [],
    gatewayTokenHygienePanels: [],
    sandboxResourceLimitPanels: [],
    parentTrajectoryLinkagePanels: [],
    battleModePermissionImportPanels: [],
    importedStopHookGatePanels: [],
    importedBrowserActionEvidencePanels: [],
    importedExecutorConfigPanels: [],
    importedPolicyDraftPanels: [],
    importedGenerationMetadataPanels: [],
    importedErrorRenderInfoPanels: [],
  };
}

function createHarness(state = projection()) {
  return {
    state,
    harness: createStudioParityPlusEventProjection({
      firstArray: (value) => Array.isArray(value) ? value : [],
      getStudioRuntimeProjection: () => state,
      normalizeReceiptRefs: (...sources) => sources.flatMap((source) =>
        Array.isArray(source?.receiptRefs) ? source.receiptRefs : Array.isArray(source?.receipt_refs) ? source.receipt_refs : []
      ),
      stringValue: (value, fallback = "") => value === null || value === undefined ? fallback : String(value),
      studioRuntimeEventKind: (event) => event.event_kind || event.eventKind || event.kind || "",
    }),
  };
}

test("parity plus event projection detects payload aliases", () => {
  const { harness } = createHarness();

  assert.deepEqual(
    harness.studioRuntimeEventPayload({ payload_summary: { status: "snake" }, payload: { status: "payload" } }),
    { status: "snake" },
  );
  assert.deepEqual(
    harness.studioRuntimeEventPayload({ payloadSummary: { status: "camel" } }),
    { status: "camel" },
  );
});

test("parity plus event projection routes session brain and row receipt metadata", () => {
  const { harness, state } = createHarness();

  assert.equal(harness.applyStudioParityPlusEvent({
    event_id: "event-brain",
    event_kind: "run_brain.ready",
    payload_summary: {
      has_implementation_plan: true,
      has_task_checklist: true,
      rows: [{
        artifact_kind: "implementation_plan",
        label: "Implementation plan",
        receiptRefs: ["receipt-row"],
      }],
    },
    receiptRefs: ["receipt-event"],
  }), true);

  assert.equal(state.sessionBrainPanels.length, 1);
  assert.equal(state.sessionBrainPanels[0].id, "event-brain");
  assert.equal(state.sessionBrainPanels[0].hasImplementationPlan, true);
  assert.equal(state.sessionBrainPanels[0].hasTaskChecklist, true);
  assert.equal(state.sessionBrainPanels[0].receiptRefs[0], "receipt-event");
  assert.deepEqual(state.sessionBrainPanels[0].rows[0], {
    id: "session-brain-row-0",
    artifactKind: "implementation_plan",
    label: "Implementation plan",
    status: "present",
    preview: "",
    receiptRefs: ["receipt-row"],
  });
});

test("parity plus event projection routes trajectory replay and import-only panels", () => {
  const { harness, state } = createHarness();

  assert.equal(harness.applyStudioParityPlusEvent({
    event_kind: "durable_trajectory.replay",
    payload: {
      trajectory_id_stable: true,
      replay_cursor_observed: true,
      gui_reconnected: true,
      replay_ids_stable: true,
      replay_from_cursor_empty: true,
      side_effect_count: 1,
      duplicate_side_effect_count: 0,
      rows: [{ kind: "memory.write", summary: "Side effect recorded once." }],
    },
  }), true);
  assert.equal(harness.applyStudioParityPlusEvent({
    event_kind: "imported.stop_hook",
    payload: { row_count: 3 },
  }), true);

  assert.equal(state.trajectoryReplayPanels[0].trajectoryIdStable, true);
  assert.equal(state.trajectoryReplayPanels[0].rows[0].id, "trajectory-replay-step-1");
  assert.equal(state.trajectoryReplayPanels[0].sideEffectCount, 1);
  assert.equal(state.importedStopHookGatePanels[0].status, "observed");
  assert.equal(state.importedStopHookGatePanels[0].rowCount, 3);
});

test("parity plus event projection routes safety panels and ignores unknown events", () => {
  const { harness, state } = createHarness();

  assert.equal(harness.applyStudioParityPlusEvent({
    event_kind: "engine_guard.security_scan",
    payload: {
      merge_block_reason: "Secret scan blocked merge.",
      finding_count: 2,
      merge_action_disabled: true,
    },
  }), true);
  assert.equal(harness.applyStudioParityPlusEvent({
    event_kind: "safe_mode.tool_suppression",
    payload: { disabled_count: 4, read_only_count: 2 },
  }), true);
  assert.equal(harness.applyStudioParityPlusEvent({ event_kind: "ordinary.runtime_event" }), false);

  assert.equal(state.securityScanPanels[0].mergeBlockReason, "Secret scan blocked merge.");
  assert.equal(state.securityScanPanels[0].findingCount, 2);
  assert.equal(state.securityScanPanels[0].mergeActionDisabled, true);
  assert.equal(state.safeModeToolSuppressionPanels[0].status, "observed");
  assert.equal(state.safeModeToolSuppressionPanels[0].disabledCount, 4);
});
