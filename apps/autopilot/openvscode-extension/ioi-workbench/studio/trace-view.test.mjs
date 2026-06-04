import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { STUDIO_RUNTIME_VISIBILITY, createStudioTraceView } = require("./trace-view.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeReceiptRefs(...sources) {
  const refs = [];
  for (const source of sources) {
    if (!source) continue;
    if (typeof source === "string") {
      refs.push(source);
      continue;
    }
    refs.push(
      ...(Array.isArray(source.receiptRefs) ? source.receiptRefs : []),
      ...(Array.isArray(source.receipt_refs) ? source.receipt_refs : []),
      ...(Array.isArray(source.receipts) ? source.receipts.map((receipt) => receipt.id || receipt.receipt_id) : []),
    );
  }
  return [...new Set(refs.filter(Boolean))];
}

function createTraceView({ projection = {}, activeTraceTarget = null } = {}) {
  return createStudioTraceView({
    commandPayloadAttr: (payload) => ` data-payload="${escapeHtml(JSON.stringify(payload))}"`,
    crypto: { randomUUID: () => "uuid-1" },
    escapeHtml,
    firstArray: (value) => Array.isArray(value) ? value : [],
    getActiveTraceTarget: () => activeTraceTarget,
    getStudioRuntimeProjection: () => ({
      sessionId: "session-1",
      threadId: "thread-1",
      runId: "run-1",
      turnId: "turn-1",
      runtimeEvents: [],
      timeline: [],
      actionCards: [],
      policyLeases: [],
      commandOutputs: [],
      diagnosticGates: [],
      diffHunks: [],
      browserCards: [],
      workerCards: [],
      conversationArtifacts: [],
      engineReconnectBanners: [],
      trajectoryReplayPanels: [],
      sessionBrainPanels: [],
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
      replaySteps: [],
      receipts: [],
      ...projection,
    }),
    normalizeReceiptRefs,
  });
}

test("trace visibility classifies actionable, progress, trace-only, and debug events", () => {
  const trace = createTraceView();

  assert.equal(trace.classifyStudioRuntimeEvent({ kind: "policy.lease", status: "requires_approval" }), STUDIO_RUNTIME_VISIBILITY.inlineAction);
  assert.equal(trace.classifyStudioRuntimeEvent({ kind: "patch.hunk" }), STUDIO_RUNTIME_VISIBILITY.inlineAction);
  assert.equal(trace.classifyStudioRuntimeEvent({ kind: "stream.delta", status: "running" }), STUDIO_RUNTIME_VISIBILITY.inlineProgress);
  assert.equal(trace.classifyStudioRuntimeEvent({ kind: "receipt.created" }), STUDIO_RUNTIME_VISIBILITY.traceOnly);
  assert.equal(trace.classifyStudioRuntimeEvent({ kind: "raw.debug" }), STUDIO_RUNTIME_VISIBILITY.debugOnly);
  assert.equal(trace.classifyStudioRuntimeEvent({ kind: "assistant.summary" }), STUDIO_RUNTIME_VISIBILITY.inlineSummary);
});

test("trace target and link preserve daemon trace payload affordance", () => {
  const trace = createTraceView();
  const target = trace.studioTraceTarget({ kind: "tool.proposal", id: "apply patch", receiptRefs: ["receipt-1"] });

  assert.deepEqual(target, {
    sessionId: "session-1",
    threadId: "thread-1",
    runId: "run-1",
    turnId: "turn-1",
    stepId: "tool.proposal.apply-patch",
    kind: "tool.proposal",
    receiptRefs: ["receipt-1"],
  });

  const link = trace.studioTraceLink({ kind: "tool.proposal", id: "apply patch", receiptRefs: ["receipt-1"] }, "Trace <now>");
  assert.match(link, /data-testid="studio-view-trace-link"/);
  assert.match(link, /data-command="ioi\.runs\.refresh"/);
  assert.match(link, /Trace &lt;now&gt;/);
  assert.match(link, /&quot;source&quot;:&quot;agent-studio&quot;/);
});

test("trace items flatten projection rows and focus by receipt fallback", () => {
  const trace = createTraceView({
    activeTraceTarget: { stepId: "missing", receiptRefs: ["receipt-cmd"] },
    projection: {
      runtimeEvents: [{ id: "event-1", kind: "stream.delta", status: "running" }],
      commandOutputs: [{ id: "cmd-1", label: "npm test", stdout: "ok", receiptRefs: ["receipt-cmd"] }],
      receipts: [{ id: "receipt-cmd", kind: "receipt", summary: "Command receipt" }],
    },
  });

  const items = trace.studioTraceItems();
  assert.equal(items.some((item) => item.kind === "stream.delta" && item.visibility === STUDIO_RUNTIME_VISIBILITY.inlineProgress), true);
  assert.equal(items.some((item) => item.kind === "command.output" && item.summary === "ok"), true);
  assert.equal(items.some((item) => item.kind === "receipt" && item.id === "receipt-cmd"), true);

  const focused = trace.studioFocusedTraceTarget();
  assert.equal(focused.focused.id, "cmd-1");
  assert.equal(focused.target.receiptRefs[0], "receipt-cmd");
});
