import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const { createStudioParityPlusPanels } = require("./parity-plus-panels.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function renderer() {
  return createStudioParityPlusPanels({
    escapeHtml,
    firstArray,
    stringValue: (value, fallback = "") => (typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value)),
    studioTraceLink: (item) => `<a data-testid="trace-link">${escapeHtml(item.kind)}</a>`,
    studioVerifiedBadge: (item) => `<span data-testid="verified-badge">${escapeHtml(item.id || item.kind || "verified")}</span>`,
  });
}

test("parity plus panels render session brain artifact rows and fallback", () => {
  const studio = renderer();

  assert.match(
    studio.studioSessionBrainArtifactRows({ rows: [] }),
    /data-brain-artifact-kind="pending"/,
  );

  const html = studio.studioSessionBrainArtifactRows({
    rows: [{
      id: "brain-plan",
      artifactKind: "implementation_plan",
      status: "present",
      label: "Implementation plan",
      preview: "Plan preview",
    }],
  });

  assert.match(html, /data-testid="studio-session-brain-artifact-row"/);
  assert.match(html, /data-brain-artifact-kind="implementation_plan"/);
  assert.match(html, /Implementation plan/);
  assert.match(html, /data-testid="verified-badge"/);
});

test("parity plus panels render trajectory replay steps and fallback", () => {
  const studio = renderer();

  assert.match(
    studio.studioTrajectoryReplayRows({ rows: [] }),
    /data-trajectory-step-kind="pending"/,
  );

  const html = studio.studioTrajectoryReplayRows({
    rows: [{
      id: "trajectory-replay.step-1",
      kind: "memory.write",
      status: "observed",
      summary: "Side effect recorded once.",
    }],
  });

  assert.match(html, /data-testid="studio-trajectory-replay-step-row"/);
  assert.match(html, /data-trajectory-step-kind="memory.write"/);
  assert.match(html, /trajectory-replay\.step-1/);
});

test("parity plus panels preserve proof-critical panel attributes", () => {
  const studio = renderer();
  const html = studio.studioParityPlusPanelRows({
    sessionBrainPanels: [{
      id: "session-brain.current",
      status: "ready",
      hasImplementationPlan: true,
      hasTaskChecklist: true,
      hasWalkthrough: true,
      hasScratchRefs: true,
      hasArtifactRefs: true,
      hasReplayCursor: true,
      brainOutsideWorkspace: true,
      readOnlyAuditMode: true,
      rows: [{ artifactKind: "task", label: "Task checklist" }],
    }],
    trajectoryReplayPanels: [{
      id: "trajectory-replay.current",
      status: "ready",
      trajectoryIdStable: true,
      replayCursorObserved: true,
      guiReconnected: true,
      replayIdsStable: true,
      replayFromCursorEmpty: true,
      sideEffectCount: 1,
      duplicateSideEffectCount: 0,
      rows: [{ id: "trajectory-replay.step-1", kind: "thread.started" }],
    }],
  });

  assert.match(html, /data-testid="studio-session-brain-panel"/);
  assert.match(html, /data-brain-implementation-plan-observed="true"/);
  assert.match(html, /data-brain-read-only-audit-mode="true"/);
  assert.match(html, /data-testid="studio-trajectory-replay-panel"/);
  assert.match(html, /data-trajectory-id-stable="true"/);
  assert.match(html, /data-trajectory-side-effect-count="1"/);
  assert.match(html, /data-testid="studio-engine-reconnect-banner"/);
  assert.match(html, /data-testid="trace-link"/);
});

test("parity plus stage proof helpers parse contract readiness values", () => {
  const studio = renderer();

  assert.deepEqual(
    studio.studioStage2FinalContractValues([
      { payload: { message: "final_output_contract_ready satisfied=false" } },
      { payload_summary: { message: "web_final_summary_contract_ready=true" } },
      "contract_ready=false",
    ]),
    [false, true, false],
  );
  assert.match(
    studio.studioStage2WebRepairEventText([{ event_kind: "turn.completed" }]),
    /turn\.completed/,
  );
});

test("parity plus product text checks catch raw trace and tool leakage", () => {
  const studio = renderer();

  assert.equal(studio.studioStage2ProductTextIsClean("Here is the cited answer."), true);
  assert.equal(studio.studioStage2ProductTextIsClean("receipt_abcdef123456 leaked"), false);
  assert.equal(studio.studioStage2ProductTextIsClean("final_output_contract_ready=true"), false);
  assert.equal(studio.studioStage2ProductTextIsClean("/home/user/project/file.txt"), false);

  assert.equal(studio.studioStage5ProductTextIsClean("Stopped safely and recovered."), true);
  assert.equal(studio.studioStage5ProductTextIsClean("tool.completed raw event leaked"), false);
  assert.equal(studio.studioStage5ProductTextIsClean(".tmp/autopilot-stage5-stop-hook-repair/state.json"), false);
  assert.equal(studio.studioStage5ProductTextIsClean("StopHookBlocked"), false);
});

test("stage2 web repair orchestration preserves proof envelope and product checks", async () => {
  const submissions = [];
  const bridgeRequests = [];
  const projection = {
    executionMode: "agent",
    modelRoute: "route.local-first",
    selectedModel: "auto",
    threadId: "thread-one",
    turnId: "turn-one",
    turns: [{
      role: "assistant",
      content: "António Guterres is the current Secretary-General. Source: https://ask.un.org/faq/14625",
      sourceRefs: [{ url: "https://ask.un.org/faq/14625", title: "UN FAQ" }],
      workRecord: { summary: "web_search web_read source ask.un.org" },
    }],
    actionCards: [{ toolId: "web_search", status: "completed", source: "ask.un.org" }],
  };
  const runtimeEvents = [
    { kind: "tool.completed", tool: "web_search" },
    { kind: "tool.completed", tool: "web_read" },
    "stage2_web_repair_forced_model_chat_reply_rejection=true",
    "final_output_contract_ready satisfied=false",
    "web_final_summary_contract_ready=true",
    "chat_reply_model_authored_web_pipeline_answer_accepted model_chat_reply",
    { kind: "tool.completed", tool: "chat_reply" },
  ];
  const studio = createStudioParityPlusPanels({
    buildWorkspaceActionContext: (source) => ({ source }),
    compactStudioWhitespace: (value) => String(value || "").replace(/\s+/g, " ").trim(),
    escapeHtml,
    fetchStudioThreadEvents: async () => runtimeEvents.slice(3),
    fetchStudioThreadTurnEvents: async () => runtimeEvents.slice(0, 3),
    firstArray,
    getStudioRuntimeProjection: () => projection,
    sanitizeStudioProductAssistantText: (value) => String(value || ""),
    STUDIO_MODE_AGENT: "agent",
    STUDIO_PERMISSION_MODE_FULL_ACCESS: "full_access",
    stringValue: (value, fallback = "") => (typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value)),
    studioRuntimeEventsIncludeCompletedTool: (events, pattern) => events.some((event) => pattern.test(JSON.stringify(event))),
    studioSourceRefsFromRuntimeEvents: () => [{ url: "https://ask.un.org/faq/14625", title: "UN FAQ" }],
    studioTraceLink: () => "",
    studioVerifiedBadge: () => "",
    submitStudioPrompt: async (payload) => submissions.push(payload),
    uniqueStudioRuntimeEvents: (events) => events,
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });

  const proof = await studio.exerciseStudioStage2WebRepairLoop({ appendLine() {} }, { prompt: "Who leads the UN?" });

  assert.equal(submissions[0].prompt, "Who leads the UN?");
  assert.equal(submissions[0].executionMode, "agent");
  assert.equal(submissions[0].approvalMode, "full_access");
  assert.equal(proof.passed, true);
  assert.deepEqual(proof.finalContractValues, [false, true]);
  assert.equal(proof.sourceRefCount, 1);
  assert.equal(proof.checks.webSearchCompleted, true);
  assert.equal(proof.checks.webReadCompleted, true);
  assert.equal(proof.checks.finalContractFalseThenTrue, true);
  assert.equal(proof.checks.productTranscriptClean, true);
  assert.equal(bridgeRequests[0][0], "studio.stage2WebRepairLoop.exercised");
  assert.equal(bridgeRequests[0][1].passed, true);
  assert.equal(bridgeRequests[0][1].sourceRefCount, 1);
  assert.equal(bridgeRequests[0][2].source, "studio-stage2-web-repair-loop");
});

test("stage5 stop-hook repair orchestration preserves repair proof envelope", async () => {
  const submissions = [];
  const bridgeRequests = [];
  const projection = {
    executionMode: "agent",
    modelRoute: "route.local-first",
    selectedModel: "auto",
    threadId: "thread-one",
    turnId: "turn-one",
    turns: [{
      role: "assistant",
      content: "The helper was repaired and validation passes.",
      workRecord: { summary: "shell__run failed; file__edit; shell__run pass validation" },
    }],
    actionCards: [{ toolId: "shell__run", status: "completed" }],
    commandOutputs: [{ output: "# pass 1\n# fail 0" }],
    diffHunks: [{ file: ".tmp/autopilot-stage5-stop-hook-repair/status-labels.mjs", after: "normalizeStatusLabel" }],
  };
  const runtimeEvents = [
    { kind: "tool.completed", tool: "shell__run", output: "not ok\n# fail 1\nexit_code: 1" },
    "ERROR_CLASS=StopHookBlocked stop_hook_completion_blocked=true",
    { kind: "tool.completed", tool: "file__edit", path: ".tmp/autopilot-stage5-stop-hook-repair/status-labels.mjs" },
    { kind: "validation.result", status: "exit code 0", summary: "passing validation" },
    { kind: "tool.completed", tool: "chat_reply" },
  ];
  const studio = createStudioParityPlusPanels({
    buildWorkspaceActionContext: (source) => ({ source }),
    compactStudioWhitespace: (value) => String(value || "").replace(/\s+/g, " ").trim(),
    escapeHtml,
    fetchStudioThreadEvents: async () => runtimeEvents.slice(2),
    fetchStudioThreadTurnEvents: async () => runtimeEvents.slice(0, 2),
    firstArray,
    getStudioRuntimeProjection: () => projection,
    sanitizeStudioProductAssistantText: (value) => String(value || ""),
    STUDIO_MODE_AGENT: "agent",
    STUDIO_PERMISSION_MODE_FULL_ACCESS: "full_access",
    stringValue: (value, fallback = "") => (typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value)),
    studioRuntimeEventsIncludeCompletedTool: (events, pattern) => events.some((event) => pattern.test(JSON.stringify(event))),
    studioRuntimeToolEventCount: (events, pattern) => events.filter((event) => pattern.test(JSON.stringify(event))).length,
    studioSourceRefsFromRuntimeEvents: () => [],
    studioPublicWorkspacePath: (value) => String(value || "").replace(/^\/workspace\//, ""),
    studioTraceLink: () => "",
    studioVerifiedBadge: () => "",
    submitStudioPrompt: async (payload) => submissions.push(payload),
    uniqueStudioRuntimeEvents: (events) => events,
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });

  const proof = await studio.exerciseStudioStage5StopHookRepairLoop({ appendLine() {} });

  assert.match(submissions[0].prompt, /normalizeStatusLabel/);
  assert.equal(submissions[0].executionMode, "agent");
  assert.equal(submissions[0].approvalMode, "full_access");
  assert.equal(proof.passed, true);
  assert.equal(proof.checks.failingValidationObserved, true);
  assert.equal(proof.checks.prematureChatReplyBlocked, true);
  assert.equal(proof.checks.hunkEditCompleted, true);
  assert.equal(proof.checks.validationReranAfterEdit, true);
  assert.equal(proof.checks.productTranscriptClean, true);
  assert.equal(bridgeRequests[0][0], "studio.stage5StopHookRepairLoop.exercised");
  assert.equal(bridgeRequests[0][1].passed, true);
  assert.match(bridgeRequests[0][1].helperPath, /status-labels\.mjs/);
  assert.equal(bridgeRequests[0][2].source, "studio-stage5-stop-hook-repair-loop");
});

test("stage5 stop/cancel/recover orchestration preserves lifecycle proof envelope", async () => {
  const bridgeRequests = [];
  const timeline = [];
  const refreshes = [];
  const projection = {
    executionMode: "ask",
    modelRoute: "route.local-first",
    selectedModel: "auto",
    pendingWorklog: [{ label: "stale" }],
    runtimeCockpit: {},
    turns: [],
  };
  const events = [
    { kind: "turn.started", message: "model stream is active" },
    { kind: "turn.control", status: "stop requested" },
    { kind: "turn.completed", status: "completed" },
  ];
  const studio = createStudioParityPlusPanels({
    appendStudioTimeline: (...args) => timeline.push(args),
    buildWorkspaceActionContext: (source) => ({ source }),
    compactStudioWhitespace: (value) => String(value || "").replace(/\s+/g, " ").trim(),
    escapeHtml,
    fetchStudioThreadEvents: async () => events.slice(1),
    fetchStudioThreadTurnEvents: async () => events.slice(0, 1),
    firstArray,
    getStudioRuntimeProjection: () => projection,
    sanitizeStudioProductAssistantText: (value) => String(value || ""),
    refreshStudioPanelHtml: async (output) => refreshes.push(output),
    resumeStudioTurn: async () => {
      projection.runtimeCockpit.resumeControlObserved = true;
      projection.runtimeCockpit.stopResumeObserved = true;
    },
    STUDIO_MODE_AGENT: "agent",
    STUDIO_AGENT_RUNTIME_PROFILE: "runtime_service",
    stringValue: (value, fallback = "") => (typeof value === "string" ? value : value === null || value === undefined ? fallback : String(value)),
    stopStudioTurn: async () => {
      projection.runtimeCockpit.stopControlObserved = true;
    },
    studioTraceLink: () => "",
    studioVerifiedBadge: () => "",
    submitStudioAgentTurn: async (payload) => {
      projection.threadId = "thread-stage5";
      projection.turnId = "turn-stage5";
      return {
        text: "Stopped safely, resumed, and finished with a clean final answer.",
        events,
        receiptRefs: ["receipt-stage5"],
        status: "completed",
        payload,
      };
    },
    uniqueStudioRuntimeEvents: (value) => value,
    workspaceSummary: () => ({ path: "/workspace/repo" }),
    writeBridgeRequest: async (...args) => bridgeRequests.push(args),
  });

  const proof = await studio.exerciseStudioStage5StopCancelRecoverLifecycle({ appendLine() {} }, { maxSteps: 4 });

  assert.equal(timeline[0][0], "Stage 5 lifecycle proof started");
  assert.equal(refreshes.length, 2);
  assert.equal(projection.pending, false);
  assert.equal(projection.status, "completed");
  assert.equal(projection.executionMode, "agent");
  assert.equal(projection.runtimeProfile, "runtime_service");
  assert.equal(projection.turns.length, 1);
  assert.equal(projection.turns[0].agentTurn.eventCount, 3);
  assert.equal(projection.turns[0].agentTurn.receiptRefs[0], "receipt-stage5");
  assert.equal(proof.passed, true);
  assert.equal(proof.threadId, "thread-stage5");
  assert.equal(proof.turnId, "turn-stage5");
  assert.equal(proof.eventCount, 3);
  assert.equal(proof.checks.stopControlObserved, true);
  assert.equal(proof.checks.resumeControlObserved, true);
  assert.equal(proof.checks.stopResumeObserved, true);
  assert.equal(proof.checks.turnStartedEventObserved, true);
  assert.equal(proof.checks.finalAnswerClean, true);
  assert.equal(bridgeRequests[0][0], "studio.stage5StopCancelRecover.exercised");
  assert.equal(bridgeRequests[0][1].sourceCommand, "ioi.studio.exerciseStage5StopCancelRecoverLifecycle");
  assert.equal(bridgeRequests[0][1].runtimeAuthority, "daemon-owned");
  assert.equal(bridgeRequests[0][1].ownsRuntimeState, false);
  assert.equal(bridgeRequests[0][1].passed, true);
  assert.equal(bridgeRequests[0][2].source, "studio-stage5-stop-cancel-recover");
});
