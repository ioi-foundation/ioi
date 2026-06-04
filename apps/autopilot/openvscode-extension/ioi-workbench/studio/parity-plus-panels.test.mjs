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
