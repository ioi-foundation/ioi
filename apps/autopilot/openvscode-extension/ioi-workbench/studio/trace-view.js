"use strict";

const STUDIO_RUNTIME_VISIBILITY = Object.freeze({
  inlineAction: "inline-action",
  inlineProgress: "inline-progress",
  inlineSummary: "inline-summary",
  traceOnly: "trace-only",
  debugOnly: "debug-only",
});

function createStudioTraceView({
  commandPayloadAttr,
  crypto,
  escapeHtml,
  firstArray,
  getActiveTraceTarget,
  getStudioRuntimeProjection,
  normalizeReceiptRefs,
}) {
  function studioTraceStepId(kind, id) {
    return String(`${kind || "runtime"}.${id || crypto.randomUUID?.() || Date.now()}`)
      .replace(/[^a-z0-9_.:-]+/gi, "-")
      .slice(0, 120);
  }

  function classifyStudioRuntimeEvent(event = {}) {
    const kind = String(event.kind || event.event_kind || event.eventKind || "").toLowerCase();
    const status = String(event.status || event.payload_summary?.status || "").toLowerCase();
    if (/approval|policy|lease|firewall/.test(kind) || /waiting_for_approval|requires_approval|blocked/.test(status)) {
      return STUDIO_RUNTIME_VISIBILITY.inlineAction;
    }
    if (/patch|hunk|diff/.test(kind)) {
      return STUDIO_RUNTIME_VISIBILITY.inlineAction;
    }
    if (/stream|progress|pending|running/.test(kind) || /pending|running|streaming/.test(status)) {
      return STUDIO_RUNTIME_VISIBILITY.inlineProgress;
    }
    if (/receipt|replay|metadata|model_invocation|browser|worker|subagent/.test(kind)) {
      return STUDIO_RUNTIME_VISIBILITY.traceOnly;
    }
    if (/debug|raw/.test(kind)) {
      return STUDIO_RUNTIME_VISIBILITY.debugOnly;
    }
    return STUDIO_RUNTIME_VISIBILITY.inlineSummary;
  }

  function studioTraceTarget(payload = {}) {
    const projection = getStudioRuntimeProjection();
    const receiptRefs = normalizeReceiptRefs(payload, ...firstArray(payload.receiptRefs));
    const stepId = payload.stepId || studioTraceStepId(payload.kind || "runtime", payload.id || receiptRefs[0]);
    return {
      sessionId: projection.sessionId || projection.threadId || "studio-session-current",
      threadId: projection.threadId || null,
      runId: projection.runId || null,
      turnId: projection.turnId || null,
      stepId,
      kind: payload.kind || "runtime.event",
      receiptRefs,
    };
  }

  function studioTraceCommandAttr(payload = {}) {
    return commandPayloadAttr({
      traceTarget: studioTraceTarget(payload),
      source: "agent-studio",
    });
  }

  function studioTraceLink(payload = {}, label = "View trace") {
    return `<button type="button" class="studio-view-trace-link" data-testid="studio-view-trace-link" data-command="ioi.runs.refresh"${studioTraceCommandAttr(payload)}>${escapeHtml(label)}</button>`;
  }

  function studioTraceItems() {
    const projection = getStudioRuntimeProjection();
    const items = [];
    const push = (item = {}) => {
      const kind = item.kind || "runtime.event";
      const receiptRefs = normalizeReceiptRefs(item);
      const stepId = item.stepId || studioTraceStepId(kind, item.id || item.label || receiptRefs[0]);
      items.push({
        stepId,
        id: item.id || stepId,
        kind,
        title: item.title || item.label || kind,
        summary: item.summary || item.detail || item.reason || item.stdout || item.status || "",
        status: item.status || "observed",
        receiptRefs,
        visibility: item.visibility || classifyStudioRuntimeEvent(item),
        payload: item,
      });
    };
    for (const event of firstArray(projection.runtimeEvents)) push(event);
    for (const item of firstArray(projection.timeline)) push({ ...item, kind: "timeline.step" });
    for (const item of firstArray(projection.actionCards)) push({ ...item, kind: "tool.proposal" });
    for (const item of firstArray(projection.policyLeases)) push({ ...item, kind: "policy.lease" });
    for (const item of firstArray(projection.commandOutputs)) push({ ...item, kind: "command.output", summary: item.stdout || item.stderr || item.label });
    for (const item of firstArray(projection.diagnosticGates)) push({ ...item, kind: "diagnostics.gate" });
    for (const item of firstArray(projection.diffHunks)) push({ ...item, kind: "patch.hunk", summary: `${item.file || "workspace"} · ${item.status || "pending"}` });
    for (const item of firstArray(projection.browserCards)) push({ ...item, kind: "browser.status" });
    for (const item of firstArray(projection.workerCards)) push({ ...item, kind: "worker.status" });
    for (const item of firstArray(projection.conversationArtifacts)) push({ ...item, kind: "conversation.artifact" });
    for (const item of firstArray(projection.engineReconnectBanners)) push({ ...item, kind: "engine.reconnect" });
    for (const item of firstArray(projection.trajectoryReplayPanels)) push({ ...item, kind: "trajectory.replay" });
    for (const item of firstArray(projection.sessionBrainPanels)) push({ ...item, kind: "session.brain" });
    for (const item of firstArray(projection.chatResponsibilityContracts)) push({ ...item, kind: "chat.responsibility" });
    for (const item of firstArray(projection.securityScanPanels)) push({ ...item, kind: "engine.guard.security" });
    for (const item of firstArray(projection.workerContributionTraces)) push({ ...item, kind: "worker.contribution" });
    for (const item of firstArray(projection.safeModeToolSuppressionPanels)) push({ ...item, kind: "safe_mode.tool_suppression" });
    for (const item of firstArray(projection.onboardingDiagnosticsPanels)) push({ ...item, kind: "onboarding.diagnostics" });
    for (const item of firstArray(projection.gatewayTokenHygienePanels)) push({ ...item, kind: "gateway.token_hygiene" });
    for (const item of firstArray(projection.sandboxResourceLimitPanels)) push({ ...item, kind: "sandbox.resource_limits" });
    for (const item of firstArray(projection.parentTrajectoryLinkagePanels)) push({ ...item, kind: "imported.parent_trajectory_linkage" });
    for (const item of firstArray(projection.battleModePermissionImportPanels)) push({ ...item, kind: "imported.battle_mode_permission" });
    for (const item of firstArray(projection.importedStopHookGatePanels)) push({ ...item, kind: "imported.stop_hook_gates" });
    for (const item of firstArray(projection.importedBrowserActionEvidencePanels)) push({ ...item, kind: "imported.browser_action_evidence" });
    for (const item of firstArray(projection.importedExecutorConfigPanels)) push({ ...item, kind: "imported.executor_config" });
    for (const item of firstArray(projection.importedPolicyDraftPanels)) push({ ...item, kind: "imported.policy_draft" });
    for (const item of firstArray(projection.importedGenerationMetadataPanels)) push({ ...item, kind: "imported.generation_metadata" });
    for (const item of firstArray(projection.importedErrorRenderInfoPanels)) push({ ...item, kind: "imported.error_render_info" });
    for (const item of firstArray(projection.replaySteps)) push({ ...item, kind: item.kind || "replay.step" });
    for (const item of firstArray(projection.receipts)) push({ ...item, kind: item.kind || "receipt" });
    return items;
  }

  function studioFocusedTraceTarget() {
    const target = getActiveTraceTarget() || studioTraceTarget({ kind: "session.summary", id: "current" });
    const items = studioTraceItems();
    const focused =
      items.find((item) => item.stepId === target.stepId) ||
      items.find((item) => normalizeReceiptRefs(item).some((id) => target.receiptRefs?.includes(id))) ||
      items[items.length - 1] ||
      null;
    return { target, focused, items };
  }

  return {
    STUDIO_RUNTIME_VISIBILITY,
    classifyStudioRuntimeEvent,
    studioFocusedTraceTarget,
    studioTraceCommandAttr,
    studioTraceItems,
    studioTraceLink,
    studioTraceStepId,
    studioTraceTarget,
  };
}

module.exports = {
  STUDIO_RUNTIME_VISIBILITY,
  createStudioTraceView,
};
