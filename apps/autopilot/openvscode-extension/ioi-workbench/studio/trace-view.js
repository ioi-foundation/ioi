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

  function renderTraceCommandButton(action) {
    const payload =
      action && "payload" in action && action.payload != null
        ? commandPayloadAttr(action.payload)
        : "";
    return `<button class="action" data-command="${escapeHtml(action.command)}"${payload}>${escapeHtml(action.label)}</button>`;
  }

  function renderTraceRow(target, item, testId = "tracing-timeline-step") {
    return `
    <li data-testid="${escapeHtml(testId)}" data-trace-step-id="${escapeHtml(item.stepId)}"${item.stepId === target.stepId ? ' class="is-focused"' : ""}>
      <span class="status-pill">${escapeHtml(item.status || "observed")}</span>
      <strong>${escapeHtml(item.title || item.kind || "Trace step")}</strong>
      <span>${escapeHtml(item.summary || "")}</span>
      <code>${escapeHtml(item.receiptRefs?.join(" · ") || item.id || item.stepId)}</code>
    </li>
  `;
  }

  function renderTraceFallback(label) {
    return `<li class="tracing-empty"><span>${escapeHtml(label)}</span></li>`;
  }

  function renderRunsView(state) {
    const { target, focused, items } = studioFocusedTraceTarget();
    const runs = firstArray(state.runs);
    const timelineItems = [
      ...runs.map((run) => ({
        stepId: studioTraceStepId("run", run.runId || run.id),
        title: run.label || run.runId || "Runtime run",
        summary: run.summary || run.currentStepLabel || "Runtime run projected by IOI daemon.",
        status: run.status || "observed",
        kind: "run",
        receiptRefs: normalizeReceiptRefs(run),
      })),
      ...items.filter((item) => item.visibility !== STUDIO_RUNTIME_VISIBILITY.debugOnly),
    ];
    const receiptItems = items.filter((item) => item.receiptRefs.length > 0 || /receipt/i.test(item.kind));
    const replayItems = items.filter((item) => /replay|timeline|turn|stream/i.test(item.kind));
    const policyItems = items.filter((item) => /policy|approval|lease/.test(item.kind));
    const commandItems = items.filter((item) => /command|diagnostic|test|tool/.test(item.kind));
    return `
    <section
      class="tracing-surface"
      data-testid="tracing-surface"
      data-runtime-authority="daemon-owned"
      data-focused-trace-step="${escapeHtml(target.stepId || "")}"
      data-tracing-separation-achieved="true"
    >
      <header class="tracing-header">
        <div>
          <p class="eyebrow">Runs / Tracing</p>
          <h2>Runtime evidence console</h2>
          <p>Receipts, replay, policy internals, command logs, model metadata, worker/browser status, and proof export live here instead of crowding Agent Studio.</p>
        </div>
        <div class="tracing-header__actions">
          ${renderTraceCommandButton({ label: "Back to Studio", command: "ioi.studio.open", payload: { source: "tracing" } })}
          ${renderTraceCommandButton({ label: "Refresh tracing", command: "ioi.runs.refresh" })}
        </div>
      </header>
      <section class="tracing-focused-step" data-testid="tracing-focused-step">
        <p class="eyebrow">Focused trace step</p>
        <h3>${escapeHtml(focused?.title || target.kind || "Current Studio session")}</h3>
        <p>${escapeHtml(focused?.summary || "Opened from Agent Studio View Trace affordance.")}</p>
        <dl>
          <div><dt>Session</dt><dd>${escapeHtml(target.sessionId || "studio-session-current")}</dd></div>
          <div><dt>Step</dt><dd>${escapeHtml(target.stepId || "current")}</dd></div>
          <div><dt>Kind</dt><dd>${escapeHtml(focused?.kind || target.kind || "session.summary")}</dd></div>
          <div><dt>Receipts</dt><dd><code>${escapeHtml((focused?.receiptRefs?.length ? focused.receiptRefs : target.receiptRefs || []).join(" · ") || "pending daemon receipt")}</code></dd></div>
        </dl>
      </section>
      <div class="tracing-grid">
        <section class="tracing-panel tracing-panel--wide" data-testid="tracing-timeline">
          <h3>Timeline</h3>
          <ol>${timelineItems.length ? timelineItems.slice(-18).map((item) => renderTraceRow(target, item)).join("") : renderTraceFallback("No runtime timeline is projected yet.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-receipt-detail">
          <h3>Receipts</h3>
          <ol>${receiptItems.length ? receiptItems.slice(-12).map((item) => renderTraceRow(target, item, "tracing-receipt-step")).join("") : renderTraceFallback("No daemon receipts projected yet.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-replay-step">
          <h3>Replay</h3>
          <ol>${replayItems.length ? replayItems.slice(-12).map((item) => renderTraceRow(target, item, "tracing-replay-row")).join("") : renderTraceFallback("Replay steps appear when daemon events are observed.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-policy-detail">
          <h3>Policy</h3>
          <ol>${policyItems.length ? policyItems.slice(-10).map((item) => renderTraceRow(target, item, "tracing-policy-row")).join("") : renderTraceFallback("No blocking policy lease is active.")}</ol>
        </section>
        <section class="tracing-panel" data-testid="tracing-command-log-detail">
          <h3>Commands / Tests / Tools</h3>
          <ol>${commandItems.length ? commandItems.slice(-10).map((item) => renderTraceRow(target, item, "tracing-command-row")).join("") : renderTraceFallback("No daemon command or test log is projected yet.")}</ol>
        </section>
        <section class="tracing-panel tracing-panel--wide" data-testid="tracing-proof-export">
          <h3>Proof bundle posture</h3>
          <p>Model prose is never accepted as runtime proof. Verified badges require daemon receipt refs; full proof export is assembled from this trace surface.</p>
          <code>${escapeHtml(JSON.stringify({
            modelProseNotAcceptedAsRuntimeTruth: true,
            verifiedBadgesRequireReceiptRefs: true,
            projectionOwner: "ioi-workbench",
            runtimeAuthority: "daemon-owned",
            externalConnectorAction: false,
          }, null, 2))}</code>
        </section>
      </div>
    </section>
  `;
  }

  return {
    STUDIO_RUNTIME_VISIBILITY,
    classifyStudioRuntimeEvent,
    renderRunsView,
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
