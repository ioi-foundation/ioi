function createStudioOperationalSurface(deps) {
  const {
    commandPayloadAttr,
    escapeHtml,
    firstArray,
    getStudioRuntimeProjection,
    mountedModelQuickInputRowsFromState,
    normalizeStudioExecutionMode,
    normalizeStudioPermissionMode,
    renderNativeChatIcon,
    studioActionCardRows,
    studioApprovalRows,
    studioBrowserWorkerRows,
    studioCommandOutputRows,
    studioCompactRuntimeStatusRows,
    studioDiagnosticsRows,
    studioDiffRows,
    studioDisplayTurnContent,
    studioExecutionModeLabel,
    studioHistoryRows,
    studioParityPlusPanelRows,
    studioPendingProjectionRows,
    studioPermissionModeLabel,
    studioPolicyLeaseRows,
    studioReasoningEffortOptions,
    studioReceiptRows,
    studioReplayRows,
    studioSnapshotFromState,
    studioTerminalRows,
    studioTimelineRows,
    studioTraceLink,
    studioTurnRows,
    workspaceSummary,
  } = deps;

  function renderStudioOperationalSurface(state, { standalone = false } = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const workspace = state.workspace || workspaceSummary();
    const snapshot = studioSnapshotFromState(state);
    const status = studioRuntimeProjection.pending ? "pending" : studioRuntimeProjection.status;
    const daemonConnected = snapshot.daemonStatus === "connected";
    const artifactCount = Math.max(
      1,
      studioRuntimeProjection.conversationArtifacts.length ||
        studioRuntimeProjection.receipts.length ||
        studioRuntimeProjection.diffHunks.length ||
        1,
    );
    const lastModelStream = studioRuntimeProjection.lastModelStream || {};
    const executionMode = normalizeStudioExecutionMode(studioRuntimeProjection.executionMode);
    const executionModeLabel = studioExecutionModeLabel(executionMode);
    const approvalMode = normalizeStudioPermissionMode(studioRuntimeProjection.approvalMode);
    const permissionLabel = studioPermissionModeLabel(approvalMode);
    return `
      <main
        class="studio-operational-shell studio-tauri-chat-shell${standalone ? " studio-operational-shell--standalone" : ""}"
        data-testid="agent-studio-operational-chat"
        data-runtime-authority="daemon-owned"
        data-extension-host-authority="projection-only"
        data-studio-ux="tauri-chat-parity"
        data-runtime-ux-denoised="${studioRuntimeProjection.runtimeUx?.denoised ? "true" : "false"}"
        data-tracing-separation-achieved="${studioRuntimeProjection.runtimeUx?.tracingSeparationAchieved ? "true" : "false"}"
        data-model-prose-runtime-truth="false"
        data-verified-badges-require-receipts="${studioRuntimeProjection.runtimeUx?.verifiedBadgesRequireReceiptRefs ? "true" : "false"}"
        data-daemon-backed="${daemonConnected ? "true" : "false"}"
        data-studio-status="${escapeHtml(status || "idle")}"
        data-thread-id="${escapeHtml(studioRuntimeProjection.threadId || "")}"
        data-session-id="${escapeHtml(studioRuntimeProjection.sessionId || "")}"
        data-model-stream-id="${escapeHtml(lastModelStream.streamId || "")}"
        data-model-stream-chunks="${escapeHtml(String(lastModelStream.chunkCount || 0))}"
        data-model-stream-receipts="${escapeHtml(String(firstArray(lastModelStream.receiptIds).length))}"
        data-runtime-cockpit-achieved="${studioRuntimeProjection.runtimeCockpit?.achieved ? "true" : "false"}"
        data-studio-execution-mode="${escapeHtml(executionMode)}"
        data-runtime-profile="${escapeHtml(studioRuntimeProjection.runtimeProfile || "")}"
        data-model-backed-streaming-observed="${studioRuntimeProjection.runtimeCockpit?.modelBackedStreamingObserved ? "true" : "false"}"
        data-real-daemon-tool-proposal-observed="${studioRuntimeProjection.runtimeCockpit?.realDaemonToolProposalObserved ? "true" : "false"}"
        data-policy-lease-dialog-observed="${studioRuntimeProjection.runtimeCockpit?.policyLeaseDialogObserved ? "true" : "false"}"
        data-managed-live-viewport-observed="${studioRuntimeProjection.runtimeCockpit?.managedLiveViewportObserved ? "true" : "false"}"
        data-managed-session-labels-observed="${studioRuntimeProjection.runtimeCockpit?.managedSessionLabelsObserved ? "true" : "false"}"
        data-managed-session-count="${escapeHtml(String(studioRuntimeProjection.runtimeCockpit?.managedSessionCount || studioRuntimeProjection.computerUseSessions.length || 0))}"
        data-immediate-submit-seen="${studioRuntimeProjection.immediateSubmitSeen ? "true" : "false"}"
        data-pending-state-seen="${studioRuntimeProjection.pendingSeen ? "true" : "false"}"
        data-pending-started-at-ms="${escapeHtml(String(studioRuntimeProjection.pendingStartedAtMs || ""))}"
        data-pending-worklog-count="${escapeHtml(String(firstArray(studioRuntimeProjection.pendingWorklog).length))}"
        data-pending-worklog="${escapeHtml(JSON.stringify(firstArray(studioRuntimeProjection.pendingWorklog)))}"
      >
        <aside class="studio-operational-rail studio-session-rail" data-testid="studio-tauri-session-rail" aria-label="Studio session context">
          <header class="studio-session-rail__header">
            <span class="studio-eyebrow">Sessions</span>
            <h2>Conversation history</h2>
            <button type="button" data-testid="studio-new-session-icon" data-bridge-request="chat.newSession" aria-label="New Session">+</button>
          </header>
          <label class="studio-session-search">
            <span class="studio-search-icon" aria-hidden="true">⌕</span>
            <input data-testid="studio-session-search" type="search" placeholder="Search sessions" />
          </label>
          <nav class="studio-session-actions" aria-label="Session actions">
            <button type="button" data-testid="studio-new-session" data-bridge-request="chat.newSession">+ <span>New Session</span></button>
          </nav>
          <section class="studio-control-group studio-history-group" data-testid="studio-session-history">
            <h3>Recent</h3>
            <span class="studio-history-date">Today</span>
            <button type="button" class="studio-history-item studio-history-item--current" data-testid="studio-current-session-row">
              <strong>${escapeHtml(studioDisplayTurnContent(studioRuntimeProjection.turns.find((turn) => turn.role === "user") || {}).slice(0, 36) || "Current daemon session")}</strong>
              <span>${escapeHtml(studioRuntimeProjection.status || "idle")}</span>
            </button>
            <div data-testid="studio-recent-sessions">
            ${studioHistoryRows()}
            </div>
          </section>
        </aside>

        <section class="studio-chat-main">
          <header class="studio-chat-header">
            <button type="button" class="studio-chat-tab is-active">Chat</button>
            <div class="studio-route-controls">
              <select data-testid="studio-model-route-picker" data-testid-proxy="studio-model-toggle" data-selected-model-id="${escapeHtml(snapshot.selectedModel)}" data-selected-endpoint-id="${escapeHtml(snapshot.endpointId)}" data-model-unavailable="${snapshot.modelUnavailable ? "true" : "false"}" aria-label="Model route picker">
                <option value="${escapeHtml(snapshot.routeId)}" data-model-id="${escapeHtml(snapshot.selectedModel)}" data-endpoint-id="${escapeHtml(snapshot.endpointId)}">${escapeHtml(snapshot.routeId)} · ${escapeHtml(snapshot.modelLabel)}</option>
              </select>
              ${snapshot.reasoningControlSupported ? `
                <select data-testid="studio-reasoning-effort-picker" data-reasoning-supported="true" aria-label="Reasoning effort">
                  ${studioReasoningEffortOptions(snapshot.reasoningEffort)}
                </select>
              ` : ""}
              <button type="button" data-command="ioi.models.open">Manage models</button>
              ${studioRuntimeProjection.status === "interrupted" ? `
                <button type="button" class="studio-stop-icon-button" data-studio-resume data-testid="studio-resume-icon" title="Resume" aria-label="Resume">${renderNativeChatIcon("send")}</button>
              ` : `
                <button type="button" class="studio-stop-icon-button" data-studio-stop data-testid="studio-stop-icon" title="Stop" aria-label="Stop">${renderNativeChatIcon("stop")}</button>
              `}
            </div>
          </header>
          <section class="studio-transcript" data-testid="studio-transcript" aria-live="polite">
            <div class="studio-chat-transcript" data-testid="studio-chat-transcript">
              ${studioTurnRows()}
              ${studioPendingProjectionRows()}
            </div>
            ${studioCompactRuntimeStatusRows()}
          </section>
          <form class="studio-composer" data-testid="studio-composer" data-studio-prompt-form>
            <div class="studio-tauri-composer" data-testid="studio-tauri-composer">
              <div class="studio-composer-context-row" data-testid="studio-composer-context-row">
                <button type="button" data-testid="studio-add-context" class="studio-context-btn" data-command="ioi.quickInput.context.open">
                  <span class="studio-context-btn__icon" aria-hidden="true">${renderNativeChatIcon("paperclip")}</span>
                  <span>Add Context...</span>
                </button>
              </div>
              <textarea data-testid="studio-composer-input" data-studio-prompt rows="3" placeholder="Describe what to build next"></textarea>
              <div class="studio-composer-toolbar" data-testid="studio-composer-toggle-row">
                <button type="button" data-testid="studio-target-toggle" class="studio-icon-toggle" data-command="ioi.quickInput.workflowTarget.pick" title="Set session target" aria-label="Set session target">
                  <span class="studio-icon-toggle__glyph" aria-hidden="true">${renderNativeChatIcon("device-desktop")}</span>
                  <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
                </button>
                <button type="button" data-testid="studio-model-toggle" class="studio-icon-toggle" data-command="ioi.quickInput.modelRoute.pick"${commandPayloadAttr({ mountedModels: mountedModelQuickInputRowsFromState(state) })} title="Choose mounted model - ${escapeHtml(snapshot.modelLabel)}" aria-label="Choose mounted model - ${escapeHtml(snapshot.modelLabel)}">
                  <span class="studio-icon-toggle__glyph" aria-hidden="true">${renderNativeChatIcon("cube")}</span>
                  <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
                </button>
                <button type="button" data-testid="studio-mode-toggle" class="studio-mode-toggle" data-command="ioi.quickInput.agentMode.pick" data-studio-mode="${escapeHtml(executionMode)}" title="Choose agent mode" aria-label="Choose agent mode">
                  <span>${escapeHtml(executionModeLabel)}</span>
                  <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
                </button>
                <button type="button" data-testid="studio-permissions-toggle" class="studio-mode-toggle studio-permissions-toggle" data-command="ioi.quickInput.permissionMode.pick" data-approval-mode="${escapeHtml(approvalMode)}" title="Permissions - ${escapeHtml(permissionLabel)}" aria-label="Permissions - ${escapeHtml(permissionLabel)}">
                  <span>${escapeHtml(permissionLabel)}</span>
                  <span class="studio-icon-toggle__chevron" aria-hidden="true">${renderNativeChatIcon("chevron-down")}</span>
                </button>
                <button type="button" data-testid="studio-tools-toggle" class="studio-icon-toggle" data-command="ioi.quickInput.tools.configure" title="Tools" aria-label="Select tools">
                  <span class="studio-icon-toggle__glyph" aria-hidden="true">${renderNativeChatIcon("tools")}</span>
                </button>
                <button type="submit" data-testid="studio-send-button" class="studio-send-icon" title="Send" aria-label="Send">
                  <span data-testid="studio-send-icon" aria-hidden="true">${renderNativeChatIcon("send")}</span>
                </button>
              </div>
            </div>
          </form>
        </section>

        <aside class="studio-operator-context studio-utility-drawer" data-testid="studio-utility-drawer" aria-label="Runtime context">
          <button type="button" class="studio-utility-toggle" data-testid="studio-utility-toggle" data-studio-drawer-toggle title="Toggle compact trace preview">Trace</button>
          <div class="studio-utility-drawer__content">
          <section data-testid="studio-trace-handoff">
            <h3>Tracing</h3>
            <p>Receipts, replay, logs, policy internals, and raw daemon events live in Runs/Tracing.</p>
            ${studioTraceLink({ kind: "session.summary", id: "studio-current-session" }, "Open Tracing")}
          </section>
          <section data-testid="studio-runtime-cockpit">
            <h3>Runtime cockpit</h3>
            ${studioActionCardRows()}
            ${studioPolicyLeaseRows()}
            ${studioCommandOutputRows()}
            ${studioDiagnosticsRows()}
            ${studioBrowserWorkerRows()}
            <section data-testid="studio-parity-plus-panels">
              ${studioParityPlusPanelRows()}
            </section>
          </section>
          <section data-testid="studio-tool-timeline">
            <h3><span data-testid="studio-tool-timeline-collapsed">Tool timeline</span></h3>
            <ol>${studioTimelineRows()}</ol>
          </section>
          ${studioApprovalRows()}
          <section data-testid="studio-inline-diff-drawer">
            <h3>Inline diff</h3>
            ${studioDiffRows()}
          </section>
          <section data-testid="studio-receipts-replay">
            <h3>Receipts / replay</h3>
            <ul>${studioReceiptRows()}</ul>
            <ol class="studio-replay-steps">${studioReplayRows()}</ol>
          </section>
          <section data-testid="studio-terminal-output">
            <h3>Terminal / tests</h3>
            <ul>${studioTerminalRows()}</ul>
          </section>
          </div>
        </aside>
      </main>
    `;
  }

  return renderStudioOperationalSurface;
}

module.exports = {
  createStudioOperationalSurface,
};
