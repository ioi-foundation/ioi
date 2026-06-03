function createStudioManagedSessionProjection({
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection,
  requestJson,
  stringValue,
  studioJsonObjectFromText,
  studioRecordValue,
  writeBridgeRequest,
}) {
  function studioComputerUseSurfaceKind({ lane = "", sessionMode = "", toolName = "" } = {}) {
    const normalizedLane = String(lane || "").toLowerCase();
    const normalizedMode = String(sessionMode || "").toLowerCase();
    const normalizedTool = String(toolName || "").toLowerCase();
    if (/screen__|window__|app__|visual_gui|desktop/.test(`${normalizedTool} ${normalizedLane} ${normalizedMode}`)) {
      return "desktop";
    }
    if (/controlled_relaunch|host_browser|local_browser|native_browser/.test(normalizedMode) && !/owned_hermetic/.test(normalizedMode)) {
      return "local_browser";
    }
    if (/browser__|browser|owned_hermetic|sandbox|hermetic/.test(`${normalizedTool} ${normalizedLane} ${normalizedMode}`)) {
      return "sandbox_browser";
    }
    return "sandbox_browser";
  }

  function studioComputerUseSurfaceLabel(kind = "") {
    if (kind === "desktop") {
      return "Desktop";
    }
    if (kind === "local_browser") {
      return "Local browser";
    }
    return "Sandbox browser";
  }

  function studioComputerUseSessionStatus(status = "", toolName = "", summary = "") {
    const haystack = `${status} ${toolName} ${summary}`.toLowerCase();
    if (/captcha|login|payment|file picker|manual|waiting_for_user|needs_user/.test(haystack)) {
      return "waiting_for_user";
    }
    if (/approval|policy|blocked|failed|error/.test(haystack)) {
      return "needs_user";
    }
    if (/running|active|pending|streaming/.test(haystack)) {
      return "browsing";
    }
    return "complete";
  }

  function studioComputerUseStatusLabel(status = "") {
    switch (status) {
      case "waiting_for_user":
        return "Waiting for user";
      case "needs_user":
        return "Needs user";
      case "browsing":
        return "Browsing";
      default:
        return "Complete";
    }
  }

  function studioManagedSessionFromRuntimeEvent(event = {}, context = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const data = studioRecordValue(event.data);
    const payload = studioRecordValue(event.payload);
    const summaryPayload = studioRecordValue(event.payload_summary);
    const action = studioRecordValue(data.computer_action || payload.computer_action || event.computer_action);
    const actionReceipt = studioRecordValue(data.action_receipt || payload.action_receipt || event.action_receipt);
    const verificationReceipt = studioRecordValue(data.verification_receipt || payload.verification_receipt || event.verification_receipt);
    const rawOutput = stringValue(
      data.output ||
        payload.output ||
        summaryPayload.output ||
        actionReceipt.postcondition_summary ||
        verificationReceipt.observed_postcondition ||
        context.summary,
    );
    const outputJson = studioJsonObjectFromText(rawOutput);
    const observation = studioRecordValue(
      outputJson.browser_observation_receipt ||
        data.browser_observation_receipt ||
        payload.browser_observation_receipt ||
        data.observation ||
        payload.observation,
    );
    const toolName = stringValue(
      context.toolName ||
        action.tool_name ||
        data.tool_name ||
        payload.tool_name ||
        summaryPayload.tool_name,
    );
    const kind = stringValue(context.kind || data.event_kind || event.event_kind || event.eventKind);
    const lane = stringValue(
      data.computer_use_lane ||
        payload.computer_use_lane ||
        summaryPayload.computer_use_lane ||
        action.computer_use_lane,
    );
    const sessionMode = stringValue(
      data.computer_use_session_mode ||
        payload.computer_use_session_mode ||
        summaryPayload.computer_use_session_mode ||
        action.computer_use_session_mode,
    );
    const isComputerUseEvent =
      /computer_use|computer-use/.test(kind) ||
      Boolean(lane || sessionMode || data.computer_use_lease_id || payload.computer_use_lease_id);
    const isBrowserTool = /^browser__/.test(toolName);
    const isDesktopTool = /^(screen__|window__|app__|screen$)/.test(toolName);
    if (!isComputerUseEvent && !isBrowserTool && !isDesktopTool) {
      return null;
    }

    const surfaceKind = studioComputerUseSurfaceKind({ lane, sessionMode, toolName });
    const surfaceLabel = studioComputerUseSurfaceLabel(surfaceKind);
    const status = studioComputerUseSessionStatus(context.status, toolName, rawOutput || context.summary);
    const sessionId =
      stringValue(data.computer_use_lease_id || payload.computer_use_lease_id) ||
      stringValue(action.observation_ref || data.observation_ref || payload.observation_ref) ||
      `${surfaceKind}:${event.run_id || event.runId || studioRuntimeProjection.runId || studioRuntimeProjection.turnId || "current"}`;
    const url = stringValue(observation.url || outputJson.url);
    const title = stringValue(observation.title || outputJson.title);
    const target = stringValue(
      action.target_ref ||
        data.computer_use_target_ref ||
        payload.computer_use_target_ref ||
        observation.observation_ref ||
        url,
    );
    const detail = stringValue(
      title ||
        url ||
        target ||
        action.payload_summary ||
        rawOutput,
      surfaceKind === "desktop" ? "Desktop foreground session" : "Managed browser session",
    );
    return {
      id: sessionId,
      kind: surfaceKind,
      surfaceLabel,
      status,
      statusLabel: studioComputerUseStatusLabel(status),
      title: surfaceKind === "desktop" ? "Computer session" : "Browser session",
      detail,
      url,
      pageTitle: title,
      target,
      lane,
      sessionMode,
      lastTool: toolName || "computer-use",
      actionCount: 1,
      waitingForUser: status === "waiting_for_user" || status === "needs_user",
      updatedAt: new Date().toISOString(),
    };
  }

  function upsertStudioManagedSession(session) {
    if (!session) {
      return;
    }
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const existingIndex = studioRuntimeProjection.computerUseSessions.findIndex((item) => item.id === session.id);
    if (existingIndex >= 0) {
      const existing = studioRuntimeProjection.computerUseSessions[existingIndex];
      studioRuntimeProjection.computerUseSessions[existingIndex] = {
        ...existing,
        ...session,
        actionCount: Math.max(1, Number(existing.actionCount || 0) + 1),
        firstObservedAt: existing.firstObservedAt || existing.updatedAt || session.updatedAt,
      };
    } else {
      studioRuntimeProjection.computerUseSessions.push({
        ...session,
        firstObservedAt: session.updatedAt,
      });
    }
    studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = true;
    studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = true;
  }

  function studioManagedSessionFromBridgeCard(card = {}) {
    const kind = stringValue(card.kind || card.session_kind || card.sessionKind, "sandbox_browser");
    const status = stringValue(card.status, "complete");
    const controlState = stringValue(card.control_state || card.controlState, "observe");
    return {
      id: stringValue(card.id || card.session_id || card.sessionId || card.managed_session_id || card.managedSessionId, "managed-session"),
      kind,
      surfaceLabel: stringValue(card.surface_label || card.surfaceLabel, studioComputerUseSurfaceLabel(kind)),
      status,
      statusLabel: stringValue(card.status_label || card.statusLabel, studioComputerUseStatusLabel(status)),
      controlState,
      availableControlStates: firstArray(card.available_control_states || card.availableControlStates),
      waitingForUser: Boolean(card.waiting_for_user || card.waitingForUser || status === "waiting_for_user" || status === "needs_user"),
      waitingReason: stringValue(card.waiting_reason || card.waitingReason),
      title: stringValue(card.step_label || card.stepLabel || card.title, kind === "desktop" ? "Computer session" : "Browser session"),
      detail: stringValue(card.detail || card.summary, "Runtime-managed viewport"),
      pageTitle: stringValue(card.page_title || card.pageTitle),
      target: stringValue(card.target || card.url),
      url: stringValue(card.url || card.target),
      lastTool: stringValue(card.last_tool || card.lastTool, "computer-use"),
      actionCount: Math.max(1, Number(card.action_count || card.actionCount || 1) || 1),
      replayReady: Boolean(card.replay_ready || card.replayReady),
      updatedAt: new Date().toISOString(),
    };
  }

  function applyStudioManagedSessionInspection(inspection = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const managed =
      inspection.managed_sessions ||
      inspection.managedSessions ||
      inspection.inspection?.managed_sessions ||
      inspection.inspection?.managedSessions ||
      {};
    if (!Array.isArray(managed.sessions)) {
      return [];
    }
    const sessions = managed.sessions
      .map(studioManagedSessionFromBridgeCard)
      .filter((session) => session.id);
    studioRuntimeProjection.computerUseSessions = sessions;
    applyStudioManagedSessionsToLatestTurn(sessions);
    studioRuntimeProjection.runtimeCockpit.managedSessionCount = sessions.length;
    if (sessions.length) {
      studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = true;
      studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = true;
    }
    return sessions;
  }

  function applyStudioManagedSessionsToLatestTurn(sessions = []) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const cards = firstArray(sessions).filter(Boolean);
    if (!cards.length) {
      return false;
    }
    for (let index = studioRuntimeProjection.turns.length - 1; index >= 0; index -= 1) {
      const turn = studioRuntimeProjection.turns[index];
      if (turn?.role !== "assistant") {
        continue;
      }
      const existingWorkRecord =
        turn.workRecord && typeof turn.workRecord === "object" && !Array.isArray(turn.workRecord)
          ? turn.workRecord
          : {};
      turn.workRecord = {
        ...existingWorkRecord,
        status: existingWorkRecord.status || "completed",
        sessionCards: cards,
      };
      return true;
    }
    return false;
  }

  async function refreshStudioManagedSessionsFromDaemon(output) {
    const endpoint = daemonEndpoint();
    const threadId = stringValue(getStudioRuntimeProjection().threadId);
    if (!endpoint || !threadId) {
      return [];
    }
    try {
      const inspection = await requestJson(
        endpoint,
        `/v1/threads/${encodeURIComponent(threadId)}/managed-sessions`,
        {
          token: daemonRequestToken(),
          timeoutMs: 2500,
        },
      );
      return applyStudioManagedSessionInspection(inspection);
    } catch (error) {
      output?.appendLine?.(
        `[ioi-studio] managed session inspection unavailable: ${error?.message || String(error)}`,
      );
      return [];
    }
  }

  function ensureStudioManagedSessionReconnectTurn() {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const marker = "managed-session-reconnect-proof";
    for (let index = studioRuntimeProjection.turns.length - 1; index >= 0; index -= 1) {
      const turn = studioRuntimeProjection.turns[index];
      if (turn?.role === "assistant" && turn?.workRecord?.id === marker) {
        return turn;
      }
    }
    const turn = {
      role: "assistant",
      content: "Managed browser session state is available for operator control.",
      createdAt: new Date().toISOString(),
      workRecord: {
        id: marker,
        status: "completed",
        title: "Managed browser session",
        sessionCards: [],
        receiptRefs: ["receipt_managed_session_reconnect_gui"],
      },
    };
    studioRuntimeProjection.turns.push(turn);
    return turn;
  }

  async function inspectStudioManagedSessionsForReconnect(output, threadId) {
    const endpoint = daemonEndpoint();
    if (!endpoint || !threadId) {
      return { inspection: null, sessions: [] };
    }
    try {
      const inspection = await requestJson(
        endpoint,
        `/v1/threads/${encodeURIComponent(threadId)}/managed-sessions`,
        {
          token: daemonRequestToken(),
          timeoutMs: 3500,
        },
      );
      const sessions = applyStudioManagedSessionInspection(inspection);
      return { inspection, sessions };
    } catch (error) {
      output?.appendLine?.(
        `[ioi-studio] managed session reconnect inspection unavailable: ${error?.message || String(error)}`,
      );
      return { inspection: null, sessions: [] };
    }
  }

  function studioManagedSessionReconnectSummary({ inspection, sessions, expectedManagedSessionId = "", expectedRuntimeSessionId = "", expectedControlState = "" } = {}) {
    const managed = inspection?.managed_sessions || inspection?.managedSessions || {};
    const replay = managed?.replay || {};
    const runtimeSessionId = stringValue(inspection?.session_id || inspection?.sessionId);
    const session = firstArray(sessions).find((candidate) => candidate.id === expectedManagedSessionId) || firstArray(sessions)[0] || null;
    const checks = {
      inspectionReturned: Boolean(inspection),
      sessionCardObserved: Boolean(session),
      expectedManagedSessionStable: expectedManagedSessionId ? session?.id === expectedManagedSessionId : Boolean(session?.id),
      expectedRuntimeSessionStable: expectedRuntimeSessionId ? runtimeSessionId === expectedRuntimeSessionId : Boolean(runtimeSessionId),
      expectedControlStateObserved: expectedControlState ? session?.controlState === expectedControlState : Boolean(session?.controlState),
      waitingForUserReplayed: Boolean(session?.waitingForUser),
      replayReady: Boolean(session?.replayReady || replay?.replayable || replay?.available),
    };
    return {
      session,
      runtimeSessionId,
      replay,
      checks,
      passed: Object.values(checks).every(Boolean),
    };
  }

  async function exerciseStudioManagedSessionReconnect(output, payload = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const phase = payload?.phase === "reconnect" ? "reconnect" : "create";
    const threadId = stringValue(payload?.threadId || payload?.thread_id);
    if (!threadId) {
      throw new Error("Managed session reconnect proof requires a daemon thread id.");
    }
    const expectedManagedSessionId = stringValue(
      payload?.expectedManagedSessionId || payload?.expected_managed_session_id || payload?.managedSessionId || payload?.managed_session_id,
    );
    const expectedRuntimeSessionId = stringValue(
      payload?.expectedRuntimeSessionId || payload?.expected_runtime_session_id || payload?.runtimeSessionId || payload?.runtime_session_id,
    );
    const expectedControlState = stringValue(payload?.expectedControlState || payload?.expected_control_state || "observe");
    const contextSnapshot = buildWorkspaceActionContext(`studio-managed-session-reconnect-${phase}`);
    studioRuntimeProjection.threadId = threadId;
    ensureStudioManagedSessionReconnectTurn();
    const { inspection, sessions } = await inspectStudioManagedSessionsForReconnect(output, threadId);
    const summary = studioManagedSessionReconnectSummary({
      inspection,
      sessions,
      expectedManagedSessionId,
      expectedRuntimeSessionId,
      expectedControlState,
    });
    const checks = {
      threadObserved: Boolean(threadId),
      ...summary.checks,
    };
    if (phase === "reconnect") {
      studioRuntimeProjection.engineReconnectBanners.push({
        id: "managed-session.engine-reconnect",
        kind: "engine.reconnect",
        status: summary.passed ? "ready" : "blocked",
        bannerLabel: "Engine reconnect restored managed browser session state.",
        composerFrozen: false,
        receiptRefs: ["receipt_managed_session_reconnect_gui"],
      });
    }
    studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = sessions.length > 0;
    studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = sessions.length > 0;
    studioRuntimeProjection.runtimeCockpit.managedSessionCount = sessions.length;
    const passed = Object.values(checks).every(Boolean);
    await writeBridgeRequest("studio.managedSessionReconnect.exercised", {
      sourceCommand: "ioi.studio.exerciseManagedSessionReconnect",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "openvscode-workbench-adapter",
      ownsRuntimeState: false,
      phase,
      threadId,
      runtimeSessionId: summary.runtimeSessionId,
      expectedRuntimeSessionId,
      managedSessionId: summary.session?.id || "",
      expectedManagedSessionId,
      controlState: summary.session?.controlState || "",
      expectedControlState,
      waitingForUser: Boolean(summary.session?.waitingForUser),
      replayReady: Boolean(summary.session?.replayReady || summary.replay?.replayable || summary.replay?.available),
      replaySource: stringValue(summary.replay?.source),
      sessionCount: sessions.length,
      checks,
      passed,
    }, contextSnapshot).catch((error) => {
      output?.appendLine?.(`[ioi-studio] managed session reconnect bridge request unavailable: ${error?.message || String(error)}`);
    });
    return {
      passed,
      phase,
      threadId,
      runtimeSessionId: summary.runtimeSessionId,
      managedSessionId: summary.session?.id || "",
      controlState: summary.session?.controlState || "",
      waitingForUser: Boolean(summary.session?.waitingForUser),
      replayReady: Boolean(summary.session?.replayReady || summary.replay?.replayable || summary.replay?.available),
      replaySource: stringValue(summary.replay?.source),
      sessionCount: sessions.length,
      checks,
    };
  }

  return {
    applyStudioManagedSessionInspection,
    applyStudioManagedSessionsToLatestTurn,
    exerciseStudioManagedSessionReconnect,
    refreshStudioManagedSessionsFromDaemon,
    studioComputerUseSessionStatus,
    studioComputerUseStatusLabel,
    studioComputerUseSurfaceKind,
    studioComputerUseSurfaceLabel,
    studioManagedSessionFromBridgeCard,
    studioManagedSessionFromRuntimeEvent,
    studioManagedSessionReconnectSummary,
    upsertStudioManagedSession,
  };
}

module.exports = {
  createStudioManagedSessionProjection,
};
