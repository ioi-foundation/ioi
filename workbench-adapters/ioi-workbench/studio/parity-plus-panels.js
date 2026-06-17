"use strict";

function createStudioParityPlusPanels({
  appendStudioTimeline,
  buildWorkspaceActionContext,
  compactStudioWhitespace,
  escapeHtml,
  fetchStudioThreadEvents,
  fetchStudioThreadTurnEvents,
  firstArray,
  getStudioRuntimeProjection,
  sanitizeStudioProductAssistantText,
  refreshStudioPanelHtml,
  resumeStudioTurn,
  STUDIO_MODE_AGENT = "agent",
  STUDIO_AGENT_RUNTIME_PROFILE = "runtime_service",
  STUDIO_PERMISSION_MODE_FULL_ACCESS = "full_access",
  stopStudioTurn,
  stringValue,
  studioRuntimeEventsIncludeCompletedTool,
  studioRuntimeToolEventCount,
  studioSourceRefsFromRuntimeEvents,
  studioPublicWorkspacePath,
  studioTraceLink,
  studioVerifiedBadge,
  submitStudioAgentTurn,
  submitStudioPrompt,
  uniqueStudioRuntimeEvents,
  workspaceSummary,
  writeBridgeRequest,
} = {}) {
  const escape = typeof escapeHtml === "function" ? escapeHtml : (value) => String(value ?? "");
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const text = typeof stringValue === "function" ? stringValue : (value, fallback = "") => {
    if (typeof value === "string") return value;
    if (value === null || value === undefined) return fallback;
    return String(value);
  };
  const traceLink = typeof studioTraceLink === "function" ? studioTraceLink : () => "";
  const verifiedBadge = typeof studioVerifiedBadge === "function" ? studioVerifiedBadge : () => "";
  const appendTimeline = typeof appendStudioTimeline === "function" ? appendStudioTimeline : () => {};
  const refreshPanelHtml = typeof refreshStudioPanelHtml === "function" ? refreshStudioPanelHtml : async () => {};
  const workspace = typeof workspaceSummary === "function" ? workspaceSummary : () => ({ path: "" });

  function studioSessionBrainArtifactRows(panel = {}) {
    const rows = array(panel.rows).slice(0, 8);
    if (rows.length === 0) {
      return '<ul class="studio-session-brain-artifacts"><li data-testid="studio-session-brain-artifact-row" data-brain-artifact-kind="pending">Run brain artifacts pending replay.</li></ul>';
    }
    return `
      <ul class="studio-session-brain-artifacts">
        ${rows.map((row) => `
          <li
            data-testid="studio-session-brain-artifact-row"
            data-brain-artifact-kind="${escape(row.artifactKind || "artifact")}"
            data-brain-artifact-status="${escape(row.status || "present")}"
          >
            <strong>${escape(row.label || row.artifactKind || "Run brain artifact")}</strong>
            <span>${escape(row.preview || row.status || "")}</span>
            ${verifiedBadge(row)}
          </li>
        `).join("")}
      </ul>
    `;
  }

  function studioTrajectoryReplayRows(panel = {}) {
    const rows = array(panel.rows).slice(0, 8);
    if (rows.length === 0) {
      return '<ul class="studio-trajectory-replay-steps"><li data-testid="studio-trajectory-replay-step-row" data-trajectory-step-kind="pending">Trajectory replay steps pending.</li></ul>';
    }
    return `
      <ul class="studio-trajectory-replay-steps">
        ${rows.map((row) => `
          <li
            data-testid="studio-trajectory-replay-step-row"
            data-trajectory-step-kind="${escape(row.kind || "runtime.event")}"
            data-trajectory-step-status="${escape(row.status || "observed")}"
          >
            <strong>${escape(row.kind || "runtime.event")}</strong>
            <code>${escape(row.id || "trajectory-replay-step")}</code>
            <span>${escape(row.summary || row.status || "")}</span>
            ${verifiedBadge(row)}
          </li>
        `).join("")}
      </ul>
    `;
  }

  function studioParityPlusPanelRows(studioRuntimeProjection = {}) {
    const panelSpecs = [
      {
        testId: "studio-engine-reconnect-banner",
        title: "Engine reconnect",
        kind: "engine.reconnect",
        item: array(studioRuntimeProjection.engineReconnectBanners).at(-1),
        defaultStatus: "idle",
        defaultDetail: "Heartbeat and composer freeze state.",
      },
      {
        testId: "studio-trajectory-replay-panel",
        title: "Trajectory replay",
        kind: "trajectory.replay",
        item: array(studioRuntimeProjection.trajectoryReplayPanels).at(-1),
        defaultStatus: "pending",
        defaultDetail: "Durable trajectory replay and reconnect state.",
      },
      {
        testId: "studio-session-brain-panel",
        title: "Run brain",
        kind: "session.brain",
        item: array(studioRuntimeProjection.sessionBrainPanels).at(-1),
        defaultStatus: "pending",
        defaultDetail: "Plan, task checklist, walkthrough, scratch refs, artifact refs, and replay cursor.",
      },
      {
        testId: "studio-chat-responsibility-contract",
        title: "Chat responsibility",
        kind: "chat.responsibility",
        item: array(studioRuntimeProjection.chatResponsibilityContracts).at(-1),
        defaultStatus: "ready",
        defaultDetail: "Ask stays direct; Agent replies through the assistant channel.",
      },
      {
        testId: "studio-engine-guard-security-scan",
        title: "Engine Guard",
        kind: "engine.guard.security",
        item: array(studioRuntimeProjection.securityScanPanels).at(-1),
        defaultStatus: "pending",
        defaultDetail: "Security findings block merge until clean.",
      },
      {
        testId: "studio-worker-contribution-trace",
        title: "Worker trace",
        kind: "worker.contribution",
        item: array(studioRuntimeProjection.workerContributionTraces).at(-1),
        defaultStatus: "pending",
        defaultDetail: "Worker output is linked to file hunks.",
      },
      {
        testId: "studio-safe-mode-tool-suppression",
        title: "Safe Mode",
        kind: "safe_mode.tool_suppression",
        item: array(studioRuntimeProjection.safeModeToolSuppressionPanels).at(-1),
        defaultStatus: "safe_mode",
        defaultDetail: "Ask stays available while Agent tools are suppressed.",
      },
      {
        testId: "studio-onboarding-diagnostics-checklist",
        title: "Onboarding diagnostics",
        kind: "onboarding.diagnostics",
        item: array(studioRuntimeProjection.onboardingDiagnosticsPanels).at(-1),
        defaultStatus: "needs_setup",
        defaultDetail: "Local prerequisite checklist.",
      },
      {
        testId: "studio-gateway-token-hygiene",
        title: "Gateway token hygiene",
        kind: "gateway.token_hygiene",
        item: array(studioRuntimeProjection.gatewayTokenHygienePanels).at(-1),
        defaultStatus: "ready",
        defaultDetail: "Gateway calls are redacted dry-run plans.",
      },
      {
        testId: "studio-sandbox-resource-limits",
        title: "Sandbox resources",
        kind: "sandbox.resource_limits",
        item: array(studioRuntimeProjection.sandboxResourceLimitPanels).at(-1),
        defaultStatus: "blocked",
        defaultDetail: "Command resource limits are enforced before execution.",
      },
      {
        testId: "studio-imported-parent-trajectory-linkage",
        title: "Imported parent links",
        kind: "imported.parent_trajectory_linkage",
        item: array(studioRuntimeProjection.parentTrajectoryLinkagePanels).at(-1),
        defaultStatus: "needs_review",
        defaultDetail: "Parent/child trajectory links are audit-only.",
      },
      {
        testId: "studio-imported-battle-mode-permission",
        title: "Imported permissions",
        kind: "imported.battle_mode_permission",
        item: array(studioRuntimeProjection.battleModePermissionImportPanels).at(-1),
        defaultStatus: "blocked",
        defaultDetail: "Historical permission rows do not grant IOI authority.",
      },
      {
        testId: "studio-imported-stop-hook-gates",
        title: "Imported stop hooks",
        kind: "imported.stop_hook_gates",
        item: array(studioRuntimeProjection.importedStopHookGatePanels).at(-1),
        defaultStatus: "needs_review",
        defaultDetail: "Historical stop-hook rows require live verification.",
      },
      {
        testId: "studio-imported-browser-action-evidence",
        title: "Imported browser evidence",
        kind: "imported.browser_action_evidence",
        item: array(studioRuntimeProjection.importedBrowserActionEvidencePanels).at(-1),
        defaultStatus: "needs_review",
        defaultDetail: "Historical browser actions require fresh observation.",
      },
      {
        testId: "studio-imported-executor-config",
        title: "Imported executor config",
        kind: "imported.executor_config",
        item: array(studioRuntimeProjection.importedExecutorConfigPanels).at(-1),
        defaultStatus: "needs_review",
        defaultDetail: "Executor metadata is advisory-only.",
      },
      {
        testId: "studio-imported-policy-draft",
        title: "Imported policy draft",
        kind: "imported.policy_draft",
        item: array(studioRuntimeProjection.importedPolicyDraftPanels).at(-1),
        defaultStatus: "needs_review",
        defaultDetail: "Executor hints become draft-only policy.",
      },
      {
        testId: "studio-imported-generation-metadata",
        title: "Imported generation metadata",
        kind: "imported.generation_metadata",
        item: array(studioRuntimeProjection.importedGenerationMetadataPanels).at(-1),
        defaultStatus: "blocked",
        defaultDetail: "Prompts and reasoning are retained only as redacted summaries.",
      },
      {
        testId: "studio-imported-error-render-info",
        title: "Imported error/render info",
        kind: "imported.error_render_info",
        item: array(studioRuntimeProjection.importedErrorRenderInfoPanels).at(-1),
        defaultStatus: "blocked",
        defaultDetail: "Stacks and render payloads stay out of replay UI.",
      },
    ];
    const rows = panelSpecs.map((spec) => {
      const item = spec.item && typeof spec.item === "object" ? spec.item : {};
      const status = text(item.status || item.state, spec.defaultStatus);
      const detail = text(item.bannerLabel || item.detail || item.mergeBlockReason || item.summary, spec.defaultDetail);
      const sessionBrainAttrs = spec.kind === "session.brain"
        ? [
            ["data-brain-implementation-plan-observed", item.hasImplementationPlan === true],
            ["data-brain-task-checklist-observed", item.hasTaskChecklist === true],
            ["data-brain-walkthrough-observed", item.hasWalkthrough === true],
            ["data-brain-scratch-refs-observed", item.hasScratchRefs === true],
            ["data-brain-artifact-refs-observed", item.hasArtifactRefs === true],
            ["data-brain-replay-cursor-observed", item.hasReplayCursor === true],
            ["data-brain-outside-workspace", item.brainOutsideWorkspace === true],
            ["data-brain-read-only-audit-mode", item.readOnlyAuditMode === true],
          ].map(([name, value]) => ` ${name}="${value ? "true" : "false"}"`).join("")
        : "";
      const trajectoryReplayAttrs = spec.kind === "trajectory.replay"
        ? [
            ["data-trajectory-id-stable", item.trajectoryIdStable === true],
            ["data-trajectory-replay-cursor-observed", item.replayCursorObserved === true],
            ["data-trajectory-gui-reconnected", item.guiReconnected === true],
            ["data-trajectory-replay-ids-stable", item.replayIdsStable === true],
            ["data-trajectory-replay-from-cursor-empty", item.replayFromCursorEmpty === true],
            ["data-trajectory-side-effect-count", Number(item.sideEffectCount || 0)],
            ["data-trajectory-duplicate-side-effect-count", Number(item.duplicateSideEffectCount || 0)],
          ].map(([name, value]) => ` ${name}="${escape(String(value))}"`).join("")
        : "";
      const sessionBrainBody = spec.kind === "session.brain" ? studioSessionBrainArtifactRows(item) : "";
      const trajectoryReplayBody = spec.kind === "trajectory.replay" ? studioTrajectoryReplayRows(item) : "";
      return `
        <article class="studio-cockpit-card" data-testid="${escape(spec.testId)}" data-panel-kind="${escape(spec.kind)}" data-panel-status="${escape(status)}"${sessionBrainAttrs}${trajectoryReplayAttrs}>
          <strong>${escape(spec.title)}</strong>
          <span>${escape(detail)}</span>
          ${trajectoryReplayBody}
          ${sessionBrainBody}
          ${verifiedBadge(item)}
          ${traceLink({ ...item, kind: spec.kind })}
        </article>
      `;
    });
    return rows.join("");
  }

  function studioStage2WebRepairEventText(events = []) {
    return array(events)
      .map((event) => {
        try {
          return JSON.stringify(event);
        } catch {
          return String(event);
        }
      })
      .join("\n");
  }

  function studioStage2FinalContractValues(events = []) {
    const values = [];
    for (const event of array(events)) {
      const eventText = studioStage2WebRepairEventText([event]);
      if (!/\b(final_output_contract_ready|web_final_summary_contract_ready|contract_ready)\b/i.test(eventText)) {
        continue;
      }
      if (/\b(satisfied|ready|success|value|passed)\b[^a-z0-9]{0,16}false\b/i.test(eventText)) {
        values.push(false);
      }
      if (/\b(satisfied|ready|success|value|passed)\b[^a-z0-9]{0,16}true\b/i.test(eventText)) {
        values.push(true);
      }
      for (const match of eventText.matchAll(/\b(?:web_final_summary_contract_ready|contract_ready)=(true|false)\b/gi)) {
        values.push(match[1].toLowerCase() === "true");
      }
    }
    return values;
  }

  function studioStage2ProductTextIsClean(value = "") {
    const productText = String(value || "");
    return ![
      /\bERROR_CLASS=/i,
      /\bValidator feedback\b/i,
      /\bweb_model_chat_reply_contract_rejected_for_retry\b/i,
      /\bfinal_output_contract_ready\b/i,
      /\bchat_reply_model_authored_web_pipeline_answer_/i,
      /\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/i,
      /\b(?:autopilot-)?native-fixture\b/i,
      /\bmodel_chat_reply\b/i,
      /\/home\/[^<\s]+/i,
      /\/tmp\/[^<\s]+/i,
    ].some((pattern) => pattern.test(productText));
  }

  function studioStage5ProductTextIsClean(value = "") {
    const productText = String(value || "");
    return ![
      /\bERROR_CLASS=/i,
      /\bStopHookBlocked\b/i,
      /\bstop_hook/i,
      /\bchat_reply_blocked_by_stop_hook\b/i,
      /\bstop_hook_completion_blocked\b/i,
      /\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/i,
      /\b(?:autopilot-)?native-fixture\b/i,
      /\btool\.(?:completed|failed|started)\b/i,
      /\.tmp\/autopilot-stage5-stop-hook-repair/i,
      /\/home\/[^<\s]+/i,
      /\/tmp\/[^<\s]+/i,
    ].some((pattern) => pattern.test(productText));
  }

  async function exerciseStudioStage2WebRepairLoop(output, payload = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const contextSnapshot = buildWorkspaceActionContext("studio-stage2-web-repair-loop");
    const prompt = text(
      payload.prompt,
      "Who is the current Secretary-General of the UN? Use current web evidence and cite the source.",
    );
    const selectedRoute = text(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
    const selectedModelId = text(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
    await submitStudioPrompt({
      prompt,
      executionMode: STUDIO_MODE_AGENT,
      approvalMode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
      routeId: selectedRoute,
      modelId: selectedModelId,
      reasoningEffort: "none",
    }, output);

    const threadId = studioRuntimeProjection.threadId;
    const turnId = studioRuntimeProjection.turnId;
    const turnEvents = await fetchStudioThreadTurnEvents(threadId, output, { turnId });
    const streamEvents = await fetchStudioThreadEvents(threadId, output, {
      sinceSeq: 0,
      timeoutMs: 5000,
    });
    const events = uniqueStudioRuntimeEvents([...turnEvents, ...streamEvents]);
    const eventText = studioStage2WebRepairEventText(events);
    const contractValues = studioStage2FinalContractValues(events);
    const falseIndex = contractValues.indexOf(false);
    const trueAfterFalse = falseIndex >= 0
      ? contractValues.findIndex((value, index) => index > falseIndex && value === true)
      : -1;
    const assistantTurn = array(studioRuntimeProjection.turns)
      .slice()
      .reverse()
      .find((turn) => text(turn?.role).toLowerCase() === "assistant") || {};
    const assistantText = sanitizeStudioProductAssistantText(assistantTurn?.content || "");
    const sourceRefs = [
      ...array(assistantTurn?.sourceRefs),
      ...studioSourceRefsFromRuntimeEvents(events),
    ].filter((source, index, all) => {
      const key = `${source?.url || ""} ${source?.title || ""}`.toLowerCase();
      return key.trim() && all.findIndex((candidate) =>
        `${candidate?.url || ""} ${candidate?.title || ""}`.toLowerCase() === key
      ) === index;
    });
    const workLaneText = [
      studioStage2WebRepairEventText(array(studioRuntimeProjection.actionCards).slice(-12)),
      (() => {
        try {
          return JSON.stringify(assistantTurn?.workRecord || {});
        } catch {
          return "";
        }
      })(),
    ].join("\n");
    const stage2ForcedRejectionObserved =
      /stage2_web_repair_forced_model_chat_reply_rejection=true/i.test(eventText);
    const chatReplyCompleted =
      studioRuntimeEventsIncludeCompletedTool(events, /chat(::|__)reply|chat_reply/) ||
      /chat(::|__)reply[\s\S]{0,120}\bcompleted\b|Used chat reply/i.test(`${eventText}\n${workLaneText}`);
    const answerMentionsCurrentSecretaryGeneral =
      /\bAnt[oó]nio Guterres\b/i.test(assistantText) && /\bSecretary-General\b/i.test(assistantText);
    const checks = {
      submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
      threadAndTurnAvailable: Boolean(threadId && turnId),
      webSearchCompleted: studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/),
      webReadCompleted: studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/),
      weakChatReplyRejected: stage2ForcedRejectionObserved || /chat_reply_model_authored_web_pipeline_answer_rejected_for_retry|web_model_chat_reply_contract_rejected_for_retry=true|Final web answer is not ready|Validator feedback/i.test(eventText),
      finalChatReplyAccepted: /chat_reply_model_authored_web_pipeline_answer_accepted|web_final_answer_source[\s\S]{0,120}model_chat_reply|terminal_chat_reply_ready[\s\S]{0,80}true/i.test(eventText) ||
        (stage2ForcedRejectionObserved && chatReplyCompleted && answerMentionsCurrentSecretaryGeneral),
      finalContractFalseThenTrue: (falseIndex >= 0 && trueAfterFalse > falseIndex) ||
        (stage2ForcedRejectionObserved && chatReplyCompleted && answerMentionsCurrentSecretaryGeneral),
      modelChatReplyProviderObserved: /\bmodel_chat_reply\b/i.test(eventText) ||
        (stage2ForcedRejectionObserved && chatReplyCompleted),
      answerMentionsCurrentSecretaryGeneral,
      answerCitesPublicSource: sourceRefs.some((source) => /ask\.un\.org\/faq\/14625/i.test(String(source?.url || ""))) ||
        /https:\/\/ask\.un\.org\/faq\/14625/i.test(assistantText),
      productTranscriptClean: studioStage2ProductTextIsClean(assistantText),
      sourceRefsProjected: sourceRefs.length > 0,
      sourceRichWorkLane: /web(::|__)search|web(::|__)read|source|ask\.un\.org/i.test(workLaneText),
    };
    const passed = Object.values(checks).every(Boolean);
    await writeBridgeRequest("studio.stage2WebRepairLoop.exercised", {
      sourceCommand: "ioi.studio.exerciseStage2WebRepairLoop",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
      passed,
      checks,
      eventCount: events.length,
      sourceRefCount: sourceRefs.length,
      finalContractValues: contractValues,
      answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
    }, contextSnapshot).catch((error) => {
      output.appendLine(`[ioi-studio] stage2 web repair loop bridge request unavailable: ${error?.message || String(error)}`);
    });
    return {
      passed,
      checks,
      eventCount: events.length,
      sourceRefCount: sourceRefs.length,
      finalContractValues: contractValues,
      answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
    };
  }

  async function exerciseStudioStage5StopHookRepairLoop(output, payload = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const contextSnapshot = buildWorkspaceActionContext("studio-stage5-stop-hook-repair-loop");
    const helperPath = text(
      payload.helperPath || payload.helper_path,
      ".tmp/autopilot-stage5-stop-hook-repair/status-labels.mjs",
    );
    const testPath = helperPath.replace(/status-labels\.mjs$/i, "status-labels.test.mjs");
    const prompt = text(
      payload.prompt,
      [
        `ARP_P0_007_PROOF_TOKEN repair loop for normalizeStatusLabel at ${helperPath}.`,
        "Follow the governed validation sequence, repair the disposable helper if validation fails, rerun validation, and answer only after green.",
      ].join(" "),
    );
    const selectedRoute = text(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
    const selectedModelId = text(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
    await submitStudioPrompt({
      prompt,
      executionMode: STUDIO_MODE_AGENT,
      approvalMode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
      routeId: selectedRoute,
      modelId: selectedModelId,
      reasoningEffort: "none",
    }, output);

    const threadId = studioRuntimeProjection.threadId;
    const turnId = studioRuntimeProjection.turnId;
    const turnEvents = await fetchStudioThreadTurnEvents(threadId, output, { turnId });
    const streamEvents = await fetchStudioThreadEvents(threadId, output, {
      sinceSeq: 0,
      timeoutMs: 5000,
    });
    const events = uniqueStudioRuntimeEvents([...turnEvents, ...streamEvents]);
    const eventText = studioStage2WebRepairEventText(events);
    const assistantTurn = array(studioRuntimeProjection.turns)
      .slice()
      .reverse()
      .find((turn) => text(turn?.role).toLowerCase() === "assistant") || {};
    const assistantText = sanitizeStudioProductAssistantText(assistantTurn?.content || "");
    const workLaneText = [
      studioStage2WebRepairEventText(array(studioRuntimeProjection.actionCards).slice(-16)),
      studioStage2WebRepairEventText(array(studioRuntimeProjection.commandOutputs).slice(-8)),
      studioStage2WebRepairEventText(array(studioRuntimeProjection.diffHunks).slice(-8)),
      (() => {
        try {
          return JSON.stringify(assistantTurn?.workRecord || {});
        } catch {
          return "";
        }
      })(),
    ].join("\n");
    const shellRunCompleted =
      studioRuntimeEventsIncludeCompletedTool(events, /shell(::|__)run|shell_run/) ||
      /shell(::|__)run[\s\S]{0,160}\bcompleted\b/i.test(`${eventText}\n${workLaneText}`);
    const shellRunCount = Math.max(
      studioRuntimeToolEventCount(events, /shell(::|__)run|shell_run/),
      (eventText.match(/\bshell(::|__)run\b/gi) || []).length,
    );
    const failingValidationObserved =
      /\bexit[_\s-]?code\b[^0-9-]{0,16}-?[1-9]\d*|\bnot ok\b|\bAssertionError\b|\b#\s*fail\s+[1-9]\d*\b/i.test(eventText);
    const stopHookBlockedReply =
      /ERROR_CLASS=StopHookBlocked|stop_hook_completion_blocked=true|chat_reply_blocked_by_stop_hook/i.test(eventText);
    const editCompleted =
      studioRuntimeEventsIncludeCompletedTool(events, /file(::|__)edit|file_edit/) ||
      /file(::|__)edit[\s\S]{0,160}\bcompleted\b/i.test(`${eventText}\n${workLaneText}`);
    const passingValidationObserved =
      /\b#\s*pass\s+[1-9]\d*\b[\s\S]{0,120}\b#\s*fail\s+0\b/i.test(eventText) ||
      /\bexit[_\s-]?code\b[^0-9-]{0,16}0\b/i.test(eventText);
    const chatReplyCompleted =
      studioRuntimeEventsIncludeCompletedTool(events, /chat(::|__)reply|chat_reply/) ||
      /chat(::|__)reply[\s\S]{0,160}\bcompleted\b|Used chat reply/i.test(`${eventText}\n${workLaneText}`);
    const hunkProjected =
      array(studioRuntimeProjection.diffHunks).some((hunk) =>
        /status-labels\.mjs/i.test(String(hunk?.file || hunk?.path || "")) ||
        /normalizeStatusLabel/i.test(`${hunk?.before || ""}\n${hunk?.after || ""}`)
      ) ||
      /studio-inline-diff-hunks|normalizeStatusLabel|file(::|__)edit/i.test(workLaneText);
    const finalAnswerClean =
      /repaired|passes|validation/i.test(assistantText) &&
      studioStage5ProductTextIsClean(assistantText);
    const checks = {
      submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
      threadAndTurnAvailable: Boolean(threadId && turnId),
      firstValidationCommandCompleted: shellRunCompleted,
      failingValidationObserved,
      prematureChatReplyBlocked: stopHookBlockedReply,
      hunkEditCompleted: editCompleted,
      hunkWorkflowProjected: hunkProjected,
      validationReranAfterEdit: shellRunCount >= 2 || (editCompleted && passingValidationObserved),
      passingValidationObserved,
      finalChatReplyCompleted: chatReplyCompleted,
      productTranscriptClean: finalAnswerClean,
      workLaneShowsRepairLoop: /shell(::|__)run|file(::|__)edit|validation|hunk|status-label/i.test(workLaneText),
    };
    const passed = Object.values(checks).every(Boolean);
    await writeBridgeRequest("studio.stage5StopHookRepairLoop.exercised", {
      sourceCommand: "ioi.studio.exerciseStage5StopHookRepairLoop",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
      passed,
      checks,
      eventCount: events.length,
      helperPath: studioPublicWorkspacePath(helperPath),
      testPath: studioPublicWorkspacePath(testPath),
      answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
    }, contextSnapshot).catch((error) => {
      output.appendLine(`[ioi-studio] stage5 stop-hook repair loop bridge request unavailable: ${error?.message || String(error)}`);
    });
    return {
      passed,
      checks,
      eventCount: events.length,
      answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
    };
  }

  async function waitForStudioRuntimeProjection(predicate, timeoutMs, label) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (predicate()) return true;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`Timed out waiting for Studio runtime projection: ${label}`);
  }

  async function exerciseStudioStage5StopCancelRecoverLifecycle(output, payload = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const contextSnapshot = buildWorkspaceActionContext("studio-stage5-stop-cancel-recover");
    const prompt = text(
      payload.prompt,
      [
        "ARP_P0_006_LIVE_GUI_STOP_CANCEL_RECOVER_PROOF",
        "Start a runtime_service turn, keep the model stream observable until operator stop, then resume and finish.",
      ].join(" "),
    );
    const selectedRoute = text(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
    const selectedModelId = text(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
    studioRuntimeProjection.pending = true;
    studioRuntimeProjection.status = "pending";
    studioRuntimeProjection.pendingSeen = true;
    studioRuntimeProjection.pendingStartedAtMs = Date.now();
    studioRuntimeProjection.pendingWorklog = [];
    studioRuntimeProjection.lastError = null;
    studioRuntimeProjection.executionMode = STUDIO_MODE_AGENT;
    studioRuntimeProjection.runtimeProfile = STUDIO_AGENT_RUNTIME_PROFILE;
    studioRuntimeProjection.modelRoute = selectedRoute;
    studioRuntimeProjection.selectedModel = selectedModelId;
    appendTimeline("Stage 5 lifecycle proof started", "Runtime turn submitted for stop/resume control proof.", "running");
    await refreshPanelHtml(output);

    const submittedAtMs = Date.now();
    const turnPromise = submitStudioAgentTurn({
      prompt,
      selectedRoute,
      selectedModelId,
      reasoningEffort: "none",
      workspacePath: workspace().path,
      maxStepsOverride: payload.maxSteps || payload.max_steps || 8,
    }, output);

    await waitForStudioRuntimeProjection(
      () => Boolean(studioRuntimeProjection.threadId && studioRuntimeProjection.turnId),
      Number(payload.turnIdTimeoutMs || payload.turn_id_timeout_ms || 30_000),
      "threadId and turnId from live runtime events",
    );
    const threadId = studioRuntimeProjection.threadId;
    const turnId = studioRuntimeProjection.turnId;
    const stopRequestedAtMs = Date.now();
    await stopStudioTurn(output);
    await waitForStudioRuntimeProjection(
      () => studioRuntimeProjection.runtimeCockpit.stopControlObserved === true,
      10_000,
      "runtime stop control acknowledgement",
    );
    const resumeRequestedAtMs = Date.now();
    await resumeStudioTurn(output);
    const agentTurn = await turnPromise;
    const productAgentText = sanitizeStudioProductAssistantText(agentTurn?.text || "");
    if (productAgentText) {
      studioRuntimeProjection.turns.push({
        role: "assistant",
        content: productAgentText,
        createdAt: new Date().toISOString(),
        agentTurn: {
          turnId,
          eventCount: array(agentTurn?.events).length,
          receiptRefs: array(agentTurn?.receiptRefs),
          prompt,
          status: agentTurn?.status === "blocked" ? "blocked" : "completed",
        },
      });
    }
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = "completed";
    await refreshPanelHtml(output);

    const events = uniqueStudioRuntimeEvents([
      ...await fetchStudioThreadTurnEvents(threadId, output, { turnId }).catch(() => []),
      ...await fetchStudioThreadEvents(threadId, output, { sinceSeq: 0, timeoutMs: 5000 }).catch(() => []),
    ]);
    const eventText = studioStage2WebRepairEventText(events);
    const checks = {
      submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
      threadAndTurnAvailable: Boolean(threadId && turnId),
      turnStartedBeforeStop: submittedAtMs <= stopRequestedAtMs,
      stopBeforeResume: stopRequestedAtMs <= resumeRequestedAtMs,
      stopControlObserved: studioRuntimeProjection.runtimeCockpit.stopControlObserved === true,
      resumeControlObserved: studioRuntimeProjection.runtimeCockpit.resumeControlObserved === true,
      stopResumeObserved: studioRuntimeProjection.runtimeCockpit.stopResumeObserved === true,
      runtimeEventsObserved: events.length > 0,
      turnStartedEventObserved: /turn\.started|model stream is active/i.test(eventText),
      finalAnswerClean: studioStage5ProductTextIsClean(productAgentText),
    };
    const passed = Object.values(checks).every(Boolean);
    await writeBridgeRequest("studio.stage5StopCancelRecover.exercised", {
      sourceCommand: "ioi.studio.exerciseStage5StopCancelRecoverLifecycle",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
      passed,
      checks,
      threadId,
      turnId,
      eventCount: events.length,
      submittedAtMs,
      stopRequestedAtMs,
      resumeRequestedAtMs,
      answerPreview: compactStudioWhitespace(productAgentText).slice(0, 240),
    }, contextSnapshot).catch((error) => {
      output.appendLine(`[ioi-studio] stage5 stop/cancel/recover bridge request unavailable: ${error?.message || String(error)}`);
    });
    return {
      passed,
      checks,
      threadId,
      turnId,
      eventCount: events.length,
      answerPreview: compactStudioWhitespace(productAgentText).slice(0, 240),
    };
  }

  return {
    exerciseStudioStage2WebRepairLoop,
    exerciseStudioStage5StopCancelRecoverLifecycle,
    exerciseStudioStage5StopHookRepairLoop,
    studioParityPlusPanelRows,
    studioSessionBrainArtifactRows,
    studioStage2FinalContractValues,
    studioStage2ProductTextIsClean,
    studioStage2WebRepairEventText,
    studioStage5ProductTextIsClean,
    studioTrajectoryReplayRows,
  };
}

module.exports = {
  createStudioParityPlusPanels,
};
