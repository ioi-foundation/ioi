"use strict";

function createStudioParityPlusPanels({
  escapeHtml,
  firstArray,
  stringValue,
  studioTraceLink,
  studioVerifiedBadge,
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

  return {
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
