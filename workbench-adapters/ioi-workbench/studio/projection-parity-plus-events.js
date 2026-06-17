"use strict";

function createStudioParityPlusEventProjection({
  firstArray,
  getStudioRuntimeProjection,
  normalizeReceiptRefs,
  stringValue,
  studioRuntimeEventKind,
}) {
  function studioRuntimeEventPayload(event = {}) {
    return event.payload_summary || event.payloadSummary || event.payload || event.data || {};
  }

  function applyStudioParityPlusEvent(event = {}, normalized = {}) {
    const projection = getStudioRuntimeProjection();
    const payload = studioRuntimeEventPayload(event);
    const kind = String(normalized.kind || studioRuntimeEventKind(event) || "").toLowerCase();
    const schema = String(payload.schemaVersion || payload.schema_version || event.schemaVersion || event.schema_version || "").toLowerCase();
    const signature = `${kind} ${schema}`.toLowerCase();
    const base = {
      id: event.event_id || event.eventId || event.id || `${kind || "parity-plus"}.${Date.now()}`,
      status: normalized.status || payload.status || event.status || "observed",
      summary: normalized.summary || payload.summary || payload.bannerLabel || payload.mergeBlockReason || "",
      detail: payload.detail || payload.reason || payload.message || "",
      receiptRefs: normalizeReceiptRefs(event, payload),
      raw: event,
    };
    if (/engine[._-]?reconnect|runtime[._-]?reconnect|connection[._-]?reconnect/.test(signature)) {
      projection.engineReconnectBanners.push({
        ...base,
        bannerLabel: payload.bannerLabel || base.summary || "Engine reconnect state observed.",
        composerFrozen: Boolean(payload.composerFrozen),
      });
      return true;
    }
    if (/session[._-]?brain|run[._-]?brain|active[._-]?brain/.test(signature)) {
      projection.sessionBrainPanels.push({
        ...base,
        status: payload.status || base.status || "ready",
        detail: payload.detail || base.detail || "Run brain artifacts are available for replay.",
        artifactCount: payload.artifactCount ?? payload.artifact_count ?? null,
        scratchCount: payload.scratchCount ?? payload.scratch_count ?? null,
        hasImplementationPlan: Boolean(payload.hasImplementationPlan ?? payload.has_implementation_plan),
        hasTaskChecklist: Boolean(payload.hasTaskChecklist ?? payload.has_task_checklist),
        hasWalkthrough: Boolean(payload.hasWalkthrough ?? payload.has_walkthrough),
        hasScratchRefs: Boolean(payload.hasScratchRefs ?? payload.has_scratch_refs),
        hasArtifactRefs: Boolean(payload.hasArtifactRefs ?? payload.has_artifact_refs),
        hasReplayCursor: Boolean(payload.hasReplayCursor ?? payload.has_replay_cursor),
        brainOutsideWorkspace: Boolean(payload.brainOutsideWorkspace ?? payload.brain_outside_workspace),
        readOnlyAuditMode: Boolean(payload.readOnlyAuditMode ?? payload.read_only_audit_mode),
        rows: firstArray(payload.rows).map((row = {}, index) => ({
          id: stringValue(row.id, `session-brain-row-${index}`),
          artifactKind: stringValue(row.artifactKind || row.artifact_kind, "artifact"),
          label: stringValue(row.label, "Run brain artifact"),
          status: stringValue(row.status, "present"),
          preview: stringValue(row.preview, ""),
          receiptRefs: normalizeReceiptRefs(row),
        })),
      });
      return true;
    }
    if (/trajectory[._-]?replay|durable[._-]?trajectory|run[._-]?trajectory/.test(signature)) {
      projection.trajectoryReplayPanels.push({
        ...base,
        status: payload.status || base.status || "ready",
        detail: payload.detail || base.detail || "Durable trajectory replay is available after reconnect.",
        trajectoryIdStable: Boolean(payload.trajectoryIdStable ?? payload.trajectory_id_stable),
        replayCursorObserved: Boolean(payload.replayCursorObserved ?? payload.replay_cursor_observed),
        guiReconnected: Boolean(payload.guiReconnected ?? payload.gui_reconnected),
        replayIdsStable: Boolean(payload.replayIdsStable ?? payload.replay_ids_stable),
        replayFromCursorEmpty: Boolean(payload.replayFromCursorEmpty ?? payload.replay_from_cursor_empty),
        sideEffectCount: Number(payload.sideEffectCount ?? payload.side_effect_count ?? 0) || 0,
        duplicateSideEffectCount: Number(payload.duplicateSideEffectCount ?? payload.duplicate_side_effect_count ?? 0) || 0,
        rows: firstArray(payload.rows).map((row = {}, index) => ({
          id: stringValue(row.id, `trajectory-replay-step-${index + 1}`),
          kind: stringValue(row.kind, "runtime.event"),
          status: stringValue(row.status, "observed"),
          summary: stringValue(row.summary, ""),
          receiptRefs: normalizeReceiptRefs(row),
        })),
      });
      return true;
    }
    if (/chat[._-]?responsibility|reply[._-]?contract|chat__reply/.test(signature)) {
      projection.chatResponsibilityContracts.push({
        ...base,
        directToolLeakCount: payload.directToolLeakCount ?? payload.direct_tool_leak_count ?? 0,
        missingAgentReplyCount: payload.missingAgentReplyCount ?? payload.missing_agent_reply_count ?? 0,
      });
      return true;
    }
    if (/engine[._-]?guard|security[._-]?scan|plaintext[._-]?secret|secret[._-]?scan/.test(signature)) {
      projection.securityScanPanels.push({
        ...base,
        mergeBlockReason: payload.mergeBlockReason || payload.merge_block_reason || base.summary,
        findingCount: payload.findingCount ?? payload.finding_count ?? null,
        mergeActionDisabled: Boolean(payload.mergeActionDisabled ?? payload.merge_action_disabled),
      });
      return true;
    }
    if (/worker[._-]?contribution|subagent[._-]?contribution|worker[._-]?hunk/.test(signature)) {
      projection.workerContributionTraces.push({
        ...base,
        contributionCount: payload.contributionCount ?? payload.contribution_count ?? null,
        workerIds: firstArray(payload.workerIds || payload.worker_ids),
      });
      return true;
    }
    if (/safe[._-]?mode|tool[._-]?suppression/.test(signature)) {
      projection.safeModeToolSuppressionPanels.push({
        ...base,
        status: payload.status || base.status || "safe_mode",
        detail: payload.detail || base.detail || "Ask direct text remains available; Agent tools are suppressed.",
        disabledCount: payload.disabledCount ?? payload.disabled_count ?? null,
        readOnlyCount: payload.readOnlyCount ?? payload.read_only_count ?? null,
      });
      return true;
    }
    if (/onboarding[._-]?diagnostics|diagnostics[._-]?checklist/.test(signature)) {
      projection.onboardingDiagnosticsPanels.push({
        ...base,
        status: payload.status || base.status || "needs_setup",
        detail: payload.detail || base.detail || "Local prerequisite checklist projected.",
        blockedCount: payload.blockedCount ?? payload.blocked_count ?? null,
        needsSetupCount: payload.needsSetupCount ?? payload.needs_setup_count ?? null,
      });
      return true;
    }
    if (/gateway[._-]?token|token[._-]?hygiene/.test(signature)) {
      projection.gatewayTokenHygienePanels.push({
        ...base,
        status: payload.status || base.status || "ready",
        detail: payload.detail || base.detail || "Gateway request is a redacted dry-run plan.",
        requestCount: payload.requestCount ?? payload.request_count ?? null,
      });
      return true;
    }
    if (/sandbox[._-]?resource|resource[._-]?limits/.test(signature)) {
      projection.sandboxResourceLimitPanels.push({
        ...base,
        status: payload.status || base.status || "blocked",
        detail: payload.detail || base.detail || "Sandbox resource limits projected before execution.",
        blockedCount: payload.blockedCount ?? payload.blocked_count ?? null,
        needsReviewCount: payload.needsReviewCount ?? payload.needs_review_count ?? null,
      });
      return true;
    }
    if (/parent[._-]?trajectory|trajectory[._-]?linkage/.test(signature)) {
      projection.parentTrajectoryLinkagePanels.push({
        ...base,
        status: payload.status || base.status || "needs_review",
        detail: payload.detail || base.detail || "Imported parent/child trajectory links are audit-only.",
        linkCount: payload.linkCount ?? payload.link_count ?? payload.rowCount ?? payload.row_count ?? null,
      });
      return true;
    }
    if (/battle[._-]?mode|permission[._-]?import/.test(signature)) {
      projection.battleModePermissionImportPanels.push({
        ...base,
        status: payload.status || base.status || "blocked",
        detail: payload.detail || base.detail || "Imported permission rows are historical-only.",
        rowCount: payload.rowCount ?? payload.row_count ?? null,
      });
      return true;
    }
    if (/stop[._-]?hook|stop[._-]?gate/.test(signature)) {
      projection.importedStopHookGatePanels.push({
        ...base,
        status: payload.status || base.status || "needs_review",
        detail: payload.detail || base.detail || "Imported stop-hook rows require live IOI verification.",
        rowCount: payload.rowCount ?? payload.row_count ?? null,
      });
      return true;
    }
    if (/browser[._-]?action|browser[._-]?evidence/.test(signature)) {
      projection.importedBrowserActionEvidencePanels.push({
        ...base,
        status: payload.status || base.status || "needs_review",
        detail: payload.detail || base.detail || "Imported browser actions require fresh observation before replay.",
        rowCount: payload.rowCount ?? payload.row_count ?? null,
      });
      return true;
    }
    if (/executor[._-]?config/.test(signature)) {
      projection.importedExecutorConfigPanels.push({
        ...base,
        status: payload.status || base.status || "needs_review",
        detail: payload.detail || base.detail || "Imported executor metadata is advisory-only.",
        rowCount: payload.rowCount ?? payload.row_count ?? null,
      });
      return true;
    }
    if (/policy[._-]?draft/.test(signature)) {
      projection.importedPolicyDraftPanels.push({
        ...base,
        status: payload.status || base.status || "needs_review",
        detail: payload.detail || base.detail || "Imported executor hints are converted into draft-only policy.",
        draftItemCount: payload.draftItemCount ?? payload.draft_item_count ?? null,
      });
      return true;
    }
    if (/generation[._-]?metadata|gen[._-]?metadata/.test(signature)) {
      projection.importedGenerationMetadataPanels.push({
        ...base,
        status: payload.status || base.status || "blocked",
        detail: payload.detail || base.detail || "Imported generation metadata is redacted and audit-only.",
        rowCount: payload.rowCount ?? payload.row_count ?? null,
      });
      return true;
    }
    if (/error[._-]?render|render[._-]?info|error[._-]?details/.test(signature)) {
      projection.importedErrorRenderInfoPanels.push({
        ...base,
        status: payload.status || base.status || "blocked",
        detail: payload.detail || base.detail || "Imported error/render rows keep stacks and payloads out of replay UI.",
        rowCount: payload.rowCount ?? payload.row_count ?? null,
      });
      return true;
    }
    return false;
  }

  return {
    applyStudioParityPlusEvent,
    studioRuntimeEventPayload,
  };
}

module.exports = {
  createStudioParityPlusEventProjection,
};
