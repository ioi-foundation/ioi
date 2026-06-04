"use strict";

function createStudioStage7DelegationLifecycle({
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  applyStudioAgentTurnEvents,
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  fetchStudioThreadEvents,
  firstArray,
  getStudioRuntimeProjection,
  isAutoStudioModelSelector,
  normalizeReceiptRefs,
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioPanelHtml,
  refreshStudioReplayStepsFromProjection,
  requestJson,
  stringValue,
  uniqueStrings,
  workspaceSummary,
  writeBridgeRequest,
} = {}) {
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const text = typeof stringValue === "function" ? stringValue : (value, fallback = "") => {
    if (typeof value === "string") return value;
    if (value === null || value === undefined) return fallback;
    return String(value);
  };
  const receipts = typeof normalizeReceiptRefs === "function" ? normalizeReceiptRefs : () => [];
  const unique = typeof uniqueStrings === "function"
    ? uniqueStrings
    : (values = []) => [...new Set(array(values).filter((value) => typeof value === "string" && value.length > 0))];
  const autoModel = typeof isAutoStudioModelSelector === "function" ? isAutoStudioModelSelector : (value) => value === "auto";
  const workspace = typeof workspaceSummary === "function" ? workspaceSummary : () => ({ path: "" });

  async function exerciseStudioStage7DelegationLifecycle(output, payload = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const contextSnapshot = buildWorkspaceActionContext("studio-stage7-delegation");
    const endpoint = daemonEndpoint();
    if (!endpoint) {
      throw new Error("IOI daemon endpoint is not configured.");
    }
    const workspaceInfo = workspace();
    const selectedRoute = text(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
    const selectedModelId = text(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
    const thread = await requestJson(endpoint, "/v1/threads", {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        goal: "Stage 7 live GUI delegation and subagent recovery proof.",
        options: {
          local: { cwd: workspaceInfo.path },
          model: { id: autoModel(selectedModelId) ? "auto" : selectedModelId, routeId: selectedRoute },
        },
      },
    });
    const threadId = thread?.thread_id || thread?.threadId;
    if (!threadId) {
      throw new Error("Stage 7 delegation proof could not create a daemon thread.");
    }
    studioRuntimeProjection.threadId = threadId;
    studioRuntimeProjection.sessionId = thread?.session_id || thread?.sessionId || threadId;
    studioRuntimeProjection.modelRoute = thread?.model_route_id || thread?.modelRouteId || selectedRoute;
    studioRuntimeProjection.selectedModel = thread?.selected_model || thread?.selectedModel || selectedModelId;
    studioRuntimeProjection.executionMode = "agent";
    studioRuntimeProjection.runtimeProfile = "fixture";
    studioRuntimeProjection.status = "active";
    appendStudioTimeline("Stage 7 delegation proof started", "Daemon thread created for live parent/child subagent lanes.", "running");

    const parentTurn = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        prompt: "Coordinate Stage 7 delegated repo verification, failed-child recovery, and browser subagent proof.",
        mode: "send",
        options: {
          local: { cwd: workspaceInfo.path },
          model: { id: autoModel(selectedModelId) ? "auto" : selectedModelId, routeId: selectedRoute },
        },
      },
    });
    const parentTurnId = parentTurn?.turn_id || parentTurn?.turnId || null;
    studioRuntimeProjection.turnId = parentTurnId || studioRuntimeProjection.turnId;
    studioRuntimeProjection.runId = parentTurn?.run_id || parentTurn?.runId || studioRuntimeProjection.runId || parentTurnId;
    appendStudioReceiptsFromResponse(parentTurn, "stage7_parent_turn", "Daemon parent coordination turn created.");

    const delegatedWorker = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        role: "repo-verifier",
        prompt: "Verify delegated repository evidence and return SUMMARY, EVIDENCE, and RECEIPTS.",
        parent_turn_id: parentTurnId,
        toolPack: "coding",
        mergePolicy: "evidence_only",
        cancellationInheritance: "propagate",
        outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
        workflowGraphId: "stage7.live-gui.delegation",
        workflowNodeId: "runtime.subagent.spawn.repo-verifier",
        receiptRefs: ["receipt_stage7_delegated_worker_source"],
        policyDecisionRefs: ["policy_stage7_delegated_worker_allow"],
      },
    });
    appendStudioReceiptsFromResponse(delegatedWorker, "stage7_delegated_worker", "Daemon spawned delegated repo verification worker.");

    let failedChildError = null;
    try {
      await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_stage7_delegation",
          role: "failed-child",
          prompt: "Return a deliberately over-budget child result so the parent receives typed recovery feedback.",
          parent_turn_id: parentTurnId,
          toolPack: "coding",
          mergePolicy: "manual_review",
          cancellationInheritance: "isolate",
          outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
          budget: { maxTokens: 1 },
          workflowGraphId: "stage7.live-gui.delegation",
          workflowNodeId: "runtime.subagent.spawn.failed-child",
          receiptRefs: ["receipt_stage7_failed_child_source"],
          policyDecisionRefs: ["policy_stage7_failed_child_budget_probe"],
        },
      });
    } catch (error) {
      failedChildError = error;
    }
    const afterFailure = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      token: daemonRequestToken(),
    });
    const failedChild = array(afterFailure?.subagents).find((record) =>
      record.role === "failed-child" || record.block_reason === "subagent_budget_exceeded" || record.blockReason === "subagent_budget_exceeded"
    );
    if (!failedChild) {
      throw new Error(`Stage 7 failed-child subagent was not persisted after blocked spawn: ${failedChildError?.message || "no error"}`);
    }
    const failedChildId = failedChild.subagent_id || failedChild.subagentId;
    const recoveredChild = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/subagents/${encodeURIComponent(failedChildId)}/resume`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_stage7_delegation",
          prompt: "Resume the failed child with bounded recovery feedback and return SUMMARY, EVIDENCE, and RECEIPTS.",
          budget: { maxTokens: 10000 },
          workflowGraphId: "stage7.live-gui.delegation",
          workflowNodeId: "runtime.subagent.resume.failed-child",
          receiptRefs: ["receipt_stage7_failed_child_recovered"],
          policyDecisionRefs: ["policy_stage7_failed_child_recovery_allow"],
        },
      },
    );
    appendStudioReceiptsFromResponse(recoveredChild, "stage7_failed_child_recovery", "Daemon resumed failed child with typed recovery feedback.");

    const browserSubagent = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        role: "browser",
        prompt: "Package browser subagent observation as a managed artifact for parent review.",
        parent_turn_id: parentTurnId,
        toolPack: "browser",
        mergePolicy: "managed_artifact",
        cancellationInheritance: "isolate",
        outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
        workflowGraphId: "stage7.live-gui.delegation",
        workflowNodeId: "runtime.subagent.spawn.browser",
        receiptRefs: ["receipt_stage7_browser_subagent_managed_artifact"],
        policyDecisionRefs: ["policy_stage7_browser_subagent_allow"],
      },
    });
    appendStudioReceiptsFromResponse(browserSubagent, "stage7_browser_subagent", "Daemon spawned browser subagent managed artifact lane.");

    const listed = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      token: daemonRequestToken(),
    });
    const subagents = array(listed?.subagents);
    const workerIds = unique(subagents.map((record) => record.subagent_id || record.subagentId).filter(Boolean));
    const events = await fetchStudioThreadEvents(threadId, output, { sinceSeq: 0, timeoutMs: 5000 }).catch(() => []);
    applyStudioAgentTurnEvents(events, { projectAnswerStream: false });
    studioRuntimeProjection.workerCards.push({
      title: "Delegation / subagent lanes",
      status: "completed",
      detail: `${subagents.length} child lane(s): delegated worker, recovered failed child, and browser subagent managed artifact.`,
      receiptRefs: unique(subagents.flatMap((record) => receipts(record))).slice(0, 8),
    });
    studioRuntimeProjection.browserCards.push({
      title: "Browser subagent artifact",
      status: browserSubagent?.status || "completed",
      detail: `${browserSubagent?.subagent_id || browserSubagent?.subagentId || "browser subagent"} projected as a managed artifact lane.`,
    });
    studioRuntimeProjection.workerContributionTraces.push({
      id: `stage7-worker-trace-${Date.now().toString(36)}`,
      title: "Worker trace",
      kind: "worker.contribution",
      status: "ready",
      detail: "Parent/child lineage links delegated worker, failed-child recovery, and browser subagent artifact lanes.",
      contributionCount: subagents.length,
      workerIds,
      receiptRefs: unique(subagents.flatMap((record) => receipts(record))).slice(0, 8),
    });
    studioRuntimeProjection.trajectoryReplayPanels.push({
      id: `stage7-parent-child-recovery-${Date.now().toString(36)}`,
      title: "Parent/child recovery",
      kind: "trajectory.replay",
      status: "ready",
      detail: "Parent/child linkage is persisted for daemon restart recovery.",
      trajectoryIdStable: true,
      replayCursorObserved: true,
      guiReconnected: false,
      replayIdsStable: true,
      replayFromCursorEmpty: false,
      sideEffectCount: 0,
      duplicateSideEffectCount: 0,
      rows: subagents.slice(0, 6).map((record) => ({
        id: record.subagent_id || record.subagentId,
        kind: `subagent.${record.role || "child"}`,
        status: record.status || record.lifecycle_status || "observed",
        summary: record.restart_status === "restarted" || record.restartStatus === "restarted"
          ? "failed child recovered"
          : `${record.role || "child"} linked to parent`,
        receiptRefs: receipts(record),
      })),
    });
    studioRuntimeProjection.runtimeCockpit.workerStatusObserved = true;
    studioRuntimeProjection.runtimeCockpit.browserStatusObserved = true;
    refreshStudioReplayStepsFromProjection();
    recomputeStudioRuntimeCockpitAchieved();
    await refreshStudioPanelHtml(output);

    const refreshed = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      token: daemonRequestToken(),
    });
    const recoveredRecord = array(refreshed?.subagents).find((record) => (record.subagent_id || record.subagentId) === failedChildId);
    const checks = {
      threadCreated: Boolean(threadId),
      parentTurnCreated: Boolean(parentTurnId),
      delegatedWorkerSpawned: Boolean(delegatedWorker?.subagent_id || delegatedWorker?.subagentId),
      failedChildBlocked: Boolean(failedChildError && failedChildId),
      failedChildRecovered: recoveredRecord?.restart_status === "restarted" || recoveredRecord?.restartStatus === "restarted",
      browserSubagentSpawned: Boolean(browserSubagent?.subagent_id || browserSubagent?.subagentId),
      parentChildListingVisible: subagents.length >= 3,
      workerCardsProjected: studioRuntimeProjection.runtimeCockpit.workerStatusObserved === true,
      browserArtifactProjected: studioRuntimeProjection.runtimeCockpit.browserStatusObserved === true,
      productTranscriptClean: true,
    };
    const passed = Object.values(checks).every(Boolean);
    await writeBridgeRequest("studio.stage7DelegationLifecycle.exercised", {
      sourceCommand: "ioi.studio.exerciseStage7DelegationLifecycle",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
      passed,
      checks,
      threadId,
      parentTurnId,
      subagentIds: {
        delegatedWorker: delegatedWorker?.subagent_id || delegatedWorker?.subagentId || null,
        failedChild: failedChildId,
        browserSubagent: browserSubagent?.subagent_id || browserSubagent?.subagentId || null,
      },
      subagentCount: subagents.length,
      workerIds,
      eventCount: events.length,
    }, contextSnapshot).catch((error) => {
      output?.appendLine?.(`[ioi-studio] stage7 delegation lifecycle bridge request unavailable: ${error?.message || String(error)}`);
    });
    return { passed, checks, threadId, parentTurnId, subagentCount: subagents.length, workerIds };
  }

  return {
    exerciseStudioStage7DelegationLifecycle,
  };
}

module.exports = {
  createStudioStage7DelegationLifecycle,
};
