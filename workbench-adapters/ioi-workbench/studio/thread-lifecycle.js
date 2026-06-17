"use strict";

function createStudioThreadLifecycle({
  appendStudioReceipts,
  daemonEndpoint,
  daemonRequestToken,
  firstArray,
  getStudioRuntimeProjection,
  isAutoStudioModelSelector,
  normalizeStudioExecutionMode,
  normalizeStudioPermissionMode,
  normalizeStudioReasoningEffort,
  requestJson,
  resetStudioDaemonThreadProjection,
  STUDIO_AGENT_RUNTIME_PROFILE = "runtime_service",
  STUDIO_DIRECT_MODEL_RUNTIME_PROFILE = "fixture",
  STUDIO_MODE_AGENT = "agent",
  studioIntentFramePayload,
  studioPermissionDaemonMapping,
  stringValue,
  uniqueStrings,
  workspaceSummary,
} = {}) {
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const text = typeof stringValue === "function" ? stringValue : (value, fallback = "") => {
    if (typeof value === "string") return value;
    if (value === null || value === undefined) return fallback;
    return String(value);
  };
  const unique = typeof uniqueStrings === "function"
    ? uniqueStrings
    : (values = []) => [...new Set(array(values).filter((value) => typeof value === "string" && value.length > 0))];

  function applyStudioAgentModeSelection(payload = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const previousMode = normalizeStudioExecutionMode(studioRuntimeProjection.executionMode);
    const previousRuntimeProfile = studioRuntimeProjection.runtimeProfile;
    const executionMode = normalizeStudioExecutionMode(
      payload.executionMode || payload.selectionId || payload.mode || payload.label,
    );
    const runtimeProfile =
      executionMode === STUDIO_MODE_AGENT
        ? STUDIO_AGENT_RUNTIME_PROFILE
        : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
    studioRuntimeProjection.executionMode = executionMode;
    studioRuntimeProjection.runtimeProfile = runtimeProfile;
    if (
      studioRuntimeProjection.threadId &&
      (previousMode !== executionMode || previousRuntimeProfile !== runtimeProfile)
    ) {
      resetStudioDaemonThreadProjection();
    }
    return { executionMode, runtimeProfile };
  }

  function studioRunResultText({ prompt, run, conversation }) {
    const assistantTurn = array(conversation)
      .slice()
      .reverse()
      .find((item) => String(item?.role || item?.type || "").toLowerCase() === "assistant");
    const content =
      assistantTurn?.content ||
      assistantTurn?.text ||
      assistantTurn?.message ||
      run?.result ||
      run?.output ||
      null;
    if (content) {
      return String(content);
    }
    return `Daemon turn completed for: ${prompt}`;
  }

  async function ensureStudioDaemonThread({
    model = "route.local-first",
    selectedModelId = "auto",
    executionMode = getStudioRuntimeProjection().executionMode,
    reasoningEffort = getStudioRuntimeProjection().reasoningEffort || "none",
    approvalMode = getStudioRuntimeProjection().approvalMode,
    intentFrame = null,
  } = {}, output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const endpoint = daemonEndpoint();
    if (!endpoint) {
      throw new Error("IOI daemon endpoint is not configured.");
    }
    const normalizedMode = normalizeStudioExecutionMode(executionMode);
    const permissionMapping = studioPermissionDaemonMapping(approvalMode);
    const runtimeProfile = normalizedMode === STUDIO_MODE_AGENT
      ? STUDIO_AGENT_RUNTIME_PROFILE
      : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
    if (
      studioRuntimeProjection.threadId &&
      studioRuntimeProjection.executionMode &&
      normalizeStudioExecutionMode(studioRuntimeProjection.executionMode) !== normalizedMode
    ) {
      resetStudioDaemonThreadProjection();
    }
    if (
      studioRuntimeProjection.threadId &&
      studioRuntimeProjection.runtimeProfile &&
      studioRuntimeProjection.runtimeProfile !== runtimeProfile
    ) {
      resetStudioDaemonThreadProjection();
    }
    if (studioRuntimeProjection.threadId) {
      return studioRuntimeProjection;
    }
    const workspace = workspaceSummary();
    const thread = await requestJson(endpoint, "/v1/threads", {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        threadMode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        thread_mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
        approvalMode: permissionMapping.approvalMode,
        approval_mode: permissionMapping.approvalMode,
        runtime_profile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
        runtimeProfile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
        options: {
          mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          threadMode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          thread_mode: normalizedMode === STUDIO_MODE_AGENT ? permissionMapping.threadMode : STUDIO_MODE_AGENT,
          approvalMode: permissionMapping.approvalMode,
          approval_mode: permissionMapping.approvalMode,
          runtime_profile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
          runtimeProfile: normalizedMode === STUDIO_MODE_AGENT ? STUDIO_AGENT_RUNTIME_PROFILE : "fixture",
          local: {
            cwd: workspace.path,
          },
          model: {
            id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId,
            routeId: model || "route.local-first",
            reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
          },
          ...(intentFrame ? { intentFrame: studioIntentFramePayload(intentFrame) } : {}),
          source: normalizedMode === STUDIO_MODE_AGENT ? "agent-studio-agent-mode" : "agent-studio-ask-mode",
        },
      },
    });
    studioRuntimeProjection.threadId = thread?.thread_id || thread?.threadId || null;
    studioRuntimeProjection.sessionId =
      thread?.session_id || thread?.sessionId || studioRuntimeProjection.threadId || null;
    studioRuntimeProjection.modelRoute = thread?.model_route_id || thread?.modelRouteId || model;
    studioRuntimeProjection.selectedModel = thread?.selected_model || thread?.selectedModel || "auto";
    studioRuntimeProjection.reasoningEffort = normalizeStudioReasoningEffort(reasoningEffort, "none");
    studioRuntimeProjection.approvalMode = permissionMapping.approvalMode;
    studioRuntimeProjection.executionMode = normalizedMode;
    studioRuntimeProjection.runtimeProfile = runtimeProfile;
    studioRuntimeProjection.status = "active";
    studioRuntimeProjection.history = [
      {
        id: studioRuntimeProjection.threadId || "studio-thread",
        title: "Daemon Studio session",
        status: thread?.status || "active",
      },
    ];
    studioRuntimeProjection.timeline.push({
      label: "Daemon session created",
      detail: studioRuntimeProjection.threadId || "thread pending",
      status: "completed",
    });
    appendStudioReceipts(
      unique([thread?.model_route_receipt_id, thread?.modelRouteReceiptId]).map((id) => ({
        id,
        kind: "model_route",
        summary: "Daemon selected the Studio model route.",
      })),
    );
    output?.appendLine?.(`[ioi-studio] daemon session ready: ${studioRuntimeProjection.threadId}`);
    return studioRuntimeProjection;
  }

  async function applyStudioPermissionModeSelection(payload = {}, output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const approvalMode = normalizeStudioPermissionMode(
      payload.approvalMode || payload.approval_mode || payload.selectionId || payload.mode || payload.label,
    );
    const mapping = studioPermissionDaemonMapping(approvalMode);
    studioRuntimeProjection.approvalMode = approvalMode;
    if (!studioRuntimeProjection.threadId) {
      return mapping;
    }
    try {
      await requestJson(
        daemonEndpoint(),
        `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/mode`,
        {
          method: "POST",
          token: daemonRequestToken(),
          payload: {
            ...mapping,
            mode: mapping.threadMode,
            value: mapping.threadMode,
            source: "agent-studio-permissions-menu",
          },
        },
      );
    } catch (error) {
      output?.appendLine?.(`[ioi-studio] permission mode update unavailable: ${error?.message || String(error)}`);
    }
    return mapping;
  }

  return {
    applyStudioAgentModeSelection,
    applyStudioPermissionModeSelection,
    ensureStudioDaemonThread,
    studioRunResultText,
  };
}

module.exports = {
  createStudioThreadLifecycle,
};
