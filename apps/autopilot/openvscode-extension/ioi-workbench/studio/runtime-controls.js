"use strict";

function createStudioRuntimeControls({
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  getStudioRuntimeProjection,
  recomputeStudioRuntimeCockpitAchieved,
  refreshStudioPanelHtml,
  requestJson,
  writeBridgeRequest,
} = {}) {
  async function stopStudioTurn(output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = "interrupted";
    studioRuntimeProjection.timeline.push({
      label: "Stop requested",
      detail: "Operator stop routed from Studio control surface.",
      status: "blocked",
    });
    if (studioRuntimeProjection.threadId && studioRuntimeProjection.turnId) {
      await requestJson(
        daemonEndpoint(),
        `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/turns/${encodeURIComponent(studioRuntimeProjection.turnId)}/interrupt`,
        {
          method: "POST",
          token: daemonRequestToken(),
          payload: {
            source: "agent_studio",
            reason: "operator_stop",
            runtimeControlAction: "stop",
            runtime_control_action: "stop",
          },
        },
      ).then((result) => {
        appendStudioReceiptsFromResponse(result, "session_stop", "Daemon stopped Studio thread.");
        if (result?.runtime_control || result?.runtimeControl) {
          studioRuntimeProjection.runtimeCockpit.stopControlObserved = true;
          studioRuntimeProjection.runtimeCockpit.stopResumeObserved =
            studioRuntimeProjection.runtimeCockpit.resumeControlObserved === true;
          recomputeStudioRuntimeCockpitAchieved();
          appendStudioTimeline("Runtime stop control", "Daemon runtime_service control_thread stop acknowledged.", "completed");
        }
      }).catch((error) => {
        output?.appendLine?.(`[ioi-studio] stop projection unavailable: ${error?.message || String(error)}`);
      });
    }
    await writeBridgeRequest(
      "chat.stop",
      {
        threadId: studioRuntimeProjection.threadId,
        turnId: studioRuntimeProjection.turnId,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
        reason: "operator_stop",
        ownsRuntimeState: false,
      },
      buildWorkspaceActionContext("agent-studio-stop"),
    ).catch((error) => {
      output?.appendLine?.(`[ioi-studio] bridge stop route unavailable: ${error?.message || String(error)}`);
    });
    await refreshStudioPanelHtml(output);
  }

  async function resumeStudioTurn(output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    studioRuntimeProjection.status = "active";
    recomputeStudioRuntimeCockpitAchieved();
    appendStudioTimeline("Resume requested", "Operator resume routed to daemon session lifecycle.", "completed");
    if (studioRuntimeProjection.threadId) {
      await requestJson(
        daemonEndpoint(),
        `/v1/threads/${encodeURIComponent(studioRuntimeProjection.threadId)}/resume`,
        {
          method: "POST",
          token: daemonRequestToken(),
          payload: {
            source: "agent_studio",
            reason: "operator_resume",
          },
        },
      ).then((result) => {
        appendStudioReceiptsFromResponse(result, "session_resume", "Daemon resumed Studio thread.");
        if (result?.runtime_control || result?.runtimeControl) {
          studioRuntimeProjection.runtimeCockpit.resumeControlObserved = true;
          studioRuntimeProjection.runtimeCockpit.stopResumeObserved =
            studioRuntimeProjection.runtimeCockpit.stopControlObserved === true;
          recomputeStudioRuntimeCockpitAchieved();
          appendStudioTimeline("Runtime resume control", "Daemon runtime_service control_thread resume acknowledged.", "completed");
        }
      }).catch((error) => {
        appendStudioTimeline("Resume projection unavailable", error?.message || String(error), "blocked");
        output?.appendLine?.(`[ioi-studio] resume projection unavailable: ${error?.message || String(error)}`);
      });
    }
    await writeBridgeRequest(
      "chat.resume",
      {
        threadId: studioRuntimeProjection.threadId,
        turnId: studioRuntimeProjection.turnId,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
        reason: "operator_resume",
        ownsRuntimeState: false,
      },
      buildWorkspaceActionContext("agent-studio-resume"),
    ).catch((error) => {
      output?.appendLine?.(`[ioi-studio] bridge resume route unavailable: ${error?.message || String(error)}`);
    });
    studioRuntimeProjection.status = "completed";
    await refreshStudioPanelHtml(output);
  }

  return {
    resumeStudioTurn,
    stopStudioTurn,
  };
}

module.exports = {
  createStudioRuntimeControls,
};
