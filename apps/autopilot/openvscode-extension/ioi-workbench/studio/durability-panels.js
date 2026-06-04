"use strict";

const STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY = "trajectory_replay_side_effect";

function createStudioDurabilityPanels({
  buildWorkspaceActionContext,
  daemonEndpoint,
  daemonRequestToken,
  fetchStudioThreadEvents,
  firstArray,
  getStudioRuntimeProjection,
  normalizeReceiptRefs,
  requestJson,
  stringValue,
  studioMaxRuntimeEventSeq,
  studioRuntimeEventKind,
  uniqueStrings,
  workspaceSummary,
  workspacePath,
  writeBridgeRequest,
} = {}) {
  const array = typeof firstArray === "function" ? firstArray : (value) => (Array.isArray(value) ? value : []);
  const receipts = typeof normalizeReceiptRefs === "function" ? normalizeReceiptRefs : () => [];
  const text = typeof stringValue === "function" ? stringValue : (value, fallback = "") => {
    if (typeof value === "string") return value;
    if (value === null || value === undefined) return fallback;
    return String(value);
  };
  const eventKind = typeof studioRuntimeEventKind === "function"
    ? studioRuntimeEventKind
    : (event = {}) => text(event.kind || event.type, "runtime.event");
  const unique = typeof uniqueStrings === "function"
    ? uniqueStrings
    : (values = []) => [...new Set(array(values).filter((value) => typeof value === "string" && value.length > 0))];
  const workspace = typeof workspacePath === "function" ? workspacePath : () => "";

  function studioSessionBrainArtifactKind(memoryKey) {
    const key = String(memoryKey || "").toLowerCase();
    if (/^(implementation[_-]?plan|plan)([./:-]|$)/.test(key)) return "implementation_plan";
    if (/^(task|checklist)([./:-]|$)/.test(key)) return "task";
    if (/^(walkthrough|verification[_-]?summary|summary)([./:-]|$)/.test(key)) return "walkthrough";
    if (/^scratch([./:-]|$)/.test(key)) return "scratch";
    return null;
  }

  function studioMemoryRecordReceiptRefs(events, recordId) {
    if (!recordId) return [];
    const refs = [];
    for (const event of array(events)) {
      let eventText = "";
      try {
        eventText = JSON.stringify(event);
      } catch {
        eventText = "";
      }
      if (!eventText.includes(recordId)) continue;
      refs.push(...receipts(event, event?.data, event?.data?.payload, event?.payload, event?.payload_summary));
    }
    return unique(refs);
  }

  function studioSessionBrainPanelFromProjection({
    memoryProjection = {},
    memoryPath = {},
    events = [],
    lateWriteBlocked = false,
    replayCursor = 0,
    completionReceiptRefs = [],
  } = {}) {
    const paths = {
      ...(memoryProjection?.paths && typeof memoryProjection.paths === "object" ? memoryProjection.paths : {}),
      ...(memoryPath && typeof memoryPath === "object" ? memoryPath : {}),
    };
    const policy = memoryProjection?.policy && typeof memoryProjection.policy === "object" ? memoryProjection.policy : {};
    const workspaceRoot = text(memoryProjection?.workspace || paths.workspace || workspace(), "");
    const brainRoot = text(paths.recordsPath || paths.brainRoot || "", "");
    const normalizedWorkspace = workspaceRoot.replace(/\/+$/, "");
    const normalizedBrainRoot = brainRoot.replace(/\/+$/, "");
    const rows = array(memoryProjection?.records)
      .map((record, index) => {
        const memoryKey = text(record?.memoryKey || record?.memory_key, "");
        const artifactKind = studioSessionBrainArtifactKind(memoryKey);
        if (!artifactKind) return null;
        const recordId = text(record?.id || record?.recordId || record?.record_id, `memory-record-${index}`);
        const receiptRefs = unique([
          ...receipts(record),
          ...studioMemoryRecordReceiptRefs(events, recordId),
        ]);
        return {
          id: `session-brain-${artifactKind}-${index}`,
          artifactKind,
          label:
            artifactKind === "implementation_plan"
              ? "Implementation plan"
              : artifactKind === "task"
                ? "Task checklist"
                : artifactKind === "walkthrough"
                  ? "Walkthrough"
                  : "Scratch",
          status: "present",
          preview: text(record?.fact || record?.text || "", "").replace(/\s+/g, " ").trim().slice(0, 180),
          receiptRefs,
          artifactRefs: unique([recordId, ...array(record?.evidenceRefs || record?.evidence_refs)]),
        };
      })
      .filter(Boolean);
    const artifactKinds = new Set(rows.map((row) => row.artifactKind));
    const artifactRefs = unique(rows.flatMap((row) => row.artifactRefs));
    const receiptRefs = unique([
      ...rows.flatMap((row) => row.receiptRefs),
      ...array(completionReceiptRefs),
    ]);
    const hasRequiredArtifacts =
      artifactKinds.has("implementation_plan") &&
      artifactKinds.has("task") &&
      artifactKinds.has("walkthrough") &&
      artifactKinds.has("scratch");
    return {
      id: "session-brain.current",
      kind: "session.brain",
      status: hasRequiredArtifacts && lateWriteBlocked ? "ready" : "blocked",
      detail: "Plan, task checklist, walkthrough, scratch refs, artifact refs, and replay cursor are available.",
      artifactCount: rows.length,
      scratchCount: rows.filter((row) => row.artifactKind === "scratch").length,
      hasImplementationPlan: artifactKinds.has("implementation_plan"),
      hasTaskChecklist: artifactKinds.has("task"),
      hasWalkthrough: artifactKinds.has("walkthrough"),
      hasScratchRefs: rows.some((row) => row.artifactKind === "scratch"),
      hasArtifactRefs: artifactRefs.length > 0,
      hasReplayCursor: Number(replayCursor) > 0,
      brainOutsideWorkspace:
        Boolean(normalizedBrainRoot && normalizedWorkspace) &&
        normalizedBrainRoot !== normalizedWorkspace &&
        !normalizedBrainRoot.startsWith(`${normalizedWorkspace}/`),
      readOnlyAuditMode: policy.readOnly === true || policy.read_only === true,
      lateWriteBlocked,
      rows,
      receiptRefs,
    };
  }

  function studioTrajectoryReplayArrayEquals(left = [], right = []) {
    const leftItems = array(left).map((item) => String(item));
    const rightItems = array(right).map((item) => String(item));
    return leftItems.length === rightItems.length && leftItems.every((item, index) => item === rightItems[index]);
  }

  function studioTrajectoryReplayRowsFromEvents(events = []) {
    return array(events)
      .filter((event) => {
        const kind = eventKind(event).toLowerCase();
        return /^(thread\.started|memory\.write|memory\.policy|turn\.(started|completed))$/.test(kind);
      })
      .map((event, index) => {
        const kind = eventKind(event) || "runtime.event";
        const seq = Number(event?.seq || 0);
        const safeStepId = seq > 0 ? `trajectory-replay.step-${seq}` : `trajectory-replay.step-${index + 1}`;
        const lowerKind = kind.toLowerCase();
        return {
          id: safeStepId,
          kind,
          status: text(event?.status || event?.payload_summary?.status, "observed"),
          summary: /memory\.write/.test(lowerKind)
            ? "Side-effect memory write recorded once."
            : /thread\.started/.test(lowerKind)
              ? "Daemon trajectory restored for Studio replay."
              : "Durable runtime step restored for Studio replay.",
          receiptRefs: receipts(event),
        };
      });
  }

  function studioTrajectoryReplayPanelFromProjection({
    phase = "create",
    threadId = "",
    expectedThreadId = "",
    events = [],
    eventsSinceCursor = [],
    memoryProjection = {},
    expectedReplayIds = [],
    replayCursor = 0,
  } = {}) {
    const rows = studioTrajectoryReplayRowsFromEvents(events);
    const replayIds = rows.map((row) => row.id);
    const records = array(memoryProjection?.records);
    const sideEffectRecords = records.filter((record) =>
      text(record?.memoryKey || record?.memory_key, "") === STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY
    );
    const sideEffectCount = sideEffectRecords.length;
    const duplicateSideEffectCount = Math.max(0, sideEffectCount - 1);
    const replayIdsStable = expectedReplayIds.length > 0
      ? studioTrajectoryReplayArrayEquals(replayIds, expectedReplayIds)
      : replayIds.length > 0;
    const trajectoryIdStable = expectedThreadId ? expectedThreadId === threadId : Boolean(threadId);
    const replayFromCursorEmpty = array(eventsSinceCursor).length === 0;
    const receiptRefs = unique(rows.flatMap((row) => receipts(row)));
    const status =
      trajectoryIdStable &&
      replayIdsStable &&
      replayFromCursorEmpty &&
      replayCursor > 0 &&
      sideEffectCount === 1 &&
      duplicateSideEffectCount === 0
        ? "ready"
        : "blocked";
    return {
      id: "trajectory-replay.current",
      kind: "trajectory.replay",
      status,
      detail:
        phase === "reconnect"
          ? "GUI reconnect restored the same daemon-owned trajectory without replaying the side effect."
          : "Daemon-owned trajectory replay cursor captured before GUI reconnect.",
      trajectoryIdStable,
      replayCursorObserved: replayCursor > 0,
      guiReconnected: phase === "reconnect",
      replayIdsStable,
      replayFromCursorEmpty,
      sideEffectCount,
      duplicateSideEffectCount,
      rows,
      replayIds,
      receiptRefs,
    };
  }

  async function exerciseStudioTrajectoryReplayReconnect(output, payload = {}) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const phase = payload?.phase === "reconnect" ? "reconnect" : "create";
    const contextSnapshot = buildWorkspaceActionContext(`studio-trajectory-replay-${phase}`);
    let threadId = text(payload?.threadId || payload?.thread_id, "");
    let sideEffectWriteAttempted = false;
    if (!threadId) {
      const workspace = workspaceSummary();
      const thread = await requestJson(daemonEndpoint(), "/v1/threads", {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_trajectory_replay_reconnect",
          goal: "Prove Agent Studio can reload daemon-owned trajectory state without duplicating side effects.",
          options: {
            local: { cwd: workspace.path },
            model: { id: studioRuntimeProjection.selectedModel || "auto", routeId: studioRuntimeProjection.modelRoute || "route.local-first" },
          },
        },
      });
      threadId = thread.thread_id || thread.threadId || thread.id;
    }
    if (!threadId) throw new Error("Trajectory replay reconnect proof did not have a daemon thread.");
    studioRuntimeProjection.threadId = threadId;

    if (phase === "create") {
      sideEffectWriteAttempted = true;
      await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_trajectory_replay_reconnect",
          text: "Trajectory replay proof side effect. This record must exist exactly once after GUI reconnect.",
          memoryKey: STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY,
          scope: "thread",
          workflowGraphId: "workflow.agent-studio.trajectory-replay",
          workflowNodeId: "runtime.trajectory-replay.side-effect",
        },
      });
    }

    const memoryProjection = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "GET",
      token: daemonRequestToken(),
    });
    const events = await fetchStudioThreadEvents(threadId, output, {
      sinceSeq: 0,
      timeoutMs: 2500,
    });
    const replayCursor = studioMaxRuntimeEventSeq(events);
    const eventsSinceCursor = await fetchStudioThreadEvents(threadId, output, {
      sinceSeq: replayCursor,
      timeoutMs: 800,
    });
    const panel = studioTrajectoryReplayPanelFromProjection({
      phase,
      threadId,
      expectedThreadId: text(payload?.expectedThreadId || payload?.expected_thread_id, ""),
      events,
      eventsSinceCursor,
      memoryProjection,
      expectedReplayIds: array(payload?.expectedReplayIds || payload?.expected_replay_ids),
      replayCursor,
    });
    studioRuntimeProjection.trajectoryReplayPanels.push(panel);
    if (phase === "reconnect") {
      studioRuntimeProjection.engineReconnectBanners.push({
        id: "trajectory-replay.engine-reconnect",
        kind: "engine.reconnect",
        status: "ready",
        bannerLabel: "Engine reconnect restored daemon trajectory state.",
        composerFrozen: false,
        receiptRefs: panel.receiptRefs,
      });
    }
    studioRuntimeProjection.replaySteps = panel.rows.map((row) => ({
      id: row.id,
      kind: row.kind,
      status: row.status,
      summary: row.summary,
    }));
    studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
      studioRuntimeProjection.replaySteps.length > 0;
    studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
      panel.receiptRefs.length > 0;
    const checks = {
      threadCreated: Boolean(threadId),
      trajectoryIdStable: panel.trajectoryIdStable,
      replayCursorObserved: panel.replayCursorObserved,
      replayRowsObserved: panel.rows.length > 0,
      replayIdsStable: panel.replayIdsStable,
      replayFromCursorEmpty: panel.replayFromCursorEmpty,
      sideEffectRecordedOnce: panel.sideEffectCount === 1,
      duplicateSideEffectsAbsent: panel.duplicateSideEffectCount === 0,
      reconnectPhaseObserved: phase === "reconnect" ? panel.guiReconnected : true,
    };
    const passed = Object.values(checks).every(Boolean);
    await writeBridgeRequest("studio.trajectoryReplayReconnect.exercised", {
      sourceCommand: "ioi.studio.exerciseTrajectoryReplayReconnect",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "openvscode-workbench-adapter",
      ownsRuntimeState: false,
      phase,
      threadId,
      passed,
      checks,
      replayCursor,
      replayIds: panel.replayIds,
      eventCount: events.length,
      eventsSinceCursorCount: eventsSinceCursor.length,
      sideEffectRecordCount: panel.sideEffectCount,
      duplicateSideEffectCount: panel.duplicateSideEffectCount,
      sideEffectWriteAttempted,
    }, contextSnapshot).catch((error) => {
      output.appendLine(`[ioi-studio] trajectory replay reconnect bridge request unavailable: ${error?.message || String(error)}`);
    });
    return {
      passed,
      phase,
      threadId,
      replayCursor,
      replayIds: panel.replayIds,
      eventCount: events.length,
      eventsSinceCursorCount: eventsSinceCursor.length,
      checks,
      panel: {
        status: panel.status,
        sideEffectCount: panel.sideEffectCount,
        duplicateSideEffectCount: panel.duplicateSideEffectCount,
        replayRows: panel.rows.length,
        replayIdsStable: panel.replayIdsStable,
        guiReconnected: panel.guiReconnected,
      },
    };
  }

  async function exerciseStudioSessionBrainLifecycle(output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    const workspace = workspaceSummary();
    const contextSnapshot = buildWorkspaceActionContext("studio-session-brain-lifecycle");
    const thread = await requestJson(daemonEndpoint(), "/v1/threads", {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_session_brain_lifecycle",
        goal: "Prove Agent Studio run brain artifacts are daemon-owned, replayable, and product-safe.",
        options: {
          local: { cwd: workspace.path },
          model: { id: studioRuntimeProjection.selectedModel || "auto", routeId: studioRuntimeProjection.modelRoute || "route.local-first" },
        },
      },
    });
    const threadId = thread.thread_id || thread.threadId || thread.id;
    if (!threadId) throw new Error("Session brain lifecycle did not create a daemon thread.");
    studioRuntimeProjection.threadId = threadId;

    const artifacts = [
      {
        memoryKey: "implementation_plan",
        text: "# Implementation Plan\n\n- Prove Agent Studio renders daemon-owned run brain artifacts.",
        workflowNodeId: "runtime.session-brain.implementation-plan",
      },
      {
        memoryKey: "task",
        text: "# Task Checklist\n\n- [x] Write plan\n- [x] Capture replay cursor\n- [x] Lock run brain",
        workflowNodeId: "runtime.session-brain.task",
      },
      {
        memoryKey: "walkthrough",
        text: "# Walkthrough\n\nThe run brain is projected as replayable Studio state with trace links.",
        workflowNodeId: "runtime.session-brain.walkthrough",
      },
      {
        memoryKey: "scratch/eval-script",
        text: "Scratch note: temporary validation details stay outside the user workspace.",
        workflowNodeId: "runtime.session-brain.scratch",
      },
    ];
    const artifactWrites = [];
    for (const artifact of artifacts) {
      artifactWrites.push(await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_session_brain_lifecycle",
          text: artifact.text,
          memoryKey: artifact.memoryKey,
          scope: "thread",
          workflowGraphId: "workflow.agent-studio.session-brain",
          workflowNodeId: artifact.workflowNodeId,
        },
      }));
    }
    const readOnlyPolicy = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory/policy`, {
      method: "PATCH",
      token: daemonRequestToken(),
      payload: {
        readOnly: true,
        retention: "persistent",
        source: "agent_studio_session_brain_completion_audit_lock",
      },
    });
    let lateWriteBlocked = false;
    let lateWriteReason = null;
    try {
      await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_session_brain_lifecycle",
          text: "This late write should be blocked by the audit lock.",
          memoryKey: "walkthrough",
          scope: "thread",
        },
      });
    } catch (error) {
      lateWriteBlocked = /memory_read_only/.test(String(error?.message || error));
      lateWriteReason = lateWriteBlocked ? "memory_read_only" : String(error?.message || error);
    }

    const memoryProjection = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "GET",
      token: daemonRequestToken(),
    });
    const memoryPath = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory/path`, {
      method: "GET",
      token: daemonRequestToken(),
    });
    const events = await fetchStudioThreadEvents(threadId, output, {
      sinceSeq: 0,
      timeoutMs: 2500,
    });
    const replayCursor = studioMaxRuntimeEventSeq(events);
    const panel = studioSessionBrainPanelFromProjection({
      memoryProjection,
      memoryPath,
      events,
      lateWriteBlocked,
      replayCursor,
      completionReceiptRefs: receipts(readOnlyPolicy),
    });
    studioRuntimeProjection.sessionBrainPanels.push(panel);
    studioRuntimeProjection.replaySteps = [
      {
        id: "session-brain.thread-started",
        kind: "thread.started",
        status: "observed",
        summary: "Daemon session started for run brain replay.",
      },
      ...artifacts.map((artifact, index) => ({
        id: `session-brain.memory-write-${index + 1}`,
        kind: "memory.write",
        status: "observed",
        summary: `${artifact.memoryKey.replace(/[_/-]+/g, " ")} recorded in run brain memory.`,
      })),
      {
        id: "session-brain.audit-lock",
        kind: "memory.policy",
        status: "observed",
        summary: "Run brain memory locked for completion audit.",
      },
    ];
    studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
      studioRuntimeProjection.replaySteps.length > 0;
    studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
      array(panel.receiptRefs).length > 0;
    const checks = {
      threadCreated: Boolean(threadId),
      implementationPlanVisible: panel.hasImplementationPlan,
      taskChecklistVisible: panel.hasTaskChecklist,
      walkthroughVisible: panel.hasWalkthrough,
      scratchRefsVisible: panel.hasScratchRefs,
      artifactRefsVisible: panel.hasArtifactRefs,
      replayCursorVisible: panel.hasReplayCursor,
      brainRootOutsideWorkspace: panel.brainOutsideWorkspace,
      readOnlyAuditModeVisible: panel.readOnlyAuditMode,
      lateWriteBlocked,
      receiptsLinked: array(panel.receiptRefs).length > 0,
    };
    await writeBridgeRequest("studio.sessionBrainLifecycle.exercised", {
      sourceCommand: "ioi.studio.exerciseSessionBrainLifecycle",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "openvscode-workbench-adapter",
      ownsRuntimeState: false,
      passed: Object.values(checks).every(Boolean),
      checks,
      artifactWriteCount: artifactWrites.length,
      replayCursor,
      lateWriteReason,
    }, contextSnapshot).catch((error) => {
      output.appendLine(`[ioi-studio] session brain lifecycle bridge request unavailable: ${error?.message || String(error)}`);
    });
    return {
      passed: Object.values(checks).every(Boolean),
      checks,
      artifactWriteCount: artifactWrites.length,
      replayCursor,
      panel: {
        status: panel.status,
        artifactCount: panel.artifactCount,
        scratchCount: panel.scratchCount,
        hasImplementationPlan: panel.hasImplementationPlan,
        hasTaskChecklist: panel.hasTaskChecklist,
        hasWalkthrough: panel.hasWalkthrough,
        hasScratchRefs: panel.hasScratchRefs,
        hasArtifactRefs: panel.hasArtifactRefs,
        hasReplayCursor: panel.hasReplayCursor,
        brainOutsideWorkspace: panel.brainOutsideWorkspace,
        readOnlyAuditMode: panel.readOnlyAuditMode,
      },
    };
  }

  return {
    exerciseStudioSessionBrainLifecycle,
    exerciseStudioTrajectoryReplayReconnect,
    studioMemoryRecordReceiptRefs,
    studioSessionBrainArtifactKind,
    studioSessionBrainPanelFromProjection,
    studioTrajectoryReplayArrayEquals,
    studioTrajectoryReplayPanelFromProjection,
    studioTrajectoryReplayRowsFromEvents,
  };
}

module.exports = {
  STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY,
  createStudioDurabilityPanels,
};
