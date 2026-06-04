"use strict";

const STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY = "trajectory_replay_side_effect";

function createStudioDurabilityPanels({
  firstArray,
  normalizeReceiptRefs,
  stringValue,
  studioRuntimeEventKind,
  uniqueStrings,
  workspacePath,
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

  return {
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
