export const WORKFLOW_COMPUTER_USE_REPLAY_TIMELINE_SCHEMA_VERSION =
  "ioi.workflow.computer-use-replay-timeline.v1" as const;

export interface WorkflowComputerUseReplayTimelineOptions {
  workflowGraphId?: string | null;
  lane?: string | null;
}

export interface WorkflowComputerUseReplayFrame {
  frameId: string;
  index: number;
  eventId: string | null;
  eventSeq: number | null;
  eventKind: string;
  lane: string | null;
  step: string | null;
  label: string;
  threadId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  observationRef: string | null;
  screenshotRef: string | null;
  somRef: string | null;
  axRef: string | null;
  targetIndexRef: string | null;
  affordanceGraphRef: string | null;
  proposalRef: string | null;
  actionRef: string | null;
  verificationRef: string | null;
  commitGateRef: string | null;
  trajectoryRef: string | null;
  cleanupRef: string | null;
  targetCount: number;
  affordanceCount: number;
  policyDecisionRef: string | null;
  displayMode: "artifact_ref_only" | "state_only";
  redaction: string;
  sourceHadRawScreenshot: boolean;
  receiptRefs: string[];
  policyDecisionRefs: string[];
  artifactRefs: string[];
}

export interface WorkflowComputerUseReplayTimeline {
  schemaVersion: typeof WORKFLOW_COMPUTER_USE_REPLAY_TIMELINE_SCHEMA_VERSION;
  status: "empty" | "ready";
  frameCount: number;
  lanes: string[];
  eventIds: string[];
  screenshotRefs: string[];
  targetIndexRefs: string[];
  affordanceGraphRefs: string[];
  replayRange: {
    firstSeq: number | null;
    lastSeq: number | null;
  };
  scrubber: {
    scrubbable: boolean;
    frameIds: string[];
    displayMode: "artifact_ref_only";
    rawScreenshotBytesIncluded: false;
  };
  frames: WorkflowComputerUseReplayFrame[];
}

type RuntimeEventInput = Record<string, unknown>;

export function buildWorkflowComputerUseReplayTimeline(
  events: readonly RuntimeEventInput[],
  options: WorkflowComputerUseReplayTimelineOptions = {},
): WorkflowComputerUseReplayTimeline {
  const graphFilter = cleanString(options.workflowGraphId);
  const laneFilter = cleanString(options.lane);
  const frames = [...events]
    .filter(isComputerUseEvent)
    .filter((event) => {
      const payload = eventPayload(event);
      const graphId = eventWorkflowGraphId(event) ?? stringField(payload, "workflow_graph_id");
      const lane = computerUseLane(payload);
      return (!graphFilter || !graphId || graphId === graphFilter) && (!laneFilter || !lane || lane === laneFilter);
    })
    .sort((left, right) => (eventSeq(left) ?? 0) - (eventSeq(right) ?? 0))
    .map((event, index) => replayFrameForEvent(event, index));
  return {
    schemaVersion: WORKFLOW_COMPUTER_USE_REPLAY_TIMELINE_SCHEMA_VERSION,
    status: frames.length > 0 ? "ready" : "empty",
    frameCount: frames.length,
    lanes: uniqueStrings(frames.map((frame) => frame.lane)),
    eventIds: uniqueStrings(frames.map((frame) => frame.eventId)),
    screenshotRefs: uniqueStrings(frames.map((frame) => frame.screenshotRef)),
    targetIndexRefs: uniqueStrings(frames.map((frame) => frame.targetIndexRef)),
    affordanceGraphRefs: uniqueStrings(frames.map((frame) => frame.affordanceGraphRef)),
    replayRange: {
      firstSeq: frames[0]?.eventSeq ?? null,
      lastSeq: frames[frames.length - 1]?.eventSeq ?? null,
    },
    scrubber: {
      scrubbable: frames.some((frame) => Boolean(frame.screenshotRef || frame.observationRef)),
      frameIds: frames.map((frame) => frame.frameId),
      displayMode: "artifact_ref_only",
      rawScreenshotBytesIncluded: false,
    },
    frames,
  };
}

function replayFrameForEvent(event: RuntimeEventInput, index: number): WorkflowComputerUseReplayFrame {
  const payload = eventPayload(event);
  const observation = objectField(payload, "observation_bundle");
  const targetIndex = objectField(payload, "target_index");
  const affordanceGraph = objectField(payload, "affordance_graph");
  const eventKind = eventKindForEvent(event);
  const step = stringField(payload, "computer_use_step") ?? stepForEventKind(eventKind);
  const lane = computerUseLane(payload);
  const screenshotRef =
    stringField(observation, "screenshot_ref") ??
    stringField(payload, "computer_use_screen_ref", "screenshot_ref");
  const somRef =
    stringField(observation, "som_ref") ??
    stringField(payload, "computer_use_som_ref", "som_ref");
  const axRef =
    stringField(observation, "ax_ref") ??
    stringField(payload, "computer_use_ax_ref", "ax_ref");
  const targetIndexRef =
    stringField(payload, "computer_use_target_index_ref") ??
    stringField(observation, "target_index_ref") ??
    stringField(targetIndex, "target_index_ref");
  const affordanceGraphRef =
    stringField(payload, "computer_use_affordance_graph_ref") ??
    stringField(affordanceGraph, "graph_ref");
  const targetCount =
    arrayField(targetIndex, "targets").length ||
    arrayField(observation, "targets").length ||
    arrayField(payload, "targets").length;
  const affordanceCount =
    arrayField(affordanceGraph, "affordances").length ||
    arrayField(payload, "affordances").length;
  const eventId = eventIdForEvent(event);
  const seqValue = eventSeq(event);
  return {
    frameId: `computer-use-frame-${String(index + 1).padStart(3, "0")}`,
    index,
    eventId,
    eventSeq: seqValue,
    eventKind,
    lane,
    step,
    label: labelForStep(step, eventKind),
    threadId: eventThreadId(event),
    workflowGraphId: eventWorkflowGraphId(event),
    workflowNodeId: eventWorkflowNodeId(event),
    observationRef:
      stringField(payload, "computer_use_observation_ref") ??
      stringField(observation, "observation_ref"),
    screenshotRef,
    somRef,
    axRef,
    targetIndexRef,
    affordanceGraphRef,
    proposalRef: stringField(payload, "computer_use_proposal_ref"),
    actionRef: stringField(payload, "computer_use_action_ref"),
    verificationRef: stringField(payload, "computer_use_verification_ref"),
    commitGateRef: stringField(payload, "computer_use_commit_gate_ref"),
    trajectoryRef: stringField(payload, "computer_use_trajectory_ref"),
    cleanupRef: stringField(payload, "computer_use_cleanup_ref"),
    targetCount,
    affordanceCount,
    policyDecisionRef: stringField(payload, "computer_use_policy_decision_ref"),
    displayMode: screenshotRef || somRef || axRef ? "artifact_ref_only" : "state_only",
    redaction: stringField(payload, "redaction") ?? "computer_use_trace_safe",
    sourceHadRawScreenshot: hasRawScreenshotPayload(payload),
    receiptRefs: uniqueStrings([
      ...arrayField(event, "receipt_refs"),
      ...arrayField(payload, "receipt_refs"),
    ]),
    policyDecisionRefs: uniqueStrings([
      ...arrayField(event, "policy_decision_refs"),
      ...arrayField(payload, "policy_decision_refs"),
      stringField(payload, "computer_use_policy_decision_ref"),
    ]),
    artifactRefs: uniqueStrings([
      ...arrayField(event, "artifact_refs"),
      screenshotRef,
      somRef,
      axRef,
    ]),
  };
}

function isComputerUseEvent(event: RuntimeEventInput): boolean {
  const kind = eventKindForEvent(event);
  const payload = eventPayload(event);
  const payloadKind = stringField(payload, "event_kind");
  return kind.startsWith("computer_use.") || (payloadKind?.startsWith("computer_use.") ?? false);
}

function eventPayload(event: RuntimeEventInput): Record<string, unknown> {
  return objectField(event, "payload_summary", "payload") ?? {};
}

function computerUseLane(payload: Record<string, unknown>): string | null {
  const observation = objectField(payload, "observation_bundle");
  return (
    stringField(payload, "computer_use_lane") ??
    stringField(observation, "lane") ??
    stringField(payload, "lane")
  );
}

function hasRawScreenshotPayload(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  for (const [key, child] of Object.entries(record)) {
    const normalizedKey = key.toLowerCase();
    if (
      normalizedKey.includes("screenshotbase64") ||
      normalizedKey.includes("screenshot_base64") ||
      normalizedKey === "screenshot" ||
      normalizedKey === "image_base64"
    ) {
      return typeof child === "string" && child.length > 0;
    }
    if (hasRawScreenshotPayload(child)) return true;
  }
  return false;
}

function stepForEventKind(eventKind: string): string | null {
  return eventKind.startsWith("computer_use.") ? eventKind.slice("computer_use.".length) : null;
}

function labelForStep(step: string | null, eventKind: string): string {
  switch (step) {
    case "select_environment":
      return "Select environment";
    case "observe":
    case "observation":
      return "Observe screen";
    case "build_affordance_graph":
    case "affordance_graph":
      return "Build affordance graph";
    case "propose_action":
    case "action_proposed":
      return "Propose action";
    case "commit_or_handoff":
    case "commit_gate":
      return "Commit gate";
    case "execute_action":
    case "action_executed":
      return "Execute action";
    case "verify_postcondition":
    case "verification":
      return "Verify postcondition";
    case "write_trajectory":
    case "trajectory_written":
      return "Write trajectory";
    case "cleanup":
      return "Cleanup";
    default:
      return eventKind || "Computer-use event";
  }
}

function eventIdForEvent(event: RuntimeEventInput): string | null {
  return stringField(event, "event_id");
}

function eventKindForEvent(event: RuntimeEventInput): string {
  return stringField(event, "event_kind") ?? "";
}

function eventSeq(event: RuntimeEventInput): number | null {
  return numberField(event, "seq");
}

function eventThreadId(event: RuntimeEventInput): string | null {
  return stringField(event, "thread_id");
}

function eventWorkflowGraphId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflow_graph_id");
}

function eventWorkflowNodeId(event: RuntimeEventInput): string | null {
  return stringField(event, "workflow_node_id");
}

function objectField(record: unknown, ...keys: string[]): Record<string, unknown> | null {
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  for (const key of keys) {
    const value = (record as Record<string, unknown>)[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  }
  return null;
}

function stringField(record: unknown, ...keys: string[]): string | null {
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  for (const key of keys) {
    const value = (record as Record<string, unknown>)[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return null;
}

function numberField(record: unknown, ...keys: string[]): number | null {
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  for (const key of keys) {
    const value = (record as Record<string, unknown>)[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return null;
}

function arrayField(record: unknown, ...keys: string[]): unknown[] {
  if (!record || typeof record !== "object" || Array.isArray(record)) return [];
  for (const key of keys) {
    const value = (record as Record<string, unknown>)[key];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function cleanString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(values.map((value) => cleanString(value)).filter((value): value is string => Boolean(value))),
  );
}
