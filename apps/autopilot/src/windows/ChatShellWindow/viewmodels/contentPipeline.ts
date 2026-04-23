import type {
  ActivityEventRef,
  AgentEvent,
  Artifact,
  ChatMessage,
  RunPresentation,
} from "../../../types";
import { buildSessionRunPresentation } from "@ioi/agent-ide";
import {
  classifyActivityEvent,
  buildSemanticDedupKey,
} from "./contentPipeline.classification";
import {
  eventOutput,
  eventToolName,
  hashString,
  normalizeOutputForHash,
} from "./contentPipeline.helpers";
import { latestPrompt, resolveFinalAnswer } from "./contentPipeline.answers";
import {
  buildActivityGroups,
  buildActivitySummary,
  buildPlanSummary,
  buildSourceSummary,
  buildThoughtSummary,
  collectArtifactRefs,
} from "./contentPipeline.summaries";

export { classifyActivityEvent } from "./contentPipeline.classification";
export { normalizeOutputForHash } from "./contentPipeline.helpers";

export function buildRunPresentation(
  history: ChatMessage[],
  events: AgentEvent[],
  artifacts: Artifact[],
): RunPresentation {
  return buildSessionRunPresentation<
    ChatMessage,
    AgentEvent,
    Artifact,
    ActivityEventRef["kind"],
    ChatMessage,
    RunPresentation["finalAnswer"],
    RunPresentation["sourceSummary"],
    RunPresentation["thoughtSummary"],
    RunPresentation["planSummary"],
    RunPresentation["activitySummary"],
    RunPresentation["activityGroups"][number],
    RunPresentation["artifactRefs"][number]
  >({
    history,
    events,
    artifacts,
    classifyActivityEvent,
    buildSemanticDedupKey,
    eventToolName,
    eventOutput,
    normalizeOutputForHash,
    hashString,
    latestPrompt,
    resolveFinalAnswer,
    buildSourceSummary,
    buildThoughtSummary,
    buildPlanSummary,
    buildActivityGroups,
    buildActivitySummary,
    collectArtifactRefs,
  });
}
