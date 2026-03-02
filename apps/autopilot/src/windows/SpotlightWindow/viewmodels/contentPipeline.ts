import type {
  ActivityEventRef,
  AgentEvent,
  Artifact,
  ChatMessage,
  RunPresentation,
} from "../../../types";
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

function dedupeActivityEvents(events: AgentEvent[]): ActivityEventRef[] {
  const deduped: ActivityEventRef[] = [];
  const seenKeys = new Set<string>();

  for (const event of events) {
    const kind = classifyActivityEvent(event);
    const toolName = eventToolName(event);
    const normalized = normalizeOutputForHash(eventOutput(event));
    const outputHash = normalized ? hashString(normalized) : undefined;
    const key = buildSemanticDedupKey(kind, event);

    if (seenKeys.has(key)) {
      continue;
    }
    seenKeys.add(key);

    deduped.push({
      key,
      event,
      kind,
      toolName,
      normalizedOutputHash: outputHash,
    });
  }

  return deduped;
}

export function buildRunPresentation(
  history: ChatMessage[],
  events: AgentEvent[],
  artifacts: Artifact[],
): RunPresentation {
  const deduped = dedupeActivityEvents(events);
  const activityGroups = buildActivityGroups(deduped);

  return {
    prompt: latestPrompt(history),
    finalAnswer: resolveFinalAnswer(history, events),
    sourceSummary: buildSourceSummary(deduped),
    thoughtSummary: buildThoughtSummary(activityGroups),
    planSummary: buildPlanSummary(deduped),
    activitySummary: buildActivitySummary(deduped, artifacts),
    activityGroups,
    artifactRefs: collectArtifactRefs(deduped, artifacts),
  };
}
