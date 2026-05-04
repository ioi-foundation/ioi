import type {
  ActivityEventRef,
  ActivityGroup,
  ActivitySummary,
  Artifact,
  ArtifactRef,
} from "../../../../types";

export function buildActivityGroups(
  deduped: ActivityEventRef[],
): ActivityGroup[] {
  const byStep = new Map<number, ActivityEventRef[]>();
  for (const entry of deduped) {
    const list = byStep.get(entry.event.step_index) || [];
    list.push(entry);
    byStep.set(entry.event.step_index, list);
  }

  const orderedStepIndexes = Array.from(byStep.keys()).sort((a, b) => a - b);
  return orderedStepIndexes.map((stepIndex) => {
    const entries = byStep.get(stepIndex) || [];
    entries.sort((a, b) =>
      String(a.event.timestamp || "").localeCompare(String(b.event.timestamp || "")),
    );
    return {
      stepIndex,
      title: groupTitle(stepIndex, entries),
      events: entries,
    };
  });
}

function groupTitle(stepIndex: number, events: ActivityEventRef[]): string {
  const firstTool = events.find((entry) => entry.toolName)?.toolName;
  if (firstTool) {
    return `Step ${stepIndex} · ${firstTool}`;
  }

  return `Step ${stepIndex}`;
}

export function buildActivitySummary(
  events: ActivityEventRef[],
  artifacts: Artifact[],
  webSearchTool: string,
  webReadTool: string,
): ActivitySummary {
  let searchCount = 0;
  let readCount = 0;
  let receiptCount = 0;
  let reasoningCount = 0;
  let systemCount = 0;

  for (const entry of events) {
    if (entry.kind === "receipt_event") {
      receiptCount += 1;
      continue;
    }

    if (entry.kind === "reasoning_event") {
      reasoningCount += 1;
      continue;
    }

    if (entry.kind === "system_event") {
      systemCount += 1;
      continue;
    }

    if (entry.kind === "workload_event") {
      const tool = entry.toolName?.toLowerCase() || "";
      if (tool.includes(webSearchTool)) {
        searchCount += 1;
      } else if (tool.includes(webReadTool)) {
        readCount += 1;
      } else {
        systemCount += 1;
      }
    }
  }

  return {
    searchCount,
    readCount,
    receiptCount,
    reasoningCount,
    systemCount,
    artifactCount: artifacts.length,
  };
}

export function collectArtifactRefs(
  events: ActivityEventRef[],
  artifacts: Artifact[],
): ArtifactRef[] {
  const seen = new Set<string>();
  const refs: ArtifactRef[] = [];

  for (const entry of events) {
    for (const ref of entry.event.artifact_refs || []) {
      const key = `${ref.artifact_type}:${ref.artifact_id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      refs.push(ref);
    }
  }

  for (const artifact of artifacts) {
    const key = `${artifact.artifact_type}:${artifact.artifact_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push({
      artifact_id: artifact.artifact_id,
      artifact_type: artifact.artifact_type,
    });
  }

  return refs;
}
