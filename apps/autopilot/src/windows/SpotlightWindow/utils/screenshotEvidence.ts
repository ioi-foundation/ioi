import type { AgentEvent } from "../../../types";
import { firstMeaningfulVisualHash } from "./visualHash";
import { eventOutputText, eventToolName } from "./eventFields";

export interface ScreenshotReceiptEvidence {
  id: string;
  hash: string;
  hasBlob: boolean;
  timestamp: string;
  stepIndex: number;
  source: string;
  summary: string;
}

const SCREENSHOT_OUTPUT_PREFIX = "screenshot captured";

function eventVisualHash(event: AgentEvent): string {
  const digest = event.digest || {};
  const details = event.details || {};
  return firstMeaningfulVisualHash(
    digest.visual_hash,
    digest.visualHash,
    details.visual_hash,
    details.visualHash,
  );
}

function isSuccessfulScreenshotAction(event: AgentEvent): boolean {
  if (event.event_type !== "COMMAND_RUN" || event.status !== "SUCCESS") {
    return false;
  }
  if (eventToolName(event).toLowerCase() !== "computer") {
    return false;
  }
  return eventOutputText(event).toLowerCase().startsWith(SCREENSHOT_OUTPUT_PREFIX);
}

export function collectScreenshotReceipts(
  events: AgentEvent[],
): ScreenshotReceiptEvidence[] {
  const latestVisualHashByStep = new Map<number, { hash: string; timestamp: string }>();
  for (const event of events) {
    const hash = eventVisualHash(event);
    if (!hash) continue;
    const existing = latestVisualHashByStep.get(event.step_index);
    if (!existing || event.timestamp > existing.timestamp) {
      latestVisualHashByStep.set(event.step_index, { hash, timestamp: event.timestamp });
    }
  }

  const receiptsByStep = new Map<number, ScreenshotReceiptEvidence>();
  for (const event of events) {
    if (!isSuccessfulScreenshotAction(event)) {
      continue;
    }
    const visual = latestVisualHashByStep.get(event.step_index);
    const hash = visual?.hash || "";
    const summary = eventOutputText(event) || "Screenshot captured.";
    const candidate: ScreenshotReceiptEvidence = {
      id: `screenshot:${event.step_index}:${event.event_id}`,
      hash,
      hasBlob: !!hash,
      timestamp: event.timestamp,
      stepIndex: event.step_index,
      source: eventToolName(event) || event.event_type,
      summary,
    };
    const existing = receiptsByStep.get(event.step_index);
    if (!existing || candidate.timestamp > existing.timestamp) {
      receiptsByStep.set(event.step_index, candidate);
    }
  }

  return Array.from(receiptsByStep.values()).sort((a, b) =>
    b.timestamp.localeCompare(a.timestamp),
  );
}
