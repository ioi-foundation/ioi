import type {
  AgentEvent,
  Artifact,
  AssistantNotificationRecord,
  AssistantWorkbenchActivityRecord,
  CanonicalTraceBundle,
  InterventionRecord,
} from "../../../types";
import { eventOutputText, eventToolName, toEventString } from "../utils/eventFields";

export interface ReplayTimelineRow {
  id: string;
  timestamp: string;
  kind: "action" | "policy" | "receipt" | "artifact";
  kindLabel: string;
  title: string;
  summary: string;
  meta: string[];
  artifactId?: string | null;
  artifactLabel?: string | null;
}

const MAX_SUMMARY_CHARS = 180;

function clipText(value: string, maxChars: number = MAX_SUMMARY_CHARS): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function humanizeLabel(value: string): string {
  const compact = value.trim().replace(/[_-]+/g, " ");
  if (!compact) return "Unknown";
  return compact.toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatStepMeta(event: AgentEvent): string[] {
  const meta = [`Step ${event.step_index}`];
  const status = humanizeLabel(event.status);
  if (status !== "Unknown") {
    meta.push(status);
  }
  return meta;
}

function eventSummary(event: AgentEvent): string {
  return clipText(eventOutputText(event) || event.title || event.event_type);
}

function eventHasPolicyDigest(event: AgentEvent): boolean {
  const digest = event.digest || {};
  const policyKeys = [
    "policy_decision",
    "gate_state",
    "resolution_action",
    "incident_stage",
    "strategy_node",
  ];
  return policyKeys.some(
    (key) =>
      toEventString(digest[key as keyof typeof digest]).trim().length > 0,
  );
}

function eventArtifactRef(event: AgentEvent): {
  artifactId: string | null;
  artifactLabel: string | null;
} {
  const reportRef =
    event.artifact_refs?.find((ref) => ref.artifact_type === "REPORT") || null;
  if (reportRef) {
    return {
      artifactId: reportRef.artifact_id,
      artifactLabel: "Open report",
    };
  }

  const firstRef = event.artifact_refs?.[0] || null;
  return firstRef
    ? {
        artifactId: firstRef.artifact_id,
        artifactLabel: "Open artifact",
      }
    : { artifactId: null, artifactLabel: null };
}

function timestampFromMs(value: number | null | undefined): string | null {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return null;
  }
  return new Date(value).toISOString();
}

function interventionArtifactRef(item: InterventionRecord): {
  artifactId: string | null;
  artifactLabel: string | null;
} {
  const reportRef =
    item.artifactRefs?.find((ref) => ref.artifact_type === "REPORT") || null;
  if (reportRef) {
    return {
      artifactId: reportRef.artifact_id,
      artifactLabel: "Open report",
    };
  }

  const firstRef = item.artifactRefs?.[0] || null;
  return firstRef
    ? {
        artifactId: firstRef.artifact_id,
        artifactLabel: "Open artifact",
      }
    : { artifactId: null, artifactLabel: null };
}

function notificationArtifactRef(item: AssistantNotificationRecord): {
  artifactId: string | null;
  artifactLabel: string | null;
} {
  const firstRef = item.artifactRefs?.[0] || null;
  return firstRef
    ? {
        artifactId: firstRef.artifact_id,
        artifactLabel: "Open artifact",
      }
    : { artifactId: null, artifactLabel: null };
}

function buildHistoryRows(bundle: CanonicalTraceBundle): ReplayTimelineRow[] {
  return bundle.history
    .filter((message) => message.role === "user" && message.text.trim().length > 0)
    .map((message, index) => ({
      id: `history-${index}-${message.timestamp}`,
      timestamp: new Date(message.timestamp).toISOString(),
      kind: "action",
      kindLabel: "Prompt",
      title: "User prompt",
      summary: clipText(message.text, 220),
      meta: ["History"],
    }));
}

function buildEventRows(bundle: CanonicalTraceBundle): ReplayTimelineRow[] {
  return bundle.events.map((event) => {
    const toolName = eventToolName(event) || "system";
    const digest = event.digest || {};
    const decision = toEventString(digest.policy_decision).trim();
    const stage = toEventString(digest.incident_stage).trim();
    const resolution = toEventString(digest.resolution_action).trim();
    const { artifactId, artifactLabel } = eventArtifactRef(event);
    const title = event.title.toLowerCase();

    if (
      event.event_type === "RECEIPT" &&
      (eventHasPolicyDigest(event) ||
        title.includes("routingreceipt") ||
        title.includes("restricted action"))
    ) {
      return {
        id: `policy-event-${event.event_id}`,
        timestamp: event.timestamp,
        kind: "policy",
        kindLabel: "Policy",
        title: `${humanizeLabel(decision || "receipt")} · ${toolName}`,
        summary: eventSummary(event),
        meta: [
          ...formatStepMeta(event),
          stage ? `Stage ${humanizeLabel(stage)}` : null,
          resolution ? `Resolution ${humanizeLabel(resolution)}` : null,
        ].filter((value): value is string => Boolean(value)),
        artifactId,
        artifactLabel,
      };
    }

    const kind = event.event_type === "RECEIPT" ? "receipt" : "action";
    return {
      id: `${kind}-event-${event.event_id}`,
      timestamp: event.timestamp,
      kind,
      kindLabel: kind === "receipt" ? "Receipt" : "Action",
      title:
        toolName !== "system"
          ? `${toolName} · ${humanizeLabel(event.event_type)}`
          : humanizeLabel(event.title || event.event_type),
      summary: eventSummary(event),
      meta: formatStepMeta(event),
      artifactId,
      artifactLabel,
    };
  });
}

function buildArtifactRows(artifacts: Artifact[]): ReplayTimelineRow[] {
  return artifacts.map((artifact) => {
    const artifactLabel = humanizeLabel(artifact.artifact_type);
    return {
      id: `artifact-${artifact.artifact_id}`,
      timestamp: artifact.created_at,
      kind: "artifact",
      kindLabel: "Artifact",
      title: artifact.title.trim() || artifactLabel,
      summary: clipText(
        artifact.description?.trim() || "Retained artifact captured for this run.",
      ),
      meta: [
        artifactLabel,
        artifact.version ? `v${artifact.version}` : null,
      ].filter((value): value is string => Boolean(value)),
      artifactId: artifact.artifact_id,
      artifactLabel: "Open artifact",
    };
  });
}

function buildInterventionRows(
  interventions: InterventionRecord[],
): ReplayTimelineRow[] {
  const rows: ReplayTimelineRow[] = [];
  for (const item of interventions) {
    const timestamp = timestampFromMs(item.updatedAtMs || item.createdAtMs);
    if (!timestamp) continue;
    const { artifactId, artifactLabel } = interventionArtifactRef(item);

    rows.push({
      id: `intervention-${item.itemId}`,
      timestamp,
      kind: "policy",
      kindLabel: "Intervention",
      title: item.title?.trim() || humanizeLabel(item.interventionType),
      summary: clipText(item.summary || item.reason || "Operator action required."),
      meta: [
        humanizeLabel(item.status),
        humanizeLabel(item.interventionType),
        item.blockedStage ? `Stage ${humanizeLabel(item.blockedStage)}` : null,
        item.approvalScope ? `Scope ${humanizeLabel(item.approvalScope)}` : null,
      ].filter((value): value is string => Boolean(value)),
      artifactId,
      artifactLabel,
    });
  }
  return rows;
}

function buildNotificationRows(
  notifications: AssistantNotificationRecord[],
): ReplayTimelineRow[] {
  const rows: ReplayTimelineRow[] = [];
  for (const item of notifications) {
    const timestamp = timestampFromMs(item.updatedAtMs || item.createdAtMs);
    if (!timestamp) continue;
    const { artifactId, artifactLabel } = notificationArtifactRef(item);

    rows.push({
      id: `assistant-${item.itemId}`,
      timestamp,
      kind: "action",
      kindLabel: "Assistant",
      title: item.title?.trim() || humanizeLabel(item.notificationClass),
      summary: clipText(item.summary || item.reason || "Assistant queued follow-up."),
      meta: [
        humanizeLabel(item.status),
        humanizeLabel(item.notificationClass),
        item.recommendedAction
          ? `Suggested ${clipText(item.recommendedAction, 48)}`
          : null,
      ].filter((value): value is string => Boolean(value)),
      artifactId,
      artifactLabel,
    });
  }
  return rows;
}

function buildWorkbenchRows(
  activities: AssistantWorkbenchActivityRecord[],
): ReplayTimelineRow[] {
  const rows: ReplayTimelineRow[] = [];
  for (const activity of activities) {
    const timestamp = timestampFromMs(activity.timestampMs);
    if (!timestamp) continue;

    const kind: ReplayTimelineRow["kind"] =
      activity.status === "succeeded" || activity.status === "failed"
        ? "receipt"
        : "action";

    rows.push({
      id: `workbench-${activity.activityId}`,
      timestamp,
      kind,
      kindLabel: kind === "receipt" ? "Workbench receipt" : "Workbench",
      title: `${humanizeLabel(activity.sessionKind)} · ${humanizeLabel(activity.action)}`,
      summary: clipText(
        activity.message || activity.detail || "Workbench activity recorded.",
      ),
      meta: [
        humanizeLabel(activity.status),
        humanizeLabel(activity.surface),
      ].filter((value): value is string => Boolean(value)),
    });
  }
  return rows;
}

export function buildReplayTimelineRows(
  bundle: CanonicalTraceBundle | null | undefined,
): ReplayTimelineRow[] {
  if (!bundle) return [];

  const rows = [
    ...buildHistoryRows(bundle),
    ...buildEventRows(bundle),
    ...buildInterventionRows(bundle.interventions),
    ...buildNotificationRows(bundle.assistantNotifications),
    ...buildWorkbenchRows(bundle.assistantWorkbenchActivities),
    ...buildArtifactRows(bundle.artifacts),
  ];

  rows.sort((left, right) => {
    const leftMs = Date.parse(left.timestamp);
    const rightMs = Date.parse(right.timestamp);
    return leftMs - rightMs || left.id.localeCompare(right.id);
  });

  return rows;
}
