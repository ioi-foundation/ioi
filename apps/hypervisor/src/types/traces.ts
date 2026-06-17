import type { AgentTask } from "./session";
import type { Artifact } from "./artifacts";
import type { ChatMessage } from "./base";
import type { AgentEvent } from "./events";
import type { ArtifactType } from "./generated";
import type {
  AssistantNotificationRecord,
  InterventionRecord,
} from "./notifications";
import type { SessionSummary } from "./session-continuity";

export interface AssistantWorkbenchActivityRecord {
  activityId: string;
  sessionKind: string;
  surface: string;
  action: string;
  status: string;
  message: string;
  timestampMs: number;
  sourceNotificationId?: string | null;
  connectorId?: string | null;
  threadId?: string | null;
  eventId?: string | null;
  evidenceThreadId?: string | null;
  detail?: string | null;
}

export interface TraceBundleStats {
  eventCount: number;
  receiptCount: number;
  artifactCount: number;
  runBundleCount: number;
  reportArtifactCount: number;
  interventionCount: number;
  assistantNotificationCount: number;
  assistantWorkbenchActivityCount: number;
  includedArtifactPayloads: boolean;
  includedArtifactPayloadCount: number;
}

export interface TraceBundleArtifactPayloadEntry {
  artifactId: string;
  artifactType: ArtifactType;
  path: string;
}

export type EvidenceTier =
  | "Projection"
  | "Runtime event receipt"
  | "Settlement receipt"
  | "External approval"
  | "Artifact promotion"
  | "Missing settlement"
  | "Simulation-only";

export type TraceAuthority =
  | "projection_only"
  | "partial_settlement"
  | "settlement";

export interface CanonicalTraceBundle {
  schemaVersion: number;
  exportedAtUtc: string;
  threadId: string;
  sessionId: string;
  latestAnswerMarkdown: string;
  stats: TraceBundleStats;
  sessionSummary?: SessionSummary | null;
  task?: AgentTask | null;
  history: ChatMessage[];
  events: AgentEvent[];
  projectionReceipts?: AgentEvent[];
  settlementReceipts?: unknown[];
  missingSettlementRefs?: string[];
  evidenceTiers?: EvidenceTier[];
  traceAuthority?: TraceAuthority;
  settlementBacked?: boolean;
  artifacts: Artifact[];
  artifactPayloads: TraceBundleArtifactPayloadEntry[];
  interventions: InterventionRecord[];
  assistantNotifications: AssistantNotificationRecord[];
  assistantWorkbenchActivities: AssistantWorkbenchActivityRecord[];
}

export type OperatorInterventionType =
  | "approval_required"
  | "graph_blocked"
  | "workflow_failure"
  | "connector_step_up"
  | "plugin_trust_change"
  | "artifact_validation_failure"
  | "missing_settlement";

export interface OperatorIntervention {
  interventionId: string;
  sessionId: string;
  type: OperatorInterventionType;
  authorityRequired: string;
  requestHash?: string | null;
  policyHash?: string | null;
  status: "open" | "resolved" | "expired" | "denied";
  deadlineAtMs: number;
  resolutionOptions: string[];
  evidenceTier: EvidenceTier;
}

export interface TraceBundleDiffStat {
  label: string;
  leftValue: string;
  rightValue: string;
}

export interface TraceBundleDiffSection {
  key: string;
  label: string;
  changed: boolean;
  summary: string;
  leftValue?: string | null;
  rightValue?: string | null;
  details: string[];
}

export interface TraceBundleDiffResult {
  schemaVersion: number;
  comparedAtUtc: string;
  leftThreadId: string;
  rightThreadId: string;
  leftSessionSummary?: SessionSummary | null;
  rightSessionSummary?: SessionSummary | null;
  firstDivergenceKey?: string | null;
  firstDivergenceSummary?: string | null;
  changedSectionCount: number;
  stats: TraceBundleDiffStat[];
  sections: TraceBundleDiffSection[];
}

export interface MutationLogEntry {
  generation: number;
  parent_hash: string;
  child_hash: string;
  diff_summary: string;
  rationale: string;
  score_delta: number;
  timestamp: number;
}
