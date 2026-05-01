import type { StopReason } from "./options.js";

export type IOISDKMessageType =
  | "run_started"
  | "step"
  | "delta"
  | "tool_call"
  | "tool_result"
  | "task_state"
  | "uncertainty"
  | "probe"
  | "postcondition_synthesized"
  | "semantic_impact"
  | "stop_condition"
  | "quality_ledger"
  | "artifact"
  | "completed"
  | "canceled"
  | "error";

export interface IOISDKMessage {
  id: string;
  runId: string;
  agentId: string;
  type: IOISDKMessageType;
  cursor: string;
  createdAt: string;
  summary: string;
  data?: unknown;
}

export interface ConversationMessage {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  eventId?: string;
  createdAt?: string;
}

export interface RuntimeTraceBundle {
  schemaVersion: "ioi.agent-sdk.trace.v1";
  traceBundleId: string;
  agentId: string;
  runId: string;
  eventStreamId: string;
  events: IOISDKMessage[];
  receipts: RuntimeReceipt[];
  taskState: TaskStateProjection;
  uncertainty: UncertaintyProjection;
  probes: ProbeProjection[];
  postconditions: PostconditionProjection;
  semanticImpact: SemanticImpactProjection;
  stopCondition: StopConditionProjection;
  qualityLedger: AgentQualityLedgerProjection;
  scorecard: RuntimeScorecard;
}

export interface RuntimeReceipt {
  id: string;
  kind: string;
  summary: string;
  redaction: "none" | "redacted";
  evidenceRefs: string[];
}

export interface TaskStateProjection {
  currentObjective: string;
  knownFacts: string[];
  uncertainFacts: string[];
  assumptions: string[];
  constraints: string[];
  blockers: string[];
  changedObjects: string[];
  evidenceRefs: string[];
}

export interface UncertaintyProjection {
  ambiguityLevel: "none" | "low" | "medium" | "high";
  selectedAction:
    | "ask_human"
    | "retrieve"
    | "probe"
    | "dry_run"
    | "execute"
    | "verify"
    | "escalate"
    | "stop";
  rationale: string;
  valueOfProbe: "none" | "low" | "medium" | "high";
}

export interface ProbeProjection {
  probeId: string;
  hypothesis: string;
  cheapestValidationAction: string;
  expectedObservation: string;
  result: "pending" | "confirmed" | "rejected" | "inconclusive" | "blocked";
  confidenceUpdate: string;
}

export interface PostconditionProjection {
  objective: string;
  taskFamily: string;
  riskClass: string;
  checks: Array<{
    checkId: string;
    description: string;
    status: "required" | "passed" | "failed" | "unknown" | "skipped";
  }>;
  minimumEvidence: string[];
}

export interface SemanticImpactProjection {
  changedSymbols: string[];
  changedApis: string[];
  changedSchemas: string[];
  changedPolicies: string[];
  affectedTests: string[];
  affectedDocs: string[];
  riskClass: string;
}

export interface StopConditionProjection {
  reason: StopReason;
  evidenceSufficient: boolean;
  rationale: string;
}

export interface AgentQualityLedgerProjection {
  ledgerId: string;
  taskFamily: string;
  selectedStrategy: string;
  toolSequence: string[];
  scorecardMetrics: Record<string, number>;
  failureOntologyLabels: string[];
}

export interface RuntimeScorecard {
  taskPassRate: number;
  recoverySuccess: number;
  memoryRelevance: number;
  toolQuality: number;
  strategyRoi: number;
  operatorInterventionRate: number;
  verifierIndependence: number;
}

export interface IOIRunResult {
  id: string;
  agentId: string;
  status: "queued" | "running" | "completed" | "canceled" | "failed" | "blocked";
  result: string;
  stopCondition: StopConditionProjection;
  trace: RuntimeTraceBundle;
  scorecard: RuntimeScorecard;
  git?: {
    branches: Array<{ name: string; prUrl?: string }>;
  };
}
