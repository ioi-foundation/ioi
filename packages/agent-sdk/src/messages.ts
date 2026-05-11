import type { StopReason } from "./options.js";

export type IOISDKMessageType =
  | "run_started"
  | "model_route_decision"
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
  modelRouteDecision?: ModelRouteDecision | null;
  stopCondition: StopConditionProjection;
  qualityLedger: AgentQualityLedgerProjection;
  scorecard: RuntimeScorecard;
}

export interface RuntimeAccountProfile {
  id: string;
  email?: string | null;
  authorityLevel: "local" | "operator" | "admin" | "hosted";
  privacyClass: "local_private" | "workspace" | "hosted" | "external";
  source: string;
}

export interface RuntimeNodeProfile {
  id: string;
  kind: "local" | "hosted" | "self_hosted" | "tee" | "depin";
  status: "available" | "unavailable" | "blocked";
  endpoint?: string;
  privacyClass: "local_private" | "workspace" | "hosted" | "external";
  evidenceRefs: string[];
}

export interface RuntimeToolCatalogEntry {
  stableToolId: string;
  displayName: string;
  primitiveCapabilities: string[];
  authorityScopeRequirements: string[];
  effectClass: string;
  riskDomain: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  evidenceRequirements: string[];
}

export interface RuntimeReceipt {
  id: string;
  kind: string;
  summary: string;
  redaction: "none" | "redacted";
  evidenceRefs: string[];
}

export interface ModelRouteDecision {
  schemaVersion: "ioi.model-route-decision.v1";
  object: "ioi.model_route_decision";
  eventKind: "ModelRouteDecision";
  decisionId: string;
  routeId: string | null;
  capability: string;
  requestedModel: string | null;
  requestedModelMode: "auto" | "explicit" | "route_default" | string;
  autoResolved: boolean;
  selectedModel: string | null;
  upstreamModel: string | null;
  neverSendAutoUpstream: boolean;
  endpointId: string | null;
  providerId: string | null;
  providerKind: string | null;
  providerLabel: string | null;
  reasoningEffort: string;
  localRemotePlacement: string;
  privacyPosture: string;
  costEstimateUsd: number;
  costEstimateSource: string;
  fallbackModel: string | null;
  fallbackEndpointId: string | null;
  fallbackAllowed: boolean;
  fallbackTriggered?: boolean;
  fallbackReason?: string | null;
  rationale: string;
  policyConstraints: Record<string, unknown>;
  evaluatedCandidateCount: number;
  rejectedCandidates: Array<{
    endpointId: string;
    providerId: string;
    reason: string | null;
  }>;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  workflowNodeType: string | null;
  responseId: string | null;
  previousResponseId: string | null;
  policyHash?: string;
  evidenceRefs: string[];
  receiptId?: string;
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
  routeDecision?: ModelRouteDecision | null;
  trace: RuntimeTraceBundle;
  scorecard: RuntimeScorecard;
  git?: {
    branches: Array<{ name: string; prUrl?: string }>;
  };
}
