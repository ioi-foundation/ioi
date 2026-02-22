// apps/autopilot/src/types.ts

// Import Graph Types from the shared package
// (Once installed, this will resolve to node_modules/@ioi/agent-ide/dist/...)
// For now, we will assume the build step handles this mapping.
import type { 
  Node, 
  Edge, 
  NodeLogic, 
  FirewallPolicy, 
  GraphGlobalConfig, 
  AgentConfiguration 
} from "@ioi/agent-ide/dist/types/graph"; // Path may vary depending on exports config

// Re-export for local consumption if needed, or update imports in Autopilot components
export type { Node, Edge, NodeLogic, FirewallPolicy, GraphGlobalConfig, AgentConfiguration };

// ============================================
// OS / Shell Types (Specific to Autopilot)
// ============================================

export type ExecutionMode = "local" | "session" | "settlement";

export type LiabilityLevel = 
  | "none"
  | "auditable"
  | "insured"
  | "proven";

export interface ChatMessage {
  role: string;
  text: string;
  timestamp: number;
}

export type EventType =
  | "COMMAND_RUN"
  | "COMMAND_STREAM"
  | "CODE_SEARCH"
  | "FILE_READ"
  | "FILE_EDIT"
  | "DIFF_CREATED"
  | "TEST_RUN"
  | "BROWSER_NAVIGATE"
  | "BROWSER_EXTRACT"
  | "RECEIPT"
  | "INFO_NOTE"
  | "WARNING"
  | "ERROR";

export type EventStatus = "SUCCESS" | "FAILURE" | "PARTIAL";

export type ArtifactType = "DIFF" | "FILE" | "WEB" | "RUN_BUNDLE" | "REPORT" | "LOG";

export interface ArtifactRef {
  artifact_id: string;
  artifact_type: ArtifactType;
}

export interface AgentEvent {
  event_id: string;
  timestamp: string;
  thread_id: string;
  step_index: number;
  event_type: EventType;
  title: string;
  digest: Record<string, unknown>;
  details: Record<string, unknown>;
  artifact_refs: ArtifactRef[];
  receipt_ref?: string | null;
  input_refs: string[];
  status: EventStatus;
  duration_ms?: number | null;
}

export interface Artifact {
  artifact_id: string;
  created_at: string;
  thread_id: string;
  artifact_type: ArtifactType;
  title: string;
  description: string;
  content_ref: string;
  metadata: Record<string, unknown>;
  version?: number | null;
  parent_artifact_id?: string | null;
}

export interface ArtifactContentPayload {
  artifact_id: string;
  encoding: "utf-8" | "base64" | string;
  content: string;
}

export type AgentStatus = 
  | 'requisition'
  | 'pending'
  | 'negotiating'
  | 'running'
  | 'paused'
  | 'reviewing'
  | 'completed'
  | 'failed';

export interface GateInfo {
  title: string;
  description: string;
  risk: "low" | "medium" | "high";
  deadline_ms?: number;
  pii?: PiiReviewInfo;
}

export interface PiiTargetServiceCall {
  kind: "service_call";
  service_id: string;
  method: string;
}

export interface PiiTargetCloudInference {
  kind: "cloud_inference";
  provider: string;
  model: string;
}

export interface PiiTargetAction {
  kind: "action";
  // Action target is tagged in Rust; we treat as opaque for UI rendering.
  [key: string]: unknown;
}

export type PiiTarget =
  | PiiTargetServiceCall
  | PiiTargetCloudInference
  | PiiTargetAction
  | Record<string, unknown>;

export interface PiiReviewInfo {
  decision_hash: string;
  target_label: string;
  span_summary: string;
  class_counts?: Record<string, number>;
  severity_counts?: Record<string, number>;
  stage2_prompt: string;
  deadline_ms: number;
  target_id?: PiiTarget | null;
}

export interface Receipt {
  duration: string;
  actions: number;
  cost?: string;
}

export interface CredentialRequest {
  kind: string;
  prompt: string;
  one_time?: boolean;
}

export interface ClarificationOption {
  id: string;
  label: string;
  description: string;
  recommended?: boolean;
}

export interface ClarificationRequest {
  kind: string;
  question: string;
  tool_name?: string;
  failure_class?: string;
  evidence_snippet?: string;
  context_hint?: string;
  options: ClarificationOption[];
  allow_other?: boolean;
}

export interface PolicyContext {
  name: string;
  mode: "strict" | "standard" | "elevated";
  constraints: string[];
}

export interface SwarmAgent {
  id: string;
  parentId: string | null;
  name: string;
  role: string;
  status: AgentStatus;
  budget_used: number;
  budget_cap: number;
  policy_hash: string;
  estimated_cost?: number;
  current_thought?: string;
  artifacts_produced: number;
  generation?: number;
}

export interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: "Idle" | "Running" | "Gate" | "Complete" | "Failed";
  progress: number;
  total_steps: number;
  current_step: string;
  receipt?: Receipt;
  gate_info?: GateInfo;
  history: ChatMessage[];
  events: AgentEvent[];
  artifacts: Artifact[];
  run_bundle_id?: string;
  liability_level?: LiabilityLevel;
  generation: number;
  lineage_id: string;
  fitness_score: number;
  swarm_tree: SwarmAgent[];
  processed_steps: Set<string>;
  visual_hash?: string;
  pending_request_hash?: string;
  session_id?: string;
  credential_request?: CredentialRequest;
  clarification_request?: ClarificationRequest;
}

export interface SessionSummary {
    session_id: string;
    title: string;
    timestamp: number;
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

export type ActivityKind =
  | "primary_answer_event"
  | "receipt_event"
  | "reasoning_event"
  | "workload_event"
  | "system_event";

export interface ActivityEventRef {
  key: string;
  event: AgentEvent;
  kind: ActivityKind;
  toolName?: string;
  normalizedOutputHash?: string;
}

export interface ActivitySummary {
  searchCount: number;
  readCount: number;
  receiptCount: number;
  reasoningCount: number;
  systemCount: number;
  artifactCount: number;
}

export interface ActivityGroup {
  stepIndex: number;
  title: string;
  events: ActivityEventRef[];
}

export interface AnswerPresentation {
  message: ChatMessage;
  runTimestampUtc?: string;
  confidence?: string;
  completionReason?: string;
  citations: string[];
  sourceUrls: string[];
}

export interface SourceDomainPreview {
  domain: string;
  faviconUrl: string;
  count: number;
}

export interface SourceSearchRow {
  query: string;
  resultCount: number;
  stepIndex: number;
}

export interface SourceBrowseRow {
  url: string;
  domain: string;
  title?: string;
  stepIndex: number;
}

export interface SourceSummary {
  totalSources: number;
  sourceUrls: string[];
  domains: SourceDomainPreview[];
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
}

export interface ThoughtAgentSummary {
  agentLabel: string;
  stepIndex: number;
  notes: string[];
}

export interface ThoughtSummary {
  agents: ThoughtAgentSummary[];
}

export type ArtifactHubViewKey =
  | "thoughts"
  | "sources"
  | "kernel_logs"
  | "security_policy"
  | "files"
  | "revisions"
  | "screenshots";

export interface RunPresentation {
  prompt: ChatMessage | null;
  finalAnswer: AnswerPresentation | null;
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  activitySummary: ActivitySummary;
  activityGroups: ActivityGroup[];
  artifactRefs: ArtifactRef[];
}

export interface ExportBundleManifest {
  schema_version: number;
  exported_at_utc: string;
  thread_id: string;
  answer_present: boolean;
  event_count: number;
  artifact_count: number;
  included_artifact_payloads: boolean;
  files: string[];
}
