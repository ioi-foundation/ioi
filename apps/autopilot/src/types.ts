// apps/autopilot/src/types.ts

// Import Graph Types from the shared package
import type {
  Node, 
  Edge, 
  NodeLogic, 
  FirewallPolicy, 
  GraphGlobalConfig, 
  AgentConfiguration 
} from "@ioi/agent-ide";

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

export interface SkillCatalogEntry {
  skill_hash: string;
  name: string;
  description: string;
  lifecycle_state: string;
  source_type: string;
  success_rate_bps: number;
  sample_size: number;
  frame_id: number;
  source_session_id?: string | null;
  source_evidence_hash?: string | null;
  relative_path?: string | null;
  stale: boolean;
  definition: {
    name: string;
    description: string;
    parameters: string;
  };
}

export interface ActiveContextItem {
  id: string;
  kind: string;
  title: string;
  summary: string;
  badge?: string | null;
  secondary_badge?: string | null;
  success_rate_bps?: number | null;
  sample_size?: number | null;
  focus_id?: string | null;
  skill_hash?: string | null;
  source_session_id?: string | null;
  source_evidence_hash?: string | null;
  relative_path?: string | null;
  stale?: boolean | null;
}

export interface ContextConstraint {
  id: string;
  label: string;
  value: string;
  severity: string;
  summary: string;
}

export interface AtlasNode {
  id: string;
  kind: string;
  label: string;
  summary: string;
  status?: string | null;
  emphasis?: number | null;
  metadata: Record<string, unknown>;
}

export interface AtlasEdge {
  id: string;
  source_id: string;
  target_id: string;
  relation: string;
  summary?: string | null;
  weight: number;
}

export interface AtlasNeighborhood {
  lens: string;
  title: string;
  summary: string;
  focus_id?: string | null;
  nodes: AtlasNode[];
  edges: AtlasEdge[];
}

export interface SkillMacroStepView {
  index: number;
  tool_name: string;
  target: string;
  params_json: Record<string, unknown> | string | number | boolean | null | Array<unknown>;
}

export interface SkillBenchmarkView {
  sample_size: number;
  success_rate_bps: number;
  intervention_rate_bps: number;
  policy_incident_rate_bps: number;
  avg_cost: number;
  avg_latency_ms: number;
  passed: boolean;
  last_evaluated_height: number;
}

export interface SkillDetailView {
  skill_hash: string;
  name: string;
  description: string;
  lifecycle_state: string;
  source_type: string;
  frame_id: number;
  success_rate_bps: number;
  sample_size: number;
  source_session_id?: string | null;
  source_evidence_hash?: string | null;
  relative_path?: string | null;
  stale: boolean;
  used_tools: string[];
  steps: SkillMacroStepView[];
  benchmark: SkillBenchmarkView;
  markdown?: string | null;
  neighborhood: AtlasNeighborhood;
}

export interface SubstrateProofReceipt {
  event_id: string;
  timestamp: string;
  step_index: number;
  tool_name: string;
  query_hash: string;
  index_root: string;
  k: number;
  ef_search: number;
  candidate_limit: number;
  candidate_total: number;
  candidate_reranked: number;
  candidate_truncated: boolean;
  distance_metric: string;
  embedding_normalized: boolean;
  proof_hash?: string | null;
  proof_ref?: string | null;
  certificate_mode?: string | null;
  success: boolean;
  error_class?: string | null;
}

export interface SubstrateProofView {
  session_id?: string | null;
  skill_hash?: string | null;
  summary: string;
  index_roots: string[];
  receipts: SubstrateProofReceipt[];
  neighborhood: AtlasNeighborhood;
}

export interface ActiveContextSnapshot {
  session_id: string;
  goal: string;
  status: string;
  mode: string;
  current_tier: string;
  focus_id: string;
  active_skill_id?: string | null;
  skills: ActiveContextItem[];
  tools: ActiveContextItem[];
  evidence: ActiveContextItem[];
  constraints: ContextConstraint[];
  recent_actions: string[];
  neighborhood: AtlasNeighborhood;
  substrate?: SubstrateProofView | null;
}

export interface AtlasSearchResult {
  id: string;
  kind: string;
  title: string;
  summary: string;
  score: number;
  lens: string;
}

export interface ResetAutopilotDataResult {
  dataDir: string;
  removedPaths: string[];
  identityPreserved: boolean;
  remoteHistoryMayPersist: boolean;
}

export type ContextAtlasLens = "Context" | "Skills" | "Substrate";
export type ContextAtlasMode = "List" | "Split" | "3D";

export interface ContextAtlasFocusRequest {
  sessionId?: string | null;
  focusId?: string | null;
  lens?: ContextAtlasLens;
  mode?: ContextAtlasMode;
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
  approve_label?: string;
  deny_label?: string;
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

export type NotificationRail = "control" | "assistant";

export type NotificationSeverity =
  | "informational"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type InterventionStatus =
  | "new"
  | "seen"
  | "pending"
  | "responded"
  | "resolved"
  | "expired"
  | "cancelled";

export type AssistantNotificationStatus =
  | "new"
  | "seen"
  | "acknowledged"
  | "snoozed"
  | "resolved"
  | "dismissed"
  | "expired"
  | "archived";

export type InterventionType =
  | "approval_gate"
  | "pii_review_gate"
  | "clarification_gate"
  | "credential_gate"
  | "reauth_gate"
  | "decision_gate"
  | "intervention_outcome";

export type AssistantNotificationClass =
  | "follow_up_risk"
  | "deadline_risk"
  | "meeting_prep"
  | "stalled_workflow"
  | "valuable_completion"
  | "digest"
  | "automation_opportunity"
  | "habitual_friction"
  | "auth_attention";

export type NotificationActionStyle = "primary" | "secondary" | "danger" | "quiet";

export type NotificationPreviewMode = "redacted" | "compact" | "full";

export type ObservationTier =
  | "workflow_state"
  | "connector_metadata"
  | "redacted_connector_content"
  | "coarse_host_context"
  | "deep_ambient_behavior";

export interface NotificationAction {
  id: string;
  label: string;
  style?: NotificationActionStyle | null;
}

export interface NotificationDeliveryState {
  toastSent: boolean;
  inboxVisible: boolean;
  badgeCounted: boolean;
  pillVisible: boolean;
  lastToastAtMs?: number | null;
}

export interface NotificationPrivacy {
  previewMode: NotificationPreviewMode;
  containsSensitiveData: boolean;
  observationTier: ObservationTier;
}

export interface NotificationSource {
  serviceName: string;
  workflowName: string;
  stepName: string;
}

export interface NotificationPolicyRefs {
  policyHash?: string | null;
  requestHash?: string | null;
}

export type NotificationTarget =
  | {
      kind: "gmail_thread";
      connectorId: string;
      threadId: string;
      messageId?: string | null;
    }
  | {
      kind: "calendar_event";
      connectorId: string;
      calendarId: string;
      eventId: string;
    }
  | {
      kind: "connector_auth";
      connectorId: string;
    }
  | {
      kind: "connector_subscription";
      connectorId: string;
      subscriptionId: string;
    };

export interface GmailThreadMessageDetail {
  id: string;
  from?: string;
  to?: string;
  subject?: string;
  date?: string;
  snippet?: string;
  rfcMessageId?: string;
  references?: string;
  labelIds: string[];
}

export interface GmailThreadDetail {
  threadId: string;
  historyId?: string;
  snippet?: string;
  messages: GmailThreadMessageDetail[];
}

export interface CalendarAttendeeDetail {
  email?: string;
  displayName?: string;
  responseStatus?: string;
  organizer?: boolean;
}

export interface CalendarEventDetail {
  calendarId: string;
  eventId: string;
  summary?: string;
  description?: string;
  location?: string;
  status?: string;
  start?: string;
  end?: string;
  htmlLink?: string;
  attendees: CalendarAttendeeDetail[];
}

export type AssistantWorkbenchSession =
  | {
      kind: "gmail_reply";
      connectorId: string;
      thread: GmailThreadDetail;
      sourceNotificationId?: string | null;
    }
  | {
      kind: "meeting_prep";
      connectorId: string;
      event: CalendarEventDetail;
      sourceNotificationId?: string | null;
    };

export interface InterventionRecord {
  itemId: string;
  rail: NotificationRail;
  interventionType: InterventionType;
  status: InterventionStatus;
  severity: NotificationSeverity;
  blocking: boolean;
  title: string;
  summary: string;
  reason?: string | null;
  recommendedAction?: string | null;
  consequenceIfIgnored?: string | null;
  createdAtMs: number;
  updatedAtMs: number;
  dueAtMs?: number | null;
  expiresAtMs?: number | null;
  snoozedUntilMs?: number | null;
  dedupeKey: string;
  threadId?: string | null;
  sessionId?: string | null;
  workflowId?: string | null;
  runId?: string | null;
  deliveryState: NotificationDeliveryState;
  privacy: NotificationPrivacy;
  source: NotificationSource;
  artifactRefs: ArtifactRef[];
  sourceEventIds: string[];
  policyRefs: NotificationPolicyRefs;
  actions: NotificationAction[];
  target?: NotificationTarget | null;
  requestHash?: string | null;
  policyHash?: string | null;
  approvalScope?: string | null;
  sensitiveActionType?: string | null;
  errorClass?: string | null;
  blockedStage?: string | null;
  retryAvailable?: boolean | null;
  recoveryHint?: string | null;
}

export interface AssistantNotificationRecord {
  itemId: string;
  rail: NotificationRail;
  notificationClass: AssistantNotificationClass;
  status: AssistantNotificationStatus;
  severity: NotificationSeverity;
  title: string;
  summary: string;
  reason?: string | null;
  recommendedAction?: string | null;
  consequenceIfIgnored?: string | null;
  createdAtMs: number;
  updatedAtMs: number;
  dueAtMs?: number | null;
  expiresAtMs?: number | null;
  snoozedUntilMs?: number | null;
  dedupeKey: string;
  threadId?: string | null;
  sessionId?: string | null;
  workflowId?: string | null;
  runId?: string | null;
  deliveryState: NotificationDeliveryState;
  privacy: NotificationPrivacy;
  source: NotificationSource;
  artifactRefs: ArtifactRef[];
  sourceEventIds: string[];
  policyRefs: NotificationPolicyRefs;
  actions: NotificationAction[];
  target?: NotificationTarget | null;
  priorityScore: number;
  confidenceScore: number;
  rankingReason: string[];
}

export interface WalletConnectorAuthRecordView {
  connectorId: string;
  providerFamily: string;
  authProtocol: string;
  state: string;
  accountLabel?: string | null;
  mailbox?: string | null;
  grantedScopes: string[];
  credentialAliases: Record<string, string>;
  metadata: Record<string, string>;
  updatedAtMs: number;
  expiresAtMs?: number | null;
  lastValidatedAtMs?: number | null;
}

export interface WalletConnectorAuthGetResult {
  fetchedAtMs: number;
  record: WalletConnectorAuthRecordView;
}

export interface DetectorPolicyConfig {
  enabled: boolean;
  minScore?: number | null;
  minAgeMinutes?: number | null;
  leadTimeMinutes?: number | null;
  toastMinScore?: number | null;
}

export interface AssistantAttentionGlobalPolicy {
  toastsEnabled: boolean;
  badgeEnabled: boolean;
  digestEnabled: boolean;
  hostedInferenceAllowed: boolean;
}

export interface ConnectorAttentionPolicy {
  scanMode?: string | null;
}

export interface AssistantAttentionPolicy {
  version: number;
  global: AssistantAttentionGlobalPolicy;
  detectors: Record<string, DetectorPolicyConfig>;
  connectors: Record<string, ConnectorAttentionPolicy>;
}

export interface AssistantAttentionProfile {
  version: number;
  preferredSurfaces: string[];
  highValueContacts: string[];
  focusWindows: string[];
  notificationFeedback: Record<string, Record<string, number>>;
}

export interface AssistantUserProfile {
  version: number;
  displayName: string;
  preferredName?: string | null;
  roleLabel?: string | null;
  timezone: string;
  locale: string;
  primaryEmail?: string | null;
  avatarSeed: string;
  groundingAllowed: boolean;
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

export type ChatContractScalar = string | number | boolean | null;
export type ChatContractValue = ChatContractScalar | ChatContractScalar[];
export type ChatContractSchemaVersion = "chat_contract_v1";
export type ChatContractOutcomeStatus = "success" | "partial" | "failed";

export interface ChatContractOutcome {
  status: ChatContractOutcomeStatus;
  summary?: string;
  count?: number;
}

export interface ChatContractResultColumn {
  key: string;
  label: string;
}

export interface ChatContractAction {
  id: string;
  label: string;
}

export type ChatContractResultRow = Record<string, ChatContractScalar>;
export type ChatContractInterpretation = Record<string, ChatContractValue>;

export interface ChatContractEnvelopeV1 {
  schema_version: ChatContractSchemaVersion;
  intent_id: string;
  outcome: ChatContractOutcome;
  interpretation: ChatContractInterpretation;
  result_rows: ChatContractResultRow[];
  result_columns?: ChatContractResultColumn[];
  actions?: ChatContractAction[];
  artifact_ref?: string;
  answer_markdown?: string;
}

export interface ChatContractValidationIssue {
  path: string;
  code: string;
  message: string;
}

export interface AnswerPresentation {
  message: ChatMessage;
  displayText: string;
  copyText: string;
  contract: ChatContractEnvelopeV1 | null;
  contractValidationIssues: ChatContractValidationIssue[];
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

export interface PlanSummary {
  selectedRoute: string;
  status: string;
  workerCount: number;
  policyBindings: string[];
}

export type ArtifactHubViewKey =
  | "active_context"
  | "thoughts"
  | "substrate"
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
  planSummary: PlanSummary | null;
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
