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

import type {
  ActiveContextItem as GeneratedActiveContextItem,
  ActiveContextSnapshot as GeneratedActiveContextSnapshot,
  AgentEvent as GeneratedAgentEvent,
  Artifact as GeneratedArtifact,
  ArtifactRef as GeneratedArtifactRef,
  ArtifactType as GeneratedArtifactType,
  AssistantNotificationClass as GeneratedAssistantNotificationClass,
  AssistantNotificationRecord as GeneratedAssistantNotificationRecord,
  AssistantNotificationStatus as GeneratedAssistantNotificationStatus,
  AtlasEdge as GeneratedAtlasEdge,
  AtlasNeighborhood as GeneratedAtlasNeighborhood,
  AtlasNode as GeneratedAtlasNode,
  ContextConstraint as GeneratedContextConstraint,
  EventStatus as GeneratedEventStatus,
  EventType as GeneratedEventType,
  InterventionRecord as GeneratedInterventionRecord,
  InterventionStatus as GeneratedInterventionStatus,
  InterventionType as GeneratedInterventionType,
  NotificationAction as GeneratedNotificationAction,
  NotificationActionStyle as GeneratedNotificationActionStyle,
  NotificationDeliveryState as GeneratedNotificationDeliveryState,
  NotificationPolicyRefs as GeneratedNotificationPolicyRefs,
  NotificationPreviewMode as GeneratedNotificationPreviewMode,
  NotificationPrivacy as GeneratedNotificationPrivacy,
  NotificationRail as GeneratedNotificationRail,
  NotificationSeverity as GeneratedNotificationSeverity,
  NotificationSource as GeneratedNotificationSource,
  ObservationTier as GeneratedObservationTier,
  SkillCatalogEntry as GeneratedSkillCatalogEntry,
  SubstrateProofReceipt as GeneratedSubstrateProofReceipt,
  SubstrateProofView as GeneratedSubstrateProofView,
} from "./generated/autopilot-contracts";

type JsonRecord = Record<string, unknown>;

export type ActiveContextItem = GeneratedActiveContextItem;
export type ArtifactType = GeneratedArtifactType;
export type ArtifactRef = GeneratedArtifactRef;
export type AssistantNotificationClass = GeneratedAssistantNotificationClass;
export type AssistantNotificationStatus = GeneratedAssistantNotificationStatus;
export type ContextConstraint = GeneratedContextConstraint;
export type EventStatus = GeneratedEventStatus;
export type EventType = GeneratedEventType | "BROWSER_EXTRACT";
export type InterventionStatus = GeneratedInterventionStatus;
export type InterventionType = GeneratedInterventionType;
export type NotificationActionStyle = GeneratedNotificationActionStyle;
export type NotificationPreviewMode = GeneratedNotificationPreviewMode;
export type NotificationRail = GeneratedNotificationRail;
export type NotificationSeverity = GeneratedNotificationSeverity;
export type ObservationTier = GeneratedObservationTier;
export type SkillCatalogEntry = GeneratedSkillCatalogEntry;

export type AgentEvent = Omit<GeneratedAgentEvent, "event_type" | "digest" | "details"> & {
  event_type: EventType;
  digest: JsonRecord;
  details: JsonRecord;
};

export type Artifact = Omit<GeneratedArtifact, "metadata"> & {
  metadata: JsonRecord;
};

export type AtlasEdge = GeneratedAtlasEdge;

export type AtlasNode = Omit<GeneratedAtlasNode, "metadata"> & {
  metadata: JsonRecord;
};

export type AtlasNeighborhood = Omit<GeneratedAtlasNeighborhood, "focus_id" | "nodes" | "edges"> & {
  focus_id?: string | null;
  nodes: AtlasNode[];
  edges: AtlasEdge[];
};

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
  archival_record_id: number;
  success_rate_bps: number;
  sample_size: number;
  source_session_id?: string | null;
  source_evidence_hash?: string | null;
  relative_path?: string | null;
  source_registry_id?: string | null;
  source_registry_label?: string | null;
  source_registry_uri?: string | null;
  source_registry_kind?: string | null;
  source_registry_sync_status?: string | null;
  source_registry_relative_path?: string | null;
  stale: boolean;
  used_tools: string[];
  steps: SkillMacroStepView[];
  benchmark: SkillBenchmarkView;
  markdown?: string | null;
  neighborhood: AtlasNeighborhood;
}

export type SubstrateProofReceipt = GeneratedSubstrateProofReceipt;

export type SubstrateProofView = Omit<GeneratedSubstrateProofView, "neighborhood" | "receipts"> & {
  neighborhood: AtlasNeighborhood;
  receipts: SubstrateProofReceipt[];
};

export type ActiveContextSnapshot = Omit<
  GeneratedActiveContextSnapshot,
  "neighborhood" | "substrate"
> & {
  neighborhood: AtlasNeighborhood;
  substrate?: SubstrateProofView | null;
};

export interface BenchmarkTraceArtifactLink {
  label: string;
  path: string;
  href: string;
}

export interface BenchmarkTraceSpan {
  id: string;
  lane: string;
  parentSpanId?: string | null;
  stepIndex?: number | null;
  status: string;
  summary: string;
  startMs: number;
  endMs: number;
  durationMs?: number | null;
  capabilityTags: string[];
  attributesSummary: string;
  artifactLinks: BenchmarkTraceArtifactLink[];
}

export interface BenchmarkTraceLane {
  lane: string;
  spans: BenchmarkTraceSpan[];
}

export interface BenchmarkTraceBookmark {
  id: string;
  label: string;
  spanId: string;
  kind: string;
}

export interface BenchmarkTraceReplay {
  source: string;
  rangeStartMs: number;
  rangeEndMs: number;
  spanCount: number;
  lanes: BenchmarkTraceLane[];
  bookmarks: BenchmarkTraceBookmark[];
}

export interface BenchmarkTraceMetric {
  metricId: string;
  label: string;
  status: string;
  summary: string;
  supportingSpanIds: string[];
}

export interface BenchmarkTraceLinks {
  traceBundle?: string | null;
  traceAnalysis?: string | null;
  benchmarkSummary?: string | null;
  diagnosticSummary?: string | null;
}

export interface BenchmarkTraceSummary {
  env_id: string;
  model?: string | null;
  provider_calls: number;
  reward: number;
  terminated: boolean;
  query_text: string;
}

export interface BenchmarkTraceCaseView {
  suite: string;
  caseId: string;
  runId: string;
  runSort: number;
  result: string;
  summary: BenchmarkTraceSummary;
  findings: string[];
  traceMetrics: BenchmarkTraceMetric[];
  trace: BenchmarkTraceReplay | null;
  links: BenchmarkTraceLinks;
}

export interface BenchmarkTraceFeed {
  generatedAt?: string | null;
  repoRoot?: string | null;
  cases: BenchmarkTraceCaseView[];
}

export type NotificationAction = Omit<GeneratedNotificationAction, "style"> & {
  style?: NotificationActionStyle | null;
};

export type NotificationDeliveryState = Omit<GeneratedNotificationDeliveryState, "lastToastAtMs"> & {
  lastToastAtMs?: number | null;
};

export type NotificationPrivacy = GeneratedNotificationPrivacy;
export type NotificationSource = GeneratedNotificationSource;

export type NotificationPolicyRefs = Omit<
  GeneratedNotificationPolicyRefs,
  "policyHash" | "requestHash"
> & {
  policyHash?: string | null;
  requestHash?: string | null;
};

export type NotificationTarget =
  | {
      kind: "gmail_thread";
      connectorId?: string;
      connector_id?: string;
      threadId?: string;
      thread_id?: string;
      messageId?: string | null;
      message_id?: string | null;
    }
  | {
      kind: "calendar_event";
      connectorId?: string;
      connector_id?: string;
      calendarId?: string;
      calendar_id?: string;
      eventId?: string;
      event_id?: string;
    }
  | {
      kind: "connector_auth";
      connectorId?: string;
      connector_id?: string;
    }
  | {
      kind: "connector_subscription";
      connectorId?: string;
      connector_id?: string;
      subscriptionId?: string;
      subscription_id?: string;
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

export type InterventionRecord = Omit<GeneratedInterventionRecord, "target"> & {
  target?: NotificationTarget | null;
};

export type AssistantNotificationRecord = Omit<GeneratedAssistantNotificationRecord, "target"> & {
  target?: NotificationTarget | null;
};

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
  surface_label?: string;
  scope_label?: string;
  operation_label?: string;
  target_label?: string;
  operator_note?: string;
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

export interface KnowledgeCollectionSourceRecord {
  sourceId: string;
  kind: string;
  uri: string;
  pollIntervalMinutes?: number | null;
  enabled: boolean;
  syncStatus: string;
  lastSyncedAtMs?: number | null;
  lastError?: string | null;
}

export interface KnowledgeCollectionEntryRecord {
  entryId: string;
  title: string;
  kind: string;
  scope: string;
  artifactId: string;
  byteCount: number;
  chunkCount: number;
  archivalRecordIds: number[];
  createdAtMs: number;
  updatedAtMs: number;
  contentPreview: string;
}

export interface KnowledgeCollectionRecord {
  collectionId: string;
  label: string;
  description: string;
  createdAtMs: number;
  updatedAtMs: number;
  active: boolean;
  entries: KnowledgeCollectionEntryRecord[];
  sources: KnowledgeCollectionSourceRecord[];
}

export interface KnowledgeCollectionEntryContent {
  collectionId: string;
  entryId: string;
  title: string;
  kind: string;
  artifactId: string;
  byteCount: number;
  content: string;
}

export interface KnowledgeCollectionSearchHit {
  collectionId: string;
  entryId: string;
  title: string;
  scope: string;
  score: number;
  lexicalScore: number;
  semanticScore?: number | null;
  trustLevel: string;
  snippet: string;
  archivalRecordId: number;
  inspectId?: number | null;
}

export interface SkillSourceDiscoveredSkill {
  name: string;
  description?: string | null;
  relativePath: string;
}

export interface SkillSourceRecord {
  sourceId: string;
  label: string;
  uri: string;
  kind: string;
  enabled: boolean;
  syncStatus: string;
  lastSyncedAtMs?: number | null;
  lastError?: string | null;
  discoveredSkills: SkillSourceDiscoveredSkill[];
}

export interface LocalEngineCapabilityFamily {
  id: string;
  label: string;
  description: string;
  status: string;
  availableCount: number;
  toolNames: string[];
  operatorSummary: string;
}

export interface LocalEngineControlAction {
  itemId: string;
  title: string;
  summary: string;
  status: string;
  severity: string;
  requestedAtMs: number;
  dueAtMs?: number | null;
  approvalScope?: string | null;
  sensitiveActionType?: string | null;
  recommendedAction?: string | null;
  recoveryHint?: string | null;
  requestHash?: string | null;
}

export interface LocalEngineActivityRecord {
  eventId: string;
  sessionId: string;
  family: string;
  title: string;
  toolName: string;
  timestampMs: number;
  success: boolean;
  operation?: string | null;
  subjectKind?: string | null;
  subjectId?: string | null;
  backendId?: string | null;
  errorClass?: string | null;
}

export interface LocalEngineCompatRoute {
  id: string;
  label: string;
  path: string;
  url: string;
  enabled: boolean;
  compatibilityTier: string;
  notes?: string | null;
}

export interface LocalEngineJobRecord {
  jobId: string;
  title: string;
  summary: string;
  status: string;
  origin: string;
  subjectKind: string;
  operation: string;
  createdAtMs: number;
  updatedAtMs: number;
  progressPercent: number;
  sourceUri?: string | null;
  subjectId?: string | null;
  backendId?: string | null;
  severity?: string | null;
  approvalScope?: string | null;
}

export interface LocalEngineModelRecord {
  modelId: string;
  status: string;
  residency: string;
  installedAtMs: number;
  updatedAtMs: number;
  sourceUri?: string | null;
  backendId?: string | null;
  hardwareProfile?: string | null;
  jobId?: string | null;
  bytesTransferred?: number | null;
}

export interface LocalEngineBackendRecord {
  backendId: string;
  status: string;
  health: string;
  installedAtMs: number;
  updatedAtMs: number;
  sourceUri?: string | null;
  alias?: string | null;
  hardwareProfile?: string | null;
  jobId?: string | null;
  installPath?: string | null;
  entrypoint?: string | null;
  healthEndpoint?: string | null;
  pid?: number | null;
  lastStartedAtMs?: number | null;
  lastHealthCheckAtMs?: number | null;
}

export interface LocalEngineGalleryEntryPreview {
  entryId: string;
  label: string;
  summary: string;
  sourceUri?: string | null;
}

export interface LocalEngineGalleryCatalogRecord {
  galleryId: string;
  kind: string;
  label: string;
  sourceUri: string;
  syncStatus: string;
  compatibilityTier: string;
  enabled: boolean;
  entryCount: number;
  updatedAtMs: number;
  lastJobId?: string | null;
  lastSyncedAtMs?: number | null;
  catalogPath?: string | null;
  sampleEntries: LocalEngineGalleryEntryPreview[];
  lastError?: string | null;
}

export interface LocalEngineWorkerCompletionContract {
  successCriteria: string;
  expectedOutput: string;
  mergeMode: string;
  verificationHint?: string | null;
}

export interface LocalEngineWorkerWorkflowRecord {
  workflowId: string;
  label: string;
  summary: string;
  goalTemplate: string;
  triggerIntents: string[];
  defaultBudget?: number | null;
  maxRetries?: number | null;
  allowedTools: string[];
  completionContract?: LocalEngineWorkerCompletionContract | null;
}

export interface LocalEngineWorkerTemplateRecord {
  templateId: string;
  label: string;
  role: string;
  summary: string;
  defaultBudget: number;
  maxRetries: number;
  allowedTools: string[];
  completionContract: LocalEngineWorkerCompletionContract;
  workflows: LocalEngineWorkerWorkflowRecord[];
}

export interface LocalEngineAgentPlaybookStepRecord {
  stepId: string;
  label: string;
  summary: string;
  workerTemplateId: string;
  workerWorkflowId: string;
  goalTemplate: string;
  dependsOn: string[];
}

export interface LocalEngineAgentPlaybookRecord {
  playbookId: string;
  label: string;
  summary: string;
  goalTemplate: string;
  triggerIntents: string[];
  recommendedFor: string[];
  defaultBudget: number;
  completionContract: LocalEngineWorkerCompletionContract;
  steps: LocalEngineAgentPlaybookStepRecord[];
}

export interface LocalEngineParentPlaybookReceiptRecord {
  eventId: string;
  timestampMs: number;
  phase: string;
  status: string;
  success: boolean;
  summary: string;
  receiptRef?: string | null;
  childSessionId?: string | null;
  templateId?: string | null;
  workflowId?: string | null;
  errorClass?: string | null;
  artifactIds: string[];
}

export interface LocalEngineParentPlaybookStepRunRecord {
  stepId: string;
  label: string;
  summary: string;
  status: string;
  childSessionId?: string | null;
  templateId?: string | null;
  workflowId?: string | null;
  updatedAtMs?: number | null;
  completedAtMs?: number | null;
  errorClass?: string | null;
  receipts: LocalEngineParentPlaybookReceiptRecord[];
}

export interface LocalEngineParentPlaybookRunRecord {
  runId: string;
  parentSessionId: string;
  playbookId: string;
  playbookLabel: string;
  status: string;
  latestPhase: string;
  summary: string;
  currentStepId?: string | null;
  currentStepLabel?: string | null;
  activeChildSessionId?: string | null;
  startedAtMs: number;
  updatedAtMs: number;
  completedAtMs?: number | null;
  errorClass?: string | null;
  steps: LocalEngineParentPlaybookStepRunRecord[];
}

export interface LocalEngineRuntimeProfile {
  mode: string;
  endpoint: string;
  defaultModel: string;
  baselineRole: string;
  kernelAuthority: string;
}

export interface LocalEngineStorageConfig {
  modelsPath: string;
  backendsPath: string;
  artifactsPath: string;
  cachePath: string;
}

export interface LocalEngineWatchdogConfig {
  enabled: boolean;
  idleCheckEnabled: boolean;
  idleTimeout: string;
  busyCheckEnabled: boolean;
  busyTimeout: string;
  checkInterval: string;
  forceEvictionWhenBusy: boolean;
  lruEvictionMaxRetries: number;
  lruEvictionRetryInterval: string;
}

export interface LocalEngineMemoryConfig {
  reclaimerEnabled: boolean;
  thresholdPercent: number;
  preferGpu: boolean;
  targetResource: string;
}

export interface LocalEngineBackendPolicyConfig {
  maxConcurrency: number;
  maxQueuedRequests: number;
  parallelBackendLoads: number;
  allowParallelRequests: boolean;
  healthProbeInterval: string;
  logLevel: string;
  autoShutdownOnIdle: boolean;
}

export interface LocalEngineResponseConfig {
  retainReceiptsDays: number;
  persistArtifacts: boolean;
  allowStreaming: boolean;
  storeRequestPreviews: boolean;
}

export interface LocalEngineApiConfig {
  bindAddress: string;
  remoteAccessEnabled: boolean;
  exposeCompatRoutes: boolean;
  corsMode: string;
  authMode: string;
}

export interface LocalEngineLauncherConfig {
  autoStartOnBoot: boolean;
  reopenStudioOnLaunch: boolean;
  autoCheckUpdates: boolean;
  releaseChannel: string;
  showKernelConsole: boolean;
}

export interface LocalEngineGallerySource {
  id: string;
  kind: string;
  label: string;
  uri: string;
  enabled: boolean;
  syncStatus: string;
  compatibilityTier: string;
}

export interface LocalEngineEnvironmentBinding {
  key: string;
  value: string;
  secret: boolean;
}

export interface LocalEngineControlPlane {
  runtime: LocalEngineRuntimeProfile;
  storage: LocalEngineStorageConfig;
  watchdog: LocalEngineWatchdogConfig;
  memory: LocalEngineMemoryConfig;
  backendPolicy: LocalEngineBackendPolicyConfig;
  responses: LocalEngineResponseConfig;
  api: LocalEngineApiConfig;
  launcher: LocalEngineLauncherConfig;
  galleries: LocalEngineGallerySource[];
  environment: LocalEngineEnvironmentBinding[];
  notes: string[];
}

export interface LocalEngineStagedOperation {
  operationId: string;
  subjectKind: string;
  operation: string;
  title: string;
  sourceUri?: string | null;
  subjectId?: string | null;
  notes?: string | null;
  createdAtMs: number;
  status: string;
}

export interface LocalEngineSnapshot {
  generatedAtMs: number;
  totalNativeTools: number;
  pendingControlCount: number;
  pendingApprovalCount: number;
  activeIssueCount: number;
  capabilities: LocalEngineCapabilityFamily[];
  compatibilityRoutes: LocalEngineCompatRoute[];
  pendingControls: LocalEngineControlAction[];
  jobs: LocalEngineJobRecord[];
  recentActivity: LocalEngineActivityRecord[];
  registryModels: LocalEngineModelRecord[];
  managedBackends: LocalEngineBackendRecord[];
  galleryCatalogs: LocalEngineGalleryCatalogRecord[];
  workerTemplates: LocalEngineWorkerTemplateRecord[];
  agentPlaybooks: LocalEngineAgentPlaybookRecord[];
  parentPlaybookRuns: LocalEngineParentPlaybookRunRecord[];
  controlPlane: LocalEngineControlPlane;
  stagedOperations: LocalEngineStagedOperation[];
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
