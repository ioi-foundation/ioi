// packages/agent-ide/src/runtime/agent-runtime.ts
import { GraphGlobalConfig, ProjectFile } from "../types/graph";

// Data needed to execute a graph
export interface GraphPayload {
  nodes: any[];
  edges: any[];
  global_config: GraphGlobalConfig;
  session_id?: string;
}

// Event received from the runtime
export interface GraphEvent {
  node_id: string;
  status: string;
  result?: {
    output: string;
    metrics?: any;
    input_snapshot?: any;
  };
  fitness_score?: number;
  generation?: number;
}

// Cache check result
export interface CacheResult {
  output: string;
  metrics?: any;
  input_snapshot?: any;
}

export interface GraphRuntimeModelOption {
  modelId: string;
  status: string;
  residency?: string;
  backendId?: string | null;
}

export interface GraphModelBindingCatalog {
  refreshedAtMs: number;
  models: GraphRuntimeModelOption[];
}

export interface GraphRuntimeCapabilityOption {
  capabilityId: string;
  familyId: string;
  label: string;
  status: string;
  availableCount: number;
  operatorSummary: string;
}

export interface GraphCapabilityCatalog {
  refreshedAtMs: number;
  capabilities: GraphRuntimeCapabilityOption[];
  activeIssueCount?: number;
}

// Agent Summary for Dashboard
export interface AgentSummary {
  id: string;
  name: string;
  description: string;
  icon?: string;
  lastEdited?: string;
  model?: string;
}

export interface RuntimeCatalogEntry {
  id: string;
  name: string;
  description: string;
  ownerLabel: string;
  entryKind: string;
  runtimeNotes: string;
  statusLabel?: string;
  icon?: string;
}

// Connector Types
export type ConnectorStatus = "connected" | "needs_auth" | "degraded" | "disabled";
export type ConnectorPluginId = "wallet_mail" | "google_workspace" | string;
export type ConnectorFieldType = "text" | "textarea" | "email" | "number" | "select";
export type ConnectorActionKind = "read" | "write" | "workflow" | "admin" | "expert";

export interface ConnectorSummary {
  id: string;
  pluginId: ConnectorPluginId;
  name: string;
  provider: string;
  category: "communication" | "productivity" | "storage" | "developer";
  description: string;
  status: ConnectorStatus;
  authMode: "wallet_capability" | "wallet_network_session" | "oauth" | "api_key";
  scopes: string[];
  lastSyncAtUtc?: string;
  notes?: string;
}

export interface ConnectorFieldOption {
  label: string;
  value: string;
}

export interface ConnectorFieldDefinition {
  id: string;
  label: string;
  type: ConnectorFieldType;
  required?: boolean;
  placeholder?: string;
  description?: string;
  defaultValue?: string | number;
  options?: ConnectorFieldOption[];
}

export interface ConnectorActionDefinition {
  id: string;
  service?: string;
  serviceLabel?: string;
  toolName?: string;
  label: string;
  description: string;
  kind: ConnectorActionKind;
  confirmBeforeRun?: boolean;
  fields: ConnectorFieldDefinition[];
  requiredScopes?: string[];
}

export interface ConnectorActionRequest {
  connectorId: string;
  actionId: string;
  input: Record<string, unknown>;
}

export interface ConnectorApprovalMemoryRequest {
  connectorId: string;
  actionId: string;
  actionLabel: string;
  policyFamily: string;
  scopeKey?: string | null;
  scopeLabel?: string | null;
  sourceLabel?: string | null;
}

export interface ConnectorActionResult {
  connectorId: string;
  actionId: string;
  toolName?: string;
  provider: string;
  summary: string;
  data: unknown;
  rawOutput?: string;
  executedAtUtc: string;
}

export interface ConnectorConfigureRequest {
  connectorId: string;
  input?: Record<string, unknown>;
}

export interface ConnectorConfigureResult {
  connectorId: string;
  provider: string;
  status: ConnectorStatus;
  summary: string;
  data?: unknown;
  executedAtUtc: string;
}

export type ConnectorSubscriptionStatus =
  | "active"
  | "paused"
  | "stopped"
  | "degraded"
  | "reauth_required"
  | "renewing";

export interface ConnectorSubscriptionSummary {
  subscriptionId: string;
  connectorId: string;
  kind: string;
  status: ConnectorSubscriptionStatus;
  accountEmail?: string;
  projectId?: string;
  pubsubTopic: string;
  pubsubSubscription: string;
  googleResourceName?: string;
  labelIds: string[];
  eventTypes: string[];
  targetResource?: string;
  gmailHistoryId?: string;
  maxMessages: number;
  pollIntervalSeconds: number;
  expiresAtUtc?: string;
  renewAtUtc?: string;
  lastAckAtUtc?: string;
  lastDeliveryAtUtc?: string;
  lastError?: string;
  automationActionId?: string;
  threadId: string;
  createdAtUtc: string;
  updatedAtUtc: string;
}

export interface WalletMailMessage {
  messageId: string;
  from: string;
  subject: string;
  receivedAtMs: number;
  preview: string;
}

export interface WalletMailReadLatestInput {
  channelId: string;
  leaseId: string;
  opSeq: number;
  mailbox?: string;
  shieldApproved?: boolean;
}

export interface WalletMailListRecentInput {
  channelId: string;
  leaseId: string;
  opSeq: number;
  mailbox?: string;
  limit?: number;
  shieldApproved?: boolean;
}

export interface WalletMailReadLatestResult {
  operationIdHex: string;
  channelIdHex: string;
  leaseIdHex: string;
  mailbox: string;
  audienceHex: string;
  executedAtMs: number;
  message: WalletMailMessage;
}

export interface WalletMailListRecentResult {
  operationIdHex: string;
  channelIdHex: string;
  leaseIdHex: string;
  mailbox: string;
  audienceHex: string;
  executedAtMs: number;
  messages: WalletMailMessage[];
}

export interface WalletMailDeleteSpamInput {
  channelId: string;
  leaseId: string;
  opSeq: number;
  mailbox?: string;
  maxDelete?: number;
  shieldApproved?: boolean;
}

export interface WalletMailDeleteSpamResult {
  operationIdHex: string;
  channelIdHex: string;
  leaseIdHex: string;
  mailbox: string;
  audienceHex: string;
  executedAtMs: number;
  deletedCount: number;
}

export interface WalletMailReplyInput {
  channelId: string;
  leaseId: string;
  opSeq: number;
  mailbox?: string;
  to: string;
  subject: string;
  body: string;
  replyToMessageId?: string;
  shieldApproved?: boolean;
}

export interface WalletMailReplyResult {
  operationIdHex: string;
  channelIdHex: string;
  leaseIdHex: string;
  mailbox: string;
  audienceHex: string;
  executedAtMs: number;
  to: string;
  subject: string;
  sentMessageId: string;
}

export type WalletMailConnectorAuthMode = "password" | "oauth2";
export type WalletMailConnectorTlsMode = "plaintext" | "starttls" | "tls";

export interface WalletMailConfigureAccountInput {
  mailbox?: string;
  accountEmail: string;
  senderDisplayName?: string;
  authMode?: WalletMailConnectorAuthMode;
  imapHost: string;
  imapPort: number;
  imapTlsMode?: WalletMailConnectorTlsMode;
  smtpHost: string;
  smtpPort: number;
  smtpTlsMode?: WalletMailConnectorTlsMode;
  imapUsername?: string;
  imapSecret: string;
  smtpUsername?: string;
  smtpSecret: string;
}

export interface WalletMailConfigureAccountResult {
  mailbox: string;
  accountEmail: string;
  senderDisplayName?: string;
  authMode: WalletMailConnectorAuthMode;
  imapHost: string;
  imapPort: number;
  imapTlsMode: WalletMailConnectorTlsMode;
  smtpHost: string;
  smtpPort: number;
  smtpTlsMode: WalletMailConnectorTlsMode;
  imapUsernameAlias: string;
  imapSecretAlias: string;
  smtpUsernameAlias: string;
  smtpSecretAlias: string;
  updatedAtMs: number;
}

export interface WalletMailConfiguredAccount {
  mailbox: string;
  accountEmail: string;
  senderDisplayName?: string;
  defaultChannelIdHex?: string;
  defaultLeaseIdHex?: string;
  updatedAtMs: number;
}

export type InstalledWorkflowStatus = "active" | "paused" | "degraded";
export type InstalledWorkflowKind = "monitor";

export interface InstalledWorkflowSummary {
  workflowId: string;
  kind: InstalledWorkflowKind;
  status: InstalledWorkflowStatus;
  triggerKind: string;
  triggerLabel: string;
  remoteTriggerId?: string;
  waitUntilMs?: number;
  title: string;
  description: string;
  artifactHash: string;
  specVersion: string;
  pollIntervalSeconds: number;
  sourceLabel: string;
  keywords: string[];
  installedAtMs: number;
  updatedAtMs: number;
  nextRunAtMs?: number;
  lastRunAtMs?: number;
  lastSuccessAtMs?: number;
  lastError?: string;
  runCount: number;
  failureCount: number;
}

export interface WorkflowRunReceipt {
  receiptVersion: number;
  workflowId: string;
  runId: string;
  triggerKind: string;
  status: string;
  startedAtMs: number;
  completedAtMs: number;
  artifactHash: string;
  workflowStatus: InstalledWorkflowStatus;
  nextRunAtMs?: number;
  observation: Record<string, unknown>;
  notificationIds: string[];
  error?: string;
}

export interface CreateMonitorWorkflowRequest {
  title?: string;
  description?: string;
  keywords: string[];
  intervalSeconds?: number;
  sourcePrompt?: string;
}

export type StudioViewTarget = string;

export type StudioCapabilityDetailSection =
  | "overview"
  | "setup"
  | "actions"
  | "policy";

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

export type AgentSessionEventName =
  | "task-started"
  | "task-updated"
  | "task-completed"
  | "task-dismissed"
  | "agent-event"
  | "artifact-created";

export interface AgentSessionProjection<TTask = unknown, TSessionSummary = unknown> {
  task: TTask | null;
  sessions: TSessionSummary[];
}

export type AssistantWorkbenchActivityAction =
  | "open"
  | "draft"
  | "send"
  | "copy"
  | "autopilot_handoff"
  | "shield_approval";

export type AssistantWorkbenchActivityStatus =
  | "started"
  | "succeeded"
  | "failed"
  | "requested";

export interface AssistantWorkbenchActivity {
  activityId: string;
  sessionKind: AssistantWorkbenchSession["kind"];
  surface: "reply-composer" | "meeting-prep";
  action: AssistantWorkbenchActivityAction;
  status: AssistantWorkbenchActivityStatus;
  message: string;
  timestampMs: number;
  sourceNotificationId?: string | null;
  connectorId?: string | null;
  threadId?: string | null;
  eventId?: string | null;
  evidenceThreadId?: string | null;
  detail?: string | null;
}

export interface AgentSessionThreadLoadOptions {
  limit?: number;
  cursor?: number;
}

export interface AgentSessionGateResponse {
  approved: boolean;
  requestHash?: string;
  action?: string;
}

export interface AgentSessionRuntime {
  startSessionTask<T>(intent: string): Promise<T>;
  continueSessionTask(sessionId: string, userInput: string): Promise<void>;
  dismissSessionTask(): Promise<void>;
  stopSessionTask(): Promise<void>;
  getCurrentSessionTask<T>(): Promise<T | null>;
  listSessionHistory<T>(): Promise<T[]>;
  getSessionProjection<TTask, TSessionSummary>(): Promise<
    AgentSessionProjection<TTask, TSessionSummary>
  >;
  loadSessionTask<T>(sessionId: string): Promise<T>;
  loadSessionThreadEvents<T>(
    threadId: string,
    options?: AgentSessionThreadLoadOptions,
  ): Promise<T[]>;
  loadSessionThreadArtifacts<T>(threadId: string): Promise<T[]>;
  showPillShell(): Promise<void>;
  hidePillShell(): Promise<void>;
  showSpotlightShell(): Promise<void>;
  hideSpotlightShell(): Promise<void>;
  showGateShell(): Promise<void>;
  hideGateShell(): Promise<void>;
  showStudioShell(): Promise<void>;
  openStudioView(view: StudioViewTarget): Promise<void>;
  openStudioSessionTarget(sessionId: string): Promise<void>;
  openStudioCapabilityTarget(
    connectorId?: string | null,
    detailSection?: StudioCapabilityDetailSection | null,
  ): Promise<void>;
  openStudioPolicyTarget(connectorId?: string | null): Promise<void>;
  openStudioAssistantWorkbench(
    session: AssistantWorkbenchSession,
  ): Promise<void>;
  activateAssistantWorkbenchSession(
    session: AssistantWorkbenchSession,
  ): Promise<void>;
  openStudioAutopilotIntent(intent: string): Promise<void>;
  getActiveAssistantWorkbenchSession(): Promise<AssistantWorkbenchSession | null>;
  listenAssistantWorkbenchSession(
    handler: (session: AssistantWorkbenchSession) => void,
  ): Promise<() => void>;
  reportAssistantWorkbenchActivity(
    activity: AssistantWorkbenchActivity,
  ): Promise<void>;
  getRecentAssistantWorkbenchActivities?(
    limit?: number,
  ): Promise<AssistantWorkbenchActivity[]>;
  listenAssistantWorkbenchActivity(
    handler: (activity: AssistantWorkbenchActivity) => void,
  ): Promise<() => void>;
  submitSessionRuntimePassword(
    sessionId: string,
    password: string,
  ): Promise<void>;
  respondToSessionGate(input: AgentSessionGateResponse): Promise<void>;
  listenSessionProjection<TTask, TSessionSummary>(
    handler: (projection: AgentSessionProjection<TTask, TSessionSummary>) => void,
  ): Promise<() => void>;
  listenSessionEvent<T>(
    eventName: AgentSessionEventName,
    handler: (payload: T) => void,
  ): Promise<() => void>;
}

// Fleet Types
export interface Zone {
  id: string;
  name: string;
  type: "local" | "cloud" | "enclave";
  capacity: { used: number; total: number; unit: string };
  costPerHour: number;
}

export interface Container {
  id: string;
  name: string;
  image: string;
  zoneId: string;
  status: "running" | "stopped" | "error";
  metrics: {
    cpu: number; // 0-100%
    ram: number; // 0-100%
    vram?: number; // 0-100%
  };
  uptime: string;
}

export interface FleetState {
    zones: Zone[];
    containers: Container[];
}

// The Adapter Interface
export interface AgentRuntime {
  // Execution
  runGraph(payload: GraphPayload): Promise<void>;
  stopExecution(): Promise<void>;
  
  // Data & Tools
  getAvailableTools(): Promise<any[]>;
  checkNodeCache(nodeId: string, config: any, input: string): Promise<CacheResult | null>;
  getGraphModelBindingCatalog?(): Promise<GraphModelBindingCatalog>;
  getGraphCapabilityCatalog?(): Promise<GraphCapabilityCatalog>;
  
  // Unit Testing (Ephemeral Node Run)
  runNode(
    nodeType: string,
    config: any,
    input: string,
    globalConfig?: GraphGlobalConfig
  ): Promise<any>;

  // Project Management
  loadProject(path?: string): Promise<ProjectFile | null>;
  saveProject(path: string, project: ProjectFile): Promise<void>;
  
  // Dashboard Management
  getAgents(): Promise<AgentSummary[]>;
  
  // Fleet Management
  getFleetState(): Promise<FleetState>;

  // Runtime Catalog Management
  getRuntimeCatalogEntries(): Promise<RuntimeCatalogEntry[]>;
  stageRuntimeCatalogEntry(entryId: string, notes?: string): Promise<void>;

  // Integrations / Connectors
  getConnectors?(): Promise<ConnectorSummary[]>;
  getConnectorActions?(connectorId: string): Promise<ConnectorActionDefinition[]>;
  runConnectorAction?(
    request: ConnectorActionRequest
  ): Promise<ConnectorActionResult>;
  rememberConnectorApproval?(
    request: ConnectorApprovalMemoryRequest
  ): Promise<void>;
  configureConnector?(
    request: ConnectorConfigureRequest
  ): Promise<ConnectorConfigureResult>;
  listConnectorSubscriptions?(connectorId: string): Promise<ConnectorSubscriptionSummary[]>;
  stopConnectorSubscription?(
    connectorId: string,
    subscriptionId: string
  ): Promise<ConnectorSubscriptionSummary>;
  resumeConnectorSubscription?(
    connectorId: string,
    subscriptionId: string
  ): Promise<ConnectorSubscriptionSummary>;
  renewConnectorSubscription?(
    connectorId: string,
    subscriptionId: string
  ): Promise<ConnectorSubscriptionSummary>;
  walletMailReadLatest?(
    input: WalletMailReadLatestInput
  ): Promise<WalletMailReadLatestResult>;
  walletMailListRecent?(
    input: WalletMailListRecentInput
  ): Promise<WalletMailListRecentResult>;
  walletMailDeleteSpam?(
    input: WalletMailDeleteSpamInput
  ): Promise<WalletMailDeleteSpamResult>;
  walletMailReply?(
    input: WalletMailReplyInput
  ): Promise<WalletMailReplyResult>;
  walletMailConfigureAccount?(
    input: WalletMailConfigureAccountInput
  ): Promise<WalletMailConfigureAccountResult>;
  walletMailListAccounts?(): Promise<WalletMailConfiguredAccount[]>;
  listInstalledWorkflows?(): Promise<InstalledWorkflowSummary[]>;
  getInstalledWorkflowProject?(workflowId: string): Promise<ProjectFile>;
  pauseWorkflow?(workflowId: string): Promise<InstalledWorkflowSummary>;
  resumeWorkflow?(workflowId: string): Promise<InstalledWorkflowSummary>;
  deleteWorkflow?(workflowId: string): Promise<InstalledWorkflowSummary>;
  runWorkflowNow?(workflowId: string): Promise<WorkflowRunReceipt>;
  triggerRemoteWorkflow?(
    workflowId: string,
    payload?: Record<string, unknown>
  ): Promise<WorkflowRunReceipt>;
  createMonitorWorkflow?(
    request: CreateMonitorWorkflowRequest
  ): Promise<InstalledWorkflowSummary>;

  // Event Subscription
  onEvent(callback: (event: GraphEvent) => void): () => void;
}
