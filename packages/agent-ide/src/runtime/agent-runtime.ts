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

// Agent Summary for Dashboard
export interface AgentSummary {
  id: string;
  name: string;
  description: string;
  icon?: string;
  lastEdited?: string;
  model?: string;
}

// [NEW] Marketplace Types
export interface MarketplaceAgent {
  id: string;
  name: string;
  description: string;
  developer: string;   
  price: string;       
  rating?: number;     
  downloads?: number;  
  icon?: string;       
  requirements?: string; 
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
}

export interface WalletMailListRecentInput {
  channelId: string;
  leaseId: string;
  opSeq: number;
  mailbox?: string;
  limit?: number;
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

export type InstalledWorkflowStatus = "active" | "paused" | "degraded";
export type InstalledWorkflowKind = "monitor";

export interface InstalledWorkflowSummary {
  workflowId: string;
  kind: InstalledWorkflowKind;
  status: InstalledWorkflowStatus;
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
  
  // Unit Testing (Ephemeral Node Run)
  runNode(nodeType: string, config: any, input: string): Promise<any>;

  // Project Management
  loadProject(path?: string): Promise<ProjectFile | null>;
  saveProject(path: string, project: ProjectFile): Promise<void>;
  
  // Dashboard Management
  getAgents(): Promise<AgentSummary[]>;
  
  // Fleet Management
  getFleetState(): Promise<FleetState>;

  // [NEW] Marketplace Management
  getMarketplaceAgents(): Promise<MarketplaceAgent[]>;
  installAgent(agentId: string): Promise<void>;

  // Integrations / Connectors
  getConnectors?(): Promise<ConnectorSummary[]>;
  getConnectorActions?(connectorId: string): Promise<ConnectorActionDefinition[]>;
  runConnectorAction?(
    request: ConnectorActionRequest
  ): Promise<ConnectorActionResult>;
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
  listInstalledWorkflows?(): Promise<InstalledWorkflowSummary[]>;
  getInstalledWorkflowProject?(workflowId: string): Promise<ProjectFile>;
  pauseWorkflow?(workflowId: string): Promise<InstalledWorkflowSummary>;
  resumeWorkflow?(workflowId: string): Promise<InstalledWorkflowSummary>;
  deleteWorkflow?(workflowId: string): Promise<InstalledWorkflowSummary>;
  runWorkflowNow?(workflowId: string): Promise<WorkflowRunReceipt>;
  createMonitorWorkflow?(
    request: CreateMonitorWorkflowRequest
  ): Promise<InstalledWorkflowSummary>;

  // Event Subscription
  onEvent(callback: (event: GraphEvent) => void): () => void;
}
