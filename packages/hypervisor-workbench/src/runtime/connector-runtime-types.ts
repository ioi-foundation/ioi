import type { ProjectFile } from "../types/graph";

export type ConnectorStatus =
  | "connected"
  | "needs_auth"
  | "degraded"
  | "disabled";

export type ConnectorPluginId = "wallet_mail" | "google_workspace" | string;
export type ConnectorFieldType =
  | "text"
  | "textarea"
  | "email"
  | "number"
  | "select";
export type ConnectorActionKind =
  | "read"
  | "write"
  | "workflow"
  | "admin"
  | "expert";

export interface ConnectorSummary {
  id: string;
  pluginId: ConnectorPluginId;
  name: string;
  provider: string;
  category: "communication" | "productivity" | "storage" | "developer";
  description: string;
  status: ConnectorStatus;
  authMode:
    | "wallet_capability"
    | "wallet_network_session"
    | "oauth"
    | "api_key";
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

export interface ConnectorWorkbenchRuntime {
  getConnectors?(): Promise<ConnectorSummary[]>;
  getConnectorActions?(connectorId: string): Promise<ConnectorActionDefinition[]>;
  runConnectorAction?(request: ConnectorActionRequest): Promise<ConnectorActionResult>;
  rememberConnectorApproval?(
    request: ConnectorApprovalMemoryRequest,
  ): Promise<void>;
  configureConnector?(
    request: ConnectorConfigureRequest,
  ): Promise<ConnectorConfigureResult>;
  listConnectorSubscriptions?(
    connectorId: string,
  ): Promise<ConnectorSubscriptionSummary[]>;
  stopConnectorSubscription?(
    connectorId: string,
    subscriptionId: string,
  ): Promise<ConnectorSubscriptionSummary>;
  resumeConnectorSubscription?(
    connectorId: string,
    subscriptionId: string,
  ): Promise<ConnectorSubscriptionSummary>;
  renewConnectorSubscription?(
    connectorId: string,
    subscriptionId: string,
  ): Promise<ConnectorSubscriptionSummary>;
  walletMailReadLatest?(
    input: WalletMailReadLatestInput,
  ): Promise<WalletMailReadLatestResult>;
  walletMailListRecent?(
    input: WalletMailListRecentInput,
  ): Promise<WalletMailListRecentResult>;
  walletMailDeleteSpam?(
    input: WalletMailDeleteSpamInput,
  ): Promise<WalletMailDeleteSpamResult>;
  walletMailReply?(input: WalletMailReplyInput): Promise<WalletMailReplyResult>;
  walletMailConfigureAccount?(
    input: WalletMailConfigureAccountInput,
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
    payload?: Record<string, unknown>,
  ): Promise<WorkflowRunReceipt>;
  createMonitorWorkflow?(
    request: CreateMonitorWorkflowRequest,
  ): Promise<InstalledWorkflowSummary>;
}
