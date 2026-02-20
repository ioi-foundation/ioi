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

export interface ConnectorSummary {
  id: string;
  name: string;
  provider: string;
  category: "communication" | "productivity" | "storage" | "developer";
  description: string;
  status: ConnectorStatus;
  authMode: "wallet_network_session" | "oauth" | "api_key";
  scopes: string[];
  lastSyncAtUtc?: string;
  notes?: string;
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

export interface WalletMailIntentInput {
  channelId: string;
  leaseId: string;
  opSeq: number;
  query: string;
  mailbox?: string;
  listLimit?: number;
  approvalArtifactJson?: string;
}

export interface WalletMailApprovalArtifactInput {
  channelId: string;
  leaseId: string;
  opSeq: number;
  query: string;
  mailbox?: string;
  ttlSeconds?: number;
}

export interface WalletMailApprovalArtifactResult {
  normalizedIntent: string;
  requestHashHex: string;
  audienceHex: string;
  revocationEpoch: number;
  expiresAtMs: number;
  approvalArtifactJson: string;
}

export interface WalletMailIntentResult {
  query: string;
  normalizedIntent: string;
  policyDecision: string;
  reason: string;
  approved: boolean;
  executed: boolean;
  operation?: string;
  nextOpSeq: number;
  readLatest?: WalletMailReadLatestResult;
  listRecent?: WalletMailListRecentResult;
  deleteSpam?: WalletMailDeleteSpamResult;
  reply?: WalletMailReplyResult;
}

export type WalletMailConnectorAuthMode = "password" | "oauth2";
export type WalletMailConnectorTlsMode = "plaintext" | "starttls" | "tls";

export interface WalletMailConfigureAccountInput {
  mailbox?: string;
  accountEmail: string;
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
  walletMailHandleIntent?(
    input: WalletMailIntentInput
  ): Promise<WalletMailIntentResult>;
  walletMailConfigureAccount?(
    input: WalletMailConfigureAccountInput
  ): Promise<WalletMailConfigureAccountResult>;
  walletMailGenerateApprovalArtifact?(
    input: WalletMailApprovalArtifactInput
  ): Promise<WalletMailApprovalArtifactResult>;

  // Event Subscription
  onEvent(callback: (event: GraphEvent) => void): () => void;
}
