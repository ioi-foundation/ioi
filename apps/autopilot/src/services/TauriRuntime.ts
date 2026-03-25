// apps/autopilot/src/services/TauriRuntime.ts
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { 
  AgentRuntime, GraphPayload, GraphEvent, ProjectFile, AgentSummary, 
  FleetState, Zone, Container, MarketplaceAgent, ConnectorSummary, ConnectorStatus,
  ConnectorActionDefinition, ConnectorActionRequest, ConnectorActionResult,
  ConnectorConfigureRequest, ConnectorConfigureResult, ConnectorSubscriptionSummary,
  WalletMailDeleteSpamInput, WalletMailDeleteSpamResult,
  WalletMailReplyInput, WalletMailReplyResult,
  WalletMailListRecentInput, WalletMailListRecentResult,
  WalletMailReadLatestInput, WalletMailReadLatestResult,
  WalletMailConfigureAccountInput, WalletMailConfigureAccountResult,
  InstalledWorkflowSummary, WorkflowRunReceipt, CreateMonitorWorkflowRequest
} from "@ioi/agent-ide";
import type {
  ActiveContextSnapshot,
  AtlasNeighborhood,
  AtlasSearchResult,
  BenchmarkTraceFeed,
  ResetAutopilotDataResult,
  SkillCatalogEntry,
  SkillDetailView,
  SubstrateProofView,
} from "../types";

// Mock Data
const MOCK_AGENTS: AgentSummary[] = [
  { id: 'a1', name: 'Invoice Analyst', description: 'Parses PDF invoices', icon: '📄', model: 'GPT-4o' },
  { id: 'a2', name: 'Support Triager', description: 'Routes incoming tickets', icon: '📞', model: 'Claude 3.5' },
];

const INITIAL_ZONES: Zone[] = [
  { id: "local", name: "Local (Mac Studio)", type: "local", capacity: { used: 14, total: 64, unit: "GB" }, costPerHour: 0.00 },
  { id: "akash", name: "Akash Network (gpu-1)", type: "cloud", capacity: { used: 22, total: 48, unit: "VRAM" }, costPerHour: 0.45 },
];

const INITIAL_CONTAINERS: Container[] = [
  { id: "c1", name: "research-worker-a", image: "ioi/researcher:v1.2", zoneId: "local", status: "running", metrics: { cpu: 12, ram: 24 }, uptime: "2h 14m" },
  { id: "c3", name: "video-gen-worker", image: "ioi/creative:v0.9", zoneId: "akash", status: "running", metrics: { cpu: 88, ram: 60, vram: 92 }, uptime: "15m" },
];

const MARKET_AGENTS: MarketplaceAgent[] = [
  { id: "a1", name: "DeFi Sentinel", developer: "QuantLabs", price: "$0.05/run", description: "Monitors chain events", requirements: "24GB VRAM" },
  { id: "a2", name: "Legal Reviewer", developer: "LawAI", price: "$29/mo", description: "Contract analysis", requirements: "8GB VRAM" },
  { id: "a3", name: "Research Swarm", developer: "OpenSci", price: "Free", description: "Deep research", requirements: "48GB VRAM" },
  { id: "a4", name: "Video Gen", developer: "CreativeX", price: "$0.10/min", description: "AI Video", requirements: "H100 GPU" },
];

const SHIELD_APPROVAL_PREFIX = "SHIELD_APPROVAL_REQUIRED:";

interface ShieldApprovalRequest {
  connectorId: string;
  actionId: string;
  actionLabel: string;
  message: string;
}

interface WalletConnectorAuthRecordView {
  connectorId: string;
  authProtocol: string;
  state: string;
  updatedAtMs: number;
  accountLabel?: string | null;
  grantedScopes: string[];
}

interface WalletConnectorAuthListResult {
  listedAtMs: number;
  records: WalletConnectorAuthRecordView[];
}

const INITIAL_CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    pluginId: "wallet_mail",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Planned first wallet_network integration. Enables inbox listing and latest-email read under delegated wallet session policy.",
    status: "needs_auth",
    authMode: "wallet_capability",
    scopes: ["mail.read.latest", "mail.list.recent", "mail.delete.spam", "mail.reply"],
    notes:
      "Wallet-backed connector auth with delegated mailbox capabilities and bounded leases.",
  },
  {
    id: "google.workspace",
    pluginId: "google_workspace",
    name: "Google",
    provider: "google",
    category: "productivity",
    description:
      "Single Google connector exposing Gmail, Calendar, Docs, Sheets, BigQuery, Drive, Tasks, Chat, events, workflows, and expert raw access.",
    status: "needs_auth",
    authMode: "wallet_capability",
    scopes: [
      "gmail",
      "calendar",
      "docs",
      "sheets",
      "bigquery",
      "drive",
      "tasks",
      "chat",
      "events",
      "workflow",
      "expert",
    ],
    notes:
      "Uses native Google OAuth for consent, with wallet-backed durable auth and direct Google APIs for execution.",
  },
];

function cloneConnectors(connectors: ConnectorSummary[]): ConnectorSummary[] {
  return connectors.map((connector) => ({
    ...connector,
    scopes: [...connector.scopes],
  }));
}

function patchMailConnectorConnected(
  connectors: ConnectorSummary[],
  result: WalletMailConfigureAccountResult
): ConnectorSummary[] {
  const connectedAt = new Date(result.updatedAtMs).toISOString();
  const identityLabel = result.senderDisplayName
    ? `${result.accountEmail} as ${result.senderDisplayName}`
    : result.accountEmail;
  const connectedNote = `Connected ${identityLabel} on mailbox "${result.mailbox}".`;

  let found = false;
  const next = connectors.map((connector) => {
    if (connector.id !== "mail.primary") return connector;
    found = true;
    return {
      ...connector,
      status: "connected" as ConnectorStatus,
      lastSyncAtUtc: connectedAt,
      notes: connectedNote,
    };
  });

  if (found) return next;

  return [
    {
      id: "mail.primary",
      pluginId: "wallet_mail",
      name: "Mail",
      provider: "wallet.network",
      category: "communication",
      description:
        "Planned first wallet_network integration. Enables inbox listing and latest-email read under delegated wallet session policy.",
      status: "connected" as ConnectorStatus,
      authMode: "wallet_capability",
      scopes: ["mail.read.latest", "mail.list.recent", "mail.delete.spam", "mail.reply"],
      lastSyncAtUtc: connectedAt,
      notes: connectedNote,
    },
    ...next,
  ];
}

function patchConnectorConfigured(
  connectors: ConnectorSummary[],
  result: ConnectorConfigureResult
): ConnectorSummary[] {
  const syncedAt = result.executedAtUtc;
  let found = false;
  const next = connectors.map((connector) => {
    if (connector.id !== result.connectorId) return connector;
    found = true;
    return {
      ...connector,
      status: result.status,
      lastSyncAtUtc: syncedAt,
      notes: result.summary,
    };
  });

  if (found) return next;
  return next;
}

function connectorStatusFromWalletAuthState(state: string): ConnectorStatus {
  switch (state) {
    case "connected":
      return "connected";
    case "expired":
    case "revoked":
    case "degraded":
      return "degraded";
    case "needs_auth":
    default:
      return "needs_auth";
  }
}

function connectorNotesFromWalletRecord(
  connector: ConnectorSummary,
  record: WalletConnectorAuthRecordView
): string {
  const account = record.accountLabel?.trim();
  if (account) {
    return `${connector.name} is connected for ${account} via wallet-backed connector auth.`;
  }
  if (record.state === "needs_auth") {
    return `${connector.name} is registered but still needs wallet-backed authorization.`;
  }
  return `${connector.name} is tracked through wallet-backed connector auth.`;
}

function patchConnectorsFromWalletAuth(
  connectors: ConnectorSummary[],
  auth: WalletConnectorAuthListResult
): ConnectorSummary[] {
  const recordsById = new Map(
    auth.records.map((record) => [record.connectorId, record] as const)
  );

  return connectors.map((connector) => {
    const record = recordsById.get(connector.id);
    if (!record) return connector;
    return {
      ...connector,
      status: connectorStatusFromWalletAuthState(record.state),
      authMode: "wallet_capability",
      lastSyncAtUtc:
        record.updatedAtMs > 0 ? new Date(record.updatedAtMs).toISOString() : connector.lastSyncAtUtc,
      notes: connectorNotesFromWalletRecord(connector, record),
      scopes: record.grantedScopes.length > 0 ? [...record.grantedScopes] : connector.scopes,
    };
  });
}

function parseShieldApprovalRequest(error: unknown): ShieldApprovalRequest | null {
  const message = String(error ?? "");
  const markerIndex = message.indexOf(SHIELD_APPROVAL_PREFIX);
  if (markerIndex < 0) return null;

  const payload = message.slice(markerIndex + SHIELD_APPROVAL_PREFIX.length).trim();
  try {
    const parsed = JSON.parse(payload) as Partial<ShieldApprovalRequest>;
    if (
      typeof parsed.connectorId === "string" &&
      typeof parsed.actionId === "string" &&
      typeof parsed.actionLabel === "string" &&
      typeof parsed.message === "string"
    ) {
      return parsed as ShieldApprovalRequest;
    }
  } catch (_error) {
    // Fall through to null; the original runtime error will be rethrown upstream.
  }

  return null;
}

function confirmShieldApproval(request: ShieldApprovalRequest): boolean {
  if (typeof window === "undefined" || typeof window.confirm !== "function") {
    return false;
  }

  return window.confirm(
    `${request.message}\n\nConnector: ${request.connectorId}\nAction: ${request.actionLabel}`
  );
}

export class TauriRuntime implements AgentRuntime {
    private connectors: ConnectorSummary[] = cloneConnectors(INITIAL_CONNECTORS);

    async runGraph(payload: GraphPayload): Promise<void> {
        await invoke("run_studio_graph", { payload });
    }

    async stopExecution(): Promise<void> {
        await invoke("cancel_task");
    }

    async checkNodeCache(nodeId: string, config: any, input: string): Promise<any> {
        return invoke("check_node_cache", { nodeId, config, input });
    }

    async getAvailableTools(): Promise<any[]> {
        return invoke("get_available_tools");
    }

    async getSkillCatalog(): Promise<SkillCatalogEntry[]> {
        return invoke("get_skill_catalog");
    }

    async getActiveContext(sessionId: string): Promise<ActiveContextSnapshot> {
        return invoke("get_active_context", { sessionId });
    }

    async getAtlasNeighborhood(params: {
        sessionId?: string | null;
        focusId?: string | null;
        lens?: string | null;
    }): Promise<AtlasNeighborhood> {
        return invoke("get_atlas_neighborhood", params);
    }

    async getSkillDetail(skillHash: string): Promise<SkillDetailView> {
        return invoke("get_skill_detail", { skillHash });
    }

    async getSubstrateProof(params: {
        sessionId?: string | null;
        skillHash?: string | null;
    }): Promise<SubstrateProofView> {
        return invoke("get_substrate_proof", params);
    }

    async searchAtlas(query: string, lens?: string | null): Promise<AtlasSearchResult[]> {
        return invoke("search_atlas", { query, lens });
    }

    async resetAutopilotData(): Promise<ResetAutopilotDataResult> {
        return invoke("reset_autopilot_data");
    }

    async getLocalBenchmarkTraceFeed(limit = 8): Promise<BenchmarkTraceFeed> {
        return invoke("get_local_benchmark_trace_feed", { limit });
    }

    async runNode(nodeType: string, config: any, input: string): Promise<any> {
        return invoke("test_node_execution", { 
            nodeType, 
            config, 
            input, 
            nodeId: null, 
            sessionId: null 
        });
    }

    async loadProject(path?: string): Promise<ProjectFile | null> {
        if (!path) return null;
        // @ts-ignore
        return invoke("load_project", { path });
    }

    async saveProject(path: string, project: ProjectFile): Promise<void> {
        await invoke("save_project", { path, project });
    }

    async getAgents(): Promise<AgentSummary[]> {
        return MOCK_AGENTS;
    }

    async getFleetState(): Promise<FleetState> {
        return {
            zones: INITIAL_ZONES,
            containers: INITIAL_CONTAINERS.map(c => ({
                ...c,
                metrics: {
                    cpu: Math.min(100, Math.max(0, c.metrics.cpu + (Math.random() * 10 - 5))),
                    ram: Math.min(100, Math.max(0, c.metrics.ram + (Math.random() * 4 - 2))),
                    vram: c.metrics.vram ? Math.min(100, Math.max(0, c.metrics.vram + (Math.random() * 6 - 3))) : undefined
                }
            }))
        };
    }

    async getMarketplaceAgents(): Promise<MarketplaceAgent[]> {
        return MARKET_AGENTS;
    }

    async installAgent(agentId: string): Promise<void> {
        try {
            await invoke("install_marketplace_agent", { agentId });
        } catch (error) {
            throw new Error(
                `NotImplemented: backend command 'install_marketplace_agent' is unavailable for agent '${agentId}'. detail=${String(error)}`
            );
        }
    }

    async loadBuilderConfigToCompose(config: unknown): Promise<void> {
        try {
            await invoke("load_builder_config_to_compose", { config });
        } catch (error) {
            throw new Error(
                `NotImplemented: builder->compose handoff is not wired. detail=${String(error)}`
            );
        }
    }

    async getConnectors(): Promise<ConnectorSummary[]> {
        let next = cloneConnectors(this.connectors);
        try {
          const auth = await invoke<WalletConnectorAuthListResult>("wallet_connector_auth_list", {
            providerFamily: null,
          });
          next = patchConnectorsFromWalletAuth(next, auth);
          this.connectors = cloneConnectors(next);
        } catch (_error) {
          // Keep local connector scaffold when wallet auth receipts are unavailable.
        }
        return next;
    }

    async getConnectorActions(connectorId: string): Promise<ConnectorActionDefinition[]> {
      return invoke("connector_list_actions", {
        connectorId,
      });
    }

    async runConnectorAction(
      request: ConnectorActionRequest
    ): Promise<ConnectorActionResult> {
      try {
        return await invoke("connector_run_action", {
          connectorId: request.connectorId,
          actionId: request.actionId,
          input: request.input,
        });
      } catch (error) {
        const approvalRequest = parseShieldApprovalRequest(error);
        if (!approvalRequest || request.input._shieldApproved === true) {
          throw error;
        }

        const approved = confirmShieldApproval(approvalRequest);
        if (!approved) {
          throw new Error(`Shield approval declined for ${approvalRequest.actionLabel}.`);
        }

        return invoke("connector_run_action", {
          connectorId: request.connectorId,
          actionId: request.actionId,
          input: {
            ...request.input,
            _shieldApproved: true,
          },
        });
      }
    }

    async configureConnector(
      request: ConnectorConfigureRequest
    ): Promise<ConnectorConfigureResult> {
      const result = await invoke<ConnectorConfigureResult>("connector_configure", {
        connectorId: request.connectorId,
        input: request.input ?? {},
      });
      this.connectors = patchConnectorConfigured(this.connectors, result);
      return result;
    }

    async listConnectorSubscriptions(
      connectorId: string
    ): Promise<ConnectorSubscriptionSummary[]> {
      return invoke("connector_list_subscriptions", {
        connectorId,
      });
    }

    async stopConnectorSubscription(
      connectorId: string,
      subscriptionId: string
    ): Promise<ConnectorSubscriptionSummary> {
      return invoke("connector_stop_subscription", {
        connectorId,
        subscriptionId,
      });
    }

    async resumeConnectorSubscription(
      connectorId: string,
      subscriptionId: string
    ): Promise<ConnectorSubscriptionSummary> {
      return invoke("connector_resume_subscription", {
        connectorId,
        subscriptionId,
      });
    }

    async renewConnectorSubscription(
      connectorId: string,
      subscriptionId: string
    ): Promise<ConnectorSubscriptionSummary> {
      return invoke("connector_renew_subscription", {
        connectorId,
        subscriptionId,
      });
    }

    async walletMailReadLatest(
      input: WalletMailReadLatestInput
    ): Promise<WalletMailReadLatestResult> {
      return invoke("wallet_mail_read_latest", {
        channelId: input.channelId,
        leaseId: input.leaseId,
        opSeq: input.opSeq,
        mailbox: input.mailbox ?? null,
      });
    }

    async walletMailListRecent(
      input: WalletMailListRecentInput
    ): Promise<WalletMailListRecentResult> {
      return invoke("wallet_mail_list_recent", {
        channelId: input.channelId,
        leaseId: input.leaseId,
        opSeq: input.opSeq,
        mailbox: input.mailbox ?? null,
        limit: input.limit ?? null,
      });
    }

    async walletMailDeleteSpam(
      input: WalletMailDeleteSpamInput
    ): Promise<WalletMailDeleteSpamResult> {
      return invoke("wallet_mail_delete_spam", {
        channelId: input.channelId,
        leaseId: input.leaseId,
        opSeq: input.opSeq,
        mailbox: input.mailbox ?? null,
        maxDelete: input.maxDelete ?? null,
      });
    }

    async walletMailReply(
      input: WalletMailReplyInput
    ): Promise<WalletMailReplyResult> {
      return invoke("wallet_mail_reply", {
        channelId: input.channelId,
        leaseId: input.leaseId,
        opSeq: input.opSeq,
        mailbox: input.mailbox ?? null,
        to: input.to,
        subject: input.subject,
        body: input.body,
        replyToMessageId: input.replyToMessageId ?? null,
      });
    }

    async walletMailConfigureAccount(
      input: WalletMailConfigureAccountInput
    ): Promise<WalletMailConfigureAccountResult> {
      const result = await invoke<WalletMailConfigureAccountResult>("wallet_mail_configure_account", {
        mailbox: input.mailbox ?? null,
        accountEmail: input.accountEmail,
        authMode: input.authMode ?? "password",
        imapHost: input.imapHost,
        imapPort: input.imapPort,
        imapTlsMode: input.imapTlsMode ?? "tls",
        smtpHost: input.smtpHost,
        smtpPort: input.smtpPort,
        smtpTlsMode: input.smtpTlsMode ?? "starttls",
        senderDisplayName: input.senderDisplayName ?? null,
        imapUsername: input.imapUsername ?? null,
        imapSecret: input.imapSecret,
        smtpUsername: input.smtpUsername ?? null,
        smtpSecret: input.smtpSecret,
      });
      this.connectors = patchMailConnectorConnected(this.connectors, result);
      return result;
    }

    async listInstalledWorkflows(): Promise<InstalledWorkflowSummary[]> {
      return invoke("workflow_list");
    }

    async getInstalledWorkflowProject(workflowId: string): Promise<ProjectFile> {
      return invoke("workflow_export_project", {
        workflowId,
      });
    }

    async pauseWorkflow(workflowId: string): Promise<InstalledWorkflowSummary> {
      return invoke("workflow_pause", {
        workflowId,
      });
    }

    async resumeWorkflow(workflowId: string): Promise<InstalledWorkflowSummary> {
      return invoke("workflow_resume", {
        workflowId,
      });
    }

    async deleteWorkflow(workflowId: string): Promise<InstalledWorkflowSummary> {
      return invoke("workflow_delete", {
        workflowId,
      });
    }

    async runWorkflowNow(workflowId: string): Promise<WorkflowRunReceipt> {
      return invoke("workflow_run_now", {
        workflowId,
      });
    }

    async createMonitorWorkflow(
      request: CreateMonitorWorkflowRequest
    ): Promise<InstalledWorkflowSummary> {
      return invoke("automation_create_monitor", {
        request,
      });
    }

    onEvent(callback: (event: GraphEvent) => void): () => void {
        const unlisten = listen<any>("graph-event", (e) => {
            callback({
                node_id: e.payload.node_id,
                status: e.payload.status,
                result: e.payload.result,
                fitness_score: e.payload.fitness_score,
                generation: e.payload.generation
            });
        });
        
        return () => { unlisten.then(f => f()); };
    }
}
