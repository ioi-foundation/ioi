// apps/agent-studio/src/services/BrowserWorkspaceRuntime.ts

import type {
  AgentRuntime,
  AgentSummary,
  CacheResult,
  ConnectorActionDefinition,
  ConnectorActionRequest,
  ConnectorActionResult,
  ConnectorConfigureRequest,
  ConnectorConfigureResult,
  ConnectorSubscriptionSummary,
  ConnectorSummary,
  FleetState,
  GraphEvent,
  GraphPayload,
  ProjectFile,
  RuntimeCatalogEntry,
} from "@ioi/agent-ide";

const STORAGE_KEYS = {
  project: "agent_studio:last_project",
  agents: "agent_studio:browser_runtime_agents",
  stagedCatalog: "agent_studio:browser_runtime_staged_catalog",
};

const STARTER_AGENTS: AgentSummary[] = [
  {
    id: "browser-research",
    name: "Research Copilot",
    description:
      "Synthesizes source material into operator-ready findings and next steps.",
    icon: "🧭",
    model: "GPT-4o",
    lastEdited: "Just now",
  },
  {
    id: "browser-release",
    name: "Release Pilot",
    description:
      "Drives launch checklists, rollout notes, and verification handoffs.",
    icon: "🚀",
    model: "GPT-4.1",
    lastEdited: "Today",
  },
  {
    id: "browser-json",
    name: "JSON Formatter",
    description: "Cleans up structured data and returns an operator-safe diff.",
    icon: "🧹",
    model: "Local",
    lastEdited: "Yesterday",
  },
];

const WORKSPACE_FLEET: FleetState = {
  zones: [
    {
      id: "local-workspace",
      name: "Workspace Shell",
      type: "local",
      capacity: { used: 3, total: 12, unit: "runs" },
      costPerHour: 0,
    },
    {
      id: "akash",
      name: "Akash Network",
      type: "cloud",
      capacity: { used: 12, total: 200, unit: "GPU" },
      costPerHour: 0.45,
    },
  ],
  containers: [
    {
      id: "backend:local-workspace",
      name: "workspace-control-plane",
      image: "ioi/browser-runtime:workspace",
      zoneId: "local-workspace",
      status: "running",
      metrics: { cpu: 18, ram: 22 },
      uptime: "Workspace session",
    },
    {
      id: "c1",
      name: "remote-worker-1",
      image: "ioi/worker:latest",
      zoneId: "akash",
      status: "running",
      metrics: { cpu: 45, ram: 30 },
      uptime: "4d 2h",
    },
  ],
};

const RUNTIME_CATALOG_ENTRIES: RuntimeCatalogEntry[] = [
  {
    id: "catalog-research-swarm",
    name: "Research Swarm",
    description:
      "A multi-agent research rig for deep source gathering and synthesis.",
    ownerLabel: "IOI Runtime Catalog",
    entryKind: "Agent pack",
    runtimeNotes:
      "Stages into this workspace as a reusable operator starting point.",
    statusLabel: "Ready to stage",
    icon: "🛰️",
  },
  {
    id: "catalog-customer-ops",
    name: "Customer Ops Desk",
    description:
      "A service operator workspace for triage, escalation, and follow-up flows.",
    ownerLabel: "IOI Runtime Catalog",
    entryKind: "Workspace",
    runtimeNotes:
      "Keeps connectors, procedures, and notes together in the workspace shell.",
    statusLabel: "Ready to stage",
    icon: "📬",
  },
  {
    id: "catalog-policy-review",
    name: "Policy Review Cell",
    description:
      "A governed review pack for approvals, policy diffs, and risk notes.",
    ownerLabel: "IOI Runtime Catalog",
    entryKind: "Review pack",
    runtimeNotes:
      "Useful when you want a focused operator loop before moving into the desktop runtime.",
    statusLabel: "Ready to stage",
    icon: "🛡️",
  },
];

const WORKSPACE_CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    pluginId: "wallet_mail",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Mail connector scaffold for delegated inbox workflows with bounded wallet session authority.",
    status: "needs_auth",
    authMode: "wallet_capability",
    scopes: ["mail.read.latest", "mail.read.thread"],
    notes:
      "Connector posture is visible here. Sign-in handoff stays in the desktop runtime.",
  },
  {
    id: "google.workspace",
    pluginId: "google_workspace",
    name: "Google",
    provider: "google",
    category: "productivity",
    description:
      "Google connector surface with Gmail, Calendar, Docs, Sheets, Drive, Tasks, and workflow actions.",
    status: "connected",
    authMode: "wallet_capability",
    scopes: [
      "gmail",
      "calendar",
      "docs",
      "sheets",
      "drive",
      "tasks",
      "workflow",
      "expert",
    ],
    notes:
      "Connector posture is available in this shell.",
  },
];

const WORKSPACE_ACTIONS: ConnectorActionDefinition[] = [
  {
    id: "gmail.read_emails",
    service: "gmail",
    serviceLabel: "Gmail",
    toolName: "connector__google__gmail_read_emails",
    label: "Gmail Read Emails",
    description: "Show unread Gmail messages with sender and subject.",
    kind: "read",
    requiredScopes: ["gmail.readonly"],
    fields: [
      { id: "max", label: "Max messages", type: "number", defaultValue: 10 },
      {
        id: "query",
        label: "Search query",
        type: "text",
        defaultValue: "is:unread",
      },
    ],
  },
  {
    id: "calendar.create_event",
    service: "calendar",
    serviceLabel: "Google Calendar",
    toolName: "connector__google__calendar_create_event",
    label: "Google Calendar Create Event",
    description: "Create a new calendar event.",
    kind: "write",
    requiredScopes: ["calendar"],
    fields: [
      {
        id: "calendarId",
        label: "Calendar ID",
        type: "text",
        defaultValue: "primary",
      },
      { id: "summary", label: "Summary", type: "text" },
      { id: "start", label: "Start", type: "text" },
      { id: "end", label: "End", type: "text" },
    ],
  },
  {
    id: "workflow.meeting_prep",
    service: "workflow",
    serviceLabel: "Workflow",
    toolName: "connector__google__workflow_meeting_prep",
    label: "Meeting Prep",
    description: "Prepare the next meeting with attendees and links.",
    kind: "workflow",
    requiredScopes: ["calendar.readonly"],
    fields: [
      {
        id: "calendar",
        label: "Calendar",
        type: "text",
        defaultValue: "primary",
      },
    ],
  },
];

let workspaceGoogleSubscriptions: ConnectorSubscriptionSummary[] = [
  {
    subscriptionId: "sub-google-local-workspace-1",
    connectorId: "google.workspace",
    kind: "gmail_watch",
    status: "active",
    accountEmail: "operator@example.com",
    projectId: "local-workspace",
    pubsubTopic: "projects/local-workspace/topics/autopilot-gmail-watch",
    pubsubSubscription:
      "projects/local-workspace/subscriptions/autopilot-gmail-watch",
    labelIds: ["INBOX"],
    eventTypes: [],
    gmailHistoryId: "123456",
    maxMessages: 10,
    pollIntervalSeconds: 5,
    renewAtUtc: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    expiresAtUtc: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
    lastAckAtUtc: new Date().toISOString(),
    lastDeliveryAtUtc: new Date().toISOString(),
    automationActionId: "workflow.email_to_task",
    threadId: "google-automation-local-workspace",
    createdAtUtc: new Date().toISOString(),
    updatedAtUtc: new Date().toISOString(),
  },
];

function readJson<T>(key: string, fallback: T): T {
  const raw = localStorage.getItem(key);
  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw) as T;
  } catch (_error) {
    return fallback;
  }
}

function writeJson<T>(key: string, value: T): void {
  localStorage.setItem(key, JSON.stringify(value));
}

function persistedAgents(): AgentSummary[] {
  return readJson<AgentSummary[]>(STORAGE_KEYS.agents, []);
}

function persistedCatalogStages(): string[] {
  return readJson<string[]>(STORAGE_KEYS.stagedCatalog, []);
}

function mergedAgents(): AgentSummary[] {
  const seen = new Set<string>();
  return [...STARTER_AGENTS, ...persistedAgents()].filter((agent) => {
    if (seen.has(agent.id)) {
      return false;
    }
    seen.add(agent.id);
    return true;
  });
}

function catalogEntryToAgent(entry: RuntimeCatalogEntry): AgentSummary {
  return {
    id: entry.id,
    name: entry.name,
    description: entry.description,
    icon: entry.icon,
    model: "Catalog-backed",
    lastEdited: "Just staged",
  };
}

export class BrowserWorkspaceRuntime implements AgentRuntime {
  private eventCallback: ((event: GraphEvent) => void) | null = null;

  async runGraph(payload: GraphPayload): Promise<void> {
    console.log("[BrowserWorkspaceRuntime] Running graph", payload);

    payload.nodes.forEach((node, index) => {
      setTimeout(() => {
        this.emit({
          node_id: node.id,
          status: "running",
          result: undefined,
        });

        setTimeout(() => {
          this.emit({
            node_id: node.id,
            status: "success",
            result: {
              output: `Workspace runtime output for ${node.id}`,
              metrics: { latency_ms: Math.random() * 500 },
              input_snapshot: { workspaceLocal: true },
            },
          });
        }, 1000 + index * 500);
      }, index * 200);
    });
  }

  async stopExecution(): Promise<void> {
    console.log("[BrowserWorkspaceRuntime] Stop execution");
  }

  async checkNodeCache(
    _nodeId: string,
    _config: unknown,
    _input: string,
  ): Promise<CacheResult | null> {
    return null;
  }

  async getAvailableTools(): Promise<Array<Record<string, string>>> {
    return [
      {
        name: "browser_catalog_stage",
        description: "Stage a runtime pack into this workspace.",
        parameters: "{}",
      },
      {
        name: "connector_read_workspace",
        description: "Run a connector read action inside the workspace shell.",
        parameters: "{}",
      },
    ];
  }

  async runNode(nodeType: string, config: unknown, input: string): Promise<unknown> {
    console.log(`[BrowserWorkspaceRuntime] Running node ${nodeType}`, {
      config,
      input,
    });
    await new Promise((resolve) => setTimeout(resolve, 800));
    return {
      status: "success",
      output: `Workspace runtime result for ${nodeType}`,
      metrics: { latency_ms: 120 },
    };
  }

  async loadProject(_path?: string): Promise<ProjectFile | null> {
    return readJson<ProjectFile | null>(STORAGE_KEYS.project, null);
  }

  async saveProject(_path: string, project: ProjectFile): Promise<void> {
    console.log("[BrowserWorkspaceRuntime] Saving project", project);
    writeJson(STORAGE_KEYS.project, project);
  }

  async getAgents(): Promise<AgentSummary[]> {
    return mergedAgents();
  }

  async getFleetState(): Promise<FleetState> {
    return WORKSPACE_FLEET;
  }

  async getRuntimeCatalogEntries(): Promise<RuntimeCatalogEntry[]> {
    const stagedIds = new Set(persistedCatalogStages());
    return RUNTIME_CATALOG_ENTRIES.map((entry) => ({
      ...entry,
      statusLabel: stagedIds.has(entry.id) ? "Staged locally" : "Ready to stage",
      runtimeNotes: stagedIds.has(entry.id)
        ? "Already staged in this workspace and available from Agents."
        : entry.runtimeNotes,
    }));
  }

  async stageRuntimeCatalogEntry(entryId: string, notes?: string): Promise<void> {
    const entry = RUNTIME_CATALOG_ENTRIES.find((candidate) => candidate.id === entryId);
    if (!entry) {
      throw new Error(`Unknown runtime catalog entry ${entryId}`);
    }

    console.log("[BrowserWorkspaceRuntime] Staging runtime catalog entry", {
      entryId,
      notes: notes ?? "",
    });

    const stagedIds = persistedCatalogStages();
    if (!stagedIds.includes(entryId)) {
      writeJson(STORAGE_KEYS.stagedCatalog, [...stagedIds, entryId]);
    }

    const agents = persistedAgents();
    if (!agents.some((agent) => agent.id === entry.id)) {
      writeJson(STORAGE_KEYS.agents, [catalogEntryToAgent(entry), ...agents]);
    }
  }

  async installAgent(agentId: string): Promise<void> {
    await this.stageRuntimeCatalogEntry(agentId, "Installed from Agent Studio");
  }

  async getConnectors(): Promise<ConnectorSummary[]> {
    return WORKSPACE_CONNECTORS;
  }

  async getConnectorActions(
    connectorId: string,
  ): Promise<ConnectorActionDefinition[]> {
    if (connectorId !== "google.workspace") {
      return [];
    }
    return WORKSPACE_ACTIONS;
  }

  async runConnectorAction(
    request: ConnectorActionRequest,
  ): Promise<ConnectorActionResult> {
    return {
      connectorId: request.connectorId,
      actionId: request.actionId,
      provider: "google",
      summary: `Workspace shell executed ${request.actionId}.`,
      data: {
        ok: true,
        input: request.input,
        workspaceLocal: true,
      },
      executedAtUtc: new Date().toISOString(),
    };
  }

  async configureConnector(
    request: ConnectorConfigureRequest,
  ): Promise<ConnectorConfigureResult> {
    return {
      connectorId: request.connectorId,
      provider: "google",
      status: "connected",
      summary: "Workspace shell reports connector posture here.",
      data: {
        workspaceLocal: true,
        input: request.input ?? {},
      },
      executedAtUtc: new Date().toISOString(),
    };
  }

  async listConnectorSubscriptions(
    connectorId: string,
  ): Promise<ConnectorSubscriptionSummary[]> {
    if (connectorId !== "google.workspace") {
      return [];
    }
    return workspaceGoogleSubscriptions;
  }

  async stopConnectorSubscription(
    connectorId: string,
    subscriptionId: string,
  ): Promise<ConnectorSubscriptionSummary> {
    if (connectorId !== "google.workspace") {
      throw new Error(`Unsupported connector ${connectorId}`);
    }
    workspaceGoogleSubscriptions = workspaceGoogleSubscriptions.map((subscription) =>
      subscription.subscriptionId !== subscriptionId
        ? subscription
        : {
            ...subscription,
            status: "paused",
            updatedAtUtc: new Date().toISOString(),
          },
    );
    return workspaceGoogleSubscriptions.find(
      (subscription) => subscription.subscriptionId === subscriptionId,
    )!;
  }

  async resumeConnectorSubscription(
    connectorId: string,
    subscriptionId: string,
  ): Promise<ConnectorSubscriptionSummary> {
    if (connectorId !== "google.workspace") {
      throw new Error(`Unsupported connector ${connectorId}`);
    }
    workspaceGoogleSubscriptions = workspaceGoogleSubscriptions.map((subscription) =>
      subscription.subscriptionId !== subscriptionId
        ? subscription
        : {
            ...subscription,
            status: "active",
            updatedAtUtc: new Date().toISOString(),
          },
    );
    return workspaceGoogleSubscriptions.find(
      (subscription) => subscription.subscriptionId === subscriptionId,
    )!;
  }

  async renewConnectorSubscription(
    connectorId: string,
    subscriptionId: string,
  ): Promise<ConnectorSubscriptionSummary> {
    if (connectorId !== "google.workspace") {
      throw new Error(`Unsupported connector ${connectorId}`);
    }
    workspaceGoogleSubscriptions = workspaceGoogleSubscriptions.map((subscription) =>
      subscription.subscriptionId !== subscriptionId
        ? subscription
        : {
            ...subscription,
            status: "active",
            renewAtUtc: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
            expiresAtUtc: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
            updatedAtUtc: new Date().toISOString(),
          },
    );
    return workspaceGoogleSubscriptions.find(
      (subscription) => subscription.subscriptionId === subscriptionId,
    )!;
  }

  onEvent(callback: (event: GraphEvent) => void): () => void {
    this.eventCallback = callback;
    return () => {
      this.eventCallback = null;
    };
  }

  private emit(event: GraphEvent) {
    if (this.eventCallback) {
      this.eventCallback(event);
    }
  }
}
