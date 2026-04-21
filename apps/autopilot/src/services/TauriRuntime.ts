// apps/autopilot/src/services/TauriRuntime.ts
import { invoke } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";
import {
  AgentWorkbenchRuntime,
  AssistantSessionRuntime,
  AssistantSessionEventName,
  AssistantSessionGateResponse,
  AssistantSessionProjection,
  AssistantSessionThreadLoadOptions,
  AssistantWorkbenchActivity,
  AssistantWorkbenchSession,
  ConnectorActionDefinition,
  ConnectorActionRequest,
  ConnectorActionResult,
  ConnectorApprovalMemoryRequest,
  ConnectorConfigureRequest,
  ConnectorConfigureResult,
  ConnectorSubscriptionSummary,
  CreateMonitorWorkflowRequest,
  FleetState,
  GraphCapabilityCatalog,
  GraphEvent,
  GraphGlobalConfig,
  GraphModelBindingCatalog,
  GraphPayload,
  InstalledWorkflowSummary,
  RuntimeCatalogEntry,
  ProjectFile,
  AgentSummary,
  ChatViewTarget,
  WalletMailConfigureAccountInput,
  WalletMailConfigureAccountResult,
  WalletMailConfiguredAccount,
  WalletMailDeleteSpamInput,
  WalletMailDeleteSpamResult,
  WalletMailListRecentInput,
  WalletMailListRecentResult,
  WalletMailReadLatestInput,
  WalletMailReadLatestResult,
  WalletMailReplyInput,
  WalletMailReplyResult,
  WorkflowRunReceipt,
  Zone,
  Container,
  ConnectorSummary,
  createAssistantWorkbenchActivity,
} from "@ioi/agent-ide";
import type {
  ActiveContextSnapshot,
  AtlasNeighborhood,
  AtlasSearchResult,
  BenchmarkTraceFeed,
  CapabilityRegistrySnapshot,
  KnowledgeCollectionEntryContent,
  KnowledgeCollectionEntryRecord,
  KnowledgeCollectionRecord,
  KnowledgeCollectionSearchHit,
  KnowledgeCollectionSourceRecord,
  LocalEngineControlPlane,
  LocalEngineManagedSettingsSnapshot,
  LocalEngineSnapshot,
  ResetAutopilotDataResult,
  SessionCompactionPolicy,
  SessionCompactionSnapshot,
  ExtensionManifestRecord,
  SkillCatalogEntry,
  SkillDetailView,
  SkillSourceRecord,
  SubstrateProofView,
  TeamMemorySyncSnapshot,
  ChatCapabilityDetailSection,
} from "../types";
import {
  recordChatLaunchReceipt,
  summarizeAssistantWorkbenchSession,
  showChatWithLaunchRequest,
} from "./chatLaunchState";

const LOCAL_ENGINE_ZONE_ID = "local-engine";
const ORCHESTRATION_ZONE_ID = "orchestration";

type LocalEngineBackend = LocalEngineSnapshot["managedBackends"][number];
type LocalEngineWorkerTemplate = LocalEngineSnapshot["workerTemplates"][number];
type LocalEnginePlaybook = LocalEngineSnapshot["agentPlaybooks"][number];
type LocalEngineParentPlaybookRun = LocalEngineSnapshot["parentPlaybookRuns"][number];
type LocalEngineGalleryCatalog = LocalEngineSnapshot["galleryCatalogs"][number];

export type WorkspaceWorkflowSummary = {
  workflowId: string;
  slashCommand: string;
  description: string;
  filePath: string;
  relativePath: string;
  sourceRoot: string;
  sourceRank: number;
  stepCount: number;
  turboAll: boolean;
};

const GRAPH_CAPABILITY_ALIASES: Record<string, string> = {
  responses: "reasoning",
  embeddings: "embedding",
};

function formatRelativeDuration(timestampMs?: number | null): string {
  if (!timestampMs || timestampMs <= 0) {
    return "n/a";
  }

  const elapsedMs = Math.max(0, Date.now() - timestampMs);
  const totalMinutes = Math.floor(elapsedMs / 60_000);
  if (totalMinutes < 1) {
    return "<1m";
  }

  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;

  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

function mapBackendStatusToContainerStatus(
  status?: string | null,
  health?: string | null,
): Container["status"] {
  const labels = `${status ?? ""} ${health ?? ""}`.toLowerCase();
  if (
    labels.includes("failed") ||
    labels.includes("error") ||
    labels.includes("blocked") ||
    labels.includes("degraded")
  ) {
    return "error";
  }
  if (
    labels.includes("running") ||
    labels.includes("healthy") ||
    labels.includes("ready") ||
    labels.includes("active")
  ) {
    return "running";
  }
  return "stopped";
}

function mapRunStatusToContainerStatus(status?: string | null): Container["status"] {
  const label = (status ?? "").toLowerCase();
  if (label === "running") {
    return "running";
  }
  if (label === "failed" || label === "blocked") {
    return "error";
  }
  return "stopped";
}

function dedupeAgentSummaries(items: AgentSummary[]): AgentSummary[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.id)) {
      return false;
    }
    seen.add(item.id);
    return true;
  });
}

function playbookAgentSummary(
  playbook: LocalEnginePlaybook,
  defaultModel: string,
): AgentSummary {
  return {
    id: `playbook:${playbook.playbookId}`,
    name: playbook.label,
    description:
      playbook.summary.trim() ||
      playbook.goalTemplate.trim() ||
      "Governed execution contract backed by the kernel playbook runtime.",
    model: defaultModel,
  };
}

function workerTemplateAgentSummary(
  template: LocalEngineWorkerTemplate,
  defaultModel: string,
): AgentSummary {
  return {
    id: `worker:${template.templateId}`,
    name: template.label,
    description:
      template.summary.trim() ||
      template.role.trim() ||
      "Typed worker template surfaced from the local engine.",
    model: defaultModel,
  };
}

function runtimeCatalogEntryFromPlaybook(
  playbook: LocalEnginePlaybook,
  defaultModel: string,
): RuntimeCatalogEntry {
  return {
    id: `playbook:${playbook.playbookId}`,
    name: playbook.label,
    ownerLabel: "IOI Kernel",
    entryKind: "Playbook",
    description:
      playbook.summary.trim() ||
      playbook.goalTemplate.trim() ||
      "Governed playbook packaged with the local engine runtime.",
    runtimeNotes:
      playbook.recommendedFor.slice(0, 2).join(" · ") ||
      `Uses ${defaultModel}`,
    statusLabel: "Promotable",
  };
}

function runtimeCatalogEntryFromWorkerTemplate(
  template: LocalEngineWorkerTemplate,
  defaultModel: string,
): RuntimeCatalogEntry {
  return {
    id: `worker:${template.templateId}`,
    name: template.label,
    ownerLabel: "IOI Kernel",
    entryKind: "Worker template",
    description:
      template.summary.trim() ||
      template.role.trim() ||
      "Typed worker template available inside the local engine.",
    runtimeNotes: `Uses ${defaultModel}`,
    statusLabel: "Promotable",
  };
}

function runtimeCatalogEntryFromGalleryCatalog(
  catalog: LocalEngineGalleryCatalog,
): RuntimeCatalogEntry {
  const preview =
    catalog.sampleEntries
      .slice(0, 2)
      .map((entry) => entry.label.trim())
      .filter(Boolean)
      .join(" · ") || catalog.sourceUri.trim();

  return {
    id: `gallery:${catalog.galleryId}`,
    name: catalog.label,
    ownerLabel: "IOI Gallery",
    entryKind: "Gallery catalog",
    description:
      catalog.lastError?.trim() ||
      preview ||
      "Live kernel gallery catalog available for governed sync.",
    runtimeNotes: `${catalog.entryCount} entries · ${catalog.syncStatus}`,
    statusLabel: catalog.syncStatus.replace(/[_-]+/g, " "),
  };
}

function liveAgentSummariesFromSnapshot(snapshot: LocalEngineSnapshot): AgentSummary[] {
  const defaultModel =
    snapshot.controlPlane.runtime.defaultModel?.trim() || "Kernel-managed";

  return dedupeAgentSummaries([
    ...snapshot.agentPlaybooks.map((playbook) =>
      playbookAgentSummary(playbook, defaultModel),
    ),
    ...snapshot.workerTemplates.map((template) =>
      workerTemplateAgentSummary(template, defaultModel),
    ),
  ]);
}

function liveRuntimeCatalogEntriesFromSnapshot(
  snapshot: LocalEngineSnapshot,
): RuntimeCatalogEntry[] {
  const defaultModel =
    snapshot.controlPlane.runtime.defaultModel?.trim() || "Kernel-managed";

  return [
    ...snapshot.galleryCatalogs.map((catalog) =>
      runtimeCatalogEntryFromGalleryCatalog(catalog),
    ),
    ...snapshot.agentPlaybooks.map((playbook) =>
      runtimeCatalogEntryFromPlaybook(playbook, defaultModel),
    ),
    ...snapshot.workerTemplates.map((template) =>
      runtimeCatalogEntryFromWorkerTemplate(template, defaultModel),
    ),
  ];
}

function runtimeCatalogEntryStagePlan(entryId: string): {
  subjectKind: string;
  operation: string;
  subjectId: string;
  notes: string;
} {
  const [rawKind, rawSubjectId] = entryId.split(":");
  const subjectId = rawSubjectId?.trim() || entryId;
  const subjectKind =
    rawKind === "worker"
      ? "worker_template"
      : rawKind === "gallery"
        ? "gallery"
      : rawKind === "playbook"
        ? "playbook"
        : "catalog_entry";
  const operation =
    rawKind === "gallery"
      ? "sync"
      : rawKind === "playbook" || rawKind === "worker"
        ? "promote"
        : "stage";

  return {
    subjectKind,
    operation,
    subjectId,
    notes:
      operation === "sync"
        ? `Synchronize live gallery catalog '${entryId}' through the Local Engine queue.`
        : operation === "promote"
        ? `Promote catalog entry '${entryId}' into the Local Engine queue.`
        : `Stage catalog entry '${entryId}' in the Local Engine queue for later review or promotion.`,
  };
}

function backendContainer(record: LocalEngineBackend): Container {
  return {
    id: `backend:${record.backendId}`,
    name: record.alias?.trim() || record.backendId,
    image:
      record.entrypoint?.trim() ||
      record.sourceUri?.trim() ||
      "kernel-managed-backend",
    zoneId: LOCAL_ENGINE_ZONE_ID,
    status: mapBackendStatusToContainerStatus(record.status, record.health),
    metrics: {
      cpu: 0,
      ram: 0,
    },
    uptime: formatRelativeDuration(record.lastStartedAtMs ?? record.installedAtMs),
  };
}

function playbookRunContainer(run: LocalEngineParentPlaybookRun): Container {
  const completedSteps = run.steps.filter((step) => step.status === "completed").length;
  const totalSteps = run.steps.length;
  const progressPercent =
    totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;

  return {
    id: `run:${run.runId}`,
    name: run.playbookLabel,
    image: run.currentStepLabel?.trim() || run.playbookId,
    zoneId: ORCHESTRATION_ZONE_ID,
    status: mapRunStatusToContainerStatus(run.status),
    metrics: {
      cpu: progressPercent,
      ram: 0,
    },
    uptime: formatRelativeDuration(run.startedAtMs),
  };
}

function liveFleetStateFromSnapshot(snapshot: LocalEngineSnapshot): FleetState {
  const liveRuns = snapshot.parentPlaybookRuns.filter(
    (run) => !["completed", "failed"].includes(run.status),
  );
  const liveBackends = snapshot.managedBackends;

  const zones: Zone[] = [
    {
      id: LOCAL_ENGINE_ZONE_ID,
      name: "Local Engine",
      type: "local",
      capacity: {
        used: liveBackends.length,
        total: Math.max(snapshot.registryModels.length + snapshot.managedBackends.length, 1),
        unit: "services",
      },
      costPerHour: 0,
    },
  ];

  if (liveRuns.length > 0 || snapshot.jobs.length > 0) {
    zones.push({
      id: ORCHESTRATION_ZONE_ID,
      name: "Orchestration",
      type: "enclave",
      capacity: {
        used: liveRuns.length,
        total: Math.max(snapshot.parentPlaybookRuns.length + snapshot.jobs.length, 1),
        unit: "runs",
      },
      costPerHour: 0,
    });
  }

  return {
    zones,
    containers: [
      ...liveBackends.map((record) => backendContainer(record)),
      ...liveRuns.map((run) => playbookRunContainer(run)),
    ],
  };
}

type RuntimeShellSurface = "overlay" | "chat";

export class TauriRuntime implements AgentWorkbenchRuntime, AssistantSessionRuntime {
    constructor(
      private readonly shellSurface: RuntimeShellSurface = "overlay",
    ) {}

    async runGraph(payload: GraphPayload): Promise<void> {
        await invoke("run_studio_graph", { payload });
    }

    async stopExecution(): Promise<void> {
        await this.stopAssistantSession();
    }

    async startAssistantSession<T>(intent: string): Promise<T> {
        console.info("[Autopilot][Runtime] start_task invoking", {
          originSurface: this.shellSurface,
          intentLength: intent.trim().length,
        });
        try {
          const task = await invoke<T>("start_task", {
            intent,
            originSurface: this.shellSurface,
          });
          console.info("[Autopilot][Runtime] start_task resolved", {
            originSurface: this.shellSurface,
          });
          return task;
        } catch (error) {
          console.error("[Autopilot][Runtime] start_task failed", error);
          throw error;
        }
    }

    async startSessionTask<T>(intent: string): Promise<T> {
        return this.startAssistantSession<T>(intent);
    }

    async submitAssistantSessionInput(sessionId: string, userInput: string): Promise<void> {
        await invoke("continue_task", { sessionId, userInput });
    }

    async continueSessionTask(sessionId: string, userInput: string): Promise<void> {
        return this.submitAssistantSessionInput(sessionId, userInput);
    }

    async dismissAssistantSession(): Promise<void> {
        await invoke("dismiss_task");
    }

    async dismissSessionTask(): Promise<void> {
        return this.dismissAssistantSession();
    }

    async stopAssistantSession(): Promise<void> {
        await invoke("cancel_task");
    }

    async stopSessionTask(): Promise<void> {
        return this.stopAssistantSession();
    }

    async getActiveAssistantSession<T>(): Promise<T | null> {
        return invoke<T | null>("get_current_task");
    }

    async getCurrentSessionTask<T>(): Promise<T | null> {
        return this.getActiveAssistantSession<T>();
    }

    async listAssistantSessions<T>(): Promise<T[]> {
        return invoke<T[]>("get_session_history");
    }

    async listSessionHistory<T>(): Promise<T[]> {
        return this.listAssistantSessions<T>();
    }

    async getAssistantSessionProjection<TTask, TSessionSummary>(): Promise<
      AssistantSessionProjection<TTask, TSessionSummary>
    > {
        return invoke<AssistantSessionProjection<TTask, TSessionSummary>>(
          "get_session_projection",
        );
    }

    async getSessionProjection<TTask, TSessionSummary>(): Promise<
      AssistantSessionProjection<TTask, TSessionSummary>
    > {
        return this.getAssistantSessionProjection<TTask, TSessionSummary>();
    }

    async loadAssistantSession<T>(sessionId: string): Promise<T> {
        return invoke<T>("load_session", { sessionId });
    }

    async loadSessionTask<T>(sessionId: string): Promise<T> {
        return this.loadAssistantSession<T>(sessionId);
    }

    async loadAssistantSessionEvents<T>(
        threadId: string,
        options?: AssistantSessionThreadLoadOptions
    ): Promise<T[]> {
        return invoke<T[]>("get_thread_events", {
            threadId,
            thread_id: threadId,
            limit: options?.limit ?? null,
            cursor: options?.cursor ?? null,
        });
    }

    async loadSessionThreadEvents<T>(
        threadId: string,
        options?: AssistantSessionThreadLoadOptions
    ): Promise<T[]> {
        return this.loadAssistantSessionEvents<T>(threadId, options);
    }

    async loadAssistantSessionArtifacts<T>(threadId: string): Promise<T[]> {
        return invoke<T[]>("get_thread_artifacts", {
            threadId,
            thread_id: threadId,
        });
    }

    async loadSessionThreadArtifacts<T>(threadId: string): Promise<T[]> {
        return this.loadAssistantSessionArtifacts<T>(threadId);
    }

    async showPillShell(): Promise<void> {
        await invoke("show_pill");
    }

    async hidePillShell(): Promise<void> {
        await invoke("hide_pill");
    }

    async showSpotlightShell(): Promise<void> {
        await invoke("show_spotlight");
    }

    async hideSpotlightShell(): Promise<void> {
        await invoke("hide_spotlight");
    }

    async showGateShell(): Promise<void> {
        await invoke("show_gate");
    }

    async hideGateShell(): Promise<void> {
        await invoke("hide_gate");
    }

    async showChatShell(): Promise<void> {
        await recordChatLaunchReceipt("runtime_show_chat_requested", {});
        await invoke("show_chat");
        await recordChatLaunchReceipt("runtime_show_chat_completed", {});
    }

    private async showChatShellWithTarget(
      request: Parameters<typeof showChatWithLaunchRequest>[0],
      stage: string,
      detail: Record<string, unknown>,
    ): Promise<void> {
        await recordChatLaunchReceipt(stage, detail);
        await showChatWithLaunchRequest(request);
        await recordChatLaunchReceipt(`${stage}_completed`, detail);
    }

    async openChatView(view: ChatViewTarget): Promise<void> {
        await this.showChatShellWithTarget(
          {
            kind: "view",
            view,
          },
          "runtime_open_view_requested",
          {
            view,
          },
        );
    }

    async openChatSessionTarget(sessionId: string): Promise<void> {
        await this.showChatShellWithTarget(
          {
            kind: "session-target",
            sessionId,
          },
          "runtime_open_session_requested",
          {
            sessionId,
          },
        );
    }

    async openChatCapabilityTarget(
      connectorId?: string | null,
      detailSection?: ChatCapabilityDetailSection | null,
    ): Promise<void> {
        await this.showChatShellWithTarget(
          {
            kind: "capability",
            connectorId: connectorId ?? null,
            detailSection: detailSection ?? null,
          },
          "runtime_open_capability_requested",
          {
            connectorId: connectorId ?? null,
            detailSection: detailSection ?? null,
          },
        );
    }

    async openChatPolicyTarget(connectorId?: string | null): Promise<void> {
        await this.showChatShellWithTarget(
          {
            kind: "policy",
            connectorId: connectorId ?? null,
          },
          "runtime_open_policy_requested",
          {
            connectorId: connectorId ?? null,
          },
        );
    }

    async openChatAssistantWorkbench(
      session: AssistantWorkbenchSession,
    ): Promise<void> {
        await this.activateAssistantWorkbenchSession(session);
        await this.showChatShellWithTarget(
          {
            kind: "assistant-workbench",
            session,
          },
          "runtime_open_assistant_workbench_requested",
          {
            session: summarizeAssistantWorkbenchSession(session),
          },
        );
    }

    async activateAssistantWorkbenchSession(
      session: AssistantWorkbenchSession,
    ): Promise<void> {
        await invoke("set_active_assistant_workbench_session", { session });
        await this.reportAssistantWorkbenchActivity(
          createAssistantWorkbenchActivity(session, {
            action: "open",
            status: "started",
            message:
              session.kind === "gmail_reply"
                ? "Opened Gmail reply workbench."
                : "Opened meeting prep workbench.",
          }),
        );
    }

    async getActiveAssistantWorkbenchSession(): Promise<AssistantWorkbenchSession | null> {
        return invoke("get_active_assistant_workbench_session");
    }

    async openChatAutopilotIntent(intent: string): Promise<void> {
        await this.showChatShellWithTarget(
          {
            kind: "autopilot-intent",
            intent,
          },
          "runtime_open_autopilot_intent_requested",
          {
            intent,
          },
        );
    }

    async listenAssistantWorkbenchSession(
      handler: (session: AssistantWorkbenchSession) => void,
    ): Promise<() => void> {
        return listen<AssistantWorkbenchSession>(
          "assistant-workbench-session-updated",
          (event) => handler(event.payload),
        );
    }

    async reportAssistantWorkbenchActivity(
      activity: AssistantWorkbenchActivity,
    ): Promise<void> {
        try {
            await invoke("record_assistant_workbench_activity", { activity });
        } catch (error) {
            await emit("assistant-workbench-activity", activity);
            throw error;
        }
    }

    async getRecentAssistantWorkbenchActivities(
      limit?: number,
    ): Promise<AssistantWorkbenchActivity[]> {
        return invoke("get_recent_assistant_workbench_activities", { limit });
    }

    async listenAssistantWorkbenchActivity(
      handler: (activity: AssistantWorkbenchActivity) => void,
    ): Promise<() => void> {
        return listen<AssistantWorkbenchActivity>(
          "assistant-workbench-activity",
          (event) => handler(event.payload),
        );
    }

    async submitAssistantSessionRuntimePassword(
        sessionId: string,
        password: string
    ): Promise<void> {
        await invoke("submit_runtime_password", { sessionId, password });
    }

    async submitSessionRuntimePassword(
        sessionId: string,
        password: string
    ): Promise<void> {
        return this.submitAssistantSessionRuntimePassword(sessionId, password);
    }

    async respondToAssistantSessionGate(
      input: AssistantSessionGateResponse,
    ): Promise<void> {
        await invoke("gate_respond", { ...input });
    }

    async respondToSessionGate(input: AssistantSessionGateResponse): Promise<void> {
        return this.respondToAssistantSessionGate(input);
    }

    async listenAssistantSessionProjection<TTask, TSessionSummary>(
      handler: (
        projection: AssistantSessionProjection<TTask, TSessionSummary>,
      ) => void,
    ): Promise<() => void> {
        return listen<AssistantSessionProjection<TTask, TSessionSummary>>(
          "session-projection-updated",
          (event) => handler(event.payload),
        );
    }

    async listenSessionProjection<TTask, TSessionSummary>(
      handler: (
        projection: AssistantSessionProjection<TTask, TSessionSummary>,
      ) => void,
    ): Promise<() => void> {
        return this.listenAssistantSessionProjection<TTask, TSessionSummary>(
          handler,
        );
    }

    async listenAssistantSessionEvent<T>(
        eventName: AssistantSessionEventName,
        handler: (payload: T) => void
    ): Promise<() => void> {
        return listen<T>(eventName, (event) => handler(event.payload));
    }

    async listenSessionEvent<T>(
        eventName: AssistantSessionEventName,
        handler: (payload: T) => void
    ): Promise<() => void> {
        return this.listenAssistantSessionEvent(eventName, handler);
    }

    async checkNodeCache(nodeId: string, config: any, input: string): Promise<any> {
        return invoke("check_node_cache", { nodeId, config, input });
    }

    async getAvailableTools(): Promise<any[]> {
        return invoke("get_available_tools");
    }

    async getLocalEngineSnapshot(): Promise<LocalEngineSnapshot> {
        return invoke("get_local_engine_snapshot");
    }

    async getCapabilityRegistrySnapshot(): Promise<CapabilityRegistrySnapshot> {
        return invoke("get_capability_registry_snapshot");
    }

    async planCapabilityGovernanceRequest<T>(input: {
        requestId?: string | null;
        capabilityEntryId: string;
        action: "widen" | "baseline";
        governingEntryId?: string | null;
        connectorId?: string | null;
        connectorLabel?: string | null;
    }): Promise<T> {
        return invoke("plan_capability_governance_request", { input });
    }

    async planCapabilityGovernanceProposal<T>(input: {
        capabilityEntryId: string;
        action: "widen" | "baseline";
        comparisonEntryId?: string | null;
    }): Promise<T> {
        return invoke("plan_capability_governance_proposal", { input });
    }

    async getCapabilityGovernanceRequest<T>(): Promise<T | null> {
        return invoke("get_capability_governance_request");
    }

    async setCapabilityGovernanceRequest<T>(request: T): Promise<T> {
        return invoke("set_capability_governance_request", { request });
    }

    async clearCapabilityGovernanceRequest(): Promise<void> {
        await invoke("clear_capability_governance_request");
    }

    async listenCapabilityGovernanceRequest<T>(
      handler: (request: T | null) => void,
    ): Promise<() => void> {
        return listen<T | null>("capability-governance-request-updated", (event) =>
          handler(event.payload),
        );
    }

    async getGraphModelBindingCatalog(): Promise<GraphModelBindingCatalog> {
        const snapshot = await this.getLocalEngineSnapshot();
        return {
            refreshedAtMs: snapshot.generatedAtMs,
            models: snapshot.registryModels.map((record) => ({
                modelId: record.modelId,
                status: record.status,
                residency: record.residency,
                backendId: record.backendId ?? null,
            })),
        };
    }

    async getGraphCapabilityCatalog(): Promise<GraphCapabilityCatalog> {
        const snapshot = await this.getLocalEngineSnapshot();
        const capabilities = snapshot.capabilities.map((family) => ({
            capabilityId: GRAPH_CAPABILITY_ALIASES[family.id] ?? family.id,
            familyId: family.id,
            label: family.label,
            status: family.status,
            availableCount: family.availableCount,
            operatorSummary: family.operatorSummary,
        }));

        return {
            refreshedAtMs: snapshot.generatedAtMs,
            activeIssueCount: snapshot.activeIssueCount,
            capabilities,
        };
    }

    async saveLocalEngineControlPlane(
      controlPlane: LocalEngineControlPlane,
    ): Promise<LocalEngineControlPlane> {
        return invoke("save_local_engine_control_plane", { controlPlane });
    }

    async refreshLocalEngineManagedSettings(): Promise<LocalEngineManagedSettingsSnapshot> {
        return invoke("refresh_local_engine_managed_settings");
    }

    async clearLocalEngineManagedSettingsOverrides(): Promise<LocalEngineManagedSettingsSnapshot> {
        return invoke("clear_local_engine_managed_settings_overrides");
    }

    async getSessionCompactionSnapshot(
      policy?: SessionCompactionPolicy | null,
    ): Promise<SessionCompactionSnapshot> {
        return invoke("get_session_compaction_snapshot", {
          policy: policy ?? null,
        });
    }

    async compactSession(input?: {
      sessionId?: string | null;
      policy?: SessionCompactionPolicy | null;
    }): Promise<SessionCompactionSnapshot> {
        return invoke("compact_session", {
          sessionId: input?.sessionId ?? null,
          policy: input?.policy ?? null,
        });
    }

    async getTeamMemorySnapshot(
      sessionId?: string | null,
    ): Promise<TeamMemorySyncSnapshot> {
        return invoke("get_team_memory_snapshot", { sessionId: sessionId ?? null });
    }

    async syncTeamMemory(input?: {
      sessionId?: string | null;
      actorLabel?: string | null;
      actorRole?: string | null;
      includeGovernanceCritical?: boolean | null;
    }): Promise<TeamMemorySyncSnapshot> {
        return invoke("sync_team_memory", {
          sessionId: input?.sessionId ?? null,
          actorLabel: input?.actorLabel ?? null,
          actorRole: input?.actorRole ?? null,
          includeGovernanceCritical: input?.includeGovernanceCritical ?? false,
        });
    }

    async forgetTeamMemoryEntry(
      entryId: string,
      sessionId?: string | null,
    ): Promise<TeamMemorySyncSnapshot> {
        return invoke("forget_team_memory_entry", {
          entryId,
          sessionId: sessionId ?? null,
        });
    }

    async stageLocalEngineOperation(input: {
      subjectKind: string;
      operation: string;
      sourceUri?: string | null;
      subjectId?: string | null;
      notes?: string | null;
    }): Promise<void> {
        await invoke("stage_local_engine_operation", { draft: input });
        await emit("local-engine-updated", {
          reason: "staged_operation_added",
          subjectKind: input.subjectKind,
          subjectId: input.subjectId ?? null,
          operation: input.operation,
        });
    }

    async removeLocalEngineOperation(operationId: string): Promise<void> {
        await invoke("remove_local_engine_operation", { operationId });
    }

    async promoteLocalEngineOperation(operationId: string): Promise<void> {
        await invoke("promote_local_engine_operation", { operationId });
    }

    async updateLocalEngineJobStatus(input: {
      jobId: string;
      status: string;
    }): Promise<void> {
        await invoke("update_local_engine_job_status", { input });
    }

    async retryLocalEngineParentPlaybookRun(runId: string): Promise<void> {
        await invoke("retry_local_engine_parent_playbook_run", { runId });
    }

    async resumeLocalEngineParentPlaybookRun(
      runId: string,
      stepId?: string | null,
    ): Promise<void> {
        await invoke("resume_local_engine_parent_playbook_run", {
          input: { runId, stepId: stepId ?? null },
        });
    }

    async dismissLocalEngineParentPlaybookRun(runId: string): Promise<void> {
        await invoke("dismiss_local_engine_parent_playbook_run", { runId });
    }

    async getKnowledgeCollections(): Promise<KnowledgeCollectionRecord[]> {
        return invoke("get_knowledge_collections");
    }

    async createKnowledgeCollection(
      name: string,
      description?: string | null,
    ): Promise<KnowledgeCollectionRecord> {
        return invoke("create_knowledge_collection", { name, description });
    }

    async resetKnowledgeCollection(collectionId: string): Promise<void> {
        await invoke("reset_knowledge_collection", { collectionId });
    }

    async deleteKnowledgeCollection(collectionId: string): Promise<void> {
        await invoke("delete_knowledge_collection", { collectionId });
    }

    async addKnowledgeTextEntry(
      collectionId: string,
      title: string,
      content: string,
    ): Promise<KnowledgeCollectionEntryRecord> {
        return invoke("add_knowledge_text_entry", { collectionId, title, content });
    }

    async importKnowledgeFile(
      collectionId: string,
      filePath: string,
    ): Promise<KnowledgeCollectionEntryRecord> {
        return invoke("import_knowledge_file", { collectionId, filePath });
    }

    async removeKnowledgeCollectionEntry(
      collectionId: string,
      entryId: string,
    ): Promise<void> {
        await invoke("remove_knowledge_collection_entry", { collectionId, entryId });
    }

    async getKnowledgeCollectionEntryContent(
      collectionId: string,
      entryId: string,
    ): Promise<KnowledgeCollectionEntryContent> {
        return invoke("get_knowledge_collection_entry_content", { collectionId, entryId });
    }

    async searchKnowledgeCollection(
      collectionId: string,
      query: string,
      limit?: number,
    ): Promise<KnowledgeCollectionSearchHit[]> {
        return invoke("search_knowledge_collection", { collectionId, query, limit });
    }

    async addKnowledgeCollectionSource(
      collectionId: string,
      uri: string,
      pollIntervalMinutes?: number | null,
    ): Promise<KnowledgeCollectionSourceRecord> {
        return invoke("add_knowledge_collection_source", {
          collectionId,
          uri,
          pollIntervalMinutes,
        });
    }

    async removeKnowledgeCollectionSource(
      collectionId: string,
      sourceId: string,
    ): Promise<void> {
        await invoke("remove_knowledge_collection_source", { collectionId, sourceId });
    }

    async getSkillSources(): Promise<SkillSourceRecord[]> {
        return invoke("get_skill_sources");
    }

    async getExtensionManifests(): Promise<ExtensionManifestRecord[]> {
        return invoke("get_extension_manifests");
    }

    async addSkillSource(
      uri: string,
      label?: string | null,
    ): Promise<SkillSourceRecord> {
        return invoke("add_skill_source", { uri, label });
    }

    async updateSkillSource(
      sourceId: string,
      uri: string,
      label?: string | null,
    ): Promise<SkillSourceRecord> {
        return invoke("update_skill_source", { sourceId, uri, label });
    }

    async removeSkillSource(sourceId: string): Promise<void> {
        await invoke("remove_skill_source", { sourceId });
    }

    async setSkillSourceEnabled(
      sourceId: string,
      enabled: boolean,
    ): Promise<SkillSourceRecord> {
        return invoke("set_skill_source_enabled", { sourceId, enabled });
    }

    async syncSkillSource(sourceId: string): Promise<SkillSourceRecord> {
        return invoke("sync_skill_source", { sourceId });
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

    async runNode(
        nodeType: string,
        config: any,
        input: string,
        globalConfig?: GraphGlobalConfig
    ): Promise<any> {
        return invoke("test_node_execution", { 
            nodeType, 
            config, 
            input, 
            nodeId: null, 
            sessionId: null,
            globalConfig: globalConfig ?? null,
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
        return liveAgentSummariesFromSnapshot(await this.getLocalEngineSnapshot());
    }

    async getFleetState(): Promise<FleetState> {
        return liveFleetStateFromSnapshot(await this.getLocalEngineSnapshot());
    }

    async getRuntimeCatalogEntries(): Promise<RuntimeCatalogEntry[]> {
        return liveRuntimeCatalogEntriesFromSnapshot(await this.getLocalEngineSnapshot());
    }

    async listWorkspaceWorkflows(): Promise<WorkspaceWorkflowSummary[]> {
        return invoke("list_workspace_workflows");
    }

    async stageRuntimeCatalogEntry(entryId: string, notes?: string): Promise<void> {
        const plan = runtimeCatalogEntryStagePlan(entryId);
        await this.stageLocalEngineOperation({
            subjectKind: plan.subjectKind,
            operation: plan.operation,
            sourceUri: `catalog:${entryId}`,
            subjectId: plan.subjectId,
            notes: notes?.trim() || plan.notes,
        });
    }

    async getConnectors(): Promise<ConnectorSummary[]> {
        return invoke<ConnectorSummary[]>("connector_list_catalog");
    }

    async getConnectorActions(connectorId: string): Promise<ConnectorActionDefinition[]> {
      return invoke("connector_list_actions", {
        connectorId,
      });
    }

    async runConnectorAction(
      request: ConnectorActionRequest
    ): Promise<ConnectorActionResult> {
      return invoke("connector_run_action", {
        connectorId: request.connectorId,
        actionId: request.actionId,
        input: request.input,
      });
    }

    async rememberConnectorApproval(
      request: ConnectorApprovalMemoryRequest
    ): Promise<void> {
      await invoke("connector_policy_memory_remember", {
        input: {
          connectorId: request.connectorId,
          actionId: request.actionId,
          actionLabel: request.actionLabel,
          policyFamily: request.policyFamily,
          scopeKey: request.scopeKey ?? null,
          scopeLabel: request.scopeLabel ?? null,
          sourceLabel: request.sourceLabel ?? null,
        },
      });
    }

    async configureConnector(
      request: ConnectorConfigureRequest
    ): Promise<ConnectorConfigureResult> {
      return invoke<ConnectorConfigureResult>("connector_configure", {
        connectorId: request.connectorId,
        input: request.input ?? {},
      });
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
        shieldApproved: input.shieldApproved ?? null,
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
        shieldApproved: input.shieldApproved ?? null,
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
        shieldApproved: input.shieldApproved ?? null,
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
        shieldApproved: input.shieldApproved ?? null,
      });
    }

    async walletMailConfigureAccount(
      input: WalletMailConfigureAccountInput
    ): Promise<WalletMailConfigureAccountResult> {
      return invoke<WalletMailConfigureAccountResult>("wallet_mail_configure_account", {
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
    }

    async walletMailListAccounts(): Promise<WalletMailConfiguredAccount[]> {
      return invoke<WalletMailConfiguredAccount[]>("wallet_mail_list_accounts");
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

    async triggerRemoteWorkflow(
      workflowId: string,
      payload?: Record<string, unknown>
    ): Promise<WorkflowRunReceipt> {
      return invoke("workflow_trigger_remote", {
        workflowId,
        payload: payload ?? null,
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
