#!/usr/bin/env node

/**
 * Hypervisor App local development replay server.
 *
 * This is a development replay scaffold over Hypervisor Daemon/Core contracts;
 * it is not a runtime, authority source, Agentgres truth source, or storage
 * authority. It exists to make the browser/dev Hypervisor App exercise
 * daemon-shaped routes before a live daemon or host bridge is attached.
 */

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8765;
const FIXED_NOW = "2026-06-19T12:00:00.000Z";
const WORKSPACE_ROOT = repoRoot;
const WORKSPACE_ROOT_LABEL = "ioi";
const ACTIVE_SESSION_REF = "session:hypervisor-dev-replay/qwen-local";
const ACTIVE_PROJECT_ID = "hypervisor-core";

function safeSegment(value) {
  return String(value ?? "unknown")
    .replace(/^[a-z]+:\/\//i, "")
    .replace(/[^a-zA-Z0-9_.:-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120) || "unknown";
}

function bodyHash(body) {
  return createHash("sha256").update(body || "").digest("hex").slice(0, 16);
}

function parseJsonBody(request) {
  return new Promise((resolveBody, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("error", reject);
    request.on("end", () => {
      if (!body.trim()) {
        resolveBody({});
        return;
      }
      try {
        resolveBody(JSON.parse(body));
      } catch (error) {
        error.status = 400;
        reject(error);
      }
    });
  });
}

function parseArgs(argv = process.argv.slice(2)) {
  const options = {
    host: DEFAULT_HOST,
    port: DEFAULT_PORT,
    evidencePath: "",
    once: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--host") {
      options.host = argv[++index] ?? options.host;
    } else if (arg === "--port") {
      options.port = Number(argv[++index] ?? options.port);
    } else if (arg === "--evidence") {
      options.evidencePath = argv[++index] ?? "";
    } else if (arg === "--once" || arg === "--smoke") {
      options.once = true;
    }
  }
  if (!Number.isFinite(options.port) || options.port < 0) {
    options.port = DEFAULT_PORT;
  }
  return options;
}

const modelMountSnapshot = {
  schema_version: "ioi.hypervisor.model_mount_inventory_snapshot.v1",
  source: "daemon-model-mount-inventory",
  checked_at: FIXED_NOW,
  routes: [
    {
      id: "model-route:hypervisor/default-local",
      role: "default-local",
      status: "active",
      privacy: "local",
    },
    {
      id: "model-route:hypervisor/qwen-local-agent-harness",
      role: "agent-harness-local",
      status: "active",
      privacy: "local",
    },
  ],
  endpoints: [
    {
      id: "model-endpoint:hypervisor/default-local",
      providerId: "provider:hypervisor-local",
      modelId: "model:local/codex-oss-qwen",
      status: "mounted",
      privacyClass: "local",
      openAiCompatibleBaseUrl: "http://127.0.0.1:8765/v1",
    },
  ],
  instances: [
    {
      id: "model-instance:hypervisor/default-local",
      endpointId: "model-endpoint:hypervisor/default-local",
      providerId: "provider:hypervisor-local",
      modelId: "model:local/codex-oss-qwen",
      status: "loaded",
    },
  ],
};

const modelCapabilities = {
  schema_version: "ioi.hypervisor.model_capabilities.v1",
  modelCapabilities: [
    {
      id: "model-capability:qwen-local/chat",
      label: "Local Qwen chat route",
      status: "active",
      readinessStatus: "ready",
      requiredScopes: ["scope:model.invoke", "scope:receipt.write"],
      receiptTypes: ["model_route_invocation", "session_lifecycle"],
      policyTarget: "policy:model-route/local-private",
      lastRepairReceiptRefs: ["receipt://model-route/qwen-local/ready"],
      lastRepairSummary: "Local OpenAI-compatible route is mounted for dev replay.",
    },
  ],
};

const toolCatalog = {
  schema_version: "ioi.hypervisor.tool_catalog.v1",
  tools: [
    {
      id: "tool:workspace.read",
      label: "Workspace read",
      status: "active",
      readinessStatus: "ready",
      requiredScopes: ["scope:workspace.read"],
      receiptTypes: ["workspace_projection"],
    },
    {
      id: "tool:terminal.attach",
      label: "Terminal attach",
      status: "active",
      readinessStatus: "ready",
      requiredScopes: ["scope:terminal.attach", "scope:receipt.write"],
      receiptTypes: ["terminal_transcript"],
    },
  ],
};

const authoritySnapshot = {
  schema_version: "ioi.hypervisor.model_mount_authority.v1",
  grants: [
    {
      id: "wallet.grant.hypervisor.local-qwen",
      grantId: "wallet.grant.hypervisor.local-qwen",
      state: "active",
      allowed: ["scope:model.invoke", "scope:workspace.read", "scope:receipt.write"],
      denied: ["scope:secret.plaintext.export"],
      vaultRefs: ["vault://wallet/local-qwen/dev-replay"],
      receiptRef: "receipt://authority/local-qwen/grant",
      receiptRefs: ["receipt://authority/local-qwen/grant"],
      expiresAt: "2026-06-19T18:00:00.000Z",
    },
  ],
  tokens: [
    {
      id: "token:dev-replay/local-qwen",
      state: "active",
      allowedScopes: ["scope:model.invoke"],
      deniedScopes: ["scope:secret.plaintext.export"],
      receiptRef: "receipt://authority/local-qwen/token",
      expiresAt: "2026-06-19T18:00:00.000Z",
    },
  ],
  vaultRefs: [
    {
      id: "vault://wallet/local-qwen/dev-replay",
      label: "Local Qwen dev replay vault ref",
      purpose: "No plaintext provider secret is released in dev replay.",
      state: "active",
      lastResolved: FIXED_NOW,
    },
  ],
};

const authorityEvidence = {
  schema_version: "ioi.authority-evidence-summary-list.v1",
  summaries: [
    {
      id: "authority-evidence:local-qwen",
      receipt_ref: "receipt://authority/local-qwen/grant",
      summary:
        "wallet.network grant projection admits local Qwen model invocation for dev replay.",
      state_root_ref: "agentgres://state-root/authority/local-qwen",
      status: "admitted",
    },
  ],
  items: [
    {
      id: "authority-evidence:terminal-attach",
      receipt_ref: "receipt://authority/terminal-attach",
      summary:
        "Terminal attach remains a daemon-admitted projection in replay mode.",
      state_root_ref: "agentgres://state-root/authority/terminal-attach",
      status: "admitted",
    },
  ],
};

const replayEpochMs = Date.parse(FIXED_NOW);

const shieldPolicyState = {
  version: 1,
  global: {
    reads: "auto",
    writes: "confirm",
    admin: "confirm",
    expert: "block",
    automations: "confirm_on_create",
    dataHandling: "local_only",
  },
  overrides: {
    "connector:workspace.fs": {
      reads: "auto",
      writes: "confirm",
      admin: "confirm",
      expert: "block",
      automations: "confirm_on_create",
      dataHandling: "local_only",
      inheritGlobal: false,
    },
  },
};

const shieldApprovalMemorySnapshot = {
  generatedAtMs: replayEpochMs,
  activeDecisionCount: 1,
  recentReceiptCount: 1,
  decisions: [
    {
      decisionId: "shield-decision:dev-replay/workspace-read",
      connectorId: "connector:workspace.fs",
      actionId: "workspace.read",
      actionLabel: "Read workspace file tree",
      policyFamily: "reads",
      scopeKey: "scope:workspace.read",
      scopeLabel: "Workspace read",
      scopeMode: "connector_policy_family",
      sourceLabel: "Hypervisor dev replay",
      createdAtMs: replayEpochMs,
      lastMatchedAtMs: replayEpochMs,
      expiresAtMs: null,
      matchCount: 4,
      status: "active",
    },
  ],
  recentReceipts: [
    {
      receiptId: "receipt://authority/workspace-read/dev-replay",
      timestampMs: replayEpochMs,
      hookKind: "connector_policy_decision",
      status: "admitted",
      summary: "wallet.network authority projection admitted replay workspace reads.",
      connectorId: "connector:workspace.fs",
      actionId: "workspace.read",
      decisionId: "shield-decision:dev-replay/workspace-read",
    },
  ],
};

const localEngineControlPlane = {
  runtime: {
    mode: "dev_replay",
    endpoint: "http://127.0.0.1:8765/v1",
    defaultModel: "model:local/codex-oss-qwen",
    baselineRole:
      "Daemon-admitted local Qwen route for browser dev sessions and harness adapters.",
    kernelAuthority:
      "Hypervisor Daemon executes Core contracts; wallet.network grants authority; Agentgres admits receipts and replay truth.",
  },
  storage: {
    modelsPath: `${WORKSPACE_ROOT}/.tmp/hypervisor-dev-replay/models`,
    backendsPath: `${WORKSPACE_ROOT}/.tmp/hypervisor-dev-replay/backends`,
    artifactsPath: `${WORKSPACE_ROOT}/.tmp/hypervisor-dev-replay/artifacts`,
    cachePath: `${WORKSPACE_ROOT}/.tmp/hypervisor-dev-replay/cache`,
  },
  watchdog: {
    enabled: true,
    idleCheckEnabled: true,
    idleTimeout: "15m",
    busyCheckEnabled: true,
    busyTimeout: "45m",
    checkInterval: "30s",
    forceEvictionWhenBusy: false,
    lruEvictionMaxRetries: 2,
    lruEvictionRetryInterval: "10s",
  },
  memory: {
    reclaimerEnabled: true,
    thresholdPercent: 82,
    preferGpu: false,
    targetResource: "system_memory",
  },
  backendPolicy: {
    maxConcurrency: 4,
    maxQueuedRequests: 16,
    parallelBackendLoads: 1,
    allowParallelRequests: true,
    healthProbeInterval: "10s",
    logLevel: "info",
    autoShutdownOnIdle: false,
  },
  responses: {
    retainReceiptsDays: 14,
    persistArtifacts: true,
    allowStreaming: true,
    storeRequestPreviews: true,
  },
  api: {
    bindAddress: "127.0.0.1:8765",
    remoteAccessEnabled: false,
    corsMode: "dev-localhost",
    authMode: "wallet-network-dev-replay",
  },
  launcher: {
    autoStartOnBoot: false,
    reopenChatOnLaunch: true,
    autoCheckUpdates: false,
    releaseChannel: "dev-replay",
    showKernelConsole: false,
  },
  galleries: [
    {
      id: "gallery:local-harness-adapters",
      kind: "harness_adapter",
      label: "Local Agent Harness Adapters",
      uri: "internal://hypervisor/harness-adapters/local-qwen",
      enabled: true,
      syncStatus: "synced",
      compatibilityTier: "dev_replay",
    },
  ],
  environment: [
    { key: "HYPERVISOR_DEV_REPLAY", value: "1", secret: false },
    { key: "OPENAI_BASE_URL", value: "http://127.0.0.1:8765/v1", secret: false },
  ],
  notes: [
    "Dev replay is scaffolding over daemon/Core contracts, not runtime truth.",
    "Local Qwen adapters are proposal sources until daemon admission writes receipts.",
  ],
};

const localEngineManagedSettings = {
  syncStatus: "ready",
  summary: "Dev replay managed settings are loaded from deterministic local payloads.",
  activeChannelId: "managed-settings:dev-replay",
  activeChannelLabel: "Hypervisor dev replay",
  activeSourceUri: "internal://hypervisor/dev-replay/managed-settings",
  lastRefreshedAtMs: replayEpochMs,
  lastSuccessfulRefreshAtMs: replayEpochMs,
  lastFailedRefreshAtMs: null,
  refreshError: null,
  localOverrideCount: 0,
  localOverrideFields: [],
  channels: [
    {
      channelId: "managed-settings:dev-replay",
      label: "Hypervisor dev replay",
      sourceUri: "internal://hypervisor/dev-replay/managed-settings",
      status: "active",
      verificationStatus: "verified",
      summary: "Deterministic settings bundle for browser parity work.",
      precedence: 10,
      authorityLabel: "wallet.network dev grant projection",
      signatureAlgorithm: "dev-replay",
      profileId: "profile:local-qwen-dev-replay",
      schemaVersion: 1,
      issuedAtMs: replayEpochMs,
      expiresAtMs: null,
      refreshedAtMs: replayEpochMs,
      localOverrideCount: 0,
      overriddenFields: [],
    },
  ],
};

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function localEngineSnapshot(controlPlane = localEngineControlPlane) {
  return {
    generatedAtMs: replayEpochMs,
    totalNativeTools: 9,
    pendingControlCount: 1,
    pendingApprovalCount: 1,
    activeIssueCount: 0,
    capabilities: [
      {
        id: "workspace",
        label: "Workspace",
        description: "File tree, editor, source control, terminal, problems, ports, and logs.",
        status: "ready",
        availableCount: 7,
        toolNames: [
          "workspace.inspect",
          "workspace.read_file",
          "workspace.git_status",
          "terminal.attach",
        ],
        operatorSummary: "Replay-backed workspace tools are available through daemon-shaped calls.",
      },
      {
        id: "model_route",
        label: "Model routes",
        description: "Local OpenAI-compatible Qwen route used by session harness adapters.",
        status: "ready",
        availableCount: 2,
        toolNames: ["model.invoke", "model.snapshot"],
        operatorSummary: "Local Qwen route is mounted for dev replay and session launches.",
      },
      {
        id: "agent_harness",
        label: "Agent harness adapters",
        description: "Codex OSS, DeepSeek TUI, Claude Code example, and generic CLI adapters.",
        status: "ready",
        availableCount: 4,
        toolNames: ["harness.bind", "harness.spawn", "terminal.attach"],
        operatorSummary: "Adapters act as proposal sources before daemon admission.",
      },
    ],
    pendingControls: [
      {
        itemId: "control:dev-replay/model-route",
        title: "Confirm local Qwen route for session launch",
        summary: "wallet.network grant projection is required before model invocation.",
        status: "pending",
        severity: "medium",
        requestedAtMs: replayEpochMs,
        dueAtMs: null,
        approvalScope: "scope:model.invoke",
        sensitiveActionType: "model_route",
        recommendedAction: "Admit local dev replay route",
        recoveryHint: "Use the replay authority projection, not provider trust.",
        requestHash: bodyHash("local-qwen-route"),
      },
    ],
    jobs: [
      {
        jobId: "job:dev-replay/qwen-route-health",
        title: "Local Qwen route health",
        summary: "OpenAI-compatible replay endpoint is serving deterministic responses.",
        status: "running",
        origin: "dev_replay",
        subjectKind: "model_route",
        operation: "health_probe",
        createdAtMs: replayEpochMs - 18_000,
        updatedAtMs: replayEpochMs,
        progressPercent: 92,
        sourceUri: "http://127.0.0.1:8765/v1/model-mount/snapshot",
        subjectId: "model-route:hypervisor/default-local",
        backendId: "backend:dev-replay/openai-compatible",
        severity: "info",
        approvalScope: "scope:model.invoke",
      },
    ],
    recentActivity: [
      {
        eventId: "event:dev-replay/workspace-snapshot",
        sessionId: ACTIVE_SESSION_REF,
        family: "workspace",
        title: "Workbench snapshot served",
        toolName: "workspace.inspect",
        timestampMs: replayEpochMs,
        success: true,
        operation: "read",
        subjectKind: "project",
        subjectId: ACTIVE_PROJECT_ID,
        backendId: "backend:dev-replay/workspace",
        errorClass: null,
      },
      {
        eventId: "event:dev-replay/session-launch",
        sessionId: ACTIVE_SESSION_REF,
        family: "agent_harness",
        title: "Codex OSS/Qwen session launch admitted",
        toolName: "harness.spawn",
        timestampMs: replayEpochMs - 7_000,
        success: true,
        operation: "spawn",
        subjectKind: "session",
        subjectId: ACTIVE_SESSION_REF,
        backendId: "backend:dev-replay/openai-compatible",
        errorClass: null,
      },
    ],
    registryModels: [
      {
        modelId: "model:local/codex-oss-qwen",
        status: "mounted",
        residency: "local_private",
        installedAtMs: replayEpochMs - 120_000,
        updatedAtMs: replayEpochMs,
        sourceUri: "ollama://qwen2.5-coder/dev-replay",
        backendId: "backend:dev-replay/openai-compatible",
        hardwareProfile: "cpu-local",
        jobId: "job:dev-replay/qwen-route-health",
        bytesTransferred: 0,
      },
    ],
    managedBackends: [
      {
        backendId: "backend:dev-replay/openai-compatible",
        status: "running",
        health: "healthy",
        installedAtMs: replayEpochMs - 120_000,
        updatedAtMs: replayEpochMs,
        sourceUri: "http://127.0.0.1:8765/v1",
        alias: "Local Qwen OpenAI-compatible route",
        hardwareProfile: "cpu-local",
        jobId: "job:dev-replay/qwen-route-health",
        installPath: `${WORKSPACE_ROOT}/.tmp/hypervisor-dev-replay/models/qwen`,
        entrypoint: "hypervisor-app-dev-replay-server.mjs",
        healthEndpoint: "http://127.0.0.1:8765/v1/hypervisor/dev-replay/status",
        pid: process.pid,
        lastStartedAtMs: replayEpochMs - 120_000,
        lastHealthCheckAtMs: replayEpochMs,
      },
      {
        backendId: "backend:dev-replay/workspace",
        status: "running",
        health: "healthy",
        installedAtMs: replayEpochMs - 120_000,
        updatedAtMs: replayEpochMs,
        sourceUri: "internal://hypervisor/workbench/replay",
        alias: "Replay workspace bridge",
        hardwareProfile: "local-filesystem",
        jobId: null,
        installPath: WORKSPACE_ROOT,
        entrypoint: "window.__HYPERVISOR_HOST_BRIDGE__",
        healthEndpoint: "http://127.0.0.1:8765/v1/hypervisor/workbench/snapshot",
        pid: process.pid,
        lastStartedAtMs: replayEpochMs - 120_000,
        lastHealthCheckAtMs: replayEpochMs,
      },
    ],
    galleryCatalogs: [
      {
        galleryId: "gallery:local-harness-adapters",
        kind: "harness_adapter",
        label: "Local Agent Harness Adapters",
        sourceUri: "internal://hypervisor/harness-adapters/local-qwen",
        syncStatus: "synced",
        compatibilityTier: "dev_replay",
        enabled: true,
        entryCount: 4,
        updatedAtMs: replayEpochMs,
        lastJobId: null,
        lastSyncedAtMs: replayEpochMs,
        catalogPath: "apps/hypervisor/src/domain/harnessAdapterModel.ts",
        sampleEntries: [
          {
            entryId: "agent-harness-adapter:codex_cli",
            label: "Codex OSS / Qwen",
            summary: "Local CLI harness adapter with terminal transcript projection.",
            sourceUri: "internal://hypervisor/harness-adapters/codex-oss-qwen",
          },
          {
            entryId: "agent-harness-adapter:deepseek_tui",
            label: "DeepSeek TUI / Qwen",
            summary: "TUI adapter proposal source over the same local model route.",
            sourceUri: "internal://hypervisor/harness-adapters/deepseek-tui-qwen",
          },
        ],
        lastError: null,
      },
    ],
    workerTemplates: [
      {
        templateId: "worker:generic-cli-qwen",
        label: "Generic CLI / Qwen worker",
        role: "Run local command-line task proposals before daemon admission.",
        summary: "Generic CLI adapter for local Qwen-backed session iteration.",
        defaultBudget: 1200,
        maxRetries: 1,
        allowedTools: ["workspace.read", "terminal.attach", "receipt.write"],
        completionContract: {
          successCriteria: "Produce a receipt-bound proposal or terminal transcript.",
          expectedOutput: "Artifact refs, transcript refs, and readiness status.",
          mergeMode: "operator_review",
          verificationHint: "Receipts must be admitted by Agentgres before replay truth.",
        },
        workflows: [
          {
            workflowId: "workflow:generic-cli/public-code-edit-smoke",
            harnessWorkflowId: "harness-workflow:generic-cli/code-edit",
            harnessActivationId: "harness-activation:generic-cli/qwen",
            harnessHash: bodyHash("generic-cli-qwen"),
            label: "Public code edit smoke",
            summary: "Exercise local terminal attach and workspace patch proposal.",
            goalTemplate: "Inspect the target file, propose a minimal patch, and attach receipts.",
            triggerIntents: ["code_edit", "workbench_recovery"],
            defaultBudget: 1200,
            maxRetries: 1,
            allowedTools: ["workspace.read", "terminal.attach"],
            completionContract: {
              successCriteria: "Terminal transcript and patch proposal are visible.",
              expectedOutput: "proposal_ref and transcript_ref",
              mergeMode: "operator_review",
              verificationHint: "Use replay terminal transcript for local demo.",
            },
          },
        ],
      },
    ],
    agentPlaybooks: [
      {
        playbookId: "playbook:codex-oss-qwen-session",
        label: "Codex OSS / Qwen session",
        summary: "Launch Codex OSS as an Agent Harness Adapter over the local Qwen route.",
        goalTemplate:
          "Bind project context, launch the adapter, attach terminal, and emit receipts.",
        triggerIntents: ["new_session", "workbench_task", "code_review"],
        recommendedFor: ["Projects", "Workbench", "Sessions"],
        defaultBudget: 2400,
        completionContract: {
          successCriteria: "Session reaches ready state with terminal attach and receipts.",
          expectedOutput: "session_ref, terminal_ref, receipt_refs",
          mergeMode: "operator_review",
          verificationHint: "Readiness must come from daemon-shaped replay admission.",
        },
        steps: [
          {
            stepId: "bind",
            label: "Bind adapter",
            summary: "Create daemon-admitted recipe and model route binding.",
            workerTemplateId: "worker:generic-cli-qwen",
            workerWorkflowId: "workflow:generic-cli/public-code-edit-smoke",
            goalTemplate: "Bind adapter to project and local Qwen model route.",
            dependsOn: [],
          },
          {
            stepId: "spawn",
            label: "Spawn session",
            summary: "Start terminal-backed harness process and project transcript.",
            workerTemplateId: "worker:generic-cli-qwen",
            workerWorkflowId: "workflow:generic-cli/public-code-edit-smoke",
            goalTemplate: "Launch session and attach terminal.",
            dependsOn: ["bind"],
          },
        ],
      },
    ],
    parentPlaybookRuns: [
      {
        runId: "run:codex-oss-qwen/dev-replay",
        parentSessionId: ACTIVE_SESSION_REF,
        playbookId: "playbook:codex-oss-qwen-session",
        playbookLabel: "Codex OSS / Qwen session",
        status: "running",
        latestPhase: "terminal_attached",
        summary: "Local Qwen-backed harness session is ready in dev replay.",
        currentStepId: "spawn",
        currentStepLabel: "Spawn session",
        activeChildSessionId: ACTIVE_SESSION_REF,
        startedAtMs: replayEpochMs - 30_000,
        updatedAtMs: replayEpochMs,
        completedAtMs: null,
        errorClass: null,
        steps: [
          {
            stepId: "bind",
            label: "Bind adapter",
            summary: "Recipe, binding, launch, and readiness projections admitted.",
            status: "completed",
            childSessionId: ACTIVE_SESSION_REF,
            templateId: "worker:generic-cli-qwen",
            workflowId: "workflow:generic-cli/public-code-edit-smoke",
            updatedAtMs: replayEpochMs - 14_000,
            completedAtMs: replayEpochMs - 14_000,
            errorClass: null,
            receipts: [
              {
                eventId: "receipt-event:adapter-bind",
                timestampMs: replayEpochMs - 14_000,
                phase: "binding",
                status: "admitted",
                success: true,
                summary: "Harness adapter binding admitted for local Qwen route.",
                receiptRef: "receipt://harness-adapter/codex-oss-qwen/bind",
                childSessionId: ACTIVE_SESSION_REF,
                templateId: "worker:generic-cli-qwen",
                workflowId: "workflow:generic-cli/public-code-edit-smoke",
                errorClass: null,
                artifactIds: ["artifact://harness-adapter/codex-oss-qwen/binding"],
              },
            ],
          },
          {
            stepId: "spawn",
            label: "Spawn session",
            summary: "Terminal attach is streaming replay transcript chunks.",
            status: "running",
            childSessionId: ACTIVE_SESSION_REF,
            templateId: "worker:generic-cli-qwen",
            workflowId: "workflow:generic-cli/public-code-edit-smoke",
            updatedAtMs: replayEpochMs,
            completedAtMs: null,
            errorClass: null,
            receipts: [
              {
                eventId: "receipt-event:terminal-attach",
                timestampMs: replayEpochMs,
                phase: "terminal",
                status: "admitted",
                success: true,
                summary: "Terminal transcript attached for dev replay session.",
                receiptRef: "receipt://terminal/dev-replay/transcript",
                childSessionId: ACTIVE_SESSION_REF,
                templateId: "worker:generic-cli-qwen",
                workflowId: "workflow:generic-cli/public-code-edit-smoke",
                errorClass: null,
                artifactIds: ["artifact://terminal/dev-replay/stdout"],
              },
            ],
          },
        ],
      },
    ],
    controlPlaneSchemaVersion: 1,
    controlPlaneProfileId: "profile:local-qwen-dev-replay",
    controlPlaneMigrations: [
      {
        migrationId: "migration:dev-replay/bootstrap",
        fromVersion: 0,
        toVersion: 1,
        appliedAtMs: replayEpochMs,
        summary: "Seed local replay control plane for browser parity.",
        details: [
          "Mounted local Qwen model route.",
          "Enabled workspace and harness adapter projections.",
        ],
      },
    ],
    controlPlane: cloneJson(controlPlane),
    managedSettings: cloneJson(localEngineManagedSettings),
    stagedOperations: [],
  };
}

function capabilityAuthority(tierId, tierLabel, summary) {
  return {
    tierId,
    tierLabel,
    governedProfileId: "guided_default",
    governedProfileLabel: "Guided default",
    summary,
    detail:
      "Authority is projected from wallet.network grants; Hypervisor Core does not replace wallet.network.",
    signals: ["wallet.network grant", "daemon admission", "Agentgres receipt refs"],
  };
}

function capabilityLease(availability, label, modeLabel, requiresAuth = false) {
  return {
    availability,
    availabilityLabel: label,
    runtimeTargetId: "runtime:hypervisor-dev-replay",
    runtimeTargetLabel: "Hypervisor dev replay daemon route",
    modeId: "lease:dev-replay/local",
    modeLabel,
    summary: `${label} through deterministic local replay.`,
    detail:
      "Lease projection is dev scaffolding over daemon contracts and does not create runtime truth.",
    requiresAuth,
    signals: ["local replay", "receipt bound", "daemon shaped"],
  };
}

function capabilityRegistryEntry({
  entryId,
  kind,
  label,
  summary,
  sourceKind,
  sourceLabel,
  sourceUri = null,
  governingFamilyId = null,
  relatedGoverningEntryIds = [],
}) {
  return {
    entryId,
    kind,
    label,
    summary,
    sourceKind,
    sourceLabel,
    sourceUri,
    trustPosture: "governed_local",
    governedProfile: "guided_default",
    availability: "available",
    statusLabel: "Ready",
    whySelectable: "Available in dev replay after daemon-shaped admission.",
    governingFamilyId,
    relatedGoverningEntryIds,
    governingFamilyHints: governingFamilyId ? [governingFamilyId] : [],
    runtimeTarget: "runtime:hypervisor-dev-replay",
    leaseMode: "local_private_dev_replay",
    authority: capabilityAuthority(
      "governed",
      "Governed local",
      "Requires wallet.network-scoped grants before consequential execution.",
    ),
    lease: capabilityLease("available", "Available", "Local private dev replay"),
  };
}

const capabilityConnectors = [
  {
    id: "connector:workspace.fs",
    pluginId: "workspace_fs",
    name: "Replay workspace",
    provider: "Hypervisor Daemon dev replay",
    category: "developer",
    description: "File tree, editor, source-control, terminal, problems, ports, and logs.",
    status: "connected",
    authMode: "wallet_capability",
    scopes: ["scope:workspace.read", "scope:workspace.write", "scope:terminal.attach"],
    lastSyncAtUtc: FIXED_NOW,
    notes: "Backed by the local replay host bridge.",
  },
  {
    id: "connector:agent-harness.codex-oss-qwen",
    pluginId: "agent_harness_adapter",
    name: "Codex OSS / Qwen",
    provider: "Local Agent Harness Adapter",
    category: "developer",
    description: "Proposal-source adapter that launches through daemon-admitted recipes.",
    status: "connected",
    authMode: "wallet_capability",
    scopes: ["scope:model.invoke", "scope:terminal.attach", "scope:receipt.write"],
    lastSyncAtUtc: FIXED_NOW,
    notes: "External harness adapter, not a Hypervisor client.",
  },
];

const capabilitySkillCatalog = [
  {
    skill_hash: "skill:hypervisor-workbench-open",
    name: "Open replay-backed Workbench",
    description: "Mount a default project session with file tree, terminal, and receipts.",
    lifecycle_state: "promoted",
    success_rate_bps: 9800,
    sample_size: 25,
    stale: false,
    evidence_refs: ["receipt://workspace/dev-replay/bootstrap"],
    updated_at_ms: replayEpochMs,
  },
  {
    skill_hash: "skill:launch-local-qwen-session",
    name: "Launch local Qwen session",
    description: "Bind, launch, spawn, and attach a terminal-backed Agent Harness Adapter.",
    lifecycle_state: "promoted",
    success_rate_bps: 9600,
    sample_size: 18,
    stale: false,
    evidence_refs: ["receipt://session/lifecycle/dev-replay"],
    updated_at_ms: replayEpochMs,
  },
];

const capabilitySkillSources = [
  {
    sourceId: "skill-source:hypervisor-dev-replay",
    label: "Hypervisor dev replay skills",
    uri: "internal://hypervisor/dev-replay/skills",
    kind: "internal",
    enabled: true,
    syncStatus: "synced",
    lastSyncedAtMs: replayEpochMs,
    discoveredSkills: [],
  },
];

const capabilityExtensionManifests = [
  {
    extensionId: "extension:hypervisor-local-demo",
    manifestKind: "codex_plugin",
    manifestPath: "internal://hypervisor/dev-replay/extensions/hypervisor-local-demo/plugin.json",
    rootPath: "internal://hypervisor/dev-replay/extensions/hypervisor-local-demo",
    sourceLabel: "Hypervisor dev replay",
    sourceUri: "internal://hypervisor/dev-replay/extensions",
    sourceKind: "internal",
    enabled: true,
    name: "hypervisor-local-demo",
    displayName: "Hypervisor Local Demo",
    version: "0.1.0",
    description: "Replay-backed app package for local reference-grade Hypervisor demo.",
    developerName: "IOI",
    authorName: "IOI",
    authorEmail: null,
    authorUrl: null,
    category: "developer",
    trustPosture: "governed_local",
    governedProfile: "guided_default",
    homepage: null,
    repository: null,
    license: null,
    keywords: ["hypervisor", "dev-replay", "local-qwen"],
    capabilities: ["workspace", "sessions", "receipts"],
    defaultPrompts: ["Launch the local Qwen workbench session."],
    contributions: [
      {
        kind: "application",
        label: "Workbench",
        path: "/workbench",
        itemCount: 1,
        detail: "Default project inspection and editing mode.",
      },
    ],
    filesystemSkills: [],
    marketplaceName: "hypervisor-local-demo",
    marketplaceDisplayName: "Hypervisor Local Demo",
    marketplaceCategory: "developer",
    marketplaceInstallationPolicy: "local",
    marketplaceAuthenticationPolicy: "wallet_capability",
    marketplaceProducts: ["hypervisor-app"],
  },
];

function capabilityRegistrySnapshot() {
  const localEngine = localEngineSnapshot();
  const entries = [
    capabilityRegistryEntry({
      entryId: "engine-family:workspace",
      kind: "engine_family",
      label: "Workspace tools",
      summary: "Replay-backed workspace, terminal, and source-control tools.",
      sourceKind: "daemon_route",
      sourceLabel: "Hypervisor dev replay",
      sourceUri: "/v1/hypervisor/workbench/snapshot",
    }),
    capabilityRegistryEntry({
      entryId: "engine-family:agent_harness",
      kind: "engine_family",
      label: "Agent harness adapters",
      summary: "Local Qwen-backed harness adapters launched through daemon contracts.",
      sourceKind: "daemon_route",
      sourceLabel: "Hypervisor dev replay",
      sourceUri: "/v1/hypervisor/harness-adapters",
    }),
    capabilityRegistryEntry({
      entryId: "connector:workspace.fs",
      kind: "connector",
      label: "Replay workspace",
      summary: "Project workspace bridge with file tree, terminal, and receipts.",
      sourceKind: "host_bridge",
      sourceLabel: "Replay host bridge",
      sourceUri: "/v1/hypervisor/dev-host-bridge/invoke",
      governingFamilyId: "engine-family:workspace",
      relatedGoverningEntryIds: ["engine-family:workspace"],
    }),
    capabilityRegistryEntry({
      entryId: "connector:agent-harness.codex-oss-qwen",
      kind: "connector",
      label: "Codex OSS / Qwen",
      summary: "Agent Harness Adapter proposal source for local sessions.",
      sourceKind: "daemon_route",
      sourceLabel: "Hypervisor dev replay",
      sourceUri: "/v1/hypervisor/harness-adapters",
      governingFamilyId: "engine-family:agent_harness",
      relatedGoverningEntryIds: ["engine-family:agent_harness"],
    }),
    capabilityRegistryEntry({
      entryId: "skill:skill:launch-local-qwen-session",
      kind: "skill",
      label: "Launch local Qwen session",
      summary: "Bind, launch, spawn, attach terminal, and emit receipts.",
      sourceKind: "daemon_route",
      sourceLabel: "Hypervisor dev replay",
      sourceUri: "/v1/hypervisor/sessions",
      governingFamilyId: "engine-family:agent_harness",
      relatedGoverningEntryIds: ["engine-family:agent_harness"],
    }),
    capabilityRegistryEntry({
      entryId: "model:model:local/codex-oss-qwen",
      kind: "model",
      label: "Local Qwen route",
      summary: "Local OpenAI-compatible model route mounted for dev replay.",
      sourceKind: "model_mount",
      sourceLabel: "Model mount snapshot",
      sourceUri: "/v1/model-mount/snapshot",
      governingFamilyId: "engine-family:agent_harness",
      relatedGoverningEntryIds: ["engine-family:agent_harness"],
    }),
    capabilityRegistryEntry({
      entryId: "extension:extension:hypervisor-local-demo",
      kind: "extension",
      label: "Hypervisor Local Demo",
      summary: "Replay-backed application package for local functional demo.",
      sourceKind: "internal",
      sourceLabel: "Hypervisor dev replay",
      sourceUri: "internal://hypervisor/dev-replay/extensions",
      governingFamilyId: "engine-family:workspace",
      relatedGoverningEntryIds: ["engine-family:workspace"],
    }),
  ];

  return {
    generatedAtMs: replayEpochMs,
    summary: {
      generatedAtMs: replayEpochMs,
      totalEntries: entries.length,
      connectorCount: capabilityConnectors.length,
      connectedConnectorCount: capabilityConnectors.length,
      runtimeSkillCount: capabilitySkillCatalog.length,
      trackedSourceCount: capabilitySkillSources.length,
      filesystemSkillCount: 0,
      extensionCount: capabilityExtensionManifests.length,
      modelCount: localEngine.registryModels.length,
      backendCount: localEngine.managedBackends.length,
      nativeFamilyCount: localEngine.capabilities.length,
      pendingEngineControlCount: localEngine.pendingControlCount,
      activeIssueCount: localEngine.activeIssueCount,
      authoritativeSourceCount: 4,
    },
    entries,
    connectors: cloneJson(capabilityConnectors),
    skillCatalog: cloneJson(capabilitySkillCatalog),
    skillSources: cloneJson(capabilitySkillSources),
    extensionManifests: cloneJson(capabilityExtensionManifests),
    localEngine,
  };
}

function capabilityGovernanceRequest(input = {}) {
  const action = input.action === "baseline" ? "baseline" : "widen";
  const entry =
    capabilityRegistrySnapshot().entries.find(
      (candidate) => candidate.entryId === input.capabilityEntryId,
    ) ?? capabilityRegistrySnapshot().entries[2];
  return {
    requestId: input.requestId ?? `capability-governance-request:${safeSegment(entry.entryId)}`,
    createdAtMs: replayEpochMs,
    status: "pending",
    action,
    capabilityEntryId: entry.entryId,
    capabilityLabel: entry.label,
    capabilityKind: entry.kind,
    governingEntryId: input.governingEntryId ?? entry.governingFamilyId ?? null,
    governingLabel: entry.governingFamilyId ?? "Guided default",
    governingKind: "engine_family",
    connectorId: input.connectorId ?? "connector:workspace.fs",
    connectorLabel: input.connectorLabel ?? "Replay workspace",
    sourceLabel: entry.sourceLabel,
    authorityTierLabel: entry.authority.tierLabel,
    governedProfileLabel: entry.authority.governedProfileLabel,
    leaseModeLabel: entry.lease.modeLabel,
    whySelectable: entry.whySelectable,
    headline: `${action === "baseline" ? "Restore" : "Widen"} ${entry.label}`,
    detail:
      "Dev replay stages capability governance through wallet.network authority projections.",
    requestedState: cloneJson(shieldPolicyState),
  };
}

function capabilityGovernanceProposal(input = {}) {
  const request = capabilityGovernanceRequest(input);
  return {
    capabilityEntryId: request.capabilityEntryId,
    capabilityLabel: request.capabilityLabel,
    action: request.action,
    recommendedTargetEntryId: request.governingEntryId ?? "engine-family:workspace",
    comparedEntryId: input.comparisonEntryId ?? null,
    comparedEntryLabel: input.comparisonEntryId ? "Compared capability" : null,
    targets: [
      {
        targetEntryId: request.governingEntryId ?? "engine-family:workspace",
        targetLabel: request.governingLabel ?? "Workspace tools",
        targetKind: request.governingKind ?? "engine_family",
        targetSummary: "Guided default keeps writes approval-bound.",
        recommendationReason: "Matches local dev replay policy without provider-trust fallback.",
        deltaSummary: "No authority bypass; request remains wallet-scoped.",
        request,
        deltaMagnitude: 1,
      },
    ],
  };
}

const projectRecords = [];

function projectNameFromRepositoryUrl(repositoryUrl = "") {
  const normalized = String(repositoryUrl).trim().replace(/\/+$/, "");
  const name = normalized.split("/").pop() ?? "";
  return name.replace(/\.git$/i, "") || "new-project";
}

function buildProjectStateProjection(selectedProjectId = "") {
  const selected =
    selectedProjectId && projectRecords.some((project) => project.project_id === selectedProjectId)
      ? selectedProjectId
      : projectRecords[0]?.project_id ?? "";
  return {
    schema_version: "ioi.hypervisor.project_state_projection.v1",
    projection_id: "project-state:hypervisor-dev-replay/repo-profile",
    source: "daemon-project-state-projection",
    selected_project_id: selected,
    project_boundary_invariant:
      "Projects are repository-backed user workspaces admitted by the Hypervisor Daemon. Hypervisor Core is runtime substrate, not a user project; Agentgres admits project truth and storage backends only hold bytes.",
    runtimeTruthSource: "daemon-runtime",
    records: projectRecords,
  };
}

function projectRecordFromCreateRequest(body = {}) {
  const repositoryUrl = String(body.repository_url ?? body.repositoryUrl ?? "").trim();
  if (!/^https?:\/\/[^/\s]+\/[^/\s]+\/[^/\s]+/i.test(repositoryUrl)) {
    const error = new Error("Project repository_url must be an http(s) Git repository URL.");
    error.status = 400;
    throw error;
  }
  const fallbackName = projectNameFromRepositoryUrl(repositoryUrl);
  const projectName = String(body.project_name ?? body.projectName ?? fallbackName).trim() || fallbackName;
  const projectId = safeSegment(projectName.toLowerCase()) || `project-${projectRecords.length + 1}`;
  const ownerAndRepo = repositoryUrl
    .replace(/^https?:\/\/[^/]+\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");
  const branch = String(body.repository_branch ?? body.branch ?? "master").trim() || "master";
  return {
    project_id: projectId,
    name: projectName,
    description: `Repository project for ${ownerAndRepo}.`,
    repository_url: repositoryUrl,
    repository_ref: `github:${ownerAndRepo}`,
    repository_branch: branch,
    created_at: FIXED_NOW,
    environment_class_refs: Array.isArray(body.environment_class_refs)
      ? body.environment_class_refs.filter((item) => typeof item === "string" && item.trim())
      : [],
    prebuilds_enabled: false,
    environment: "No environment yet",
    root_path: `/workspace/${projectId}`,
    workspace_ref: `workspace://repo/${projectId}`,
    current_session_ref: null,
    environment_ref: null,
    provider_candidate_ref: "provider-candidate:local-workstation",
    adapter_preference_ref: "code-editor-adapter:embedded_code_editor",
    custody_posture: "local_private",
    restore_state: "idle",
    agentgres_object_head_ref: `agentgres://object-head/project:${projectId}`,
    state_root_ref: `agentgres://state-root/project:${projectId}`,
    artifact_refs: [`artifact://project/${projectId}/repository-link`],
    archive_ref: `artifact://agentgres/archive/${projectId}/latest`,
    restore_ref: `agentgres://restore/${projectId}/latest`,
    latest_receipt_refs: [`receipt://project/${projectId}/created`],
  };
}

const sessionOperationsProjection = {
  schema_version: "ioi.hypervisor.session_operations_projection.v1",
  projection_id: "session-operations:hypervisor-dev-replay/default",
  source: "daemon-session-operations-projection",
  selected_session_ref: ACTIVE_SESSION_REF,
  display_title: "Local Qwen harness replay session",
  branch_label: "main",
  lifecycle_state: "active",
  auto_stop_label: "manual dev replay",
  created_label: "now",
  last_started_label: "now",
  resource_health_label: "Replay healthy",
  resource_health_state: "healthy",
  project_ref: "project:hypervisor-core",
  environment_ref: "environment:local-dev-replay",
  provider_candidate_ref: "provider-candidate:local-workstation",
  selected_adapter_ref: "agent-harness-adapter:codex_cli",
  selected_adapter_admission_state: "daemon_admitted",
  authority_scope_refs: [
    "scope:model.invoke",
    "scope:workspace.read",
    "scope:terminal.attach",
    "scope:receipt.write",
  ],
  access_lease_ref: "lease://wallet/session/dev-replay/workspace-read",
  log_lease_ref: "lease://wallet/session/dev-replay/logs",
  archive_ref: "artifact://agentgres/archive/hypervisor-core/dev-replay",
  restore_ref: "agentgres://restore/hypervisor-core/dev-replay",
  session_rail: [
    { state: "active", count: 1, selected: true },
    { state: "pinned", count: 1, selected: false },
    { state: "waiting_for_approval", count: 0, selected: false },
    { state: "blocked", count: 0, selected: false },
    { state: "completed", count: 3, selected: false },
  ],
  detail_tabs: [
    "agent",
    "code",
    "environment",
    "changes",
    "receipts",
    "replay",
  ].map((tab) => ({
    tab_id: tab,
    label: tab[0].toUpperCase() + tab.slice(1),
    summary: `${tab} projection is hydrated by the dev replay harness.`,
    evidence_refs: [`receipt://session-detail/${tab}/dev-replay`],
  })),
  right_inspector_panels: [
    "changes",
    "authority",
    "privacy",
    "receipts",
    "model_harness_provider",
  ].map((panel) => ({
    panel_id: panel,
    label: panel.split("_").join(" "),
    summary: `${panel} evidence is projected from replay routes.`,
    status: panel === "authority" ? "attention" : "clear",
    evidence_refs: [`receipt://right-inspector/${panel}/dev-replay`],
  })),
  bottom_inspector_panels: ["ports_services", "tasks", "terminal", "logs"].map(
    (panel) => ({
      panel_id: panel,
      label: panel.split("_").join(" "),
      summary: `${panel} stream is available in dev replay mode.`,
      status: "clear",
      evidence_refs: [`receipt://bottom-inspector/${panel}/dev-replay`],
    }),
  ),
  ports_services: [
    {
      service_ref: "service:hypervisor-dev-replay",
      label: "Dev replay daemon",
      port: 8765,
      protocol: "http",
      lease_ref: "lease://wallet/service/dev-replay",
      status: "available",
    },
  ],
  tasks: [
    {
      task_ref: "task:hypervisor/replay-harness",
      label: "Hydrate Hypervisor App with local replay routes",
      status: "running",
      receipt_ref: "receipt://task/replay-harness/running",
    },
  ],
  terminal_events: [
    {
      event_ref: "terminal-event:dev-replay/status",
      command_summary: "node scripts/hypervisor-app-dev-replay-server.mjs --port 8765",
      status: "executed",
      receipt_ref: "receipt://terminal/dev-replay/status",
    },
  ],
  activity_signals: [
    {
      signal_ref: "activity:session/dev-replay/ready",
      kind: "receipt",
      label: "Replay session ready",
      detail: "Local daemon-shaped replay routes are available.",
      status: "normal",
      receipt_ref: "receipt://session/lifecycle/dev-replay",
    },
  ],
  access_log_leases: [
    {
      lease_ref: "lease://wallet/session/dev-replay/logs",
      label: "Session log lease",
      scope_ref: "scope:logs.read",
      status: "active",
      expires_label: "dev replay",
      receipt_ref: "receipt://authority/log-lease/dev-replay",
    },
  ],
  environment_lifecycle_steps: [
    {
      step_ref: "environment-step:dev-replay/started",
      label: "Replay endpoint started",
      detail: "Local daemon-shaped route surface is serving Hypervisor projections.",
      status: "completed",
      evidence_ref: "receipt://environment/dev-replay/started",
    },
  ],
  changed_file_groups: [
    {
      group_ref: "changed-files:hypervisor/replay",
      folder: "apps/hypervisor",
      files: [
        {
          file_ref: "file:apps/hypervisor/src/dev/hypervisorDevReplayClient.ts",
          name: "hypervisorDevReplayClient.ts",
          delta: "+ endpoint bootstrap",
          status: "added",
          receipt_ref: "receipt://workspace/dev-replay/bootstrap",
        },
      ],
    },
  ],
  latest_receipt_refs: [
    "receipt://session/lifecycle/dev-replay",
    "receipt://terminal/dev-replay/transcript",
    "receipt://authority/local-qwen/grant",
  ],
  runtimeTruthSource: "daemon-runtime",
};

const receiptEvidenceProjection = {
  schema_version: "ioi.hypervisor.receipt_evidence_projection.v1",
  projection_id: "receipt-evidence:hypervisor-dev-replay/default",
  source: "daemon-receipt-evidence-projection",
  page_cursor: null,
  next_page_cursor: null,
  page_size: 25,
  has_more: false,
  receipt_boundary_invariant:
    "Receipts make transitions attributable; Agentgres admits operational truth, artifact refs bind payload meaning, and the Hypervisor client only renders evidence projections.",
  runtimeTruthSource: "daemon-runtime",
  records: [
    {
      receipt_ref: "receipt://session/lifecycle/dev-replay",
      kind: "session_lifecycle",
      summary: "Local replay session lifecycle admitted for browser/dev demo.",
      source_projection_ref: sessionOperationsProjection.projection_id,
      agentgres_operation_refs: ["agentgres://operation/session/dev-replay"],
      artifact_refs: ["artifact://session/dev-replay/lifecycle"],
      trace_refs: ["trace://session/dev-replay/lifecycle"],
      state_root_ref: "agentgres://state-root/session/dev-replay",
      replay_ref: "agentgres://replay/session/dev-replay",
      status: "admitted",
    },
    {
      receipt_ref: "receipt://terminal/dev-replay/transcript",
      kind: "terminal_transcript",
      summary: "Replay-backed Workbench terminal transcript projection.",
      source_projection_ref: "agentgres://trace/terminal/dev-replay",
      agentgres_operation_refs: ["agentgres://operation/terminal/dev-replay"],
      artifact_refs: ["artifact://terminal/dev-replay/transcript"],
      trace_refs: ["trace://terminal/dev-replay"],
      state_root_ref: "agentgres://state-root/terminal/dev-replay",
      replay_ref: "agentgres://replay/terminal/dev-replay",
      status: "admitted",
    },
    {
      receipt_ref: "receipt://authority/local-qwen/grant",
      kind: "authority",
      summary: "wallet.network grant projection for local Qwen model route.",
      source_projection_ref: "wallet://authority/local-qwen",
      agentgres_operation_refs: ["agentgres://operation/authority/local-qwen"],
      artifact_refs: ["artifact://authority/local-qwen/grant"],
      trace_refs: ["trace://authority/local-qwen"],
      state_root_ref: "agentgres://state-root/authority/local-qwen",
      replay_ref: "agentgres://replay/authority/local-qwen",
      status: "admitted",
    },
  ],
};

const homeCockpitProjection = {
  schema_version: "ioi.hypervisor.home_cockpit_projection.v1",
  projection_id: "home-cockpit:hypervisor-dev-replay/default",
  source: "daemon-home-cockpit-projection",
  selected_project_id: ACTIVE_PROJECT_ID,
  runtimeTruthSource: "daemon-runtime",
  boundary_invariant:
    "Home is a cockpit projection over daemon/Core runtime, wallet.network authority, Agentgres truth, storage bytes, and local replay evidence.",
  metrics: [
    {
      metric_ref: "home-cockpit:dev-replay/session",
      label: "Active session",
      value: "active",
      detail: ACTIVE_SESSION_REF,
      surface_ref: "surface:sessions",
      evidence_refs: ["receipt://session/lifecycle/dev-replay"],
      drill_refs: [
        {
          label: "Inspect session",
          surface_ref: "surface:sessions",
          target_ref: ACTIVE_SESSION_REF,
          evidence_ref: "receipt://session/lifecycle/dev-replay",
        },
      ],
    },
    {
      metric_ref: "home-cockpit:dev-replay/workbench",
      label: "Workbench",
      value: "mounted",
      detail: "Replay-backed project workspace",
      surface_ref: "surface:projects",
      evidence_refs: ["receipt://workspace/dev-replay/bootstrap"],
      drill_refs: [
        {
          label: "Open project workspace",
          surface_ref: "surface:projects",
          target_ref: ACTIVE_PROJECT_ID,
          evidence_ref: "receipt://workspace/dev-replay/bootstrap",
        },
      ],
    },
    {
      metric_ref: "home-cockpit:dev-replay/receipts",
      label: "Receipts",
      value: `${receiptEvidenceProjection.records.length} records`,
      detail: receiptEvidenceProjection.records[0].state_root_ref,
      surface_ref: "surface:receipts",
      evidence_refs: receiptEvidenceProjection.records.map((record) => record.receipt_ref),
      drill_refs: receiptEvidenceProjection.records.slice(0, 2).map((record) => ({
        label: record.summary,
        surface_ref: "surface:receipts",
        target_ref: record.receipt_ref,
        evidence_ref: record.state_root_ref,
      })),
    },
  ],
};

const providerPlacementProjection = {
  schema_version: "ioi.hypervisor.provider_placement_projection.v1",
  projection_id: "provider-placement:hypervisor-dev-replay/default",
  source: "daemon-provider-placement-projection",
  selected_project_ref: "project:hypervisor-core",
  anti_gateway_invariant:
    "Provider posture is projected inside Hypervisor sessions/projects; wallet.network authorizes spend and secrets, Agentgres records admitted truth.",
  runtimeTruthSource: "daemon-runtime",
  candidates: [
    {
      candidate_ref: "provider-candidate:local-workstation",
      label: "Local workstation",
      integration_kind: "local_machine",
      direct_provider_ref: "provider:local-workstation",
      workload_fit: "Private local demo, Qwen model mount, Workbench terminal replay.",
      privacy_posture: "local_custody",
      wallet_authority_scope_refs: ["scope:workspace.read", "scope:terminal.attach"],
      agentgres_receipt_ref: "receipt://provider/local-workstation/placement",
      storage_policy_ref: "storage-policy:local-agentgres-artifact-refs",
      restore_policy_ref: "agentgres://restore/local-workstation/dev-replay",
      risk_labels: ["Local custody", "No provider root"],
    },
  ],
};

const privacyPostureProjection = {
  schema_version: "ioi.hypervisor.execution_privacy_posture_projection.v1",
  projection_id: "privacy-posture:hypervisor-dev-replay/default",
  source: "daemon-privacy-posture-projection",
  project_ref: "project:hypervisor-core",
  selected_session_ref: ACTIVE_SESSION_REF,
  selected_privacy_ref: "privacy:ctee-private-workspace",
  default_model_route_ref: "model-route:hypervisor/default-local",
  invariant:
    "Local replay can project privacy posture but cannot turn provider trust into private local custody.",
  runtimeTruthSource: "daemon-runtime",
  workspace_segments: [
    {
      segment_ref: "workspace-segment:public-trunk",
      label: "Public project trunk",
      custody_class: "public_trunk",
      node_plaintext_allowed: true,
      owner: "hypervisor_core",
      evidence_refs: ["receipt://workspace/dev-replay/bootstrap"],
    },
    {
      segment_ref: "workspace-segment:private-head",
      label: "Private local head",
      custody_class: "private_head",
      node_plaintext_allowed: false,
      owner: "wallet_network",
      evidence_refs: ["receipt://authority/local-qwen/grant"],
    },
  ],
  model_weight_policies: [
    {
      lane: "open_or_local_weights",
      label: "Local/open Qwen weights",
      protects_workspace_state: true,
      protects_model_weights_from_provider_root: true,
      allowed_postures: ["private_native", "ctee_split"],
      admission_summary: "Local Qwen route is allowed for dev replay.",
      authority_scope_refs: ["scope:model.invoke"],
    },
  ],
  provider_candidates: [
    {
      candidate_ref: "provider-candidate:local-workstation",
      label: "Local workstation",
      posture: "private_native",
      model_weight_lane: "open_or_local_weights",
      provider_root_plaintext_risk: "none",
      admission_summary: "Local process boundary; no provider-root custody claim.",
      receipt_ref: "receipt://provider/local-workstation/placement",
    },
  ],
  admission_controls: [
    {
      control_ref: "privacy-control:no-provider-trust-as-local",
      label: "Provider trust cannot masquerade as private local route",
      owner: "wallet_network",
      blocks_unsafe_plaintext: true,
      receipt_ref: "receipt://privacy/no-provider-trust-as-local",
    },
  ],
  unsafe_mount_receipt_ref: "receipt://privacy/no-provider-trust-as-local",
};

const modelInfrastructureProjection = {
  schema_version: "ioi.hypervisor.model_infrastructure_projection.v1",
  projection_id: "model-infrastructure:hypervisor-dev-replay/default",
  source: "daemon-model-infrastructure-projection",
  selected_project_id: ACTIVE_PROJECT_ID,
  selected_session_ref: ACTIVE_SESSION_REF,
  runtimeTruthSource: "daemon-runtime",
  infrastructure_boundary_invariant:
    "Model infrastructure projects daemon-admitted model routes; it does not bypass wallet authority or Agentgres receipt truth.",
  inventory_source: "daemon-model-mount-inventory",
  checked_at: FIXED_NOW,
  model_route_refs: modelMountSnapshot.routes.map((route) => route.id),
  endpoint_refs: modelMountSnapshot.endpoints.map((endpoint) => endpoint.id),
  loaded_instance_refs: modelMountSnapshot.instances.map((instance) => instance.id),
  provider_refs: ["provider:hypervisor-local"],
  routes: [
    {
      route_ref: "model-route:hypervisor/default-local",
      role: "default-local",
      status: "active",
      privacy_posture: "local_model_mount",
      provider_ref: "provider:hypervisor-local",
      endpoint_refs: ["model-endpoint:hypervisor/default-local"],
      loaded_instance_refs: ["model-instance:hypervisor/default-local"],
      model_weight_custody_lane: "open_or_local_weights",
      authority_scope_refs: ["scope:model.invoke"],
      receipt_refs: ["receipt://model-route/qwen-local/ready"],
    },
  ],
  providers: [
    {
      provider_ref: "provider:hypervisor-local",
      label: "Hypervisor local model provider",
      provider_kind: "local",
      privacy_posture: "local_model_mount",
      credential_scope_refs: [],
      receipt_ref: "receipt://model-provider/local/ready",
    },
  ],
  session_bindings: [
    {
      session_ref: ACTIVE_SESSION_REF,
      selected_model_route_ref: "model-route:hypervisor/default-local",
      selected_endpoint_ref: "model-endpoint:hypervisor/default-local",
      selected_instance_ref: "model-instance:hypervisor/default-local",
      custody_profile_ref: "privacy:ctee-private-workspace",
      policy_ref: "policy:model-route/local-private",
      receipt_ref: "receipt://session/model-binding/dev-replay",
    },
  ],
  model_weight_custody_policy_refs: ["model-weight-policy:local-open-qwen"],
  latest_receipt_refs: [
    "receipt://model-route/qwen-local/ready",
    "receipt://session/model-binding/dev-replay",
  ],
};

const automationCompositorProjection = {
  schema_version: "ioi.hypervisor.automation_compositor_projection.v1",
  projection_id: "automation-compositor:hypervisor-dev-replay/default",
  source: "daemon-automation-compositor-projection",
  selected_project_id: ACTIVE_PROJECT_ID,
  runtimeTruthSource: "daemon-runtime",
  compositor_boundary_invariant:
    "Automations edits and proposes durable workflow runs; the daemon admits execution and Agentgres records truth.",
  workflow_template_refs: ["workflow-template:reference-parity-loop"],
  run_recipe_refs: ["run-recipe:reference-parity-loop/manual"],
  graph_refs: ["workflow://graph/reference-parity-loop"],
  templates: [
    {
      template_ref: "workflow-template:reference-parity-loop",
      label: "Reference parity loop",
      description:
        "Run source capture, route audit, workbench smoke, and receipt evidence checks as a durable workflow.",
      graph_ref: "workflow://graph/reference-parity-loop",
      recipe_ref: "run-recipe:reference-parity-loop/manual",
      required_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
      model_route_policy_ref: "model-route-policy:local-qwen",
      receipt_policy_ref: "receipt-policy:workflow/reference-parity",
      latest_receipt_refs: ["receipt://automation/reference-parity/template"],
    },
  ],
  run_recipes: [
    {
      run_recipe_ref: "run-recipe:reference-parity-loop/manual",
      template_ref: "workflow-template:reference-parity-loop",
      label: "Manual parity audit",
      schedule_ref: "schedule:manual",
      launch_action_ref: "action:automation/reference-parity/manual",
      authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
      receipt_refs: ["receipt://automation/reference-parity/recipe"],
    },
  ],
  graphs: [
    {
      graph_ref: "workflow://graph/reference-parity-loop",
      label: "Reference parity loop",
      node_count: 5,
      edge_count: 4,
      context_chamber_refs: ["context:reference-source-capture"],
      artifact_refs: ["artifact://automation/reference-parity/graph"],
      receipt_refs: ["receipt://automation/reference-parity/graph"],
    },
  ],
  runs: [
    {
      run_ref: "automation-run:reference-parity/dev-replay",
      template_ref: "workflow-template:reference-parity-loop",
      status: "running",
      action_proposal_ref: "action-proposal:automation/reference-parity",
      agentgres_operation_ref: "agentgres://operation/automation/reference-parity",
      state_root_ref: "agentgres://state-root/automation/reference-parity",
      latest_receipt_ref: "receipt://automation/reference-parity/run",
    },
  ],
  latest_receipt_refs: ["receipt://automation/reference-parity/run"],
  agentgres_operation_refs: ["agentgres://operation/automation/reference-parity"],
  state_root_ref: "agentgres://state-root/automation/reference-parity",
};

const agentsProjection = {
  schema_version: "ioi.hypervisor.agents_projection.v1",
  projection_id: "agents:hypervisor-dev-replay/default",
  source: "daemon-agents-projection",
  selected_project_ref: "project:hypervisor-core",
  boundary_invariant:
    "Agent harnesses are proposal sources only. Hypervisor Daemon admits sessions, gates, receipts, and replay.",
  memory_invariant:
    "Semantic memory is owned by Agent Wiki / ioi-memory; Agentgres records admitted operational refs.",
  capability_invariant:
    "Agents exercise wallet.network leases, not unrestricted credentials.",
  runtimeTruthSource: "daemon-runtime",
  records: [
    {
      agent_ref: "agent:codex-oss-qwen",
      label: "Codex OSS / Qwen",
      objective: "Run local Codex OSS harness sessions through Qwen route.",
      status: "running",
      workspace_ref: "workspace://ioi/hypervisor-core",
      session_ref: ACTIVE_SESSION_REF,
      runtime: {
        harness_selection_ref: "agent-harness-adapter:codex_cli",
        harness_label: "Codex CLI",
        truth_boundary: "daemon_owned",
        model_route_ref: "model-route:hypervisor/default-local",
        adapter_target_ref: "adapter-target:embedded-workbench",
        privacy_posture_ref: "privacy:ctee-private-workspace",
      },
      skill_bindings: [
        {
          skill_ref: "skill:reference-parity.local-demo",
          label: "Reference parity local demo",
          source: "workspace",
          version_ref: "skill-version:reference-parity/v1",
          promotion_state: "active",
          receipt_ref: "receipt://agent/codex-oss-qwen/skill",
        },
      ],
      memory_bindings: [
        {
          memory_ref: "memory://workspace/hypervisor-core/parity-notes",
          label: "Parity implementation notes",
          scope: "workspace_bound",
          owner: "agentgres_projection",
          persistence: "persistent",
          receipt_ref: "receipt://memory/hypervisor-core/parity-notes",
        },
      ],
      capability_leases: [
        {
          lease_ref: "lease://wallet/agent/codex-oss-qwen/workspace-read",
          capability_ref: "scope:workspace.read",
          status: "active",
          expires_at: "2026-06-19T18:00:00.000Z",
          wallet_authority_scope_refs: ["scope:workspace.read"],
          receipt_ref: "receipt://wallet/lease/codex-oss-qwen/workspace-read",
        },
      ],
      agentgres_operation_refs: ["agentgres://operation/agent/codex-oss-qwen"],
      state_root_ref: "agentgres://state-root/agent/codex-oss-qwen",
      latest_receipt_refs: ["receipt://agent/codex-oss-qwen/session"],
      updated_at: FIXED_NOW,
    },
  ],
};

const applicationsCatalog = {
  schema_version: "ioi.hypervisor.applications_catalog.v1",
  applications: [
    "foundry",
    "models",
    "workers",
    "connectors",
    "policies",
    "receipts",
    "monitoring",
  ].map((id) => ({
    application_id: id,
    label: id[0].toUpperCase() + id.slice(1),
    category: id === "receipts" || id === "policies" ? "governance" : "platform",
    pinned: true,
    route_ref: `surface:${id}`,
    status: "available",
  })),
};

const foundryState = {
  schema_version: "ioi.hypervisor.foundry_projection.v1",
  jobs: [
    {
      job_ref: "foundry-job:harness-qwen-eval",
      label: "Local Qwen harness eval",
      status: "running",
      receipt_ref: "receipt://foundry/qwen-harness-eval",
    },
  ],
  evals: [
    {
      eval_ref: "foundry-eval:reference-parity",
      label: "Reference parity route coverage",
      status: "ready",
      score: 0.82,
    },
  ],
  packages: [
    {
      package_ref: "foundry-package:generic-cli-qwen",
      label: "Generic CLI / Qwen adapter",
      status: "candidate",
      receipt_ref: "receipt://foundry/generic-cli-qwen/package",
    },
  ],
};

const workspaceTree = [
  {
    name: WORKSPACE_ROOT_LABEL,
    path: WORKSPACE_ROOT_LABEL,
    kind: "directory",
    hasChildren: true,
    children: [
      {
        name: "apps",
        path: `${WORKSPACE_ROOT_LABEL}/apps`,
        kind: "directory",
        hasChildren: true,
        children: [],
      },
      {
        name: "docs",
        path: `${WORKSPACE_ROOT_LABEL}/docs`,
        kind: "directory",
        hasChildren: true,
        children: [],
      },
      {
        name: "scripts",
        path: `${WORKSPACE_ROOT_LABEL}/scripts`,
        kind: "directory",
        hasChildren: true,
        children: [],
      },
      {
        name: "package.json",
        path: `${WORKSPACE_ROOT_LABEL}/package.json`,
        kind: "file",
        hasChildren: false,
        children: [],
      },
    ],
  },
];

const workspaceFiles = new Map([
  [
    `${WORKSPACE_ROOT_LABEL}/docs/architecture/components/hypervisor/core-clients-surfaces.md`,
    `# Hypervisor Core, Clients, Application Surfaces, Sessions, and Adapters\n\nReplay-backed Workbench preview for the canonical Hypervisor product surface and adapter doctrine.\n`,
  ],
  [
    `${WORKSPACE_ROOT_LABEL}/apps/hypervisor/src/dev/hypervisorDevReplayClient.ts`,
    `export const HYPERVISOR_DEV_REPLAY_CLIENT = "daemon-shaped dev replay bootstrap";\n`,
  ],
  [
    `${WORKSPACE_ROOT_LABEL}/scripts/hypervisor-app-dev-replay-server.mjs`,
    `#!/usr/bin/env node\n// Development replay scaffold over Hypervisor Daemon/Core contracts.\n`,
  ],
  [
    `${WORKSPACE_ROOT_LABEL}/package.json`,
    `{"scripts":{"check:ioi-reference":"node internal-docs/reverse-engineering/ioi/verify.js"}}\n`,
  ],
]);

function workspaceSnapshot() {
  return {
    rootPath: WORKSPACE_ROOT,
    displayName: "Hypervisor Core",
    git: {
      isRepo: true,
      branch: "main",
      dirty: true,
      lastCommit: "reference-grade replay harness",
    },
    tree: workspaceTree,
  };
}

function listWorkspaceDirectory(pathname = WORKSPACE_ROOT_LABEL) {
  if (!pathname || pathname === "." || pathname === WORKSPACE_ROOT_LABEL) {
    return workspaceTree[0].children;
  }
  if (`${WORKSPACE_ROOT_LABEL}/docs` === pathname) {
    return [
      {
        name: "architecture",
        path: `${WORKSPACE_ROOT_LABEL}/docs/architecture`,
        kind: "directory",
        hasChildren: true,
        children: [],
      },
    ];
  }
  if (`${WORKSPACE_ROOT_LABEL}/docs/architecture` === pathname) {
    return [
      {
        name: "components",
        path: `${WORKSPACE_ROOT_LABEL}/docs/architecture/components`,
        kind: "directory",
        hasChildren: true,
        children: [],
      },
    ];
  }
  if (`${WORKSPACE_ROOT_LABEL}/docs/architecture/components` === pathname) {
    return [
      {
        name: "hypervisor",
        path: `${WORKSPACE_ROOT_LABEL}/docs/architecture/components/hypervisor`,
        kind: "directory",
        hasChildren: true,
        children: [],
      },
    ];
  }
  if (`${WORKSPACE_ROOT_LABEL}/docs/architecture/components/hypervisor` === pathname) {
    return [
      {
        name: "core-clients-surfaces.md",
        path: `${WORKSPACE_ROOT_LABEL}/docs/architecture/components/hypervisor/core-clients-surfaces.md`,
        kind: "file",
        hasChildren: false,
        children: [],
      },
    ];
  }
  if (`${WORKSPACE_ROOT_LABEL}/apps` === pathname) {
    return [
      {
        name: "hypervisor",
        path: `${WORKSPACE_ROOT_LABEL}/apps/hypervisor`,
        kind: "directory",
        hasChildren: true,
        children: [],
      },
    ];
  }
  if (`${WORKSPACE_ROOT_LABEL}/scripts` === pathname) {
    return [
      {
        name: "hypervisor-app-dev-replay-server.mjs",
        path: `${WORKSPACE_ROOT_LABEL}/scripts/hypervisor-app-dev-replay-server.mjs`,
        kind: "file",
        hasChildren: false,
        children: [],
      },
    ];
  }
  return [];
}

function workspaceFile(pathname) {
  const normalizedPath = pathname || `${WORKSPACE_ROOT_LABEL}/package.json`;
  const content =
    workspaceFiles.get(normalizedPath) ??
    `// Replay-backed file projection for ${normalizedPath}\n`;
  const name = normalizedPath.split("/").pop() || normalizedPath;
  const languageHint = name.endsWith(".ts")
    ? "typescript"
    : name.endsWith(".mjs")
      ? "javascript"
      : name.endsWith(".md")
        ? "markdown"
        : name.endsWith(".json")
          ? "json"
          : "plaintext";
  return {
    name,
    path: normalizedPath,
    absolutePath: resolve(WORKSPACE_ROOT, normalizedPath.replace(/^ioi\/?/, "")),
    languageHint,
    content,
    sizeBytes: Buffer.byteLength(content),
    modifiedAtMs: Date.parse(FIXED_NOW),
    isBinary: false,
    isTooLarge: false,
    readOnly: false,
  };
}

function sourceControlState() {
  return {
    git: workspaceSnapshot().git,
    entries: [
      {
        path: "scripts/hypervisor-app-dev-replay-server.mjs",
        originalPath: null,
        x: "A",
        y: "M",
      },
      {
        path: "apps/hypervisor/src/dev/hypervisorDevReplayClient.ts",
        originalPath: null,
        x: "A",
        y: "M",
      },
    ],
  };
}

function workspaceDiff(pathname = "scripts/hypervisor-app-dev-replay-server.mjs") {
  return {
    id: `diff:${pathname}`,
    path: pathname,
    title: pathname,
    originalLabel: "HEAD",
    modifiedLabel: "Dev replay",
    originalContent: "",
    modifiedContent: workspaceFile(`${WORKSPACE_ROOT_LABEL}/${pathname}`).content,
    languageHint: pathname.endsWith(".ts") ? "typescript" : "javascript",
    isBinary: false,
  };
}

function terminalSession(id = "terminal:dev-replay/default", cols = 120, rows = 32) {
  return {
    sessionId: id,
    shell: "/bin/bash",
    rootPath: WORKSPACE_ROOT,
    startedAtMs: Date.parse(FIXED_NOW),
    cols,
    rows,
  };
}

function terminalReadResult(sessionId = "terminal:dev-replay/default", cursor = 0) {
  const chunks = [
    {
      sequence: 1,
      text: "$ node scripts/hypervisor-app-dev-replay-server.mjs --port 8765\n",
    },
    {
      sequence: 2,
      text:
        "Hypervisor dev replay serving daemon-shaped routes for browser parity.\n",
    },
    {
      sequence: 3,
      text: "Model route: model-route:hypervisor/default-local (Qwen local)\n",
    },
  ].filter((chunk) => chunk.sequence > Number(cursor || 0));
  return {
    sessionId,
    cursor: chunks.length ? chunks[chunks.length - 1].sequence : Number(cursor || 0),
    chunks,
    running: false,
    exitCode: 0,
  };
}

function workbenchSnapshot() {
  return {
    schema_version: "ioi.hypervisor.workbench_snapshot.v1",
    project_id: ACTIVE_PROJECT_ID,
    project_ref: "project:hypervisor-core",
    session_ref: ACTIVE_SESSION_REF,
    workspace_ref: "workspace://ioi/hypervisor-core",
    root: WORKSPACE_ROOT,
    selected_file:
      `${WORKSPACE_ROOT_LABEL}/docs/architecture/components/hypervisor/core-clients-surfaces.md`,
    snapshot: workspaceSnapshot(),
    source_control: sourceControlState(),
    problems: [
      {
        id: "problem:workbench/replay-gap",
        severity: "warning",
        title: "Replay harness in progress",
        detail: "Local dev replay replaces host bridge throws in browser mode.",
        path: "apps/hypervisor/src/services/workspaceAdapter.ts",
        line: 1,
        column: 1,
      },
    ],
    ports: sessionOperationsProjection.ports_services,
    logs: [
      {
        id: "log:dev-replay/server",
        stream: "system",
        text: "Dev replay server is serving Workbench routes.",
        receipt_ref: "receipt://terminal/dev-replay/status",
      },
    ],
    receipt_refs: receiptEvidenceProjection.records.map((record) => record.receipt_ref),
  };
}

function harnessAdapterCatalog() {
  return {
    schema_version: "ioi.hypervisor.harness_adapters_projection.v1",
    adapters: [
      {
        adapter_id: "codex_cli",
        label: "Codex OSS / Qwen",
        role: "agent_harness_adapter",
        model_route_ref: "model-route:hypervisor/default-local",
        readiness: "ready",
        truth_boundary: "proposal_source_only",
      },
      {
        adapter_id: "deepseek_tui",
        label: "DeepSeek TUI / Qwen",
        role: "agent_harness_adapter",
        model_route_ref: "model-route:hypervisor/default-local",
        readiness: "ready",
        truth_boundary: "proposal_source_only",
      },
      {
        adapter_id: "claude_code_cli",
        label: "Claude Code example / Qwen",
        role: "agent_harness_adapter",
        model_route_ref: "model-route:hypervisor/default-local",
        readiness: "example_ready",
        truth_boundary: "proposal_source_only",
      },
      {
        adapter_id: "generic_cli",
        label: "Generic CLI / Qwen",
        role: "agent_harness_adapter",
        model_route_ref: "model-route:hypervisor/default-local",
        readiness: "ready",
        truth_boundary: "proposal_source_only",
      },
    ],
  };
}

function baseAdmissionFields(kind, ref) {
  return {
    decision: "admitted",
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    receipt_refs: [`receipt://${kind}/${safeSegment(ref)}`],
    agentgres_operation_refs: [`agentgres://operation/${kind}/${safeSegment(ref)}`],
    state_root: `agentgres://state-root/${kind}/${safeSegment(ref)}`,
  };
}

function codeEditorAdapterAdmission(body) {
  const launchPlanRef =
    body.launch_plan_ref ?? body.launchPlanRef ?? "code-editor-adapter-launch:dev-replay";
  return {
    schema_version: "ioi.runtime.code_editor_adapter_launch_plan_admission.v1",
    admission_id: `admission:${safeSegment(launchPlanRef)}`,
    launch_plan_ref: launchPlanRef,
    adapter_ref: body.adapter_ref ?? "code-editor-adapter:embedded_code_editor",
    target_ref: body.target_ref ?? "adapter-target:embedded-workbench",
    launch_mode: body.launch_mode ?? "embedded",
    connection_kind: body.connection_kind ?? "embedded_host",
    connection_contract_ref: "connection-contract:dev-replay/workbench",
    executor_lane: "embedded_code_editor_host",
    control_action: "open_embedded_code_editor",
    control_channel_ref: "control-channel:dev-replay/workbench",
    required_access_lease_refs: ["lease://wallet/session/dev-replay/workspace-read"],
    required_authority_scope_refs: ["scope:workspace.read"],
    required_receipt_refs: ["receipt://workspace/dev-replay/bootstrap"],
    custody_posture: "local_projection",
    secret_release_policy: "no_durable_secret_release",
    wallet_approval_ref: "wallet://approval/dev-replay/workbench",
    adapter_runtime_truth_claimed: false,
    admitted_at: FIXED_NOW,
    ...baseAdmissionFields("code-editor-adapter-launch", launchPlanRef),
  };
}

function sessionLaunchRecipeAdmission(body) {
  const recipeRef =
    body.recipe_ref ?? body.recipe_id ?? "session-launch-recipe:local-qwen-dev-replay";
  return {
    schema_version: "ioi.runtime.session_launch_recipe_admission.v1",
    admission_id: `session-launch-recipe-admission:${safeSegment(recipeRef)}`,
    launch_recipe_ref: recipeRef,
    recipe_ref: recipeRef,
    project_ref: body.project_ref ?? "project:hypervisor-core",
    session_route_ref: "session-route:hypervisor-dev-replay/local-qwen",
    authority_scope_refs: [
      "scope:model.invoke",
      "scope:workspace.read",
      "scope:receipt.write",
    ],
    admitted_at: FIXED_NOW,
    ...baseAdmissionFields("session-launch-recipe", recipeRef),
  };
}

function harnessBindingAdmission(body) {
  const bindingRef =
    body.session_binding_ref ??
    body.binding_ref ??
    "harness-session-binding:dev-replay/local-qwen";
  return {
    schema_version: "ioi.runtime.harness_session_binding_admission.v1",
    admission_id: `harness-session-binding-admission:${safeSegment(bindingRef)}`,
    session_binding_ref: bindingRef,
    session_route_ref: "session-route:hypervisor-dev-replay/local-qwen",
    harness_selection_ref:
      body.harness_selection_ref ?? "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id: body.agent_harness_adapter_id ?? "codex_cli",
    model_configuration_ref:
      body.model_configuration_ref ?? "model-config:local/codex-oss-qwen",
    model_route_ref: body.model_route_ref ?? "model-route:hypervisor/default-local",
    workspace_ref: body.workspace_ref ?? "workspace://ioi/hypervisor-core",
    privacy_posture_ref:
      body.privacy_posture_ref ?? "privacy:ctee-private-workspace",
    authority_scope_refs: [
      "scope:model.invoke",
      "scope:workspace.read",
      "scope:terminal.attach",
    ],
    receipt_policy_ref: "receipt-policy:harness-adapter/dev-replay",
    admitted_at: FIXED_NOW,
    ...baseAdmissionFields("harness-session-binding", bindingRef),
  };
}

function harnessSessionLaunch(body) {
  const admission = body.binding_admission ?? body;
  const bindingRef =
    admission.session_binding_ref ?? "harness-session-binding:dev-replay/local-qwen";
  return {
    schema_version: "ioi.runtime.harness_session_launch.v1",
    launch_id: `harness-session-launch:${safeSegment(bindingRef)}`,
    decision: "admitted",
    launch_state: "daemon_launch_admitted",
    session_binding_ref: bindingRef,
    session_route_ref:
      admission.session_route_ref ?? "session-route:hypervisor-dev-replay/local-qwen",
    harness_selection_ref:
      admission.harness_selection_ref ?? "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id: admission.agent_harness_adapter_id ?? "codex_cli",
    model_configuration_ref:
      admission.model_configuration_ref ?? "model-config:local/codex-oss-qwen",
    model_route_ref:
      admission.model_route_ref ?? "model-route:hypervisor/default-local",
    workspace_ref: body.workspace_ref ?? admission.workspace_ref ?? "workspace://ioi/hypervisor-core",
    terminal_session_ref:
      body.terminal_session_ref ?? "terminal-session:dev-replay/local-qwen",
    launched_at: FIXED_NOW,
    authority_scope_refs: admission.authority_scope_refs ?? [],
    privacy_posture_ref:
      admission.privacy_posture_ref ?? "privacy:ctee-private-workspace",
    receipt_policy_ref:
      admission.receipt_policy_ref ?? "receipt-policy:harness-adapter/dev-replay",
    ...baseAdmissionFields("harness-session-launch", bindingRef),
  };
}

function harnessSessionSpawn(body) {
  const launch = body.session_launch ?? body;
  const launchId = launch.launch_id ?? "harness-session-launch:dev-replay";
  return {
    schema_version: "ioi.runtime.harness_session_spawn.v1",
    spawn_id: `harness-session-spawn:${safeSegment(launchId)}`,
    decision: "admitted",
    spawn_state: "host_spawn_admitted",
    launch_id: launchId,
    session_binding_ref:
      launch.session_binding_ref ?? "harness-session-binding:dev-replay/local-qwen",
    session_route_ref:
      launch.session_route_ref ?? "session-route:hypervisor-dev-replay/local-qwen",
    harness_selection_ref:
      launch.harness_selection_ref ?? "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id: launch.agent_harness_adapter_id ?? "codex_cli",
    model_configuration_ref:
      launch.model_configuration_ref ?? "model-config:local/codex-oss-qwen",
    model_route_ref: launch.model_route_ref ?? "model-route:hypervisor/default-local",
    model_name: body.model_name ?? "qwen",
    provider: "ollama",
    harness_binary: "codex",
    provider_binary: "ollama",
    workspace_ref: launch.workspace_ref ?? "workspace://ioi/hypervisor-core",
    workspace_root: body.workspace_root ?? WORKSPACE_ROOT,
    terminal_session_ref:
      launch.terminal_session_ref ?? "terminal-session:dev-replay/local-qwen",
    privacy_posture_ref:
      launch.privacy_posture_ref ?? "privacy:ctee-private-workspace",
    authority_scope_refs: launch.authority_scope_refs ?? [],
    receipt_policy_ref:
      launch.receipt_policy_ref ?? "receipt-policy:harness-adapter/dev-replay",
    spawned_at: FIXED_NOW,
    ...baseAdmissionFields("harness-session-spawn", launchId),
  };
}

function harnessSessionReadiness(body) {
  const spawn = body.session_spawn ?? body;
  const spawnId = spawn.spawn_id ?? "harness-session-spawn:dev-replay";
  return {
    ...baseAdmissionFields("harness-session-readiness", spawnId),
    schema_version: "ioi.runtime.harness_session_readiness.v1",
    readiness_id: `harness-session-readiness:${safeSegment(spawnId)}`,
    decision: "ready",
    readiness_state: "host_ready",
    spawn_id: spawnId,
    launch_id: spawn.launch_id ?? "harness-session-launch:dev-replay",
    session_binding_ref:
      spawn.session_binding_ref ?? "harness-session-binding:dev-replay/local-qwen",
    session_route_ref:
      spawn.session_route_ref ?? "session-route:hypervisor-dev-replay/local-qwen",
    harness_selection_ref:
      spawn.harness_selection_ref ?? "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id: spawn.agent_harness_adapter_id ?? "codex_cli",
    model_configuration_ref:
      spawn.model_configuration_ref ?? "model-config:local/codex-oss-qwen",
    model_route_ref: spawn.model_route_ref ?? "model-route:hypervisor/default-local",
    model_name: body.model_name ?? spawn.model_name ?? "qwen",
    provider: "ollama",
    harness_binary: "codex",
    provider_binary: "ollama",
    available_model_names: ["qwen", "qwen2.5-coder"],
    checks: [
      {
        id: "check:codex-help",
        status: "pass",
        required: true,
        summary: "Codex OSS harness command is available in replay.",
        evidence_refs: ["receipt://harness/readiness/codex-help"],
      },
      {
        id: "check:qwen-route",
        status: "pass",
        required: true,
        summary: "Local Qwen model route is mounted.",
        evidence_refs: ["receipt://model-route/qwen-local/ready"],
      },
    ],
    operator_next_action: "Attach terminal to the admitted local Qwen harness session.",
    checked_at: FIXED_NOW,
  };
}

function harnessSessionTerminalAttach(body) {
  const spawn = body.session_spawn ?? {};
  const readiness = body.session_readiness ?? {};
  const spawnId = spawn.spawn_id ?? readiness.spawn_id ?? "harness-session-spawn:dev-replay";
  const readinessId =
    readiness.readiness_id ?? `harness-session-readiness:${safeSegment(spawnId)}`;
  return {
    schema_version: "ioi.runtime.harness_session_terminal_attach.v1",
    attach_id: `harness-session-terminal-attach:${safeSegment(spawnId)}`,
    decision: "admitted",
    attach_state: "client_pty_attach_admitted",
    attach_lane: "hypervisor_client_terminal_adapter",
    spawn_id: spawnId,
    readiness_id: readinessId,
    launch_id: spawn.launch_id ?? readiness.launch_id ?? "harness-session-launch:dev-replay",
    session_binding_ref:
      spawn.session_binding_ref ??
      readiness.session_binding_ref ??
      "harness-session-binding:dev-replay/local-qwen",
    session_route_ref:
      spawn.session_route_ref ??
      readiness.session_route_ref ??
      "session-route:hypervisor-dev-replay/local-qwen",
    harness_selection_ref:
      spawn.harness_selection_ref ??
      readiness.harness_selection_ref ??
      "agent-harness-adapter:codex_cli",
    agent_harness_adapter_id:
      spawn.agent_harness_adapter_id ?? readiness.agent_harness_adapter_id ?? "codex_cli",
    model_configuration_ref:
      spawn.model_configuration_ref ??
      readiness.model_configuration_ref ??
      "model-config:local/codex-oss-qwen",
    model_route_ref:
      spawn.model_route_ref ??
      readiness.model_route_ref ??
      "model-route:hypervisor/default-local",
    model_name: spawn.model_name ?? readiness.model_name ?? "qwen",
    workspace_ref: spawn.workspace_ref ?? "workspace://ioi/hypervisor-core",
    workspace_root: spawn.workspace_root ?? WORKSPACE_ROOT,
    terminal_session_ref:
      spawn.terminal_session_ref ?? "terminal-session:dev-replay/local-qwen",
    command_contract_ref: "host-command:codex-cli/local-ollama-qwen",
    command_contract: {
      command_ref: "host-command:codex-cli/local-ollama-qwen",
      binary_name: "codex",
      argv_template: ["codex", "--oss", "--local-provider", "ollama", "--model", "qwen"],
      readiness_probe_argv_template: ["codex", "--help"],
      env_policy_ref: "env-policy:harness-session/local-ollama-qwen",
      secret_release_policy: "none",
      requires_pty: true,
      workspace_env: "HYPERVISOR_SESSION_WORKSPACE",
      model_env: "HYPERVISOR_LOCAL_HARNESS_MODEL",
      resolved_argv: ["codex", "--oss", "--local-provider", "ollama", "--model", "qwen"],
      readiness_probe_argv: ["codex", "--help"],
      resolved_command_line: "codex --oss --local-provider ollama --model qwen",
      pty_transport: "hypervisor_client_terminal_adapter",
      process_custody: "client_host_pty_after_daemon_spawn_admission",
    },
    client_attach_contract: {
      root: WORKSPACE_ROOT,
      cols: 120,
      rows: 32,
      command_line: "codex --oss --local-provider ollama --model qwen",
      requires_pty: true,
      launch_after_attach: true,
      initial_write: "codex --oss --local-provider ollama --model qwen\n",
      transcript_stream_ref: "agentgres://trace/harness-terminal-transcript/dev-replay",
      pty_transport: "hypervisor_client_terminal_adapter",
      process_custody: "client_host_pty_after_daemon_attach_admission",
    },
    terminal_transcript_projection: {
      schema_version: "ioi.runtime.harness_terminal_transcript_projection.v1",
      transcript_id: "harness-terminal-transcript:dev-replay/local-qwen",
      transcript_state: "streaming",
      transcript_stream_ref: "agentgres://trace/harness-terminal-transcript/dev-replay",
      cursor: 0,
      lines: [
        {
          stream: "system",
          text: "Local Qwen harness terminal admitted through dev replay.",
          sequence: 1,
          terminal_session_ref: "terminal-session:dev-replay/local-qwen",
        },
      ],
      runtimeTruthSource: "daemon-runtime",
    },
    workspace_mount_policy: "ctee_private_workspace",
    privacy_posture_ref: "privacy:ctee-private-workspace",
    authority_scope_refs: ["scope:terminal.attach", "scope:receipt.write"],
    receipt_policy_ref: "receipt-policy:harness-adapter/dev-replay",
    attached_at: FIXED_NOW,
    ...baseAdmissionFields("harness-session-terminal-attach", spawnId),
  };
}

function genericAdmission(kind, body = {}) {
  const ref =
    body.proposal_ref ??
    body.candidate_ref ??
    body.project_ref ??
    body.route_ref ??
    body.receipt_ref ??
    `${kind}:dev-replay`;
  return {
    schema_version: `ioi.runtime.${kind.replaceAll("-", "_")}_admission.v1`,
    admission_id: `${kind}-admission:${safeSegment(ref)}`,
    decision: "admitted",
    admission_state: "ready_for_daemon_admission",
    received: body,
    admitted_at: FIXED_NOW,
    ...baseAdmissionFields(kind, ref),
  };
}

function routeFamilyFor(pathname) {
  if (pathname.includes("workbench")) return "workbench";
  if (pathname.includes("session")) return "sessions";
  if (pathname.includes("model")) return "models";
  if (pathname.includes("authority") || pathname.includes("policies")) return "authority";
  if (pathname.includes("receipt") || pathname.includes("replay")) return "receipts";
  if (pathname.includes("automation")) return "automations";
  if (pathname.includes("foundry")) return "foundry";
  if (pathname.includes("privacy")) return "privacy";
  if (pathname.includes("provider") || pathname.includes("environment")) return "environments";
  if (pathname.includes("project")) return "projects";
  if (pathname.includes("agent") || pathname.includes("worker") || pathname.includes("harness")) {
    return "agents";
  }
  if (pathname.includes("application")) return "applications";
  if (pathname.includes("home")) return "home";
  if (pathname.includes("dev-replay")) return "health";
  return "misc";
}

function createEvidenceState() {
  return {
    generated_at: FIXED_NOW,
    description:
      "Hypervisor App dev replay evidence. Development scaffold over daemon/Core contracts; not runtime truth.",
    requests: [],
    route_families: {},
  };
}

function writeEvidenceFile(evidencePath, evidence) {
  if (!evidencePath) return;
  mkdirSync(dirname(evidencePath), { recursive: true });
  writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
}

function createResponder(response, evidence, evidencePath, requestMeta) {
  function setBaseHeaders(contentType = "application/json; charset=utf-8") {
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS");
    response.setHeader(
      "access-control-allow-headers",
      "accept,content-type,authorization",
    );
    response.setHeader("cache-control", "no-store");
    response.setHeader("content-type", contentType);
  }

  function record(status, responseFamily, responseBody) {
    const family = requestMeta.family;
    evidence.requests.push({
      ...requestMeta,
      status,
      response_family: responseFamily,
      response_hash:
        typeof responseBody === "string"
          ? bodyHash(responseBody)
          : bodyHash(JSON.stringify(responseBody ?? {})),
      completed_at: new Date().toISOString(),
    });
    evidence.route_families[family] = (evidence.route_families[family] ?? 0) + 1;
    writeEvidenceFile(evidencePath, evidence);
  }

  return {
    options() {
      setBaseHeaders();
      response.statusCode = 204;
      response.end();
      record(204, "cors-preflight", {});
    },
    json(value, status = 200, responseFamily = requestMeta.family) {
      setBaseHeaders();
      response.statusCode = status;
      response.end(JSON.stringify(value));
      record(status, responseFamily, value);
    },
    text(value, status = 200, contentType = "text/plain; charset=utf-8") {
      setBaseHeaders(contentType);
      response.statusCode = status;
      response.end(value);
      record(status, contentType, value);
    },
    sse(events) {
      setBaseHeaders("text/event-stream; charset=utf-8");
      response.statusCode = 200;
      response.write(": hypervisor dev replay stream\n\n");
      for (const event of events) {
        response.write(`event: ${event.event}\n`);
        response.write(`data: ${JSON.stringify(event.data)}\n\n`);
      }
      response.end();
      record(200, "event-stream", { events: events.map((event) => event.event) });
    },
  };
}

function handleHostBridgeInvoke(command, args = {}) {
  switch (command) {
    case "peek_pending_hypervisor_launch":
      return null;
    case "ack_pending_hypervisor_launch":
      return false;
    case "set_pending_hypervisor_launch":
    case "clear_pending_hypervisor_launch":
    case "show_hypervisor_with_target":
    case "show_hypervisor":
      return null;
    case "record_hypervisor_launch_receipt":
      return null;
    case "get_hypervisor_launch_receipts":
      return [];
    case "chat_workspace_inspect":
      return workspaceSnapshot();
    case "chat_workspace_list_directory":
      return listWorkspaceDirectory(args.path);
    case "chat_workspace_read_file":
      return workspaceFile(args.path);
    case "chat_workspace_write_file":
      return {
        ...workspaceFile(args.path),
        content: String(args.content ?? ""),
        sizeBytes: Buffer.byteLength(String(args.content ?? "")),
      };
    case "chat_workspace_create_file":
      return workspaceFile(args.path);
    case "chat_workspace_create_directory":
    case "chat_workspace_rename_path":
      return { path: args.to ?? args.path ?? "" };
    case "chat_workspace_delete_path":
      return { deletedPath: args.path ?? "" };
    case "chat_workspace_stat_path":
      return {
        kind: String(args.path ?? "").includes(".") ? "file" : "directory",
        sizeBytes: 128,
        modifiedAtMs: Date.parse(FIXED_NOW),
        readOnly: false,
      };
    case "chat_workspace_search_text":
      return {
        query: args.query ?? "",
        totalMatches: 1,
        files: [
          {
            path:
              `${WORKSPACE_ROOT_LABEL}/docs/architecture/components/hypervisor/core-clients-surfaces.md`,
            matchCount: 1,
            matches: [
              {
                path:
                  `${WORKSPACE_ROOT_LABEL}/docs/architecture/components/hypervisor/core-clients-surfaces.md`,
                line: 1,
                column: 1,
                preview: "Hypervisor Core, Clients, Application Surfaces, Sessions, and Adapters",
              },
            ],
          },
        ],
      };
    case "chat_workspace_git_status":
    case "chat_workspace_git_stage":
    case "chat_workspace_git_unstage":
    case "chat_workspace_git_discard":
      return sourceControlState();
    case "chat_workspace_git_diff":
      return workspaceDiff(args.path);
    case "chat_workspace_git_commit":
      return {
        state: sourceControlState(),
        committedFileCount: 2,
        remainingChangeCount: 0,
        commitSummary: args.headline ?? "Replay commit",
      };
    case "chat_workspace_lsp_snapshot":
      return {
        generatedAtMs: Date.parse(FIXED_NOW),
        workspaceRoot: WORKSPACE_ROOT,
        path: args.path ?? "",
        languageId: "typescript",
        availability: "ready",
        statusLabel: "Ready",
        serviceLabel: "TypeScript language service",
        serverLabel: "Dev replay LSP",
        detail: "Replay-backed language snapshot.",
        diagnostics: [],
        symbols: [],
      };
    case "chat_workspace_lsp_definition":
    case "chat_workspace_lsp_references":
    case "chat_workspace_lsp_code_actions":
      return [];
    case "chat_workspace_terminal_create":
      return terminalSession("terminal:dev-replay/default", args.cols, args.rows);
    case "chat_workspace_terminal_read":
      return terminalReadResult(args.sessionId, args.cursor);
    case "chat_workspace_terminal_write":
    case "chat_workspace_terminal_resize":
    case "chat_workspace_terminal_close":
      return null;
    case "connector_policy_get":
      return cloneJson(shieldPolicyState);
    case "connector_policy_set":
      return cloneJson(args.policy ?? shieldPolicyState);
    case "connector_policy_memory_get":
    case "connector_policy_memory_remember":
    case "connector_policy_memory_forget":
    case "connector_policy_memory_set_scope_mode":
    case "connector_policy_memory_set_expiry":
      return cloneJson(shieldApprovalMemorySnapshot);
    case "get_local_engine_snapshot":
      return localEngineSnapshot();
    case "get_capability_registry_snapshot":
      return capabilityRegistrySnapshot();
    case "save_local_engine_control_plane":
      return cloneJson(args.controlPlane ?? localEngineControlPlane);
    case "refresh_local_engine_managed_settings":
    case "clear_local_engine_managed_settings_overrides":
      return cloneJson(localEngineManagedSettings);
    case "stage_local_engine_operation":
    case "remove_local_engine_operation":
    case "promote_local_engine_operation":
    case "update_local_engine_job_status":
    case "retry_local_engine_parent_playbook_run":
    case "resume_local_engine_parent_playbook_run":
    case "dismiss_local_engine_parent_playbook_run":
      return localEngineSnapshot();
    case "get_capability_governance_request":
      return null;
    case "set_capability_governance_request":
      return cloneJson(args.request ?? null);
    case "clear_capability_governance_request":
      return null;
    case "plan_capability_governance_request":
      return capabilityGovernanceRequest(args.input ?? {});
    case "plan_capability_governance_proposal":
      return capabilityGovernanceProposal(args.input ?? {});
    case "connector_list_catalog":
      return cloneJson(capabilityConnectors);
    case "connector_list_actions":
      return [
        {
          id: "workspace.read",
          service: "workspace",
          serviceLabel: "Workspace",
          toolName: "workspace.read_file",
          label: "Read workspace file",
          description: "Read a project file through the replay host bridge.",
          kind: "read",
          confirmBeforeRun: false,
          fields: [
            {
              id: "path",
              label: "Path",
              type: "text",
              required: true,
              placeholder:
                "docs/architecture/components/hypervisor/core-clients-surfaces.md",
            },
          ],
          requiredScopes: ["scope:workspace.read"],
        },
        {
          id: "terminal.attach",
          service: "terminal",
          serviceLabel: "Terminal",
          toolName: "terminal.attach",
          label: "Attach terminal",
          description: "Attach the replay terminal transcript to a session.",
          kind: "workflow",
          confirmBeforeRun: true,
          fields: [],
          requiredScopes: ["scope:terminal.attach", "scope:receipt.write"],
        },
      ];
    case "get_available_tools":
      return cloneJson(toolCatalog.tools);
    default:
      return {
        schema_version: "ioi.hypervisor.dev_host_bridge_unknown_command.v1",
        command,
        args,
        status: "noop",
      };
  }
}

const MODEL_TURN_UPSTREAM_BASE = (
  process.env.IOI_HYPERVISOR_MODEL_UPSTREAM || "http://127.0.0.1:11434/v1"
).replace(/\/+$/, "");

// Phase 0 (real-execution master guide): the deterministic replay turn is a
// fallback that must be EXPLICITLY enabled. With no reachable model and without
// this flag, a session turn returns an honest "no model route" error instead of
// faking an answer — no silent prose. Set IOI_HYPERVISOR_REPLAY_MODE=1 to allow
// the deterministic turn for offline UI work.
const REPLAY_MODE_ENABLED = /^(1|true|on|yes)$/i.test(
  String(process.env.IOI_HYPERVISOR_REPLAY_MODE ?? "").trim(),
);

const NO_MODEL_ROUTE_MESSAGE =
  "The model route did not respond. Start a local model (Ollama with a Qwen " +
  "model on :11434) or set IOI_HYPERVISOR_MODEL_UPSTREAM to any " +
  "OpenAI-compatible endpoint to stream real completions. To replay a " +
  "deterministic turn without a model, set IOI_HYPERVISOR_REPLAY_MODE=1.";

const turnDelay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function probeModelUpstreamReachable() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 600);
    const probe = await fetch(`${MODEL_TURN_UPSTREAM_BASE}/models`, {
      signal: controller.signal,
    }).catch(() => null);
    clearTimeout(timer);
    return Boolean(probe && probe.ok);
  } catch {
    return false;
  }
}

function harnessDisplayName(harnessRef) {
  if (harnessRef.includes("deepseek")) return "DeepSeek TUI";
  if (harnessRef.includes("claude")) return "Claude Code";
  if (harnessRef.includes("generic")) return "Generic CLI";
  return "Codex OSS";
}

function buildDeterministicTurn(userText, modelName, harnessRef) {
  const agent = harnessDisplayName(harnessRef);
  const task = userText.replace(/\s+/g, " ").trim().slice(0, 160) || "your task";
  return [
    `Running on the ${agent} harness over the local ${modelName} route.`,
    "",
    "Plan:",
    "1. Inspect the workspace and locate the files relevant to this task.",
    `2. Implement: "${task}".`,
    "3. Run the available checks and report the diff and a preview path.",
    "",
    "Note: this is a governed dev-replay turn. Start a local model — Ollama with a Qwen model on :11434, or set IOI_HYPERVISOR_MODEL_UPSTREAM to any OpenAI-compatible endpoint — and the same turn streams real completions with no app change.",
  ].join("\n");
}

function sseTurnHeaders(response) {
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("cache-control", "no-store");
  response.setHeader("connection", "keep-alive");
  response.setHeader("content-type", "text/event-stream; charset=utf-8");
  response.statusCode = 200;
}

function sseTurnWrite(response, event, data) {
  response.write(`event: ${event}\n`);
  response.write(`data: ${JSON.stringify(data)}\n\n`);
}

/**
 * Stream a governed model turn. Proxies token deltas from an OpenAI-compatible
 * upstream (Ollama or the real Hypervisor daemon) when one is reachable;
 * otherwise streams a deterministic replay turn so the demo query is functional
 * with no external dependency. Same SSE shape either way.
 */
async function streamSessionTurn({ request, response, body }) {
  const messages =
    Array.isArray(body.messages) && body.messages.length
      ? body.messages
      : [
          {
            role: "user",
            content: String(body.prompt ?? body.seed_intent ?? "Describe your task."),
          },
        ];
  const modelName = String(body.model_name || body.model || "qwen");
  const harnessRef = String(
    body.harness_selection_ref || "agent-harness-adapter:codex_cli",
  );
  const turnRef = `session-turn:${bodyHash(
    JSON.stringify({ messages, model: modelName }),
  )}`;
  const receiptRef = `receipt://hypervisor/session-turn/${turnRef.replace(
    /[^a-z0-9_-]+/gi,
    "-",
  )}`;

  sseTurnHeaders(response);
  response.write(": hypervisor session turn\n\n");
  let aborted = false;
  request.on("close", () => {
    aborted = true;
  });

  const upstreamOk = await probeModelUpstreamReachable();
  const plannedSource = upstreamOk
    ? "model_upstream"
    : REPLAY_MODE_ENABLED
      ? "deterministic_replay"
      : "no_model_route";
  sseTurnWrite(response, "turn_start", {
    turn_ref: turnRef,
    model_name: modelName,
    harness_selection_ref: harnessRef,
    source: plannedSource,
    upstream: upstreamOk ? MODEL_TURN_UPSTREAM_BASE : null,
    replay_mode: REPLAY_MODE_ENABLED,
  });

  if (upstreamOk) {
    try {
      const upstream = await fetch(`${MODEL_TURN_UPSTREAM_BASE}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "text/event-stream" },
        body: JSON.stringify({ model: modelName, stream: true, messages }),
      });
      if (!upstream.ok || !upstream.body) {
        throw new Error(`upstream responded ${upstream.status}`);
      }
      const reader = upstream.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!aborted) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith("data:")) continue;
          const payload = trimmed.slice(5).trim();
          if (payload === "[DONE]") continue;
          try {
            const parsed = JSON.parse(payload);
            const delta = parsed.choices?.[0]?.delta?.content ?? "";
            if (delta) sseTurnWrite(response, "token", { text: delta });
          } catch {
            // ignore non-JSON keepalive lines
          }
        }
      }
      sseTurnWrite(response, "done", {
        turn_ref: turnRef,
        receipt_ref: receiptRef,
        finish_reason: "stop",
        source: "model_upstream",
      });
      response.end();
      return;
    } catch (error) {
      sseTurnWrite(response, "notice", {
        message: `Model upstream stream failed (${String(error).slice(
          0,
          120,
        )}); falling back to deterministic replay turn.`,
      });
    }
  }

  // No reachable model. Only stream the deterministic replay turn when it is
  // explicitly enabled; otherwise emit an honest "no model route" error so the
  // cockpit shows an actionable state instead of faking an answer.
  if (!REPLAY_MODE_ENABLED) {
    sseTurnWrite(response, "error", {
      code: "no_model_route",
      turn_ref: turnRef,
      upstream: MODEL_TURN_UPSTREAM_BASE,
      replay_mode: false,
      message: NO_MODEL_ROUTE_MESSAGE,
    });
    sseTurnWrite(response, "done", {
      turn_ref: turnRef,
      receipt_ref: receiptRef,
      finish_reason: "no_model_route",
      source: "no_model_route",
    });
    response.end();
    return;
  }

  const lastUser = messages[messages.length - 1]?.content ?? "your task";
  const reply = buildDeterministicTurn(String(lastUser), modelName, harnessRef);
  for (const token of reply.split(/(\s+)/)) {
    if (aborted) break;
    if (token) sseTurnWrite(response, "token", { text: token });
    await turnDelay(26);
  }
  sseTurnWrite(response, "done", {
    turn_ref: turnRef,
    receipt_ref: receiptRef,
    finish_reason: "stop",
    source: "deterministic_replay",
  });
  response.end();
}

async function handleRequest({
  request,
  response,
  evidence,
  evidencePath,
  endpoint,
}) {
  const url = new URL(request.url ?? "/", endpoint);
  const requestBody =
    request.method === "POST" || request.method === "PUT" || request.method === "DELETE"
      ? await parseJsonBody(request)
      : {};
  const responder = createResponder(response, evidence, evidencePath, {
    method: request.method ?? "GET",
    path: url.pathname,
    query: Object.fromEntries(url.searchParams.entries()),
    family: routeFamilyFor(url.pathname),
    request_hash: bodyHash(JSON.stringify(requestBody)),
    started_at: new Date().toISOString(),
  });

  if (request.method === "OPTIONS") {
    responder.options();
    return;
  }

  const pathname = url.pathname;

  if (request.method === "GET" && pathname === "/v1/hypervisor/dev-replay/status") {
    responder.json({
      schema_version: "ioi.hypervisor.dev_replay_status.v1",
      status: "ready",
      endpoint,
      generated_at: FIXED_NOW,
      boundary:
        "development replay scaffold over Hypervisor Daemon/Core contracts; not an authority source",
      route_families: [
        "home",
        "projects",
        "automations",
        "applications",
        "sessions",
        "workbench",
        "models",
        "authority",
        "agents",
        "environments",
        "foundry",
        "privacy",
        "receipts",
      ],
    });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/dev-replay/evidence") {
    responder.json(evidence);
    return;
  }

  if (request.method === "POST" && pathname === "/v1/hypervisor/session-turns") {
    await streamSessionTurn({ request, response, body: requestBody });
    return;
  }

  if (request.method === "POST" && pathname === "/v1/hypervisor/dev-replay/evidence/reset") {
    evidence.requests.splice(0, evidence.requests.length);
    evidence.route_families = {};
    writeEvidenceFile(evidencePath, evidence);
    responder.json({ ok: true, evidence });
    return;
  }

  if (request.method === "POST" && pathname === "/v1/hypervisor/dev-host-bridge/invoke") {
    responder.json(
      handleHostBridgeInvoke(requestBody.command, requestBody.args),
      200,
      "dev-host-bridge",
    );
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/capabilities") {
    responder.json({
      schema_version: "ioi.hypervisor.capabilities.v1",
      capabilities: [
        "dev_replay",
        "model_mount_snapshot",
        "authority_projection",
        "workbench_bridge",
        "session_events",
      ],
    });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/tools") {
    responder.json(toolCatalog);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/model-capabilities") {
    responder.json(modelCapabilities);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/model-mount/snapshot") {
    responder.json(modelMountSnapshot);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/model-mount/authority") {
    responder.json(authoritySnapshot);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/authority-evidence") {
    responder.json(authorityEvidence);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/home-cockpit") {
    responder.json(homeCockpitProjection);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/recommended-actions") {
    responder.json({
      schema_version: "ioi.hypervisor.recommended_actions.v1",
      actions: [
        {
          action_ref: "action:open-workbench-dev-replay",
          label: "Open replay-backed Workbench",
          surface_ref: "surface:projects",
          target_ref: ACTIVE_PROJECT_ID,
          receipt_ref: "receipt://workspace/dev-replay/bootstrap",
        },
      ],
    });
    return;
  }

  if (
    request.method === "GET" &&
    (pathname === "/v1/hypervisor/project-state" || pathname === "/v1/hypervisor/projects")
  ) {
    responder.json(buildProjectStateProjection(url.searchParams.get("project_id") ?? ""));
    return;
  }

  if (request.method === "GET" && pathname.startsWith("/v1/hypervisor/projects/")) {
    const id = decodeURIComponent(pathname.split("/").pop() ?? ACTIVE_PROJECT_ID);
    const record = projectRecords.find((project) => project.project_id === id);
    if (!record) {
      responder.json({
        error: {
          code: "project_not_found",
          message: "Project record does not exist in this dev replay profile.",
          details: { project_id: id },
        },
      }, 404);
      return;
    }
    responder.json({
      schema_version: "ioi.hypervisor.project_detail.v1",
      project: record,
      state: record,
      activity: sessionOperationsProjection.activity_signals,
    });
    return;
  }

  if (
    request.method === "GET" &&
    (pathname === "/v1/hypervisor/session-operations" || pathname === "/v1/hypervisor/sessions")
  ) {
    if (pathname === "/v1/hypervisor/sessions") {
      responder.json({
        schema_version: "ioi.hypervisor.sessions_projection.v1",
        selected_session_ref: ACTIVE_SESSION_REF,
        sessions: [
          {
            session_ref: ACTIVE_SESSION_REF,
            title: sessionOperationsProjection.display_title,
            lifecycle_state: "active",
            project_ref: "project:hypervisor-core",
            harness_adapter_ref: "agent-harness-adapter:codex_cli",
            model_route_ref: "model-route:hypervisor/default-local",
            latest_receipt_refs: sessionOperationsProjection.latest_receipt_refs,
          },
        ],
        projection: sessionOperationsProjection,
      });
      return;
    }
    responder.json(sessionOperationsProjection);
    return;
  }

  const sessionEventsMatch = pathname.match(/^\/v1\/hypervisor\/sessions\/([^/]+)\/events$/);
  if (request.method === "GET" && sessionEventsMatch) {
    responder.sse([
      {
        event: "session_state",
        data: {
          session_ref: ACTIVE_SESSION_REF,
          lifecycle_state: "active",
          projection_id: sessionOperationsProjection.projection_id,
        },
      },
      {
        event: "readiness",
        data: {
          readiness_id: "harness-session-readiness:dev-replay",
          decision: "ready",
        },
      },
      {
        event: "terminal_chunk",
        data: terminalReadResult("terminal:dev-replay/default", 0).chunks[1],
      },
      {
        event: "receipt_projection",
        data: receiptEvidenceProjection.records[0],
      },
    ]);
    return;
  }

  const sessionHistoryMatch = pathname.match(/^\/v1\/hypervisor\/sessions\/([^/]+)\/history$/);
  if (request.method === "GET" && sessionHistoryMatch) {
    responder.json({
      schema_version: "ioi.hypervisor.session_history.v1",
      session_ref: ACTIVE_SESSION_REF,
      chunks: [
        {
          chunk_id: "chunk:dev-replay/1",
          role: "system",
          text: "Local Qwen harness session started through dev replay.",
          receipt_ref: "receipt://session/lifecycle/dev-replay",
        },
      ],
      has_more: false,
    });
    return;
  }

  if (request.method === "GET" && pathname.startsWith("/v1/hypervisor/sessions/")) {
    responder.json({
      schema_version: "ioi.hypervisor.session_detail.v1",
      session_ref: ACTIVE_SESSION_REF,
      projection: sessionOperationsProjection,
      receipts: receiptEvidenceProjection.records,
    });
    return;
  }

  if (request.method === "POST" && pathname === "/v1/hypervisor/sessions") {
    responder.json({
      schema_version: "ioi.hypervisor.session_create_projection.v1",
      session_ref: ACTIVE_SESSION_REF,
      projection: sessionOperationsProjection,
      receipt_ref: "receipt://session/lifecycle/dev-replay",
    }, 202);
    return;
  }

  if (
    request.method === "GET" &&
    (pathname === "/v1/hypervisor/automation-compositor" ||
      pathname === "/v1/hypervisor/automations" ||
      pathname === "/v1/hypervisor/automation-runs")
  ) {
    responder.json(automationCompositorProjection);
    return;
  }

  if (request.method === "GET" && pathname.startsWith("/v1/hypervisor/automations/")) {
    responder.json({
      schema_version: "ioi.hypervisor.automation_detail.v1",
      automation: automationCompositorProjection.templates[0],
      graph: automationCompositorProjection.graphs[0],
      runs: automationCompositorProjection.runs,
    });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/applications") {
    responder.json(applicationsCatalog);
    return;
  }

  if (request.method === "GET" && pathname.startsWith("/v1/hypervisor/applications/")) {
    const id = decodeURIComponent(pathname.split("/").pop() ?? "");
    responder.json({
      schema_version: "ioi.hypervisor.application_detail.v1",
      application:
        applicationsCatalog.applications.find((application) => application.application_id === id) ??
        applicationsCatalog.applications[0],
    });
    return;
  }

  if (
    request.method === "GET" &&
    (pathname === "/v1/hypervisor/provider-placement" ||
      pathname === "/v1/hypervisor/environments" ||
      pathname === "/v1/hypervisor/compute-posture")
  ) {
    responder.json(
      pathname === "/v1/hypervisor/environments"
        ? {
            schema_version: "ioi.hypervisor.environments_projection.v1",
            environments: [
              {
                environment_ref: "environment:local-dev-replay",
                label: "Local dev replay",
                status: "running",
                provider_candidate_ref: "provider-candidate:local-workstation",
                vm: {
                  cpu: { usage_percent: 12.5, cores: 8 },
                  memory: { used_bytes: 2147483648, total_bytes: 17179869184 },
                },
              },
            ],
            provider_projection: providerPlacementProjection,
          }
        : providerPlacementProjection,
    );
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/privacy-posture") {
    responder.json(privacyPostureProjection);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/declassification-requests") {
    responder.json({
      schema_version: "ioi.hypervisor.declassification_requests.v1",
      requests: [
        {
          request_ref: "declassify-request:dev-replay/private-head-summary",
          status: "requires_wallet_review",
          receipt_ref: "receipt://privacy/declassification/dev-replay",
        },
      ],
    });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/model-infrastructure") {
    responder.json(modelInfrastructureProjection);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/model-routes") {
    responder.json(modelInfrastructureProjection);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/agents") {
    responder.json(agentsProjection);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workers") {
    responder.json({
      schema_version: "ioi.hypervisor.workers_projection.v1",
      workers: [
        {
          worker_ref: "worker:generic-cli-qwen",
          label: "Generic CLI / Qwen worker",
          status: "ready",
          harness_adapter_ref: "agent-harness-adapter:generic_cli",
        },
      ],
    });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/harness-adapters") {
    responder.json(harnessAdapterCatalog());
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/receipt-evidence") {
    responder.json(receiptEvidenceProjection);
    return;
  }

  if (
    request.method === "GET" &&
    (pathname === "/v1/hypervisor/receipts" ||
      pathname === "/v1/hypervisor/artifact-refs" ||
      pathname === "/v1/hypervisor/archive-restore-validity")
  ) {
    responder.json(
      pathname === "/v1/hypervisor/receipts"
        ? receiptEvidenceProjection
        : {
            schema_version: "ioi.hypervisor.receipt_support_projection.v1",
            artifact_refs: receiptEvidenceProjection.records.flatMap(
              (record) => record.artifact_refs,
            ),
            archive_restore_validity: {
              restore_ref: "agentgres://restore/hypervisor-core/dev-replay",
              valid: true,
              receipt_ref: "receipt://project/hypervisor-core/restore-validity",
            },
          },
    );
    return;
  }

  if (request.method === "GET" && pathname.startsWith("/v1/hypervisor/receipts/")) {
    const receiptId = decodeURIComponent(pathname.split("/").pop() ?? "");
    responder.json({
      schema_version: "ioi.hypervisor.receipt_detail.v1",
      receipt:
        receiptEvidenceProjection.records.find((record) =>
          record.receipt_ref.endsWith(receiptId),
        ) ?? receiptEvidenceProjection.records[0],
    });
    return;
  }

  if (request.method === "GET" && pathname.startsWith("/v1/hypervisor/replay/")) {
    responder.json({
      schema_version: "ioi.hypervisor.replay_detail.v1",
      replay_id: decodeURIComponent(pathname.split("/").pop() ?? "dev-replay"),
      timeline: receiptEvidenceProjection.records.map((record, index) => ({
        index,
        receipt_ref: record.receipt_ref,
        state_root_ref: record.state_root_ref,
        replay_ref: record.replay_ref,
      })),
    });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/snapshot") {
    responder.json(workbenchSnapshot());
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/files") {
    responder.json(listWorkspaceDirectory(url.searchParams.get("path") ?? WORKSPACE_ROOT_LABEL));
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/file") {
    responder.json(workspaceFile(url.searchParams.get("path")));
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/git/status") {
    responder.json(sourceControlState());
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/git/diff") {
    responder.json(workspaceDiff(url.searchParams.get("path")));
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/problems") {
    responder.json(workbenchSnapshot().problems);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/ports") {
    responder.json(sessionOperationsProjection.ports_services);
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/workbench/logs") {
    responder.json(workbenchSnapshot().logs);
    return;
  }

  if (request.method === "POST" && pathname === "/v1/hypervisor/workbench/terminal") {
    responder.json(terminalSession("terminal:dev-replay/default", requestBody.cols, requestBody.rows), 201);
    return;
  }

  const terminalReadMatch = pathname.match(
    /^\/v1\/hypervisor\/workbench\/terminal\/([^/]+)\/read$/,
  );
  if (request.method === "GET" && terminalReadMatch) {
    responder.json(
      terminalReadResult(
        decodeURIComponent(terminalReadMatch[1]),
        Number(url.searchParams.get("cursor") ?? 0),
      ),
    );
    return;
  }

  const terminalWriteMatch = pathname.match(
    /^\/v1\/hypervisor\/workbench\/terminal\/([^/]+)\/write$/,
  );
  if (request.method === "POST" && terminalWriteMatch) {
    responder.json({
      ok: true,
      sessionId: decodeURIComponent(terminalWriteMatch[1]),
      receipt_ref: "receipt://terminal/dev-replay/write",
    });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/foundry/jobs") {
    responder.json({ schema_version: foundryState.schema_version, jobs: foundryState.jobs });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/foundry/evals") {
    responder.json({ schema_version: foundryState.schema_version, evals: foundryState.evals });
    return;
  }

  if (request.method === "GET" && pathname === "/v1/hypervisor/foundry/packages") {
    responder.json({
      schema_version: foundryState.schema_version,
      packages: foundryState.packages,
    });
    return;
  }

  if (request.method === "POST") {
    if (pathname === "/v1/hypervisor/projects") {
      let record;
      try {
        record = projectRecordFromCreateRequest(requestBody);
      } catch (error) {
        responder.json({
          error: {
            code: "invalid_project_create_request",
            message:
              error instanceof Error
                ? error.message
                : "Project create request was invalid.",
          },
        }, 400);
        return;
      }
      const existingIndex = projectRecords.findIndex(
        (project) => project.project_id === record.project_id,
      );
      if (existingIndex >= 0) {
        projectRecords[existingIndex] = record;
      } else {
        projectRecords.push(record);
      }
      responder.json(buildProjectStateProjection(record.project_id), 201);
      return;
    }
    const genericPostRoutes = new Map([
      ["/v1/hypervisor/code-editor-adapter-launch-plans", () => codeEditorAdapterAdmission(requestBody)],
      ["/v1/hypervisor/session-launch-recipe-admissions", () => sessionLaunchRecipeAdmission(requestBody)],
      ["/v1/hypervisor/harness-session-binding-admissions", () => harnessBindingAdmission(requestBody)],
      ["/v1/hypervisor/harness-session-launches", () => harnessSessionLaunch(requestBody)],
      ["/v1/hypervisor/harness-session-spawns", () => harnessSessionSpawn(requestBody)],
      ["/v1/hypervisor/harness-session-readiness", () => harnessSessionReadiness(requestBody)],
      ["/v1/hypervisor/harness-session-terminal-attachments", () => harnessSessionTerminalAttach(requestBody)],
      ["/v1/hypervisor/harness-public-fixture-runs", () => ({
        schema_version: "ioi.hypervisor.harness_comparison_run.v1",
        run_id: "harness-comparison:dev-replay/qwen",
        task_ref: "task:reference-parity/local-qwen",
        comparison_mode: "same_fixture",
        candidate_selection_refs: [
          "agent-harness-adapter:codex_cli",
          "agent-harness-adapter:deepseek_tui",
          "agent-harness-adapter:claude_code_cli",
          "agent-harness-adapter:generic_cli",
        ],
        acceptance_criteria_refs: ["criteria:route-backed-demo"],
        receipt_refs: ["receipt://foundry/harness-comparison/dev-replay"],
        candidate_reports: [
          {
            selection_ref: "agent-harness-adapter:codex_cli",
            label: "Codex OSS / Qwen",
            execution_lane: "host_dev",
            output_summary: "Codex OSS adapter is ready for local Qwen session launch.",
            estimated_cost_usd: 0,
            verification_status: "passed",
            receipt_ref: "receipt://foundry/harness-comparison/codex-qwen",
            evidence_refs: [
              "receipt://foundry/harness-comparison/codex-qwen",
              "artifact://sessions/local-qwen/codex-cli-transcript",
            ],
          },
          {
            selection_ref: "agent-harness-adapter:deepseek_tui",
            label: "DeepSeek TUI / Qwen",
            execution_lane: "host_dev",
            output_summary: "DeepSeek TUI adapter is ready for local Qwen session launch.",
            estimated_cost_usd: 0,
            verification_status: "passed",
            receipt_ref: "receipt://foundry/harness-comparison/deepseek-qwen",
            evidence_refs: [
              "receipt://foundry/harness-comparison/deepseek-qwen",
              "artifact://sessions/local-qwen/deepseek-tui-transcript",
            ],
          },
          {
            selection_ref: "agent-harness-adapter:claude_code_cli",
            label: "Claude Code example / Qwen",
            execution_lane: "host_dev",
            output_summary: "Claude Code example adapter is ready for local Qwen session launch.",
            estimated_cost_usd: 0,
            verification_status: "passed",
            receipt_ref: "receipt://foundry/harness-comparison/claude-code-qwen",
            evidence_refs: [
              "receipt://foundry/harness-comparison/claude-code-qwen",
              "artifact://sessions/local-qwen/claude-code-transcript",
            ],
          },
          {
            selection_ref: "agent-harness-adapter:generic_cli",
            label: "Generic CLI / Qwen",
            execution_lane: "host_dev",
            output_summary: "Generic CLI adapter is ready for local Qwen session launch.",
            estimated_cost_usd: 0,
            verification_status: "passed",
            receipt_ref: "receipt://foundry/harness-comparison/generic-cli-qwen",
            evidence_refs: [
              "receipt://foundry/harness-comparison/generic-cli-qwen",
              "artifact://sessions/local-qwen/generic-cli-transcript",
            ],
          },
        ],
      })],
      ["/v1/hypervisor/project-operations", () => genericAdmission("project-operation", requestBody)],
      ["/v1/hypervisor/session-operations/proposals", () => genericAdmission("session-operation", requestBody)],
      ["/v1/hypervisor/automation-runs/proposals", () => genericAdmission("automation-run", requestBody)],
      ["/v1/hypervisor/model-routes/proposals", () => genericAdmission("model-route", requestBody)],
      ["/v1/hypervisor/model-route-mutation-admissions", () => genericAdmission("model-route-mutation", requestBody)],
      ["/v1/hypervisor/approvals/proposals", () => genericAdmission("approval", requestBody)],
      ["/v1/hypervisor/harness-adapters/proposals", () => genericAdmission("harness-adapter", requestBody)],
      ["/v1/hypervisor/foundry/jobs/proposals", () => genericAdmission("foundry-job", requestBody)],
      ["/v1/hypervisor/declassification-requests/proposals", () => genericAdmission("declassification", requestBody)],
      ["/v1/hypervisor/model-weight-custody-admissions", () => genericAdmission("model-weight-custody", requestBody)],
      ["/v1/hypervisor/private-workspace-mount-admissions", () => genericAdmission("private-workspace-mount", requestBody)],
      ["/v1/hypervisor/worker-package-install-admissions", () => genericAdmission("worker-package-install", requestBody)],
    ]);
    const handler = genericPostRoutes.get(pathname);
    if (handler) {
      responder.json(handler(), 202);
      return;
    }
    if (pathname.startsWith("/v1/hypervisor/applications/") && pathname.endsWith("/pin")) {
      responder.json(genericAdmission("application-pin", requestBody), 202);
      return;
    }
  }

  if (pathname.startsWith("/v1/model-mount/")) {
    responder.json({
      schema_version: "ioi.hypervisor.model_mount_dev_replay_response.v1",
      ok: true,
      path: pathname,
      method: request.method,
      snapshot: modelMountSnapshot,
      receipt_ref: "receipt://model-mount/dev-replay/generic",
    });
    return;
  }

  responder.json(
    {
      error: {
        code: "hypervisor_dev_replay_route_not_found",
        message: `${request.method} ${pathname} is not implemented by the Hypervisor dev replay server.`,
      },
    },
    404,
    "not-found",
  );
}

export function createHypervisorAppDevReplayServer(options = {}) {
  const host = options.host ?? DEFAULT_HOST;
  const evidencePath = options.evidencePath ?? "";
  const evidence = createEvidenceState();
  let endpoint = `http://${host}:${options.port ?? DEFAULT_PORT}`;
  const server = createServer((request, response) => {
    handleRequest({
      request,
      response,
      evidence,
      evidencePath,
      endpoint,
    }).catch((error) => {
      const responder = createResponder(response, evidence, evidencePath, {
        method: request.method ?? "GET",
        path: request.url ?? "/",
        query: {},
        family: "error",
        request_hash: "",
        started_at: new Date().toISOString(),
      });
      responder.json(
        {
          error: {
            code: "hypervisor_dev_replay_error",
            message: error instanceof Error ? error.message : String(error),
          },
        },
        error?.status ?? 500,
        "error",
      );
    });
  });
  return {
    server,
    evidence,
    get endpoint() {
      return endpoint;
    },
    setEndpoint(nextEndpoint) {
      endpoint = nextEndpoint;
    },
    writeEvidence() {
      writeEvidenceFile(evidencePath, evidence);
    },
  };
}

function listenOnce(server, host, port) {
  return new Promise((resolveListen, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolveListen(server.address());
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
}

export async function startHypervisorAppDevReplayServer(options = {}) {
  const host = options.host ?? DEFAULT_HOST;
  const requestedPort = options.port ?? DEFAULT_PORT;
  let lastError = null;
  for (let offset = 0; offset < 25; offset += 1) {
    const port = requestedPort === 0 ? 0 : requestedPort + offset;
    const replay = createHypervisorAppDevReplayServer({
      ...options,
      host,
      port,
    });
    try {
      const address = await listenOnce(replay.server, host, port);
      const resolvedPort =
        typeof address === "object" && address ? address.port : port;
      const endpoint = `http://${host}:${resolvedPort}`;
      replay.setEndpoint(endpoint);
      replay.writeEvidence();
      return {
        ...replay,
        endpoint,
        port: resolvedPort,
        close: () =>
          new Promise((resolveClose, rejectClose) => {
            replay.server.close((error) => {
              if (error) rejectClose(error);
              else resolveClose();
            });
          }),
      };
    } catch (error) {
      lastError = error;
      if (error?.code !== "EADDRINUSE" || requestedPort === 0) {
        throw error;
      }
    }
  }
  throw lastError ?? new Error("Unable to start Hypervisor dev replay server");
}

async function main() {
  const options = parseArgs();
  const replay = await startHypervisorAppDevReplayServer(options);
  console.log(
    `[hypervisor-dev-replay] serving ${replay.endpoint} (${replay.evidence.requests.length} recorded requests)`,
  );
  if (options.evidencePath) {
    console.log(`[hypervisor-dev-replay] evidence ${options.evidencePath}`);
  }
  if (options.once) {
    await fetch(`${replay.endpoint}/v1/hypervisor/dev-replay/status`);
    await fetch(`${replay.endpoint}/v1/model-mount/snapshot`);
    await replay.close();
    return;
  }
  const shutdown = async () => {
    replay.writeEvidence();
    await replay.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error("[hypervisor-dev-replay] failed", error);
    process.exit(1);
  });
}
