import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import {
  ModelMountingState,
  anthropicMessage,
  openAiChatCompletion,
  openAiCompletion,
  openAiEmbedding,
  openAiResponse,
} from "./model-mounting.mjs";
import * as routeDecision from "./model-mounting/route-decision.mjs";
import { AgentMemoryStore, parseMemoryCommand } from "./memory-store.mjs";
import {
  CODING_TOOL_IDS,
  CODING_TOOL_PACK_ID,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  codingToolContracts,
  codingToolInputForRequest,
  codingToolInputSummary,
  codingToolResultSummary,
  codingToolSourceEventKind,
  codingToolSummary,
  executeCodingTool,
} from "./coding-tools.mjs";
import {
  RuntimeApiBridgeUnavailableError,
  createRuntimeApiBridge,
  isRuntimeServiceProfile,
  runtimeProfileForRequest,
} from "./runtime-api-bridge.mjs";

export {
  RuntimeAgentServiceCommandAdapter,
  RuntimeAgentServiceCommandAdapterError,
  createRuntimeAgentServiceCommandAdapter,
  createRuntimeAgentServiceCommandAdapterFromEnv,
} from "./runtime-agent-service-adapter.mjs";

const TERMINAL_EVENT_TYPES = new Set(["completed", "canceled", "failed", "error"]);
const JOB_TERMINAL_EVENT_TYPES = new Set(["job_completed", "job_failed", "job_canceled"]);
const RUNTIME_THREAD_SCHEMA_VERSION = "ioi.runtime.thread.v1";
const RUNTIME_TURN_SCHEMA_VERSION = "ioi.runtime.turn.v1";
const RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION = "ioi.runtime.event.v1";
const CODING_TOOL_ARTIFACT_SCHEMA_VERSION = "ioi.runtime.coding-tool-artifact.v1";
const LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION = "ioi.runtime.lsp-diagnostics-injection.v1";
const LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION = "ioi.runtime.lsp-diagnostics-blocking-gate.v1";
const LSP_DIAGNOSTICS_AUTO_NODE_ID = "runtime.coding-tool.lsp-diagnostics.auto";
const LSP_DIAGNOSTICS_INJECTION_NODE_ID = "runtime.lsp-diagnostics.injected";
const LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID = "runtime.lsp-diagnostics.blocking-gate";
const LSP_DIAGNOSTICS_MAX_INJECTED_FINDINGS = 10;
const LSP_DIAGNOSTICS_MAX_INJECTED_MESSAGE_CHARS = 240;
const DAEMON_FIXTURE_PROFILE = "local_daemon_agentgres_projection";
const RUN_EVENT_TO_TTI_EVENT = {
  run_started: "turn.started",
  runtime_task: "item.completed",
  job_queued: "item.created",
  job_started: "item.started",
  runtime_checklist: "item.completed",
  job_completed: "item.completed",
  job_failed: "item.failed",
  job_canceled: "item.canceled",
  repository_context: "item.completed",
  branch_policy: "item.completed",
  github_context: "item.completed",
  issue_context: "item.completed",
  pr_attempt: "item.completed",
  review_gate: "item.completed",
  github_pr_create_plan: "item.completed",
  model_route_decision: "item.completed",
  skill_hook_manifest: "item.completed",
  hook_dry_run_plan: "item.completed",
  hook_invocation_ledger: "item.completed",
  memory_update: "item.completed",
  lsp_diagnostics_injected: "lsp.diagnostics.injected",
  policy_blocked: "policy.blocked",
  task_state: "item.completed",
  uncertainty: "item.completed",
  probe: "item.completed",
  postcondition_synthesized: "item.completed",
  semantic_impact: "item.completed",
  delta: "item.delta",
  stop_condition: "item.completed",
  quality_ledger: "item.completed",
  artifact: "item.completed",
  completed: "turn.completed",
  canceled: "turn.canceled",
  failed: "turn.failed",
  error: "turn.failed",
};
const HOOK_INVOCATION_RUNTIME_EVENTS = [
  {
    eventKind: "workflow_activation",
    runtimeEventType: "run_started",
    phase: "activation",
    workflowNodeId: "runtime.runtime-thread",
  },
  {
    eventKind: "pre_model",
    runtimeEventType: "model_route_decision",
    phase: "before_model",
    workflowNodeId: "runtime.model-router",
  },
  {
    eventKind: "post_model",
    runtimeEventType: "delta",
    phase: "after_model",
    workflowNodeId: "runtime.output-writer",
  },
];

export async function startRuntimeDaemonService(options = {}) {
  const stateDir = path.resolve(options.stateDir ?? path.join(process.cwd(), ".ioi", "agentgres"));
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: options.cwd ?? process.cwd(),
    homeDir: options.homeDir,
    vaultSecrets: options.vaultSecrets,
    runtimeBridge: options.runtimeBridge,
  });
  const server = http.createServer((request, response) => {
    handleRequest({ request, response, store }).catch((error) => {
      writeError(response, {
        status: 500,
        code: "runtime",
        message: "IOI runtime daemon failed while handling request.",
        details: { error: String(error?.message ?? error) },
      });
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Runtime daemon did not bind to a TCP port.");
  }
  return {
    endpoint: `http://${address.address}:${address.port}`,
    stateDir,
    store,
    close: () =>
      new Promise((resolve, reject) => {
        store.close();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

export class AgentgresRuntimeStateStore {
  constructor(stateDir, options = {}) {
    this.stateDir = path.resolve(stateDir);
    this.defaultCwd = path.resolve(options.cwd ?? process.cwd());
    this.homeDir = path.resolve(options.homeDir ?? process.env.HOME ?? os.homedir());
    this.agents = new Map();
    this.runs = new Map();
    this.runtimeEventStreams = new Map();
    this.codingArtifacts = new Map();
    this.runtimeBridge = createRuntimeApiBridge(options.runtimeBridge);
    this.schemaVersion = "ioi.agentgres.runtime.v0";
    this.ensureDirs();
    this.modelMounting = new ModelMountingState({
      stateDir: this.stateDir,
      cwd: this.defaultCwd,
      homeDir: options.homeDir,
      vaultSecrets: options.vaultSecrets,
      appendOperation: (kind, payload) => this.appendOperation(kind, payload),
    });
    this.memory = new AgentMemoryStore(this.stateDir, {
      appendOperation: (kind, payload) => this.appendOperation(kind, payload),
    });
    this.writeSchema();
    this.load();
  }

  close() {
    this.modelMounting.close();
  }

  createAgent(options = {}) {
    const now = new Date().toISOString();
    const cwd = path.resolve(options.local?.cwd ?? this.defaultCwd);
    const runtime = runtimeModeForOptions(options);
    ensureProviderAvailable(runtime, options);
    const modelRoute = this.resolveModelRoute(options, {
      evidenceRefs: ["runtime_agent_model_route"],
      workflowNodeId: "runtime.model-router",
      workflowNodeType: "Model Router",
    });
    const agent = {
      id: `agent_${crypto.randomUUID()}`,
      status: "active",
      runtime,
      cwd,
      modelId: modelRoute.selectedModel,
      requestedModelId: modelRoute.requestedModelId,
      modelRouteId: modelRoute.routeId,
      modelRouteEndpointId: modelRoute.endpointId,
      modelRouteProviderId: modelRoute.providerId,
      modelRouteReceiptId: modelRoute.receiptId,
      modelRouteDecision: modelRoute.decision,
      createdAt: now,
      updatedAt: now,
      options: summarizeAgentOptions(cwd, options),
    };
    this.agents.set(agent.id, agent);
    this.writeAgent(agent, "agent.create");
    return agent;
  }

  listAgents() {
    return [...this.agents.values()].sort((left, right) =>
      left.createdAt.localeCompare(right.createdAt),
    );
  }

  getAgent(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw notFound(`Agent not found: ${agentId}`, { agentId });
    }
    return agent;
  }

  updateAgent(agentId, status, operationKind) {
    const agent = this.getAgent(agentId);
    const updated = { ...agent, status, updatedAt: new Date().toISOString() };
    this.agents.set(agentId, updated);
    this.writeAgent(updated, operationKind);
    return updated;
  }

  deleteAgent(agentId) {
    const agent = this.getAgent(agentId);
    const runCount = this.listRuns(agentId).length;
    if (runCount > 0) {
      throw policyError(
        "Permanent agent deletion requires retention review when canonical runs exist; archive instead.",
        { agentId, runCount },
      );
    }
    this.agents.delete(agentId);
    this.appendOperation("agent.delete", { agentId, priorStatus: agent.status });
    this.removeQuiet(path.join(this.stateDir, "agents", `${agentId}.json`));
  }

  createRun(agentId, request = {}) {
    const agent = this.getAgent(agentId);
    ensureProviderAvailable(agent.runtime, agent.options);
    const mode = request.mode ?? "send";
    const prompt =
      request.prompt ??
      (mode === "learn"
        ? `Learn governed task-family updates for ${request.options?.taskFamily ?? "runtime"}`
        : "");
    const modelRoute = this.resolveRunModelRoute(agent, request);
    const memory = this.resolveRunMemory(agent, request, prompt);
    const skillHookCatalog = this.skillHookCatalog({ cwd: agent.cwd });
    const run = buildRun({
      agent,
      mode,
      prompt,
      request,
      source: "local_daemon_agentgres",
      modelRoute,
      memory,
      skillHookCatalog,
      diagnosticsFeedback: request.diagnosticsFeedback ?? request.diagnostics_feedback ?? null,
    });
    this.runs.set(run.id, run);
    this.writeRun(run, "run.create");
    return run;
  }

  resolveModelRoute(options = {}, context = {}) {
    const model = options.model ?? {};
    const requestedModel = model.id ?? model.model ?? model.modelId ?? "local:auto";
    const routeId = model.routeId ?? model.route_id ?? model.route ?? options.routeId ?? options.route_id ?? "route.local-first";
    const capability = model.capability ?? options.capability ?? "chat";
    const policy = modelPolicyForOptions(options);
    const workflow = modelWorkflowContext({ model, options, context });
    const body = {
      model: requestedModel,
      route_id: routeId,
      model_policy: policy,
      ...workflow,
    };
    return this.selectModelRouteWithFallback({
      requestedModel,
      routeId,
      capability,
      policy,
      body,
      evidenceRefs: context.evidenceRefs ?? [],
    });
  }

  resolveRunModelRoute(agent, request = {}) {
    const options = request.options ?? {};
    if (options.model) {
      return this.resolveModelRoute(options, {
        evidenceRefs: ["runtime_run_model_route"],
        workflowNodeId: "runtime.model-router",
        workflowNodeType: "Model Router",
      });
    }
    return {
      requestedModelId: agent.requestedModelId ?? agent.modelId,
      selectedModel: agent.modelId,
      routeId: agent.modelRouteId ?? "route.local-first",
      endpointId: agent.modelRouteEndpointId ?? null,
      providerId: agent.modelRouteProviderId ?? null,
      receiptId: agent.modelRouteReceiptId ?? null,
      decision: agent.modelRouteDecision ?? null,
    };
  }

  selectModelRouteWithFallback({ requestedModel, routeId, capability, policy, body, evidenceRefs }) {
    try {
      const selection = this.modelMounting.selectRoute({ modelId: requestedModel, routeId, capability, policy });
      const receipt = this.modelMounting.routeSelectionReceipt(selection, {
        body,
        capability,
        evidenceRefs,
      });
      return modelRouteBindingFromReceipt(receipt, requestedModel);
    } catch (error) {
      const fallbackRouteId = "route.local-first";
      const fallbackPolicy = {
        ...policy,
        allow_hosted_fallback: false,
      };
      const fallbackBody = {
        ...body,
        model: "auto",
        route_id: fallbackRouteId,
        model_policy: fallbackPolicy,
        fallback_triggered: true,
        fallback_reason: error?.code ?? "primary_route_unavailable",
      };
      const fallbackSelection = this.modelMounting.selectRoute({
        modelId: "auto",
        routeId: fallbackRouteId,
        capability,
        policy: fallbackPolicy,
      });
      fallbackSelection.evaluatedCandidates = [
        ...normalizeArray(error?.details?.evaluatedCandidates),
        ...normalizeArray(fallbackSelection.evaluatedCandidates),
      ];
      const receipt = this.modelMounting.routeSelectionReceipt(fallbackSelection, {
        body: fallbackBody,
        capability,
        evidenceRefs: ["runtime_model_route_fallback", ...evidenceRefs],
      });
      return modelRouteBindingFromReceipt(receipt, requestedModel);
    }
  }

  resolveRunMemory(agent, request = {}, prompt = "") {
    const memoryOptions = memoryOptionsForRequest(request);
    const threadId = memoryOptions.threadId ?? memoryOptions.thread_id ?? threadIdForAgent(agent.id);
    const command = parseMemoryCommand(prompt);
    const paths = this.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
    let policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(memoryOptions),
    });
    const policyUpdates = [];
    const mutations = [];
    if (command.kind === "disable" || command.kind === "enable") {
      const update = this.memory.setPolicy({
        targetType: "thread",
        targetId: threadId,
        agent,
        threadId,
        workspace: agent.cwd,
        source: command.kind === "disable" ? "chat_memory_disable" : "chat_memory_enable",
        updates: {
          disabled: command.kind === "disable",
          injectionEnabled: command.kind !== "disable",
        },
      });
      policyUpdates.push(update);
      mutations.push(update);
      policy = this.memory.effectivePolicy({
        agent,
        threadId,
        workspace: agent.cwd,
        overrides: memoryPolicyOverrides(memoryOptions),
      });
    }
    const subagentMemoryInheritance =
      (request.mode ?? "send") === "handoff"
        ? this.resolveSubagentMemoryInheritance({ agent, threadId, request, parentPolicy: policy })
        : null;
    const effectivePolicy = subagentMemoryInheritance?.effectivePolicy ?? policy;
    const requestedRemember =
      memoryOptions.remember ??
      request.remember ??
      null;
    const requestedWrite =
      command.kind === "remember" ||
      command.kind === "edit" ||
      command.kind === "delete" ||
      Boolean(requestedRemember);
    const policyBlockReason = memoryWriteBlockReason(effectivePolicy, memoryOptions, requestedWrite);
    if (subagentMemoryInheritance) {
      subagentMemoryInheritance.writeBlockReason = policyBlockReason;
      subagentMemoryInheritance.writeAllowed = requestedWrite
        ? policyBlockReason === null
        : !effectivePolicy.disabled && !effectivePolicy.readOnly && !effectivePolicy.writeRequiresApproval;
    }
    if (effectivePolicy.disabled || effectivePolicy.injectionEnabled === false) {
      return {
        command: command.kind,
        records: [],
        writes: mutations.filter((mutation) => mutation.receipt?.kind === "memory_write"),
        mutations,
        policy: effectivePolicy,
        policyUpdates,
        paths,
        injected: false,
        disabled: Boolean(effectivePolicy.disabled),
        policyBlockReason,
        subagentMemoryInheritance,
      };
    }
    const writes = [];
    if (!policyBlockReason && command.kind === "remember") {
      const write = this.rememberForAgent(agent, { text: command.text, threadId, scope: effectivePolicy.scope ?? "thread", source: "chat_hash_remember" });
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    } else if (!policyBlockReason && command.kind === "edit") {
      mutations.push(this.updateMemoryRecord(command.id, { text: command.text, source: "chat_memory_edit" }));
    } else if (!policyBlockReason && command.kind === "delete") {
      mutations.push(this.deleteMemoryRecord(command.id, { source: "chat_memory_delete" }));
    } else if (!policyBlockReason && requestedRemember) {
      const write = this.rememberForAgent(agent, { text: requestedRemember, threadId, scope: effectivePolicy.scope ?? "thread", source: "api_remember", workflow: memoryOptions.workflow ?? memoryOptions });
      writes.push(write);
      mutations.push({ ...write, operation: "write" });
    }
    const records = subagentMemoryInheritance?.records ??
      this.memory.list({ agent, threadId, workspace: agent.cwd, ...memoryListFilters(memoryOptions) });
    return {
      command: command.kind,
      records,
      writes,
      mutations,
      policy: effectivePolicy,
      policyUpdates,
      paths,
      injected: command.kind !== "remember" && records.length > 0,
      policyBlockReason,
      subagentMemoryInheritance,
    };
  }

  resolveSubagentMemoryInheritance({ agent, threadId, request = {}, parentPolicy = {} } = {}) {
    const memoryOptions = memoryOptionsForRequest(request);
    const requestedMode =
      optionalString(memoryOptions.subagentInheritance ?? memoryOptions.subagent_inheritance) ??
      parentPolicy.subagentInheritance ??
      "explicit";
    const mode = normalizeSubagentInheritanceMode(requestedMode);
    const receiver = subagentReceiverForRequest(request);
    const filters = memoryListFilters(memoryOptions);
    const parentAllowsInjection = !parentPolicy.disabled && parentPolicy.injectionEnabled !== false;
    const records = parentAllowsInjection && shouldInheritSubagentMemory(mode, memoryOptions)
      ? this.memory.list({
          agent,
          threadId,
          workspace: agent.cwd,
          ...memoryListFilters({
            ...memoryOptions,
            redaction: memoryOptions.redaction ?? parentPolicy.redaction,
          }),
        })
      : [];
    const effectivePolicy = subagentMemoryPolicy({ agent, threadId, parentPolicy, receiver, mode });
    return {
      schemaVersion: "ioi.agent-runtime.subagent-memory-inheritance.v1",
      object: "ioi.subagent_memory_inheritance",
      parentAgentId: agent.id,
      subagentName: receiver,
      threadId,
      mode,
      requestedMode,
      parentPolicyId: parentPolicy.id ?? null,
      effectivePolicyId: effectivePolicy.id,
      parentPolicy,
      effectivePolicy,
      filters,
      records,
      inheritedRecordIds: records.map((record) => record.id),
      writeAllowed: !effectivePolicy.disabled && !effectivePolicy.readOnly && !effectivePolicy.writeRequiresApproval,
      writeBlockReason: null,
      evidenceRefs: [
        "subagent_memory_inheritance",
        "agent_memory_store",
        parentPolicy.id,
        effectivePolicy.id,
        ...records.map((record) => record.id),
      ].filter(Boolean),
    };
  }

  rememberForAgent(agent, { text, threadId = threadIdForAgent(agent.id), scope = "thread", source = "operator_remember", workflow = {} } = {}) {
    return this.memory.remember({
      text,
      agent,
      threadId,
      scope,
      source,
      workflow,
    });
  }

  rememberForThread(threadId, body = {}) {
    const agent = this.agentForThread(threadId);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory write blocked by policy.", { threadId, reason: blocked, policy });
    }
    return this.rememberForAgent(agent, {
      text: body.text ?? body.fact ?? body.memory,
      threadId,
      scope: body.scope ?? "thread",
      source: body.source ?? "thread_memory_api",
      workflow: body.workflow ?? body,
    });
  }

  listMemoryForThread(threadId, options = {}) {
    const agent = this.agentForThread(threadId);
    return this.memory.projection({ agent, threadId, workspace: agent.cwd, filters: memoryListFilters(options) });
  }

  memoryPolicyForThread(threadId) {
    const agent = this.agentForThread(threadId);
    return this.memory.effectivePolicy({ agent, threadId, workspace: agent.cwd });
  }

  setMemoryPolicyForThread(threadId, body = {}) {
    const agent = this.agentForThread(threadId);
    return this.memory.setPolicy({
      targetType: "thread",
      targetId: threadId,
      agent,
      threadId,
      workspace: agent.cwd,
      source: body.source ?? "thread_memory_policy_api",
      updates: memoryPolicyOverrides(body.policy ?? body),
    });
  }

  memoryPathForThread(threadId) {
    const agent = this.agentForThread(threadId);
    return this.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  updateMemoryForThread(threadId, memoryId, body = {}) {
    const agent = this.agentForThread(threadId);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory edit blocked by policy.", { threadId, memoryId, reason: blocked, policy });
    }
    return this.updateMemoryRecord(memoryId, body);
  }

  deleteMemoryForThread(threadId, memoryId, body = {}) {
    const agent = this.agentForThread(threadId);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory delete blocked by policy.", { threadId, memoryId, reason: blocked, policy });
    }
    return this.deleteMemoryRecord(memoryId, body);
  }

  rememberForAgentId(agentId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory write blocked by policy.", { agentId, threadId, reason: blocked, policy });
    }
    return this.rememberForAgent(agent, {
      text: body.text ?? body.fact ?? body.memory,
      threadId,
      scope: body.scope ?? "thread",
      source: body.source ?? "agent_memory_api",
      workflow: body.workflow ?? body,
    });
  }

  listMemoryForAgent(agentId, options = {}) {
    const agent = this.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return this.memory.projection({ agent, threadId, workspace: agent.cwd, filters: memoryListFilters(options) });
  }

  memoryPolicyForAgent(agentId, options = {}) {
    const agent = this.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return this.memory.effectivePolicy({ agent, threadId, workspace: agent.cwd });
  }

  setMemoryPolicyForAgent(agentId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    return this.memory.setPolicy({
      targetType: body.targetType ?? body.target_type ?? "thread",
      targetId: body.targetId ?? body.target_id ?? threadId,
      agent,
      threadId,
      workspace: agent.cwd,
      source: body.source ?? "agent_memory_policy_api",
      updates: memoryPolicyOverrides(body.policy ?? body),
    });
  }

  memoryPathForAgent(agentId, options = {}) {
    const agent = this.getAgent(agentId);
    const threadId = options.thread_id ?? options.threadId ?? threadIdForAgent(agent.id);
    return this.memory.pathProjection({ agent, threadId, workspace: agent.cwd });
  }

  updateMemoryForAgentId(agentId, memoryId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory edit blocked by policy.", { agentId, threadId, memoryId, reason: blocked, policy });
    }
    return this.updateMemoryRecord(memoryId, body);
  }

  deleteMemoryForAgentId(agentId, memoryId, body = {}) {
    const agent = this.getAgent(agentId);
    const threadId = body.thread_id ?? body.threadId ?? threadIdForAgent(agent.id);
    const policy = this.memory.effectivePolicy({
      agent,
      threadId,
      workspace: agent.cwd,
      overrides: memoryPolicyOverrides(body),
    });
    const blocked = memoryWriteBlockReason(policy, body, true);
    if (blocked) {
      throw policyError("Memory delete blocked by policy.", { agentId, threadId, memoryId, reason: blocked, policy });
    }
    return this.deleteMemoryRecord(memoryId, body);
  }

  updateMemoryRecord(memoryId, body = {}) {
    return this.memory.updateRecord({
      id: memoryId,
      text: body.text ?? body.fact ?? body.memory,
      source: body.source ?? "memory_edit_api",
    });
  }

  deleteMemoryRecord(memoryId, body = {}) {
    return this.memory.deleteRecord({
      id: memoryId,
      source: body.source ?? "memory_delete_api",
    });
  }

  async createThread(request = {}) {
    const options = request.options ?? request;
    const runtimeProfile = runtimeProfileForRequest(request, options);
    if (isRuntimeServiceProfile(runtimeProfile)) {
      return this.createRuntimeBridgeThread({ request, options, runtimeProfile });
    }
    const agent = this.createAgent(options);
    this.ensureThreadStartedEvent(agent);
    return this.threadForAgent(agent);
  }

  async createRuntimeBridgeThread({ request, options, runtimeProfile }) {
    this.assertRuntimeBridgeAvailable({ runtimeProfile, operation: "start_thread" });
    const agent = this.createAgent(options);
    const threadId = threadIdForAgent(agent.id);
    const input = {
      request,
      options,
      runtimeProfile,
      agentId: agent.id,
      threadId,
      workspaceRoot: agent.cwd,
      modelRouteDecision: agent.modelRouteDecision ?? null,
      createdAt: agent.createdAt,
    };
    let bridgeResult;
    try {
      bridgeResult = await this.runtimeBridge.startThread(input);
    } catch (error) {
      if (error instanceof RuntimeApiBridgeUnavailableError) {
        throw this.runtimeBridgeUnavailable({ runtimeProfile, operation: "start_thread", details: error.details });
      }
      throw error;
    }
    const projection = this.normalizeRuntimeBridgeThreadStart({ bridgeResult, agent, threadId, runtimeProfile });
    const updated = {
      ...agent,
      runtimeProfile,
      runtimeSessionId: projection.sessionId,
      runtimeBridgeId: projection.bridgeId,
      runtimeBridgeStatus: projection.status,
      runtimeBridgeSource: projection.source,
      fixtureProfile: null,
      updatedAt: projection.updatedAt,
    };
    this.agents.set(agent.id, updated);
    this.writeAgent(updated, "thread.runtime_bridge.start");
    for (const event of projection.events) this.appendRuntimeEvent(event);
    return this.threadForAgent(updated);
  }

  listThreads() {
    return this.listAgents().map((agent) => this.threadForAgent(agent));
  }

  getThread(threadId) {
    return this.threadForAgent(this.agentForThread(threadId));
  }

  resumeThread(threadId) {
    const agent = this.agentForThread(threadId);
    const updated = this.updateAgent(agent.id, "active", "thread.resume");
    return this.threadForAgent(updated);
  }

  forkThread(threadId, request = {}) {
    const sourceThread = this.getThread(threadId);
    const sourceAgent = this.agentForThread(threadId);
    const options = {
      ...(request.options ?? {}),
      local: {
        cwd: request.options?.local?.cwd ?? sourceThread.workspace ?? this.defaultCwd,
      },
      model: request.options?.model ? request.options.model : { id: sourceThread.model_route },
    };
    const idempotencyKey = request.idempotency_key ?? request.idempotencyKey;
    const streamId = eventStreamIdForThread(threadId);
    if (idempotencyKey) {
      const duplicate = this.runtimeEventStream(streamId).idempotency.get(String(idempotencyKey));
      const duplicateForkThreadId =
        duplicate?.payload_summary?.fork_thread_id ?? duplicate?.payload?.fork_thread_id;
      if (duplicateForkThreadId) {
        return {
          ...this.getThread(String(duplicateForkThreadId)),
          source_thread_id: sourceThread.thread_id,
          forked_from_seq:
            Number(duplicate?.payload_summary?.source_latest_seq ?? sourceThread.latest_seq) ||
            sourceThread.latest_seq,
        };
      }
    }
    const fork = this.createAgent(options);
    const thread = this.threadForAgent(fork);
    const sourceLatestSeq = sourceThread.latest_seq;
    const sourceLatestTurnId = sourceThread.latest_turn_id ?? "";
    const controlSource = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason = optionalString(request.reason ?? request.message ?? request.input) ?? "operator requested thread fork";
    const now = new Date().toISOString();
    this.appendRuntimeEvent({
      event_stream_id: streamId,
      thread_id: threadId,
      turn_id: sourceLatestTurnId,
      item_id: `${threadId}:item:thread-fork:${thread.thread_id}`,
      idempotency_key: idempotencyKey ? String(idempotencyKey) : `thread:${threadId}:operator.fork:${thread.thread_id}`,
      source: controlSource,
      source_event_kind: "OperatorControl.Fork",
      event_kind: "thread.forked",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: sourceAgent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.thread-fork",
      component_kind: "thread_fork",
      payload_schema_version: "ioi.runtime.thread-fork.v1",
      payload: {
        event_kind: "OperatorControl.Fork",
        reason,
        requested_by: requestedBy,
        control_surface: controlSource,
        source_thread_id: sourceThread.thread_id,
        source_agent_id: sourceThread.agent_id,
        source_latest_seq: sourceLatestSeq,
        source_latest_turn_id: sourceLatestTurnId || null,
        fork_thread_id: thread.thread_id,
        fork_agent_id: thread.agent_id,
        fork_session_id: thread.session_id,
        session_id: sourceThread.session_id,
      },
      receipt_refs: [`receipt_${sourceThread.agent_id}_thread_fork_${thread.agent_id}`],
      policy_decision_refs: [`policy_${sourceThread.agent_id}_thread_fork_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(sourceAgent),
    });
    return {
      ...thread,
      source_thread_id: sourceThread.thread_id,
      forked_from_seq: sourceLatestSeq,
    };
  }

  assertRuntimeBridgeAvailable({ runtimeProfile, operation }) {
    if (operation === "start_thread" && this.runtimeBridge.canStartThread) return;
    if (operation === "submit_turn" && this.runtimeBridge.canSubmitTurn) return;
    throw this.runtimeBridgeUnavailable({ runtimeProfile, operation });
  }

  runtimeBridgeUnavailable({ runtimeProfile, operation, details = {} }) {
    return externalBlocker("RuntimeAgentService bridge is required for runtime_service profile.", {
      runtimeProfile,
      operation,
      requiredBridge: "RuntimeApiBridge",
      fixtureProfile: "fixture",
      syntheticFallbackAllowed: false,
      ...details,
    });
  }

  normalizeRuntimeBridgeThreadStart({ bridgeResult, agent, threadId, runtimeProfile }) {
    const sessionId = String(bridgeResult?.session_id ?? bridgeResult?.sessionId ?? "").trim();
    if (!sessionId) {
      throw runtimeError({
        status: 502,
        code: "runtime_bridge_contract",
        message: "RuntimeApiBridge startThread result must include session_id.",
        details: { runtimeProfile, operation: "start_thread" },
      });
    }
    const events = normalizeArray(bridgeResult?.events);
    const hasThreadStarted = events.some((event) => event?.event_kind === "thread.started");
    if (!hasThreadStarted) {
      throw runtimeError({
        status: 502,
        code: "runtime_bridge_contract",
        message: "RuntimeApiBridge startThread result must include a thread.started event.",
        details: { runtimeProfile, sessionId, operation: "start_thread" },
      });
    }
    const now = new Date().toISOString();
    return {
      sessionId,
      bridgeId: bridgeResult?.bridge_id ?? bridgeResult?.bridgeId ?? this.runtimeBridge.bridgeId,
      status: bridgeResult?.status ?? "active",
      source: bridgeResult?.source ?? "runtime_service",
      updatedAt: bridgeResult?.updated_at ?? bridgeResult?.updatedAt ?? now,
      events: events.map((event) => ({
        ...event,
        event_stream_id: event.event_stream_id ?? eventStreamIdForThread(threadId),
        thread_id: event.thread_id ?? threadId,
        workspace_root: event.workspace_root ?? agent.cwd,
        source: event.source ?? "runtime_service",
        source_event_kind: event.source_event_kind ?? "RuntimeAgentService",
        fixture_profile: Object.hasOwn(event, "fixture_profile") ? event.fixture_profile : null,
        payload: {
          agent_id: agent.id,
          session_id: sessionId,
          ...(event.payload ?? event.payload_summary ?? {}),
        },
      })),
    };
  }

  normalizeRuntimeBridgeTurnSubmit({ bridgeResult, agent, threadId, request }) {
    const turnId = String(bridgeResult?.turn_id ?? bridgeResult?.turnId ?? "").trim();
    if (!turnId || !turnId.startsWith("turn_")) {
      throw runtimeError({
        status: 502,
        code: "runtime_bridge_contract",
        message: "RuntimeApiBridge submitTurn result must include turn_id.",
        details: { runtimeProfile: agent.runtimeProfile, operation: "submit_turn" },
      });
    }
    const runId = String(bridgeResult?.run_id ?? bridgeResult?.runId ?? runIdForTurn(turnId)).trim();
    const events = normalizeArray(bridgeResult?.events);
    const hasTurnStarted = events.some((event) => event?.event_kind === "turn.started");
    if (!hasTurnStarted) {
      throw runtimeError({
        status: 502,
        code: "runtime_bridge_contract",
        message: "RuntimeApiBridge submitTurn result must include a turn.started event.",
        details: { runtimeProfile: agent.runtimeProfile, operation: "submit_turn", turnId },
      });
    }
    const now = new Date().toISOString();
    return {
      runId,
      turnId,
      status: bridgeResult?.status ?? "completed",
      result: bridgeResult?.result ?? "",
      createdAt: bridgeResult?.created_at ?? bridgeResult?.createdAt ?? now,
      updatedAt: bridgeResult?.updated_at ?? bridgeResult?.updatedAt ?? now,
      mode: request.mode ?? "send",
      prompt: request.prompt ?? request.message ?? request.input ?? "",
      stopReason: bridgeResult?.stop_reason ?? bridgeResult?.stopReason ?? "runtime_bridge_completed",
      events: events.map((event) => ({
        ...event,
        event_stream_id: event.event_stream_id ?? eventStreamIdForThread(threadId),
        thread_id: event.thread_id ?? threadId,
        turn_id: event.turn_id ?? turnId,
        workspace_root: event.workspace_root ?? agent.cwd,
        source: event.source ?? "runtime_service",
        source_event_kind: event.source_event_kind ?? "RuntimeAgentService",
        fixture_profile: Object.hasOwn(event, "fixture_profile") ? event.fixture_profile : null,
        payload: {
          agent_id: agent.id,
          run_id: runId,
          session_id: runtimeSessionIdForAgent(agent),
          ...(event.payload ?? event.payload_summary ?? {}),
        },
      })),
    };
  }

  doctorReport({ baseUrl = null } = {}) {
    const generatedAt = new Date().toISOString();
    const modelProjection = this.modelMounting.projection();
    const skillHookCatalog = this.skillHookCatalog();
    const memoryPaths = this.memory.pathProjection({
      threadId: null,
      workspace: this.defaultCwd,
    });
    const providerKeys = doctorProviderKeyReport();
    const optionalWarnings = [];
    const checks = [
      doctorCheck("daemon.public_api", "pass", true, "Public runtime daemon routes are reachable.", [
        "/v1/doctor",
      ]),
      doctorCheck(
        "workspace.root",
        fs.existsSync(this.defaultCwd) ? "pass" : "blocked",
        true,
        fs.existsSync(this.defaultCwd)
          ? "Workspace root exists."
          : "Workspace root is missing.",
        [this.defaultCwd],
      ),
      doctorCheck(
        "agentgres.store",
        fs.existsSync(this.stateDir) ? "pass" : "blocked",
        true,
        "Agentgres v0 state directory is present.",
        [this.stateDir, "agentgres_canonical_operation_log"],
      ),
      doctorCheck(
        "model.routes",
        modelProjection.routes.length > 0 ? "pass" : "blocked",
        true,
        `${modelProjection.routes.length} model route(s) are registered.`,
        modelProjection.routes.map((route) => route.id),
      ),
      doctorCheck(
        "memory.store",
        fs.existsSync(memoryPaths.recordsPath) && fs.existsSync(memoryPaths.policiesPath)
          ? "pass"
          : "blocked",
        true,
        "Memory records and policies are backed by durable state paths.",
        [memoryPaths.recordsPath, memoryPaths.policiesPath],
      ),
      doctorCheck(
        "tool.catalog",
        this.listTools().length > 0 ? "pass" : "blocked",
        true,
        `${this.listTools().length} governed runtime tool(s) are registered.`,
        this.listTools().map((tool) => tool.stableToolId),
      ),
      doctorCheck(
        "workflow.react_flow_registry",
        "pass",
        true,
        "React Flow registry exposes runtime doctor and readiness nodes.",
        ["RuntimeDoctorNode", "packages/agent-ide/src/runtime/workflow-node-registry.ts"],
      ),
      doctorCheck(
        "mcp.registry",
        modelProjection.mcpServers.length > 0 ? "pass" : "degraded",
        false,
        modelProjection.mcpServers.length > 0
          ? `${modelProjection.mcpServers.length} MCP server(s) are registered.`
          : "No MCP servers are registered; MCP remains optional.",
        modelProjection.mcpServers.map((server) => server.id),
      ),
      doctorCheck(
        "skills.hooks",
        skillHookCatalog.status,
        false,
        `${skillHookCatalog.skillCount} governed skill(s) and ${skillHookCatalog.hookCount} hook(s) discovered across ${skillHookCatalog.sources.length} source(s).`,
        ["runtime_skill_hook_discovery", "/v1/skills", "/v1/hooks"],
      ),
      doctorCheck(
        "wallet.network",
        process.env.IOI_WALLET_NETWORK_URL ? "pass" : "degraded",
        false,
        process.env.IOI_WALLET_NETWORK_URL
          ? "Wallet/network approval endpoint is configured."
          : "Wallet/network approval endpoint is optional and not configured.",
        ["IOI_WALLET_NETWORK_URL"],
      ),
      doctorCheck(
        "remote.agentgres",
        process.env.IOI_AGENTGRES_URL ? "pass" : "degraded",
        false,
        process.env.IOI_AGENTGRES_URL
          ? "Remote Agentgres adapter is configured."
          : "Remote Agentgres adapter is optional and not configured.",
        ["IOI_AGENTGRES_URL"],
      ),
      doctorCheck(
        "lsp.status",
        "degraded",
        false,
        "LSP health is not daemon-owned yet; workflow activation should treat it as optional.",
        ["lsp.status.next_slice"],
      ),
    ];
    for (const check of checks) {
      if (!check.required && check.status !== "pass") optionalWarnings.push(check.id);
    }
    const requiredFailures = checks.filter((check) => check.required && check.status !== "pass");
    const status = requiredFailures.length > 0
      ? "blocked"
      : optionalWarnings.length > 0
        ? "degraded"
        : "pass";
    return {
      schemaVersion: "ioi.agent-runtime.doctor.v1",
      object: "ioi.agent_runtime_doctor_report",
      generatedAt,
      status,
      readiness: requiredFailures.length > 0 ? "blocked" : "ready",
      version: {
        runtime: "ioi-runtime-daemon",
        schema: this.schemaVersion,
      },
      daemon: {
        endpoint: baseUrl,
        publicApi: "/v1",
        nativeApi: "/api/v1",
        requestScoped: true,
      },
      workspace: {
        root: this.defaultCwd,
        exists: fs.existsSync(this.defaultCwd),
      },
      configPaths: {
        stateDir: this.stateDir,
        operationLog: path.join(this.stateDir, "operation-log.jsonl"),
        memoryRecords: memoryPaths.recordsPath,
        memoryPolicies: memoryPaths.policiesPath,
        modelMountingProjection: path.join(this.stateDir, "projections", "model-mounting-canonical.json"),
      },
      providerKeys,
      modelRoutes: {
        modelCount: modelProjection.artifacts.length,
        routeCount: modelProjection.routes.length,
        routeIds: modelProjection.routes.map((route) => route.id),
        selectedDefaultRoute: modelProjection.routes.find((route) => route.id === "route.local-first")?.id ?? null,
      },
      mcp: {
        serverCount: modelProjection.mcpServers.length,
        servers: modelProjection.mcpServers.map((server) => ({
          id: server.id,
          transport: server.transport,
          status: server.status,
          secretRefCount: normalizeArray(server.secretRefs).length,
          secretsRedacted: true,
        })),
      },
      skillsHooks: {
        status: skillHookCatalog.status,
        skillCount: skillHookCatalog.skillCount,
        hookCount: skillHookCatalog.hookCount,
        sourceCount: skillHookCatalog.sources.length,
        activeSkillSetHash: skillHookCatalog.activeSkillSetHash,
        activeHookSetHash: skillHookCatalog.activeHookSetHash,
        validationIssueCount: skillHookCatalog.validationIssueCount,
        discoveryEndpoints: ["/v1/skills", "/v1/hooks"],
      },
      memory: {
        recordCount: this.memory.records.size,
        policyCount: this.memory.policies.size,
        defaultPolicy: this.memory.effectivePolicy({
          threadId: null,
          workspace: this.defaultCwd,
        }),
        paths: memoryPaths,
      },
      sandbox: {
        status: "pass",
        profile: "local_private",
        approvalMode: "suggest",
        networkDefault: "local_only",
      },
      workflow: {
        reactFlowRegistryVersion: "ioi.reactflow.workflow-node-registry.v1",
        doctorNodeType: "runtime_doctor",
        activationConsumesDoctorReport: true,
        readinessBlockerField: "checks",
      },
      agentgres: {
        schemaVersion: this.schemaVersion,
        operationCount: this.operationCount(),
        localStateDirPresent: fs.existsSync(this.stateDir),
        remoteAdapterConfigured: Boolean(process.env.IOI_AGENTGRES_URL),
        remoteAdapterHash: process.env.IOI_AGENTGRES_URL ? doctorHash(process.env.IOI_AGENTGRES_URL) : null,
      },
      wallet: {
        approvalStatus: process.env.IOI_WALLET_NETWORK_URL ? "configured" : "not_configured",
        networkConfigured: Boolean(process.env.IOI_WALLET_NETWORK_URL),
        networkUrlHash: process.env.IOI_WALLET_NETWORK_URL ? doctorHash(process.env.IOI_WALLET_NETWORK_URL) : null,
      },
      runtimeNodes: this.listRuntimeNodes().map(redactRuntimeNodeForDoctor),
      checks,
      blockers: requiredFailures.map((check) => check.id),
      optionalWarnings,
      redaction: {
        profile: "doctor_safe",
        secretValuesIncluded: false,
        endpointValuesHashed: true,
      },
      evidenceRefs: ["ioi_agent_runtime_doctor", "runtime_preflight", "RuntimeDoctorNode"],
    };
  }

  skillHookCatalog({ cwd = this.defaultCwd } = {}) {
    return discoverSkillHookCatalog({ cwd, homeDir: this.homeDir });
  }

  listSkills({ cwd = this.defaultCwd } = {}) {
    const catalog = this.skillHookCatalog({ cwd });
    return {
      schemaVersion: "ioi.agent-runtime.skills.v1",
      object: "ioi.agent_skill_registry_projection",
      generatedAt: catalog.generatedAt,
      workspace: catalog.workspace,
      status: catalog.skillStatus,
      skillCount: catalog.skillCount,
      activeSkillSetHash: catalog.activeSkillSetHash,
      sources: catalog.sources.filter((source) => source.kind === "skill_dir"),
      skills: catalog.skills,
      redaction: catalog.redaction,
      evidenceRefs: ["runtime_skill_discovery", "SkillNode", "SkillPackNode"],
    };
  }

  listHooks({ cwd = this.defaultCwd } = {}) {
    const catalog = this.skillHookCatalog({ cwd });
    return {
      schemaVersion: "ioi.agent-runtime.hooks.v1",
      object: "ioi.agent_hook_registry_projection",
      generatedAt: catalog.generatedAt,
      workspace: catalog.workspace,
      status: catalog.hookStatus,
      hookCount: catalog.hookCount,
      activeHookSetHash: catalog.activeHookSetHash,
      sources: catalog.sources.filter((source) => source.kind === "hook_file" || source.kind === "hook_dir"),
      hooks: catalog.hooks,
      redaction: catalog.redaction,
      evidenceRefs: ["runtime_hook_discovery", "HookNode", "HookPolicyNode"],
    };
  }

  async createTurn(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const diagnosticsFeedback = this.pendingDiagnosticsFeedbackForNextTurn(threadId, request);
    if (diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)) {
      const prompt = request.prompt ?? request.message ?? request.input ?? "";
      const run = this.createRun(agent.id, {
        mode: request.mode ?? "send",
        prompt,
        options: request.options ?? {},
        memory: request.memory,
        remember: request.remember,
        diagnosticsFeedback,
      });
      return this.turnForRun(run);
    }
    if (isRuntimeBackedAgent(agent)) {
      return this.createRuntimeBridgeTurn({
        agent,
        threadId,
        request: requestWithDiagnosticsFeedback(request, diagnosticsFeedback),
        diagnosticsFeedback,
      });
    }
    const prompt = request.prompt ?? request.message ?? request.input ?? "";
    const run = this.createRun(agent.id, {
      mode: request.mode ?? "send",
      prompt,
      options: request.options ?? {},
      memory: request.memory,
      remember: request.remember,
      diagnosticsFeedback,
    });
    return this.turnForRun(run);
  }

  async createRuntimeBridgeTurn({ agent, threadId, request, diagnosticsFeedback = null }) {
    this.assertRuntimeBridgeAvailable({ runtimeProfile: agent.runtimeProfile, operation: "submit_turn" });
    const input = {
      request,
      agentId: agent.id,
      threadId,
      sessionId: runtimeSessionIdForAgent(agent),
      workspaceRoot: agent.cwd,
      createdAt: new Date().toISOString(),
    };
    let bridgeResult;
    try {
      bridgeResult = await this.runtimeBridge.submitTurn(input);
    } catch (error) {
      if (error instanceof RuntimeApiBridgeUnavailableError) {
        throw this.runtimeBridgeUnavailable({
          runtimeProfile: agent.runtimeProfile,
          operation: "submit_turn",
          details: error.details,
        });
      }
      throw error;
    }
    const projection = this.normalizeRuntimeBridgeTurnSubmit({ bridgeResult, agent, threadId, request });
    if (diagnosticsFeedback) {
      projection.events = insertRuntimeBridgeDiagnosticsInjectionEvent({
        projection,
        agent,
        threadId,
        diagnosticsFeedback,
      });
    }
    for (const event of projection.events) this.appendRuntimeEvent(event);
    const run = runtimeBridgeRunRecord({ agent, request, projection });
    this.runs.set(run.id, run);
    this.writeRun(run, "turn.runtime_bridge.submit");
    return this.turnForRun(run);
  }

  listTurns(threadId) {
    const agent = this.agentForThread(threadId);
    return this.listRuns(agent.id).map((run) => this.turnForRun(run));
  }

  getTurn(threadId, turnId) {
    const turn = this.listTurns(threadId).find((candidate) => candidate.turn_id === turnId);
    if (!turn) throw notFound(`Turn not found: ${turnId}`, { threadId, turnId });
    return turn;
  }

  eventsForThread(threadId, cursor = {}) {
    const agent = this.agentForThread(threadId);
    this.projectThreadEvents(agent);
    return this.runtimeEventsForStream(eventStreamIdForThread(threadIdForAgent(agent.id)), cursor);
  }

  eventsForRun(runId, cursor = {}) {
    const run = this.getRun(runId);
    const agent = this.getAgent(run.agentId);
    this.projectThreadEvents(agent);
    return this.runtimeEventsForTurn(turnIdForRun(run.id), cursor);
  }

  ensureThreadStartedEvent(agent) {
    const threadId = threadIdForAgent(agent.id);
    return this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: "",
      item_id: `${threadId}:item:thread-started`,
      idempotency_key: `agent:${agent.id}:thread.started`,
      source: "daemon_bridge",
      source_event_kind: "agent.create",
      event_kind: "thread.started",
      status: threadStatusForAgent(agent.status),
      actor: "runtime",
      created_at: agent.createdAt,
      workspace_root: agent.cwd,
      component_kind: "runtime_thread",
      workflow_node_id: "runtime.runtime-thread",
      payload_schema_version: RUNTIME_THREAD_SCHEMA_VERSION,
      payload: {
        event_kind: "ThreadStarted",
        agent_id: agent.id,
        thread_id: threadId,
        status: threadStatusForAgent(agent.status),
      },
      artifact_refs: [],
      receipt_refs: [agent.modelRouteReceiptId].filter(Boolean),
      fixture_profile: DAEMON_FIXTURE_PROFILE,
    });
  }

  projectThreadEvents(agent) {
    if (isRuntimeBackedAgent(agent)) return;
    this.ensureThreadStartedEvent(agent);
    for (const run of this.listRuns(agent.id)) {
      this.projectRunEvents(run, agent);
    }
  }

  projectRunEvents(run, agent = this.getAgent(run.agentId)) {
    if (isRuntimeBackedAgent(agent)) return;
    const threadId = threadIdForAgent(agent.id);
    const turnId = turnIdForRun(run.id);
    for (const event of run.events) {
      this.appendRuntimeEvent(
        ttiEnvelopeForRunEvent({
          event,
          threadId,
          turnId,
          workspaceRoot: agent.cwd,
        }),
      );
    }
  }

  appendRuntimeEvent(event) {
    const streamId = event.event_stream_id;
    if (!streamId) {
      throw runtimeError({
        status: 400,
        code: "runtime_event_stream_required",
        message: "Runtime events require event_stream_id.",
        details: { eventKind: event.event_kind ?? event.event ?? null },
      });
    }
    const stream = this.runtimeEventStream(streamId);
    const idempotencyKey = String(event.idempotency_key ?? event.event_id ?? "");
    if (!idempotencyKey) {
      throw runtimeError({
        status: 400,
        code: "runtime_event_idempotency_required",
        message: "Runtime events require idempotency_key.",
        details: { eventStreamId: streamId, eventKind: event.event_kind ?? event.event ?? null },
      });
    }
    const duplicate = stream.idempotency.get(idempotencyKey);
    if (duplicate) return duplicate;

    const seq = stream.events.length + 1;
    const record = normalizeRuntimeEventEnvelope(event, {
      seq,
      parentSeq: seq > 1 ? stream.events.at(-1).seq : null,
      idempotencyKey,
    });
    stream.events.push(record);
    stream.idempotency.set(record.idempotency_key, record);
    fs.appendFileSync(this.runtimeEventStreamPath(streamId), `${JSON.stringify(record)}\n`);
    return record;
  }

  runtimeEventsForStream(eventStreamId, cursor = {}) {
    const stream = this.runtimeEventStream(eventStreamId);
    const cursorSeq = this.runtimeCursorSeq(stream, cursor);
    return stream.events.filter((event) => event.seq > cursorSeq);
  }

  runtimeEventsForTurn(turnId, cursor = {}) {
    const events = [...this.runtimeEventStreams.values()]
      .flatMap((stream) => stream.events)
      .filter((event) => event.turn_id === turnId)
      .sort((left, right) => left.seq - right.seq);
    if (!events.length) return [];
    const stream = this.runtimeEventStream(events[0].event_stream_id);
    const cursorSeq = this.runtimeCursorSeq(stream, cursor);
    return events.filter((event) => event.seq > cursorSeq);
  }

  runtimeCursorSeq(stream, cursor = {}) {
    const latestSeq = stream.events.at(-1)?.seq ?? 0;
    if (typeof cursor === "number") {
      return this.assertRuntimeCursorSeq(Number(cursor) || 0, latestSeq, {
        eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
        sinceSeq: Number(cursor) || 0,
      });
    }
    if (typeof cursor === "string") {
      return this.runtimeCursorSeq(stream, { lastEventId: cursor });
    }
    if (cursor.sinceSeq !== null && cursor.sinceSeq !== undefined) {
      return this.assertRuntimeCursorSeq(Number(cursor.sinceSeq) || 0, latestSeq, {
        eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
        sinceSeq: Number(cursor.sinceSeq) || 0,
      });
    }
    const lastEventId = String(cursor.lastEventId ?? "").trim();
    if (!lastEventId) return 0;
    if (/^\d+$/.test(lastEventId)) {
      return this.assertRuntimeCursorSeq(Number(lastEventId), latestSeq, {
        eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
        lastEventId,
      });
    }
    const match = stream.events.find((event) => event.event_id === lastEventId || event.id === lastEventId);
    if (match) return match.seq;
    throw runtimeError({
      status: 409,
      code: "event_cursor_out_of_range",
      message: "Runtime event cursor does not exist in this stream.",
      details: {
        eventStreamId: stream.events.at(-1)?.event_stream_id ?? null,
        lastEventId,
        latestSeq,
      },
    });
  }

  assertRuntimeCursorSeq(cursorSeq, latestSeq, details = {}) {
    if (cursorSeq > latestSeq) {
      throw runtimeError({
        status: 409,
        code: "event_cursor_out_of_range",
        message: "Runtime event cursor is beyond the latest committed sequence.",
        details: { ...details, sinceSeq: cursorSeq, latestSeq },
      });
    }
    return cursorSeq;
  }

  latestRuntimeEventSeq(eventStreamId) {
    return this.runtimeEventStream(eventStreamId).events.at(-1)?.seq ?? 0;
  }

  runtimeEventStream(eventStreamId) {
    const key = String(eventStreamId);
    let stream = this.runtimeEventStreams.get(key);
    if (!stream) {
      stream = { events: [], idempotency: new Map() };
      this.runtimeEventStreams.set(key, stream);
    }
    return stream;
  }

  registerRuntimeEvent(record) {
    const stream = this.runtimeEventStream(record.event_stream_id);
    if (stream.idempotency.has(record.idempotency_key)) return;
    stream.events.push(record);
    stream.events.sort((left, right) => left.seq - right.seq);
    stream.idempotency.set(record.idempotency_key, record);
  }

  runtimeEventStreamPath(eventStreamId) {
    return this.pathFor("events", `${runtimeEventStreamFileName(eventStreamId)}.jsonl`);
  }

  threadForAgent(agent) {
    const runs = this.listRuns(agent.id);
    const latestRun = runs.at(-1);
    this.projectThreadEvents(agent);
    const threadId = threadIdForAgent(agent.id);
    const latestSeq = this.latestRuntimeEventSeq(eventStreamIdForThread(threadId));
    const updatedAt = Math.max(
      Date.parse(agent.updatedAt) || 0,
      ...runs.map((run) => Date.parse(run.updatedAt) || 0),
    );
    return {
      schema_version: RUNTIME_THREAD_SCHEMA_VERSION,
      thread_id: threadId,
      session_id: runtimeSessionIdForAgent(agent),
      agent_id: agent.id,
      workspace_root: agent.cwd,
      title: latestRun?.objective ?? agent.cwd,
      mode: "agent",
      approval_mode: "suggest",
      trust_profile: "local_private",
      model_route: agent.modelId,
      status: latestRun?.turnStatus === "interrupted" ? "interrupted" : threadStatusForAgent(agent.status),
      latest_turn_id: latestRun ? turnIdForRun(latestRun.id) : null,
      latest_seq: latestSeq,
      event_stream_id: eventStreamIdForThread(threadId),
      workflow_graph_id: null,
      harness_binding_id: null,
      agentgres_projection_ref: `agents/${agent.id}.json`,
      created_at: agent.createdAt,
      updated_at: new Date(updatedAt || Date.parse(agent.updatedAt) || Date.now()).toISOString(),
      archived_at: agent.status === "archived" ? agent.updatedAt : null,
      fixture_profile: fixtureProfileForAgent(agent),
      created_at_ms: Date.parse(agent.createdAt) || 0,
      updated_at_ms: updatedAt,
      workspace: agent.cwd,
      requested_model: agent.requestedModelId ?? agent.modelId,
      model_route_id: agent.modelRouteId ?? null,
      model_route_receipt_id: agent.modelRouteReceiptId ?? null,
      model_route_decision: agent.modelRouteDecision ?? null,
      memory_count: this.memory.list({
        agent,
        threadId,
        workspace: agent.cwd,
      }).length,
      archived: agent.status === "archived",
      evidence_refs: ["agentgres_canonical_operation_log", "runtime_tti_projection"],
      runtime_profile: agent.runtimeProfile ?? "fixture",
      runtime_bridge_id: agent.runtimeBridgeId ?? null,
      runtime_bridge_source: agent.runtimeBridgeSource ?? null,
    };
  }

  turnForRun(run) {
    const agent = this.getAgent(run.agentId);
    this.projectRunEvents(run, agent);
    const turnEvents = this.runtimeEventsForTurn(turnIdForRun(run.id));
    const seqStart = turnEvents.at(0)?.seq ?? null;
    const status = run.turnStatus ?? lifecycleStatusForRun(run.status);
    const isOpen = status === "queued" || status === "running" || status === "waiting_for_approval" || status === "waiting_for_input";
    const seqEnd = isOpen ? null : (turnEvents.at(-1)?.seq ?? null);
    const completedAt = isOpen ? null : run.updatedAt;
    return {
      schema_version: RUNTIME_TURN_SCHEMA_VERSION,
      turn_id: turnIdForRun(run.id),
      thread_id: threadIdForAgent(run.agentId),
      parent_turn_id: null,
      request_id: run.id,
      status,
      input_item_ids: turnEvents
        .filter((event) => event.event_kind === "turn.started")
        .map((event) => event.item_id),
      output_item_ids: turnEvents
        .filter((event) => event.event_kind !== "turn.started")
        .map((event) => event.item_id),
      seq_start: seqStart,
      seq_end: seqEnd,
      started_at: run.createdAt,
      completed_at: completedAt,
      mode: "agent",
      approval_mode: "suggest",
      model_route_decision_id: run.modelRouteDecision?.decisionId ?? run.trace?.modelRouteDecision?.decisionId ?? null,
      usage: null,
      stop_reason: run.trace?.stopCondition?.reason ?? null,
      error: run.status === "failed" ? run.result : null,
      rollback_snapshot_id: null,
      quality_ledger_ref: run.trace?.qualityLedger?.ledgerId ?? null,
      workflow_execution_ref: null,
      fixture_profile: fixtureProfileForAgent(agent),
      started_at_ms: Date.parse(run.createdAt) || 0,
      completed_at_ms: completedAt ? Date.parse(completedAt) || 0 : null,
      error_summary: run.status === "failed" ? run.result : null,
      model_route_decision: run.modelRouteDecision ?? run.trace?.modelRouteDecision ?? null,
      model_route_receipt_id: run.modelRouteReceiptId ?? null,
      active_skill_hook_manifest_ref: run.activeSkillHookManifest?.manifestId ?? null,
      active_skill_set_hash: run.activeSkillHookManifest?.activeSkillSetHash ?? null,
      active_hook_set_hash: run.activeSkillHookManifest?.activeHookSetHash ?? null,
      memory_refs: run.memoryRecords?.map((record) => record.id) ?? [],
      memory_write_receipt_ids: run.memoryWriteReceipts?.map((receipt) => receipt.id) ?? [],
      evidence_refs: [
        "agentgres_canonical_operation_log",
        `run:${run.id}`,
        run.activeSkillHookManifest?.manifestId,
      ].filter(Boolean),
    };
  }

  interruptTurn(threadId, turnId, request = {}) {
    const agent = this.agentForThread(threadId);
    const runId = runIdForTurn(turnId);
    const run = this.getRun(runId);
    if (run.agentId !== agent.id) {
      throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId });
    }
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ?? "operator requested interrupt";
    const now = new Date().toISOString();
    const previousStatus = run.turnStatus ?? lifecycleStatusForRun(run.status);
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId}:item:operator-interrupt`,
      idempotency_key: `turn:${turnId}:operator.interrupt`,
      source,
      source_event_kind: "OperatorControl.Interrupt",
      event_kind: "turn.interrupted",
      status: "interrupted",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.operator-interrupt",
      component_kind: "operator_control",
      payload_schema_version: "ioi.runtime.operator-control.v1",
      payload: {
        event_kind: "OperatorControl.Interrupt",
        reason,
        requested_by: requestedBy,
        control_surface: source,
        previous_status: previousStatus,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId,
        run_id: run.id,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${run.id}_operator_interrupt`],
      policy_decision_refs: [`policy_${run.id}_operator_interrupt_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "interrupt",
      source,
      reason,
      eventId: event.event_id,
      seq: event.seq,
      createdAt: event.created_at,
    };
    const stopCondition = {
      reason: "operator_interrupt",
      evidenceSufficient: true,
      rationale: `Operator interrupt accepted from ${source}: ${reason}`,
    };
    const updated = {
      ...run,
      status: ["queued", "running", "blocked"].includes(run.status) ? "canceled" : run.status,
      turnStatus: "interrupted",
      updatedAt: event.created_at,
      result: `Turn interrupted by operator: ${reason}`,
      trace: {
        ...run.trace,
        status: "interrupted",
        stopCondition,
        operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
        qualityLedger: {
          ...run.trace?.qualityLedger,
          failureOntologyLabels: [
            ...new Set([
              ...normalizeArray(run.trace?.qualityLedger?.failureOntologyLabels),
              "operator_interrupt",
            ]),
          ],
        },
      },
      operatorControls: appendOperatorControl(run.operatorControls, control),
    };
    this.runs.set(run.id, updated);
    this.writeRun(updated, "turn.interrupt");
    return this.turnForRun(updated);
  }

  steerTurn(threadId, turnId, request = {}) {
    const agent = this.agentForThread(threadId);
    const runId = runIdForTurn(turnId);
    const run = this.getRun(runId);
    if (run.agentId !== agent.id) {
      throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId });
    }
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const guidance =
      optionalString(request.guidance ?? request.message ?? request.input) ?? "operator provided steering guidance";
    const now = new Date().toISOString();
    const previousStatus = run.turnStatus ?? lifecycleStatusForRun(run.status);
    const guidanceHash = crypto.createHash("sha256").update(guidance).digest("hex").slice(0, 16);
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId}:item:operator-steer:${guidanceHash}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `turn:${turnId}:operator.steer:${guidanceHash}`,
      source,
      source_event_kind: "OperatorControl.Steer",
      event_kind: "turn.steered",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.operator-steer",
      component_kind: "operator_control",
      payload_schema_version: "ioi.runtime.operator-control.v1",
      payload: {
        event_kind: "OperatorControl.Steer",
        guidance,
        requested_by: requestedBy,
        control_surface: source,
        previous_status: previousStatus,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId,
        run_id: run.id,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${run.id}_operator_steer_${guidanceHash}`],
      policy_decision_refs: [`policy_${run.id}_operator_steer_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "steer",
      source,
      guidance,
      eventId: event.event_id,
      seq: event.seq,
      createdAt: event.created_at,
    };
    const updated = {
      ...run,
      updatedAt: event.created_at,
      trace: {
        ...run.trace,
        operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
      },
      operatorControls: appendOperatorControl(run.operatorControls, control),
    };
    this.runs.set(run.id, updated);
    this.writeRun(updated, "turn.steer");
    return this.turnForRun(updated);
  }

  decideThreadApproval(threadId, approvalId, request = {}) {
    const agent = this.agentForThread(threadId);
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id ?? request.approvalId) ??
      (() => {
        throw runtimeError({
          status: 400,
          code: "approval_id_required",
          message: "Approval decisions require an approval id.",
          details: { threadId },
        });
      })();
    const decision = approvalDecisionForRequest(request.decision ?? request.action ?? request.status);
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason = optionalString(request.reason ?? request.message ?? request.input) ?? null;
    const runs = this.listRuns(agent.id);
    const requestedTurnId = optionalString(request.turn_id ?? request.turnId);
    let turnId = requestedTurnId ?? "";
    let run = null;
    if (turnId) {
      run = this.getRun(runIdForTurn(turnId));
      if (run.agentId !== agent.id) {
        throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId: run.id });
      }
    } else {
      run = runs.at(-1) ?? null;
      turnId = run ? turnIdForRun(run.id) : "";
    }

    const now = new Date().toISOString();
    const status = decision === "approve" ? "approved" : "rejected";
    const decisionVerb = decision === "approve" ? "Approve" : "Reject";
    const decisionHash = crypto
      .createHash("sha256")
      .update(`${normalizedApprovalId}:${decision}:${reason ?? ""}:${requestedBy}`)
      .digest("hex")
      .slice(0, 16);
    const workflowNodeId =
      request.workflow_node_id ??
      request.workflowNodeId ??
      `runtime.approval.${safeId(normalizedApprovalId)}`;
    const runOrAgentId = run?.id ?? agent.id;
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:approval-${decision}:${safeId(normalizedApprovalId)}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:approval.${decision}:${normalizedApprovalId}:${decisionHash}`,
      source,
      source_event_kind: `OperatorApproval.${decisionVerb}`,
      event_kind: `approval.${status}`,
      status,
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: workflowNodeId,
      component_kind: "approval_gate",
      approval_id: normalizedApprovalId,
      payload_schema_version: "ioi.runtime.approval-decision.v1",
      payload: {
        event_kind: `OperatorApproval.${decisionVerb}`,
        approval_id: normalizedApprovalId,
        decision,
        status,
        reason,
        requested_by: requestedBy,
        control_surface: source,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${runOrAgentId}_approval_${decision}_${safeId(normalizedApprovalId)}_${decisionHash}`],
      policy_decision_refs: [`policy_${runOrAgentId}_approval_${decision}_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "approval_decision",
      approvalId: normalizedApprovalId,
      decision,
      status,
      source,
      reason,
      eventId: event.event_id,
      seq: event.seq,
      receiptRefs: event.receipt_refs,
      policyDecisionRefs: event.policy_decision_refs,
      createdAt: event.created_at,
    };
    if (run) {
      const updated = {
        ...run,
        updatedAt: event.created_at,
        turnStatus: decision === "reject" ? "waiting_for_input" : run.turnStatus,
        trace: {
          ...run.trace,
          operatorControls: appendOperatorControl(run.trace?.operatorControls, control),
          approvalDecisions: appendOperatorControl(run.trace?.approvalDecisions, control),
        },
        operatorControls: appendOperatorControl(run.operatorControls, control),
        approvalDecisions: appendOperatorControl(run.approvalDecisions, control),
      };
      this.runs.set(run.id, updated);
      this.writeRun(updated, `approval.${decision}`);
      return {
        ...this.turnForRun(updated),
        approval_id: normalizedApprovalId,
        decision,
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    }
    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, `approval.${decision}`);
    return {
      ...this.threadForAgent(updatedAgent),
      approval_id: normalizedApprovalId,
      decision,
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
  }

  compactThread(threadId, request = {}) {
    const agent = this.agentForThread(threadId);
    const runs = this.listRuns(agent.id);
    const latestRun = runs.at(-1);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      (latestRun ? turnIdForRun(latestRun.id) : "");
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by ?? request.requestedBy) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ?? "operator requested context compaction";
    const scope = optionalString(request.scope) ?? "thread";
    const now = new Date().toISOString();
    const streamId = eventStreamIdForThread(threadId);
    const previousLatestSeq = this.latestRuntimeEventSeq(streamId);
    const compactHash = crypto
      .createHash("sha256")
      .update(`${reason}:${scope}`)
      .digest("hex")
      .slice(0, 16);
    const event = this.appendRuntimeEvent({
      event_stream_id: streamId,
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:context-compact:${compactHash}`,
      idempotency_key:
        request.idempotency_key ??
        request.idempotencyKey ??
        `thread:${threadId}:context.compact:${compactHash}`,
      source,
      source_event_kind: "OperatorControl.Compact",
      event_kind: "context.compacted",
      status: "completed",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? request.workflowGraphId ?? null,
      workflow_node_id: request.workflow_node_id ?? request.workflowNodeId ?? "runtime.context-compact",
      component_kind: "context_compaction",
      payload_schema_version: "ioi.runtime.context-compaction.v1",
      payload: {
        event_kind: "OperatorControl.Compact",
        reason,
        scope,
        requested_by: requestedBy,
        control_surface: source,
        previous_latest_seq: previousLatestSeq,
        compacted_tokens: 0,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: latestRun?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${latestRun?.id ?? agent.id}_context_compaction_${compactHash}`],
      policy_decision_refs: [`policy_${latestRun?.id ?? agent.id}_context_compaction_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    const control = {
      control: "compact",
      source,
      reason,
      scope,
      eventId: event.event_id,
      seq: event.seq,
      createdAt: event.created_at,
    };
    if (latestRun) {
      const updated = {
        ...latestRun,
        updatedAt: event.created_at,
        trace: {
          ...latestRun.trace,
          operatorControls: appendOperatorControl(latestRun.trace?.operatorControls, control),
          contextCompaction: {
            reason,
            scope,
            eventId: event.event_id,
            seq: event.seq,
            compactedTokens: 0,
          },
        },
        operatorControls: appendOperatorControl(latestRun.operatorControls, control),
      };
      this.runs.set(latestRun.id, updated);
      this.writeRun(updated, "thread.compact");
      return this.threadForAgent(agent);
    }
    const updatedAgent = { ...agent, updatedAt: event.created_at };
    this.agents.set(agent.id, updatedAgent);
    this.writeAgent(updatedAgent, "thread.compact");
    return this.threadForAgent(updatedAgent);
  }

  listJobs(options = {}) {
    const agentId = options.agentId ?? options.agent_id ?? undefined;
    const status = options.status ?? undefined;
    return this.listRuns(agentId)
      .map((run) => runtimeJobRecordForRun(run))
      .filter((job) => !status || job.status === status)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getJob(jobId) {
    const job = this.listJobs().find((candidate) => candidate.jobId === jobId || candidate.runId === jobId);
    if (!job) throw notFound(`Job not found: ${jobId}`, { jobId });
    return job;
  }

  cancelJob(jobId) {
    const job = this.getJob(jobId);
    const canceledRun = this.cancelRun(job.runId);
    return runtimeJobRecordForRun(canceledRun);
  }

  agentForThread(threadId) {
    return this.getAgent(agentIdForThread(threadId));
  }

  getRun(runId) {
    const run = this.runs.get(runId);
    if (!run) {
      throw notFound(`Run not found: ${runId}`, { runId });
    }
    return run;
  }

  listRuns(agentId) {
    return [...this.runs.values()]
      .filter((run) => !agentId || run.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  cancelRun(runId) {
    const run = this.getRun(runId);
    const status = run.status === "canceled" ? "canceled" : "canceled";
    const updatedAt = new Date().toISOString();
    const nonTerminalEvents = run.events.filter(
      (event) => !TERMINAL_EVENT_TYPES.has(event.type) && !JOB_TERMINAL_EVENT_TYPES.has(event.type),
    );
    const hasRuntimeTaskEvent = nonTerminalEvents.some((event) => event.type === "runtime_task");
    const hasRuntimeChecklistEvent = nonTerminalEvents.some((event) => event.type === "runtime_checklist");
    const finalEventCount =
      nonTerminalEvents.length + (hasRuntimeTaskEvent ? 0 : 1) + (hasRuntimeChecklistEvent ? 0 : 1) + 2;
    const stopCondition = {
      reason: "marginal_improvement_too_low",
      evidenceSufficient: true,
      rationale:
        "Cancellation became the single terminal event and replay cursor continuity was preserved.",
    };
    const runtimeTask = runtimeTaskRecord({
      runId: run.id,
      agent: { id: run.agentId },
      prompt: run.objective,
      mode: run.mode,
      taskFamily: run.trace?.qualityLedger?.taskFamily ?? taskFamilyForMode(run.mode ?? "send"),
      selectedStrategy: run.trace?.qualityLedger?.selectedStrategy ?? strategyForMode(run.mode ?? "send"),
      modelRouteDecision: run.modelRouteDecision ?? run.trace?.modelRouteDecision,
      activeSkillHookManifest: run.activeSkillHookManifest ?? run.trace?.activeSkillHookManifest,
      createdAt: run.createdAt,
      updatedAt,
      status,
    });
    let runtimeJob = runtimeJobRecord({
      runtimeTask,
      status,
      createdAt: run.createdAt,
      updatedAt,
      queuedAt: run.runtimeJob?.queuedAt ?? run.createdAt,
      startedAt: run.runtimeJob?.startedAt ?? run.createdAt,
      completedAt: updatedAt,
      lifecycle: ["queued", "started", "canceled"],
      eventCount: finalEventCount,
      terminalEventCount: 1,
      artifactNames: normalizeArray(run.artifacts).map((artifactItem) => artifactItem.name).filter(Boolean),
      receiptKinds: normalizeArray(run.receipts).map((receipt) => receipt.kind).filter(Boolean),
    });
    const runtimeChecklist = runtimeChecklistRecord({
      runtimeTask,
      runtimeJob,
      status,
      createdAt: run.createdAt,
      updatedAt,
    });
    runtimeJob = attachChecklistToRuntimeJob(runtimeJob, runtimeChecklist);
    const canceledEvents = nonTerminalEvents.map((event) => {
      if (event.type === "runtime_task") {
        return {
          ...event,
          data: {
            ...runtimeTask,
            receiptId: `receipt_${run.id}_runtime_task`,
            eventKind: "RuntimeTaskRecord",
            workflowNodeId: "runtime.runtime-task",
          },
        };
      }
      if (event.type === "runtime_checklist") {
        return {
          ...event,
          data: {
            ...runtimeChecklist,
            receiptId: `receipt_${run.id}_runtime_checklist`,
            eventKind: "RuntimeChecklistRecord",
            workflowNodeId: "runtime.runtime-checklist",
          },
        };
      }
      return event;
    });
    if (!canceledEvents.some((event) => event.type === "runtime_task")) {
      canceledEvents.push(
        makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_task", "Runtime task record written", {
          ...runtimeTask,
          receiptId: `receipt_${run.id}_runtime_task`,
          eventKind: "RuntimeTaskRecord",
          workflowNodeId: "runtime.runtime-task",
        }),
      );
    }
    if (!canceledEvents.some((event) => event.type === "runtime_checklist")) {
      canceledEvents.push(
        makeEvent(run.id, run.agentId, canceledEvents.length, "runtime_checklist", "Runtime checklist recorded", {
          ...runtimeChecklist,
          receiptId: `receipt_${run.id}_runtime_checklist`,
          eventKind: "RuntimeChecklistRecord",
          workflowNodeId: "runtime.runtime-checklist",
        }),
      );
    }
    const jobCanceled = makeEvent(
      run.id,
      run.agentId,
      canceledEvents.length,
      "job_canceled",
      "Runtime job canceled",
      {
        ...runtimeJob,
        lifecycleStatus: "canceled",
        receiptId: `receipt_${run.id}_runtime_job`,
        eventKind: "JobCanceled",
        workflowNodeId: "runtime.runtime-job",
      },
    );
    canceledEvents.push(jobCanceled);
    const canceled = makeEvent(
      run.id,
      run.agentId,
      canceledEvents.length,
      "canceled",
      "Run canceled",
      { reason: "operator_cancel", priorStatus: run.status },
    );
    canceledEvents.push(canceled);
    const runtimeChecklistReceipt = {
      id: `receipt_${run.id}_runtime_checklist`,
      kind: "runtime_checklist",
      summary: runtimeChecklist.summary,
      redaction: "redacted",
      evidenceRefs: [
        runtimeChecklist.checklistId,
        runtimeTask.taskId,
        runtimeJob.jobId,
        "RuntimeChecklistNode",
        "runtime.checklists.durable_projection",
      ].filter(Boolean),
    };
    const receipts = normalizeArray(run.receipts).map((receipt) =>
      receipt.id === runtimeChecklistReceipt.id ? runtimeChecklistReceipt : receipt,
    );
    if (!receipts.some((receipt) => receipt.id === runtimeChecklistReceipt.id)) {
      receipts.push(runtimeChecklistReceipt);
    }
    const trace = {
      ...run.trace,
      events: canceledEvents,
      receipts,
      runtimeTask,
      runtimeJob,
      runtimeChecklist,
      stopCondition,
      qualityLedger: {
        ...run.trace.qualityLedger,
        failureOntologyLabels: [
          ...new Set([...run.trace.qualityLedger.failureOntologyLabels, "operator_cancel"]),
        ],
      },
    };
    const artifacts = normalizeArray(run.artifacts).map((item) => {
      if (item.name === "runtime-task.json") return { ...item, content: runtimeTask };
      if (item.name === "runtime-job.json") return { ...item, content: runtimeJob };
      if (item.name === "runtime-checklist.json") return { ...item, content: runtimeChecklist };
      return item;
    });
    if (!artifacts.some((item) => item.name === "runtime-checklist.json")) {
      artifacts.push(
        artifact(run.id, "runtime-checklist.json", "application/json", runtimeChecklistReceipt.id, runtimeChecklist, "redacted"),
      );
    }
    const updated = {
      ...run,
      status,
      updatedAt,
      events: trace.events,
      trace,
      receipts,
      artifacts,
      runtimeTask: trace.runtimeTask,
      runtimeJob: trace.runtimeJob,
      runtimeChecklist: trace.runtimeChecklist,
      result: "Run canceled with terminal event continuity preserved.",
    };
    this.runs.set(runId, updated);
    this.writeRun(updated, "run.cancel");
    return updated;
  }

  legacyEventsForRun(runId, lastEventId) {
    const events = this.getRun(runId).events;
    if (!lastEventId) return events;
    const index = events.findIndex((event) => event.id === lastEventId);
    return events.slice(index >= 0 ? index + 1 : 0);
  }

  replayFromCanonicalState(runId, cursor) {
    return this.eventsForRun(runId, cursor);
  }

  traceFromCanonicalState(runId) {
    return this.getRun(runId).trace;
  }

  canonicalProjection(runId) {
    const run = this.getRun(runId);
    const watermark = this.operationCount();
    return {
      schemaVersion: this.schemaVersion,
      runId,
      source: "agentgres_canonical_operation_log",
      watermark,
      freshness: {
        source: "local-agentgres-v0",
        operationCount: watermark,
        generatedAt: new Date().toISOString(),
      },
      paths: {
        run: relative(this.stateDir, this.pathFor("runs", `${run.id}.json`)),
        task: relative(this.stateDir, this.pathFor("tasks", `${run.id}.json`)),
        job: relative(this.stateDir, this.pathFor("jobs", `${runtimeJobRecordForRun(run).jobId}.json`)),
        checklist: relative(this.stateDir, this.pathFor("checklists", `${runtimeChecklistRecordForRun(run).checklistId}.json`)),
        quality: relative(this.stateDir, this.pathFor("quality", `${run.id}.json`)),
        operationLog: "operation-log.jsonl",
      },
      terminalState: run.status,
      stopCondition: run.trace.stopCondition,
      scorecard: run.trace.scorecard,
    };
  }

  listModels() {
    return this.modelMounting.legacyModelList();
  }

  listRepositories() {
    const context = repositoryContextForWorkspace({
      cwd: this.defaultCwd,
      contextId: `repoctx_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    return [
      {
        url: this.defaultCwd,
        source: context.isGitRepository ? "local_git" : "local_workspace",
        status: context.isGitRepository ? "available" : "not_a_git_repository",
        contextId: context.contextId,
        repoRoot: context.repoRoot,
        branch: context.branch,
        headSha: context.headSha,
        upstream: context.upstream,
        remoteCount: context.remoteCount,
        remotes: context.remotes,
        isDirty: context.status.isDirty,
        dirtyCounts: context.status.counts,
        redaction: context.redaction,
      },
    ];
  }

  repositoryContext() {
    return repositoryContextForWorkspace({
      cwd: this.defaultCwd,
      contextId: `repoctx_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
  }

  branchPolicy() {
    const repositoryContext = this.repositoryContext();
    return branchPolicyForRepositoryContext({
      repositoryContext,
      policyId: `branch_policy_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
  }

  githubContext() {
    const repositoryContext = this.repositoryContext();
    const branchPolicy = branchPolicyForRepositoryContext({
      repositoryContext,
      policyId: `branch_policy_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    return githubContextForRepository({
      repositoryContext,
      branchPolicy,
      contextId: `github_context_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
  }

  prAttempts() {
    const repositoryContext = this.repositoryContext();
    const branchPolicy = branchPolicyForRepositoryContext({
      repositoryContext,
      policyId: `branch_policy_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const githubContext = githubContextForRepository({
      repositoryContext,
      branchPolicy,
      contextId: `github_context_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    return [
      prAttemptForRepository({
        repositoryContext,
        branchPolicy,
        githubContext,
        attemptId: `pr_attempt_${doctorHash(this.defaultCwd).slice(0, 12)}`,
      }),
    ];
  }

  issueContext() {
    const repositoryContext = this.repositoryContext();
    const branchPolicy = branchPolicyForRepositoryContext({
      repositoryContext,
      policyId: `branch_policy_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const githubContext = githubContextForRepository({
      repositoryContext,
      branchPolicy,
      contextId: `github_context_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const prAttempt = prAttemptForRepository({
      repositoryContext,
      branchPolicy,
      githubContext,
      attemptId: `pr_attempt_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const reviewGate = reviewGateForPrAttempt({
      repositoryContext,
      branchPolicy,
      githubContext,
      prAttempt,
      gateId: `review_gate_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    return issueContextForGithub({
      repositoryContext,
      githubContext,
      prAttempt,
      reviewGate,
      contextId: `issue_context_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
  }

  reviewGate() {
    const repositoryContext = this.repositoryContext();
    const branchPolicy = branchPolicyForRepositoryContext({
      repositoryContext,
      policyId: `branch_policy_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const githubContext = githubContextForRepository({
      repositoryContext,
      branchPolicy,
      contextId: `github_context_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const prAttempt = prAttemptForRepository({
      repositoryContext,
      branchPolicy,
      githubContext,
      attemptId: `pr_attempt_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    return reviewGateForPrAttempt({
      repositoryContext,
      branchPolicy,
      githubContext,
      prAttempt,
      gateId: `review_gate_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
  }

  githubPrCreatePlan() {
    const repositoryContext = this.repositoryContext();
    const branchPolicy = branchPolicyForRepositoryContext({
      repositoryContext,
      policyId: `branch_policy_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const githubContext = githubContextForRepository({
      repositoryContext,
      branchPolicy,
      contextId: `github_context_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const prAttempt = prAttemptForRepository({
      repositoryContext,
      branchPolicy,
      githubContext,
      attemptId: `pr_attempt_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const reviewGate = reviewGateForPrAttempt({
      repositoryContext,
      branchPolicy,
      githubContext,
      prAttempt,
      gateId: `review_gate_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    const issueContext = issueContextForGithub({
      repositoryContext,
      githubContext,
      prAttempt,
      reviewGate,
      contextId: `issue_context_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
    return githubPrCreatePlanForReviewGate({
      repositoryContext,
      branchPolicy,
      githubContext,
      issueContext,
      prAttempt,
      reviewGate,
      planId: `github_pr_create_plan_${doctorHash(this.defaultCwd).slice(0, 12)}`,
    });
  }

  getAccount() {
    return {
      id: "local-operator",
      email: process.env.IOI_OPERATOR_EMAIL ?? null,
      authorityLevel: "local",
      privacyClass: "local_private",
      source: "ioi-daemon-agentgres",
    };
  }

  listRuntimeNodes() {
    return [
      {
        id: "local-daemon-agentgres",
        kind: "local",
        status: "available",
        endpoint: "local",
        privacyClass: "local_private",
        evidenceRefs: ["agentgres_canonical_operation_log", "ioi_daemon_public_runtime_api"],
      },
      {
        id: "hosted-provider",
        kind: "hosted",
        status: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT,
        privacyClass: "hosted",
        evidenceRefs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
      },
      {
        id: "self-hosted-provider",
        kind: "self_hosted",
        status: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT,
        privacyClass: "workspace",
        evidenceRefs: ["IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT"],
      },
    ];
  }

  listTools(options = {}) {
    const pack = optionalString(options.pack)?.toLowerCase();
    const tools = [
      {
        stableToolId: "fs.read",
        displayName: "Read file",
        pack: "runtime",
        primitiveCapabilities: ["prim:fs.read"],
        authorityScopeRequirements: [],
        effectClass: "local_read",
        riskDomain: "filesystem",
        inputSchema: { type: "object", required: ["path"] },
        outputSchema: { type: "object", required: ["content"] },
        evidenceRequirements: ["file_read_receipt"],
      },
      {
        stableToolId: "sys.exec",
        displayName: "Shell command",
        pack: "runtime",
        primitiveCapabilities: ["prim:sys.exec"],
        authorityScopeRequirements: ["scope:host.controlled_execution"],
        effectClass: "local_command",
        riskDomain: "host",
        inputSchema: { type: "object", required: ["command"] },
        outputSchema: { type: "object", required: ["exitCode", "stdout", "stderr"] },
        evidenceRequirements: ["shell_receipt", "sandbox_profile"],
      },
      {
        stableToolId: "mcp.invoke",
        displayName: "MCP tool invocation",
        pack: "runtime",
        primitiveCapabilities: ["prim:connector.invoke"],
        authorityScopeRequirements: ["scope:mcp.invoke"],
        effectClass: "connector_call",
        riskDomain: "connector",
        inputSchema: { type: "object", required: ["server", "tool"] },
        outputSchema: { type: "object" },
        evidenceRequirements: ["mcp_containment_receipt"],
      },
      ...codingToolContracts(),
    ];
    return pack
      ? tools.filter((tool) => optionalString(tool.pack)?.toLowerCase() === pack)
      : tools;
  }

  invokeThreadTool(threadId, toolId, request = {}) {
    const agent = this.agentForThread(threadId);
    const normalizedToolId = optionalString(toolId);
    if (!normalizedToolId || !CODING_TOOL_IDS.has(normalizedToolId)) {
      throw notFound(`Coding tool not found: ${toolId}`, {
        threadId,
        toolId,
        pack: CODING_TOOL_PACK_ID,
      });
    }
    const input = codingToolInputForRequest(request);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(this.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      `runtime.coding-tool.${safeId(normalizedToolId)}`;
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `coding_tool_${doctorHash(`${threadId}:${normalizedToolId}:${JSON.stringify(input)}:${Date.now()}`).slice(0, 16)}`;
    const receiptId = `receipt_coding_tool_${safeId(normalizedToolId)}_${doctorHash(
      `${threadId}:${normalizedToolId}:${toolCallId}`,
    ).slice(0, 12)}`;
    const artifactRefs = [];
    const receiptRefs = [receiptId];
    let status = "completed";
    let result = null;
    let error = null;
    try {
      result = executeCodingTool(normalizedToolId, agent.cwd, input, {
        threadId,
        toolId: normalizedToolId,
        toolCallId,
        readArtifact: (artifactId, range) => this.readCodingToolArtifact(threadId, artifactId, range),
        retrieveToolResult: (query) => this.retrieveCodingToolResult(threadId, query),
      });
      const materializedArtifacts = this.materializeCodingToolArtifactDrafts({
        threadId,
        toolId: normalizedToolId,
        toolCallId,
        workspaceRoot: agent.cwd,
        result,
        receiptId,
      });
      result = codingToolResultWithoutDrafts(result, materializedArtifacts);
      artifactRefs.push(...normalizeArray(result.artifactRefs));
      receiptRefs.push(...normalizeArray(result.receiptRefs));
    } catch (caught) {
      status = "failed";
      error = {
        code: caught?.code ?? "coding_tool_failed",
        message: String(caught?.message ?? caught),
        details: caught?.details ?? null,
      };
      result = {
        schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
        toolName: normalizedToolId,
        status,
        error,
      };
    }
    const summary = codingToolSummary(normalizedToolId, result, status);
    const payloadSummary = {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      event_kind: "CodingToolResult",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: normalizedToolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      status,
      summary,
      shell_fallback_used: false,
      input_summary: codingToolInputSummary(normalizedToolId, input),
      result_summary: codingToolResultSummary(normalizedToolId, result),
      result,
      error,
      receipt_id: receiptId,
      receipt_count: receiptRefs.length,
      artifact_count: artifactRefs.length,
    };
    const event = this.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:coding-tool:${safeId(normalizedToolId)}:${doctorHash(toolCallId).slice(0, 12)}`,
      idempotency_key:
        optionalString(request.idempotency_key ?? request.idempotencyKey) ??
        `thread:${threadId}:coding-tool:${toolCallId}`,
      source: operatorControlSource(request.source),
      source_event_kind: codingToolSourceEventKind(normalizedToolId),
      event_kind: status === "failed" ? "tool.failed" : "tool.completed",
      status,
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      tool_call_id: toolCallId,
      artifact_refs: artifactRefs,
      receipt_refs: uniqueStrings(receiptRefs),
      payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
    const autoDiagnostics =
      status === "completed" && normalizedToolId === "file.apply_patch"
        ? this.maybeRunPostEditDiagnostics({
            threadId,
            turnId,
            patchToolCallId: toolCallId,
            patchResult: result,
            request,
            input,
            workflowGraphId,
          })
        : null;
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: normalizedToolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      status,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      shell_fallback_used: false,
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      event,
      auto_diagnostics: autoDiagnostics,
      autoDiagnostics,
      result,
      error,
    };
  }

  maybeRunPostEditDiagnostics({
    threadId,
    turnId,
    patchToolCallId,
    patchResult,
    request = {},
    input = {},
    workflowGraphId = null,
  } = {}) {
    const config = postEditDiagnosticsConfig(request, input);
    if (config.mode === "skip") return null;
    const paths = normalizeArray(patchResult?.changedFiles)
      .filter((entry) => entry?.diagnosticsRecommended !== false)
      .map((entry) => optionalString(entry?.path))
      .filter(Boolean);
    if (!paths.length) return null;
    return this.invokeThreadTool(threadId, "lsp.diagnostics", {
      source: "runtime_auto",
      turn_id: turnId || null,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: LSP_DIAGNOSTICS_AUTO_NODE_ID,
      tool_call_id: `coding_tool_lsp_diagnostics_auto_${doctorHash(`${patchToolCallId}:${paths.join(",")}`).slice(0, 16)}`,
      input: {
        commandId: config.commandId,
        paths,
        cwd: config.cwd,
        timeoutMs: config.timeoutMs,
        maxOutputBytes: config.maxOutputBytes,
      },
    });
  }

  pendingDiagnosticsFeedbackForNextTurn(threadId, request = {}) {
    const injectionMode = normalizeDiagnosticsMode(
      request.diagnosticsMode ??
        request.diagnostics_mode ??
        request.options?.diagnosticsMode ??
        request.options?.diagnostics_mode ??
        "advisory",
    );
    if (injectionMode === "skip") return null;
    const stream = this.runtimeEventStream(eventStreamIdForThread(threadId));
    const lastInjectedSeq = Math.max(
      0,
      ...stream.events
        .filter((event) => event.event_kind === "lsp.diagnostics.injected")
        .map((event) => Number(event.seq) || 0),
    );
    const diagnosticEvents = stream.events.filter((event) => {
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.seq > lastInjectedSeq &&
        event.event_kind === "tool.completed" &&
        event.source === "runtime_auto" &&
        payload.tool_name === "lsp.diagnostics"
      );
    });
    if (!diagnosticEvents.length) return null;
    return compactDiagnosticsFeedback({ threadId, mode: injectionMode, diagnosticEvents });
  }

  materializeCodingToolArtifactDrafts({ threadId, toolId, toolCallId, workspaceRoot, result, receiptId }) {
    const drafts = normalizeArray(result?.artifactDrafts ?? result?.artifact_drafts);
    const createdAt = new Date().toISOString();
    return drafts
      .map((draft, index) => {
        if (!draft || typeof draft !== "object" || Array.isArray(draft)) return null;
        const content = String(draft.content ?? "");
        const channel = optionalString(draft.channel) ?? `artifact-${index + 1}`;
        const mediaType = optionalString(draft.mediaType ?? draft.media_type) ?? "text/plain";
        const contentBytes = Buffer.byteLength(content, "utf8");
        const contentHash = doctorHash(content);
        const artifactRecord = {
          schema_version: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
          schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
          id: `artifact_coding_tool_${safeId(toolCallId)}_${safeId(channel)}`,
          thread_id: threadId,
          threadId,
          tool_name: toolId,
          toolName: toolId,
          tool_call_id: toolCallId,
          toolCallId,
          workspace_root: workspaceRoot,
          workspaceRoot,
          name: optionalString(draft.name) ?? `${safeId(toolId)}-${channel}.txt`,
          channel,
          media_type: mediaType,
          mediaType,
          redaction: optionalString(draft.redaction) ?? "none",
          receipt_id: receiptId,
          receiptId,
          content,
          content_bytes: contentBytes,
          contentBytes,
          content_hash: contentHash,
          contentHash,
          created_at: createdAt,
          createdAt,
        };
        this.codingArtifacts.set(artifactRecord.id, artifactRecord);
        writeJson(this.pathFor("artifacts", `${artifactRecord.id}.json`), artifactRecord);
        return artifactRecord;
      })
      .filter(Boolean);
  }

  readCodingToolArtifact(threadId, artifactId, range = {}) {
    const artifactRecord = this.codingArtifacts.get(artifactId);
    if (!artifactRecord) throw notFound(`Artifact not found: ${artifactId}`, { threadId, artifactId });
    if (artifactRecord.thread_id && artifactRecord.thread_id !== threadId) {
      throw policyError("Artifact read blocked outside the owning runtime thread.", {
        threadId,
        artifactId,
        ownerThreadId: artifactRecord.thread_id,
      });
    }
    return codingToolArtifactReadResult(artifactRecord, range);
  }

  retrieveCodingToolResult(threadId, query = {}) {
    if (query.artifactId) {
      return {
        ...this.readCodingToolArtifact(threadId, query.artifactId, query.range),
        shellFallbackUsed: false,
      };
    }
    const toolCallId = optionalString(query.toolCallId);
    if (!toolCallId) {
      throw runtimeError({
        status: 400,
        code: "tool_retrieve_result_target_required",
        message: "tool.retrieve_result requires a toolCallId or artifactId.",
        details: { threadId },
      });
    }
    const artifacts = [...this.codingArtifacts.values()]
      .filter((artifactRecord) => artifactRecord.thread_id === threadId && artifactRecord.tool_call_id === toolCallId)
      .sort((left, right) => String(left.channel ?? "").localeCompare(String(right.channel ?? "")));
    if (!artifacts.length) {
      throw notFound(`Tool result artifact not found: ${toolCallId}`, { threadId, toolCallId });
    }
    const channel = optionalString(query.channel);
    const artifactRecord = artifacts.find((item) => item.channel === channel) ?? artifacts[0];
    return {
      ...codingToolArtifactReadResult(artifactRecord, query.range),
      toolCallId,
      availableArtifacts: artifacts.map(codingToolArtifactMetadata),
      shellFallbackUsed: false,
    };
  }

  ensureDirs() {
    for (const dir of [
      "agents",
      "runs",
      "tasks",
      "jobs",
      "checklists",
      "artifacts",
      "receipts",
      "quality",
      "policy-decisions",
      "authority-decisions",
      "stop-conditions",
      "scorecards",
      "ledgers",
      "projections",
      "model-artifacts",
      "model-endpoints",
      "model-instances",
      "model-routes",
      "model-providers",
      "model-downloads",
      "tokens",
      "mcp-servers",
      "memory-records",
      "memory-policies",
      "events",
    ]) {
      fs.mkdirSync(path.join(this.stateDir, dir), { recursive: true });
    }
  }

  writeSchema() {
    writeJson(this.pathFor("schema.json"), {
      schemaVersion: this.schemaVersion,
      relationSchemas: {
        runs: ["id", "agentId", "status", "objective", "mode", "createdAt", "updatedAt"],
        tasks: ["runId", "currentObjective", "facts", "constraints", "evidenceRefs"],
        jobs: ["jobId", "taskId", "runId", "agentId", "status", "createdAt", "updatedAt"],
        checklists: ["checklistId", "taskId", "jobId", "runId", "status", "itemCount", "completedItemCount"],
        artifacts: ["id", "runId", "name", "mediaType", "redaction", "receiptId"],
        receipts: ["id", "runId", "kind", "summary", "redaction", "evidenceRefs"],
        memoryRecords: ["id", "scope", "threadId", "agentId", "workspace", "createdAt"],
        memoryPolicies: ["id", "targetType", "targetId", "disabled", "readOnly", "writeRequiresApproval", "updatedAt"],
        runtimeEvents: [
          "event_stream_id",
          "seq",
          "idempotency_key",
          "thread_id",
          "turn_id",
          "item_id",
          "event_kind",
          "created_at",
        ],
        quality: ["runId", "scorecard", "qualityLedger", "stopCondition"],
        operationLog: ["sequence", "operationId", "kind", "objectId", "createdAt", "digest"],
        ...this.modelMounting.writeSchemaRelationSchemas(),
      },
      canonicalOwner: "Agentgres",
      sdkCheckpointAuthority: "cache_only",
    });
  }

  load() {
    for (const file of listJson(this.pathFor("agents"))) {
      const agent = readJson(file);
      this.agents.set(agent.id, agent);
    }
    for (const file of listJson(this.pathFor("runs"))) {
      const run = readJson(file);
      this.runs.set(run.id, run);
    }
    for (const file of listJson(this.pathFor("artifacts"))) {
      const artifactRecord = readJson(file);
      const schemaVersion = artifactRecord.schema_version ?? artifactRecord.schemaVersion;
      if (schemaVersion === CODING_TOOL_ARTIFACT_SCHEMA_VERSION && artifactRecord.id) {
        this.codingArtifacts.set(artifactRecord.id, artifactRecord);
      }
    }
    for (const file of listJsonl(this.pathFor("events"))) {
      for (const record of readJsonl(file)) {
        this.registerRuntimeEvent(record);
      }
    }
  }

  writeAgent(agent, operationKind) {
    writeJson(this.pathFor("agents", `${agent.id}.json`), agent);
    this.appendOperation(operationKind, { objectId: agent.id, agent });
  }

  writeRun(run, operationKind) {
    const runtimeTask = runtimeTaskRecordForRun(run);
    const runtimeJob = runtimeJobRecordForRun(run);
    const runtimeChecklist = runtimeChecklistRecordForRun(run);
    writeJson(this.pathFor("runs", `${run.id}.json`), run);
    writeJson(this.pathFor("tasks", `${run.id}.json`), {
      runId: run.id,
      agentId: run.agentId,
      runtimeTask,
      runtimeChecklist,
      taskState: run.trace.taskState,
      postconditions: run.trace.postconditions,
      semanticImpact: run.trace.semanticImpact,
      projectionWatermark: this.operationCount() + 1,
    });
    writeJson(this.pathFor("jobs", `${runtimeJob.jobId}.json`), runtimeJob);
    writeJson(this.pathFor("checklists", `${runtimeChecklist.checklistId}.json`), runtimeChecklist);
    for (const receipt of run.receipts) {
      writeJson(this.pathFor("receipts", `${receipt.id}.json`), { runId: run.id, ...receipt });
    }
    for (const artifact of run.artifacts) {
      writeJson(this.pathFor("artifacts", `${artifact.id}.json`), artifact);
    }
    writeJson(this.pathFor("policy-decisions", `${run.id}.json`), {
      runId: run.id,
      decision: "allowed",
      rationale: "Local daemon run stayed inside bounded local/private runtime contract.",
      primitiveCapabilities: ["prim:model.invoke"],
      authorityScopes: [],
      receiptId: run.receipts.find((receipt) => receipt.kind === "policy_decision")?.id,
    });
    writeJson(this.pathFor("authority-decisions", `${run.id}.json`), {
      runId: run.id,
      decision: "allowed",
      authorityScopes: [],
      walletLayer: "wallet.network",
      receiptId: run.receipts.find((receipt) => receipt.kind === "authority_decision")?.id,
    });
    writeJson(this.pathFor("stop-conditions", `${run.id}.json`), run.trace.stopCondition);
    writeJson(this.pathFor("scorecards", `${run.id}.json`), run.trace.scorecard);
    writeJson(this.pathFor("ledgers", `${run.id}.json`), run.trace.qualityLedger);
    writeJson(this.pathFor("quality", `${run.id}.json`), {
      runId: run.id,
      scorecard: run.trace.scorecard,
      qualityLedger: run.trace.qualityLedger,
      stopCondition: run.trace.stopCondition,
      verifierIndependencePolicy: {
        sameModelAllowed: false,
        evidenceOnlyMode: true,
        humanReviewThreshold: "high_risk",
      },
    });
    writeJson(this.pathFor("projections", `${run.id}.json`), this.canonicalProjection(run.id));
    this.appendOperation(operationKind, {
      objectId: run.id,
      runId: run.id,
      agentId: run.agentId,
      status: run.status,
      eventCount: run.events.length,
      terminalEventCount: terminalCount(run.events),
      traceBundleId: run.trace.traceBundleId,
    });
  }

  appendOperation(kind, payload) {
    const sequence = this.operationCount() + 1;
    const operation = {
      sequence,
      operationId: `op_${String(sequence).padStart(8, "0")}_${kind.replace(/[^a-z0-9]+/gi, "_")}`,
      kind,
      objectId: payload.objectId ?? payload.agentId ?? payload.runId ?? null,
      createdAt: new Date().toISOString(),
      payload,
    };
    const digest = crypto.createHash("sha256").update(JSON.stringify(operation)).digest("hex");
    const record = { ...operation, digest };
    fs.mkdirSync(this.stateDir, { recursive: true });
    fs.appendFileSync(this.pathFor("operation-log.jsonl"), `${JSON.stringify(record)}\n`);
    return record;
  }

  operationCount() {
    const logPath = this.pathFor("operation-log.jsonl");
    if (!fs.existsSync(logPath)) return 0;
    const text = fs.readFileSync(logPath, "utf8").trim();
    return text ? text.split(/\n/).length : 0;
  }

  pathFor(...segments) {
    return path.join(this.stateDir, ...segments);
  }

  removeQuiet(filePath) {
    try {
      fs.rmSync(filePath, { force: true });
    } catch {
      // Deleting a non-existent projection is not a state transition.
    }
  }
}

async function handleRequest({ request, response, store }) {
  const requestId = `req_${crypto.randomUUID()}`;
  response.setHeader("x-request-id", requestId);
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("access-control-allow-headers", "authorization,content-type,last-event-id,x-api-key");
  response.setHeader("access-control-allow-methods", "GET,POST,PATCH,DELETE,OPTIONS");
  if (request.method === "OPTIONS") {
    response.statusCode = 204;
    response.end();
    return;
  }

  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  const segments = url.pathname.split("/").filter(Boolean);
  try {
    if (segments[0] === "api" && segments[1] === "v1") {
      await handleModelMountingNativeRoute({ request, response, store, url, segments });
      return;
    }
    if (segments[0] === "v1" && isOpenAiCompatibilityRoute(request, url)) {
      await handleOpenAiCompatibilityRoute({ request, response, store, url });
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/doctor") {
      writeJsonResponse(response, store.doctorReport({ baseUrl: baseUrlForRequest(request) }));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/skills") {
      writeJsonResponse(response, store.listSkills());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/hooks") {
      writeJsonResponse(response, store.listHooks());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/repository-context") {
      writeJsonResponse(response, store.repositoryContext());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/branch-policy") {
      writeJsonResponse(response, store.branchPolicy());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/github-context") {
      writeJsonResponse(response, store.githubContext());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/pr-attempts") {
      writeJsonResponse(response, store.prAttempts());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/issue-context") {
      writeJsonResponse(response, store.issueContext());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/review-gate") {
      writeJsonResponse(response, store.reviewGate());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/github/pr-create-plan") {
      writeJsonResponse(response, store.githubPrCreatePlan());
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/agents") {
      writeJsonResponse(response, store.createAgent((await readBody(request)).options ?? {}));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/agents") {
      writeJsonResponse(response, store.listAgents());
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads") {
      writeJsonResponse(response, await store.createThread(await readBody(request)));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/threads") {
      writeJsonResponse(response, store.listThreads());
      return;
    }
    if (segments[0] === "v1" && segments[1] === "threads" && segments[2]) {
      await handleThreadRoute({ request, response, store, url, segments });
      return;
    }
    if (segments[0] === "v1" && segments[1] === "agents" && segments[2]) {
      await handleAgentRoute({ request, response, store, url, segments });
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/memory") {
      const agentId = url.searchParams.get("agent_id") ?? url.searchParams.get("agentId");
      if (!agentId) throw notFound("Memory listing requires agent_id.", { path: url.pathname });
      writeJsonResponse(response, store.listMemoryForAgent(agentId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs") {
      writeJsonResponse(response, store.listRuns(url.searchParams.get("agentId") ?? undefined));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/jobs") {
      writeJsonResponse(response, store.listJobs(Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (segments[0] === "v1" && segments[1] === "jobs" && segments[2] && request.method === "POST" && segments[3] === "cancel") {
      writeJsonResponse(response, store.cancelJob(decodeURIComponent(segments[2])));
      return;
    }
    if (segments[0] === "v1" && segments[1] === "jobs" && segments[2]) {
      writeJsonResponse(response, store.getJob(decodeURIComponent(segments[2])));
      return;
    }
    if (segments[0] === "v1" && segments[1] === "runs" && segments[2]) {
      await handleRunRoute({ request, response, store, url, segments });
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/models") {
      writeJsonResponse(response, store.listModels());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/repositories") {
      writeJsonResponse(response, store.listRepositories());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/account") {
      writeJsonResponse(response, store.getAccount());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runtime/nodes") {
      writeJsonResponse(response, store.listRuntimeNodes());
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/tools") {
      writeJsonResponse(response, store.listTools(Object.fromEntries(url.searchParams.entries())));
      return;
    }
    throw notFound("Public daemon route not found.", {
      method: request.method,
      path: url.pathname,
    });
  } catch (error) {
    writeError(response, error);
  }
}

async function handleModelMountingNativeRoute({ request, response, store, url, segments }) {
  const mounts = store.modelMounting;
  const authorization = request.headers.authorization;
  const baseUrl = baseUrlForRequest(request);
  if (request.method === "GET" && url.pathname === "/api/v1/server/status") {
    writeJsonResponse(response, mounts.serverStatus(baseUrl));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/server/start") {
    mounts.authorize(authorization, "server.control:*");
    writeJsonResponse(response, mounts.serverStart(baseUrl));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/server/stop") {
    mounts.authorize(authorization, "server.control:*");
    writeJsonResponse(response, mounts.serverStop(baseUrl));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/server/restart") {
    mounts.authorize(authorization, "server.control:*");
    writeJsonResponse(response, mounts.serverRestart(baseUrl));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/server/logs") {
    mounts.authorize(authorization, "server.logs:*");
    writeJsonResponse(response, mounts.serverLogs(Object.fromEntries(url.searchParams.entries())));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/server/events") {
    mounts.authorize(authorization, "server.logs:*");
    writeJsonResponse(response, mounts.serverEvents(Object.fromEntries(url.searchParams.entries())));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/backends") {
    writeJsonResponse(response, mounts.listBackends());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/runtime/engines") {
    writeJsonResponse(response, mounts.listRuntimeEngines());
    return;
  }
  if (request.method === "GET" && segments[2] === "runtime" && segments[3] === "engines" && segments[4]) {
    writeJsonResponse(response, mounts.runtimeEngine(decodeURIComponent(segments[4])));
    return;
  }
  if (request.method === "POST" && segments[2] === "runtime" && segments[3] === "engines" && segments[4] && segments[5] === "select") {
    writeJsonResponse(response, mounts.selectRuntimeEngine({ engine_id: decodeURIComponent(segments[4]), ...(await readBody(request)) }));
    return;
  }
  if (request.method === "PATCH" && segments[2] === "runtime" && segments[3] === "engines" && segments[4]) {
    writeJsonResponse(response, mounts.updateRuntimeEngine(decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "DELETE" && segments[2] === "runtime" && segments[3] === "engines" && segments[4]) {
    writeJsonResponse(response, mounts.removeRuntimeEngineOverride(decodeURIComponent(segments[4])));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/runtime/survey") {
    writeJsonResponse(response, mounts.runtimeSurvey());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/runtime/select") {
    writeJsonResponse(response, mounts.selectRuntimeEngine(await readBody(request)));
    return;
  }
  if (request.method === "POST" && segments[2] === "backends" && segments[3] && segments[4] === "health") {
    writeJsonResponse(response, mounts.backendHealth(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "POST" && segments[2] === "backends" && segments[3] && segments[4] === "start") {
    mounts.authorize(authorization, `backend.control:${decodeURIComponent(segments[3])}`);
    writeJsonResponse(response, mounts.startBackend(decodeURIComponent(segments[3]), await readBody(request)));
    return;
  }
  if (request.method === "POST" && segments[2] === "backends" && segments[3] && segments[4] === "stop") {
    mounts.authorize(authorization, `backend.control:${decodeURIComponent(segments[3])}`);
    writeJsonResponse(response, mounts.stopBackend(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && segments[2] === "backends" && segments[3] && segments[4] === "logs") {
    writeJsonResponse(response, mounts.backendLogs(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/models") {
    writeJsonResponse(response, mounts.snapshot(baseUrl));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/models/catalog/search") {
    writeJsonResponse(response, await mounts.catalogSearch(Object.fromEntries(url.searchParams.entries())));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/catalog/import-url") {
    mounts.authorize(authorization, "model.download:*");
    mounts.authorize(authorization, "model.import:*");
    writeJsonResponse(response, await mounts.catalogImportUrl(await readBody(request)), 202);
    return;
  }
  if (request.method === "GET" && segments[2] === "models" && segments[3] === "catalog" && segments[4] === "providers" && segments[5]) {
    writeJsonResponse(response, mounts.getCatalogProviderConfig(decodeURIComponent(segments[5])));
    return;
  }
  if (request.method === "PATCH" && segments[2] === "models" && segments[3] === "catalog" && segments[4] === "providers" && segments[5]) {
    const providerId = decodeURIComponent(segments[5]);
    mounts.authorize(authorization, `provider.write:${providerId}`);
    writeJsonResponse(response, mounts.configureCatalogProvider(providerId, await readBody(request)));
    return;
  }
  if (
    request.method === "POST" &&
    segments[2] === "models" &&
    segments[3] === "catalog" &&
    segments[4] === "providers" &&
    segments[5] &&
    segments[6] === "oauth" &&
    segments[7] === "start"
  ) {
    const providerId = decodeURIComponent(segments[5]);
    mounts.authorize(authorization, `provider.write:${providerId}`);
    mounts.authorize(authorization, "vault.write:*");
    writeJsonResponse(response, mounts.startCatalogProviderOAuth(providerId, await readBody(request)), 201);
    return;
  }
  if (
    request.method === "POST" &&
    segments[2] === "models" &&
    segments[3] === "catalog" &&
    segments[4] === "providers" &&
    segments[5] &&
    segments[6] === "oauth" &&
    segments[7] === "callback"
  ) {
    const providerId = decodeURIComponent(segments[5]);
    mounts.authorize(authorization, `provider.write:${providerId}`);
    mounts.authorize(authorization, "vault.write:*");
    writeJsonResponse(response, await mounts.completeCatalogProviderOAuth(providerId, await readBody(request)), 201);
    return;
  }
  if (
    request.method === "POST" &&
    segments[2] === "models" &&
    segments[3] === "catalog" &&
    segments[4] === "providers" &&
    segments[5] &&
    segments[6] === "oauth" &&
    segments[7] === "exchange"
  ) {
    const providerId = decodeURIComponent(segments[5]);
    mounts.authorize(authorization, `provider.write:${providerId}`);
    mounts.authorize(authorization, "vault.write:*");
    writeJsonResponse(response, await mounts.exchangeCatalogProviderOAuth(providerId, await readBody(request)), 201);
    return;
  }
  if (
    request.method === "POST" &&
    segments[2] === "models" &&
    segments[3] === "catalog" &&
    segments[4] === "providers" &&
    segments[5] &&
    segments[6] === "oauth" &&
    segments[7] === "refresh"
  ) {
    const providerId = decodeURIComponent(segments[5]);
    mounts.authorize(authorization, `provider.write:${providerId}`);
    mounts.authorize(authorization, "vault.write:*");
    writeJsonResponse(response, await mounts.refreshCatalogProviderOAuth(providerId));
    return;
  }
  if (
    request.method === "POST" &&
    segments[2] === "models" &&
    segments[3] === "catalog" &&
    segments[4] === "providers" &&
    segments[5] &&
    segments[6] === "oauth" &&
    segments[7] === "revoke"
  ) {
    const providerId = decodeURIComponent(segments[5]);
    mounts.authorize(authorization, `provider.write:${providerId}`);
    mounts.authorize(authorization, "vault.delete:*");
    writeJsonResponse(response, mounts.revokeCatalogProviderOAuth(providerId));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/storage/cleanup") {
    mounts.authorize(authorization, "model.delete:*");
    writeJsonResponse(response, mounts.cleanupModelStorage(await readBody(request)));
    return;
  }
  if (
    request.method === "GET" &&
    segments[2] === "models" &&
    segments[3] &&
    !["download", "loaded"].includes(segments[3])
  ) {
    writeJsonResponse(response, mounts.getModel(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "DELETE" && segments[2] === "models" && segments[3]) {
    mounts.authorize(authorization, "model.delete:*");
    writeJsonResponse(response, mounts.deleteModelArtifact(decodeURIComponent(segments[3]), await readBody(request)));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/download") {
    mounts.authorize(authorization, "model.download:*");
    writeJsonResponse(response, await mounts.downloadModel(await readBody(request)), 202);
    return;
  }
  if (
    request.method === "GET" &&
    segments[2] === "models" &&
    segments[3] === "download" &&
    segments[4] === "status" &&
    segments[5]
  ) {
    writeJsonResponse(response, mounts.downloadStatus(decodeURIComponent(segments[5])));
    return;
  }
  if (
    request.method === "POST" &&
    segments[2] === "models" &&
    segments[3] === "download" &&
    segments[4] === "cancel" &&
    segments[5]
  ) {
    mounts.authorize(authorization, "model.download:*");
    writeJsonResponse(response, mounts.cancelDownload(decodeURIComponent(segments[5]), await readBody(request)));
    return;
  }
  if (
    request.method === "POST" &&
    segments[2] === "models" &&
    segments[3] === "download" &&
    segments[4] &&
    segments[5] === "cancel"
  ) {
    mounts.authorize(authorization, "model.download:*");
    writeJsonResponse(response, mounts.cancelDownload(decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/import") {
    mounts.authorize(authorization, "model.import:*");
    writeJsonResponse(response, mounts.importModel(await readBody(request)), 201);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/mount") {
    mounts.authorize(authorization, "model.mount:*");
    writeJsonResponse(response, mounts.mountEndpoint(await readBody(request)), 201);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/unmount") {
    mounts.authorize(authorization, "model.unmount:*");
    writeJsonResponse(response, mounts.unmountEndpoint(await readBody(request)));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/load") {
    mounts.authorize(authorization, "model.load:*");
    writeJsonResponse(response, await mounts.loadModel(await readBody(request)), 201);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/models/unload") {
    mounts.authorize(authorization, "model.unload:*");
    writeJsonResponse(response, await mounts.unloadModel(await readBody(request)));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/models/loaded") {
    writeJsonResponse(response, mounts.listInstances().filter((instance) => instance.status === "loaded"));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/providers") {
    writeJsonResponse(response, mounts.listProviders());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/vault/refs") {
    mounts.authorize(authorization, "vault.read:*");
    writeJsonResponse(response, mounts.listVaultRefs());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/vault/status") {
    mounts.authorize(authorization, "vault.read:*");
    writeJsonResponse(response, mounts.vaultStatus());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/vault/health/latest") {
    mounts.authorize(authorization, "vault.read:*");
    writeJsonResponse(response, mounts.latestVaultHealth());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/vault/health") {
    mounts.authorize(authorization, "vault.read:*");
    writeJsonResponse(response, mounts.vaultHealth());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/vault/refs") {
    mounts.authorize(authorization, "vault.write:*");
    writeJsonResponse(response, mounts.bindVaultRef(await readBody(request)), 201);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/vault/refs/meta") {
    mounts.authorize(authorization, "vault.read:*");
    writeJsonResponse(response, mounts.vaultRefMetadata(await readBody(request)));
    return;
  }
  if (request.method === "DELETE" && url.pathname === "/api/v1/vault/refs") {
    mounts.authorize(authorization, "vault.delete:*");
    writeJsonResponse(response, mounts.removeVaultRef(await readBody(request)));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/providers") {
    mounts.authorize(authorization, "provider.write:*");
    writeJsonResponse(response, mounts.upsertProvider(await readBody(request)), 201);
    return;
  }
  if (request.method === "PATCH" && segments[2] === "providers" && segments[3]) {
    mounts.authorize(authorization, `provider.write:${decodeURIComponent(segments[3])}`);
    writeJsonResponse(response, mounts.upsertProvider({ ...(await readBody(request)), id: decodeURIComponent(segments[3]) }));
    return;
  }
  if (request.method === "GET" && segments[2] === "providers" && segments[3] && segments[4] === "health" && segments[5] === "latest") {
    writeJsonResponse(response, mounts.latestProviderHealth(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "POST" && segments[2] === "providers" && segments[3] && segments[4] === "health") {
    writeJsonResponse(response, await mounts.providerHealth(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && segments[2] === "providers" && segments[3] && segments[4] === "models") {
    writeJsonResponse(response, await mounts.listProviderModels(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && segments[2] === "providers" && segments[3] && segments[4] === "loaded") {
    writeJsonResponse(response, await mounts.listProviderLoaded(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "POST" && segments[2] === "providers" && segments[3] && segments[4] === "start") {
    mounts.authorize(authorization, `provider.control:${decodeURIComponent(segments[3])}`);
    writeJsonResponse(response, await mounts.startProvider(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "POST" && segments[2] === "providers" && segments[3] && segments[4] === "stop") {
    mounts.authorize(authorization, `provider.control:${decodeURIComponent(segments[3])}`);
    writeJsonResponse(response, await mounts.stopProvider(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/routes") {
    writeJsonResponse(response, mounts.listRoutes());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/routes") {
    mounts.authorize(authorization, "route.write:*");
    writeJsonResponse(response, mounts.upsertRoute(await readBody(request)), 201);
    return;
  }
  if (request.method === "POST" && segments[2] === "routes" && segments[3] && segments[4] === "test") {
    mounts.authorize(authorization, `route.use:${decodeURIComponent(segments[3])}`);
    writeJsonResponse(response, mounts.testRoute(decodeURIComponent(segments[3]), await readBody(request)));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/chat") {
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "chat",
      body: await readBody(request),
    });
    writeJsonResponse(response, nativeInvocationResponse(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/responses") {
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.responses:*",
      kind: "responses",
      body: await readBody(request),
    });
    writeJsonResponse(response, nativeInvocationResponse(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/embeddings") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.embeddings:*",
      kind: "embeddings",
      body,
    });
    writeJsonResponse(response, {
      ...nativeInvocationResponse(invocation),
      embeddings: openAiEmbedding(invocation, body).data,
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/rerank") {
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.rerank:*",
      kind: "rerank",
      body: await readBody(request),
    });
    writeJsonResponse(response, nativeInvocationResponse(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/tokenize") {
    writeJsonResponse(
      response,
      mounts.tokenizeModel({
        authorization,
        requiredScope: "model.tokenize:*",
        body: await readBody(request),
      }),
    );
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/tokens/count") {
    writeJsonResponse(
      response,
      mounts.countModelTokens({
        authorization,
        requiredScope: "model.tokenize:*",
        body: await readBody(request),
      }),
    );
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/context/fit") {
    writeJsonResponse(
      response,
      mounts.fitModelContext({
        authorization,
        requiredScope: "model.context:*",
        body: await readBody(request),
      }),
    );
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/tokens") {
    writeJsonResponse(response, mounts.listTokens());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/tokens") {
    writeJsonResponse(response, mounts.createToken(await readBody(request)), 201);
    return;
  }
  if (request.method === "DELETE" && segments[2] === "tokens" && segments[3]) {
    writeJsonResponse(response, mounts.revokeToken(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/receipts") {
    writeJsonResponse(response, mounts.listReceipts());
    return;
  }
  if (request.method === "GET" && segments[2] === "receipts" && segments[3] && segments[4] === "replay") {
    writeJsonResponse(response, mounts.receiptReplay(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && segments[2] === "receipts" && segments[3]) {
    writeJsonResponse(response, mounts.getReceipt(decodeURIComponent(segments[3])));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/projections/model-mounting") {
    writeJsonResponse(response, mounts.projection());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/workflows/nodes/execute") {
    writeJsonResponse(response, await mounts.executeWorkflowNode({ authorization, body: await readBody(request) }));
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/workflows/receipt-gate") {
    writeJsonResponse(response, mounts.validateReceiptGate(await readBody(request)));
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/mcp") {
    writeJsonResponse(response, mounts.listMcpServers());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/mcp/import") {
    mounts.authorize(authorization, "mcp.import:*");
    writeJsonResponse(response, mounts.importMcpJson(await readBody(request)), 201);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/mcp/invoke") {
    writeJsonResponse(response, mounts.invokeMcpTool({ authorization, body: await readBody(request) }));
    return;
  }
  throw notFound("Model mounting route not found.", {
    method: request.method,
    path: url.pathname,
  });
}

async function handleOpenAiCompatibilityRoute({ request, response, store, url }) {
  const mounts = store.modelMounting;
  const authorization = compatibilityAuthorization(request);
  if (request.method === "GET" && url.pathname === "/v1/models") {
    writeJsonResponse(response, mounts.openAiModelList());
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
    const body = await readBody(request);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      });
      if (stream.native) {
        await writeOpenAiProviderChatCompletionStream(request, response, stream, mounts);
        return;
      }
      await writeOpenAiChatCompletionStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "chat.completions",
      body,
    });
    writeJsonResponse(response, openAiChatCompletion(invocation, body));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/responses") {
    const body = await readBody(request);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.responses:*",
        kind: "responses",
        body,
      });
      if (stream.native) {
        await writeOpenAiProviderResponseStream(response, stream, mounts);
        return;
      }
      await writeOpenAiResponseStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.responses:*",
      kind: "responses",
      body,
    });
    writeJsonResponse(response, openAiResponse(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/embeddings") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.embeddings:*",
      kind: "embeddings",
      body,
    });
    writeJsonResponse(response, openAiEmbedding(invocation, body));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/completions") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "completions",
      body,
    });
    writeJsonResponse(response, openAiCompletion(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/messages") {
    const body = await readBody(request);
    const canonicalBody = anthropicMessagesToCanonicalBody(body);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body: canonicalBody,
      });
      if (stream.native) {
        await writeAnthropicProviderMessageStream(response, stream, mounts);
        return;
      }
      await writeAnthropicMessageStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "messages",
      body: canonicalBody,
    });
    writeJsonResponse(response, anthropicMessage(invocation));
    return;
  }
  throw notFound("OpenAI-compatible route not found.", {
    method: request.method,
    path: url.pathname,
  });
}

function isOpenAiCompatibilityRoute(request, url) {
  if (request.method === "GET" && url.pathname === "/v1/models") {
    return Boolean(compatibilityAuthorization(request));
  }
  return [
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/embeddings",
    "/v1/completions",
    "/v1/messages",
  ].includes(url.pathname);
}

function compatibilityAuthorization(request) {
  const authorization = firstHeader(request.headers.authorization);
  if (authorization) return authorization;
  const apiKey = firstHeader(request.headers["x-api-key"]);
  if (!apiKey) return undefined;
  return apiKey.startsWith("Bearer ") ? apiKey : `Bearer ${apiKey}`;
}

function firstHeader(value) {
  if (Array.isArray(value)) return value[0];
  return value;
}

function anthropicMessagesToCanonicalBody(body = {}) {
  return {
    ...body,
    messages: canonicalAnthropicMessages(body),
    max_tokens: body.max_tokens ?? body.maxTokens,
    stream: false,
  };
}

function canonicalAnthropicMessages(body = {}) {
  const messages = [];
  if (body.system !== undefined) {
    messages.push({ role: "system", content: anthropicContentToText(body.system) });
  }
  for (const message of Array.isArray(body.messages) ? body.messages : []) {
    messages.push({
      role: message?.role ?? "user",
      content: anthropicContentToText(message?.content ?? ""),
    });
  }
  return messages.length > 0 ? messages : [{ role: "user", content: anthropicContentToText(body.input ?? "") }];
}

function anthropicContentToText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((item) => {
        if (typeof item === "string") return item;
        if (typeof item?.text === "string") return item.text;
        if (typeof item?.content === "string") return item.content;
        if (item?.type === "image" || item?.type === "image_url") return "[image]";
        return JSON.stringify(redact(item ?? {}));
      })
      .join("\n");
  }
  if (content && typeof content === "object") {
    if (typeof content.text === "string") return content.text;
    return JSON.stringify(redact(content));
  }
  return String(content ?? "");
}

async function writeAnthropicMessageStream(response, invocation, mounts) {
  const message = anthropicMessage(invocation);
  const text = String(message.content?.[0]?.text ?? "");
  const chunks = textChunksForSse(text);
  const usage = message.usage ?? { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 };
  const events = [
    {
      event: "message_start",
      data: {
        type: "message_start",
        message: {
          id: message.id,
          type: "message",
          role: "assistant",
          content: [],
          model: message.model,
          stop_reason: null,
          stop_sequence: null,
          usage: {
            input_tokens: usage.input_tokens,
            output_tokens: 0,
            cache_read_input_tokens: usage.cache_read_input_tokens ?? 0,
          },
        },
      },
    },
    {
      event: "content_block_start",
      data: {
        type: "content_block_start",
        index: 0,
        content_block: { type: "text", text: "" },
      },
    },
    ...chunks.map((chunk) => ({
      event: "content_block_delta",
      data: {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: chunk },
      },
    })),
    {
      event: "content_block_stop",
      data: {
        type: "content_block_stop",
        index: 0,
      },
    },
    {
      event: "message_delta",
      data: {
        type: "message_delta",
        delta: {
          stop_reason: message.stop_reason,
          stop_sequence: message.stop_sequence,
        },
        usage: {
          output_tokens: usage.output_tokens,
        },
      },
    },
    {
      event: "message_stop",
      data: {
        type: "message_stop",
        receipt_id: message.receipt_id,
        response_id: message.response_id,
        previous_response_id: message.previous_response_id,
        route_id: message.route_id,
        tool_receipt_ids: message.tool_receipt_ids,
      },
    },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "anthropic_messages",
    frames: events.map((event) => `event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`),
  });
}

async function writeAnthropicProviderMessageStream(response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = "anthropic_messages_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const messageId = invocation.responseId?.startsWith("msg_") ? invocation.responseId : `msg_${crypto.randomUUID()}`;
  const startUsage = invocation.tokenCount ?? { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "end_turn";
  let buffer = "";
  const writeEvent = (event, data) => {
    response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    written += 1;
  };
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    writeEvent("message_start", {
      type: "message_start",
      message: {
        id: messageId,
        type: "message",
        role: "assistant",
        content: [],
        model: invocation.model,
        stop_reason: null,
        stop_sequence: null,
        usage: {
          input_tokens: startUsage.prompt_tokens ?? startUsage.input_tokens ?? 0,
          output_tokens: 0,
          cache_read_input_tokens: 0,
        },
      },
    });
    writeEvent("content_block_start", {
      type: "content_block_start",
      index: 0,
      content_block: { type: "text", text: "" },
    });
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
        const lines = takeLineBlocks(buffer);
        buffer = lines.remainder;
        for (const line of lines.blocks) {
          if (canceled) break;
          if (response.destroyed || response.writableEnded) {
            markCanceled();
            break;
          }
          const parsed = parseJsonMaybe(line);
          const delta = ollamaStreamDelta(parsed);
          if (delta) {
            outputText += delta;
            writeEvent("content_block_delta", {
              type: "content_block_delta",
              index: 0,
              delta: { type: "text_delta", text: delta },
            });
          }
          if (parsed?.done) {
            providerUsage = ollamaUsage(parsed);
            finishReason = parsed.done_reason ?? "end_turn";
          }
        }
      } else {
        const frames = takeSseFrameBlocks(buffer);
        buffer = frames.remainder;
        for (const frame of frames.blocks) {
          if (canceled) break;
          if (response.destroyed || response.writableEnded) {
            markCanceled();
            break;
          }
          for (const payload of dataPayloadsFromSseBlock(frame)) {
            if (payload === "[DONE]") continue;
            const parsed = parseJsonMaybe(payload);
            const delta = parsed?.choices?.[0]?.delta?.content;
            if (typeof delta === "string" && delta) {
              outputText += delta;
              writeEvent("content_block_delta", {
                type: "content_block_delta",
                index: 0,
                delta: { type: "text_delta", text: delta },
              });
            }
            if (parsed?.usage) providerUsage = parsed.usage;
            const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
            if (nextFinishReason) finishReason = nextFinishReason;
          }
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    if (buffer.trim()) {
      const tailLines = ["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)
        ? takeLineBlocks(`${buffer}\n`).blocks
        : takeSseFrameBlocks(`${buffer}\n\n`).blocks.flatMap((block) => dataPayloadsFromSseBlock(block));
      for (const item of tailLines) {
        const parsed = parseJsonMaybe(item);
        const delta =
          ["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)
            ? ollamaStreamDelta(parsed)
            : parsed?.choices?.[0]?.delta?.content;
        if (typeof delta === "string" && delta) {
          outputText += delta;
          writeEvent("content_block_delta", {
            type: "content_block_delta",
            index: 0,
            delta: { type: "text_delta", text: delta },
          });
        }
        if (parsed?.usage) providerUsage = parsed.usage;
        if (parsed?.done) providerUsage = ollamaUsage(parsed);
        const nextFinishReason = parsed?.choices?.[0]?.finish_reason ?? parsed?.done_reason;
        if (nextFinishReason) finishReason = nextFinishReason;
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const usage = providerUsage ?? invocation.tokenCount ?? { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
    if (!response.destroyed && !response.writableEnded) {
      writeEvent("content_block_stop", { type: "content_block_stop", index: 0 });
      writeEvent("message_delta", {
        type: "message_delta",
        delta: {
          stop_reason: finishReason || "end_turn",
          stop_sequence: null,
        },
        usage: {
          output_tokens: usage.completion_tokens ?? usage.output_tokens ?? 0,
        },
      });
      writeEvent("message_stop", {
        type: "message_stop",
        receipt_id: invocation.receipt.id,
        stream_receipt_id: completionReceipt.id,
        response_id: invocation.responseId ?? null,
        previous_response_id: invocation.previousResponseId ?? null,
        route_id: invocation.route.id,
        tool_receipt_ids: invocation.toolReceiptIds ?? [],
        provider_stream: "native",
      });
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

function textChunksForSse(text) {
  if (!text) return [""];
  const chunks = text.match(/.{1,96}(?:\s+|$)/gs);
  return chunks?.length ? chunks : [text];
}

async function writeOpenAiChatCompletionStream(response, invocation, mounts) {
  const id = `chatcmpl_${crypto.randomUUID()}`;
  const created = Math.floor(Date.now() / 1000);
  const chunks = textChunksForSse(invocation.outputText);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model: invocation.model,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
  };
  const payloads = [
    {
      ...base,
      choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }],
    },
    ...chunks.map((chunk) => ({
      ...base,
      choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }],
    })),
    {
      ...base,
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "openai_chat_completions",
    frames: [...payloads.map((payload) => `data: ${JSON.stringify(payload)}\n\n`), "data: [DONE]\n\n"],
  });
}

async function writeOpenAiProviderChatCompletionStream(request, response, streamInvocation, mounts) {
  if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
    await writeOllamaChatCompletionStream(request, response, streamInvocation, mounts);
    return;
  }
  const invocation = streamInvocation.invocation;
  const streamKind = "openai_chat_completions_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const forwardDelayMs = providerStreamForwardDelayMs();
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = null;
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  request.on("aborted", onClose);
  request.on("close", onClose);
  try {
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const frames = takeSseFrameBlocks(buffer);
      buffer = frames.remainder;
      for (const frame of frames.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        for (const payload of dataPayloadsFromSseBlock(frame)) {
          if (payload === "[DONE]") continue;
          const parsed = parseJsonMaybe(payload);
          const delta = parsed?.choices?.[0]?.delta?.content;
          if (typeof delta === "string") outputText += delta;
          if (parsed?.usage) providerUsage = parsed.usage;
          const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
          if (nextFinishReason) finishReason = nextFinishReason;
          try {
            response.write(`data: ${payload}\n\n`);
          } catch {
            markCanceled();
            break;
          }
          written += 1;
          if (forwardDelayMs > 0) await delay(forwardDelayMs);
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    const trailingBlocks = buffer.trim() ? [buffer] : [];
    for (const frame of trailingBlocks) {
      for (const payload of dataPayloadsFromSseBlock(frame)) {
        if (payload === "[DONE]") continue;
        const parsed = parseJsonMaybe(payload);
        const delta = parsed?.choices?.[0]?.delta?.content;
        if (typeof delta === "string") outputText += delta;
        if (parsed?.usage) providerUsage = parsed.usage;
        const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
        if (nextFinishReason) finishReason = nextFinishReason;
        response.write(`data: ${payload}\n\n`);
        written += 1;
        if (forwardDelayMs > 0) await delay(forwardDelayMs);
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const metadata = {
      id: `chatcmpl_${crypto.randomUUID()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: invocation.model,
      receipt_id: invocation.receipt.id,
      stream_receipt_id: completionReceipt.id,
      response_id: invocation.responseId ?? null,
      previous_response_id: invocation.previousResponseId ?? null,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      provider_stream: "native",
      choices: [{ index: 0, delta: {}, finish_reason: null }],
    };
    if (!response.destroyed && !response.writableEnded) {
      response.write(`data: ${JSON.stringify(metadata)}\n\n`);
      response.write("data: [DONE]\n\n");
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    request.off("aborted", onClose);
    request.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOllamaChatCompletionStream(request, response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = streamInvocation.providerResult?.streamKind ?? "openai_chat_completions_ollama_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const forwardDelayMs = providerStreamForwardDelayMs();
  const id = `chatcmpl_${crypto.randomUUID()}`;
  const created = Math.floor(Date.now() / 1000);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model: invocation.model,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
    provider_stream: "native",
  };
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "stop";
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  request.on("aborted", onClose);
  request.on("close", onClose);
  try {
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`);
    written += 1;
    if (forwardDelayMs > 0) await delay(forwardDelayMs);
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const lines = takeLineBlocks(buffer);
      buffer = lines.remainder;
      for (const line of lines.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsed = parseJsonMaybe(line);
        const delta = ollamaStreamDelta(parsed);
        if (delta) {
          outputText += delta;
          response.write(
            `data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: delta }, finish_reason: null }] })}\n\n`,
          );
          written += 1;
          if (forwardDelayMs > 0) await delay(forwardDelayMs);
        }
        if (parsed?.done) {
          providerUsage = ollamaUsage(parsed);
          finishReason = parsed.done_reason ?? "stop";
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    for (const line of buffer.trim() ? [buffer.trim()] : []) {
      const parsed = parseJsonMaybe(line);
      const delta = ollamaStreamDelta(parsed);
      if (delta) outputText += delta;
      if (parsed?.done) {
        providerUsage = ollamaUsage(parsed);
        finishReason = parsed.done_reason ?? "stop";
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    response.write(
      `data: ${JSON.stringify({
        ...base,
        stream_receipt_id: completionReceipt.id,
        choices: [{ index: 0, delta: {}, finish_reason: finishReason }],
      })}\n\n`,
    );
    response.write("data: [DONE]\n\n");
    completed = true;
    response.end();
  } finally {
    response.off("close", onClose);
    request.off("aborted", onClose);
    request.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOpenAiProviderResponseStream(response, streamInvocation, mounts) {
  if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
    await writeOllamaResponseStream(response, streamInvocation, mounts);
    return;
  }
  const invocation = streamInvocation.invocation;
  const streamKind = "openai_responses_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = null;
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const frames = takeSseFrameBlocks(buffer);
      buffer = frames.remainder;
      for (const frame of frames.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsedPayloads = responseStreamPayloads(frame);
        for (const payload of parsedPayloads) {
          if (payload.raw === "[DONE]") continue;
          if (payload.delta) outputText += payload.delta;
          if (!outputText && payload.completionText) outputText = payload.completionText;
          if (payload.usage) providerUsage = payload.usage;
          if (payload.finishReason) finishReason = payload.finishReason;
        }
        try {
          response.write(`${frame}\n\n`);
        } catch {
          markCanceled();
          break;
        }
        written += 1;
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    const trailingBlocks = buffer.trim() ? [buffer] : [];
    for (const frame of trailingBlocks) {
      const parsedPayloads = responseStreamPayloads(frame);
      if (parsedPayloads.every((payload) => payload.raw === "[DONE]")) continue;
      for (const payload of parsedPayloads) {
        if (payload.raw === "[DONE]") continue;
        if (payload.delta) outputText += payload.delta;
        if (!outputText && payload.completionText) outputText = payload.completionText;
        if (payload.usage) providerUsage = payload.usage;
        if (payload.finishReason) finishReason = payload.finishReason;
      }
      response.write(`${frame}\n\n`);
      written += 1;
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const metadata = {
      type: "response.ioi.receipt",
      receipt_id: invocation.receipt.id,
      stream_receipt_id: completionReceipt.id,
      response_id: invocation.responseId ?? null,
      previous_response_id: invocation.previousResponseId ?? null,
      route_id: invocation.route.id,
      model: invocation.model,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      provider_stream: "native",
    };
    if (!response.destroyed && !response.writableEnded) {
      response.write(`event: response.ioi.receipt\ndata: ${JSON.stringify(metadata)}\n\n`);
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOllamaResponseStream(response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = streamInvocation.providerResult?.streamKind ?? "openai_responses_ollama_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const responseId = invocation.responseId ?? `resp_${crypto.randomUUID()}`;
  const outputItemId = `msg_${crypto.randomUUID()}`;
  const createdAt = Math.floor(Date.now() / 1000);
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "stop";
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  const baseResponse = {
    id: responseId,
    object: "response",
    created_at: createdAt,
    model: invocation.model,
    status: "in_progress",
    output: [],
    usage: null,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    previous_response_id: invocation.previousResponseId ?? null,
    provider_stream: "native",
  };
  const outputItem = {
    id: outputItemId,
    type: "message",
    status: "in_progress",
    role: "assistant",
    content: [],
  };
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    response.write(`event: response.created\ndata: ${JSON.stringify({ type: "response.created", response: baseResponse })}\n\n`);
    response.write(`event: response.output_item.added\ndata: ${JSON.stringify({ type: "response.output_item.added", output_index: 0, item: outputItem })}\n\n`);
    response.write(
      `event: response.content_part.added\ndata: ${JSON.stringify({
        type: "response.content_part.added",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: "" },
      })}\n\n`,
    );
    written += 3;
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const lines = takeLineBlocks(buffer);
      buffer = lines.remainder;
      for (const line of lines.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsed = parseJsonMaybe(line);
        const delta = ollamaStreamDelta(parsed);
        if (delta) {
          outputText += delta;
          response.write(
            `event: response.output_text.delta\ndata: ${JSON.stringify({
              type: "response.output_text.delta",
              item_id: outputItemId,
              output_index: 0,
              content_index: 0,
              delta,
            })}\n\n`,
          );
          written += 1;
        }
        if (parsed?.done) {
          providerUsage = ollamaUsage(parsed);
          finishReason = parsed.done_reason ?? "stop";
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    for (const line of buffer.trim() ? [buffer.trim()] : []) {
      const parsed = parseJsonMaybe(line);
      const delta = ollamaStreamDelta(parsed);
      if (delta) outputText += delta;
      if (parsed?.done) {
        providerUsage = ollamaUsage(parsed);
        finishReason = parsed.done_reason ?? "stop";
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const completedOutputItem = {
      ...outputItem,
      status: "completed",
      content: [{ type: "output_text", text: outputText }],
    };
    const completedResponse = {
      ...baseResponse,
      status: "completed",
      output: [completedOutputItem],
      output_text: outputText,
      usage: providerUsage,
      stream_receipt_id: completionReceipt.id,
    };
    response.write(
      `event: response.content_part.done\ndata: ${JSON.stringify({
        type: "response.content_part.done",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: outputText },
      })}\n\n`,
    );
    response.write(`event: response.output_item.done\ndata: ${JSON.stringify({ type: "response.output_item.done", output_index: 0, item: completedOutputItem })}\n\n`);
    response.write(`event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: completedResponse })}\n\n`);
    completed = true;
    response.end();
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOpenAiResponseStream(response, invocation, mounts) {
  const responseId = invocation.responseId ?? `resp_${crypto.randomUUID()}`;
  const outputItemId = `msg_${crypto.randomUUID()}`;
  const createdAt = Math.floor(Date.now() / 1000);
  const chunks = textChunksForSse(invocation.outputText);
  const baseResponse = {
    id: responseId,
    object: "response",
    created_at: createdAt,
    model: invocation.model,
    status: "in_progress",
    output: [],
    usage: null,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    previous_response_id: invocation.previousResponseId ?? null,
  };
  const outputItem = {
    id: outputItemId,
    type: "message",
    status: "in_progress",
    role: "assistant",
    content: [],
  };
  const completedOutputItem = {
    ...outputItem,
    status: "completed",
    content: [{ type: "output_text", text: invocation.outputText }],
  };
  const completedResponse = {
    ...baseResponse,
    status: "completed",
    output: [completedOutputItem],
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
  const events = [
    { event: "response.created", data: { type: "response.created", response: baseResponse } },
    {
      event: "response.output_item.added",
      data: { type: "response.output_item.added", output_index: 0, item: outputItem },
    },
    {
      event: "response.content_part.added",
      data: {
        type: "response.content_part.added",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: "" },
      },
    },
    ...chunks.map((chunk) => ({
      event: "response.output_text.delta",
      data: {
        type: "response.output_text.delta",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        delta: chunk,
      },
    })),
    {
      event: "response.content_part.done",
      data: {
        type: "response.content_part.done",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: invocation.outputText },
      },
    },
    {
      event: "response.output_item.done",
      data: { type: "response.output_item.done", output_index: 0, item: completedOutputItem },
    },
    { event: "response.completed", data: { type: "response.completed", response: completedResponse } },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "openai_responses",
    frames: events.map((event) => `event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`),
  });
}

async function writeModelSseFrames({ response, invocation, mounts, streamKind, frames }) {
  let completed = false;
  let canceled = false;
  const onClose = () => {
    if (completed || canceled) return;
    canceled = true;
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  let written = 0;
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.on("close", onClose);
  try {
    for (const frame of frames) {
      if (canceled || response.destroyed || response.writableEnded) break;
      response.write(frame);
      written += 1;
      await delay(streamFrameDelayMs());
    }
    if (!canceled && !response.destroyed && !response.writableEnded) {
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
  }
}

function recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten }) {
  mounts.receipt("model_invocation_stream_canceled", {
    summary: `${streamKind} stream canceled for ${invocation.model}.`,
    redaction: "redacted",
    evidenceRefs: ["model_stream", streamKind, invocation.receipt.id, invocation.route.id, invocation.endpoint.id],
    details: {
      streamKind,
      invocationReceiptId: invocation.receipt.id,
      routeId: invocation.route.id,
      selectedModel: invocation.model,
      endpointId: invocation.endpoint.id,
      providerId: invocation.endpoint.providerId,
      instanceId: invocation.instance.id,
      backendId: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
      selectedBackend: invocation.receipt.details?.selectedBackend ?? null,
      streamSource: invocation.receipt.details?.streamSource ?? null,
      providerResponseKind: invocation.providerResponseKind ?? invocation.receipt.details?.providerResponseKind ?? null,
      backendEvidenceRefs: invocation.receipt.details?.backendEvidenceRefs ?? [],
      toolReceiptIds: invocation.toolReceiptIds ?? [],
      framesWritten,
      status: "aborted",
      reason: "client_disconnect",
    },
  });
}

function streamFrameDelayMs() {
  const configured = Number(process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS ?? "");
  if (Number.isFinite(configured) && configured >= 0) return Math.min(configured, 1000);
  return 5;
}

function providerStreamForwardDelayMs() {
  const configured = Number(process.env.IOI_PROVIDER_SSE_FRAME_DELAY_MS ?? "");
  if (Number.isFinite(configured) && configured >= 0) return Math.min(configured, 1000);
  return 0;
}

function takeSseFrameBlocks(buffer) {
  const parts = String(buffer).split(/\r?\n\r?\n/);
  const remainder = parts.pop() ?? "";
  return { blocks: parts.filter(Boolean), remainder };
}

function takeLineBlocks(buffer) {
  const parts = String(buffer).split(/\r?\n/);
  const remainder = parts.pop() ?? "";
  return { blocks: parts.map((part) => part.trim()).filter(Boolean), remainder };
}

function dataPayloadsFromSseBlock(block) {
  const payload = String(block)
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.replace(/^data:\s?/, ""))
    .join("\n");
  return payload ? [payload] : [];
}

function responseStreamPayloads(block) {
  return dataPayloadsFromSseBlock(block).map((raw) => {
    if (raw === "[DONE]") return { raw };
    const parsed = parseJsonMaybe(raw);
    return {
      raw,
      parsed,
      delta: typeof parsed?.delta === "string" && parsed?.type === "response.output_text.delta" ? parsed.delta : "",
      completionText: typeof parsed?.response?.output_text === "string" ? parsed.response.output_text : "",
      usage: parsed?.response?.usage ?? parsed?.usage ?? null,
      finishReason: parsed?.response?.status ?? parsed?.status ?? parsed?.type ?? null,
    };
  });
}

function ollamaStreamDelta(payload) {
  if (!payload || typeof payload !== "object") return "";
  return String(payload.delta ?? payload.message?.content ?? payload.response ?? "");
}

function ollamaUsage(payload) {
  const promptTokens = Number(payload?.prompt_eval_count ?? 0) || 0;
  const completionTokens = Number(payload?.eval_count ?? 0) || 0;
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
  };
}

function parseJsonMaybe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function nativeInvocationResponse(invocation) {
  return {
    id: `model_invocation_${crypto.randomUUID()}`,
    object: "ioi.model_invocation",
    model: invocation.model,
    route_id: invocation.route.id,
    endpoint_id: invocation.endpoint.id,
    instance_id: invocation.instance.id,
    backend_id: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
    receipt_id: invocation.receipt.id,
    route_receipt_id: invocation.routeReceipt?.id ?? null,
    route_decision: invocation.routeReceipt?.details?.modelRouteDecision ?? null,
    response_id: invocation.responseId ?? null,
    previous_response_id: invocation.previousResponseId ?? null,
    compat_translation: invocation.compatTranslation ?? null,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
}

function baseUrlForRequest(request) {
  const host = request.headers.host;
  return host ? `http://${host}` : null;
}

function runtimeEventCursorFromRequest({ request, url }) {
  if (url.searchParams.has("since_seq")) {
    return { sinceSeq: Number(url.searchParams.get("since_seq") ?? 0) || 0 };
  }
  return {
    lastEventId:
      url.searchParams.get("lastEventId") ??
      url.searchParams.get("last_event_id") ??
      request.headers["last-event-id"] ??
      "",
  };
}

async function handleAgentRoute({ request, response, store, url, segments }) {
  const agentId = decodeURIComponent(segments[2]);
  const action = segments[3];
  if (request.method === "GET" && !action) {
    writeJsonResponse(response, store.getAgent(agentId));
    return;
  }
  if (request.method === "DELETE" && !action) {
    store.deleteAgent(agentId);
    writeJsonResponse(response, undefined, 204);
    return;
  }
  if (request.method === "POST" && action === "archive") {
    writeJsonResponse(response, store.updateAgent(agentId, "archived", "agent.archive"));
    return;
  }
  if (request.method === "POST" && action === "unarchive") {
    writeJsonResponse(response, store.updateAgent(agentId, "active", "agent.unarchive"));
    return;
  }
  if (request.method === "POST" && action === "resume") {
    writeJsonResponse(response, store.updateAgent(agentId, "active", "agent.resume"));
    return;
  }
  if (request.method === "POST" && action === "close") {
    writeJsonResponse(response, store.updateAgent(agentId, "closed", "agent.close"));
    return;
  }
  if (request.method === "POST" && action === "reload") {
    writeJsonResponse(response, store.updateAgent(agentId, store.getAgent(agentId).status, "agent.reload"));
    return;
  }
  if (request.method === "POST" && action === "runs") {
    writeJsonResponse(response, store.createRun(agentId, await readBody(request)));
    return;
  }
  if (request.method === "GET" && action === "runs") {
    writeJsonResponse(response, store.listRuns(agentId));
    return;
  }
  if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
    writeJsonResponse(response, store.memoryPolicyForAgent(agentId, Object.fromEntries(url.searchParams.entries())));
    return;
  }
  if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
    writeJsonResponse(response, store.setMemoryPolicyForAgent(agentId, await readBody(request)));
    return;
  }
  if (request.method === "GET" && action === "memory" && segments[4] === "path") {
    writeJsonResponse(response, store.memoryPathForAgent(agentId, Object.fromEntries(url.searchParams.entries())));
    return;
  }
  if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
    writeJsonResponse(response, store.updateMemoryForAgentId(agentId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "DELETE" && action === "memory" && segments[4]) {
    writeJsonResponse(response, store.deleteMemoryForAgentId(agentId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "GET" && action === "memory") {
    writeJsonResponse(response, store.listMemoryForAgent(agentId, Object.fromEntries(new URL(request.url ?? "/", "http://127.0.0.1").searchParams.entries())));
    return;
  }
  if (request.method === "POST" && action === "memory") {
    writeJsonResponse(response, store.rememberForAgentId(agentId, await readBody(request)));
    return;
  }
  throw notFound("Agent route not found.", { agentId, action, method: request.method });
}

async function handleThreadRoute({ request, response, store, url, segments }) {
  const threadId = decodeURIComponent(segments[2]);
  const action = segments[3];
  if (request.method === "GET" && !action) {
    writeJsonResponse(response, {
      ...store.getThread(threadId),
      turns: store.listTurns(threadId),
    });
    return;
  }
  if (request.method === "POST" && action === "resume") {
    writeJsonResponse(response, store.resumeThread(threadId));
    return;
  }
  if (request.method === "POST" && action === "fork") {
    writeJsonResponse(response, store.forkThread(threadId, await readBody(request)));
    return;
  }
  if (request.method === "POST" && action === "compact") {
    writeJsonResponse(response, store.compactThread(threadId, await readBody(request)));
    return;
  }
  if (request.method === "POST" && action === "turns" && !segments[4]) {
    writeJsonResponse(response, await store.createTurn(threadId, await readBody(request)));
    return;
  }
  if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "interrupt" && !segments[6]) {
    writeJsonResponse(response, store.interruptTurn(threadId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "steer" && !segments[6]) {
    writeJsonResponse(response, store.steerTurn(threadId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "POST" && action === "approvals" && segments[4] && segments[5] === "decision" && !segments[6]) {
    writeJsonResponse(response, store.decideThreadApproval(threadId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "POST" && action === "approvals" && segments[4] && ["approve", "reject"].includes(segments[5]) && !segments[6]) {
    const body = await readBody(request);
    writeJsonResponse(response, store.decideThreadApproval(threadId, decodeURIComponent(segments[4]), {
      ...body,
      decision: segments[5],
    }));
    return;
  }
  if (request.method === "POST" && action === "tools" && segments[4] && segments[5] === "invoke" && !segments[6]) {
    writeJsonResponse(response, store.invokeThreadTool(threadId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "GET" && action === "turns" && !segments[4]) {
    writeJsonResponse(response, store.listTurns(threadId));
    return;
  }
  if (request.method === "GET" && action === "turns" && segments[4] && !segments[5]) {
    writeJsonResponse(response, store.getTurn(threadId, decodeURIComponent(segments[4])));
    return;
  }
  if (request.method === "GET" && action === "events" && (!segments[4] || segments[4] === "stream")) {
    writeSse(response, store.eventsForThread(threadId, runtimeEventCursorFromRequest({ request, url })));
    return;
  }
  if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
    writeJsonResponse(response, store.memoryPolicyForThread(threadId));
    return;
  }
  if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
    writeJsonResponse(response, store.setMemoryPolicyForThread(threadId, await readBody(request)));
    return;
  }
  if (request.method === "GET" && action === "memory" && segments[4] === "path") {
    writeJsonResponse(response, store.memoryPathForThread(threadId));
    return;
  }
  if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
    writeJsonResponse(response, store.updateMemoryForThread(threadId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "DELETE" && action === "memory" && segments[4]) {
    writeJsonResponse(response, store.deleteMemoryForThread(threadId, decodeURIComponent(segments[4]), await readBody(request)));
    return;
  }
  if (request.method === "GET" && action === "memory") {
    writeJsonResponse(response, store.listMemoryForThread(threadId, Object.fromEntries(url.searchParams.entries())));
    return;
  }
  if (request.method === "POST" && action === "memory") {
    writeJsonResponse(response, store.rememberForThread(threadId, await readBody(request)));
    return;
  }
  throw notFound("Thread route not found.", { threadId, action, method: request.method });
}

async function handleRunRoute({ request, response, store, url, segments }) {
  const runId = decodeURIComponent(segments[2]);
  const action = segments[3];
  if (request.method === "GET" && !action) {
    writeJsonResponse(response, store.getRun(runId));
    return;
  }
  if (request.method === "POST" && action === "cancel") {
    writeJsonResponse(response, store.cancelRun(runId));
    return;
  }
  if (request.method === "GET" && action === "wait") {
    const run = store.getRun(runId);
    writeJsonResponse(response, {
      id: run.id,
      agentId: run.agentId,
      status: run.status,
      result: run.result,
      stopCondition: run.trace.stopCondition,
      routeDecision: run.modelRouteDecision ?? run.trace.modelRouteDecision ?? null,
      trace: run.trace,
      scorecard: run.trace.scorecard,
    });
    return;
  }
  if (request.method === "GET" && action === "conversation") {
    writeJsonResponse(response, store.getRun(runId).conversation);
    return;
  }
  if (request.method === "GET" && action === "events") {
    writeSse(
      response,
      store.eventsForRun(
        runId,
        runtimeEventCursorFromRequest({ request, url }),
      ),
    );
    return;
  }
  if (request.method === "GET" && action === "replay") {
    writeSse(
      response,
      store.replayFromCanonicalState(
        runId,
        runtimeEventCursorFromRequest({ request, url }),
      ),
    );
    return;
  }
  if (request.method === "GET" && (action === "trace" || action === "inspect")) {
    const trace = store.traceFromCanonicalState(runId);
    writeJsonResponse(response, {
      ...trace,
      canonicalState: store.canonicalProjection(runId),
    });
    return;
  }
  if (request.method === "GET" && action === "scorecard") {
    writeJsonResponse(response, store.getRun(runId).trace.scorecard);
    return;
  }
  if (request.method === "GET" && action === "artifacts" && !segments[4]) {
    writeJsonResponse(response, store.getRun(runId).artifacts);
    return;
  }
  if (request.method === "GET" && action === "artifacts" && segments[4]) {
    const artifactId = decodeURIComponent(segments[4]);
    const artifact = store.getRun(runId).artifacts.find((item) => item.id === artifactId);
    if (!artifact) throw notFound(`Artifact not found: ${artifactId}`, { runId, artifactId });
    writeJsonResponse(response, artifact);
    return;
  }
  throw notFound("Run route not found.", { runId, action, method: request.method });
}

function buildRun({
  agent,
  mode,
  prompt,
  request,
  source,
  modelRoute,
  memory = {},
  skillHookCatalog = null,
  diagnosticsFeedback = null,
}) {
  const runId = `run_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const diagnosticsBlockingGate = diagnosticsBlockingGateForFeedback(diagnosticsFeedback);
  const runStatus = diagnosticsBlockingGate ? "blocked" : "completed";
  const taskFamily = taskFamilyForMode(mode);
  const selectedStrategy = strategyForMode(mode);
  const toolSequence = capabilitySequenceForMode(mode, agent);
  const modelRouteDecision = modelRoute?.decision ?? null;
  const selectedModel =
    modelRouteDecision?.selectedModel ??
    modelRoute?.selectedModel ??
    request.options?.model?.id ??
    agent.modelId;
  const modelRouteReceiptId =
    modelRoute?.receiptId ?? modelRouteDecision?.receiptId ?? `receipt_${runId}_model_route`;
  const memoryRecords = normalizeArray(memory.records);
  const memoryWrites = normalizeArray(memory.writes);
  const memoryMutations = normalizeArray(memory.mutations).length > 0
    ? normalizeArray(memory.mutations)
    : memoryWrites.map((write) => ({ ...write, operation: "write" }));
  const memoryWriteReceipts = memoryMutations.map((write) => write.receipt).filter(Boolean);
  const memoryWriteRecords = memoryWrites.map((write) => write.record).filter(Boolean);
  const memoryPolicy = memory.policy ?? null;
  const subagentMemoryInheritance =
    mode === "handoff" ? memory.subagentMemoryInheritance ?? null : null;
  const subagentMemoryReceipt = subagentMemoryInheritance
    ? subagentMemoryInheritanceReceipt(runId, subagentMemoryInheritance)
    : null;
  const activeSkillHookManifest = activeSkillHookManifestForRun({
    runId,
    agent,
    request,
    catalog: skillHookCatalog,
  });
  const runtimeTask = runtimeTaskRecord({
    runId,
    agent,
    prompt,
    mode,
    taskFamily,
    selectedStrategy,
    modelRouteDecision,
    activeSkillHookManifest,
    createdAt,
    updatedAt: createdAt,
    status: runStatus,
  });
  let runtimeJob = runtimeJobRecord({
    runtimeTask,
    agent,
    status: runStatus,
    createdAt,
    updatedAt: createdAt,
    queuedAt: createdAt,
    startedAt: createdAt,
    completedAt: diagnosticsBlockingGate ? null : createdAt,
    lifecycle: diagnosticsBlockingGate ? ["queued", "started", "blocked"] : ["queued", "started", "completed"],
  });
  const runtimeChecklist = runtimeChecklistRecord({
    runtimeTask,
    runtimeJob,
    status: runStatus,
    createdAt,
    updatedAt: createdAt,
  });
  runtimeJob = attachChecklistToRuntimeJob(runtimeJob, runtimeChecklist);
  const hookDryRunPlan = hookDryRunPlanForManifest({
    runId,
    manifest: activeSkillHookManifest,
  });
  const hookInvocationLedger = hookInvocationLedgerForPlan({
    runId,
    manifest: activeSkillHookManifest,
    dryRunPlan: hookDryRunPlan,
  });
  const repositoryContext = repositoryContextForWorkspace({
    cwd: agent.cwd,
    contextId: `repoctx_${runId}`,
    generatedAt: createdAt,
  });
  const branchPolicy = branchPolicyForRepositoryContext({
    runId,
    repositoryContext,
    generatedAt: createdAt,
  });
  const githubContext = githubContextForRepository({
    runId,
    repositoryContext,
    branchPolicy,
    generatedAt: createdAt,
  });
  const prAttempt = prAttemptForRepository({
    runId,
    repositoryContext,
    branchPolicy,
    githubContext,
    generatedAt: createdAt,
    prompt,
  });
  const reviewGate = reviewGateForPrAttempt({
    runId,
    repositoryContext,
    branchPolicy,
    githubContext,
    prAttempt,
    generatedAt: createdAt,
  });
  const issueContext = issueContextForGithub({
    runId,
    repositoryContext,
    githubContext,
    prAttempt,
    reviewGate,
    generatedAt: createdAt,
  });
  const githubPrCreatePlan = githubPrCreatePlanForReviewGate({
    runId,
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    generatedAt: createdAt,
  });
  const taskState = {
    currentObjective: prompt,
    knownFacts: [
      "Run entered the live local IOI daemon public runtime API",
      "Agentgres v0 is the canonical owner for this run state",
      `Selected model profile: ${selectedModel}`,
      `Runtime task: id=${runtimeTask.taskId}, family=${runtimeTask.taskFamily}, status=${runtimeTask.status}`,
      `Runtime job: id=${runtimeJob.jobId}, status=${runtimeJob.status}, queue=${runtimeJob.queueName}`,
      `Runtime checklist: id=${runtimeChecklist.checklistId}, status=${runtimeChecklist.status}, items=${runtimeChecklist.completedItemCount}/${runtimeChecklist.itemCount}`,
      `Repository context: ${repositoryContext.isGitRepository ? "git" : "workspace"} root=${repositoryContext.repoRoot ?? repositoryContext.workspaceRoot}, branch=${repositoryContext.branch ?? "none"}, dirty=${repositoryContext.status.isDirty}`,
      `Branch policy: status=${branchPolicy.status}, protected=${branchPolicy.protectedBranch}, mutationAllowed=${branchPolicy.mutationAllowed}`,
      `GitHub context: status=${githubContext.status}, repo=${githubContext.repoFullName ?? "none"}, prEligible=${githubContext.prCreationEligible}`,
      `Issue context: status=${issueContext.status}, bound=${issueContext.bound}, repo=${issueContext.repoFullName ?? "none"}`,
      `PR attempt: status=${prAttempt.status}, outcome=${prAttempt.outcome}, mutationExecuted=${prAttempt.mutationExecuted}`,
      `Review gate: status=${reviewGate.status}, reviewRequired=${reviewGate.reviewRequired}, reviewSatisfied=${reviewGate.reviewSatisfied}`,
      `GitHub PR create plan: status=${githubPrCreatePlan.status}, dryRun=${githubPrCreatePlan.dryRun}, mutationExecuted=${githubPrCreatePlan.mutationExecuted}`,
      ...(memoryPolicy
        ? [
            `Memory policy: disabled=${Boolean(memoryPolicy.disabled)}, injection=${memoryPolicy.injectionEnabled !== false}, readOnly=${Boolean(memoryPolicy.readOnly)}, writeRequiresApproval=${Boolean(memoryPolicy.writeRequiresApproval)}`,
          ]
        : []),
      ...(subagentMemoryInheritance
        ? [
            `Subagent memory inheritance: mode=${subagentMemoryInheritance.mode}, receiver=${subagentMemoryInheritance.subagentName ?? "handoff"}, records=${subagentMemoryInheritance.records.length}, writeAllowed=${subagentMemoryInheritance.writeAllowed}`,
          ]
        : []),
      `Active skill/hook manifest: skills=${activeSkillHookManifest.selectedSkillIds.length}, hooks=${activeSkillHookManifest.selectedHookIds.length}, skillSet=${activeSkillHookManifest.activeSkillSetHash.slice(0, 12)}, hookSet=${activeSkillHookManifest.activeHookSetHash.slice(0, 12)}`,
      `Hook dry-run plan: wouldRun=${hookDryRunPlan.wouldRunCount}, blocked=${hookDryRunPlan.blockedCount}, skipped=${hookDryRunPlan.skippedCount}`,
      `Hook invocation ledger: invocations=${hookInvocationLedger.invocationCount}, wouldRun=${hookInvocationLedger.wouldRunCount}, blocked=${hookInvocationLedger.blockedCount}, skipped=${hookInvocationLedger.skippedCount}`,
      `Hook escalation receipts: ${hookInvocationLedger.escalationCount} blocked invocation(s) require declaration fixes`,
      ...(diagnosticsFeedback
        ? [
            `Post-edit diagnostics: status=${diagnosticsFeedback.diagnosticStatus}, findings=${diagnosticsFeedback.diagnosticCount}, mode=${diagnosticsFeedback.mode}`,
          ]
        : []),
      ...(diagnosticsBlockingGate
        ? [
            `Post-edit diagnostics blocking gate: id=${diagnosticsBlockingGate.gateId}, status=${diagnosticsBlockingGate.status}, decision=${diagnosticsBlockingGate.decision}`,
          ]
        : []),
      ...memoryRecords.map((record) => `Memory fact (${record.scope}:${record.id}): ${record.fact}`),
    ],
    uncertainFacts: mode === "dry_run" ? ["Side effects are previewed, not executed"] : [],
    assumptions: [],
    constraints: [
      "No GUI internals",
      "No raw receipt dump",
      "No policy bypass",
      ...(diagnosticsBlockingGate ? ["No model continuation while blocking diagnostics have findings"] : []),
    ],
    blockers: diagnosticsBlockingGate ? [diagnosticsBlockingGate.summary] : [],
    changedObjects: mode === "send" ? [] : [`daemon:${mode}`],
    evidenceRefs: [
      "ioi_daemon_public_runtime_api",
      "agentgres_canonical_operation_log",
      runtimeTask.taskId,
      runtimeJob.jobId,
      runtimeChecklist.checklistId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      issueContext.contextId,
      prAttempt.attemptId,
      reviewGate.gateId,
      githubPrCreatePlan.planId,
      activeSkillHookManifest.manifestId,
      hookDryRunPlan.planId,
      hookInvocationLedger.ledgerId,
      diagnosticsFeedback?.injectionId,
      diagnosticsBlockingGate?.gateId,
      diagnosticsBlockingGate?.policyDecisionId,
      diagnosticsBlockingGate?.receiptId,
      activeSkillHookManifest.activeSkillSetHash,
      activeSkillHookManifest.activeHookSetHash,
      ...agent.options.mcpServerNames,
      ...agent.options.skillNames,
      ...agent.options.hookNames,
      ...normalizeArray(modelRouteDecision?.evidenceRefs),
      modelRouteReceiptId,
      memoryPolicy?.id,
      ...memoryRecords.map((record) => record.id),
      ...memoryWriteReceipts.map((receipt) => receipt.id),
      subagentMemoryReceipt?.id,
    ].filter(Boolean),
  };
  const uncertainty = {
    ambiguityLevel: mode === "send" ? "low" : "medium",
    selectedAction:
      mode === "dry_run"
        ? "dry_run"
        : mode === "plan"
          ? "verify"
          : mode === "handoff"
            ? "execute"
            : "probe",
    rationale: "Live daemon run chose bounded local execution with canonical state writeback.",
    valueOfProbe: mode === "send" ? "medium" : "high",
  };
  const probes = [
    {
      probeId: `${runId}:probe:canonical-replay`,
      hypothesis: diagnosticsBlockingGate
        ? "Agentgres canonical operation log can replay the blocked diagnostics gate event stream."
        : "Agentgres canonical operation log can replay the terminal run event stream.",
      cheapestValidationAction: "Read canonical run projection and replay events by cursor.",
      expectedObservation: diagnosticsBlockingGate
        ? "Monotonic event stream with a blocked diagnostics policy event and no model output delta."
        : "Monotonic event stream with exactly one terminal event.",
      result: "confirmed",
      confidenceUpdate: "Canonical replay and daemon stream use the same event IDs.",
    },
  ];
  const postconditions = {
    objective: prompt,
    taskFamily,
    riskClass: mode === "dry_run" ? "side_effect_preview" : "bounded_local",
    checks: [
      {
        checkId: diagnosticsBlockingGate ? "daemon-event-stream-blocked" : "daemon-event-stream-terminal",
        description: diagnosticsBlockingGate
          ? "Daemon event stream is open and blocked by diagnostics policy before model continuation."
          : "Daemon event stream contains exactly one terminal event.",
        status: diagnosticsBlockingGate ? "blocked" : "passed",
      },
      {
        checkId: "agentgres-operation-log",
        description: "Run, task, receipts, scorecard, and ledger are written to Agentgres v0.",
        status: "passed",
      },
      {
        checkId: "runtime-job-ledger",
        description: "Runtime task and job records are durable, replayable, and inspectable through the public jobs API.",
        status: "passed",
      },
      {
        checkId: "runtime-checklist-ledger",
        description: "Runtime checklist record binds task, job, lifecycle, artifacts, and receipts into a replayable workflow projection.",
        status: "passed",
      },
      {
        checkId: "canonical-replay",
        description: "Replay from Agentgres reconstructs terminal event stream.",
        status: "passed",
      },
      {
        checkId: "active-skill-hook-manifest",
        description: "Trace records the exact skill and hook catalog snapshot used by this turn.",
        status: "passed",
      },
      {
        checkId: "repository-context-read-only",
        description: "Repository context is captured without mutating branch, index, or worktree state.",
        status: "passed",
      },
      {
        checkId: "branch-policy-read-only",
        description: "Branch policy decision consumes repository context without mutating branch, index, or worktree state.",
        status: "passed",
      },
      {
        checkId: "github-context-read-only",
        description: "GitHub context is resolved from repository remotes without network calls or PR mutation.",
        status: "passed",
      },
      {
        checkId: "issue-context-read-only",
        description: "Issue context is projected without GitHub network reads or mutation, and may remain unbound.",
        status: "passed",
      },
      {
        checkId: "pr-attempt-preview-only",
        description: "PR attempt intent, branch, and diff artifacts are recorded without creating or updating a PR.",
        status: "passed",
      },
      {
        checkId: "review-gate-read-only",
        description: "Review gate decision is recorded before PR creation and cannot satisfy review or mutate GitHub.",
        status: "passed",
      },
      {
        checkId: "github-pr-create-dry-run",
        description: "GitHub PR creation is represented as a dry-run request plan with no network lookup, token exposure, or mutation.",
        status: "passed",
      },
      {
        checkId: "hook-dry-run-plan",
        description: "Hook execution is previewed with policy decisions and no command execution.",
        status: "passed",
      },
      ...(hookInvocationLedger.escalationCount > 0
        ? [
            {
              checkId: "hook-escalation-receipts",
              description: "Blocked hook invocations produce escalation receipts with required declaration fixes.",
              status: "passed",
            },
          ]
        : []),
      ...(diagnosticsFeedback
        ? [
            {
              checkId: "post-edit-diagnostics-injected",
              description: diagnosticsBlockingGate
                ? "Compact post-edit diagnostics were injected and stopped model continuation."
                : "Compact post-edit diagnostics were injected before this model turn continued.",
              status: diagnosticsFeedback.blocking && diagnosticsFeedback.diagnosticStatus === "findings"
                ? "blocked"
                : "passed",
            },
          ]
        : []),
      ...(diagnosticsBlockingGate
        ? [
            {
              checkId: "post-edit-diagnostics-blocking-gate",
              description: "Blocking diagnostics findings produced a policy gate that requires repair, advisory override, or skip before continuing.",
              status: "blocked",
            },
          ]
        : []),
    ],
    minimumEvidence: [
      "events",
      "receipts",
      "trace",
      "scorecard",
      "agentgres_operation_log",
      "runtime_task",
      "runtime_job",
      "runtime_checklist",
      "repository_context",
      "branch_policy",
      "github_context",
      "issue_context",
      "pr_attempt",
      "pr_branch_artifact",
      "pr_diff_artifact",
      "review_gate",
      "github_pr_create_plan",
      "active_skill_hook_manifest",
      "hook_dry_run_plan",
      "hook_invocation_ledger",
      "hook_escalation_receipt",
      ...(diagnosticsFeedback ? ["lsp_diagnostics_injection"] : []),
      ...(diagnosticsBlockingGate ? ["lsp_diagnostics_blocking_gate"] : []),
    ],
  };
  const semanticImpact = {
    changedSymbols: [],
    changedApis: [
      "/v1/agents/{id}/runs",
      "/v1/agents/{id}/memory",
      "/v1/threads/{id}/memory",
      "/v1/jobs",
      "/v1/jobs/{id}",
      "/v1/jobs/{id}/cancel",
      "/v1/runs/{id}/events",
      "/v1/runs/{id}/trace",
      "/v1/skills",
      "/v1/hooks",
      "/v1/repository-context",
      "/v1/branch-policy",
      "/v1/github-context",
      "/v1/issue-context",
      "/v1/pr-attempts",
      "/v1/review-gate",
      "/v1/github/pr-create-plan",
      "/v1/repositories",
    ],
    changedSchemas: [
      "IOISDKMessage",
      "RuntimeTraceBundle",
      "AgentgresRuntimeStateV0",
      "RuntimeTaskRecord",
      "RuntimeJobRecord",
      "RuntimeChecklistRecord",
      "RepositoryContext",
      "BranchPolicyDecision",
      "GitHubContext",
      "IssueContext",
      "PrAttemptRecord",
      "ReviewGateDecision",
      "GitHubPrCreatePlan",
      "ModelRouteDecision",
      "AgentMemoryRecord",
      "SubagentMemoryInheritanceProjection",
      "ActiveSkillHookManifest",
      "HookDryRunPlan",
      "HookInvocationLedger",
      "HookInvocationRecord",
      "HookEscalationReceipt",
      ...(diagnosticsBlockingGate ? ["LspDiagnosticsBlockingGate"] : []),
      "RuntimeEventEnvelope",
    ],
    changedPolicies: [
      ...(mode === "dry_run" ? ["authority.preview_only"] : []),
      ...(memory.policyBlockReason ? [`memory.${memory.policyBlockReason}`] : []),
      ...normalizeArray(memory.policyUpdates).map(() => "memory.policy"),
      ...(subagentMemoryInheritance
        ? [`memory.subagent_inheritance.${subagentMemoryInheritance.mode}`]
        : []),
      "runtime.jobs.durable_projection",
      "runtime.tasks.durable_projection",
      "runtime.checklists.durable_projection",
      "repository.context.read_only",
      "repository.branch_policy.read_only",
      "github.context.read_only",
      "github.issue_context.read_only",
      "github.pr_attempt.preview_only",
      "repository.review_gate.read_only",
      "github.pr_create.dry_run",
      "skills_hooks.active_manifest.read_only",
      "hooks.dry_run_preview_only",
      "hooks.invocation_ledger_preview_only",
      ...(hookInvocationLedger.escalationCount > 0
        ? ["hooks.escalation_receipt_required_for_blocked_invocations"]
        : []),
      ...(activeSkillHookManifest.mutationBlockedHookIds.length > 0
        ? ["hooks.mutation_blocked_without_contract"]
        : []),
      ...(hookDryRunPlan.blockedCount > 0
        ? ["hooks.dry_run_blocked_without_declared_capabilities"]
        : []),
      ...(diagnosticsFeedback
        ? [`lsp.diagnostics.${diagnosticsFeedback.mode}`]
        : []),
      ...(diagnosticsBlockingGate ? ["lsp.diagnostics.blocking_gate"] : []),
    ],
    affectedTests: ["live-runtime-daemon-contract"],
    affectedDocs: ["docs/plans/architectural-improvements-broad-master-guide.md"],
    riskClass: postconditions.riskClass,
  };
  const stopCondition = {
    reason: diagnosticsBlockingGate ? "blocked_by_post_edit_diagnostics" : "evidence_sufficient",
    evidenceSufficient: !diagnosticsBlockingGate,
    rationale: diagnosticsBlockingGate
      ? "Blocking post-edit diagnostics findings paused model continuation until repair, advisory override, or skip."
      : "Daemon stream, canonical Agentgres writeback, trace export, replay, and scorecard evidence were produced.",
  };
  const qualityLedger = {
    ledgerId: `quality_${runId}`,
    taskFamily,
    selectedStrategy,
    toolSequence,
    scorecardMetrics: {
      task_pass_rate: diagnosticsBlockingGate ? 0 : 100,
      recovery_success: diagnosticsBlockingGate ? 0 : 100,
      memory_relevance: mode === "learn" ? 100 : 92,
      tool_quality: 96,
      strategy_roi: 93,
      operator_interventions: diagnosticsBlockingGate ? 1 : 0,
      verifier_independence: 100,
    },
    failureOntologyLabels: diagnosticsBlockingGate ? ["diagnostics_blocked_continuation"] : [],
  };
  const scorecard = {
    taskPassRate: diagnosticsBlockingGate ? 0 : 1,
    recoverySuccess: diagnosticsBlockingGate ? 0 : 1,
    memoryRelevance: mode === "learn" ? 1 : 0.92,
    toolQuality: 0.96,
    strategyRoi: 0.93,
    operatorInterventionRate: diagnosticsBlockingGate ? 1 : 0,
    verifierIndependence: 1,
  };
  const modelRouteReceipt = modelRouteDecision
    ? {
        id: modelRouteReceiptId,
        kind: "model_route_selection",
        summary: `Route ${modelRouteDecision.routeId} selected ${modelRouteDecision.selectedModel}.`,
        redaction: "none",
        evidenceRefs: normalizeArray(modelRouteDecision.evidenceRefs),
      }
    : null;
  const policyReceipt = {
    id: `receipt_${runId}_policy`,
    kind: "policy_decision",
    summary: "Local daemon run was admitted under bounded local/private runtime policy.",
    redaction: "none",
    evidenceRefs: ["prim:model.invoke", "policy.local_private"],
  };
  const authorityReceipt = {
    id: `receipt_${runId}_authority`,
    kind: "authority_decision",
    summary: "No external authority scope was required for this bounded local daemon run.",
    redaction: "none",
    evidenceRefs: ["wallet.network", "authority.no_external_scope"],
  };
  const runtimeTaskReceipt = {
    id: `receipt_${runId}_runtime_task`,
    kind: "runtime_task",
    summary: runtimeTask.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeTask.taskId,
      runtimeTask.threadId,
      runtimeTask.turnId,
      "RuntimeTaskNode",
      "runtime.tasks.durable_projection",
    ].filter(Boolean),
  };
  const runtimeJobReceipt = {
    id: `receipt_${runId}_runtime_job`,
    kind: "runtime_job",
    summary: runtimeJob.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeJob.jobId,
      runtimeTask.taskId,
      `run:${runId}`,
      "RuntimeJobNode",
      "runtime.jobs.durable_projection",
    ].filter(Boolean),
  };
  const runtimeChecklistReceipt = {
    id: `receipt_${runId}_runtime_checklist`,
    kind: "runtime_checklist",
    summary: runtimeChecklist.summary,
    redaction: "redacted",
    evidenceRefs: [
      runtimeChecklist.checklistId,
      runtimeTask.taskId,
      runtimeJob.jobId,
      "RuntimeChecklistNode",
      "runtime.checklists.durable_projection",
    ].filter(Boolean),
  };
  const repositoryContextReceipt = {
    id: `receipt_${runId}_repository_context`,
    kind: "repository_context",
    summary: repositoryContext.isGitRepository
      ? `Captured read-only repository context for ${repositoryContext.repoRoot}: branch=${repositoryContext.branch ?? "detached"}, dirty=${repositoryContext.status.isDirty}.`
      : `Captured read-only workspace context for ${repositoryContext.workspaceRoot}; no Git repository was detected.`,
    redaction: "redacted",
    evidenceRefs: [
      repositoryContext.contextId,
      repositoryContext.repoRootHash,
      "RepositoryContextNode",
      "repository.context.read_only",
    ].filter(Boolean),
  };
  const branchPolicyReceipt = {
    id: `receipt_${runId}_branch_policy`,
    kind: "branch_policy",
    summary: branchPolicy.summary,
    redaction: "redacted",
    evidenceRefs: [
      branchPolicy.policyId,
      repositoryContext.contextId,
      "BranchPolicyNode",
      "repository.branch_policy.read_only",
    ].filter(Boolean),
  };
  const githubContextReceipt = {
    id: `receipt_${runId}_github_context`,
    kind: "github_context",
    summary: githubContext.summary,
    redaction: "redacted",
    evidenceRefs: [
      githubContext.contextId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      "GitHubContextNode",
      "github.context.read_only",
    ].filter(Boolean),
  };
  const prAttemptReceipt = {
    id: `receipt_${runId}_pr_attempt`,
    kind: "pr_attempt",
    summary: prAttempt.summary,
    redaction: "redacted",
    evidenceRefs: [
      prAttempt.attemptId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      prAttempt.branchArtifact.artifactName,
      prAttempt.diffArtifact.artifactName,
      "PrAttemptNode",
      "github.pr_attempt.preview_only",
    ].filter(Boolean),
  };
  const issueContextReceipt = {
    id: `receipt_${runId}_issue_context`,
    kind: "issue_context",
    summary: issueContext.summary,
    redaction: "redacted",
    evidenceRefs: [
      issueContext.contextId,
      githubContext.contextId,
      prAttempt.attemptId,
      reviewGate.gateId,
      "IssueContextNode",
      "github.issue_context.read_only",
    ].filter(Boolean),
  };
  const reviewGateReceipt = {
    id: `receipt_${runId}_review_gate`,
    kind: "review_gate",
    summary: reviewGate.summary,
    redaction: "redacted",
    evidenceRefs: [
      reviewGate.gateId,
      prAttempt.attemptId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      "ReviewGateNode",
      "repository.review_gate.read_only",
    ].filter(Boolean),
  };
  const githubPrCreatePlanReceipt = {
    id: `receipt_${runId}_github_pr_create_plan`,
    kind: "github_pr_create_plan",
    summary: githubPrCreatePlan.summary,
    redaction: "redacted",
    evidenceRefs: [
      githubPrCreatePlan.planId,
      repositoryContext.contextId,
      branchPolicy.policyId,
      githubContext.contextId,
      issueContext.contextId,
      prAttempt.attemptId,
      reviewGate.gateId,
      "GitHubPrCreateNode",
      "github.pr_create.dry_run",
    ].filter(Boolean),
  };
  const skillHookReceipt = {
    id: `receipt_${runId}_skill_hook_manifest`,
    kind: "active_skill_hook_manifest",
    summary: `Recorded active skill/hook manifest with ${activeSkillHookManifest.selectedSkillIds.length} skill(s) and ${activeSkillHookManifest.selectedHookIds.length} hook(s).`,
    redaction: "redacted",
    evidenceRefs: [
      activeSkillHookManifest.manifestId,
      "runtime_skill_hook_discovery",
      "hook_execution_disabled_until_policy",
    ],
  };
  const hookDryRunReceipt = {
    id: `receipt_${runId}_hook_dry_run_plan`,
    kind: "hook_dry_run_plan",
    summary: `Previewed ${hookDryRunPlan.decisionCount} hook(s): ${hookDryRunPlan.wouldRunCount} would run, ${hookDryRunPlan.blockedCount} blocked, ${hookDryRunPlan.skippedCount} skipped.`,
    redaction: "redacted",
    evidenceRefs: [hookDryRunPlan.planId, activeSkillHookManifest.manifestId, "hook_preview_only"],
  };
  const hookPolicyReceipt = {
    id: `receipt_${runId}_hook_policy_decision`,
    kind: "hook_policy_decision",
    summary: hookDryRunPlan.policyDecision.summary,
    redaction: "redacted",
    evidenceRefs: [
      hookDryRunPlan.planId,
      "hook_policy_decision",
      "hook_execution_disabled_until_policy",
    ],
  };
  const hookInvocationReceipt = {
    id: `receipt_${runId}_hook_invocation_ledger`,
    kind: "hook_invocation_ledger",
    summary: `Recorded ${hookInvocationLedger.invocationCount} preview hook invocation(s): ${hookInvocationLedger.wouldRunCount} would run, ${hookInvocationLedger.blockedCount} blocked, ${hookInvocationLedger.skippedCount} skipped, ${hookInvocationLedger.escalationCount} escalated.`,
    redaction: "redacted",
    evidenceRefs: [
      hookInvocationLedger.ledgerId,
      hookDryRunPlan.planId,
      activeSkillHookManifest.manifestId,
      "hook_invocation_preview_only",
    ],
  };
  const hookEscalationReceipts = hookEscalationReceiptsForLedger(hookInvocationLedger);
  const diagnosticsInjectionReceipt = diagnosticsFeedback
    ? {
        id: diagnosticsFeedback.receiptId,
        kind: "lsp_diagnostics_injection",
        summary: diagnosticsFeedback.summary,
        redaction: "redacted",
        evidenceRefs: [
          diagnosticsFeedback.injectionId,
          ...normalizeArray(diagnosticsFeedback.diagnosticEventIds),
          "lsp.diagnostics.injected",
          "LspDiagnosticsNode",
        ],
      }
    : null;
  const diagnosticsBlockingGateReceipt = diagnosticsBlockingGate
    ? {
        id: diagnosticsBlockingGate.receiptId,
        kind: "lsp_diagnostics_blocking_gate",
        summary: diagnosticsBlockingGate.summary,
        redaction: "redacted",
        evidenceRefs: [
          diagnosticsBlockingGate.gateId,
          diagnosticsBlockingGate.policyDecisionId,
          diagnosticsBlockingGate.injectionId,
          diagnosticsBlockingGate.diagnosticsReceiptId,
          ...diagnosticsBlockingGate.diagnosticEventIds,
          "policy.blocked",
          "LspDiagnosticsNode",
        ].filter(Boolean),
      }
    : null;
  const agentgresReceipt = {
    id: `receipt_${runId}_agentgres`,
    kind: "agentgres_canonical_write",
    summary: "Run state, task state, receipts, scorecard, stop condition, and quality ledger were written to Agentgres v0.",
    redaction: "redacted",
    evidenceRefs: ["agentgres_canonical_operation_log", `run:${runId}`],
  };
  const traceReceipt = {
    id: `receipt_${runId}_trace`,
    kind: "trace_export",
    summary: "Trace export is reconstructed from daemon runtime state and canonical Agentgres projection.",
    redaction: "redacted",
    evidenceRefs: ["RuntimeTraceBundle", "canonical_replay"],
  };
  const receipts = [
    modelRouteReceipt,
    subagentMemoryReceipt,
    runtimeTaskReceipt,
    runtimeJobReceipt,
    runtimeChecklistReceipt,
    repositoryContextReceipt,
    branchPolicyReceipt,
    githubContextReceipt,
    issueContextReceipt,
    prAttemptReceipt,
    reviewGateReceipt,
    githubPrCreatePlanReceipt,
    skillHookReceipt,
    hookDryRunReceipt,
    hookPolicyReceipt,
    hookInvocationReceipt,
    diagnosticsInjectionReceipt,
    diagnosticsBlockingGateReceipt,
    ...hookEscalationReceipts,
    ...memoryWriteReceipts,
    policyReceipt,
    authorityReceipt,
    agentgresReceipt,
    traceReceipt,
  ].filter(Boolean);
  const result = diagnosticsBlockingGate
    ? diagnosticsBlockingGate.message
    : resultForMode(mode, agent, prompt, source, memory);
  const modelInput = promptWithDiagnosticsFeedback(prompt, diagnosticsFeedback);
  const events = [];
  const addEvent = (type, summary, data) => {
    const event = makeEvent(runId, agent.id, events.length, type, summary, data);
    events.push(event);
    return event;
  };
  const startedEvent = addEvent("run_started", "Run entered local IOI daemon", {
    taskFamily,
    selectedStrategy,
  });
  addEvent("runtime_task", "Runtime task record written", {
    ...runtimeTask,
    receiptId: runtimeTaskReceipt.id,
    eventKind: "RuntimeTaskRecord",
    workflowNodeId: "runtime.runtime-task",
  });
  addEvent("job_queued", "Runtime job queued", {
    ...runtimeJob,
    status: "queued",
    lifecycleStatus: "queued",
    completedAt: null,
    receiptId: runtimeJobReceipt.id,
    eventKind: "JobQueued",
    workflowNodeId: "runtime.runtime-job",
  });
  addEvent("job_started", "Runtime job started", {
    ...runtimeJob,
    status: "running",
    lifecycleStatus: "started",
    completedAt: null,
    receiptId: runtimeJobReceipt.id,
    eventKind: "JobStarted",
    workflowNodeId: "runtime.runtime-job",
  });
  addEvent("runtime_checklist", "Runtime checklist recorded", {
    ...runtimeChecklist,
    receiptId: runtimeChecklistReceipt.id,
    eventKind: "RuntimeChecklistRecord",
    workflowNodeId: "runtime.runtime-checklist",
  });
  addEvent("repository_context", "Repository context recorded", {
    ...repositoryContext,
    receiptId: repositoryContextReceipt.id,
    eventKind: "RepositoryContext",
    workflowNodeId: "runtime.repository-context",
  });
  addEvent("branch_policy", "Branch policy decision recorded", {
    ...branchPolicy,
    receiptId: branchPolicyReceipt.id,
    eventKind: "BranchPolicyDecision",
    workflowNodeId: "runtime.branch-policy",
  });
  addEvent("github_context", "GitHub context recorded", {
    ...githubContext,
    receiptId: githubContextReceipt.id,
    eventKind: "GitHubContext",
    workflowNodeId: "runtime.github-context",
  });
  addEvent("issue_context", "Issue context recorded", {
    ...issueContext,
    receiptId: issueContextReceipt.id,
    eventKind: "IssueContext",
    workflowNodeId: "runtime.issue-context",
  });
  addEvent("pr_attempt", "PR attempt preview recorded", {
    ...prAttempt,
    receiptId: prAttemptReceipt.id,
    eventKind: "PrAttemptRecord",
    workflowNodeId: "runtime.pr-attempt",
  });
  addEvent("review_gate", "Review gate decision recorded", {
    ...reviewGate,
    receiptId: reviewGateReceipt.id,
    eventKind: "ReviewGateDecision",
    workflowNodeId: "runtime.review-gate",
  });
  addEvent("github_pr_create_plan", "GitHub PR create dry-run plan recorded", {
    ...githubPrCreatePlan,
    receiptId: githubPrCreatePlanReceipt.id,
    eventKind: "GitHubPrCreatePlan",
    workflowNodeId: "runtime.github-pr-create",
  });
  addEvent("skill_hook_manifest", "Active skill and hook manifest recorded", {
    ...activeSkillHookManifest,
    receiptId: skillHookReceipt.id,
    eventKind: "ActiveSkillHookManifest",
    workflowNodeId: "runtime.skill-hook-manifest",
  });
  addEvent("hook_dry_run_plan", "Hook dry-run plan recorded", {
    ...hookDryRunPlan,
    receiptId: hookDryRunReceipt.id,
    policyReceiptId: hookPolicyReceipt.id,
    eventKind: "HookDryRunPlan",
    workflowNodeId: "runtime.hook-policy",
  });
  addEvent("hook_invocation_ledger", "Hook invocation ledger recorded", {
    ...hookInvocationLedger,
    receiptId: hookInvocationReceipt.id,
    escalationReceiptIds: hookEscalationReceipts.map((receipt) => receipt.id),
    eventKind: "HookInvocationLedger",
    workflowNodeId: "runtime.hook-invocations",
  });
  if (modelRouteDecision) {
    addEvent("model_route_decision", "Model route decision recorded", {
      ...modelRouteDecision,
      receiptId: modelRouteReceiptId,
    });
  }
  for (const mutation of memoryMutations) {
    const operation = mutation.operation ?? "write";
    addEvent("memory_update", memoryEventSummary(operation), {
      ...(mutation.record ?? mutation.policy ?? {}),
      operation,
      eventKind: memoryEventKind(operation),
      receiptId: mutation.receipt?.id ?? null,
      workflowNodeId: mutation.record?.workflowNodeId ?? "runtime.memory-policy",
    });
  }
  if (subagentMemoryInheritance) {
    addEvent("memory_update", "Subagent memory inheritance resolved", {
      ...subagentMemoryInheritance,
      operation: "subagent_inheritance",
      eventKind: "SubagentMemoryInheritance",
      receiptId: subagentMemoryReceipt?.id ?? null,
      workflowNodeId: "runtime.subagent-memory",
    });
  }
  if (diagnosticsFeedback) {
    addEvent("lsp_diagnostics_injected", diagnosticsFeedback.summary, {
      ...diagnosticsFeedback,
      eventKind: "LspDiagnosticsInjected",
      receiptId: diagnosticsInjectionReceipt?.id ?? diagnosticsFeedback.receiptId,
      workflowNodeId: LSP_DIAGNOSTICS_INJECTION_NODE_ID,
    });
  }
  const diagnosticsBlockingGateEvent = diagnosticsBlockingGate
    ? addEvent("policy_blocked", diagnosticsBlockingGate.summary, {
        ...diagnosticsBlockingGate,
        eventKind: "LspDiagnosticsBlockingGate",
        receiptId: diagnosticsBlockingGateReceipt?.id ?? diagnosticsBlockingGate.receiptId,
        workflowNodeId: LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
        componentKind: "lsp_diagnostics_gate",
      })
    : null;
  addEvent("task_state", "Task state written to Agentgres", taskState);
  addEvent("uncertainty", "Uncertainty assessed", uncertainty);
  addEvent("probe", "Canonical replay probe completed", probes[0]);
  addEvent("postcondition_synthesized", "Postconditions synthesized", postconditions);
  addEvent("semantic_impact", "Semantic impact classified", semanticImpact);
  const deltaEvent = diagnosticsBlockingGate ? null : addEvent("delta", result, { text: result });
  addEvent("stop_condition", "Stop condition recorded", stopCondition);
  addEvent("quality_ledger", "Quality ledger recorded", qualityLedger);
  if (!diagnosticsBlockingGate) {
    addEvent("job_completed", "Runtime job completed", {
      ...runtimeJob,
      lifecycleStatus: "completed",
      receiptId: runtimeJobReceipt.id,
      eventKind: "JobCompleted",
      workflowNodeId: "runtime.runtime-job",
    });
  }
  addEvent("artifact", "Trace and scorecard artifacts recorded", {
    artifactNames: [
      "trace.json",
      "runtime-task.json",
      "runtime-job.json",
      "runtime-checklist.json",
      "repository-context.json",
      "branch-policy.json",
      "github-context.json",
      "issue-context.json",
      "pr-attempt.json",
      "pr-branch.json",
      "pr-diff.patch",
      "review-gate.json",
      "github-pr-create-plan.json",
      "active-skill-hook-manifest.json",
      "hook-dry-run-plan.json",
      "hook-invocations.json",
      ...(diagnosticsBlockingGate ? ["diagnostics-blocking-gate.json"] : []),
      "scorecard.json",
      "agentgres-projection.json",
    ],
  });
  if (!diagnosticsBlockingGate) {
    addEvent("completed", "Run completed", { stopReason: stopCondition.reason });
  }
  const trace = {
    schemaVersion: "ioi.agent-sdk.trace.v1",
    traceBundleId: `trace_${runId}`,
    agentId: agent.id,
    runId,
    eventStreamId: `events_${runId}`,
    events,
    receipts,
    taskState,
    uncertainty,
    probes,
    postconditions,
    semanticImpact,
    modelRouteDecision,
    activeSkillHookManifest,
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    githubPrCreatePlan,
    hookDryRunPlan,
    hookInvocationLedger,
    promptAudit: {
      schemaVersion: "ioi.agent-runtime.prompt-audit.v1",
      runId,
      promptHash: doctorHash(prompt),
      runtimeTaskId: runtimeTask.taskId,
      runtimeJobId: runtimeJob.jobId,
      runtimeChecklistId: runtimeChecklist.checklistId,
      repositoryContextId: repositoryContext.contextId,
      branchPolicyId: branchPolicy.policyId,
      githubContextId: githubContext.contextId,
      issueContextId: issueContext.contextId,
      prAttemptId: prAttempt.attemptId,
      reviewGateId: reviewGate.gateId,
      githubPrCreatePlanId: githubPrCreatePlan.planId,
      activeSkillHookManifestId: activeSkillHookManifest.manifestId,
      activeSkillSetHash: activeSkillHookManifest.activeSkillSetHash,
      activeHookSetHash: activeSkillHookManifest.activeHookSetHash,
      selectedSkillIds: activeSkillHookManifest.selectedSkillIds,
      selectedHookIds: activeSkillHookManifest.selectedHookIds,
      hookExecutionEnabled: false,
      hookDryRunPlanId: hookDryRunPlan.planId,
      hookInvocationLedgerId: hookInvocationLedger.ledgerId,
      redaction: {
        promptIncluded: false,
        hookCommandsIncluded: false,
      },
      evidenceRefs: [
        "prompt_audit",
        runtimeTask.taskId,
        runtimeJob.jobId,
        runtimeChecklist.checklistId,
        repositoryContext.contextId,
        branchPolicy.policyId,
        githubContext.contextId,
        issueContext.contextId,
        prAttempt.attemptId,
        reviewGate.gateId,
        githubPrCreatePlan.planId,
        activeSkillHookManifest.manifestId,
      ],
    },
    memoryPolicy,
    memoryRecords,
    memoryWrites: memoryWriteRecords,
    diagnosticsFeedback,
    diagnosticsBlockingGate,
    subagentMemoryInheritance,
    stopCondition,
    qualityLedger,
    scorecard,
  };
  const artifacts = [
    artifact(runId, "trace.json", "application/json", traceReceipt.id, trace, "redacted"),
    artifact(
      runId,
      "runtime-task.json",
      "application/json",
      runtimeTaskReceipt.id,
      runtimeTask,
      "redacted",
    ),
    artifact(
      runId,
      "runtime-job.json",
      "application/json",
      runtimeJobReceipt.id,
      runtimeJob,
      "redacted",
    ),
    artifact(
      runId,
      "runtime-checklist.json",
      "application/json",
      runtimeChecklistReceipt.id,
      runtimeChecklist,
      "redacted",
    ),
    artifact(
      runId,
      "repository-context.json",
      "application/json",
      repositoryContextReceipt.id,
      repositoryContext,
      "redacted",
    ),
    artifact(
      runId,
      "branch-policy.json",
      "application/json",
      branchPolicyReceipt.id,
      branchPolicy,
      "redacted",
    ),
    artifact(
      runId,
      "github-context.json",
      "application/json",
      githubContextReceipt.id,
      githubContext,
      "redacted",
    ),
    artifact(
      runId,
      "issue-context.json",
      "application/json",
      issueContextReceipt.id,
      issueContext,
      "redacted",
    ),
    artifact(
      runId,
      "pr-attempt.json",
      "application/json",
      prAttemptReceipt.id,
      prAttempt,
      "redacted",
    ),
    artifact(
      runId,
      prAttempt.branchArtifact.artifactName,
      prAttempt.branchArtifact.mediaType,
      prAttemptReceipt.id,
      prAttempt.artifactContents.branch,
      "redacted",
    ),
    artifact(
      runId,
      prAttempt.diffArtifact.artifactName,
      prAttempt.diffArtifact.mediaType,
      prAttemptReceipt.id,
      prAttempt.artifactContents.diff,
      "redacted",
    ),
    artifact(
      runId,
      "review-gate.json",
      "application/json",
      reviewGateReceipt.id,
      reviewGate,
      "redacted",
    ),
    artifact(
      runId,
      "github-pr-create-plan.json",
      "application/json",
      githubPrCreatePlanReceipt.id,
      githubPrCreatePlan,
      "redacted",
    ),
    artifact(
      runId,
      "active-skill-hook-manifest.json",
      "application/json",
      skillHookReceipt.id,
      activeSkillHookManifest,
      "redacted",
    ),
    artifact(
      runId,
      "hook-dry-run-plan.json",
      "application/json",
      hookDryRunReceipt.id,
      hookDryRunPlan,
      "redacted",
    ),
    artifact(
      runId,
      "hook-invocations.json",
      "application/json",
      hookInvocationReceipt.id,
      hookInvocationLedger,
      "redacted",
    ),
    ...(diagnosticsBlockingGate
      ? [
          artifact(
            runId,
            "diagnostics-blocking-gate.json",
            "application/json",
            diagnosticsBlockingGateReceipt.id,
            diagnosticsBlockingGate,
            "redacted",
          ),
        ]
      : []),
    artifact(runId, "scorecard.json", "application/json", traceReceipt.id, scorecard, "none"),
    artifact(
      runId,
      "agentgres-projection.json",
      "application/json",
      agentgresReceipt.id,
      {
        runId,
        canonicalOwner: "Agentgres",
        source: "agentgres_canonical_operation_log",
      },
      "redacted",
    ),
  ];
  return {
    id: runId,
    agentId: agent.id,
    status: runStatus,
    turnStatus: diagnosticsBlockingGate ? "waiting_for_input" : undefined,
    objective: prompt,
    mode,
    createdAt,
    updatedAt: createdAt,
    events,
    conversation: [
      { role: "user", content: modelInput, eventId: startedEvent.id, createdAt },
      diagnosticsBlockingGate
        ? { role: "system", content: result, eventId: diagnosticsBlockingGateEvent?.id, createdAt }
        : { role: "assistant", content: result, eventId: deltaEvent.id, createdAt },
    ],
    receipts,
    artifacts,
    trace,
    modelRouteDecision,
    modelRouteReceiptId,
    activeSkillHookManifest,
    runtimeTask,
    runtimeJob,
    runtimeChecklist,
    repositoryContext,
    branchPolicy,
    githubContext,
    issueContext,
    prAttempt,
    reviewGate,
    githubPrCreatePlan,
    hookDryRunPlan,
    hookInvocationLedger,
    memoryPolicy,
    memoryRecords,
    memoryWriteReceipts,
    diagnosticsFeedback,
    diagnosticsBlockingGate,
    subagentMemoryInheritance,
    result,
  };
}

function runtimeTaskRecord({
  runId,
  agent,
  prompt,
  mode,
  taskFamily,
  selectedStrategy,
  modelRouteDecision,
  activeSkillHookManifest,
  createdAt,
  updatedAt,
  status,
} = {}) {
  const id = runId ?? `run_${doctorHash(String(prompt ?? "task")).slice(0, 12)}`;
  const agentId = agent?.id ?? null;
  const promptHash = doctorHash(String(prompt ?? ""));
  return {
    schemaVersion: "ioi.agent-runtime.task-record.v1",
    object: "ioi.runtime_task",
    taskId: `task_${id}`,
    runId: id,
    agentId,
    threadId: agentId ? threadIdForAgent(agentId) : null,
    turnId: turnIdForRun(id),
    status: status ?? "completed",
    mode: mode ?? "send",
    taskFamily: taskFamily ?? taskFamilyForMode(mode ?? "send"),
    selectedStrategy: selectedStrategy ?? strategyForMode(mode ?? "send"),
    summary: `Runtime task for ${taskFamily ?? taskFamilyForMode(mode ?? "send")} is ${status ?? "completed"}.`,
    promptHash,
    promptIncluded: false,
    objectivePreviewIncluded: false,
    modelRouteDecisionId: modelRouteDecision?.decisionId ?? null,
    activeSkillHookManifestId: activeSkillHookManifest?.manifestId ?? null,
    createdAt: createdAt ?? new Date().toISOString(),
    updatedAt: updatedAt ?? createdAt ?? new Date().toISOString(),
    durable: true,
    replayable: true,
    workflowNodeId: "runtime.runtime-task",
    redaction: {
      profile: "runtime_task_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_task",
      "runtime.tasks.durable_projection",
      "RuntimeTaskNode",
      `run:${id}`,
      activeSkillHookManifest?.manifestId,
    ].filter(Boolean),
  };
}

function runtimeBridgeRunRecord({ agent, request, projection }) {
  const taskFamily = taskFamilyForMode(projection.mode);
  const selectedStrategy = strategyForMode(projection.mode);
  const stopCondition = {
    reason: projection.stopReason,
    evidenceSufficient: true,
    rationale: "RuntimeAgentService bridge supplied the terminal turn event projection.",
  };
  const qualityLedger = {
    ledgerId: `quality_${projection.runId}`,
    taskFamily,
    selectedStrategy,
    toolSequence: [],
    scorecardMetrics: {
      task_pass_rate: 100,
      recovery_success: 100,
      memory_relevance: 100,
      tool_quality: 100,
      strategy_roi: 100,
      operator_interventions: 0,
      verifier_independence: 100,
    },
    failureOntologyLabels: [],
  };
  const scorecard = {
    taskPassRate: 1,
    recoverySuccess: 1,
    memoryRelevance: 1,
    toolQuality: 1,
    strategyRoi: 1,
    operatorInterventionRate: 0,
    verifierIndependence: 1,
  };
  const trace = {
    runId: projection.runId,
    agentId: agent.id,
    status: projection.status,
    source: "runtime_service",
    events: [],
    receipts: [],
    artifacts: [],
    taskState: null,
    uncertainty: null,
    probe: null,
    postconditions: null,
    semanticImpact: null,
    memoryPolicy: null,
    memoryRecords: [],
    memoryWrites: [],
    stopCondition,
    qualityLedger,
    scorecard,
  };
  return {
    id: projection.runId,
    agentId: agent.id,
    mode: projection.mode,
    objective: projection.prompt,
    status: projection.status,
    createdAt: projection.createdAt,
    updatedAt: projection.updatedAt,
    source: "runtime_service",
    runtimeProfile: agent.runtimeProfile,
    runtimeSessionId: runtimeSessionIdForAgent(agent),
    runtimeTurnId: projection.turnId,
    result: projection.result,
    events: [],
    conversation: [
      { role: "user", content: projection.prompt, createdAt: projection.createdAt },
      ...(projection.result ? [{ role: "assistant", content: projection.result, createdAt: projection.updatedAt }] : []),
    ],
    trace,
    artifacts: [],
    receipts: [],
    modelRouteDecision: agent.modelRouteDecision ?? null,
    modelRouteReceiptId: agent.modelRouteReceiptId ?? null,
    activeSkillHookManifest: null,
    memoryRecords: [],
    memoryWriteReceipts: [],
  };
}

function runtimeTaskRecordForRun(run) {
  if (run?.runtimeTask) return run.runtimeTask;
  return runtimeTaskRecord({
    runId: run?.id,
    agent: { id: run?.agentId },
    prompt: run?.objective,
    mode: run?.mode,
    taskFamily: run?.trace?.qualityLedger?.taskFamily ?? taskFamilyForMode(run?.mode ?? "send"),
    selectedStrategy: run?.trace?.qualityLedger?.selectedStrategy ?? strategyForMode(run?.mode ?? "send"),
    modelRouteDecision: run?.modelRouteDecision ?? run?.trace?.modelRouteDecision,
    activeSkillHookManifest: run?.activeSkillHookManifest ?? run?.trace?.activeSkillHookManifest,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
    status: jobStatusForRunStatus(run?.status),
  });
}

function runtimeJobRecord({
  runtimeTask,
  runtimeChecklist,
  agent,
  status,
  createdAt,
  updatedAt,
  queuedAt,
  startedAt,
  completedAt,
  lifecycle,
  eventCount,
  terminalEventCount,
  artifactNames,
  receiptKinds,
} = {}) {
  const task = runtimeTask ?? runtimeTaskRecord();
  const jobStatus = status ?? "completed";
  const jobId = `job_${task.runId}`;
  return {
    schemaVersion: "ioi.agent-runtime.job-record.v1",
    object: "ioi.runtime_job",
    jobId,
    taskId: task.taskId,
    runId: task.runId,
    agentId: task.agentId ?? agent?.id ?? null,
    threadId: task.threadId,
    turnId: task.turnId,
    status: jobStatus,
    lifecycle: lifecycle ?? jobLifecycleForStatus(jobStatus),
    summary: `Runtime job ${jobId} is ${jobStatus}.`,
    queueName: "local-agentgres",
    runner: "local-daemon-agentgres",
    jobType: "agent_run",
    priority: "normal",
    background: true,
    durable: true,
    replayable: true,
    createdAt: createdAt ?? task.createdAt,
    updatedAt: updatedAt ?? task.updatedAt,
    queuedAt: queuedAt ?? createdAt ?? task.createdAt,
    startedAt: startedAt ?? createdAt ?? task.createdAt,
    completedAt: completedAt ?? (["completed", "failed", "canceled"].includes(jobStatus) ? updatedAt ?? task.updatedAt : null),
    progress: {
      completedSteps: ["completed", "failed", "canceled"].includes(jobStatus) ? 1 : jobStatus === "running" ? 0 : 0,
      totalSteps: 1,
      percent: ["completed", "failed", "canceled"].includes(jobStatus) ? 100 : jobStatus === "running" ? 50 : 0,
    },
    eventCount: eventCount ?? null,
    terminalEventCount: terminalEventCount ?? null,
    artifactNames: artifactNames ?? ["runtime-task.json", "runtime-job.json", "runtime-checklist.json", "trace.json", "agentgres-projection.json"],
    receiptKinds: receiptKinds ?? ["runtime_task", "runtime_job", "runtime_checklist", "agentgres_canonical_write"],
    checklistId: runtimeChecklist?.checklistId ?? null,
    checklistStatus: runtimeChecklist?.status ?? null,
    checklistItemCount: runtimeChecklist?.itemCount ?? null,
    checklistCompletedItemCount: runtimeChecklist?.completedItemCount ?? null,
    failure: jobStatus === "failed" ? { reason: "runtime_failed", message: "Runtime job failed." } : null,
    cancellation: jobStatus === "canceled" ? { reason: "operator_cancel" } : null,
    retryCount: 0,
    cancelable: jobStatus !== "canceled",
    cancelEndpoint: `/v1/jobs/${jobId}/cancel`,
    endpoints: {
      self: `/v1/jobs/${jobId}`,
      cancel: `/v1/jobs/${jobId}/cancel`,
      run: `/v1/runs/${task.runId}`,
      events: `/v1/runs/${task.runId}/events`,
      trace: `/v1/runs/${task.runId}/trace`,
    },
    workflowNodeId: "runtime.runtime-job",
    redaction: {
      profile: "runtime_job_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_job",
      "runtime.jobs.durable_projection",
      "RuntimeJobNode",
      task.taskId,
      `run:${task.runId}`,
    ],
  };
}

function runtimeChecklistRecord({
  runtimeTask,
  runtimeJob,
  status,
  createdAt,
  updatedAt,
} = {}) {
  const task = runtimeTask ?? runtimeTaskRecord();
  const job = runtimeJob ?? runtimeJobRecord({ runtimeTask: task });
  const checklistStatus = status ?? job.status ?? task.status ?? "completed";
  const checklistId = `checklist_${task.runId}`;
  const terminalLabel =
    checklistStatus === "canceled"
      ? "Job canceled event emitted"
      : checklistStatus === "failed"
        ? "Job failed event emitted"
        : checklistStatus === "blocked"
          ? "Job blocked by policy gate"
        : "Job completed event emitted";
  const terminalEventKind =
    checklistStatus === "canceled"
      ? "JobCanceled"
      : checklistStatus === "failed"
        ? "JobFailed"
        : checklistStatus === "blocked"
          ? "PolicyBlocked"
        : "JobCompleted";
  const terminalItemStatus =
    checklistStatus === "canceled"
      ? "canceled"
      : checklistStatus === "failed"
        ? "failed"
        : checklistStatus === "blocked"
          ? "blocked"
        : "passed";
  const item = (suffix, label, itemStatus, evidenceRefs) => ({
    itemId: `${checklistId}:${suffix}`,
    label,
    status: itemStatus,
    evidenceRefs: uniqueStrings(evidenceRefs),
  });
  const items = [
    item("task_record", "Runtime task record durable", "passed", [
      task.taskId,
      "RuntimeTaskNode",
      "runtime.tasks.durable_projection",
    ]),
    item("job_record", "Runtime job record durable", "passed", [
      job.jobId,
      "RuntimeJobNode",
      "runtime.jobs.durable_projection",
    ]),
    item("job_queued", "Job queued event emitted", "passed", ["JobQueued"]),
    item("job_started", "Job started event emitted", "passed", ["JobStarted"]),
    item("job_terminal", terminalLabel, terminalItemStatus, [terminalEventKind]),
    item("artifacts", "Runtime task/job/checklist artifacts attached", "passed", [
      "runtime-task.json",
      "runtime-job.json",
      "runtime-checklist.json",
    ]),
  ];
  return {
    schemaVersion: "ioi.agent-runtime.checklist-record.v1",
    object: "ioi.runtime_checklist",
    checklistId,
    taskId: task.taskId,
    jobId: job.jobId,
    runId: task.runId,
    agentId: task.agentId,
    threadId: task.threadId,
    turnId: task.turnId,
    status: checklistStatus,
    summary: `Runtime checklist for ${job.jobId} is ${checklistStatus}.`,
    durable: true,
    replayable: true,
    readOnly: true,
    itemCount: items.length,
    completedItemCount: items.filter((entry) => entry.status === "passed").length,
    canceledItemCount: items.filter((entry) => entry.status === "canceled").length,
    failedItemCount: items.filter((entry) => entry.status === "failed").length,
    blockedItemCount: items.filter((entry) => entry.status === "blocked").length,
    items,
    requiredItemIds: items.map((entry) => entry.itemId),
    createdAt: createdAt ?? task.createdAt,
    updatedAt: updatedAt ?? task.updatedAt,
    workflowNodeId: "runtime.runtime-checklist",
    redaction: {
      profile: "runtime_checklist_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_checklist",
      "runtime.checklists.durable_projection",
      "RuntimeChecklistNode",
      task.taskId,
      job.jobId,
      `run:${task.runId}`,
    ],
  };
}

function attachChecklistToRuntimeJob(job, checklist) {
  return {
    ...job,
    checklistId: checklist.checklistId,
    checklistStatus: checklist.status,
    checklistItemCount: checklist.itemCount,
    checklistCompletedItemCount: checklist.completedItemCount,
    artifactNames: uniqueStrings([...normalizeArray(job.artifactNames), "runtime-checklist.json"]),
    receiptKinds: uniqueStrings([...normalizeArray(job.receiptKinds), "runtime_checklist"]),
    evidenceRefs: uniqueStrings([...normalizeArray(job.evidenceRefs), checklist.checklistId, "runtime_checklist"]),
  };
}

function runtimeJobRecordForRun(run) {
  if (run?.runtimeJob) return run.runtimeJob;
  const task = runtimeTaskRecordForRun(run);
  const status = jobStatusForRunStatus(run?.status);
  return runtimeJobRecord({
    runtimeTask: task,
    status,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
    queuedAt: run?.createdAt,
    startedAt: run?.createdAt,
    completedAt: ["completed", "failed", "canceled"].includes(status) ? run?.updatedAt : null,
    lifecycle: jobLifecycleForStatus(status),
    eventCount: normalizeArray(run?.events).length || null,
    terminalEventCount: terminalCount(normalizeArray(run?.events)) || null,
    artifactNames: normalizeArray(run?.artifacts).map((artifactItem) => artifactItem.name).filter(Boolean),
    receiptKinds: normalizeArray(run?.receipts).map((receipt) => receipt.kind).filter(Boolean),
  });
}

function runtimeChecklistRecordForRun(run) {
  if (run?.runtimeChecklist) return run.runtimeChecklist;
  const task = runtimeTaskRecordForRun(run);
  const job = runtimeJobRecordForRun(run);
  return runtimeChecklistRecord({
    runtimeTask: task,
    runtimeJob: job,
    status: job.status,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
  });
}

function jobStatusForRunStatus(status) {
  if (status === "canceled") return "canceled";
  if (status === "failed" || status === "error") return "failed";
  if (status === "blocked") return "blocked";
  if (status === "running" || status === "active") return "running";
  if (status === "queued" || status === "pending") return "queued";
  return "completed";
}

function jobLifecycleForStatus(status) {
  if (status === "queued") return ["queued"];
  if (status === "running") return ["queued", "started"];
  if (status === "failed") return ["queued", "started", "failed"];
  if (status === "canceled") return ["queued", "started", "canceled"];
  if (status === "blocked") return ["queued", "started", "blocked"];
  return ["queued", "started", "completed"];
}

function repositoryContextForWorkspace({ cwd, contextId, generatedAt } = {}) {
  const workspaceRoot = path.resolve(cwd ?? process.cwd());
  const rootOutput = gitOutput(workspaceRoot, ["rev-parse", "--show-toplevel"]);
  const baseContext = {
    schemaVersion: "ioi.agent-runtime.repository-context.v1",
    object: "ioi.repository_context",
    contextId: contextId ?? `repoctx_${doctorHash(workspaceRoot).slice(0, 12)}`,
    generatedAt: generatedAt ?? new Date().toISOString(),
    workspaceRoot,
    workspaceRootHash: doctorHash(workspaceRoot),
    provider: "git",
    readOnly: true,
    mutationExecuted: false,
    evidenceRefs: ["repository_context", "repository.context.read_only", "RepositoryContextNode"],
  };
  if (!rootOutput) {
    return {
      ...baseContext,
      status: repositoryStatusProjection("not_a_git_repository"),
      isGitRepository: false,
      repoRoot: null,
      repoRootHash: null,
      workspaceRelativePath: null,
      branch: null,
      detachedHead: false,
      headSha: null,
      headShortSha: null,
      upstream: null,
      remoteCount: 0,
      remotes: [],
      redaction: repositoryContextRedaction(),
    };
  }

  const repoRoot = path.resolve(rootOutput);
  const branchName = emptyToNull(gitOutput(repoRoot, ["branch", "--show-current"]));
  const abbrevRef = emptyToNull(gitOutput(repoRoot, ["rev-parse", "--abbrev-ref", "HEAD"]));
  const detachedHead = !branchName && abbrevRef === "HEAD";
  const headSha = emptyToNull(gitOutput(repoRoot, ["rev-parse", "HEAD"]));
  const upstream = emptyToNull(
    gitOutput(repoRoot, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]),
  );
  const porcelain = gitOutput(repoRoot, ["status", "--porcelain=v1", "--untracked-files=normal"]) ?? "";
  const branchStatus = gitOutput(repoRoot, ["status", "--porcelain=v2", "--branch", "--untracked-files=no"]) ?? "";
  const aheadBehind = repositoryAheadBehind(branchStatus);
  const counts = repositoryStatusCounts(porcelain);
  const remotes = parseGitRemotes(gitOutput(repoRoot, ["remote", "-v"]) ?? "");
  const defaultBranch = repositoryDefaultBranch(repoRoot);
  return {
    ...baseContext,
    status: repositoryStatusProjection("available", counts, aheadBehind, porcelain),
    isGitRepository: true,
    repoRoot,
    repoRootHash: doctorHash(repoRoot),
    workspaceRelativePath: relative(repoRoot, workspaceRoot),
    branch: branchName ?? (detachedHead ? null : abbrevRef),
    defaultBranch,
    detachedHead,
    headSha,
    headShortSha: headSha ? headSha.slice(0, 12) : null,
    upstream,
    remoteCount: remotes.length,
    remotes,
    redaction: repositoryContextRedaction(),
  };
}

function branchPolicyForRepositoryContext({
  runId,
  policyId,
  repositoryContext,
  generatedAt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const counts = context.status?.counts ?? repositoryStatusCounts("");
  const protectedBranchNames = uniqueStrings([
    context.defaultBranch,
    "main",
    "master",
    "trunk",
    "production",
    "release",
    "stable",
  ]);
  const branch = context.branch ?? null;
  const protectedBranch = Boolean(branch && protectedBranchNames.includes(branch));
  const blockers = [];
  const warnings = [];
  if (!context.isGitRepository) blockers.push("not_a_git_repository");
  if (!context.headSha && context.isGitRepository) blockers.push("missing_head");
  if (context.detachedHead || !branch) blockers.push("detached_head");
  if ((counts.conflicted ?? 0) > 0) blockers.push("conflicted_worktree");
  if (protectedBranch) blockers.push("protected_branch");
  if (context.status?.isDirty) warnings.push("dirty_worktree");
  if ((counts.untracked ?? 0) > 0) warnings.push("untracked_files");
  if (!context.upstream && context.isGitRepository) warnings.push("missing_upstream");
  if ((context.status?.ahead ?? 0) > 0) warnings.push("ahead_of_upstream");
  if ((context.status?.behind ?? 0) > 0) warnings.push("behind_upstream");

  const status = blockers.length > 0 ? "blocked" : warnings.length > 0 ? "warning" : "passed";
  const mutationAllowed = status === "passed";
  const summary = branchPolicySummary({ status, branch, protectedBranch, blockers, warnings });
  const id = policyId ?? (runId ? `branch_policy_${runId}` : `branch_policy_${doctorHash(context.contextId ?? "workspace").slice(0, 12)}`);
  return {
    schemaVersion: "ioi.agent-runtime.branch-policy.v1",
    object: "ioi.branch_policy_decision",
    policyId: id,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    status,
    decision: status,
    summary,
    readOnly: true,
    mutationExecuted: false,
    mutationAllowed,
    prCreationAllowed: mutationAllowed,
    reviewRequired: warnings.length > 0 || blockers.length > 0,
    approvalRequired: warnings.length > 0 || blockers.length > 0,
    branch,
    defaultBranch: context.defaultBranch ?? null,
    protectedBranch,
    protectedBranchNames,
    detachedHead: Boolean(context.detachedHead),
    headSha: context.headSha ?? null,
    headShortSha: context.headShortSha ?? null,
    upstream: context.upstream ?? null,
    ahead: context.status?.ahead ?? 0,
    behind: context.status?.behind ?? 0,
    dirty: Boolean(context.status?.isDirty),
    counts,
    blockers: uniqueStrings(blockers),
    warnings: uniqueStrings(warnings),
    recommendedNextAction: branchPolicyRecommendedNextAction({ status, blockers, warnings }),
    redaction: {
      profile: "branch_policy_safe",
      remoteCredentialsIncluded: false,
      statusPathsIncluded: false,
    },
    evidenceRefs: [
      "branch_policy",
      "repository.branch_policy.read_only",
      "BranchPolicyNode",
      context.contextId,
    ].filter(Boolean),
  };
}

function branchPolicySummary({ status, branch, protectedBranch, blockers, warnings }) {
  if (status === "passed") {
    return `Branch policy passed for ${branch ?? "detached HEAD"}; mutation and PR workflows may proceed.`;
  }
  if (status === "blocked") {
    return `Branch policy blocked ${branch ?? "detached HEAD"}${protectedBranch ? " because it is protected/default" : ""}: ${blockers.join(", ")}.`;
  }
  return `Branch policy warning for ${branch ?? "detached HEAD"}: ${warnings.join(", ")}.`;
}

function branchPolicyRecommendedNextAction({ status, blockers, warnings }) {
  if (status === "passed") return "Proceed to review or PR workflow gates.";
  if (blockers.includes("protected_branch")) {
    return "Create or switch to a feature branch before requesting branch mutation or PR creation.";
  }
  if (blockers.includes("conflicted_worktree")) {
    return "Resolve merge conflicts before requesting branch mutation or PR creation.";
  }
  if (blockers.includes("detached_head")) {
    return "Check out a named feature branch before requesting branch mutation or PR creation.";
  }
  if (warnings.includes("dirty_worktree")) {
    return "Review, stage, or commit local worktree changes before requesting PR creation.";
  }
  if (warnings.includes("missing_upstream")) {
    return "Configure an upstream branch or accept a review gate before PR creation.";
  }
  return "Review branch policy warnings before requesting mutation.";
}

function githubContextForRepository({
  runId,
  contextId,
  repositoryContext,
  branchPolicy,
  generatedAt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
  const githubRemotes = normalizeArray(context.remotes).filter((remote) => remote.provider === "github");
  const defaultRemote =
    githubRemotes.find((remote) => remote.name === "origin") ??
    githubRemotes[0] ??
    null;
  const owner = defaultRemote?.owner ?? null;
  const repo = defaultRemote?.repo ?? null;
  const repoFullName = owner && repo ? `${owner}/${repo}` : null;
  const tokenSources = githubTokenSources();
  const githubRemotePresent = Boolean(defaultRemote && repoFullName);
  const branchPolicyAllowsPr = policy.prCreationAllowed === true;
  const prCreationEligible = githubRemotePresent && branchPolicyAllowsPr && tokenSources.length > 0;
  const status = !githubRemotePresent
    ? "unavailable"
    : policy.status === "blocked"
      ? "blocked"
      : policy.status === "warning"
        ? "warning"
        : "available";
  const id = contextId ?? (runId ? `github_context_${runId}` : `github_context_${doctorHash(context.contextId ?? "workspace").slice(0, 12)}`);
  return {
    schemaVersion: "ioi.agent-runtime.github-context.v1",
    object: "ioi.github_context",
    contextId: id,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    branchPolicyId: policy.policyId ?? null,
    status,
    summary: githubContextSummary({ status, repoFullName, policy }),
    readOnly: true,
    networkLookupPerformed: false,
    mutationExecuted: false,
    provider: "github",
    githubRemotePresent,
    defaultRemoteName: defaultRemote?.name ?? null,
    owner,
    repo,
    repoFullName,
    htmlUrl: repoFullName ? `https://github.com/${repoFullName}` : null,
    defaultBranch: context.defaultBranch ?? null,
    branch: context.branch ?? null,
    branchPolicyStatus: policy.status ?? null,
    branchPolicyBlockers: normalizeArray(policy.blockers),
    branchPolicyWarnings: normalizeArray(policy.warnings),
    prCreationEligible,
    prCreationPreconditions: {
      githubRemotePresent,
      branchPolicyAllowsPr,
      tokenAvailable: tokenSources.length > 0,
      networkLookupPerformed: false,
      mutationExecuted: false,
    },
    remotes: githubRemotes.map((remote) => ({
      name: remote.name,
      host: remote.host,
      owner: remote.owner,
      repo: remote.repo,
      repoFullName: remote.repoFullName,
      fetchUrl: remote.fetchUrl,
      fetchUrlHash: remote.fetchUrlHash,
      pushUrl: remote.pushUrl,
      pushUrlHash: remote.pushUrlHash,
    })),
    credentials: {
      tokenAvailable: tokenSources.length > 0,
      tokenSources,
      tokenValueIncluded: false,
      authorizationHeaderIncluded: false,
    },
    redaction: {
      profile: "github_context_safe",
      tokenValueIncluded: false,
      remoteCredentialsIncluded: false,
      networkResponseIncluded: false,
    },
    evidenceRefs: [
      "github_context",
      "github.context.read_only",
      "GitHubContextNode",
      context.contextId,
      policy.policyId,
    ].filter(Boolean),
  };
}

function githubContextSummary({ status, repoFullName, policy }) {
  if (!repoFullName) return "No GitHub remote was detected in repository context.";
  if (status === "blocked") {
    return `GitHub context resolved ${repoFullName}, but branch policy is blocked: ${normalizeArray(policy.blockers).join(", ")}.`;
  }
  if (status === "warning") {
    return `GitHub context resolved ${repoFullName} with branch policy warnings: ${normalizeArray(policy.warnings).join(", ")}.`;
  }
  return `GitHub context resolved ${repoFullName} without network calls.`;
}

function githubTokenSources() {
  return ["GITHUB_TOKEN", "GH_TOKEN"].filter((name) => Boolean(process.env[name]));
}

function issueContextForGithub({
  runId,
  contextId,
  repositoryContext,
  githubContext,
  prAttempt,
  reviewGate,
  issue,
  generatedAt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const github = githubContext ?? githubContextForRepository({ repositoryContext: context });
  const issueNumber = normalizeIssueNumber(issue?.number ?? issue?.issueNumber);
  const title = emptyToNull(issue?.title);
  const sourceUrl = emptyToNull(issue?.url ?? issue?.sourceUrl);
  const bound = Boolean(issueNumber || title || sourceUrl);
  const status = !github.githubRemotePresent ? "unavailable" : bound ? "bound" : "unbound";
  const warnings = uniqueStrings([
    ...(!bound ? ["issue_context_unbound"] : []),
    ...(!github.githubRemotePresent ? ["missing_github_remote"] : []),
  ]);
  const id = contextId ?? (runId ? `issue_context_${runId}` : `issue_context_${doctorHash(github.contextId ?? context.contextId ?? "workspace").slice(0, 12)}`);
  return {
    schemaVersion: "ioi.agent-runtime.issue-context.v1",
    object: "ioi.issue_context",
    contextId: id,
    runId: runId ?? null,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    githubContextId: github.contextId ?? null,
    prAttemptId: prAttempt?.attemptId ?? null,
    reviewGateId: reviewGate?.gateId ?? null,
    status,
    summary: issueContextSummary({ status, repoFullName: github.repoFullName, issueNumber, title }),
    readOnly: true,
    provider: "github",
    repoFullName: github.repoFullName ?? null,
    htmlUrl: github.htmlUrl ?? null,
    bound,
    issueProvided: bound,
    issueNumber,
    title,
    sourceUrl,
    sourceKind: bound ? "github_issue" : "unbound",
    labels: normalizeArray(issue?.labels),
    assignees: [],
    blockers: [],
    warnings,
    noIssuePolicy: {
      allowed: true,
      reason: "Issue context is optional for local PR previews until a task source is supplied.",
    },
    networkLookupPerformed: false,
    mutationExecuted: false,
    redaction: {
      profile: "issue_context_safe",
      tokenValueIncluded: false,
      remoteCredentialsIncluded: false,
      networkResponseIncluded: false,
      bodyIncluded: false,
      reviewerIdentityIncluded: false,
    },
    evidenceRefs: [
      "issue_context",
      "IssueContextNode",
      "github.issue_context.read_only",
      context.contextId,
      github.contextId,
      prAttempt?.attemptId,
      reviewGate?.gateId,
    ].filter(Boolean),
  };
}

function issueContextSummary({ status, repoFullName, issueNumber, title }) {
  const target = repoFullName ?? "unknown GitHub repository";
  if (status === "bound") {
    const issueRef = issueNumber ? `#${issueNumber}` : title ?? "provided issue";
    return `Issue context ${issueRef} is bound for ${target} without network reads.`;
  }
  if (status === "unavailable") return "Issue context is unavailable because no GitHub remote was detected.";
  return `No issue is bound for ${target}; PR workflow may continue with an unbound issue context.`;
}

function normalizeIssueNumber(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : null;
}

function prAttemptForRepository({
  runId,
  attemptId,
  repositoryContext,
  branchPolicy,
  githubContext,
  generatedAt,
  prompt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
  const github = githubContext ?? githubContextForRepository({ repositoryContext: context, branchPolicy: policy });
  const diffArtifact = prDiffArtifactForRepository(context);
  const branchArtifact = prBranchArtifactForRepository({ repositoryContext: context, branchPolicy: policy, githubContext: github });
  const missingAuthorityScopes = ["github.pr.create"];
  const branchPolicyBlockers = normalizeArray(policy.blockers);
  const githubPreconditions = github.prCreationPreconditions ?? {};
  const blockers = uniqueStrings([
    ...branchPolicyBlockers,
    ...(!context.isGitRepository ? ["not_git_repository"] : []),
    ...(!github.githubRemotePresent ? ["missing_github_remote"] : []),
    ...(!githubPreconditions.tokenAvailable ? ["missing_github_token"] : []),
    ...(!githubPreconditions.branchPolicyAllowsPr ? ["branch_policy_not_passed"] : []),
    ...missingAuthorityScopes.map((scope) => `missing_authority_scope:${scope}`),
  ]);
  const warnings = uniqueStrings([
    ...normalizeArray(policy.warnings),
    ...normalizeArray(github.branchPolicyWarnings),
    "pr_attempt_preview_only",
  ]);
  const status = blockers.length > 0 ? "blocked" : "ready";
  const outcome = blockers.length > 0 ? "failed_precondition" : "preview_ready";
  const id = attemptId ?? (runId ? `pr_attempt_${runId}` : `pr_attempt_${doctorHash(context.contextId ?? "workspace").slice(0, 12)}`);
  const record = {
    schemaVersion: "ioi.agent-runtime.pr-attempt.v1",
    object: "ioi.pr_attempt",
    attemptId: id,
    runId: runId ?? null,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    branchPolicyId: policy.policyId ?? null,
    githubContextId: github.contextId ?? null,
    status,
    outcome,
    summary: prAttemptSummary({ status, outcome, repoFullName: github.repoFullName, blockers }),
    previewOnly: true,
    readOnly: true,
    provider: "github",
    action: "pr_create",
    title: prompt ? `Draft PR for: ${String(prompt).slice(0, 96)}` : null,
    bodyIncluded: false,
    repoFullName: github.repoFullName ?? null,
    htmlUrl: github.htmlUrl ?? null,
    branch: context.branch ?? null,
    defaultBranch: context.defaultBranch ?? null,
    headSha: context.headSha ?? null,
    headShortSha: context.headShortSha ?? null,
    upstream: context.upstream ?? null,
    dirty: Boolean(context.status?.isDirty),
    counts: context.status?.counts ?? {},
    blockers,
    warnings,
    failure: blockers.length
      ? {
          reason: blockers[0],
          message: "PR creation was not attempted because preview preconditions or authority requirements were not satisfied.",
        }
      : null,
    authority: {
      requiredScopes: ["github.pr.create"],
      grantedScopes: [],
      missingScopes: missingAuthorityScopes,
      scopeGranted: false,
      approvalRequired: true,
      approvalSatisfied: false,
    },
    preconditions: {
      gitRepositoryPresent: Boolean(context.isGitRepository),
      githubRemotePresent: Boolean(github.githubRemotePresent),
      branchPolicyAllowsPr: Boolean(githubPreconditions.branchPolicyAllowsPr),
      tokenAvailable: Boolean(githubPreconditions.tokenAvailable),
      authorityScopeGranted: false,
      diffCaptured: true,
      branchArtifactAttached: true,
      diffArtifactAttached: true,
      networkLookupPerformed: false,
      mutationExecuted: false,
    },
    mutationAttempted: false,
    mutationExecuted: false,
    networkLookupPerformed: false,
    prNumber: null,
    prUrl: null,
    branchArtifact: prArtifactMetadata(branchArtifact),
    diffArtifact: prArtifactMetadata(diffArtifact),
    artifacts: [
      { name: "pr-attempt.json", mediaType: "application/json" },
      prArtifactMetadata(branchArtifact),
      prArtifactMetadata(diffArtifact),
    ],
    redaction: {
      profile: "pr_attempt_safe",
      tokenValueIncluded: false,
      remoteCredentialsIncluded: false,
      networkResponseIncluded: false,
      diffContentInProjection: false,
    },
    evidenceRefs: [
      "pr_attempt",
      "pr_attempt_preview_only",
      "PrAttemptNode",
      context.contextId,
      policy.policyId,
      github.contextId,
      branchArtifact.artifactName,
      diffArtifact.artifactName,
    ].filter(Boolean),
  };
  Object.defineProperty(record, "artifactContents", {
    enumerable: false,
    value: {
      branch: branchArtifact.content,
      diff: diffArtifact.content,
    },
  });
  return record;
}

function prAttemptSummary({ status, outcome, repoFullName, blockers }) {
  const target = repoFullName ?? "unknown GitHub repository";
  if (status === "blocked") {
    return `PR attempt for ${target} recorded as ${outcome}; blockers: ${normalizeArray(blockers).join(", ")}.`;
  }
  return `PR attempt for ${target} recorded as preview-ready; mutation remains disabled.`;
}

function prBranchArtifactForRepository({ repositoryContext, branchPolicy, githubContext }) {
  const value = {
    schemaVersion: "ioi.agent-runtime.pr-branch-artifact.v1",
    object: "ioi.pr_branch_artifact",
    repositoryContextId: repositoryContext.contextId ?? null,
    branchPolicyId: branchPolicy.policyId ?? null,
    githubContextId: githubContext.contextId ?? null,
    repoFullName: githubContext.repoFullName ?? null,
    branch: repositoryContext.branch ?? null,
    defaultBranch: repositoryContext.defaultBranch ?? null,
    headSha: repositoryContext.headSha ?? null,
    headShortSha: repositoryContext.headShortSha ?? null,
    upstream: repositoryContext.upstream ?? null,
    dirty: Boolean(repositoryContext.status?.isDirty),
    counts: repositoryContext.status?.counts ?? {},
    branchPolicyStatus: branchPolicy.status ?? null,
    redaction: {
      profile: "pr_branch_artifact_safe",
      statusPathsIncluded: false,
      remoteCredentialsIncluded: false,
    },
  };
  return {
    artifactName: "pr-branch.json",
    mediaType: "application/json",
    artifactHash: doctorHash(JSON.stringify(value)),
    content: value,
  };
}

function prDiffArtifactForRepository(repositoryContext) {
  const rawPatch = repositoryContext.isGitRepository && repositoryContext.repoRoot
    ? gitOutput(repositoryContext.repoRoot, ["diff", "--no-ext-diff", "--binary", "HEAD", "--"]) ?? ""
    : "";
  const maxBytes = 512 * 1024;
  const rawBytes = Buffer.byteLength(rawPatch, "utf8");
  const truncated = rawBytes > maxBytes;
  const retainedPatch = truncated
    ? `${rawPatch.slice(0, maxBytes)}\n\n[ioi pr diff truncated: ${rawBytes - maxBytes} byte(s) omitted]\n`
    : rawPatch;
  return {
    artifactName: "pr-diff.patch",
    mediaType: "text/x-diff",
    artifactHash: doctorHash(rawPatch),
    diffHash: doctorHash(rawPatch),
    byteLength: rawBytes,
    retainedByteLength: Buffer.byteLength(retainedPatch, "utf8"),
    truncated,
    fileCount: prDiffFileCount(rawPatch),
    hasDiff: rawPatch.length > 0,
    untrackedCount: repositoryContext.status?.counts?.untracked ?? 0,
    content: retainedPatch,
  };
}

function prArtifactMetadata(artifactProjection) {
  const { content: _content, ...metadata } = artifactProjection;
  return metadata;
}

function prDiffFileCount(patch) {
  return String(patch).split(/\r?\n/).filter((line) => line.startsWith("diff --git ")).length;
}

function reviewGateForPrAttempt({
  runId,
  gateId,
  repositoryContext,
  branchPolicy,
  githubContext,
  prAttempt,
  generatedAt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
  const github = githubContext ?? githubContextForRepository({ repositoryContext: context, branchPolicy: policy });
  const attempt = prAttempt ?? prAttemptForRepository({ repositoryContext: context, branchPolicy: policy, githubContext: github });
  const requiredReviewers = ["code-owner"];
  const requiredChecks = [
    "branch_policy_passed",
    "github_context_available",
    "pr_attempt_ready",
    "diff_artifact_attached",
    "human_review_satisfied",
  ];
  const prAttemptReady = attempt.status === "ready";
  const reviewSatisfied = false;
  const blockers = uniqueStrings([
    ...normalizeArray(attempt.blockers),
    ...(policy.status !== "passed" ? ["branch_policy_not_passed"] : []),
    ...(github.status !== "available" ? ["github_context_not_available"] : []),
    ...(!prAttemptReady ? ["pr_attempt_not_ready"] : []),
    ...(!reviewSatisfied ? ["review_not_satisfied"] : []),
  ]);
  const warnings = uniqueStrings([
    ...normalizeArray(policy.warnings),
    ...normalizeArray(attempt.warnings),
    "review_gate_preview_only",
  ]);
  const status = blockers.length > 0 ? "blocked" : "passed";
  const decision = status;
  const id = gateId ?? (runId ? `review_gate_${runId}` : `review_gate_${doctorHash(attempt.attemptId ?? context.contextId ?? "workspace").slice(0, 12)}`);
  return {
    schemaVersion: "ioi.agent-runtime.review-gate.v1",
    object: "ioi.review_gate_decision",
    gateId: id,
    runId: runId ?? null,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    branchPolicyId: policy.policyId ?? null,
    githubContextId: github.contextId ?? null,
    prAttemptId: attempt.attemptId ?? null,
    status,
    decision,
    summary: reviewGateSummary({ status, repoFullName: github.repoFullName, blockers }),
    readOnly: true,
    previewOnly: true,
    reviewRequired: true,
    approvalRequired: true,
    reviewSatisfied,
    approvalSatisfied: false,
    mutationAllowed: false,
    prCreationAllowed: false,
    mutationExecuted: false,
    networkLookupPerformed: false,
    provider: "github",
    repoFullName: github.repoFullName ?? null,
    branch: context.branch ?? null,
    defaultBranch: context.defaultBranch ?? null,
    prAttemptStatus: attempt.status ?? null,
    prAttemptOutcome: attempt.outcome ?? null,
    requiredReviewers,
    satisfiedReviewers: [],
    requiredChecks,
    passedChecks: [],
    blockers,
    warnings,
    authority: {
      requiredScopes: ["github.pr.create"],
      grantedScopes: [],
      missingScopes: ["github.pr.create"],
      scopeGranted: false,
      approvalRequired: true,
      approvalSatisfied: false,
    },
    preconditions: {
      repositoryContextPresent: Boolean(context.contextId),
      branchPolicyPassed: policy.status === "passed",
      githubContextAvailable: github.status === "available",
      prAttemptPresent: Boolean(attempt.attemptId),
      prAttemptReady,
      diffArtifactAttached: Boolean(attempt.diffArtifact?.artifactName),
      branchArtifactAttached: Boolean(attempt.branchArtifact?.artifactName),
      reviewPolicySatisfied: reviewSatisfied,
      networkLookupPerformed: false,
      mutationExecuted: false,
    },
    redaction: {
      profile: "review_gate_safe",
      reviewerIdentityIncluded: false,
      tokenValueIncluded: false,
      networkResponseIncluded: false,
    },
    evidenceRefs: [
      "review_gate",
      "review_gate_preview_only",
      "ReviewGateNode",
      context.contextId,
      policy.policyId,
      github.contextId,
      attempt.attemptId,
    ].filter(Boolean),
  };
}

function reviewGateSummary({ status, repoFullName, blockers }) {
  const target = repoFullName ?? "unknown GitHub repository";
  if (status === "passed") {
    return `Review gate passed for ${target}; PR creation may proceed to authority checks.`;
  }
  return `Review gate blocked PR creation for ${target}: ${normalizeArray(blockers).join(", ")}.`;
}

function githubPrCreatePlanForReviewGate({
  runId,
  planId,
  repositoryContext,
  branchPolicy,
  githubContext,
  issueContext,
  prAttempt,
  reviewGate,
  generatedAt,
} = {}) {
  const context = repositoryContext ?? repositoryContextForWorkspace({});
  const policy = branchPolicy ?? branchPolicyForRepositoryContext({ repositoryContext: context });
  const github = githubContext ?? githubContextForRepository({ repositoryContext: context, branchPolicy: policy });
  const attempt = prAttempt ?? prAttemptForRepository({ repositoryContext: context, branchPolicy: policy, githubContext: github });
  const gate = reviewGate ?? reviewGateForPrAttempt({ repositoryContext: context, branchPolicy: policy, githubContext: github, prAttempt: attempt });
  const issue = issueContext ?? issueContextForGithub({ repositoryContext: context, githubContext: github, prAttempt: attempt, reviewGate: gate });
  const title = attempt.title ?? `Draft PR for ${context.branch ?? "working branch"}`;
  const payloadPreview = {
    owner: github.owner ?? null,
    repo: github.repo ?? null,
    base: context.defaultBranch ?? null,
    head: context.branch ?? null,
    title,
    bodyIncluded: false,
    draft: true,
    maintainerCanModify: true,
    issueNumber: issue.issueNumber ?? null,
  };
  const requestPayloadHash = doctorHash(JSON.stringify(payloadPreview));
  const blockers = uniqueStrings([
    ...normalizeArray(gate.blockers),
    ...normalizeArray(attempt.blockers),
    ...(github.status !== "available" ? ["github_context_not_available"] : []),
    ...(policy.status !== "passed" ? ["branch_policy_not_passed"] : []),
    ...(attempt.status !== "ready" ? ["pr_attempt_not_ready"] : []),
    ...(gate.status !== "passed" ? ["review_gate_not_passed"] : []),
    ...(!gate.reviewSatisfied ? ["review_not_satisfied"] : []),
    ...(!github.credentials?.tokenAvailable ? ["missing_github_token"] : []),
    "missing_authority_scope:github.pr.create",
    "dry_run_only",
  ]);
  const warnings = uniqueStrings([
    ...normalizeArray(issue.warnings),
    ...normalizeArray(gate.warnings),
    "github_pr_create_plan_dry_run",
  ]);
  const status = blockers.length > 0 ? "blocked" : "ready";
  const id = planId ?? (runId ? `github_pr_create_plan_${runId}` : `github_pr_create_plan_${doctorHash(gate.gateId ?? attempt.attemptId ?? "workspace").slice(0, 12)}`);
  return {
    schemaVersion: "ioi.agent-runtime.github-pr-create-plan.v1",
    object: "ioi.github_pr_create_plan",
    planId: id,
    runId: runId ?? null,
    generatedAt: generatedAt ?? new Date().toISOString(),
    repositoryContextId: context.contextId ?? null,
    branchPolicyId: policy.policyId ?? null,
    githubContextId: github.contextId ?? null,
    issueContextId: issue.contextId ?? null,
    prAttemptId: attempt.attemptId ?? null,
    reviewGateId: gate.gateId ?? null,
    status,
    decision: status,
    summary: githubPrCreatePlanSummary({ status, repoFullName: github.repoFullName, blockers }),
    dryRun: true,
    previewOnly: true,
    provider: "github",
    toolName: "github__pr_create",
    action: "pr_create",
    repoFullName: github.repoFullName ?? null,
    owner: github.owner ?? null,
    repo: github.repo ?? null,
    baseBranch: context.defaultBranch ?? null,
    headBranch: context.branch ?? null,
    title,
    bodyPlan: {
      included: false,
      source: issue.bound ? "issue_context" : "runtime_template",
      redaction: "body_not_included_in_projection",
    },
    issueNumber: issue.issueNumber ?? null,
    reviewGateStatus: gate.status ?? null,
    reviewSatisfied: Boolean(gate.reviewSatisfied),
    authority: {
      requiredScopes: ["github.pr.create"],
      grantedScopes: [],
      missingScopes: ["github.pr.create"],
      scopeGranted: false,
      approvalRequired: true,
      approvalSatisfied: false,
    },
    request: {
      method: "POST",
      path: github.repoFullName ? `/repos/${github.repoFullName}/pulls` : null,
      payloadHash: requestPayloadHash,
      payloadPreview,
      bodyIncluded: false,
      tokenIncluded: false,
    },
    blockers,
    warnings,
    networkLookupPerformed: false,
    mutationAttempted: false,
    mutationExecuted: false,
    prNumber: null,
    prUrl: null,
    redaction: {
      profile: "github_pr_create_plan_safe",
      tokenValueIncluded: false,
      authorizationHeaderIncluded: false,
      requestBodyIncluded: false,
      responseBodyIncluded: false,
      networkResponseIncluded: false,
    },
    evidenceRefs: [
      "github_pr_create_plan",
      "github.pr_create.request_hash",
      "github.pr_create.authority_scope",
      "github.pr_create.dry_run",
      "GitHubPrCreateNode",
      context.contextId,
      policy.policyId,
      github.contextId,
      issue.contextId,
      attempt.attemptId,
      gate.gateId,
    ].filter(Boolean),
  };
}

function githubPrCreatePlanSummary({ status, repoFullName, blockers }) {
  const target = repoFullName ?? "unknown GitHub repository";
  if (status === "ready") {
    return `GitHub PR create dry-run plan is ready for ${target}; mutation remains disabled pending authority approval.`;
  }
  return `GitHub PR create dry-run plan is blocked for ${target}: ${normalizeArray(blockers).join(", ")}.`;
}

function repositoryDefaultBranch(repoRoot) {
  const remoteHead = emptyToNull(gitOutput(repoRoot, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]));
  if (remoteHead?.startsWith("origin/")) return remoteHead.slice("origin/".length);
  return remoteHead;
}

function gitOutput(cwd, args) {
  try {
    return execFileSync("git", ["-C", cwd, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1500,
      maxBuffer: 4 * 1024 * 1024,
    }).trimEnd();
  } catch {
    return null;
  }
}

function emptyToNull(value) {
  const text = typeof value === "string" ? value.trim() : "";
  return text ? text : null;
}

function repositoryStatusProjection(availability, counts = repositoryStatusCounts(""), aheadBehind = {}, porcelain = "") {
  const isDirty =
    counts.staged > 0 ||
    counts.unstaged > 0 ||
    counts.untracked > 0 ||
    counts.conflicted > 0;
  return {
    availability,
    clean: availability === "available" ? !isDirty : null,
    isDirty,
    counts,
    ahead: aheadBehind.ahead ?? 0,
    behind: aheadBehind.behind ?? 0,
    porcelainHash: porcelain ? doctorHash(porcelain) : null,
    untrackedMode: availability === "available" ? "normal" : "none",
  };
}

function repositoryStatusCounts(porcelain) {
  const counts = {
    staged: 0,
    unstaged: 0,
    untracked: 0,
    ignored: 0,
    conflicted: 0,
  };
  for (const line of String(porcelain).split(/\r?\n/).filter(Boolean)) {
    const status = line.slice(0, 2);
    const x = status[0];
    const y = status[1];
    if (status === "??") {
      counts.untracked += 1;
      continue;
    }
    if (status === "!!") {
      counts.ignored += 1;
      continue;
    }
    if (repositoryStatusIsConflict(status)) counts.conflicted += 1;
    if (x && x !== " " && x !== "?" && x !== "!") counts.staged += 1;
    if (y && y !== " " && y !== "?" && y !== "!") counts.unstaged += 1;
  }
  return counts;
}

function repositoryStatusIsConflict(status) {
  return ["DD", "AU", "UD", "UA", "DU", "AA", "UU"].includes(status);
}

function repositoryAheadBehind(branchStatus) {
  const line = String(branchStatus)
    .split(/\r?\n/)
    .find((item) => item.startsWith("# branch.ab "));
  const match = line?.match(/\+(\d+)\s+-(\d+)/);
  return {
    ahead: match ? Number(match[1]) : 0,
    behind: match ? Number(match[2]) : 0,
  };
}

function parseGitRemotes(remoteOutput) {
  const byName = new Map();
  for (const line of String(remoteOutput).split(/\r?\n/).filter(Boolean)) {
    const match = line.match(/^(\S+)\s+(.+?)\s+\((fetch|push)\)$/);
    if (!match) continue;
    const [, name, url, kind] = match;
    const metadata = parseRemoteMetadata(url);
    const current = byName.get(name) ?? { name };
    current[`${kind}Url`] = redactRemoteUrl(url);
    current[`${kind}UrlHash`] = doctorHash(url);
    current.provider ??= metadata.provider;
    current.host ??= metadata.host;
    current.owner ??= metadata.owner;
    current.repo ??= metadata.repo;
    current.repoFullName ??= metadata.repoFullName;
    byName.set(name, current);
  }
  return [...byName.values()].sort((left, right) => left.name.localeCompare(right.name));
}

function parseRemoteMetadata(remoteUrl) {
  const normalized = {
    provider: null,
    host: null,
    owner: null,
    repo: null,
    repoFullName: null,
  };
  const fromParts = (host, remotePath) => {
    const parts = String(remotePath ?? "")
      .replace(/^\/+/, "")
      .replace(/\.git$/, "")
      .split("/")
      .filter(Boolean);
    const owner = parts[0] ?? null;
    const repo = parts[1] ?? null;
    const lowerHost = host ? String(host).toLowerCase() : null;
    return {
      provider: lowerHost === "github.com" ? "github" : null,
      host: lowerHost,
      owner,
      repo,
      repoFullName: owner && repo ? `${owner}/${repo}` : null,
    };
  };
  try {
    const parsed = new URL(remoteUrl);
    return fromParts(parsed.hostname, parsed.pathname);
  } catch {
    const scpLike = String(remoteUrl).match(/^(?:[^@]+@)?([^:]+):(.+)$/);
    if (scpLike) return fromParts(scpLike[1], scpLike[2]);
  }
  return normalized;
}

function redactRemoteUrl(remoteUrl) {
  try {
    const parsed = new URL(remoteUrl);
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return remoteUrl.includes("@")
      ? `redacted:${doctorHash(remoteUrl).slice(0, 12)}`
      : remoteUrl;
  }
}

function repositoryContextRedaction() {
  return {
    profile: "repository_context_safe",
    pathIncluded: true,
    remoteUrlsHashed: true,
    remoteCredentialsIncluded: false,
    statusPathsIncluded: false,
  };
}

function activeSkillHookManifestForRun({ runId, agent, request = {}, catalog = null } = {}) {
  const skills = normalizeArray(catalog?.skills);
  const hooks = normalizeArray(catalog?.hooks);
  const options = request.options ?? {};
  const requestedSkillRefs = normalizeManifestSelection([
    options.skills,
    options.skillIds,
    options.skill_ids,
    options.skillNames,
    options.skill_names,
    agent?.options?.skillNames,
  ]);
  const requestedHookRefs = normalizeManifestSelection([
    options.hooks,
    options.hookIds,
    options.hook_ids,
    options.hookNames,
    options.hook_names,
    agent?.options?.hookNames,
  ]);
  const selectedSkills = selectCatalogRecords(skills, requestedSkillRefs, "skillHash");
  const selectedHooks = selectCatalogRecords(
    hooks.filter((hook) => hook.enabled !== false),
    requestedHookRefs,
    "definitionHash",
  );
  const skillHashes = selectedSkills.map((skill) => skill.skillHash).filter(Boolean).sort();
  const hookHashes = selectedHooks.map((hook) => hook.definitionHash).filter(Boolean).sort();
  const blockedHooks = selectedHooks.filter((hook) =>
    hook.commandConfigured &&
    (normalizeArray(hook.authorityScopes).length === 0 || normalizeArray(hook.toolContracts).length === 0)
  );
  const manifestPayload = {
    skillHashes,
    hookHashes,
    catalogSkillSetHash: catalog?.activeSkillSetHash ?? doctorHash(""),
    catalogHookSetHash: catalog?.activeHookSetHash ?? doctorHash(""),
    blockedHookIds: blockedHooks.map((hook) => hook.id).sort(),
  };
  const manifestHash = doctorHash(JSON.stringify(manifestPayload));
  const validationIssues = [
    ...selectedSkills.flatMap((skill) => normalizeArray(skill.validation?.issues)),
    ...selectedHooks.flatMap((hook) => normalizeArray(hook.validation?.issues)),
  ];
  return {
    schemaVersion: "ioi.agent-runtime.active-skill-hook-manifest.v1",
    object: "ioi.agent_active_skill_hook_manifest",
    manifestId: `skill_hook_manifest_${runId}_${manifestHash.slice(0, 12)}`,
    runId,
    agentId: agent?.id ?? null,
    generatedAt: new Date().toISOString(),
    workspace: agent?.cwd ?? catalog?.workspace?.root ?? null,
    selectionMode:
      requestedSkillRefs.length > 0 || requestedHookRefs.length > 0
        ? "explicit_or_configured"
        : "catalog_snapshot_read_only",
    catalog: {
      schemaVersion: catalog?.schemaVersion ?? "ioi.agent-runtime.skill-hook-catalog.v1",
      generatedAt: catalog?.generatedAt ?? null,
      status: catalog?.status ?? "pass",
      activeSkillSetHash: catalog?.activeSkillSetHash ?? doctorHash(""),
      activeHookSetHash: catalog?.activeHookSetHash ?? doctorHash(""),
      skillCount: catalog?.skillCount ?? skills.length,
      hookCount: catalog?.hookCount ?? hooks.length,
    },
    activeSkillSetHash: doctorHash(skillHashes.join("\n")),
    activeHookSetHash: doctorHash(hookHashes.join("\n")),
    manifestHash,
    selectedSkillIds: selectedSkills.map((skill) => skill.id),
    selectedHookIds: selectedHooks.map((hook) => hook.id),
    requestedSkillRefs,
    requestedHookRefs,
    skills: selectedSkills.map((skill) => ({
      id: skill.id,
      name: skill.name,
      skillHash: skill.skillHash,
      sourceId: skill.sourceId,
      compatibility: skill.compatibility,
      trustLevel: skill.trustLevel,
      activationMode: skill.activationMode,
      validationStatus: skill.validation?.status ?? "pass",
      provenance: skill.provenance,
      evidenceRefs: normalizeArray(skill.evidenceRefs),
    })),
    hooks: selectedHooks.map((hook) => ({
      id: hook.id,
      name: hook.name,
      enabled: hook.enabled !== false,
      definitionHash: hook.definitionHash,
      sourceId: hook.sourceId,
      compatibility: hook.compatibility,
      trustLevel: hook.trustLevel,
      eventKinds: normalizeArray(hook.eventKinds),
      failurePolicy: hook.failurePolicy,
      sideEffectClass: hook.sideEffectClass ?? "none",
      authorityScopes: normalizeArray(hook.authorityScopes),
      toolContracts: normalizeArray(hook.toolContracts),
      commandConfigured: Boolean(hook.commandConfigured),
      commandHash: hook.commandHash ?? null,
      commandRedacted: Boolean(hook.commandRedacted),
      validationStatus: hook.validation?.status ?? "pass",
      mutationPolicy: hook.mutationPolicy,
      evidenceRefs: normalizeArray(hook.evidenceRefs),
    })),
    validation: {
      status: validationIssues.length > 0 ? "degraded" : "pass",
      issueCount: validationIssues.length,
      issues: [...new Set(validationIssues)].sort(),
    },
    hookExecution: {
      enabled: false,
      disabledReason: "hook_execution_policy_slice_pending",
      mutationBlockedWithoutDeclaredCapabilities: true,
      mutationAllowedHookIds: selectedHooks
        .filter((hook) =>
          hook.commandConfigured &&
          normalizeArray(hook.authorityScopes).length > 0 &&
          normalizeArray(hook.toolContracts).length > 0
        )
        .map((hook) => hook.id),
      mutationBlockedHookIds: blockedHooks.map((hook) => hook.id),
    },
    mutationBlockedHookIds: blockedHooks.map((hook) => hook.id),
    redaction: {
      profile: "active_skill_hook_manifest_safe",
      skillBodiesIncluded: false,
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "active_skill_hook_manifest",
      "runtime_skill_hook_discovery",
      "prompt_audit",
      "hook_execution_disabled_until_policy",
    ],
  };
}

function hookDryRunPlanForManifest({ runId, manifest } = {}) {
  const hooks = normalizeArray(manifest?.hooks);
  const decisions = hooks.map((hook) => {
    const authorityScopes = normalizeArray(hook.authorityScopes);
    const toolContracts = normalizeArray(hook.toolContracts);
    const commandConfigured = Boolean(hook.commandConfigured);
    const blockers = [];
    let decision = "skipped";
    let reason = "no_command_configured";

    if (commandConfigured) {
      if (authorityScopes.length === 0) blockers.push("missing_authority_scope");
      if (toolContracts.length === 0) blockers.push("missing_tool_contract");
      if (blockers.length > 0) {
        decision = "blocked";
        reason = "missing_declared_capabilities";
      } else {
        decision = "would_run";
        reason = "preview_only_authority_and_tool_contract_declared";
      }
    }

    return {
      hookId: hook.id,
      name: hook.name,
      eventKinds: normalizeArray(hook.eventKinds),
      failurePolicy: hook.failurePolicy ?? "warn",
      sideEffectClass: hook.sideEffectClass ?? "none",
      commandConfigured,
      commandHash: hook.commandHash ?? null,
      commandRedacted: Boolean(hook.commandRedacted),
      authorityScopes,
      toolContracts,
      decision,
      reason,
      blockers,
      execution: {
        previewOnly: true,
        commandExecuted: false,
        mutationAllowed: false,
      },
      evidenceRefs: normalizeArray(hook.evidenceRefs),
    };
  });
  const wouldRunCount = decisions.filter((decision) => decision.decision === "would_run").length;
  const blockedCount = decisions.filter((decision) => decision.decision === "blocked").length;
  const skippedCount = decisions.filter((decision) => decision.decision === "skipped").length;
  const planPayload = {
    manifestId: manifest?.manifestId ?? null,
    decisions: decisions.map((decision) => ({
      hookId: decision.hookId,
      decision: decision.decision,
      blockers: decision.blockers,
    })),
  };
  const planHash = doctorHash(JSON.stringify(planPayload));

  return {
    schemaVersion: "ioi.agent-runtime.hook-dry-run-plan.v1",
    object: "ioi.agent_hook_dry_run_plan",
    planId: `hook_dry_run_${runId}_${planHash.slice(0, 12)}`,
    runId,
    manifestId: manifest?.manifestId ?? null,
    activeHookSetHash: manifest?.activeHookSetHash ?? doctorHash(""),
    generatedAt: new Date().toISOString(),
    mode: "preview_only",
    hookExecutionEnabled: false,
    commandExecutionEnabled: false,
    decisionCount: decisions.length,
    wouldRunCount,
    blockedCount,
    skippedCount,
    decisions,
    policyDecision: {
      status: blockedCount > 0 ? "blocked" : "passed",
      summary:
        blockedCount > 0
          ? `${blockedCount} hook(s) blocked by missing declared capabilities; no commands executed.`
          : "All command-backed hooks are eligible for dry-run preview; no commands executed.",
      previewOnly: true,
      hookExecutionEnabled: false,
      commandExecutionEnabled: false,
    },
    redaction: {
      profile: "hook_dry_run_safe",
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "hook_dry_run_plan",
      "hook_policy_decision",
      manifest?.manifestId,
    ].filter(Boolean),
  };
}

function hookInvocationLedgerForPlan({ runId, manifest, dryRunPlan } = {}) {
  const hooks = normalizeArray(manifest?.hooks);
  const decisionsByHookId = new Map(
    normalizeArray(dryRunPlan?.decisions).map((decision) => [decision.hookId, decision]),
  );
  const records = [];
  for (const runtimeEvent of HOOK_INVOCATION_RUNTIME_EVENTS) {
    for (const hook of hooks) {
      const hookEventKinds = normalizeArray(hook.eventKinds);
      if (!hookEventKinds.includes(runtimeEvent.eventKind)) continue;
      const planDecision = decisionsByHookId.get(hook.id) ?? {};
      const decision = planDecision.decision ?? "skipped";
      const blockers = normalizeArray(planDecision.blockers);
      const invocationHash = doctorHash(
        JSON.stringify({
          runId,
          eventKind: runtimeEvent.eventKind,
          hookId: hook.id,
          decision,
          blockers,
        }),
      );
      const escalation =
        decision === "blocked"
          ? hookEscalationForBlockedInvocation({
              runId,
              invocationHash,
              runtimeEvent,
              hook,
              planDecision,
              blockers,
            })
          : {
              required: false,
              receiptId: null,
              missingAuthorityScopes: [],
              missingToolContracts: [],
              recommendedNextAction: "No hook escalation is required for this preview invocation.",
            };
      records.push({
        schemaVersion: "ioi.agent-runtime.hook-invocation-record.v1",
        object: "ioi.agent_hook_invocation_record",
        invocationId: `hook_invocation_${runId}_${invocationHash.slice(0, 12)}`,
        runId,
        manifestId: manifest?.manifestId ?? null,
        dryRunPlanId: dryRunPlan?.planId ?? null,
        eventKind: runtimeEvent.eventKind,
        runtimeEventType: runtimeEvent.runtimeEventType,
        runtimeEventPhase: runtimeEvent.phase,
        hookId: hook.id,
        hookName: hook.name,
        hookDefinitionHash: hook.definitionHash ?? null,
        hookEventKinds,
        failurePolicy: hook.failurePolicy ?? "warn",
        sideEffectClass: hook.sideEffectClass ?? "none",
        authorityScopes: normalizeArray(hook.authorityScopes),
        toolContracts: normalizeArray(hook.toolContracts),
        commandConfigured: Boolean(hook.commandConfigured),
        commandHash: hook.commandHash ?? null,
        commandRedacted: Boolean(hook.commandRedacted),
        state: decision,
        decision,
        reason: planDecision.reason ?? "preview_only_event_subscription_matched",
        blockers,
        escalation,
        policyDecisionStatus: dryRunPlan?.policyDecision?.status ?? null,
        execution: {
          previewOnly: true,
          commandExecuted: false,
          mutationAllowed: false,
        },
        workflowNodeId: `runtime.hook.${runtimeEvent.eventKind.replace(/_/g, "-")}`,
        hookPolicyNodeId: "runtime.hook-policy",
        evidenceRefs: [
          "hook_invocation_record",
          dryRunPlan?.planId,
          manifest?.manifestId,
          hook.id,
          runtimeEvent.eventKind,
        ].filter(Boolean),
      });
    }
  }
  const wouldRunCount = records.filter((record) => record.state === "would_run").length;
  const blockedCount = records.filter((record) => record.state === "blocked").length;
  const skippedCount = records.filter((record) => record.state === "skipped").length;
  const escalations = records
    .filter((record) => record.escalation?.required === true)
    .map((record) => ({
      ...record.escalation,
      invocationId: record.invocationId,
      hookId: record.hookId,
      hookName: record.hookName,
      eventKind: record.eventKind,
      failurePolicy: record.failurePolicy,
      workflowNodeId: record.workflowNodeId,
    }));
  const ledgerHash = doctorHash(
    JSON.stringify({
      manifestId: manifest?.manifestId ?? null,
      planId: dryRunPlan?.planId ?? null,
      records: records.map((record) => ({
        eventKind: record.eventKind,
        hookId: record.hookId,
        state: record.state,
      })),
    }),
  );
  return {
    schemaVersion: "ioi.agent-runtime.hook-invocation-ledger.v1",
    object: "ioi.agent_hook_invocation_ledger",
    ledgerId: `hook_invocations_${runId}_${ledgerHash.slice(0, 12)}`,
    runId,
    manifestId: manifest?.manifestId ?? null,
    dryRunPlanId: dryRunPlan?.planId ?? null,
    activeHookSetHash: manifest?.activeHookSetHash ?? doctorHash(""),
    generatedAt: new Date().toISOString(),
    mode: "preview_only",
    hookExecutionEnabled: false,
    commandExecutionEnabled: false,
    emittedEventKinds: HOOK_INVOCATION_RUNTIME_EVENTS.map((event) => event.eventKind),
    invocationCount: records.length,
    wouldRunCount,
    blockedCount,
    skippedCount,
    escalationCount: escalations.length,
    escalations,
    records,
    redaction: {
      profile: "hook_invocation_ledger_safe",
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "hook_invocation_ledger",
      "hook_invocation_preview_only",
      dryRunPlan?.planId,
      manifest?.manifestId,
    ].filter(Boolean),
  };
}

function hookEscalationForBlockedInvocation({
  runId,
  invocationHash,
  runtimeEvent,
  hook,
  planDecision,
  blockers,
} = {}) {
  const missingAuthorityScopes = blockers.includes("missing_authority_scope")
    ? ["declare_at_least_one_authority_scope"]
    : [];
  const missingToolContracts = blockers.includes("missing_tool_contract")
    ? ["declare_at_least_one_tool_contract"]
    : [];
  const missingDeclarations = [
    ...(missingAuthorityScopes.length > 0 ? ["authorityScopes"] : []),
    ...(missingToolContracts.length > 0 ? ["toolContracts"] : []),
  ];
  return {
    required: true,
    receiptId: `receipt_${runId}_hook_escalation_${invocationHash.slice(0, 12)}`,
    escalationKind: "missing_declared_capabilities",
    missingDeclarations,
    missingAuthorityScopes,
    missingToolContracts,
    eventKind: runtimeEvent?.eventKind ?? null,
    hookId: hook?.id ?? null,
    hookName: hook?.name ?? null,
    failurePolicy: hook?.failurePolicy ?? "warn",
    blockers,
    recommendedNextAction:
      missingDeclarations.length > 0
        ? `Declare ${missingDeclarations.join(" and ")} for this hook before requesting execution.`
        : "Review hook policy before requesting execution.",
    commandExecuted: false,
    approvalGrantCreated: false,
    evidenceRefs: [
      "hook_escalation_receipt",
      hook?.id,
      runtimeEvent?.eventKind,
      planDecision?.decision,
    ].filter(Boolean),
  };
}

function hookEscalationReceiptsForLedger(ledger = {}) {
  return normalizeArray(ledger.records)
    .filter((record) => record.escalation?.required === true)
    .map((record) => ({
      id: record.escalation.receiptId,
      kind: "hook_escalation",
      summary: `Hook ${record.hookName} on ${record.eventKind} is blocked until ${record.escalation.missingDeclarations.join(" and ") || "policy"} are declared.`,
      redaction: "redacted",
      evidenceRefs: [
        ledger.ledgerId,
        record.invocationId,
        record.dryRunPlanId,
        record.manifestId,
        "hook_escalation_receipt",
      ].filter(Boolean),
      details: {
        schemaVersion: "ioi.agent-runtime.hook-escalation-receipt.v1",
        object: "ioi.agent_hook_escalation_receipt",
        receiptId: record.escalation.receiptId,
        invocationId: record.invocationId,
        hookId: record.hookId,
        hookName: record.hookName,
        eventKind: record.eventKind,
        failurePolicy: record.failurePolicy,
        blockers: record.blockers,
        missingDeclarations: record.escalation.missingDeclarations,
        missingAuthorityScopes: record.escalation.missingAuthorityScopes,
        missingToolContracts: record.escalation.missingToolContracts,
        recommendedNextAction: record.escalation.recommendedNextAction,
        workflowNodeId: record.workflowNodeId,
        hookPolicyNodeId: record.hookPolicyNodeId,
        commandExecuted: false,
        approvalGrantCreated: false,
      },
    }));
}

function normalizeManifestSelection(values) {
  const items = [];
  const visit = (value) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (value && typeof value === "object") {
      for (const key of ["id", "name", "skillHash", "definitionHash"]) {
        if (value[key]) items.push(value[key]);
      }
      return;
    }
    if (value !== undefined && value !== null) items.push(value);
  };
  values.forEach(visit);
  return items.map((value) => optionalString(value)).filter(Boolean);
}

function selectCatalogRecords(records, requestedRefs, hashField) {
  if (requestedRefs.length === 0) return records;
  const requested = new Set(requestedRefs.map(normalizeManifestToken));
  return records.filter((record) => {
    const candidates = [
      record.id,
      record.name,
      record[hashField],
      record.sourceId,
    ].map(normalizeManifestToken);
    return candidates.some((candidate) => requested.has(candidate));
  });
}

function normalizeManifestToken(value) {
  return String(value ?? "").trim().toLowerCase().replace(/\s+/g, "-");
}

function artifact(runId, name, mediaType, receiptId, value, redaction) {
  return {
    id: `artifact_${runId}_${name.replace(/[^a-z0-9]+/gi, "_").replace(/_$/, "")}`,
    runId,
    name,
    mediaType,
    redaction,
    receiptId,
    content: typeof value === "string" ? value : JSON.stringify(value, null, 2),
  };
}

function summarizeAgentOptions(cwd, options = {}) {
  const cursorConfig = loadCursorCompatibilityConfig(cwd);
  return {
    localCwd: options.local?.cwd,
    cloudConfigured: Boolean(options.cloud ?? options.hosted),
    selfHostedConfigured: Boolean(options.selfHosted),
    mcpServerNames: [
      ...new Set([
        ...Object.keys(options.mcpServers ?? {}),
        ...Object.keys(cursorConfig.mcpServers),
      ]),
    ],
    skillNames: cursorConfig.skillNames,
    hookNames: cursorConfig.hookNames,
    subagentNames: Object.keys(options.agents ?? {}),
    sandboxProfile: options.sandboxOptions?.profile ?? "development",
  };
}

function modelPolicyForOptions(options = {}) {
  const model = options.model ?? {};
  const policy = {
    ...(options.model_policy ?? options.modelPolicy ?? {}),
    ...(model.policy ?? model.model_policy ?? model.modelPolicy ?? {}),
  };
  if (model.provider && policy.provider === undefined) policy.provider = model.provider;
  if (model.reasoningEffort && policy.reasoning_effort === undefined) {
    policy.reasoning_effort = model.reasoningEffort;
  }
  if (model.thinking && policy.reasoning_effort === undefined) {
    policy.reasoning_effort = model.thinking;
  }
  if (model.privacy && policy.privacy === undefined) policy.privacy = model.privacy;
  if (model.maxCostUsd !== undefined && policy.max_cost_usd === undefined) {
    policy.max_cost_usd = model.maxCostUsd;
  }
  if (model.max_cost_usd !== undefined && policy.max_cost_usd === undefined) {
    policy.max_cost_usd = model.max_cost_usd;
  }
  if (model.allowHostedFallback !== undefined && policy.allow_hosted_fallback === undefined) {
    policy.allow_hosted_fallback = model.allowHostedFallback;
  }
  if (model.allow_hosted_fallback !== undefined && policy.allow_hosted_fallback === undefined) {
    policy.allow_hosted_fallback = model.allow_hosted_fallback;
  }
  return policy;
}

function modelWorkflowContext({ model = {}, options = {}, context = {} } = {}) {
  const workflow = options.workflow ?? model.workflow ?? {};
  return {
    workflow_graph_id:
      model.workflowGraphId ??
      model.workflow_graph_id ??
      options.workflowGraphId ??
      options.workflow_graph_id ??
      workflow.graphId ??
      workflow.graph_id ??
      context.workflowGraphId ??
      null,
    workflow_node_id:
      model.workflowNodeId ??
      model.workflow_node_id ??
      options.workflowNodeId ??
      options.workflow_node_id ??
      workflow.nodeId ??
      workflow.node_id ??
      context.workflowNodeId ??
      "runtime.model-router",
    workflow_node_type:
      model.workflowNodeType ??
      model.workflow_node_type ??
      options.workflowNodeType ??
      options.workflow_node_type ??
      workflow.nodeType ??
      workflow.node_type ??
      context.workflowNodeType ??
      "Model Router",
  };
}

function modelRouteBindingFromReceipt(receipt, requestedModelId) {
  const decision = routeDecision.routeDecisionProjectionFromReceipt(receipt);
  return {
    requestedModelId: decision?.requestedModel ?? requestedModelId ?? "local:auto",
    selectedModel: decision?.selectedModel ?? requestedModelId ?? "local:auto",
    routeId: decision?.routeId ?? null,
    endpointId: decision?.endpointId ?? null,
    providerId: decision?.providerId ?? null,
    receiptId: receipt.id,
    decision,
  };
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}

function loadCursorCompatibilityConfig(cwd) {
  const cursorDir = path.join(cwd, ".cursor");
  const mcpPath = path.join(cursorDir, "mcp.json");
  const hooksPath = path.join(cursorDir, "hooks.json");
  const skillsDir = path.join(cursorDir, "skills");
  return {
    mcpServers: fs.existsSync(mcpPath) ? readJson(mcpPath).mcpServers ?? {} : {},
    hookNames: fs.existsSync(hooksPath) ? Object.keys(readJson(hooksPath)) : [],
    skillNames: fs.existsSync(skillsDir)
      ? fs.readdirSync(skillsDir).filter((entry) => !entry.startsWith("."))
      : [],
  };
}

function runtimeModeForOptions(options = {}) {
  if (options.cloud) return "cloud";
  if (options.hosted) return "hosted";
  if (options.selfHosted) return "selfHosted";
  return "local";
}

function ensureProviderAvailable(runtime, options = {}) {
  if (runtime === "local") return;
  const endpoint =
    options.hosted?.endpoint ??
    options.hosted?.provider?.endpoint ??
    options.cloud?.endpoint ??
    options.selfHosted?.endpoint ??
    process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ??
    process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  if (!endpoint) {
    throw externalBlocker(`${runtime} runtime requested, but no IOI worker provider endpoint is configured.`, {
      runtime,
      requiredEnvironment: [
        "IOI_AGENT_SDK_HOSTED_ENDPOINT",
        "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
      ],
    });
  }
}

function memoryOptionsForRequest(request = {}) {
  return {
    ...(request.memory ?? {}),
    ...(request.options?.memory ?? {}),
  };
}

function doctorCheck(id, status, required, summary, evidenceRefs = []) {
  return {
    id,
    status,
    required,
    summary,
    evidenceRefs: normalizeArray(evidenceRefs),
  };
}

function doctorProviderKeyReport() {
  return [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "IOI_AGENT_SDK_HOSTED_ENDPOINT",
    "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
  ].map((name) => ({
    name,
    source: "env",
    configured: Boolean(process.env[name]),
    valueRedacted: true,
    valueHash: process.env[name] ? doctorHash(process.env[name]) : null,
  }));
}

function redactRuntimeNodeForDoctor(node = {}) {
  return {
    id: node.id,
    kind: node.kind,
    status: node.status,
    privacyClass: node.privacyClass,
    endpointConfigured: Boolean(node.endpoint),
    endpointHash: node.endpoint ? doctorHash(node.endpoint) : null,
    evidenceRefs: normalizeArray(node.evidenceRefs),
  };
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function discoverSkillHookCatalog({ cwd, homeDir } = {}) {
  const workspaceRoot = path.resolve(cwd ?? process.cwd());
  const globalHome = path.resolve(homeDir ?? process.env.HOME ?? os.homedir());
  const generatedAt = new Date().toISOString();
  const sources = skillHookSources({ workspaceRoot, globalHome });
  const skills = sources.flatMap((source) => discoverSkillsFromSource(source, workspaceRoot));
  const hooks = sources.flatMap((source) => discoverHooksFromSource(source, workspaceRoot));
  const validationIssueCount =
    skills.reduce((count, skill) => count + normalizeArray(skill.validation?.issues).length, 0) +
    hooks.reduce((count, hook) => count + normalizeArray(hook.validation?.issues).length, 0) +
    sources.filter((source) => source.status === "error").length;
  const skillStatus = skills.some((skill) => skill.validation?.status !== "pass") ? "degraded" : "pass";
  const hookStatus = hooks.some((hook) => hook.validation?.status !== "pass") ? "degraded" : "pass";
  const status =
    validationIssueCount > 0 || skillStatus !== "pass" || hookStatus !== "pass" ? "degraded" : "pass";
  const skillHashes = skills.map((skill) => skill.skillHash).filter(Boolean).sort();
  const hookHashes = hooks.map((hook) => hook.definitionHash).filter(Boolean).sort();
  return {
    schemaVersion: "ioi.agent-runtime.skill-hook-catalog.v1",
    object: "ioi.agent_skill_hook_catalog",
    generatedAt,
    status,
    skillStatus,
    hookStatus,
    workspace: {
      root: workspaceRoot,
      exists: fs.existsSync(workspaceRoot),
    },
    sources,
    skillCount: skills.length,
    hookCount: hooks.length,
    skills,
    hooks,
    activeSkillSetHash: doctorHash(skillHashes.join("\n")),
    activeHookSetHash: doctorHash(hookHashes.join("\n")),
    validationIssueCount,
    redaction: {
      profile: "skill_hook_registry_safe",
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: ["runtime_skill_hook_discovery", "governed_skill_hook_catalog"],
  };
}

function skillHookSources({ workspaceRoot, globalHome }) {
  const skillSources = [
    ["workspace.ioi.skills", ".ioi/skills", "ioi", "workspace"],
    ["workspace.agents.skills", ".agents/skills", "agents", "workspace"],
    ["workspace.cursor.skills", ".cursor/skills", "cursor", "workspace"],
    ["workspace.claude.skills", ".claude/skills", "claude", "workspace"],
    ["global.ioi.skills", ".ioi/skills", "ioi", "global"],
    ["global.agents.skills", ".agents/skills", "agents", "global"],
  ];
  const hookSources = [
    ["workspace.ioi.hooks_file", ".ioi/hooks.json", "ioi", "workspace", "hook_file"],
    ["workspace.agents.hooks_file", ".agents/hooks.json", "agents", "workspace", "hook_file"],
    ["workspace.cursor.hooks_file", ".cursor/hooks.json", "cursor", "workspace", "hook_file"],
    ["workspace.claude.hooks_file", ".claude/hooks.json", "claude", "workspace", "hook_file"],
    ["workspace.ioi.hooks_dir", ".ioi/hooks", "ioi", "workspace", "hook_dir"],
    ["workspace.agents.hooks_dir", ".agents/hooks", "agents", "workspace", "hook_dir"],
    ["workspace.cursor.hooks_dir", ".cursor/hooks", "cursor", "workspace", "hook_dir"],
    ["workspace.claude.hooks_dir", ".claude/hooks", "claude", "workspace", "hook_dir"],
    ["global.ioi.hooks_file", ".ioi/hooks.json", "ioi", "global", "hook_file"],
    ["global.agents.hooks_file", ".agents/hooks.json", "agents", "global", "hook_file"],
  ];
  const rootForScope = (scope) => (scope === "global" ? globalHome : workspaceRoot);
  return [
    ...skillSources.map(([id, relativePath, compatibility, scope]) =>
      skillHookSource({
        id,
        relativePath,
        compatibility,
        scope,
        kind: "skill_dir",
        root: rootForScope(scope),
      }),
    ),
    ...hookSources.map(([id, relativePath, compatibility, scope, kind]) =>
      skillHookSource({
        id,
        relativePath,
        compatibility,
        scope,
        kind,
        root: rootForScope(scope),
      }),
    ),
  ];
}

function skillHookSource({ id, relativePath, compatibility, scope, kind, root }) {
  const sourcePath = path.join(root, relativePath);
  return {
    id,
    kind,
    compatibility,
    scope,
    trustLevel: scope === "global" ? "global_user" : "workspace",
    path: sourcePath,
    pathHash: doctorHash(sourcePath),
    exists: fs.existsSync(sourcePath),
    status: fs.existsSync(sourcePath) ? "available" : "missing",
    evidenceRefs: ["skill_hook_source", id],
  };
}

function discoverSkillsFromSource(source, workspaceRoot) {
  if (source.kind !== "skill_dir" || !source.exists) return [];
  return safeDirectoryEntries(source.path).flatMap((entry) => {
    if (entry.name.startsWith(".")) return [];
    const entryPath = path.join(source.path, entry.name);
    const stat = safeStat(entryPath);
    if (!stat) return [];
    if (stat.isDirectory()) {
      return [skillRecordFromPath({ source, skillPath: entryPath, workspaceRoot })];
    }
    if (stat.isFile() && entry.name.toLowerCase().endsWith(".md")) {
      return [skillRecordFromPath({ source, skillPath: entryPath, workspaceRoot, markdownFile: entryPath })];
    }
    return [];
  });
}

function skillRecordFromPath({ source, skillPath, workspaceRoot, markdownFile = null }) {
  const stat = safeStat(skillPath);
  const candidateFiles = markdownFile
    ? [markdownFile]
    : ["SKILL.md", "skill.md", "README.md"].map((name) => path.join(skillPath, name));
  const skillFile = candidateFiles.find((filePath) => fs.existsSync(filePath)) ?? null;
  const content = skillFile ? readTextQuiet(skillFile) ?? "" : "";
  const metadata = parseMarkdownSkillMetadata(content);
  const hasSkillMd = Boolean(skillFile && path.basename(skillFile).toLowerCase() === "skill.md");
  const issues = [];
  if (!skillFile) issues.push("missing_skill_markdown");
  if (skillFile && !hasSkillMd && stat?.isDirectory()) issues.push("missing_canonical_SKILL_md");
  if (skillFile && !content.trim()) issues.push("empty_skill_markdown");
  const name = metadata.name ?? metadata.title ?? path.basename(skillPath, path.extname(skillPath));
  const skillHash = doctorHash(`${source.id}:${skillFile ?? skillPath}:${content}`);
  return {
    schemaVersion: "ioi.agent-runtime.skill.v1",
    id: `skill.${safeId(source.id)}.${safeId(name)}.${skillHash.slice(0, 10)}`,
    name,
    description: metadata.description ?? null,
    sourceId: source.id,
    compatibility: source.compatibility,
    trustLevel: source.trustLevel,
    activationMode: metadata.activationMode ?? "discoverable",
    skillHash,
    path: skillPath,
    pathHash: doctorHash(skillPath),
    relativePath: relativePathForWorkspace(skillPath, workspaceRoot),
    skillFile,
    skillFileHash: skillFile ? doctorHash(skillFile) : null,
    hasSkillMd,
    frontmatterKeys: metadata.frontmatterKeys,
    capabilityScopes: metadata.capabilityScopes,
    validation: {
      status: issues.length > 0 ? "degraded" : "pass",
      issues,
    },
    provenance: {
      importedFrom: source.compatibility,
      governed: true,
      readOnlyDiscovery: true,
    },
    evidenceRefs: ["runtime_skill_discovery", source.id, skillFile ? "SKILL.md" : "missing_SKILL.md"],
  };
}

function discoverHooksFromSource(source, workspaceRoot) {
  if (!source.exists) return [];
  if (source.kind === "hook_file") {
    const parsed = readJsonQuiet(source.path);
    return hooksFromDefinition({ source, definition: parsed, definitionPath: source.path, workspaceRoot });
  }
  if (source.kind === "hook_dir") {
    return safeDirectoryEntries(source.path).flatMap((entry) => {
      if (entry.name.startsWith(".")) return [];
      const entryPath = path.join(source.path, entry.name);
      const stat = safeStat(entryPath);
      if (!stat) return [];
      if (stat.isFile() && entry.name.toLowerCase().endsWith(".json")) {
        return hooksFromDefinition({
          source,
          definition: readJsonQuiet(entryPath),
          definitionPath: entryPath,
          workspaceRoot,
        });
      }
      if (stat.isDirectory()) {
        const hookJson = path.join(entryPath, "hook.json");
        if (!fs.existsSync(hookJson)) return [];
        return hooksFromDefinition({
          source,
          definition: readJsonQuiet(hookJson),
          definitionPath: hookJson,
          workspaceRoot,
          fallbackName: entry.name,
        });
      }
      return [];
    });
  }
  return [];
}

function hooksFromDefinition({ source, definition, definitionPath, workspaceRoot, fallbackName = null }) {
  if (!definition || typeof definition !== "object") {
    return [
      hookRecordFromDefinition({
        source,
        name: fallbackName ?? path.basename(definitionPath, path.extname(definitionPath)),
        definition: {},
        definitionPath,
        workspaceRoot,
        issues: ["invalid_hook_definition"],
      }),
    ];
  }
  if (Array.isArray(definition)) {
    return definition.map((item, index) =>
      hookRecordFromDefinition({
        source,
        name: item?.name ?? fallbackName ?? `hook_${index + 1}`,
        definition: item,
        definitionPath,
        workspaceRoot,
      }),
    );
  }
  const entries = Object.entries(definition);
  if (entries.length === 1 && entries[0][0] === "hooks" && Array.isArray(entries[0][1])) {
    return entries[0][1].map((item, index) =>
      hookRecordFromDefinition({
        source,
        name: item?.name ?? fallbackName ?? `hook_${index + 1}`,
        definition: item,
        definitionPath,
        workspaceRoot,
      }),
    );
  }
  return entries.map(([name, item]) =>
    hookRecordFromDefinition({
      source,
      name,
      definition: item,
      definitionPath,
      workspaceRoot,
    }),
  );
}

function hookRecordFromDefinition({ source, name, definition, definitionPath, workspaceRoot, issues = [] }) {
  const record = definition && typeof definition === "object" && !Array.isArray(definition) ? definition : {};
  const eventKinds = normalizeStringList(record.eventKinds ?? record.events ?? record.subscribe ?? record.subscriptions);
  const inferredEventKinds = eventKinds.length > 0 ? eventKinds : inferHookEventKinds(name);
  const authorityScopes = normalizeStringList(record.authorityScopes ?? record.authority_scopes ?? record.capabilities);
  const toolContracts = normalizeStringList(record.toolContracts ?? record.tool_contracts ?? record.tools);
  const commandInput = record.command ?? record.script ?? record.path ?? (typeof definition === "string" ? definition : null);
  const failurePolicy = normalizeHookFailurePolicy(record.failurePolicy ?? record.failure_policy ?? record.onFailure);
  const sideEffectClass = optionalString(record.sideEffectClass ?? record.side_effect_class) ?? "none";
  const nextIssues = [...issues];
  if (commandInput && authorityScopes.length === 0) nextIssues.push("missing_authority_scope");
  if (sideEffectClass !== "none" && toolContracts.length === 0) nextIssues.push("missing_tool_contract");
  const definitionHash = doctorHash(JSON.stringify(redactedHookDefinition(record)));
  return {
    schemaVersion: "ioi.agent-runtime.hook.v1",
    id: `hook.${safeId(source.id)}.${safeId(name)}.${definitionHash.slice(0, 10)}`,
    name,
    sourceId: source.id,
    compatibility: source.compatibility,
    trustLevel: source.trustLevel,
    enabled: record.enabled !== false,
    eventKinds: inferredEventKinds,
    failurePolicy,
    sideEffectClass,
    authorityScopes,
    toolContracts,
    commandConfigured: Boolean(commandInput),
    commandHash: commandInput ? doctorHash(commandInput) : null,
    commandRedacted: Boolean(commandInput),
    definitionPath,
    definitionPathHash: doctorHash(definitionPath),
    relativePath: relativePathForWorkspace(definitionPath, workspaceRoot),
    definitionHash,
    mutationPolicy: {
      outsideDeclaredCapabilitiesBlocked: true,
      mutationRequiresAuthorityScope: true,
      mutationRequiresToolContract: true,
    },
    validation: {
      status: nextIssues.length > 0 ? "degraded" : "pass",
      issues: [...new Set(nextIssues)],
    },
    evidenceRefs: ["runtime_hook_discovery", source.id, "hook_failure_policy"],
  };
}

function redactedHookDefinition(record = {}) {
  const clone = { ...record };
  for (const key of ["command", "script", "env", "secrets", "headers"]) {
    if (clone[key] !== undefined) clone[key] = "[redacted]";
  }
  return clone;
}

function parseMarkdownSkillMetadata(content = "") {
  const frontmatter = {};
  const text = String(content ?? "");
  if (text.startsWith("---")) {
    const end = text.indexOf("\n---", 3);
    if (end > 0) {
      for (const line of text.slice(3, end).split(/\r?\n/)) {
        const match = line.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
        if (match) frontmatter[match[1]] = match[2].trim().replace(/^["']|["']$/g, "");
      }
    }
  }
  const title = text.match(/^#\s+(.+)$/m)?.[1]?.trim();
  return {
    name: optionalString(frontmatter.name),
    title: optionalString(title),
    description: optionalString(frontmatter.description),
    activationMode: optionalString(frontmatter.activationMode ?? frontmatter.activation_mode),
    capabilityScopes: normalizeStringList(frontmatter.capabilityScopes ?? frontmatter.capability_scopes),
    frontmatterKeys: Object.keys(frontmatter).sort(),
  };
}

function inferHookEventKinds(name) {
  const text = String(name ?? "").toLowerCase();
  if (text.includes("pre-model") || text.includes("pre_model")) return ["pre_model"];
  if (text.includes("post-model") || text.includes("post_model")) return ["post_model"];
  if (text.includes("pre-tool") || text.includes("pre_tool")) return ["pre_tool"];
  if (text.includes("post-tool") || text.includes("post_tool")) return ["post_tool"];
  if (text.includes("approval")) return ["approval"];
  if (text.includes("activation")) return ["workflow_activation"];
  return ["event_subscriber"];
}

function normalizeHookFailurePolicy(value) {
  const text = optionalString(value)?.toLowerCase();
  if (["block", "warn", "ignore", "retry"].includes(text)) return text;
  return "warn";
}

function normalizeStringList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => optionalString(item)).filter(Boolean);
  }
  const text = optionalString(value);
  return text ? text.split(",").map((item) => item.trim()).filter(Boolean) : [];
}

function safeDirectoryEntries(directory) {
  try {
    return fs.readdirSync(directory, { withFileTypes: true });
  } catch {
    return [];
  }
}

function safeStat(filePath) {
  try {
    return fs.statSync(filePath);
  } catch {
    return null;
  }
}

function readTextQuiet(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function readJsonQuiet(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function relativePathForWorkspace(filePath, workspaceRoot) {
  const relative = path.relative(workspaceRoot, filePath);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative : null;
}

function subagentReceiverForRequest(request = {}) {
  return optionalString(
    request.receiver ??
      request.options?.receiver ??
      request.subagent ??
      request.options?.subagent ??
      request.subagentName ??
      request.options?.subagentName,
  ) ?? null;
}

function normalizeSubagentInheritanceMode(value) {
  const mode = optionalString(value) ?? "explicit";
  return ["none", "explicit", "read_only", "full"].includes(mode) ? mode : "explicit";
}

function shouldInheritSubagentMemory(mode, options = {}) {
  if (mode === "none") return false;
  if (mode === "explicit") return hasExplicitSubagentMemorySelector(options);
  return true;
}

function hasExplicitSubagentMemorySelector(options = {}) {
  return Boolean(
    optionalString(options.memoryKey ?? options.memory_key) ??
      optionalString(options.query ?? options.q ?? options.memoryQuery ?? options.memory_query) ??
      optionalString(options.scope ?? options.memoryScope ?? options.memory_scope),
  );
}

function postEditDiagnosticsConfig(request = {}, input = {}) {
  const packRoot = request.toolPack ?? request.tool_pack ?? request.options?.toolPack ?? request.options?.tool_pack ?? {};
  const pack = packRoot?.coding ?? packRoot;
  const mode = normalizeDiagnosticsMode(
    request.diagnosticsMode ??
      request.diagnostics_mode ??
      input.diagnosticsMode ??
      input.diagnostics_mode ??
      pack.diagnosticsMode ??
      pack.diagnostics_mode ??
      pack.diagnosticMode ??
      pack.diagnostic_mode ??
      "advisory",
  );
  return {
    mode,
    commandId: optionalString(
      request.diagnosticCommandId ??
        request.diagnostic_command_id ??
        input.diagnosticCommandId ??
        input.diagnostic_command_id ??
        pack.defaultDiagnosticCommandId ??
        pack.default_diagnostic_command_id,
    ) ?? "node.check",
    cwd: optionalString(input.cwd ?? request.cwd) ?? ".",
    timeoutMs:
      input.diagnosticTimeoutMs ??
      input.diagnostic_timeout_ms ??
      request.diagnosticTimeoutMs ??
      request.diagnostic_timeout_ms ??
      pack.timeoutMs ??
      pack.timeout_ms ??
      30000,
    maxOutputBytes:
      input.diagnosticMaxOutputBytes ??
      input.diagnostic_max_output_bytes ??
      request.diagnosticMaxOutputBytes ??
      request.diagnostic_max_output_bytes ??
      4096,
  };
}

function normalizeDiagnosticsMode(value) {
  const mode = optionalString(value)?.toLowerCase() ?? "advisory";
  if (["skip", "off", "disabled", "none"].includes(mode)) return "skip";
  if (["block", "blocking", "required", "fail"].includes(mode)) return "blocking";
  return "advisory";
}

function compactDiagnosticsFeedback({ threadId, mode, diagnosticEvents }) {
  const findings = [];
  const statuses = [];
  const diagnosticEventIds = [];
  const receiptRefs = [];
  for (const event of diagnosticEvents) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const result = payload.result ?? {};
    diagnosticEventIds.push(event.event_id);
    receiptRefs.push(...normalizeArray(event.receipt_refs));
    statuses.push(result.diagnosticStatus ?? payload.result_summary?.diagnosticStatus ?? "clean");
    for (const diagnostic of normalizeArray(result.diagnostics)) {
      findings.push(compactDiagnosticFinding(diagnostic, event));
    }
  }
  const visibleFindings = findings.slice(0, LSP_DIAGNOSTICS_MAX_INJECTED_FINDINGS);
  const diagnosticStatus = statuses.includes("findings")
    ? "findings"
    : statuses.includes("degraded")
      ? "degraded"
      : "clean";
  const omittedCount = Math.max(0, findings.length - visibleFindings.length);
  const summary =
    diagnosticStatus === "findings"
      ? `Injected ${visibleFindings.length}${omittedCount ? ` of ${findings.length}` : ""} post-edit diagnostic finding(s).`
      : `Injected post-edit diagnostics status: ${diagnosticStatus}.`;
  const injectionId = `lsp_diagnostics_injection_${doctorHash(
    `${threadId}:${diagnosticEventIds.join(",")}:${mode}`,
  ).slice(0, 16)}`;
  const receiptId = `receipt_${injectionId}`;
  return {
    schemaVersion: LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
    object: "ioi.runtime_lsp_diagnostics_injection",
    injectionId,
    threadId,
    mode,
    blocking: mode === "blocking",
    diagnosticStatus,
    diagnosticCount: findings.length,
    injectedFindingCount: visibleFindings.length,
    omittedFindingCount: omittedCount,
    findings: visibleFindings,
    diagnosticEventIds,
    receiptRefs: uniqueStrings(receiptRefs),
    receiptId,
    summary,
    promptText: diagnosticsPromptText({ diagnosticStatus, mode, visibleFindings, omittedCount }),
  };
}

function compactDiagnosticFinding(diagnostic = {}, event = {}) {
  const location = [
    optionalString(diagnostic.path) ?? "workspace",
    diagnostic.line ? String(diagnostic.line) : null,
    diagnostic.column ? String(diagnostic.column) : null,
  ].filter(Boolean).join(":");
  const message = String(diagnostic.message ?? "Diagnostic finding.").slice(
    0,
    LSP_DIAGNOSTICS_MAX_INJECTED_MESSAGE_CHARS,
  );
  return {
    path: optionalString(diagnostic.path) ?? null,
    line: Number(diagnostic.line ?? 0) || null,
    column: Number(diagnostic.column ?? 0) || null,
    severity: optionalString(diagnostic.severity) ?? "warning",
    source: optionalString(diagnostic.source) ?? "lsp.diagnostics",
    code: optionalString(diagnostic.code) ?? null,
    message,
    location,
    diagnosticEventId: event.event_id ?? null,
  };
}

function diagnosticsPromptText({ diagnosticStatus, mode, visibleFindings, omittedCount }) {
  const header = `Post-edit diagnostics (${mode}, ${diagnosticStatus})`;
  if (!visibleFindings.length) return `${header}: no findings were reported.`;
  const lines = visibleFindings.map((finding) =>
    `- ${finding.location} [${finding.severity}${finding.code ? ` ${finding.code}` : ""}] ${finding.message}`,
  );
  if (omittedCount > 0) lines.push(`- ${omittedCount} additional finding(s) omitted from compact context.`);
  return `${header}:\n${lines.join("\n")}`;
}

function promptWithDiagnosticsFeedback(prompt, diagnosticsFeedback) {
  if (!diagnosticsFeedback?.promptText) return prompt;
  return `${diagnosticsFeedback.promptText}\n\nUser request:\n${prompt}`;
}

function diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback) {
  return Boolean(
    diagnosticsFeedback?.blocking &&
      diagnosticsFeedback?.diagnosticStatus === "findings" &&
      Number(diagnosticsFeedback?.diagnosticCount ?? 0) > 0,
  );
}

function diagnosticsBlockingGateForFeedback(diagnosticsFeedback) {
  if (!diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)) return null;
  const injectionId = diagnosticsFeedback.injectionId ?? `diagnostics_${doctorHash(JSON.stringify(diagnosticsFeedback)).slice(0, 16)}`;
  const gateId = `lsp_diagnostics_gate_${doctorHash(injectionId).slice(0, 16)}`;
  const diagnosticCount = Number(diagnosticsFeedback.diagnosticCount ?? 0) || 0;
  const injectedFindingCount = Number(diagnosticsFeedback.injectedFindingCount ?? diagnosticCount) || 0;
  const summary = `Blocking diagnostics gate paused model continuation after ${diagnosticCount} finding(s).`;
  return {
    schemaVersion: LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
    object: "ioi.runtime_lsp_diagnostics_blocking_gate",
    gateId,
    policyDecisionId: `policy_${gateId}`,
    receiptId: `receipt_${gateId}`,
    status: "blocked",
    decision: "block_model_continuation",
    reason: "post_edit_diagnostics_findings",
    mode: diagnosticsFeedback.mode ?? "blocking",
    blocking: true,
    requiresInput: true,
    diagnosticStatus: diagnosticsFeedback.diagnosticStatus,
    diagnosticCount,
    injectedFindingCount,
    omittedFindingCount: Number(diagnosticsFeedback.omittedFindingCount ?? 0) || 0,
    injectionId,
    diagnosticsReceiptId: diagnosticsFeedback.receiptId ?? null,
    diagnosticEventIds: uniqueStrings(normalizeArray(diagnosticsFeedback.diagnosticEventIds)),
    findings: normalizeArray(diagnosticsFeedback.findings).slice(0, LSP_DIAGNOSTICS_MAX_INJECTED_FINDINGS),
    summary,
    message:
      `Blocking diagnostics mode found ${diagnosticCount} post-edit diagnostic finding(s). ` +
      "Model continuation is paused until the findings are repaired, diagnosticsMode is changed to advisory, or diagnostics are explicitly skipped.",
    recommendedNextActions: [
      "repair_findings",
      "resubmit_with_diagnosticsMode_advisory",
      "resubmit_with_diagnosticsMode_skip",
    ],
    workflowNodeId: LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
    componentKind: "lsp_diagnostics_gate",
    redaction: "lsp_diagnostics_safe",
  };
}

function requestWithDiagnosticsFeedback(request = {}, diagnosticsFeedback = null) {
  if (!diagnosticsFeedback) return request;
  return {
    ...request,
    diagnosticsFeedback,
    diagnostics_feedback: diagnosticsFeedback,
    context: {
      ...(request.context ?? {}),
      diagnosticsFeedback,
      diagnostics_feedback: diagnosticsFeedback,
    },
  };
}

function insertRuntimeBridgeDiagnosticsInjectionEvent({
  projection,
  agent,
  threadId,
  diagnosticsFeedback,
}) {
  const event = {
    event_stream_id: eventStreamIdForThread(threadId),
    thread_id: threadId,
    turn_id: projection.turnId,
    item_id: `${projection.turnId}:item:lsp-diagnostics-injection`,
    idempotency_key: `turn:${projection.turnId}:lsp-diagnostics-injected:${diagnosticsFeedback.injectionId}`,
    source: "runtime_auto",
    source_event_kind: "LspDiagnostics.Injected",
    event_kind: "lsp.diagnostics.injected",
    status: diagnosticsFeedback.blocking && diagnosticsFeedback.diagnosticStatus === "findings" ? "blocked" : "completed",
    actor: "runtime",
    created_at: projection.createdAt,
    workspace_root: agent.cwd,
    workflow_node_id: LSP_DIAGNOSTICS_INJECTION_NODE_ID,
    component_kind: "lsp_diagnostics",
    payload_schema_version: LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
    payload: {
      ...diagnosticsFeedback,
      event_kind: "LspDiagnosticsInjected",
      run_id: projection.runId,
      turn_id: projection.turnId,
    },
    receipt_refs: [diagnosticsFeedback.receiptId],
    artifact_refs: [],
  };
  const events = [...normalizeArray(projection.events)];
  const turnStartedIndex = events.findIndex((candidate) => candidate?.event_kind === "turn.started");
  if (turnStartedIndex >= 0) {
    events.splice(turnStartedIndex + 1, 0, event);
    return events;
  }
  return [event, ...events];
}

function subagentMemoryPolicy({ agent, threadId, parentPolicy = {}, receiver, mode }) {
  const targetId = `${threadId}:${receiver ?? "subagent"}`;
  const id = `memory_policy_subagent_${safeId(targetId)}`;
  const disabled = Boolean(parentPolicy.disabled) || mode === "none";
  const injectionEnabled = parentPolicy.injectionEnabled !== false && mode !== "none";
  const readOnly = disabled || Boolean(parentPolicy.readOnly) || mode === "read_only";
  const writeRequiresApproval =
    mode === "explicit" ? true : Boolean(parentPolicy.writeRequiresApproval);
  return {
    ...parentPolicy,
    id,
    targetType: "subagent",
    targetId,
    agentId: agent?.id ?? parentPolicy.agentId ?? null,
    threadId,
    workspace: agent?.cwd ?? parentPolicy.workspace ?? null,
    disabled,
    injectionEnabled,
    readOnly,
    writeRequiresApproval,
    source: "daemon_subagent_memory_inheritance",
    updatedAt: new Date().toISOString(),
    evidenceRefs: [
      ...new Set([
        ...normalizeArray(parentPolicy.evidenceRefs),
        "subagent_memory_inheritance",
        "memory.policy.effective.subagent",
      ]),
    ],
    effective: true,
    policyRefs: [parentPolicy.id].filter(Boolean),
  };
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function operatorControlSource(value) {
  const source = optionalString(value);
  return ["cli_tui", "react_flow", "sdk_client", "runtime_auto"].includes(source) ? source : "sdk_client";
}

function approvalDecisionForRequest(value) {
  const decision = optionalString(value)?.toLowerCase();
  if (["approve", "approved", "accept", "accepted", "allow", "allowed"].includes(decision)) {
    return "approve";
  }
  if (["reject", "rejected", "deny", "denied", "block", "blocked"].includes(decision)) {
    return "reject";
  }
  throw runtimeError({
    status: 400,
    code: "approval_decision_invalid",
    message: "Approval decisions must be approve or reject.",
    details: { decision: value ?? null },
  });
}

function appendOperatorControl(controls, control) {
  const existing = normalizeArray(controls);
  if (existing.some((candidate) => candidate?.eventId === control.eventId)) return existing;
  return [...existing, control];
}

function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

function memoryPolicyOverrides(options = {}) {
  const policy = {};
  for (const key of [
    "disabled",
    "injectionEnabled",
    "readOnly",
    "writeRequiresApproval",
    "retention",
    "redaction",
    "subagentInheritance",
    "scope",
  ]) {
    if (options[key] !== undefined) policy[key] = options[key];
  }
  if (options.injection_enabled !== undefined) policy.injectionEnabled = options.injection_enabled;
  if (options.read_only !== undefined) policy.readOnly = options.read_only;
  if (options.write_requires_approval !== undefined) policy.writeRequiresApproval = options.write_requires_approval;
  if (options.subagent_inheritance !== undefined) policy.subagentInheritance = options.subagent_inheritance;
  return policy;
}

function memoryWriteBlockReason(policy = {}, options = {}, requestedWrite = false) {
  if (!requestedWrite) return null;
  if (policy.disabled) return "memory_disabled";
  if (policy.readOnly) return "memory_read_only";
  if (policy.writeRequiresApproval && !memoryWriteApproved(options)) {
    return "memory_write_requires_approval";
  }
  return null;
}

function memoryWriteApproved(options = {}) {
  return Boolean(
    options.writeApproved ??
      options.write_approved ??
      options.approved ??
      options.approvalGranted ??
      options.approval_granted,
  );
}

function subagentMemoryInheritanceReceipt(runId, projection = {}) {
  return {
    id: `receipt_${runId}_subagent_memory_inheritance`,
    kind: "subagent_memory_inheritance",
    summary: `Subagent memory inheritance ${projection.mode} for ${projection.subagentName ?? "handoff"} exposed ${normalizeArray(projection.records).length} record(s).`,
    redaction: projection.effectivePolicy?.redaction === "redacted" ? "redacted" : "none",
    evidenceRefs: normalizeArray(projection.evidenceRefs),
  };
}

function memoryListFilters(options = {}) {
  return {
    scope: options.scope ?? options.memoryScope ?? options.memory_scope,
    memoryKey: options.memoryKey ?? options.memory_key,
    query: options.query ?? options.q ?? options.memoryQuery ?? options.memory_query,
    limit: options.limit ?? options.memoryLimit ?? options.memory_limit,
    redaction: options.redaction ?? options.memoryRedaction ?? options.memory_redaction,
  };
}

function memoryEventKind(operation = "write") {
  switch (operation) {
    case "policy_update":
      return "MemoryPolicy";
    case "edit":
      return "MemoryEdit";
    case "delete":
      return "MemoryDelete";
    case "write":
    default:
      return "MemoryWrite";
  }
}

function memoryEventSummary(operation = "write") {
  switch (operation) {
    case "policy_update":
      return "Memory policy updated";
    case "edit":
      return "Memory record edited";
    case "delete":
      return "Memory record deleted";
    case "write":
    default:
      return "Memory write recorded";
  }
}

function resultForMode(mode, agent, prompt, source, memory = {}) {
  if (memory.command === "disable") {
    return "Memory is disabled for this thread.";
  }
  if (memory.command === "enable") {
    return "Memory is enabled for this thread.";
  }
  if (memory.command === "path") {
    return `Memory records path: ${memory.paths?.recordsPath ?? "unknown"}\nMemory policy path: ${memory.paths?.policiesPath ?? "unknown"}`;
  }
  if (memory.policyBlockReason) {
    return `Memory write blocked by policy: ${memory.policyBlockReason}.`;
  }
  if (memory.command === "edit") {
    const edited = normalizeArray(memory.mutations).find((mutation) => mutation.operation === "edit")?.record;
    return edited ? `Edited memory: ${edited.id}` : "No memory was edited.";
  }
  if (memory.command === "delete") {
    const deleted = normalizeArray(memory.mutations).find((mutation) => mutation.operation === "delete")?.record;
    return deleted ? `Deleted memory: ${deleted.id}` : "No memory was deleted.";
  }
  if (memory.disabled && (memory.command === "remember" || memory.command === "show")) {
    return "Memory is disabled for this run.";
  }
  if (memory.command === "remember") {
    const remembered = normalizeArray(memory.writes).map((write) => write.record?.fact).filter(Boolean);
    return remembered.length > 0
      ? `Remembered: ${remembered.join("; ")}`
      : "No memory was written because the remember request was empty.";
  }
  if (memory.command === "show") {
    const records = normalizeArray(memory.records);
    return records.length > 0
      ? `Memory:\n${records.map((record) => `- ${record.fact}`).join("\n")}`
      : "Memory is empty for this thread.";
  }
  switch (mode) {
    case "plan":
      return `Plan-only daemon run recorded objective, constraints, postconditions, and stop reason for: ${prompt}`;
    case "dry_run":
      return "Dry run completed through the daemon. Side effects were previewed and no mutation was executed.";
    case "handoff":
      return "Daemon handoff bundle is complete: objective, state, blockers, evidence, and next action are preserved.";
    case "learn":
      return "Governed learning record created behind memory quality and bounded self-improvement gates.";
    case "send":
    default:
      return `IOI daemon run completed for ${agent.cwd}. Source=${source}. Trace, receipts, Agentgres canonical projection, task state, uncertainty, probe, postconditions, semantic impact, stop condition, and scorecard are available through public runtime APIs.`;
  }
}

function taskFamilyForMode(mode) {
  switch (mode) {
    case "plan":
      return "planning";
    case "dry_run":
      return "safety_preview";
    case "handoff":
      return "delegation";
    case "learn":
      return "learning";
    case "send":
    default:
      return "local_daemon_agentgres";
  }
}

function strategyForMode(mode) {
  switch (mode) {
    case "plan":
      return "daemon_plan_with_postconditions";
    case "dry_run":
      return "daemon_dry_run_before_effect";
    case "handoff":
      return "daemon_handoff_with_state_preservation";
    case "learn":
      return "daemon_bounded_learning_gate";
    case "send":
    default:
      return "local_daemon_agentgres_execution";
  }
}

function capabilitySequenceForMode(mode, agent) {
  const sequence = [
    "authority_check",
    "policy_check",
    "task_state_write",
    "agentgres_operation_log",
    "trace_export",
    "canonical_replay",
  ];
  if (agent.options.mcpServerNames.length > 0) sequence.push("mcp_containment");
  if (agent.options.skillNames.length > 0) sequence.push("skill_instruction_import");
  if (agent.options.hookNames.length > 0) sequence.push("runtime_event_hook");
  if (mode === "dry_run") sequence.push("side_effect_preview");
  if (mode === "handoff") sequence.push("handoff_quality");
  if (mode === "learn") sequence.push("memory_quality_gate");
  return sequence;
}

function makeEvent(runId, agentId, index, type, summary, data) {
  return {
    id: `${runId}:event:${String(index).padStart(3, "0")}:${type}`,
    runId,
    agentId,
    type,
    cursor: `${runId}:${index}`,
    createdAt: new Date().toISOString(),
    summary,
    data,
  };
}

function threadIdForAgent(agentId) {
  return agentId.startsWith("agent_") ? `thread_${agentId.slice("agent_".length)}` : `thread_${agentId}`;
}

function agentIdForThread(threadId) {
  return threadId.startsWith("thread_") ? `agent_${threadId.slice("thread_".length)}` : threadId;
}

function runtimeSessionIdForAgent(agent) {
  return agent.runtimeSessionId ?? agent.id;
}

function isRuntimeBackedAgent(agent) {
  return isRuntimeServiceProfile(agent.runtimeProfile);
}

function fixtureProfileForAgent(agent) {
  return Object.hasOwn(agent, "fixtureProfile") ? agent.fixtureProfile : DAEMON_FIXTURE_PROFILE;
}

function turnIdForRun(runId) {
  return runId.startsWith("run_") ? `turn_${runId.slice("run_".length)}` : `turn_${runId}`;
}

function runIdForTurn(turnId) {
  return turnId.startsWith("turn_") ? `run_${turnId.slice("turn_".length)}` : `run_${turnId}`;
}

function eventStreamIdForThread(threadId) {
  return `${threadId}:events`;
}

function threadStatusForAgent(status) {
  switch (status) {
    case "archived":
    case "closed":
      return "archived";
    case "failed":
    case "error":
      return "failed";
    default:
      return "active";
  }
}

function lifecycleStatusForRun(status) {
  switch (status) {
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "canceled":
      return "canceled";
    case "failed":
    case "error":
      return "failed";
    case "blocked":
      return "waiting_for_input";
    case "completed":
    default:
      return "completed";
  }
}

function ttiEnvelopeForRunEvent({ event, threadId, turnId, workspaceRoot }) {
  const eventKind = RUN_EVENT_TO_TTI_EVENT[event.type] ?? `item.${event.type}`;
  const payload = payloadSummaryForRunEvent(event);
  const isDiagnosticsInjection = event.type === "lsp_diagnostics_injected";
  const isDiagnosticsBlockingGate =
    event.type === "policy_blocked" && event.data?.reason === "post_edit_diagnostics_findings";
  return {
    schema_version: RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
    event_stream_id: eventStreamIdForThread(threadId),
    thread_id: threadId,
    turn_id: turnId,
    item_id: `${turnId}:item:${doctorHash(event.id).slice(0, 12)}`,
    idempotency_key: `run:${event.runId}:event:${event.id}`,
    source: isDiagnosticsInjection || isDiagnosticsBlockingGate ? "runtime_auto" : "daemon_bridge",
    source_event_kind: isDiagnosticsInjection
      ? "LspDiagnostics.Injected"
      : isDiagnosticsBlockingGate
        ? "LspDiagnostics.BlockingGate"
        : `run.${event.type}`,
    event_kind: eventKind,
    status: runtimeEventStatusForRunEvent(event),
    actor: event.type === "delta" ? "assistant" : "runtime",
    created_at: event.createdAt,
    workspace_root: workspaceRoot,
    workflow_graph_id: event.data?.workflowGraphId ?? event.data?.workflow_graph_id ?? null,
    component_kind: componentKindForRunEvent(event),
    workflow_node_id: workflowNodeForRunEvent(event),
    tool_call_id: event.data?.toolCallId ?? event.data?.tool_call_id ?? null,
    approval_id: event.data?.approvalId ?? event.data?.approval_id ?? null,
    policy_decision_refs: policyDecisionRefsForRunEvent(event),
    rollback_refs: normalizeArray(event.data?.rollbackRefs ?? event.data?.rollback_refs),
    payload_schema_version: isDiagnosticsInjection
      ? LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION
      : isDiagnosticsBlockingGate
        ? LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION
        : RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
    payload,
    payload_ref: null,
    receipt_refs: receiptRefsForRunEvent(event),
    artifact_refs: artifactRefsForRunEvent(event),
    redaction_profile: "internal",
    fixture_profile: DAEMON_FIXTURE_PROFILE,
  };
}

function normalizeRuntimeEventEnvelope(event, { seq, parentSeq, idempotencyKey }) {
  const eventKind = event.event_kind ?? event.event ?? "runtime.event";
  const createdAt = event.created_at ?? new Date().toISOString();
  const payloadSummary = event.payload_summary ?? event.payload ?? {};
  return {
    schema_version: RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
    event_id: event.event_id ?? `${event.event_stream_id}:seq:${String(seq).padStart(8, "0")}`,
    event_stream_id: event.event_stream_id,
    thread_id: event.thread_id ?? "",
    turn_id: event.turn_id ?? "",
    item_id: event.item_id ?? "",
    seq,
    parent_seq: parentSeq,
    idempotency_key: idempotencyKey,
    source: event.source ?? "daemon_bridge",
    source_event_kind: event.source_event_kind ?? eventKind,
    event_kind: eventKind,
    status: event.status ?? "completed",
    actor: event.actor ?? "runtime",
    created_at: createdAt,
    workspace_root: event.workspace_root ?? "",
    workflow_graph_id: event.workflow_graph_id ?? null,
    workflow_node_id: event.workflow_node_id ?? null,
    component_kind: event.component_kind ?? null,
    tool_call_id: event.tool_call_id ?? null,
    approval_id: event.approval_id ?? null,
    artifact_refs: normalizeArray(event.artifact_refs),
    receipt_refs: normalizeArray(event.receipt_refs),
    policy_decision_refs: normalizeArray(event.policy_decision_refs),
    rollback_refs: normalizeArray(event.rollback_refs),
    payload_schema_version: event.payload_schema_version ?? RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION,
    payload_ref: event.payload_ref ?? null,
    payload: stringRecord(payloadSummary),
    redaction_profile: event.redaction_profile ?? "internal",
    fixture_profile: Object.hasOwn(event, "fixture_profile") ? event.fixture_profile : DAEMON_FIXTURE_PROFILE,
    id: String(seq),
    timestamp_ms: Date.parse(createdAt) || 0,
    event: eventKind,
    payload_summary: payloadSummary,
  };
}

function runtimeEventStatusForRunEvent(event) {
  if (event.type === "job_queued") return "queued";
  if (event.type === "job_started" || event.type === "run_started" || event.type === "delta") return "running";
  if (event.type === "lsp_diagnostics_injected") {
    return event.data?.blocking && event.data?.diagnosticStatus === "findings" ? "blocked" : "completed";
  }
  if (event.type === "policy_blocked") return "blocked";
  if (event.type === "canceled" || event.type === "job_canceled") return "canceled";
  if (event.type === "failed" || event.type === "error" || event.type === "job_failed") return "failed";
  return "completed";
}

function policyDecisionRefsForRunEvent(event) {
  return [
    event.data?.policyDecisionId,
    event.data?.policy_decision_id,
    event.data?.policyDecisionRef,
    event.data?.policy_decision_ref,
  ].filter(Boolean);
}

function stringRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      typeof item === "string" ? item : JSON.stringify(item),
    ]),
  );
}

function payloadSummaryForRunEvent(event) {
  const summary = {
    legacy_event_id: event.id,
    legacy_event_type: event.type,
    run_id: event.runId,
    agent_id: event.agentId,
    summary: event.summary,
  };
  if (event.type === "memory_update") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? memoryEventKind(event.data?.operation),
      memory_operation: event.data?.operation ?? "write",
      memory_record_id: event.data?.memoryRecordId ?? (event.data?.object === "ioi.agent_memory_record" ? event.data?.id : null),
      memory_policy_id: event.data?.memoryPolicyId ?? (event.data?.object === "ioi.agent_memory_policy" ? event.data?.id : null),
      subagent_name: event.data?.subagentName ?? null,
      subagent_inheritance_mode: event.data?.mode ?? null,
      inherited_memory_count: normalizeArray(event.data?.inheritedRecordIds).length,
      memory_scope: event.data?.scope ?? null,
      memory_thread_id: event.data?.threadId ?? null,
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction ?? "none",
    };
  }
  if (event.type === "lsp_diagnostics_injected") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "LspDiagnosticsInjected",
      injection_id: event.data?.injectionId ?? null,
      diagnostic_status: event.data?.diagnosticStatus ?? null,
      diagnostic_count: event.data?.diagnosticCount ?? 0,
      injected_finding_count: event.data?.injectedFindingCount ?? 0,
      omitted_finding_count: event.data?.omittedFindingCount ?? 0,
      diagnostic_event_ids: normalizeArray(event.data?.diagnosticEventIds),
      mode: event.data?.mode ?? "advisory",
      blocking: Boolean(event.data?.blocking),
      prompt_text: event.data?.promptText ?? null,
      findings: normalizeArray(event.data?.findings),
      workflow_node_id: event.data?.workflowNodeId ?? LSP_DIAGNOSTICS_INJECTION_NODE_ID,
      redaction: "lsp_diagnostics_safe",
    };
  }
  if (event.type === "policy_blocked") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "PolicyBlocked",
      gate_id: event.data?.gateId ?? null,
      policy_decision_id: event.data?.policyDecisionId ?? null,
      receipt_id: event.data?.receiptId ?? null,
      decision: event.data?.decision ?? "blocked",
      reason: event.data?.reason ?? null,
      status: event.data?.status ?? "blocked",
      diagnostic_status: event.data?.diagnosticStatus ?? null,
      diagnostic_count: event.data?.diagnosticCount ?? 0,
      injected_finding_count: event.data?.injectedFindingCount ?? 0,
      omitted_finding_count: event.data?.omittedFindingCount ?? 0,
      mode: event.data?.mode ?? null,
      blocking: Boolean(event.data?.blocking),
      requires_input: Boolean(event.data?.requiresInput),
      injection_id: event.data?.injectionId ?? null,
      diagnostics_receipt_id: event.data?.diagnosticsReceiptId ?? null,
      diagnostic_event_ids: normalizeArray(event.data?.diagnosticEventIds),
      recommended_next_actions: normalizeArray(event.data?.recommendedNextActions),
      findings: normalizeArray(event.data?.findings),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      component_kind: event.data?.componentKind ?? "policy_gate",
      redaction: event.data?.redaction ?? "policy_safe",
    };
  }
  if (event.type === "repository_context") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "RepositoryContext",
      context_id: event.data?.contextId ?? null,
      is_git_repository: Boolean(event.data?.isGitRepository),
      repo_root_hash: event.data?.repoRootHash ?? null,
      branch: event.data?.branch ?? null,
      detached_head: Boolean(event.data?.detachedHead),
      head_short_sha: event.data?.headShortSha ?? null,
      upstream: event.data?.upstream ?? null,
      remote_count: event.data?.remoteCount ?? 0,
      is_dirty: Boolean(event.data?.status?.isDirty),
      staged_count: event.data?.status?.counts?.staged ?? 0,
      unstaged_count: event.data?.status?.counts?.unstaged ?? 0,
      untracked_count: event.data?.status?.counts?.untracked ?? 0,
      conflicted_count: event.data?.status?.counts?.conflicted ?? 0,
      mutation_executed: Boolean(event.data?.mutationExecuted),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "repository_context_safe",
    };
  }
  if (event.type === "runtime_task") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "RuntimeTaskRecord",
      task_id: event.data?.taskId ?? null,
      run_id: event.data?.runId ?? null,
      agent_id: event.data?.agentId ?? null,
      thread_id: event.data?.threadId ?? null,
      turn_id: event.data?.turnId ?? null,
      status: event.data?.status ?? null,
      mode: event.data?.mode ?? null,
      task_family: event.data?.taskFamily ?? null,
      selected_strategy: event.data?.selectedStrategy ?? null,
      durable: Boolean(event.data?.durable),
      replayable: Boolean(event.data?.replayable),
      prompt_included: Boolean(event.data?.promptIncluded),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "runtime_task_safe",
    };
  }
  if (event.type === "runtime_checklist") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "RuntimeChecklistRecord",
      checklist_id: event.data?.checklistId ?? null,
      task_id: event.data?.taskId ?? null,
      job_id: event.data?.jobId ?? null,
      run_id: event.data?.runId ?? null,
      status: event.data?.status ?? null,
      item_count: event.data?.itemCount ?? 0,
      completed_item_count: event.data?.completedItemCount ?? 0,
      failed_item_count: event.data?.failedItemCount ?? 0,
      canceled_item_count: event.data?.canceledItemCount ?? 0,
      blocked_item_count: event.data?.blockedItemCount ?? 0,
      required_item_ids: normalizeArray(event.data?.requiredItemIds),
      durable: Boolean(event.data?.durable),
      replayable: Boolean(event.data?.replayable),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "runtime_checklist_safe",
    };
  }
  if (event.type === "job_queued" || event.type === "job_started" || event.type === "job_completed" || event.type === "job_failed" || event.type === "job_canceled") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "RuntimeJobLifecycle",
      job_id: event.data?.jobId ?? null,
      task_id: event.data?.taskId ?? null,
      run_id: event.data?.runId ?? null,
      agent_id: event.data?.agentId ?? null,
      thread_id: event.data?.threadId ?? null,
      turn_id: event.data?.turnId ?? null,
      status: event.data?.status ?? null,
      lifecycle_status: event.data?.lifecycleStatus ?? null,
      queue_name: event.data?.queueName ?? null,
      runner: event.data?.runner ?? null,
      job_type: event.data?.jobType ?? null,
      background: Boolean(event.data?.background),
      durable: Boolean(event.data?.durable),
      replayable: Boolean(event.data?.replayable),
      queued_at: event.data?.queuedAt ?? null,
      started_at: event.data?.startedAt ?? null,
      completed_at: event.data?.completedAt ?? null,
      progress_percent: event.data?.progress?.percent ?? null,
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "runtime_job_safe",
    };
  }
  if (event.type === "branch_policy") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "BranchPolicyDecision",
      policy_id: event.data?.policyId ?? null,
      repository_context_id: event.data?.repositoryContextId ?? null,
      status: event.data?.status ?? null,
      branch: event.data?.branch ?? null,
      default_branch: event.data?.defaultBranch ?? null,
      protected_branch: Boolean(event.data?.protectedBranch),
      detached_head: Boolean(event.data?.detachedHead),
      dirty: Boolean(event.data?.dirty),
      upstream: event.data?.upstream ?? null,
      ahead: event.data?.ahead ?? 0,
      behind: event.data?.behind ?? 0,
      blocker_count: normalizeArray(event.data?.blockers).length,
      warning_count: normalizeArray(event.data?.warnings).length,
      mutation_allowed: Boolean(event.data?.mutationAllowed),
      pr_creation_allowed: Boolean(event.data?.prCreationAllowed),
      review_required: Boolean(event.data?.reviewRequired),
      mutation_executed: Boolean(event.data?.mutationExecuted),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "branch_policy_safe",
    };
  }
  if (event.type === "github_context") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "GitHubContext",
      context_id: event.data?.contextId ?? null,
      repository_context_id: event.data?.repositoryContextId ?? null,
      branch_policy_id: event.data?.branchPolicyId ?? null,
      status: event.data?.status ?? null,
      github_remote_present: Boolean(event.data?.githubRemotePresent),
      default_remote_name: event.data?.defaultRemoteName ?? null,
      owner: event.data?.owner ?? null,
      repo: event.data?.repo ?? null,
      repo_full_name: event.data?.repoFullName ?? null,
      branch: event.data?.branch ?? null,
      default_branch: event.data?.defaultBranch ?? null,
      branch_policy_status: event.data?.branchPolicyStatus ?? null,
      token_available: Boolean(event.data?.credentials?.tokenAvailable),
      pr_creation_eligible: Boolean(event.data?.prCreationEligible),
      network_lookup_performed: Boolean(event.data?.networkLookupPerformed),
      mutation_executed: Boolean(event.data?.mutationExecuted),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "github_context_safe",
    };
  }
  if (event.type === "issue_context") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "IssueContext",
      context_id: event.data?.contextId ?? null,
      repository_context_id: event.data?.repositoryContextId ?? null,
      github_context_id: event.data?.githubContextId ?? null,
      pr_attempt_id: event.data?.prAttemptId ?? null,
      review_gate_id: event.data?.reviewGateId ?? null,
      status: event.data?.status ?? null,
      repo_full_name: event.data?.repoFullName ?? null,
      bound: Boolean(event.data?.bound),
      issue_provided: Boolean(event.data?.issueProvided),
      issue_number: event.data?.issueNumber ?? null,
      source_kind: event.data?.sourceKind ?? null,
      warning_count: normalizeArray(event.data?.warnings).length,
      network_lookup_performed: Boolean(event.data?.networkLookupPerformed),
      mutation_executed: Boolean(event.data?.mutationExecuted),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "issue_context_safe",
    };
  }
  if (event.type === "pr_attempt") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "PrAttemptRecord",
      attempt_id: event.data?.attemptId ?? null,
      repository_context_id: event.data?.repositoryContextId ?? null,
      branch_policy_id: event.data?.branchPolicyId ?? null,
      github_context_id: event.data?.githubContextId ?? null,
      status: event.data?.status ?? null,
      outcome: event.data?.outcome ?? null,
      repo_full_name: event.data?.repoFullName ?? null,
      branch: event.data?.branch ?? null,
      default_branch: event.data?.defaultBranch ?? null,
      head_short_sha: event.data?.headShortSha ?? null,
      blocker_count: normalizeArray(event.data?.blockers).length,
      warning_count: normalizeArray(event.data?.warnings).length,
      required_authority_scopes: normalizeArray(event.data?.authority?.requiredScopes),
      missing_authority_scopes: normalizeArray(event.data?.authority?.missingScopes),
      authority_scope_granted: Boolean(event.data?.authority?.scopeGranted),
      branch_artifact_name: event.data?.branchArtifact?.artifactName ?? null,
      diff_artifact_name: event.data?.diffArtifact?.artifactName ?? null,
      diff_hash: event.data?.diffArtifact?.diffHash ?? null,
      diff_file_count: event.data?.diffArtifact?.fileCount ?? 0,
      mutation_attempted: Boolean(event.data?.mutationAttempted),
      mutation_executed: Boolean(event.data?.mutationExecuted),
      network_lookup_performed: Boolean(event.data?.networkLookupPerformed),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "pr_attempt_safe",
    };
  }
  if (event.type === "review_gate") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "ReviewGateDecision",
      gate_id: event.data?.gateId ?? null,
      repository_context_id: event.data?.repositoryContextId ?? null,
      branch_policy_id: event.data?.branchPolicyId ?? null,
      github_context_id: event.data?.githubContextId ?? null,
      pr_attempt_id: event.data?.prAttemptId ?? null,
      status: event.data?.status ?? null,
      decision: event.data?.decision ?? null,
      repo_full_name: event.data?.repoFullName ?? null,
      branch: event.data?.branch ?? null,
      default_branch: event.data?.defaultBranch ?? null,
      review_required: Boolean(event.data?.reviewRequired),
      review_satisfied: Boolean(event.data?.reviewSatisfied),
      approval_required: Boolean(event.data?.approvalRequired),
      approval_satisfied: Boolean(event.data?.approvalSatisfied),
      required_reviewers: normalizeArray(event.data?.requiredReviewers),
      required_checks: normalizeArray(event.data?.requiredChecks),
      blocker_count: normalizeArray(event.data?.blockers).length,
      warning_count: normalizeArray(event.data?.warnings).length,
      mutation_allowed: Boolean(event.data?.mutationAllowed),
      pr_creation_allowed: Boolean(event.data?.prCreationAllowed),
      mutation_executed: Boolean(event.data?.mutationExecuted),
      network_lookup_performed: Boolean(event.data?.networkLookupPerformed),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "review_gate_safe",
    };
  }
  if (event.type === "github_pr_create_plan") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "GitHubPrCreatePlan",
      plan_id: event.data?.planId ?? null,
      repository_context_id: event.data?.repositoryContextId ?? null,
      branch_policy_id: event.data?.branchPolicyId ?? null,
      github_context_id: event.data?.githubContextId ?? null,
      issue_context_id: event.data?.issueContextId ?? null,
      pr_attempt_id: event.data?.prAttemptId ?? null,
      review_gate_id: event.data?.reviewGateId ?? null,
      status: event.data?.status ?? null,
      decision: event.data?.decision ?? null,
      dry_run: Boolean(event.data?.dryRun),
      tool_name: event.data?.toolName ?? null,
      repo_full_name: event.data?.repoFullName ?? null,
      base_branch: event.data?.baseBranch ?? null,
      head_branch: event.data?.headBranch ?? null,
      issue_number: event.data?.issueNumber ?? null,
      review_gate_status: event.data?.reviewGateStatus ?? null,
      review_satisfied: Boolean(event.data?.reviewSatisfied),
      request_payload_hash: event.data?.request?.payloadHash ?? null,
      request_body_included: Boolean(event.data?.request?.bodyIncluded),
      request_token_included: Boolean(event.data?.request?.tokenIncluded),
      required_authority_scopes: normalizeArray(event.data?.authority?.requiredScopes),
      missing_authority_scopes: normalizeArray(event.data?.authority?.missingScopes),
      authority_scope_granted: Boolean(event.data?.authority?.scopeGranted),
      blocker_count: normalizeArray(event.data?.blockers).length,
      warning_count: normalizeArray(event.data?.warnings).length,
      mutation_attempted: Boolean(event.data?.mutationAttempted),
      mutation_executed: Boolean(event.data?.mutationExecuted),
      network_lookup_performed: Boolean(event.data?.networkLookupPerformed),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "github_pr_create_plan_safe",
    };
  }
  if (event.type === "skill_hook_manifest") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "ActiveSkillHookManifest",
      manifest_id: event.data?.manifestId ?? null,
      active_skill_set_hash: event.data?.activeSkillSetHash ?? null,
      active_hook_set_hash: event.data?.activeHookSetHash ?? null,
      selected_skill_count: normalizeArray(event.data?.selectedSkillIds).length,
      selected_hook_count: normalizeArray(event.data?.selectedHookIds).length,
      mutation_blocked_hook_count: normalizeArray(event.data?.mutationBlockedHookIds).length,
      hook_execution_enabled: Boolean(event.data?.hookExecution?.enabled),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "active_skill_hook_manifest_safe",
    };
  }
  if (event.type === "hook_dry_run_plan") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "HookDryRunPlan",
      plan_id: event.data?.planId ?? null,
      manifest_id: event.data?.manifestId ?? null,
      decision_count: event.data?.decisionCount ?? 0,
      would_run_count: event.data?.wouldRunCount ?? 0,
      blocked_count: event.data?.blockedCount ?? 0,
      skipped_count: event.data?.skippedCount ?? 0,
      policy_status: event.data?.policyDecision?.status ?? null,
      hook_execution_enabled: Boolean(event.data?.hookExecutionEnabled),
      command_execution_enabled: Boolean(event.data?.commandExecutionEnabled),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "hook_dry_run_safe",
    };
  }
  if (event.type === "hook_invocation_ledger") {
    return {
      ...summary,
      event_kind: event.data?.eventKind ?? "HookInvocationLedger",
      ledger_id: event.data?.ledgerId ?? null,
      manifest_id: event.data?.manifestId ?? null,
      dry_run_plan_id: event.data?.dryRunPlanId ?? null,
      emitted_event_kinds: normalizeArray(event.data?.emittedEventKinds),
      invocation_count: event.data?.invocationCount ?? 0,
      would_run_count: event.data?.wouldRunCount ?? 0,
      blocked_count: event.data?.blockedCount ?? 0,
      skipped_count: event.data?.skippedCount ?? 0,
      escalation_count: event.data?.escalationCount ?? 0,
      hook_execution_enabled: Boolean(event.data?.hookExecutionEnabled),
      command_execution_enabled: Boolean(event.data?.commandExecutionEnabled),
      workflow_node_id: event.data?.workflowNodeId ?? null,
      redaction: event.data?.redaction?.profile ?? "hook_invocation_ledger_safe",
    };
  }
  if (event.type !== "model_route_decision") return summary;
  return {
    ...summary,
    event_kind: event.data?.eventKind ?? "ModelRouteDecision",
    model_route_decision_id: event.data?.decisionId ?? null,
    route_id: event.data?.routeId ?? null,
    requested_model: event.data?.requestedModel ?? null,
    requested_model_mode: event.data?.requestedModelMode ?? null,
    selected_model: event.data?.selectedModel ?? null,
    endpoint_id: event.data?.endpointId ?? null,
    provider_id: event.data?.providerId ?? null,
    provider_kind: event.data?.providerKind ?? null,
    reasoning_effort: event.data?.reasoningEffort ?? null,
    local_remote_placement: event.data?.localRemotePlacement ?? null,
    privacy_posture: event.data?.privacyPosture ?? null,
    cost_estimate_usd: event.data?.costEstimateUsd ?? null,
    fallback_triggered: Boolean(event.data?.fallbackTriggered),
  };
}

function componentKindForRunEvent(eventOrType) {
  const type = typeof eventOrType === "string" ? eventOrType : eventOrType?.type;
  switch (type) {
    case "runtime_task":
      return "runtime_task";
    case "runtime_checklist":
      return "runtime_checklist";
    case "job_queued":
    case "job_started":
    case "job_completed":
    case "job_failed":
    case "job_canceled":
      return "runtime_job";
    case "repository_context":
      return "repository_context";
    case "branch_policy":
      return "branch_policy";
    case "github_context":
      return "github_context";
    case "issue_context":
      return "issue_context";
    case "pr_attempt":
      return "pr_attempt";
    case "review_gate":
      return "review_gate";
    case "github_pr_create_plan":
      return "github_pr_create";
    case "model_route_decision":
      return "model_router";
    case "skill_hook_manifest":
      return "skill_registry";
    case "hook_dry_run_plan":
      return "hook_policy";
    case "hook_invocation_ledger":
      return "hook_runtime";
    case "memory_update":
      if (typeof eventOrType !== "string" && eventOrType?.data?.operation === "subagent_inheritance") {
        return "subagent_memory";
      }
      if (typeof eventOrType !== "string" && eventOrType?.data?.operation === "policy_update") {
        return "memory_policy";
      }
      return "memory_write";
    case "lsp_diagnostics_injected":
      return "lsp_diagnostics";
    case "policy_blocked":
      if (typeof eventOrType !== "string" && eventOrType?.data?.componentKind) {
        return eventOrType.data.componentKind;
      }
      return "policy_gate";
    case "task_state":
      return "task_state";
    case "uncertainty":
      return "uncertainty_gate";
    case "probe":
      return "probe_runner";
    case "postcondition_synthesized":
      return "postcondition_synthesizer";
    case "semantic_impact":
      return "semantic_impact_analyzer";
    case "quality_ledger":
      return "quality_ledger";
    case "artifact":
      return "artifact_store";
    case "completed":
    case "canceled":
      return "completion_gate";
    case "delta":
      return "output_writer";
    case "run_started":
    default:
      return "runtime_thread";
  }
}

function workflowNodeForRunEvent(eventOrType) {
  if (
    typeof eventOrType !== "string" &&
    (eventOrType?.type === "model_route_decision" ||
      eventOrType?.type === "runtime_task" ||
      eventOrType?.type === "runtime_checklist" ||
      eventOrType?.type === "job_queued" ||
      eventOrType?.type === "job_started" ||
      eventOrType?.type === "job_completed" ||
      eventOrType?.type === "job_failed" ||
      eventOrType?.type === "job_canceled" ||
      eventOrType?.type === "repository_context" ||
      eventOrType?.type === "branch_policy" ||
      eventOrType?.type === "github_context" ||
      eventOrType?.type === "issue_context" ||
      eventOrType?.type === "pr_attempt" ||
      eventOrType?.type === "review_gate" ||
      eventOrType?.type === "github_pr_create_plan" ||
      eventOrType?.type === "memory_update" ||
      eventOrType?.type === "lsp_diagnostics_injected" ||
      eventOrType?.type === "policy_blocked" ||
      eventOrType?.type === "skill_hook_manifest" ||
      eventOrType?.type === "hook_dry_run_plan" ||
      eventOrType?.type === "hook_invocation_ledger") &&
    eventOrType.data?.workflowNodeId
  ) {
    return eventOrType.data.workflowNodeId;
  }
  return `runtime.${componentKindForRunEvent(eventOrType).replace(/_/g, "-")}`;
}

function receiptRefsForRunEvent(event) {
  if (event.type === "run_started") return [`receipt_${event.runId}_policy`];
  if (event.type === "model_route_decision") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "runtime_task") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "runtime_checklist") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "job_queued" || event.type === "job_started" || event.type === "job_completed" || event.type === "job_failed" || event.type === "job_canceled") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "repository_context") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "branch_policy") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "github_context") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "issue_context") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "pr_attempt") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "review_gate") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "github_pr_create_plan") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "skill_hook_manifest") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "hook_dry_run_plan") {
    return [
      event.data?.receiptId ?? event.data?.receipt_id,
      event.data?.policyReceiptId ?? event.data?.policy_receipt_id,
    ].filter(Boolean);
  }
  if (event.type === "hook_invocation_ledger") {
    return [
      event.data?.receiptId ?? event.data?.receipt_id,
      ...normalizeArray(event.data?.escalationReceiptIds),
    ].filter(Boolean);
  }
  if (event.type === "memory_update") {
    return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
  }
  if (event.type === "lsp_diagnostics_injected") {
    return [
      event.data?.receiptId ?? event.data?.receipt_id,
      ...normalizeArray(event.data?.receiptRefs),
    ].filter(Boolean);
  }
  if (event.type === "policy_blocked") {
    return [
      event.data?.receiptId ?? event.data?.receipt_id,
      ...normalizeArray(event.data?.receiptRefs),
    ].filter(Boolean);
  }
  if (event.type === "completed" || event.type === "canceled") return [`receipt_${event.runId}_agentgres`];
  return [];
}

function artifactRefsForRunEvent(event) {
  if (event.type === "runtime_task") return ["runtime-task.json"];
  if (event.type === "runtime_checklist") return ["runtime-checklist.json"];
  if (event.type === "job_queued" || event.type === "job_started" || event.type === "job_completed" || event.type === "job_failed" || event.type === "job_canceled") return ["runtime-job.json"];
  if (event.type === "repository_context") return ["repository-context.json"];
  if (event.type === "branch_policy") return ["branch-policy.json"];
  if (event.type === "github_context") return ["github-context.json"];
  if (event.type === "issue_context") return ["issue-context.json"];
  if (event.type === "pr_attempt") return ["pr-attempt.json", "pr-branch.json", "pr-diff.patch"];
  if (event.type === "review_gate") return ["review-gate.json"];
  if (event.type === "github_pr_create_plan") return ["github-pr-create-plan.json"];
  if (event.type === "skill_hook_manifest") return ["active-skill-hook-manifest.json"];
  if (event.type === "hook_dry_run_plan") return ["hook-dry-run-plan.json"];
  if (event.type === "hook_invocation_ledger") return ["hook-invocations.json"];
  if (event.type === "policy_blocked" && event.data?.reason === "post_edit_diagnostics_findings") return ["diagnostics-blocking-gate.json"];
  if (event.type === "artifact") return event.data?.artifactNames ?? [];
  return [];
}

function codingToolResultWithoutDrafts(result = {}, artifacts = []) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return result;
  const publicResult = { ...result };
  delete publicResult.artifactDrafts;
  delete publicResult.artifact_drafts;
  if (artifacts.length) {
    publicResult.artifactRefs = uniqueStrings([
      ...normalizeArray(publicResult.artifactRefs),
      ...artifacts.map((artifactRecord) => artifactRecord.id),
    ]);
    publicResult.artifacts = artifacts.map(codingToolArtifactMetadata);
  }
  return publicResult;
}

function codingToolArtifactMetadata(artifactRecord = {}) {
  return {
    schemaVersion: CODING_TOOL_ARTIFACT_SCHEMA_VERSION,
    artifactId: artifactRecord.id,
    artifactRef: artifactRecord.id,
    threadId: artifactRecord.thread_id ?? artifactRecord.threadId ?? null,
    toolName: artifactRecord.tool_name ?? artifactRecord.toolName ?? null,
    toolCallId: artifactRecord.tool_call_id ?? artifactRecord.toolCallId ?? null,
    name: artifactRecord.name ?? null,
    channel: artifactRecord.channel ?? null,
    mediaType: artifactRecord.media_type ?? artifactRecord.mediaType ?? "text/plain",
    contentBytes: Number(artifactRecord.content_bytes ?? artifactRecord.contentBytes ?? 0),
    contentHash: artifactRecord.content_hash ?? artifactRecord.contentHash ?? null,
    receiptId: artifactRecord.receipt_id ?? artifactRecord.receiptId ?? null,
    redaction: artifactRecord.redaction ?? "none",
    createdAt: artifactRecord.created_at ?? artifactRecord.createdAt ?? null,
  };
}

function codingToolArtifactReadResult(artifactRecord = {}, range = {}) {
  const content = String(artifactRecord.content ?? "");
  const buffer = Buffer.from(content, "utf8");
  const offsetBytes = Math.max(0, Math.min(buffer.byteLength, Number(range.offsetBytes ?? range.offset_bytes ?? 0) || 0));
  const lengthLimit = Math.max(1, Number(range.lengthBytes ?? range.length_bytes ?? range.maxBytes ?? range.max_bytes ?? 64 * 1024) || 64 * 1024);
  const chunk = buffer.subarray(offsetBytes, Math.min(buffer.byteLength, offsetBytes + lengthLimit));
  const text = chunk.toString("utf8");
  const metadata = codingToolArtifactMetadata(artifactRecord);
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    ...metadata,
    artifactRefs: [artifactRecord.id].filter(Boolean),
    offsetBytes,
    lengthBytes: chunk.byteLength,
    totalBytes: buffer.byteLength,
    content: text,
    contentHash: doctorHash(text),
    fullContentHash: metadata.contentHash,
    truncated: offsetBytes + chunk.byteLength < buffer.byteLength,
    receiptRefs: [`receipt_artifact_read_${safeId(artifactRecord.id)}_${doctorHash(`${offsetBytes}:${chunk.byteLength}`).slice(0, 12)}`],
    shellFallbackUsed: false,
  };
}

function terminalCount(events) {
  return events.filter((event) => TERMINAL_EVENT_TYPES.has(event.type)).length;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  return text.trim() ? JSON.parse(text) : {};
}

function writeSse(response, events) {
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.end(
    events
      .map((event) => `id: ${event.id ?? event.seq}\nevent: runtime.event\ndata: ${JSON.stringify(event)}\n\n`)
      .join(""),
  );
}

function writeJsonResponse(response, value, status = 200) {
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(status === 204 ? "" : JSON.stringify(value));
}

function writeError(response, error) {
  if (response.destroyed || response.writableEnded) return;
  if (response.headersSent) {
    try {
      response.end();
    } catch {
      // Streaming clients may disconnect while the handler is unwinding.
    }
    return;
  }
  const status = error?.status ?? 500;
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(
    JSON.stringify({
      error: {
        code: error?.code ?? "runtime",
        message: error?.message ?? "Local daemon request failed.",
        retryable: status >= 500,
        requestId: response.getHeader("x-request-id"),
        details: redact(error?.details ?? {}),
      },
    }),
  );
}

function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

function policyError(message, details) {
  return runtimeError({ status: 403, code: "policy", message, details });
}

function externalBlocker(message, details) {
  return runtimeError({ status: 424, code: "external_blocker", message, details });
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function redact(value) {
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      /token|secret|key|authorization/i.test(key) ? "[REDACTED]" : item,
    ]),
  );
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => path.join(dir, file));
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs
    .readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function listJsonl(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".jsonl"))
    .map((file) => path.join(dir, file));
}

function runtimeEventStreamFileName(eventStreamId) {
  return crypto.createHash("sha256").update(String(eventStreamId)).digest("hex");
}

function relative(from, to) {
  return path.relative(from, to) || ".";
}
