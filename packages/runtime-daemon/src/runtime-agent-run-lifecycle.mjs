import crypto from "node:crypto";
import path from "node:path";

import { runtimeUsageTelemetryForRun } from "./usage-telemetry.mjs";

export function createAgent(store, options = {}, deps = {}) {
  const {
    ensureProviderAvailable,
    initialThreadRuntimeControls,
    mcpRegistryForWorkspace,
    randomUUID = () => crypto.randomUUID(),
    runtimeModeForOptions,
    summarizeAgentOptions,
  } = deps;
  const now = new Date().toISOString();
  const cwd = path.resolve(options.local?.cwd ?? store.defaultCwd);
  const runtime = runtimeModeForOptions(options);
  ensureProviderAvailable(runtime, options);
  const modelRoute = store.resolveModelRoute(options, {
    evidenceRefs: ["runtime_agent_model_route"],
    workflowNodeId: "runtime.model-router",
    workflowNodeType: "Model Router",
  });
  const agent = {
    id: `agent_${randomUUID()}`,
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
    runtimeControls: initialThreadRuntimeControls(options, modelRoute, now),
    mcpRegistry: mcpRegistryForWorkspace(cwd, {
      ...options,
      homeDir: store.homeDir,
    }),
    createdAt: now,
    updatedAt: now,
    options: summarizeAgentOptions(cwd, options),
  };
  store.agents.set(agent.id, agent);
  store.writeAgent(agent, "agent.create");
  return agent;
}

export function createRun(store, agentId, request = {}, deps = {}) {
  const {
    approvalModeForThreadMode,
    buildRun,
    ensureProviderAvailable,
    runtimeUsageTelemetryForRun: usageForRun = runtimeUsageTelemetryForRun,
    threadIdForAgent,
    threadModeForRunMode,
  } = deps;
  const agent = store.getAgent(agentId);
  ensureProviderAvailable(agent.runtime, agent.options);
  const mode = request.mode ?? "send";
  const threadMode = request.threadMode ?? threadModeForRunMode(mode, agent.runtimeControls?.mode);
  const approvalMode =
    request.approvalMode ??
    request.approval_mode ??
    agent.runtimeControls?.approvalMode ??
    approvalModeForThreadMode(threadMode);
  const prompt =
    request.prompt ??
    (mode === "learn"
      ? `Learn governed task-family updates for ${request.options?.taskFamily ?? "runtime"}`
      : "");
  const modelRoute = store.resolveRunModelRoute(agent, request);
  const memory = store.resolveRunMemory(agent, request, prompt);
  const skillHookCatalog = store.skillHookCatalog({ cwd: agent.cwd });
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
  const runtimeRunDraft = {
    ...run,
    threadMode,
    approvalMode,
  };
  const usageTelemetry = usageForRun({
    run: runtimeRunDraft,
    agent,
    threadId: threadIdForAgent(agent.id),
  });
  const runtimeRun = {
    ...runtimeRunDraft,
    usage: usageTelemetry,
    usage_telemetry: usageTelemetry,
    usageTelemetry,
    runtimeUsage: usageTelemetry,
    trace: {
      ...runtimeRunDraft.trace,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
      usageTelemetry,
      runtimeUsage: usageTelemetry,
    },
  };
  store.runs.set(runtimeRun.id, runtimeRun);
  store.writeRun(runtimeRun, "run.create");
  return runtimeRun;
}
