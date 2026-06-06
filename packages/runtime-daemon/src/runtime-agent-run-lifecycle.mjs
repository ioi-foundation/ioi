import crypto from "node:crypto";
import path from "node:path";

import { runtimeUsageTelemetryForRun } from "./usage-telemetry.mjs";

function requiredPlannedOperationKind(stateUpdate, expectedOperationKind, recordKind) {
  const operationKind =
    typeof stateUpdate?.operation_kind === "string" && stateUpdate.operation_kind.trim()
      ? stateUpdate.operation_kind
      : null;
  if (!operationKind) {
    const error = new Error(
      `Rust policy state-update planning did not return an operation kind for ${recordKind} creation.`,
    );
    error.code = "runtime_lifecycle_state_update_operation_kind_missing";
    error.details = {
      record_kind: recordKind,
      operation_kind: expectedOperationKind,
    };
    throw error;
  }
  if (operationKind !== expectedOperationKind) {
    const error = new Error(
      `Rust policy state-update planning returned an unexpected operation kind for ${recordKind} creation.`,
    );
    error.code = "runtime_lifecycle_state_update_operation_kind_mismatch";
    error.details = {
      record_kind: recordKind,
      expected_operation_kind: expectedOperationKind,
      operation_kind: operationKind,
    };
    throw error;
  }
  return operationKind;
}

export function createAgent(store, options = {}, deps = {}) {
  const {
    contextPolicyRunner,
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
  if (typeof contextPolicyRunner?.planAgentCreateStateUpdate !== "function") {
    throw new Error("Agent creation requires Rust policy state-update planning.");
  }
  const stateUpdate = contextPolicyRunner.planAgentCreateStateUpdate({ agent });
  const plannedAgent = stateUpdate.agent;
  if (!plannedAgent?.id) {
    throw new Error("Rust policy state-update planning did not return an agent record.");
  }
  const operationKind = requiredPlannedOperationKind(stateUpdate, "agent.create", "agent");
  store.agents.set(plannedAgent.id, plannedAgent);
  store.writeAgent(plannedAgent, operationKind);
  return plannedAgent;
}

export function createRun(store, agentId, request = {}, deps = {}) {
  const {
    approvalModeForThreadMode,
    buildRun,
    contextPolicyRunner,
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
    trace: {
      ...runtimeRunDraft.trace,
      usage: usageTelemetry,
      usage_telemetry: usageTelemetry,
    },
  };
  if (typeof contextPolicyRunner?.planRunCreateStateUpdate !== "function") {
    throw new Error("Run creation requires Rust policy state-update planning.");
  }
  const stateUpdate = contextPolicyRunner.planRunCreateStateUpdate({ run: runtimeRun });
  const plannedRun = stateUpdate.run;
  if (!plannedRun?.id) {
    throw new Error("Rust policy state-update planning did not return a run record.");
  }
  const operationKind = requiredPlannedOperationKind(stateUpdate, "run.create", "run");
  store.runs.set(plannedRun.id, plannedRun);
  store.writeRun(plannedRun, operationKind);
  return plannedRun;
}
