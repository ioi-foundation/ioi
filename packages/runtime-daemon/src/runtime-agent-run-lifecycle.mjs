import {
  deleteAgent as deleteAgentState,
  updateAgent as updateAgentState,
} from "./threads/thread-store.mjs";
import {
  isRuntimeServiceProfile,
  runtimeProfileForRequest,
} from "./runtime-api-bridge.mjs";

export function createRuntimeAgentRunLifecycleSurface({
  lifecycleAdmissionRunner = null,
  runtimeError,
} = {}) {
  return {
    createAgent(store, options = {}) {
      return createAgent(store, options, { lifecycleAdmissionRunner });
    },
    createRun(store, agentId, request = {}) {
      return createRun(store, agentId, request, { lifecycleAdmissionRunner });
    },
    createThread(store, request = {}) {
      return createThread(store, request, { lifecycleAdmissionRunner });
    },
    updateAgent(store, agentId, status, operationKind) {
      return updateAgentState(store, agentId, status, operationKind, { runtimeError });
    },
    deleteAgent(store, agentId) {
      return deleteAgentState(store, agentId, { runtimeError });
    },
  };
}

export function createThread(store, request = {}, deps = {}) {
  const options = request.options ?? request;
  const runtimeProfile = runtimeProfileForRequest(request, options);
  if (isRuntimeServiceProfile(runtimeProfile)) {
    return store.createRuntimeBridgeThread({ request, options, runtimeProfile });
  }
  const agent = createAgent(store, options, deps);
  store.ensureThreadStartedEvent(agent);
  return store.threadForAgent(agent);
}

export function createAgent(store, options = {}, deps = {}) {
  throwRuntimeLifecycleRustCoreRequired({
    lifecycleAdmissionRunner: deps.lifecycleAdmissionRunner ?? store.contextPolicyRunner ?? null,
    code: "runtime_agent_create_rust_core_required",
    message: "Agent creation requires direct Rust daemon-core state admission and persistence.",
    boundary: "runtime.agent_create",
    operation: "agent_create",
    operation_kind: "agent.create",
    requested_cwd: options.local?.cwd ?? store.defaultCwd ?? null,
    requested_runtime: options.hosted ? "hosted" : options.runtime ?? null,
    evidence_refs: [
      "runtime_agent_create_js_facade_retired",
      "rust_daemon_core_agent_create_required",
      "agentgres_agent_create_state_truth_required",
    ],
  });
}

export function createRun(store, agentId, request = {}, deps = {}) {
  throwRuntimeLifecycleRustCoreRequired({
    lifecycleAdmissionRunner: deps.lifecycleAdmissionRunner ?? store.contextPolicyRunner ?? null,
    code: "runtime_run_create_rust_core_required",
    message: "Run creation requires direct Rust daemon-core state admission and persistence.",
    boundary: "runtime.run_create",
    operation: "run_create",
    operation_kind: "run.create",
    agent_id: agentId ?? null,
    requested_mode: request.mode ?? "send",
    evidence_refs: [
      "runtime_run_create_js_facade_retired",
      "rust_daemon_core_run_create_required",
      "agentgres_run_create_state_truth_required",
    ],
  });
}

function throwRuntimeLifecycleRustCoreRequired({
  lifecycleAdmissionRunner,
  code,
  message,
  boundary,
  operation,
  operation_kind,
  evidence_refs,
  ...details
}) {
  if (lifecycleAdmissionRunner?.planLifecycleAdmissionRequired) {
    const record = lifecycleAdmissionRunner.planLifecycleAdmissionRequired({
      operation,
      operation_kind,
      agent_id: details.agent_id,
      requested_cwd: details.requested_cwd,
      requested_runtime: details.requested_runtime,
      requested_mode: details.requested_mode,
      evidence_refs,
    });
    const planned = record?.record ?? record;
    const error = new Error(planned?.message ?? record?.message ?? message);
    error.status = Number(planned?.status_code ?? record?.status_code ?? 501);
    error.code = planned?.code ?? record?.code ?? code;
    error.details = planned?.details ?? record?.details ?? {
      rust_core_boundary: boundary,
      operation,
      operation_kind,
      ...details,
      evidence_refs,
    };
    throw error;
  }
  const error = new Error(message);
  error.status = 501;
  error.code = code;
  error.details = {
    rust_core_boundary: boundary,
    operation,
    operation_kind,
    ...details,
    evidence_refs,
  };
  throw error;
}
