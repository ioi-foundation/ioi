import assert from "node:assert/strict";
import test from "node:test";

import { createPublicRuntimeRequestHandler } from "./public-runtime-routes.mjs";
import { createAgentgresAdmissionClient } from "../runtime-agentgres-admission-client.mjs";
import { admitHypervisorApprovedOperation } from "../runtime-hypervisor-approved-operation-admission.mjs";
import {
  createHypervisorApprovedOperationExecutorRegistry,
  expectedExecutorRefForPlan,
} from "../runtime-hypervisor-approved-operation-executors.mjs";

function responseRecorder() {
  return {
    headers: {},
    statusCode: 200,
    ended: false,
    body: null,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(value = "") {
      this.ended = true;
      this.body = value;
    },
  };
}

function request({ method = "GET", url = "/", body = {} } = {}) {
  return {
    method,
    url,
    headers: {},
    body,
  };
}

function retiredRouteWrapper() {
  throw new Error("retired public runtime route wrapper must not be routed");
}

function routeHarness(overrides = {}) {
  const calls = [];
  const deps = {
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION: "usage.v.test",
    baseUrlForRequest: () => "http://daemon.test",
    handleAgentRoute: async () => calls.push("agent"),
    handleModelMountingNativeRoute: async () => calls.push("model-native"),
    handleOpenAiCompatibilityRoute: async () => calls.push("openai"),
    handleRunRoute: async () => calls.push("run"),
    handleThreadRoute: async () => calls.push("thread"),
    isOpenAiCompatibilityRoute: () => false,
    normalizeBooleanOption: (value, fallback) => (value == null ? fallback : value !== "false" && value !== "0"),
    notFound: (message, details) => {
      const error = new Error(message);
      error.details = details;
      throw error;
    },
    optionalString: (value) => {
      const text = typeof value === "string" ? value.trim() : "";
      return text || null;
    },
    readBody: async (req) => req.body ?? {},
    runtimeError: (error) => Object.assign(new Error(error.message), error),
    usageRequestMetadataFromUrl: () => ({ requestMetadata: true }),
    usageTelemetryWithRequestMetadata: (payload, metadata) => ({ payload, metadata }),
    writeError: (response, error) => {
      response.statusCode = error.status ?? 500;
      response.error = error;
      response.end(JSON.stringify({ error: error.code ?? error.message }));
    },
    writeJsonResponse: (response, payload, status = 200) => {
      response.statusCode = status;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(payload));
    },
    writeMcpJsonRpcResponse: (response, payload) => {
      response.statusCode = 200;
      response.end(JSON.stringify(payload));
    },
    ...overrides,
  };
  return {
    calls,
    handleRequest: createPublicRuntimeRequestHandler(deps),
  };
}

test("public runtime routes answer CORS preflight without store access", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({ request: request({ method: "OPTIONS", url: "/v1/doctor" }), response, store: null });

  assert.equal(response.statusCode, 204);
  assert.equal(response.ended, true);
  assert.equal(response.headers["access-control-allow-origin"], "*");
  assert.match(response.headers["x-request-id"], /^req_/);
});

test("public runtime /v1/doctor is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const contextPolicyCore = {
    projectRuntimeDoctorReport(request) {
      calls.push({ method: "projectRuntimeDoctorReport", request });
      return { report: {} };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    runtimeDoctorReport: retiredRouteWrapper,
    doctorReport: retiredRouteWrapper,
  };

  await handleRequest({ request: request({ url: "/v1/doctor" }), response, store, contextPolicyCore });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
  assert.deepEqual(calls, [], "the JS doctor projection must not be invoked");
});

test("public runtime Hypervisor home cockpit projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/home-cockpit" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor session operations projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/session-operations" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor project state projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/project-state" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor Core taxonomy route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({ url: "/v1/hypervisor/core-taxonomy" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor automation compositor projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/automation-compositor" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor automation run proposal operation route is retired", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/automation-runs/proposals",
      body: {},
    }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor agents projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/agents" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor model infrastructure projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/model-infrastructure" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor provider placement projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/provider-placement" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor privacy posture projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/privacy-posture" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor receipt evidence projection route is retired (served by fixtures)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/hypervisor/receipt-evidence" }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor provider operation route is retired", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/provider-operations",
      body: {},
    }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor session operation route is retired", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/session-operations/proposals",
      body: {},
    }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor project operation route is retired", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/project-operations",
      body: {},
    }),
    response,
    store: { projectRuntimeLifecycleProjection: retiredRouteWrapper },
  });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime routes admit approved Hypervisor operations after wallet and Agentgres refs", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/approved-operations",
      body: {
        operation_family: "session",
        proposal_ref: "session-operation:daemon/restore",
        proposal_schema_version: "ioi.hypervisor.session_operation_proposal.v1",
        proposal_source: "daemon-session-operation-proposal",
        project_ref: "project:ioi",
        session_ref: "session:ioi",
        environment_ref: "environment:ioi",
        provider_candidate_ref: "provider:local-workstation",
        operation_kind: "restore_session",
        target_ref: "agentgres://restore/ioi/latest",
        wallet_approval_ref: "approval://wallet/session/restore",
        wallet_lease_ref: "lease:wallet/session/restore",
        required_scope_refs: ["scope:restore.apply"],
        authority_receipt_refs: ["receipt://wallet/session/restore"],
        agentgres_operation_ref: "agentgres://operation/session/ioi/restore",
        receipt_ref: "receipt://session/ioi/restore",
        state_root_ref: "agentgres://state-root/session/ioi",
        archive_ref: "artifact://agentgres/archive/ioi/latest",
        restore_ref: "agentgres://restore/ioi/latest",
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 202);
  const result = JSON.parse(response.body);
  assert.equal(
    result.schema_version,
    "ioi.runtime.hypervisor_approved_operation_admission.v1",
  );
  assert.equal(result.decision, "admitted");
  assert.equal(result.execution_status, "admitted_for_execution");
  assert.equal(result.executor_kind, "session_lifecycle_adapter");
  assert.match(result.execution_plan_ref, /^execution-plan:\/\/hypervisor\/session\//);
  assert.match(result.execution_dispatch_ref, /^dispatch:\/\/hypervisor\/session\//);
  assert.equal(
    result.execution_plan.schema_version,
    "ioi.runtime.hypervisor_approved_operation_execution_plan.v1",
  );
  assert.equal(result.execution_plan.dispatch_status, "awaiting_executor");
  assert.equal(result.execution_plan.executor_kind, "session_lifecycle_adapter");
  assert.equal(result.execution_plan.wallet_lease_ref, result.wallet_lease_ref);
  assert.equal(result.wallet_approval_ref, "approval://wallet/session/restore");
  assert.deepEqual(result.agentgres_operation_refs, [
    "agentgres://operation/session/ioi/restore",
  ]);
  assert.equal(result.runtimeTruthSource, "daemon-runtime");
});

test("public runtime routes reject fixture Hypervisor operation execution admission", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/approved-operations",
      body: {
        operation_family: "provider",
        proposal_ref: "provider-operation:fixture/archive",
        proposal_schema_version: "ioi.hypervisor.provider_operation_proposal.v1",
        proposal_source: "fixture",
        project_ref: "project:ioi",
        candidate_ref: "provider-candidate:akash-gpu",
        direct_provider_ref: "provider:akash/gpu-market",
        operation_kind: "archive",
        wallet_approval_ref: "approval://wallet/provider/archive",
        wallet_lease_ref: "lease:wallet/provider/archive",
        required_scope_refs: ["scope:archive.write"],
        agentgres_operation_ref: "agentgres://operation/provider/archive",
        receipt_ref: "receipt://provider/archive",
        state_root_ref: "agentgres://state-root/provider/archive",
        archive_ref: "artifact://agentgres/archive/provider/latest",
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 403);
  assert.equal(
    response.error.code,
    "hypervisor_approved_operation_proposal_source_not_admissible",
  );
});

test("public runtime routes dispatch approved Hypervisor operation plans through mounted executors", async () => {
  const admitted = admitHypervisorApprovedOperation({
    operation_family: "session",
    proposal_ref: "session-operation:daemon/restore",
    proposal_schema_version: "ioi.hypervisor.session_operation_proposal.v1",
    proposal_source: "daemon-session-operation-proposal",
    project_ref: "project:ioi",
    session_ref: "session:ioi",
    environment_ref: "environment:ioi",
    provider_candidate_ref: "provider:local-workstation",
    operation_kind: "restore_session",
    target_ref: "agentgres://restore/ioi/latest",
    wallet_approval_ref: "approval://wallet/session/restore",
    wallet_lease_ref: "lease:wallet/session/restore",
    required_scope_refs: ["scope:restore.apply"],
    authority_receipt_refs: ["receipt://wallet/session/restore"],
    agentgres_operation_ref: "agentgres://operation/session/ioi/restore",
    receipt_ref: "receipt://session/ioi/restore",
    state_root_ref: "agentgres://state-root/session/ioi",
    archive_ref: "artifact://agentgres/archive/ioi/latest",
    restore_ref: "agentgres://restore/ioi/latest",
  });
  const calls = [];
  const { handleRequest } = routeHarness({
    executeApprovedOperationPlan(plan, context) {
      calls.push({ plan, context });
      return {
        execution_status: "completed",
        execution_receipt_ref: "receipt://session/ioi/restore/executed",
        agentgres_operation_refs: [
          "agentgres://operation/session/ioi/restore/executed",
        ],
        artifact_refs: ["artifact://session/ioi/restore/log"],
        trace_refs: ["trace://session/ioi/restore"],
        next_state_root_ref: "agentgres://state-root/session/ioi/restored",
      };
    },
  });
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/approved-operation-dispatches",
      body: {
        execution_plan: admitted.execution_plan,
        execution_plan_ref: admitted.execution_plan_ref,
        dispatch_ref: admitted.execution_dispatch_ref,
        executor_kind: admitted.executor_kind,
        executor_ref: "executor://hypervisor/session/local-workstation",
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 202);
  const result = JSON.parse(response.body);
  assert.equal(
    result.schema_version,
    "ioi.runtime.hypervisor_approved_operation_dispatch.v1",
  );
  assert.equal(result.dispatch_status, "executed");
  assert.equal(result.executor_kind, "session_lifecycle_adapter");
  assert.equal(
    result.executor_ref,
    "executor://hypervisor/session/local-workstation",
  );
  assert.deepEqual(result.receipt_refs, [
    "receipt://session/ioi/restore",
    "receipt://session/ioi/restore/executed",
  ]);
  assert.equal(
    result.next_state_root_ref,
    "agentgres://state-root/session/ioi/restored",
  );
  assert.equal(result.runtimeTruthSource, "daemon-runtime");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].plan.execution_plan_ref, admitted.execution_plan_ref);
});

test("public runtime routes dispatch through the default approved-operation executor registry", async () => {
  const admitted = admitHypervisorApprovedOperation({
    operation_family: "project",
    proposal_ref: "project-operation:daemon/restore",
    proposal_schema_version: "ioi.hypervisor.project_operation_proposal.v1",
    proposal_source: "daemon-project-operation-proposal",
    project_ref: "project:ioi",
    workspace_ref: "workspace://ioi",
    operation_kind: "restore",
    wallet_approval_ref: "approval://wallet/project/restore",
    wallet_lease_ref: "lease:wallet/project/restore",
    required_scope_refs: ["scope:agentgres.restore", "scope:artifact.decrypt"],
    authority_receipt_refs: ["receipt://wallet/project/restore"],
    agentgres_operation_ref: "agentgres://operation/project/ioi/restore",
    receipt_ref: "receipt://project/ioi/restore",
    state_root_ref: "agentgres://state-root/project/ioi",
    archive_ref: "artifact://agentgres/archive/ioi/latest",
    restore_ref: "agentgres://restore/ioi/latest",
  });
  const registry = createHypervisorApprovedOperationExecutorRegistry({
    nowIso: () => "2026-06-18T00:03:00.000Z",
  });
  const { handleRequest } = routeHarness({
    executeApprovedOperationPlan: registry.executeApprovedOperationPlan,
  });
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/approved-operation-dispatches",
      body: {
        execution_plan: admitted.execution_plan,
        executor_ref: expectedExecutorRefForPlan(admitted.execution_plan),
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 202);
  const result = JSON.parse(response.body);
  assert.equal(result.operation_family, "project");
  assert.equal(result.dispatch_status, "executed");
  assert.equal(
    result.executor_ref,
    "executor://hypervisor/project/lifecycle-adapter",
  );
  assert.ok(
    result.receipt_refs.some((ref) =>
      ref.startsWith("receipt://hypervisor/project-lifecycle/"),
    ),
  );
  assert.ok(
    result.next_state_root_ref.startsWith(
      "agentgres://state-root/hypervisor/project-lifecycle/",
    ),
  );
  assert.equal(result.runtimeTruthSource, "daemon-runtime");
});

test("public runtime routes fail approved-operation dispatch without mounted executor", async () => {
  const admitted = admitHypervisorApprovedOperation({
    operation_family: "provider",
    proposal_ref: "provider-operation:daemon/zero-to-idle",
    proposal_schema_version: "ioi.hypervisor.provider_operation_proposal.v1",
    proposal_source: "daemon-provider-operation-proposal",
    project_ref: "project:ioi",
    candidate_ref: "provider-candidate:akash-gpu",
    direct_provider_ref: "provider:akash/gpu-market",
    operation_kind: "zero_to_idle",
    wallet_approval_ref: "approval://wallet/provider/akash",
    wallet_lease_ref: "lease:wallet/provider/akash/zero-to-idle",
    required_scope_refs: ["scope:provider.spend", "scope:receipt.write"],
    agentgres_operation_ref:
      "agentgres://operation/provider/akash/zero-to-idle",
    receipt_ref: "receipt://provider/akash/zero-to-idle",
    state_root_ref: "agentgres://state-root/provider/akash",
    archive_ref: "artifact://agentgres/archive/provider/akash/latest",
    restore_ref: "agentgres://restore/akash/latest",
  });
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/approved-operation-dispatches",
      body: {
        execution_plan: admitted.execution_plan,
        executor_ref: "executor://hypervisor/provider/akash",
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 501);
  assert.equal(
    response.error.code,
    "hypervisor_approved_operation_executor_required",
  );
});

test("public runtime routes expose daemon-planned harness container lane receipts", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-container-lanes",
      body: {
        selection_ref: "agent-harness-adapter:deepseek_tui",
        adapter_id: "deepseek_tui",
        runtime: "docker",
        container_image_ref: "container-image:deepseek-tui:local",
        command_argv: [
          "harness-adapter",
          "run",
          "deepseek_tui",
          "--fixture",
          "harness-testbed:public-code-edit-fixture",
        ],
        mounts: [
          {
            mount_ref: "mount:public-trunk",
            source_ref: "artifact://workspace/public-trunk",
            target_path: "/workspace",
            access: "read_only",
            custody: "public_trunk",
          },
        ],
        network_policy: "disabled",
        env_policy_ref: "env-policy:harness-adapter/no-plaintext-env",
        authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
        privacy_posture_ref: "privacy-posture:public-trunk",
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.hypervisor.harness_container_lane_plan.v1",
  );
  assert.equal(payload.selection_ref, "agent-harness-adapter:deepseek_tui");
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
  assert.equal(payload.requiresDaemonGate, true);
  assert.match(payload.command_argv_hash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    payload.receipt.schema_version,
    "ioi.hypervisor.harness_container_lane_receipt.v1",
  );
  assert.equal(payload.receipt.exit_status, "not_executed");
  assert.deepEqual(payload.receipt.mounts, payload.mounts);
});

test("public runtime routes expose harness public fixture comparison under daemon gates", async () => {
  const executed = [];
  const { handleRequest } = routeHarness({
    executeHarnessContainerLane: async ({ plan, fixture_id, task_ref }) => {
      executed.push({ plan_id: plan.plan_id, fixture_id, task_ref });
      return {
        exit_status: "success",
        exit_code: 0,
        agentgres_operation_refs: [
          `agentgres://operation/${plan.adapter_id}/public-fixture`,
        ],
        artifact_refs: [`artifact://harness-fixture/${plan.adapter_id}/stdout`],
        created_at: "2026-06-17T13:01:00.000Z",
      };
    },
  });
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-public-fixture-runs",
      body: {
        installed_adapter_ids: ["deepseek_tui", "generic_cli"],
        candidate_lanes: [
          {
            adapter_id: "deepseek_tui",
            selection_ref: "agent-harness-adapter:deepseek_tui",
            runtime: "docker",
            container_image_ref: "container-image:deepseek-tui:local",
          },
          {
            adapter_id: "generic_cli",
            selection_ref: "agent-harness-adapter:generic_cli",
            runtime: "docker",
            container_image_ref: "container-image:generic-cli:local",
          },
        ],
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(payload.schema_version, "ioi.hypervisor.harness_public_fixture_run.v1");
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(payload.candidate_selection_refs, [
    "agent-harness-adapter:deepseek_tui",
    "agent-harness-adapter:generic_cli",
  ]);
  assert.deepEqual(
    payload.attempts.map((attempt) => attempt.exit_status),
    ["success", "success"],
  );
  assert.equal(executed.length, 2);
  assert.ok(
    payload.attempts.every((attempt) =>
      attempt.mounts.every((mount) =>
        ["public_trunk", "redacted_projection"].includes(mount.custody),
      ),
    ),
  );
  assert.equal(
    payload.attempts[0].receipt.agentgres_operation_refs[0],
    "agentgres://operation/deepseek_tui/public-fixture",
  );
});

test("public runtime harness fixture route preserves private workspace mount guard", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-public-fixture-runs",
      body: {
        installed_adapter_ids: ["deepseek_tui", "generic_cli"],
        candidate_lanes: [
          {
            adapter_id: "deepseek_tui",
            runtime: "docker",
            container_image_ref: "container-image:deepseek-tui:local",
            mounts: [
              {
                source_ref: "artifact://workspace/private",
                target_path: "/workspace",
                access: "read_only",
                custody: "ctee_private_workspace",
              },
            ],
          },
          {
            adapter_id: "generic_cli",
            runtime: "docker",
            container_image_ref: "container-image:generic-cli:local",
          },
        ],
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "harness_container_lane_private_mount_blocked",
  });
});

test("public runtime model route mutation admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/model-route-mutation-admissions",
      body: { mutation_kind: "bind_session_route" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime model-weight custody admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/model-weight-custody-admissions",
      body: { route_ref: "model-route:local/default", weight_class: "user_local_private_weight" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime private workspace mount admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/private-workspace-mount-admissions",
      body: { workspace_ref: "workspace://ioi", custody_class: "redacted_projection" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime managed worker lifecycle admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/managed-worker-lifecycle-admissions",
      body: { lifecycle_id: "lifecycle:agent_123", from_state: "active", to_state: "idle" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime physical action intent admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/physical-action-intent-admissions",
      body: { intent_id: "intent://physical/carwash/prep-vehicle-001" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime worker package install admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/worker-package-install-admissions",
      body: { install_id: "install://aiagent/carwash-prep/heath/default" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime code editor adapter launch plan admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/code-editor-adapter-launch-plans",
      body: { launch_plan_ref: "code-editor-adapter:external_editor/launch-plan" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime Hypervisor session launch recipe admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/session-launch-recipe-admissions",
      body: {
        schema_version:
          "ioi.hypervisor.session_launch_recipe_admission_request.v1",
      },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime harness session binding admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-binding-admissions",
      body: { schema_version: "ioi.hypervisor.harness_session_binding.v1" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime routes expose Codex OSS harness session launches", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-launches",
      body: {
        binding_admission: {
          schema_version: "ioi.runtime.harness_session_binding_admission.v1",
          admission_id:
            "harness-session-binding-admission:harness-session-binding-session-route-sessions-mission-default-project-ioi-agent-harness-adapter-codex_cli-model-config-local-codex-oss-qwen",
          decision: "admitted",
          admission_state: "admitted_for_harness_launch",
          session_binding_ref:
            "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli:model-config-local-codex-oss-qwen",
          session_route_ref: "session-route:sessions/mission.default/project:ioi",
          harness_selection_ref: "agent-harness-adapter:codex_cli",
          harness_selection_kind: "agent_harness_adapter",
          harness_truth_boundary: "proposal_source_only",
          harness_launch_route_ref: "harness-route:codex-cli/local-model",
          agent_harness_adapter_id: "codex_cli",
          harness_profile_ref: null,
          model_configuration_ref: "model-config:local/codex-oss-qwen",
          model_route_ref: "model-route:hypervisor/default-local",
          model_route_policy: "hypervisor_model_mount",
          model_route_availability_state: "daemon_verified",
          model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
          model_route_loaded_instance_refs: [
            "model-instance:hypervisor/default-local",
          ],
          workspace_mount_policy: "redacted_projection",
          privacy_posture_ref: "privacy:redacted-projection",
          authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
          receipt_policy_ref: "receipt-policy:harness-adapter/default",
          receipt_preview_ref: "receipt-preview:new-session/admitted",
          expected_receipt_refs: [
            "receipt-preview:new-session/admitted",
            "receipt-policy:harness-adapter/default",
          ],
          agentgres_operation_refs: [
            "agentgres://operation/harness-session-binding/admit",
          ],
          receipt_refs: ["receipt://harness-session-binding/admit"],
          state_root: "agentgres://state-root/harness-session-binding/admit",
          harness_runtime_truth_claimed: false,
          requiresDaemonGate: true,
          runtimeTruthSource: "daemon-runtime",
          admitted_at: "2026-06-18T12:00:00.000Z",
        },
        workspace_ref: "workspace://local/ioi",
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(payload.schema_version, "ioi.runtime.harness_session_launch.v1");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.launch_state, "ready_to_spawn");
  assert.equal(payload.launch_lane, "host_dev_pty");
  assert.equal(
    payload.command_contract.command_ref,
    "host-command:codex-cli/local-ollama-qwen",
  );
  assert.deepEqual(payload.command_contract.argv_template.slice(0, 6), [
    "codex",
    "--oss",
    "--local-provider",
    "ollama",
    "--model",
    "${HYPERVISOR_LOCAL_HARNESS_MODEL:-qwen}",
  ]);
  assert.equal(payload.model_mount_contract.provider, "ollama");
  assert.equal(payload.command_contract.secret_release_policy, "none");
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime routes expose Codex OSS harness session spawn contracts", async () => {
  const { handleRequest } = routeHarness();
  const launchResponse = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-launches",
      body: {
        binding_admission: {
          schema_version: "ioi.runtime.harness_session_binding_admission.v1",
          admission_id:
            "harness-session-binding-admission:harness-session-binding-session-route-sessions-mission-default-project-ioi-agent-harness-adapter-codex_cli-model-config-local-codex-oss-qwen",
          decision: "admitted",
          admission_state: "admitted_for_harness_launch",
          session_binding_ref:
            "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli:model-config-local-codex-oss-qwen",
          session_route_ref: "session-route:sessions/mission.default/project:ioi",
          harness_selection_ref: "agent-harness-adapter:codex_cli",
          harness_selection_kind: "agent_harness_adapter",
          harness_truth_boundary: "proposal_source_only",
          harness_launch_route_ref: "harness-route:codex-cli/local-model",
          agent_harness_adapter_id: "codex_cli",
          harness_profile_ref: null,
          model_configuration_ref: "model-config:local/codex-oss-qwen",
          model_route_ref: "model-route:hypervisor/default-local",
          model_route_policy: "hypervisor_model_mount",
          model_route_availability_state: "daemon_verified",
          model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
          model_route_loaded_instance_refs: [
            "model-instance:hypervisor/default-local",
          ],
          workspace_mount_policy: "redacted_projection",
          privacy_posture_ref: "privacy:redacted-projection",
          authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
          receipt_policy_ref: "receipt-policy:harness-adapter/default",
          receipt_preview_ref: "receipt-preview:new-session/admitted",
          expected_receipt_refs: [
            "receipt-preview:new-session/admitted",
            "receipt-policy:harness-adapter/default",
          ],
          agentgres_operation_refs: [
            "agentgres://operation/harness-session-binding/admit",
          ],
          receipt_refs: ["receipt://harness-session-binding/admit"],
          state_root: "agentgres://state-root/harness-session-binding/admit",
          harness_runtime_truth_claimed: false,
          requiresDaemonGate: true,
          runtimeTruthSource: "daemon-runtime",
          admitted_at: "2026-06-18T12:00:00.000Z",
        },
        workspace_ref: "workspace://local/ioi",
      },
    }),
    response: launchResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const spawnResponse = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-spawns",
      body: {
        session_launch: JSON.parse(launchResponse.body),
        workspace_root: "apps/hypervisor",
        model_name: "qwen2.5-coder:7b",
      },
    }),
    response: spawnResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const payload = JSON.parse(spawnResponse.body);
  assert.equal(spawnResponse.statusCode, 202);
  assert.equal(payload.schema_version, "ioi.runtime.harness_session_spawn.v1");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.spawn_state, "ready_for_client_pty_attach");
  assert.equal(payload.spawn_lane, "host_terminal_session");
  assert.equal(payload.workspace_root, "/workspace/apps/hypervisor");
  assert.equal(payload.model_name, "qwen2.5-coder:7b");
  assert.deepEqual(payload.command_contract.resolved_argv.slice(0, 6), [
    "codex",
    "--oss",
    "--local-provider",
    "ollama",
    "--model",
    "qwen2.5-coder:7b",
  ]);
  assert.equal(
    payload.command_contract.process_custody,
    "client_host_pty_after_daemon_spawn_admission",
  );
  assert.equal(payload.terminal_attach_contract.requires_pty, true);
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime harness session terminal attach admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-terminal-attachments",
      body: { session_spawn: {}, session_readiness: {} },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime routes expose DeepSeek TUI local harness session spawn contracts", async () => {
  const { handleRequest } = routeHarness();
  const launchResponse = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-launches",
      body: {
        binding_admission: {
          schema_version: "ioi.runtime.harness_session_binding_admission.v1",
          admission_id: "harness-session-binding-admission:deepseek-local",
          decision: "admitted",
          admission_state: "admitted_for_harness_launch",
          session_binding_ref:
            "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-deepseek_tui:model-config-local-codex-oss-qwen",
          session_route_ref: "session-route:sessions/mission.default/project:ioi",
          harness_selection_ref: "agent-harness-adapter:deepseek_tui",
          harness_selection_kind: "agent_harness_adapter",
          harness_truth_boundary: "proposal_source_only",
          harness_launch_route_ref: "harness-route:deepseek-tui/local-model",
          agent_harness_adapter_id: "deepseek_tui",
          harness_profile_ref: null,
          model_configuration_ref: "model-config:local/codex-oss-qwen",
          model_route_ref: "model-route:hypervisor/default-local",
          model_route_policy: "hypervisor_model_mount",
          model_route_availability_state: "daemon_verified",
          model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
          model_route_loaded_instance_refs: [
            "model-instance:hypervisor/default-local",
          ],
          workspace_mount_policy: "redacted_projection",
          privacy_posture_ref: "privacy:redacted-projection",
          authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
          receipt_policy_ref: "receipt-policy:harness-adapter/default",
          receipt_preview_ref: "receipt-preview:new-session/admitted",
          expected_receipt_refs: [
            "receipt-preview:new-session/admitted",
            "receipt-policy:harness-adapter/default",
          ],
          agentgres_operation_refs: [
            "agentgres://operation/harness-session-binding/admit",
          ],
          receipt_refs: ["receipt://harness-session-binding/admit"],
          state_root: "agentgres://state-root/harness-session-binding/admit",
          harness_runtime_truth_claimed: false,
          requiresDaemonGate: true,
          runtimeTruthSource: "daemon-runtime",
          admitted_at: "2026-06-18T12:00:00.000Z",
        },
        workspace_ref: "workspace://local/ioi",
      },
    }),
    response: launchResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const launch = JSON.parse(launchResponse.body);
  assert.equal(launchResponse.statusCode, 202);
  assert.equal(
    launch.command_contract.command_ref,
    "host-command:deepseek-tui/local-ollama-qwen",
  );
  assert.deepEqual(launch.command_contract.argv_template, [
    "deepseek",
    "--provider",
    "ollama",
    "--model",
    "${HYPERVISOR_LOCAL_HARNESS_MODEL:-qwen}",
  ]);

  const spawnResponse = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-spawns",
      body: {
        session_launch: launch,
        workspace_root: ".",
      },
    }),
    response: spawnResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const payload = JSON.parse(spawnResponse.body);
  assert.equal(spawnResponse.statusCode, 202);
  assert.equal(payload.schema_version, "ioi.runtime.harness_session_spawn.v1");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.agent_harness_adapter_id, "deepseek_tui");
  assert.equal(
    payload.command_contract_ref,
    "host-command:deepseek-tui/local-ollama-qwen",
  );
  assert.deepEqual(payload.command_contract.resolved_argv, [
    "deepseek",
    "--provider",
    "ollama",
    "--model",
    "qwen",
  ]);
  assert.equal(payload.terminal_attach_contract.requires_pty, true);
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime routes expose Claude Code example local harness session spawn contracts", async () => {
  const { handleRequest } = routeHarness();
  const launchResponse = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-launches",
      body: {
        binding_admission: {
          schema_version: "ioi.runtime.harness_session_binding_admission.v1",
          admission_id: "harness-session-binding-admission:claude-example-local",
          decision: "admitted",
          admission_state: "admitted_for_harness_launch",
          session_binding_ref:
            "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-claude_code_cli:model-config-local-codex-oss-qwen",
          session_route_ref: "session-route:sessions/mission.default/project:ioi",
          harness_selection_ref: "agent-harness-adapter:claude_code_cli",
          harness_selection_kind: "agent_harness_adapter",
          harness_truth_boundary: "proposal_source_only",
          harness_launch_route_ref: "harness-route:claude-code-cli/local-example",
          agent_harness_adapter_id: "claude_code_cli",
          harness_profile_ref: null,
          model_configuration_ref: "model-config:local/codex-oss-qwen",
          model_route_ref: "model-route:hypervisor/default-local",
          model_route_policy: "hypervisor_model_mount",
          model_route_availability_state: "daemon_verified",
          model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
          model_route_loaded_instance_refs: [
            "model-instance:hypervisor/default-local",
          ],
          workspace_mount_policy: "redacted_projection",
          privacy_posture_ref: "privacy:redacted-projection",
          authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
          receipt_policy_ref: "receipt-policy:harness-adapter/local-example",
          receipt_preview_ref: "receipt-preview:new-session/admitted",
          expected_receipt_refs: [
            "receipt-preview:new-session/admitted",
            "receipt-policy:harness-adapter/local-example",
          ],
          agentgres_operation_refs: [
            "agentgres://operation/harness-session-binding/admit",
          ],
          receipt_refs: ["receipt://harness-session-binding/admit"],
          state_root: "agentgres://state-root/harness-session-binding/admit",
          harness_runtime_truth_claimed: false,
          requiresDaemonGate: true,
          runtimeTruthSource: "daemon-runtime",
          admitted_at: "2026-06-18T12:00:00.000Z",
        },
        workspace_ref: "workspace://local/ioi",
      },
    }),
    response: launchResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const launch = JSON.parse(launchResponse.body);
  assert.equal(launchResponse.statusCode, 202);
  assert.equal(
    launch.command_contract.command_ref,
    "host-command:claude-code-example/local-ollama-qwen",
  );
  assert.equal(launch.command_contract.binary_name, "claude-code-example");
  assert.equal(
    launch.command_contract.example_script_ref,
    "packages/runtime-daemon/src/harness-shims/claude-code-example.mjs",
  );

  const spawnResponse = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-spawns",
      body: {
        session_launch: launch,
        workspace_root: ".",
      },
    }),
    response: spawnResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const payload = JSON.parse(spawnResponse.body);
  assert.equal(spawnResponse.statusCode, 202);
  assert.equal(payload.schema_version, "ioi.runtime.harness_session_spawn.v1");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.agent_harness_adapter_id, "claude_code_cli");
  assert.equal(
    payload.command_contract_ref,
    "host-command:claude-code-example/local-ollama-qwen",
  );
  assert.deepEqual(payload.command_contract.resolved_argv, [
    "node",
    "/workspace/packages/runtime-daemon/src/harness-shims/claude-code-example.mjs",
    "--provider",
    "ollama",
    "--model",
    "qwen",
    "--cd",
    "/workspace",
  ]);
  assert.deepEqual(payload.command_contract.readiness_probe_argv, [
    "node",
    "/workspace/packages/runtime-daemon/src/harness-shims/claude-code-example.mjs",
    "--help",
  ]);
  assert.equal(payload.terminal_attach_contract.requires_pty, true);
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime routes expose generic CLI local harness session spawn contracts", async () => {
  const { handleRequest } = routeHarness();
  const launchResponse = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-launches",
      body: {
        binding_admission: {
          schema_version: "ioi.runtime.harness_session_binding_admission.v1",
          admission_id: "harness-session-binding-admission:generic-cli-local",
          decision: "admitted",
          admission_state: "admitted_for_harness_launch",
          session_binding_ref:
            "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-generic_cli:model-config-local-codex-oss-qwen",
          session_route_ref: "session-route:sessions/mission.default/project:ioi",
          harness_selection_ref: "agent-harness-adapter:generic_cli",
          harness_selection_kind: "agent_harness_adapter",
          harness_truth_boundary: "proposal_source_only",
          harness_launch_route_ref: "harness-route:generic-cli/local-model",
          agent_harness_adapter_id: "generic_cli",
          harness_profile_ref: null,
          model_configuration_ref: "model-config:local/codex-oss-qwen",
          model_route_ref: "model-route:hypervisor/default-local",
          model_route_policy: "hypervisor_model_mount",
          model_route_availability_state: "daemon_verified",
          model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
          model_route_loaded_instance_refs: [
            "model-instance:hypervisor/default-local",
          ],
          workspace_mount_policy: "redacted_projection",
          privacy_posture_ref: "privacy:redacted-projection",
          authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
          receipt_policy_ref: "receipt-policy:harness-adapter/generic-cli",
          receipt_preview_ref: "receipt-preview:new-session/admitted",
          expected_receipt_refs: [
            "receipt-preview:new-session/admitted",
            "receipt-policy:harness-adapter/generic-cli",
          ],
          agentgres_operation_refs: [
            "agentgres://operation/harness-session-binding/admit",
          ],
          receipt_refs: ["receipt://harness-session-binding/admit"],
          state_root: "agentgres://state-root/harness-session-binding/admit",
          harness_runtime_truth_claimed: false,
          requiresDaemonGate: true,
          runtimeTruthSource: "daemon-runtime",
          admitted_at: "2026-06-18T12:00:00.000Z",
        },
        workspace_ref: "workspace://local/ioi",
      },
    }),
    response: launchResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const launch = JSON.parse(launchResponse.body);
  assert.equal(launchResponse.statusCode, 202);
  assert.equal(
    launch.command_contract.command_ref,
    "host-command:generic-cli/local-ollama-qwen",
  );
  assert.equal(launch.command_contract.binary_name, "generic-cli-local");
  assert.equal(
    launch.command_contract.example_script_ref,
    "packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs",
  );

  const spawnResponse = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-spawns",
      body: {
        session_launch: launch,
        workspace_root: ".",
      },
    }),
    response: spawnResponse,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const payload = JSON.parse(spawnResponse.body);
  assert.equal(spawnResponse.statusCode, 202);
  assert.equal(payload.schema_version, "ioi.runtime.harness_session_spawn.v1");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.agent_harness_adapter_id, "generic_cli");
  assert.equal(
    payload.command_contract_ref,
    "host-command:generic-cli/local-ollama-qwen",
  );
  assert.deepEqual(payload.command_contract.resolved_argv, [
    "node",
    "/workspace/packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs",
    "--provider",
    "ollama",
    "--model",
    "qwen",
    "--cd",
    "/workspace",
    "--harness-label",
    "Generic CLI Harness",
  ]);
  assert.deepEqual(payload.command_contract.readiness_probe_argv, [
    "node",
    "/workspace/packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs",
    "--help",
  ]);
  assert.equal(payload.terminal_attach_contract.requires_pty, true);
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime harness session launch route blocks unsupported harnesses", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-launches",
      body: {
        binding_admission: {
          schema_version: "ioi.runtime.harness_session_binding_admission.v1",
          admission_id: "harness-session-binding-admission:aider",
          decision: "admitted",
          admission_state: "admitted_for_harness_launch",
          session_binding_ref:
            "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-aider_cli:model-config-local-codex-oss-qwen",
          session_route_ref: "session-route:sessions/mission.default/project:ioi",
          harness_selection_ref: "agent-harness-adapter:aider_cli",
          harness_selection_kind: "agent_harness_adapter",
          harness_truth_boundary: "proposal_source_only",
          harness_launch_route_ref: "harness-route:aider-cli/local-model",
          agent_harness_adapter_id: "aider_cli",
          harness_profile_ref: null,
          model_configuration_ref: "model-config:local/codex-oss-qwen",
          model_route_ref: "model-route:hypervisor/default-local",
          model_route_policy: "hypervisor_model_mount",
          model_route_availability_state: "daemon_verified",
          model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
          model_route_loaded_instance_refs: [
            "model-instance:hypervisor/default-local",
          ],
          workspace_mount_policy: "redacted_projection",
          privacy_posture_ref: "privacy:redacted-projection",
          authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
          receipt_policy_ref: "receipt-policy:harness-adapter/default",
          receipt_preview_ref: "receipt-preview:new-session/admitted",
          expected_receipt_refs: [
            "receipt-preview:new-session/admitted",
            "receipt-policy:harness-adapter/default",
          ],
          agentgres_operation_refs: [
            "agentgres://operation/harness-session-binding/admit",
          ],
          receipt_refs: ["receipt://harness-session-binding/admit"],
          harness_runtime_truth_claimed: false,
          requiresDaemonGate: true,
          runtimeTruthSource: "daemon-runtime",
          admitted_at: "2026-06-18T12:00:00.000Z",
        },
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "harness_session_launch_harness_unsupported",
  });
});

test("public runtime service composition receipt bundle admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/service-composition-receipt-bundles",
      body: { service_ref: "service://sas/reporting" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime artifact availability incident admission route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/artifact-availability-incidents",
      body: { artifact_ref: "artifact://evidence/report" },
    }),
    response,
    store: {},
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
});

test("public runtime computer-use routes dispatch through Rust daemon-core projection", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const contextPolicyCore = {
    projectRuntimeComputerUse(request) {
      calls.push({ method: "projectRuntimeComputerUse", request });
      if (request.projection_kind === "provider_registry") {
        return {
          provider_registry: {
            object: "ioi.computer_use.provider_registry_report",
            providers: [{ provider_id: "ioi.computer_use.native_browser.task_scoped_profile" }],
          },
        };
      }
      return {
        browser_discovery: {
          object: "ioi.computer_use.browser_discovery_report",
          browser_process_count: 0,
          cdp_endpoint_count: 0,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
  };

  const providersResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/computer-use/providers" }),
    response: providersResponse,
    store,
    contextPolicyCore,
  });

  assert.equal(providersResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(providersResponse.body), {
    object: "ioi.computer_use.provider_registry_report",
    providers: [{ provider_id: "ioi.computer_use.native_browser.task_scoped_profile" }],
  });

  const browserResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/computer-use/browser-discovery?probe=false&include_tabs=true&reveal_tab_titles=true" }),
    response: browserResponse,
    store,
    contextPolicyCore,
  });

  assert.equal(browserResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(browserResponse.body), {
    object: "ioi.computer_use.browser_discovery_report",
    browser_process_count: 0,
    cdp_endpoint_count: 0,
  });
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeComputerUse",
      request: {
        operation: "runtime_computer_use_projection",
        operation_kind: "runtime.computer_use.projection.provider_registry",
        projection_kind: "provider_registry",
        workspace_root: "/workspace",
        state_dir: "/state",
        source: "public_runtime_routes./v1/computer-use/providers",
      },
    },
    {
      method: "projectRuntimeComputerUse",
      request: {
        operation: "runtime_computer_use_projection",
        operation_kind: "runtime.computer_use.projection.browser_discovery",
        projection_kind: "browser_discovery",
        workspace_root: "/workspace",
        state_dir: "/state",
        include_cdp_probe: false,
        include_tab_metadata: true,
        reveal_tab_titles: true,
        source: "public_runtime_routes./v1/computer-use/browser-discovery",
      },
    },
  ]);
});

test("public runtime repository workflow routes are retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const repositoryApi = {
    listRepositories: retiredRouteWrapper,
    repositoryContext: retiredRouteWrapper,
    branchPolicy: retiredRouteWrapper,
    githubContext: retiredRouteWrapper,
    prAttempts: retiredRouteWrapper,
    issueContext: retiredRouteWrapper,
    reviewGate: retiredRouteWrapper,
    githubPrCreatePlan: retiredRouteWrapper,
  };
  const store = { repositoryApi };

  for (const url of [
    "/v1/repositories",
    "/v1/repository-context",
    "/v1/branch-policy",
    "/v1/github-context",
    "/v1/pr-attempts",
    "/v1/issue-context",
    "/v1/review-gate",
    "/v1/github/pr-create-plan",
  ]) {
    const response = responseRecorder();
    await handleRequest({ request: request({ url }), response, store });
    assert.equal(response.statusCode, 410, `${url} should be retired`);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }
});

test("public runtime skill and hook routes are retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const store = {
    defaultCwd: "/workspace/canonical",
    skillHookApi: {
      listSkills: retiredRouteWrapper,
      listHooks: retiredRouteWrapper,
    },
  };

  for (const path of ["/v1/skills", "/v1/hooks"]) {
    const response = responseRecorder();
    await handleRequest({ request: request({ url: path }), response, store });
    assert.equal(response.statusCode, 410, `${path} should be retired`);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }
});

test("public runtime model catalog routes use mounted model projection surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    modelMounting: {
      runtimeModelCatalogList() {
        calls.push({ method: "runtimeModelCatalogList" });
        return {
          object: "list",
          data: [{ id: "model.route" }],
        };
      },
      listModelCapabilities() {
        calls.push({ method: "listModelCapabilities" });
        return {
          capabilities: [{ model: "model.route", features: ["chat"] }],
        };
      },
      listArtifacts() {
        calls.push({ method: "listArtifacts" });
        return [{ id: "artifact.route" }];
      },
      listEndpoints() {
        calls.push({ method: "listEndpoints" });
        return [{ id: "endpoint.route" }];
      },
      listProviders() {
        calls.push({ method: "listProviders" });
        return [{ id: "provider.route" }];
      },
      listRoutes() {
        calls.push({ method: "listRoutes" });
        return [{ id: "route.route" }];
      },
      getModel(id) {
        calls.push({ method: "getModel", id });
        return { id, object: "model.artifact" };
      },
      snapshot(baseUrl) {
        calls.push({ method: "snapshot", baseUrl });
        return { id: "snapshot.route", baseUrl };
      },
      projection() {
        calls.push({ method: "projection" });
        return { id: "projection.route" };
      },
      listMcpServers() {
        calls.push({ method: "listMcpServers" });
        return [{ id: "mcp.route" }];
      },
      importMcpJson(body) {
        calls.push({ method: "importMcpJson", body });
        return { id: "mcp.import", object: "mcp.import" };
      },
      invokeMcpTool({ authorization, body }) {
        calls.push({ method: "invokeMcpTool", authorization, body });
        return { id: "mcp.invoke", object: "mcp.invoke" };
      },
      executeWorkflowNode({ authorization, body }) {
        calls.push({ method: "executeWorkflowNode", authorization, body });
        return { id: "workflow.node", object: "workflow.node" };
      },
      validateReceiptGate(body) {
        calls.push({ method: "validateReceiptGate", body });
        return { id: "receipt.gate", object: "receipt.gate" };
      },
      upsertRoute(body) {
        calls.push({ method: "upsertRoute", body });
        return { id: "route.write", object: "route.upsert" };
      },
      testRoute(id, body) {
        calls.push({ method: "testRoute", id, body });
        return { id, object: "route.test" };
      },
      catalogSearch(query) {
        calls.push({ method: "catalogSearch", query });
        return [{ id: "catalog.route", query: query.query }];
      },
      catalogImportUrl(body) {
        calls.push({ method: "catalogImportUrl", body });
        return { id: "catalog.import", object: "catalog.import" };
      },
      importModel(body) {
        calls.push({ method: "importModel", body });
        return { id: "artifact.imported", object: "model.artifact" };
      },
      deleteModelArtifact(id, body) {
        calls.push({ method: "deleteModelArtifact", id, body });
        return { id, object: "model.artifact.deleted" };
      },
      mountEndpoint(body) {
        calls.push({ method: "mountEndpoint", body });
        return { id: "endpoint.route", object: "model.endpoint" };
      },
      downloadModel(body) {
        calls.push({ method: "downloadModel", body });
        return { id: "download.route", object: "model.download" };
      },
      downloadStatus(id) {
        calls.push({ method: "downloadStatus", id });
        return { id, status: "completed" };
      },
      cancelDownload(id, body) {
        calls.push({ method: "cancelDownload", id, body });
        return { id, status: "canceled" };
      },
      cleanupModelStorage(body) {
        calls.push({ method: "cleanupModelStorage", body });
        return { status: "cleaned" };
      },
      unmountEndpoint(body) {
        calls.push({ method: "unmountEndpoint", body });
        return { id: body.endpoint_id, object: "model.endpoint.unmounted" };
      },
      loadModel(body) {
        calls.push({ method: "loadModel", body });
        return { id: "instance.loaded", object: "model.instance.loaded", ...body };
      },
      unloadModel(body) {
        calls.push({ method: "unloadModel", body });
        return { id: body.instance_id ?? body.endpoint_id ?? "instance.unloaded", object: "model.instance.unloaded" };
      },
      authorize(authorization, scope) {
        calls.push({ method: "authorize", authorization, scope });
      },
      serverStatus(baseUrl) {
        calls.push({ method: "serverStatus", baseUrl });
        return { id: "server.status", baseUrl };
      },
      serverStart(baseUrl) {
        calls.push({ method: "serverStart", baseUrl });
        return { id: "server.start", baseUrl };
      },
      serverStop(baseUrl) {
        calls.push({ method: "serverStop", baseUrl });
        return { id: "server.stop", baseUrl };
      },
      serverRestart(baseUrl) {
        calls.push({ method: "serverRestart", baseUrl });
        return { id: "server.restart", baseUrl };
      },
      serverLogs(query) {
        calls.push({ method: "serverLogs", query });
        return { id: "server.logs", limit: query.limit };
      },
      serverEvents(query) {
        calls.push({ method: "serverEvents", query });
        return { id: "server.events", limit: query.limit };
      },
      listBackends() {
        calls.push({ method: "listBackends" });
        return [{ id: "backend.route" }];
      },
      backendHealth(id) {
        calls.push({ method: "backendHealth", id });
        return { id, object: "backend.health" };
      },
      startBackend(id, body) {
        calls.push({ method: "startBackend", id, body });
        return { id, object: "backend.start" };
      },
      stopBackend(id) {
        calls.push({ method: "stopBackend", id });
        return { id, object: "backend.stop" };
      },
      backendLogs(id) {
        calls.push({ method: "backendLogs", id });
        return { id, object: "backend.logs" };
      },
      listRuntimeEngines() {
        calls.push({ method: "listRuntimeEngines" });
        return [{ id: "engine.route" }];
      },
      runtimeEngine(id) {
        calls.push({ method: "runtimeEngine", id });
        return { id, object: "runtime.engine" };
      },
      runtimeSurvey() {
        calls.push({ method: "runtimeSurvey" });
        return { object: "runtime.survey" };
      },
      selectRuntimeEngine(body) {
        calls.push({ method: "selectRuntimeEngine", body });
        return { selectedEngineId: body.engine_id };
      },
      updateRuntimeEngine(id, body) {
        calls.push({ method: "updateRuntimeEngine", id, body });
        return { id, object: "runtime.engine.update" };
      },
      removeRuntimeEngineOverride(id) {
        calls.push({ method: "removeRuntimeEngineOverride", id });
        return { id, removed: true };
      },
      listInstances() {
        calls.push({ method: "listInstances" });
        return [{ id: "instance.loaded", status: "loaded" }, { id: "instance.idle", status: "idle" }];
      },
      authoritySnapshot(baseUrl) {
        calls.push({ method: "authoritySnapshot", baseUrl });
        return { id: "authority.snapshot", baseUrl };
      },
      listReceipts() {
        calls.push({ method: "listReceipts" });
        return [{ id: "receipt.route" }];
      },
      getReceipt(id) {
        calls.push({ method: "getReceipt", id });
        return { id };
      },
      receiptReplay(id) {
        calls.push({ method: "receiptReplay", id });
        return { receipt_id: id, replayed: true };
      },
    },
    listModels: retiredRouteWrapper,
    listModelCapabilities: retiredRouteWrapper,
  };

  const modelsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/models" }), response: modelsResponse, store });
  assert.equal(modelsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(modelsResponse.body), {
    object: "list",
    data: [{ id: "model.route" }],
  });

  const capabilitiesResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/model-capabilities" }),
    response: capabilitiesResponse,
    store,
  });
  assert.equal(capabilitiesResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(capabilitiesResponse.body), {
    capabilities: [{ model: "model.route", features: ["chat"] }],
  });

  for (const [path, expected] of [
    ["/v1/models/artifacts", [{ id: "artifact.route" }]],
    ["/v1/models/endpoints", [{ id: "endpoint.route" }]],
    ["/v1/models/providers", [{ id: "provider.route" }]],
    ["/v1/models/routes", [{ id: "route.route" }]],
    ["/v1/models/model.route", { id: "model.route", object: "model.artifact" }],
    ["/v1/model-mount/snapshot", { id: "snapshot.route", baseUrl: "http://daemon.test" }],
    ["/v1/model-mount/projection", { id: "projection.route" }],
    ["/v1/model-mount/mcp", [{ id: "mcp.route" }]],
    ["POST /v1/model-mount/mcp/import", { id: "mcp.import", object: "mcp.import" }],
    ["POST /v1/model-mount/mcp/invoke", { id: "mcp.invoke", object: "mcp.invoke" }],
    ["POST /v1/model-mount/workflows/nodes/execute", { id: "workflow.node", object: "workflow.node" }],
    ["POST /v1/model-mount/workflows/receipt-gate", { id: "receipt.gate", object: "receipt.gate" }],
    ["POST /v1/model-mount/routes", { id: "route.write", object: "route.upsert" }],
    ["POST /v1/model-mount/routes/route.route/test", { id: "route.route", object: "route.test" }],
    ["/v1/models/catalog/search?query=qwen", [{ id: "catalog.route", query: "qwen" }]],
    ["POST /v1/model-mount/catalog/import-url", { id: "catalog.import", object: "catalog.import" }],
    ["POST /v1/model-mount/artifacts/import", { id: "artifact.imported", object: "model.artifact" }],
    ["DELETE /v1/model-mount/artifacts/artifact.route", { id: "artifact.route", object: "model.artifact.deleted" }],
    ["POST /v1/model-mount/endpoints", { id: "endpoint.route", object: "model.endpoint" }],
    ["POST /v1/model-mount/downloads", { id: "download.route", object: "model.download" }],
    ["/v1/model-mount/downloads/download.route/status", { id: "download.route", status: "completed" }],
    ["POST /v1/model-mount/downloads/download.route/cancel", { id: "download.route", status: "canceled" }],
    ["POST /v1/model-mount/storage/cleanup", { status: "cleaned" }],
    ["POST /v1/model-mount/endpoints/endpoint.route/load", { id: "instance.loaded", object: "model.instance.loaded", endpoint_id: "endpoint.route" }],
    ["POST /v1/model-mount/endpoints/endpoint.route/unload", { id: "endpoint.route", object: "model.instance.unloaded" }],
    ["DELETE /v1/model-mount/endpoints/endpoint.route", { id: "endpoint.route", object: "model.endpoint.unmounted" }],
    ["/v1/model-mount/server/status", { id: "server.status", baseUrl: "http://daemon.test" }],
    ["POST /v1/model-mount/server/start", { id: "server.start", baseUrl: "http://daemon.test" }],
    ["POST /v1/model-mount/server/stop", { id: "server.stop", baseUrl: "http://daemon.test" }],
    ["POST /v1/model-mount/server/restart", { id: "server.restart", baseUrl: "http://daemon.test" }],
    ["/v1/model-mount/server/logs?limit=5", { id: "server.logs", limit: "5" }],
    ["/v1/model-mount/server/events?limit=6", { id: "server.events", limit: "6" }],
    ["/v1/model-mount/backends", [{ id: "backend.route" }]],
    ["POST /v1/model-mount/backends/backend.route/health", { id: "backend.route", object: "backend.health" }],
    ["POST /v1/model-mount/backends/backend.route/start", { id: "backend.route", object: "backend.start" }],
    ["POST /v1/model-mount/backends/backend.route/stop", { id: "backend.route", object: "backend.stop" }],
    ["/v1/model-mount/backends/backend.route/logs", { id: "backend.route", object: "backend.logs" }],
    ["/v1/model-mount/runtime/engines", [{ id: "engine.route" }]],
    ["/v1/model-mount/runtime/engines/engine.route", { id: "engine.route", object: "runtime.engine" }],
    ["POST /v1/model-mount/runtime/survey", { object: "runtime.survey" }],
    ["POST /v1/model-mount/runtime/select", {}],
    ["POST /v1/model-mount/runtime/engines/engine.route/select", { selectedEngineId: "engine.route" }],
    ["PATCH /v1/model-mount/runtime/engines/engine.route", { id: "engine.route", object: "runtime.engine.update" }],
    ["DELETE /v1/model-mount/runtime/engines/engine.route", { id: "engine.route", removed: true }],
    ["/v1/model-mount/instances", [{ id: "instance.loaded", status: "loaded" }, { id: "instance.idle", status: "idle" }]],
    ["/v1/model-mount/instances/loaded", [{ id: "instance.loaded", status: "loaded" }]],
    ["POST /v1/model-mount/instances/load", { id: "instance.loaded", object: "model.instance.loaded" }],
    ["POST /v1/model-mount/instances/unload", { id: "instance.unloaded", object: "model.instance.unloaded" }],
    ["POST /v1/model-mount/instances/instance.loaded/unload", { id: "instance.loaded", object: "model.instance.unloaded" }],
    ["/v1/model-mount/authority", { id: "authority.snapshot", baseUrl: "http://daemon.test" }],
    ["/v1/model-mount/receipts", [{ id: "receipt.route" }]],
    ["/v1/model-mount/receipts/receipt.route", { id: "receipt.route" }],
    ["/v1/model-mount/receipts/receipt.route/replay", { receipt_id: "receipt.route", replayed: true }],
  ]) {
    const methodMatch = path.match(/^(GET|POST|PATCH|DELETE) (.+)$/);
    const [method, routePath] = methodMatch ? [methodMatch[1], methodMatch[2]] : ["GET", path];
    const body = method === "PATCH" ? { label: "Engine route" } : {};
    const routeResponse = responseRecorder();
    await handleRequest({ request: request({ method, url: routePath, body }), response: routeResponse, store });
    const acceptedRoutes = new Set(["/v1/model-mount/catalog/import-url", "/v1/model-mount/downloads"]);
    const createdRoutes = new Set([
      "/v1/model-mount/routes",
      "/v1/model-mount/mcp/import",
      "/v1/model-mount/artifacts/import",
      "/v1/model-mount/endpoints",
      "/v1/model-mount/endpoints/endpoint.route/load",
      "/v1/model-mount/instances/load",
    ]);
    assert.equal(
      routeResponse.statusCode,
      acceptedRoutes.has(routePath) ? 202 : createdRoutes.has(routePath) ? 201 : 200,
    );
    assert.deepEqual(JSON.parse(routeResponse.body), expected);
  }

  assert.deepEqual(calls, [
    { method: "runtimeModelCatalogList" },
    { method: "listModelCapabilities" },
    { method: "listArtifacts" },
    { method: "listEndpoints" },
    { method: "listProviders" },
    { method: "listRoutes" },
    { method: "getModel", id: "model.route" },
    { method: "snapshot", baseUrl: "http://daemon.test" },
    { method: "projection" },
    { method: "listMcpServers" },
    { method: "importMcpJson", body: {} },
    { method: "invokeMcpTool", authorization: undefined, body: {} },
    { method: "executeWorkflowNode", authorization: undefined, body: {} },
    { method: "validateReceiptGate", body: {} },
    { method: "authorize", authorization: undefined, scope: "route.write:*" },
    { method: "upsertRoute", body: {} },
    { method: "authorize", authorization: undefined, scope: "route.use:route.route" },
    { method: "testRoute", id: "route.route", body: {} },
    { method: "catalogSearch", query: { query: "qwen" } },
    { method: "authorize", authorization: undefined, scope: "model.download:*" },
    { method: "authorize", authorization: undefined, scope: "model.import:*" },
    { method: "catalogImportUrl", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.import:*" },
    { method: "importModel", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.delete:*" },
    { method: "deleteModelArtifact", id: "artifact.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.mount:*" },
    { method: "mountEndpoint", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.download:*" },
    { method: "downloadModel", body: {} },
    { method: "downloadStatus", id: "download.route" },
    { method: "authorize", authorization: undefined, scope: "model.download:*" },
    { method: "cancelDownload", id: "download.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.delete:*" },
    { method: "cleanupModelStorage", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.load:*" },
    { method: "loadModel", body: { endpoint_id: "endpoint.route" } },
    { method: "authorize", authorization: undefined, scope: "model.unload:*" },
    { method: "unloadModel", body: { endpoint_id: "endpoint.route" } },
    { method: "authorize", authorization: undefined, scope: "model.unmount:*" },
    { method: "unmountEndpoint", body: { endpoint_id: "endpoint.route" } },
    { method: "serverStatus", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.control:*" },
    { method: "serverStart", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.control:*" },
    { method: "serverStop", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.control:*" },
    { method: "serverRestart", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.logs:*" },
    { method: "serverLogs", query: { limit: "5" } },
    { method: "authorize", authorization: undefined, scope: "server.logs:*" },
    { method: "serverEvents", query: { limit: "6" } },
    { method: "listBackends" },
    { method: "backendHealth", id: "backend.route" },
    { method: "authorize", authorization: undefined, scope: "backend.control:backend.route" },
    { method: "startBackend", id: "backend.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "backend.control:backend.route" },
    { method: "stopBackend", id: "backend.route" },
    { method: "backendLogs", id: "backend.route" },
    { method: "listRuntimeEngines" },
    { method: "runtimeEngine", id: "engine.route" },
    { method: "runtimeSurvey" },
    { method: "selectRuntimeEngine", body: {} },
    { method: "selectRuntimeEngine", body: { engine_id: "engine.route" } },
    { method: "updateRuntimeEngine", id: "engine.route", body: { label: "Engine route" } },
    { method: "removeRuntimeEngineOverride", id: "engine.route" },
    { method: "listInstances" },
    { method: "listInstances" },
    { method: "authorize", authorization: undefined, scope: "model.load:*" },
    { method: "loadModel", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.unload:*" },
    { method: "unloadModel", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.unload:*" },
    { method: "unloadModel", body: { instance_id: "instance.loaded" } },
    { method: "authoritySnapshot", baseUrl: "http://daemon.test" },
    { method: "listReceipts" },
    { method: "getReceipt", id: "receipt.route" },
    { method: "receiptReplay", id: "receipt.route" },
  ]);
});

test("public runtime provider vault token and catalog controls use stable model mount protocol routes", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    modelMounting: {
      authorize(authorization, scope) {
        calls.push({ method: "authorize", authorization, scope });
      },
      getCatalogProviderConfig(id) {
        calls.push({ method: "getCatalogProviderConfig", id });
        return { id, object: "catalog.provider" };
      },
      configureCatalogProvider(id, body) {
        calls.push({ method: "configureCatalogProvider", id, body });
        return { id, object: "catalog.provider.configured" };
      },
      startCatalogProviderOAuth(id, body) {
        calls.push({ method: "startCatalogProviderOAuth", id, body });
        return { id, object: "catalog.oauth.start" };
      },
      completeCatalogProviderOAuth(id, body) {
        calls.push({ method: "completeCatalogProviderOAuth", id, body });
        return { id, object: "catalog.oauth.callback" };
      },
      exchangeCatalogProviderOAuth(id, body) {
        calls.push({ method: "exchangeCatalogProviderOAuth", id, body });
        return { id, object: "catalog.oauth.exchange" };
      },
      refreshCatalogProviderOAuth(id) {
        calls.push({ method: "refreshCatalogProviderOAuth", id });
        return { id, object: "catalog.oauth.refresh" };
      },
      revokeCatalogProviderOAuth(id) {
        calls.push({ method: "revokeCatalogProviderOAuth", id });
        return { id, object: "catalog.oauth.revoke" };
      },
      listTokens() {
        calls.push({ method: "listTokens" });
        return [{ id: "token.route" }];
      },
      createToken(body) {
        calls.push({ method: "createToken", body });
        return { id: "token.created", object: "token" };
      },
      tokenizeModel({ authorization, requiredScope, body }) {
        calls.push({ method: "tokenizeModel", authorization, requiredScope, body });
        return { tokens: [{ text: "route" }], token_count: 1 };
      },
      countModelTokens({ authorization, requiredScope, body }) {
        calls.push({ method: "countModelTokens", authorization, requiredScope, body });
        return { token_count: 7 };
      },
      fitModelContext({ authorization, requiredScope, body }) {
        calls.push({ method: "fitModelContext", authorization, requiredScope, body });
        return { fits: true, context_window: 2048 };
      },
      revokeToken(id) {
        calls.push({ method: "revokeToken", id });
        return { id, revoked: true };
      },
      listVaultRefs() {
        calls.push({ method: "listVaultRefs" });
        return [{ vault_ref: "vault://route" }];
      },
      bindVaultRef(body) {
        calls.push({ method: "bindVaultRef", body });
        return { vault_ref: "vault://route", bound: true };
      },
      removeVaultRef(body) {
        calls.push({ method: "removeVaultRef", body });
        return { vault_ref: body.vault_ref, removed: true };
      },
      vaultRefMetadata(body) {
        calls.push({ method: "vaultRefMetadata", body });
        return { vault_ref: body.vault_ref, redacted: true };
      },
      vaultStatus() {
        calls.push({ method: "vaultStatus" });
        return { status: "ready" };
      },
      vaultHealth() {
        calls.push({ method: "vaultHealth" });
        return { status: "healthy" };
      },
      latestVaultHealth() {
        calls.push({ method: "latestVaultHealth" });
        return { status: "latest" };
      },
      listProviders() {
        calls.push({ method: "listProviders" });
        return [{ id: "provider.route" }];
      },
      upsertProvider(body) {
        calls.push({ method: "upsertProvider", body });
        return { id: body.id ?? "provider.created", object: "provider" };
      },
      latestProviderHealth(id) {
        calls.push({ method: "latestProviderHealth", id });
        return { id, status: "latest" };
      },
      providerHealth(id) {
        calls.push({ method: "providerHealth", id });
        return { id, status: "healthy" };
      },
      listProviderModels(id) {
        calls.push({ method: "listProviderModels", id });
        return [{ id: "provider.model", provider_id: id }];
      },
      listProviderLoaded(id) {
        calls.push({ method: "listProviderLoaded", id });
        return [{ id: "provider.loaded", provider_id: id }];
      },
      startProvider(id) {
        calls.push({ method: "startProvider", id });
        return { id, status: "started" };
      },
      stopProvider(id) {
        calls.push({ method: "stopProvider", id });
        return { id, status: "stopped" };
      },
    },
  };

  for (const [path, expected, status = 200] of [
    ["/v1/model-mount/catalog/providers/catalog.route", { id: "catalog.route", object: "catalog.provider" }],
    ["PATCH /v1/model-mount/catalog/providers/catalog.route", { id: "catalog.route", object: "catalog.provider.configured" }],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/start", { id: "catalog.route", object: "catalog.oauth.start" }, 201],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/callback", { id: "catalog.route", object: "catalog.oauth.callback" }, 201],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/exchange", { id: "catalog.route", object: "catalog.oauth.exchange" }, 201],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/refresh", { id: "catalog.route", object: "catalog.oauth.refresh" }],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/revoke", { id: "catalog.route", object: "catalog.oauth.revoke" }],
    ["/v1/model-mount/tokens", [{ id: "token.route" }]],
    ["POST /v1/model-mount/tokens", { id: "token.created", object: "token" }, 201],
    ["POST /v1/model-mount/tokens/tokenize", { tokens: [{ text: "route" }], token_count: 1 }],
    ["POST /v1/model-mount/tokens/count", { token_count: 7 }],
    ["POST /v1/model-mount/context/fit", { fits: true, context_window: 2048 }],
    ["DELETE /v1/model-mount/tokens/token.route", { id: "token.route", revoked: true }],
    ["/v1/model-mount/vault/refs", [{ vault_ref: "vault://route" }]],
    ["POST /v1/model-mount/vault/refs", { vault_ref: "vault://route", bound: true }, 201],
    ["DELETE /v1/model-mount/vault/refs", { vault_ref: "vault://route", removed: true }],
    ["POST /v1/model-mount/vault/refs/meta", { vault_ref: "vault://route", redacted: true }],
    ["/v1/model-mount/vault/status", { status: "ready" }],
    ["POST /v1/model-mount/vault/health", { status: "healthy" }],
    ["/v1/model-mount/vault/health/latest", { status: "latest" }],
    ["/v1/model-mount/providers", [{ id: "provider.route" }]],
    ["POST /v1/model-mount/providers", { id: "provider.created", object: "provider" }, 201],
    ["PATCH /v1/model-mount/providers/provider.route", { id: "provider.route", object: "provider" }],
    ["/v1/model-mount/providers/provider.route/health/latest", { id: "provider.route", status: "latest" }],
    ["POST /v1/model-mount/providers/provider.route/health", { id: "provider.route", status: "healthy" }],
    ["/v1/model-mount/providers/provider.route/models", [{ id: "provider.model", provider_id: "provider.route" }]],
    ["/v1/model-mount/providers/provider.route/loaded", [{ id: "provider.loaded", provider_id: "provider.route" }]],
    ["POST /v1/model-mount/providers/provider.route/start", { id: "provider.route", status: "started" }],
    ["POST /v1/model-mount/providers/provider.route/stop", { id: "provider.route", status: "stopped" }],
  ]) {
    const methodMatch = path.match(/^(GET|POST|PATCH|DELETE) (.+)$/);
    const [method, routePath] = methodMatch ? [methodMatch[1], methodMatch[2]] : ["GET", path];
    const body = routePath.includes("/vault/") ? { vault_ref: "vault://route" } : {};
    const routeResponse = responseRecorder();
    await handleRequest({ request: request({ method, url: routePath, body }), response: routeResponse, store });
    assert.equal(routeResponse.statusCode, status);
    assert.deepEqual(JSON.parse(routeResponse.body), expected);
  }

  assert.deepEqual(calls, [
    { method: "getCatalogProviderConfig", id: "catalog.route" },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "configureCatalogProvider", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "startCatalogProviderOAuth", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "completeCatalogProviderOAuth", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "exchangeCatalogProviderOAuth", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "refreshCatalogProviderOAuth", id: "catalog.route" },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.delete:*" },
    { method: "revokeCatalogProviderOAuth", id: "catalog.route" },
    { method: "listTokens" },
    { method: "createToken", body: {} },
    { method: "tokenizeModel", authorization: undefined, requiredScope: "model.tokenize:*", body: {} },
    { method: "countModelTokens", authorization: undefined, requiredScope: "model.tokenize:*", body: {} },
    { method: "fitModelContext", authorization: undefined, requiredScope: "model.context:*", body: {} },
    { method: "revokeToken", id: "token.route" },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "listVaultRefs" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "bindVaultRef", body: { vault_ref: "vault://route" } },
    { method: "authorize", authorization: undefined, scope: "vault.delete:*" },
    { method: "removeVaultRef", body: { vault_ref: "vault://route" } },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "vaultRefMetadata", body: { vault_ref: "vault://route" } },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "vaultStatus" },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "vaultHealth" },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "latestVaultHealth" },
    { method: "listProviders" },
    { method: "authorize", authorization: undefined, scope: "provider.write:*" },
    { method: "upsertProvider", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:provider.route" },
    { method: "upsertProvider", body: { id: "provider.route" } },
    { method: "latestProviderHealth", id: "provider.route" },
    { method: "providerHealth", id: "provider.route" },
    { method: "listProviderModels", id: "provider.route" },
    { method: "listProviderLoaded", id: "provider.route" },
    { method: "authorize", authorization: undefined, scope: "provider.control:provider.route" },
    { method: "startProvider", id: "provider.route" },
    { method: "authorize", authorization: undefined, scope: "provider.control:provider.route" },
    { method: "stopProvider", id: "provider.route" },
  ]);
});

test("public runtime studio intent route is retired (served by the Rust daemon)", async () => {
  const calls = [];
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const contextPolicyCore = {
    projectStudioIntentFrame(request) {
      calls.push({ method: "projectStudioIntentFrame", request });
      return { frame: {} };
    },
  };
  const store = {
    resolveStudioIntentFrame: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/studio/intent-frame",
      body: { prompt: "inspect the runtime", execution_mode: "ask" },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
  assert.deepEqual(calls, [], "the JS Studio intent-frame projection must not be invoked");
});

test("public runtime account node and tool routes are retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const store = {
    toolApi: {
      getAccount: retiredRouteWrapper,
      listRuntimeNodes: retiredRouteWrapper,
      listTools: retiredRouteWrapper,
    },
    getAccount: retiredRouteWrapper,
    listRuntimeNodes: retiredRouteWrapper,
    listTools: retiredRouteWrapper,
  };

  // Account summary, runtime node inventory, and the tool catalog are all Rust-owned (410);
  // the JS toolApi must not be invoked.
  for (const path of ["/v1/account", "/v1/runtime/nodes", "/v1/tools?pack=coding"]) {
    const retiredResponse = responseRecorder();
    await handleRequest({ request: request({ url: path }), response: retiredResponse, store });
    assert.equal(retiredResponse.statusCode, 410, `${path} should be retired`);
    assert.equal(
      JSON.parse(retiredResponse.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }
});

test("public runtime routes delegate thread subroutes unchanged", async () => {
  const { calls, handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({ request: request({ url: "/v1/threads/thread_123/events" }), response, store: {} });

  assert.deepEqual(calls, ["thread"]);
  assert.equal(response.ended, false);
});

test("public runtime agent and thread list routes are retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  let projectionCalled = false;
  const store = {
    projectRuntimeLifecycleProjection() {
      projectionCalled = true;
      return [];
    },
  };

  for (const path of ["/v1/agents", "/v1/threads"]) {
    const response = responseRecorder();
    await handleRequest({ request: request({ url: path }), response, store });
    assert.equal(response.statusCode, 410);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }
  assert.equal(projectionCalled, false, "the JS lifecycle projection must not be invoked");
});

test("public runtime run list route is retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  let projectionCalled = false;
  const store = {
    projectRuntimeLifecycleProjection() {
      projectionCalled = true;
      return [];
    },
  };

  const response = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/runs?agent_id=agent-canonical" }), response, store });
  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
  assert.equal(projectionCalled, false, "the JS lifecycle projection must not be invoked");
});

test("public runtime agent create route is retired (served by the Rust daemon)", async () => {
  let lifecycleInvoked = false;
  const { handleRequest } = routeHarness({
    createLifecycleAgent() {
      lifecycleInvoked = true;
    },
  });
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/agents",
      body: { options: { local: { cwd: "/workspace/project" } } },
    }),
    response,
    store: {},
    contextPolicyCore: { direct: true },
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
  assert.equal(lifecycleInvoked, false, "createLifecycleAgent must not be invoked");
});

test("public runtime thread create route is retired (served by the Rust daemon)", async () => {
  let lifecycleInvoked = false;
  const { handleRequest } = routeHarness({
    async createLifecycleThread() {
      lifecycleInvoked = true;
      return { thread_id: "thread_route", status: "active" };
    },
  });
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/threads",
      body: { options: { local: { cwd: "/workspace/project" } } },
    }),
    response,
    store: {},
    contextPolicyCore: { direct: true },
  });

  assert.equal(response.statusCode, 410);
  assert.equal(
    JSON.parse(response.body).error.code,
    "runtime_lifecycle_retired_served_by_rust_daemon",
  );
  assert.equal(lifecycleInvoked, false, "createLifecycleThread must not be invoked");
});

test("public runtime usage + authority-evidence routes are retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  let projectionCalled = false;
  const store = {
    projectRuntimeLifecycleProjection() {
      projectionCalled = true;
      return null;
    },
    listUsage: retiredRouteWrapper,
    authorityEvidenceSummary: retiredRouteWrapper,
  };

  for (const path of [
    "/v1/usage?group_by=thread&agent_id=agent_route",
    "/v1/authority-evidence?thread_id=thread_route",
    "/v1/workflow-capability-preflights",
  ]) {
    const response = responseRecorder();
    await handleRequest({ request: request({ url: path }), response, store });
    assert.equal(response.statusCode, 410, `${path} should be retired`);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }
  assert.equal(projectionCalled, false, "the JS lifecycle projection must not be invoked");
});

test("public runtime top-level memory context routes are retired", async () => {
  const { handleRequest } = routeHarness({
    notFound(message, details) {
      throw Object.assign(new Error(message), {
        status: 404,
        code: "route_not_found",
        details,
      });
    },
  });
  const store = {
    threadMemorySurface: {
      publicMemoryStatus() {
        assert.fail("retired top-level memory status route must not reach the memory surface");
      },
      publicMemoryProjectionForContext() {
        assert.fail("retired top-level memory records route must not reach the memory surface");
      },
      publicMemoryPolicyForContext() {
        assert.fail("retired top-level memory policy route must not reach the memory surface");
      },
      publicMemoryPathForContext() {
        assert.fail("retired top-level memory path route must not reach the memory surface");
      },
      publicValidateMemory() {
        assert.fail("retired top-level memory validation route must not reach the memory surface");
      },
    },
  };

  for (const route of [
    { method: "GET", url: "/v1/memory?thread_id=thread_route", path: "/v1/memory" },
    { method: "GET", url: "/v1/memory/records?thread_id=thread_route", path: "/v1/memory/records" },
    { method: "GET", url: "/v1/memory/policy?agent_id=agent_route", path: "/v1/memory/policy" },
    { method: "GET", url: "/v1/memory/path?thread_id=thread_route", path: "/v1/memory/path" },
    { method: "POST", url: "/v1/memory/validate", path: "/v1/memory/validate", body: { thread_id: "thread_route" } },
  ]) {
    const response = responseRecorder();
    await handleRequest({
      request: request({ method: route.method, url: route.url, body: route.body }),
      response,
      store,
    });
    assert.equal(response.statusCode, 404);
    assert.equal(response.error.code, "route_not_found");
    assert.deepEqual(response.error.details, { method: route.method, path: route.path });
  }
});

test("public conversation artifact routes are retired (served by the Rust daemon)", async () => {
  const { handleRequest } = routeHarness();
  const store = {
    listConversationArtifacts: retiredRouteWrapper,
    createConversationArtifact: retiredRouteWrapper,
    getConversationArtifact: retiredRouteWrapper,
    listConversationArtifactRevisions: retiredRouteWrapper,
    performConversationArtifactAction: retiredRouteWrapper,
    exportConversationArtifact: retiredRouteWrapper,
    promoteConversationArtifact: retiredRouteWrapper,
  };

  const requests = [
    { method: "GET", url: "/v1/conversation-artifacts?thread_id=thread_route" },
    { method: "POST", url: "/v1/conversation-artifacts", body: { thread_id: "thread_route", title: "Draft" } },
    { method: "GET", url: "/v1/conversation-artifacts/artifact_route" },
    { method: "GET", url: "/v1/conversation-artifacts/artifact_route/revisions" },
    { method: "POST", url: "/v1/conversation-artifacts/artifact_route/actions", body: { action_kind: "edit" } },
    { method: "POST", url: "/v1/conversation-artifacts/artifact_route/export", body: { export_format: "zip" } },
    { method: "POST", url: "/v1/conversation-artifacts/artifact_route/promote", body: { promotion_target: "canvas" } },
  ];

  for (const { method, url, body } of requests) {
    const response = responseRecorder();
    await handleRequest({ request: request({ method, url, body }), response, store });
    assert.equal(response.statusCode, 410, `${method} ${url} should be retired`);
    assert.equal(
      JSON.parse(response.body).error.code,
      "runtime_lifecycle_retired_served_by_rust_daemon",
    );
  }
});

test("public runtime task and job routes use store-owned task job API directly", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const body = { prompt: "plan the cutover" };
  const apiResult = (method, args) => ({
    status: "blocked",
    method,
    args,
  });
  const store = {
    createRuntimeTask(requestBody) {
      calls.push({ method: "createRuntimeTask", args: [requestBody] });
      return apiResult("createRuntimeTask", [requestBody]);
    },
    listRuntimeTasks(options) {
      calls.push({ method: "listRuntimeTasks", args: [options] });
      return apiResult("listRuntimeTasks", [options]);
    },
    getRuntimeTask(taskId) {
      calls.push({ method: "getRuntimeTask", args: [taskId] });
      return apiResult("getRuntimeTask", [taskId]);
    },
    cancelRuntimeTask(taskId) {
      calls.push({ method: "cancelRuntimeTask", args: [taskId] });
      return apiResult("cancelRuntimeTask", [taskId]);
    },
    listRuntimeJobs(options) {
      calls.push({ method: "listRuntimeJobs", args: [options] });
      return apiResult("listRuntimeJobs", [options]);
    },
    getRuntimeJob(jobId) {
      calls.push({ method: "getRuntimeJob", args: [jobId] });
      return apiResult("getRuntimeJob", [jobId]);
    },
    cancelRuntimeJob(jobId) {
      calls.push({ method: "cancelRuntimeJob", args: [jobId] });
      return apiResult("cancelRuntimeJob", [jobId]);
    },
  };
  const cases = [
    {
      method: "POST",
      path: "/v1/tasks",
      retired: true,
    },
    {
      method: "GET",
      path: "/v1/tasks?agent_id=agent-canonical",
      retired: true,
    },
    {
      method: "GET",
      path: "/v1/tasks/task_1",
      apiMethod: "getRuntimeTask",
      expectedArgs: ["task_1"],
    },
    {
      method: "POST",
      path: "/v1/tasks/task_1/cancel",
      apiMethod: "cancelRuntimeTask",
      expectedArgs: ["task_1"],
    },
    {
      method: "GET",
      path: "/v1/jobs?agent_id=agent-canonical",
      retired: true,
    },
    {
      method: "GET",
      path: "/v1/jobs/job_1",
      apiMethod: "getRuntimeJob",
      expectedArgs: ["job_1"],
    },
    {
      method: "POST",
      path: "/v1/jobs/job_1/cancel",
      apiMethod: "cancelRuntimeJob",
      expectedArgs: ["job_1"],
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleRequest({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body,
      }),
      response,
      store,
    });
    if (testCase.retired) {
      // Collection routes are retired (served by the Rust daemon); the store is not called.
      assert.equal(response.statusCode, 410);
      assert.equal(
        JSON.parse(response.body).error.code,
        "runtime_lifecycle_retired_served_by_rust_daemon",
      );
      continue;
    }
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.method, testCase.apiMethod);
    assert.deepEqual(call.args, testCase.expectedArgs);
    assert.deepEqual(JSON.parse(response.body), {
      status: "blocked",
      method: testCase.apiMethod,
      args: testCase.expectedArgs,
    });
  }
});

test("public runtime context budget route uses store-owned context policy API", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const body = { request_id: "public-context-budget-route-test" };
  const store = {
    contextPolicySurface: {
      evaluateContextBudget: retiredRouteWrapper,
    },
    evaluateContextBudget(input) {
      calls.push({ input });
      return {
        status: "rust_core_required",
        input,
        direct_truth_write_allowed: false,
      };
    },
  };

  await handleRequest({
    request: request({ method: "POST", url: "/v1/context-budget", body }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].input, { request: body });
  assert.deepEqual(JSON.parse(response.body), {
    status: "rust_core_required",
    input: { request: body },
    direct_truth_write_allowed: false,
  });
});

test("public runtime top-level MCP route family is retired", async () => {
  const { handleRequest } = routeHarness({
    notFound(message, details) {
      throw Object.assign(new Error(message), {
        status: 404,
        code: "route_not_found",
        details,
      });
    },
  });
  const failRetiredRoute = () => assert.fail("retired top-level MCP route must not reach an MCP surface");
  const store = {
    mcpCatalogApi: {
      mcpStatus: failRetiredRoute,
      listMcpServers: failRetiredRoute,
      listMcpTools: failRetiredRoute,
      searchMcpTools: failRetiredRoute,
      getMcpTool: failRetiredRoute,
      listMcpResources: failRetiredRoute,
      listMcpPrompts: failRetiredRoute,
      validateMcp: failRetiredRoute,
    },
    mcpControlApi: {
      importMcp: failRetiredRoute,
      addMcpServer: failRetiredRoute,
      setMcpServerEnabled: failRetiredRoute,
      removeMcpServer: failRetiredRoute,
      invokeMcpTool: failRetiredRoute,
    },
    mcpServeApi: {
      mcpServeStatus: failRetiredRoute,
      handleMcpServeJsonRpc: failRetiredRoute,
    },
  };
  const cases = [
    { method: "GET", path: "/v1/mcp?thread_id=thread_route" },
    { method: "GET", path: "/v1/mcp/servers?thread_id=thread_route" },
    { method: "GET", path: "/v1/mcp/tools" },
    { method: "GET", path: "/v1/mcp/tools/search?query=diff" },
    { method: "GET", path: "/v1/mcp/tools/mcp.tool" },
    { method: "GET", path: "/v1/mcp/resources" },
    { method: "GET", path: "/v1/mcp/prompts" },
    { method: "POST", path: "/v1/mcp/validate" },
    { method: "POST", path: "/v1/mcp/import?thread_id=thread_route" },
    { method: "POST", path: "/v1/mcp/servers" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/enable" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/disable" },
    { method: "DELETE", path: "/v1/mcp/servers/mcp.docs" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/remove" },
    { method: "POST", path: "/v1/mcp/tools/mcp.tool/invoke" },
    { method: "GET", path: "/v1/mcp/serve?thread_id=thread-retired" },
    { method: "POST", path: "/v1/mcp/serve?thread_id=thread-retired" },
  ];

  for (const { method, path } of cases) {
    const response = responseRecorder();
    await handleRequest({
      request: request({
        method,
        url: path,
        body: { request_id: "public-mcp-route-test" },
      }),
      response,
      store,
    });

    assert.equal(response.statusCode, 404);
    assert.equal(response.error.code, "route_not_found");
    assert.deepEqual(response.error.details, { method, path: new URL(path, "http://daemon.test").pathname });
  }
});

test("public runtime MCP serve route accepts stable protocol admission envelope", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    mcpServeApi: {
      handleMcpServeJsonRpc: retiredRouteWrapper,
    },
    handleMcpServeJsonRpc(threadId, message, options) {
      calls.push({ thisArg: this, threadId, message, options });
      return { jsonrpc: "2.0", id: message.id, result: { ok: true } };
    },
  };
  const admission = {
    authority_grant_refs: ["wallet.network://grant/mcp-serve/git.diff"],
    authority_receipt_refs: ["receipt://wallet.network/mcp-serve/git.diff"],
    custody_ref: "ctee://workspace/thread-route",
    containment_ref: "containment://mcp-serve/thread-route/git.diff",
  };
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/mcp/serve",
      body: {
        schema_version: "ioi.runtime.mcp-serve-client.v1",
        source: "sdk_client",
        ...admission,
        message: {
          jsonrpc: "2.0",
          id: 31,
          method: "tools/call",
          params: { name: "git.diff", arguments: { includeStat: true } },
        },
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls[0].thisArg, store);
  assert.equal(calls[0].threadId, "thread_route");
  assert.equal(calls[0].message.method, "tools/call");
  assert.deepEqual(calls[0].options.authority_grant_refs, admission.authority_grant_refs);
  assert.deepEqual(calls[0].options.authority_receipt_refs, admission.authority_receipt_refs);
  assert.equal(calls[0].options.custody_ref, admission.custody_ref);
  assert.equal(calls[0].options.containment_ref, admission.containment_ref);
  assert.equal(calls[0].options.thread_id, "thread_route");
  assert.deepEqual(JSON.parse(response.body), { jsonrpc: "2.0", id: 31, result: { ok: true } });
});

test("public runtime MCP serve route rejects query or raw JSON-RPC compatibility transport", async () => {
  const { handleRequest } = routeHarness();
  const store = {
    mcpServeStatus: retiredRouteWrapper,
    handleMcpServeJsonRpc: retiredRouteWrapper,
    mcpServeApi: {
      mcpServeStatus: retiredRouteWrapper,
      handleMcpServeJsonRpc: retiredRouteWrapper,
    },
  };

  for (const { method, url, body, code } of [
    {
      method: "GET",
      url: "/v1/threads/thread_route/mcp/serve?server_id=mcp.docs",
      body: {},
      code: "runtime_mcp_serve_query_context_retired",
    },
    {
      method: "POST",
      url: "/v1/threads/thread_route/mcp/serve?server_id=mcp.docs",
      body: {
        schema_version: "ioi.runtime.mcp-serve-client.v1",
        message: { jsonrpc: "2.0", id: 32, method: "tools/list" },
      },
      code: "runtime_mcp_serve_query_context_retired",
    },
    {
      method: "POST",
      url: "/v1/threads/thread_route/mcp/serve",
      body: { jsonrpc: "2.0", id: 33, method: "tools/list" },
      code: "runtime_mcp_serve_protocol_envelope_required",
    },
  ]) {
    const response = responseRecorder();
    await handleRequest({
      request: request({ method, url, body }),
      response,
      store,
    });

    assert.equal(response.statusCode, 400);
    assert.equal(response.error.code, code);
  }
});

test("harness session turn lane route runs the injected spawn executor", async () => {
  const laneCalls = [];
  const { handleRequest } = routeHarness({
    executeHarnessSpawnLane: async (input) => {
      laneCalls.push(input);
      return {
        schema_version: "ioi.hypervisor.harness_spawn_lane_result.v1",
        exit_status: "success",
        files_written: ["index.html"],
        runtimeTruthSource: "daemon-runtime",
      };
    },
  });
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-turn-lanes",
      body: {
        spawn: { schema_version: "ioi.runtime.harness_session_spawn.v1" },
        intent: "create a website that explains post-quantum computers",
        model_endpoint: "http://127.0.0.1:11434/v1",
      },
    }),
    response,
    store: { defaultCwd: "/workspace" },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body).files_written, ["index.html"]);
  assert.equal(laneCalls.length, 1);
  assert.equal(
    laneCalls[0].intent,
    "create a website that explains post-quantum computers",
  );
  assert.equal(laneCalls[0].model_endpoint, "http://127.0.0.1:11434/v1");
});

test("harness session turn lane route reports 501 when no executor is configured", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-turn-lanes",
      body: { spawn: {}, intent: "do work" },
    }),
    response,
    store: { defaultCwd: "/workspace" },
  });

  assert.equal(response.statusCode, 501);
  assert.equal(
    JSON.parse(response.body).error.code,
    "harness_spawn_lane_executor_unconfigured",
  );
});

test("harness lane route gates on the wallet lease and admits writes (Phase 4)", async () => {
  const { handleRequest } = routeHarness({
    executeHarnessSpawnLane: async () => ({
      schema_version: "ioi.hypervisor.harness_spawn_lane_result.v1",
      exit_status: "success",
      workspace_root: "/tmp/ws",
      files_written: ["index.html"],
      runtimeTruthSource: "daemon-runtime",
    }),
    agentgresAdmissionClient: createAgentgresAdmissionClient({
      nowIso: () => "2026-06-19T00:00:00.000Z",
    }),
  });
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-turn-lanes",
      body: {
        spawn: {
          schema_version: "ioi.runtime.harness_session_spawn.v1",
          session_route_ref: "session-route:demo",
          authority_scope_refs: ["scope:workspace.patch"],
        },
        intent: "create a website",
      },
    }),
    response,
    store: { defaultCwd: "/workspace" },
  });

  assert.equal(response.statusCode, 200);
  const result = JSON.parse(response.body);
  assert.equal(result.governance.operations.length, 1);
  assert.equal(result.governance.operations[0].operation_kind, "workspace_write");
  assert.match(result.governance.latest_receipt_refs[0], /^receipt:\/\/agentgres\//);
});

test("harness lane route blocks (403 step-up) when the workspace lease is missing (Phase 4)", async () => {
  let laneCalled = false;
  const { handleRequest } = routeHarness({
    executeHarnessSpawnLane: async () => {
      laneCalled = true;
      return { exit_status: "success", files_written: [] };
    },
    agentgresAdmissionClient: createAgentgresAdmissionClient(),
  });
  const response = responseRecorder();
  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-session-turn-lanes",
      body: {
        spawn: {
          schema_version: "ioi.runtime.harness_session_spawn.v1",
          session_route_ref: "session-route:demo",
          authority_scope_refs: [],
        },
        intent: "create a website",
      },
    }),
    response,
    store: { defaultCwd: "/workspace" },
  });

  assert.equal(response.statusCode, 403);
  assert.equal(response.error.code, "harness_operation_capability_lease_required");
  assert.equal(laneCalled, false);
});
