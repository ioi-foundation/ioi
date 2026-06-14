import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";
import { createModelMountCore } from "./model-mounting/model-mount-core.mjs";

test("daemon-level typed APIs feed migrated daemon-core surfaces", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-daemon-core-direct-"));
  const calls = [];
  const contextLifecycleCalls = [];
  const runtimeControlCalls = [];
  const threadLifecycleCalls = [];
  const workspaceTrustCalls = [];
  const mcpCalls = [];
  const modelMountCalls = [];
  const threadMemoryCalls = [];
  const agentgresCalls = [];
  const approvalCalls = [];
  const governedAdmissionCalls = [];
  const failCommandInvoker = (request) => {
    calls.push(request);
    throw new Error(`generic command invoker must not run migrated typed APIs: ${request?.operation}`);
  };
  const assertModelMountDirectApiCall = (call, method, schemaVersion) => {
    assert.equal(call.method, method);
    assert.equal(call.request.schema_version, schemaVersion);
    assert.equal(Object.hasOwn(call.request, "operation"), false);
    assert.equal(Object.hasOwn(call.request, "backend"), false);
  };
  const daemonCoreModelMountApi = {
    admitModelMountInvocation(request) {
      modelMountCalls.push({ method: "admitModelMountInvocation", request });
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          invocation_admission_ref: "model_mount://invocation_admission/direct",
          invocation_admission_hash: "sha256:direct-invocation",
        },
        invocation_admission_ref: "model_mount://invocation_admission/direct",
        invocation_admission_hash: "sha256:direct-invocation",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["rust_daemon_core_model_mount_invocation"],
      };
    },
    admitModelMountProviderExecution(request) {
      modelMountCalls.push({ method: "admitModelMountProviderExecution", request });
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_execution_ref: "model_mount://provider_execution/direct",
          provider_execution_hash: "sha256:direct-provider-execution",
        },
        provider_execution_ref: "model_mount://provider_execution/direct",
        provider_execution_hash: "sha256:direct-provider-execution",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["rust_daemon_core_model_mount_provider_execution"],
      };
    },
    executeModelMountProviderInvocation(request) {
      modelMountCalls.push({ method: "executeModelMountProviderInvocation", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          output_text: "direct provider invocation",
          token_count: { total_tokens: 1 },
          provider_response_kind: "rust_model_mount.fixture",
          backend_id: request.backend_ref,
          invocation_hash: "sha256:direct-provider-invocation",
          evidence_refs: ["rust_daemon_core_model_mount_provider_invocation"],
        },
        outputText: "direct provider invocation",
        tokenCount: { total_tokens: 1 },
        providerResponseKind: "rust_model_mount.fixture",
        execution_backend: request.execution_backend,
        backendId: request.backend_ref,
        invocation_hash: "sha256:direct-provider-invocation",
        evidence_refs: ["rust_daemon_core_model_mount_provider_invocation"],
      };
    },
    executeModelMountProviderStreamInvocation(request) {
      modelMountCalls.push({ method: "executeModelMountProviderStreamInvocation", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          output_text: "direct provider stream",
          token_count: { total_tokens: 1 },
          provider_response_kind: "rust_model_mount.native_local.stream",
          backend_id: request.backend_ref,
          stream_format: "ioi_jsonl",
          stream_kind: "openai_responses_native_local",
          stream_chunks: ["{\"delta\":\"direct\",\"done\":false}\n", "{\"delta\":\"\",\"done\":true}\n"],
          invocation_hash: "sha256:direct-provider-stream",
          evidence_refs: ["rust_daemon_core_model_mount_provider_stream_invocation"],
        },
        outputText: "direct provider stream",
        tokenCount: { total_tokens: 1 },
        providerResponseKind: "rust_model_mount.native_local.stream",
        execution_backend: request.execution_backend,
        backendId: request.backend_ref,
        streamFormat: "ioi_jsonl",
        streamKind: "openai_responses_native_local",
        streamChunks: ["{\"delta\":\"direct\",\"done\":false}\n", "{\"delta\":\"\",\"done\":true}\n"],
        invocation_hash: "sha256:direct-provider-stream",
        evidence_refs: ["rust_daemon_core_model_mount_provider_stream_invocation"],
      };
    },
    planModelMountProviderLifecycle(request) {
      modelMountCalls.push({ method: "planModelMountProviderLifecycle", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          status: "loaded",
          backend: "autopilot.native_local.fixture",
          backend_id: request.backend_ref,
          lifecycle_hash: "sha256:direct-provider-lifecycle",
          evidence_refs: ["rust_daemon_core_model_mount_provider_lifecycle"],
        },
        status: "loaded",
        backend_id: request.backend_ref,
        provider_backend: "autopilot.native_local.fixture",
        driver: request.driver,
        execution_backend: request.execution_backend,
        lifecycle_hash: "sha256:direct-provider-lifecycle",
        evidence_refs: ["rust_daemon_core_model_mount_provider_lifecycle"],
      };
    },
    planModelMountProviderInventory(request) {
      modelMountCalls.push({ method: "planModelMountProviderInventory", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          status: "listed",
          backend: "autopilot.native_local.fixture",
          backend_id: request.backend_ref,
          item_refs: ["model_instance://native/direct"],
          item_count: 1,
          inventory_hash: "sha256:direct-provider-inventory",
          evidence_refs: ["rust_daemon_core_model_mount_provider_inventory"],
        },
        status: "listed",
        backend_id: request.backend_ref,
        provider_backend: "autopilot.native_local.fixture",
        driver: request.driver,
        execution_backend: request.execution_backend,
        item_refs: ["model_instance://native/direct"],
        item_count: 1,
        inventory_hash: "sha256:direct-provider-inventory",
        evidence_refs: ["rust_daemon_core_model_mount_provider_inventory"],
      };
    },
    planModelMountInstanceLifecycle(request) {
      modelMountCalls.push({ method: "planModelMountInstanceLifecycle", request });
      return {
        source: "direct_model_mount_api",
        backend: request.execution_backend,
        result: {
          ...request,
          status: "loaded",
          backend_id: request.backend_ref,
          instance_lifecycle_hash: "sha256:direct-instance-lifecycle",
          evidence_refs: ["rust_daemon_core_model_mount_instance_lifecycle"],
        },
        status: "loaded",
        backendId: request.backend_ref,
        driver: request.driver,
        execution_backend: request.execution_backend,
        provider_lifecycle_hash: request.provider_lifecycle_hash,
        instance_lifecycle_hash: "sha256:direct-instance-lifecycle",
        evidence_refs: ["rust_daemon_core_model_mount_instance_lifecycle"],
      };
    },
    admitModelMountProviderResult(request) {
      modelMountCalls.push({ method: "admitModelMountProviderResult", request });
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          provider_result_ref: "model_mount://provider_result/direct",
          provider_result_hash: "sha256:direct-provider-result",
        },
        provider_result_ref: "model_mount://provider_result/direct",
        provider_result_hash: "sha256:direct-provider-result",
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["rust_daemon_core_model_mount_provider_result"],
      };
    },
    planModelMountArtifactEndpoint(request) {
      modelMountCalls.push({ method: "planModelMountArtifactEndpoint", request });
      const record = {
        id: "endpoint.direct",
        object: "ioi.model_mount_endpoint",
        status: "mounted",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.artifact_endpoint",
        model_id: request.body?.model_id ?? null,
        provider_id: request.body?.provider_id ?? null,
        public_response: {
          object: "ioi.model_mount_endpoint",
          id: "endpoint.direct",
          endpoint_id: "endpoint.direct",
          model_id: request.body?.model_id ?? null,
          provider_id: request.body?.provider_id ?? null,
          status: "mounted",
          plaintext_transport_material_returned: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_artifact_endpoint_js_facade_retired",
          "rust_daemon_core_artifact_endpoint",
          "agentgres_artifact_endpoint_truth_required",
        ],
        control_hash: "sha256:direct-artifact-endpoint-control",
        authority_hash: "sha256:direct-artifact-endpoint-authority",
      };
      return {
        source: "direct_model_mount_api",
        schema_version: "ioi.model_mount.artifact_endpoint_plan.v1",
        object: "ioi.model_mount_artifact_endpoint_plan",
        status: "planned",
        rust_core_boundary: "model_mount.artifact_endpoint",
        operation_kind: request.operation_kind,
        record_dir: "model-endpoints",
        record_id: record.id,
        record,
        public_response: record.public_response,
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: record.control_hash,
        authority_hash: record.authority_hash,
      };
    },
    planModelMountStorageControl(request) {
      modelMountCalls.push({ method: "planModelMountStorageControl", request });
      const record = {
        id: "download.direct",
        object: "ioi.model_mount_download",
        status: "queued",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        details: {
          model_id: request.body?.model_id ?? null,
          network_transfer_executed: false,
        },
        public_response: {
          object: "ioi.model_mount_download",
          id: "download.direct",
          status: "queued",
          record_dir: "model-downloads",
          record_id: "download.direct",
          operation_kind: request.operation_kind,
          rust_core_boundary: "model_mount.storage_control",
          js_network_transfer_executed: false,
          js_filesystem_mutation_executed: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_model_storage_js_facade_retired",
          "rust_daemon_core_model_storage",
          "agentgres_model_storage_truth_required",
        ],
        control_hash: "sha256:direct-storage-control",
        authority_hash: "sha256:direct-storage-authority",
      };
      return {
        source: "direct_model_mount_api",
        backend: "rust_model_mount_storage_control",
        plan: {
          schema_version: "ioi.model_mount.storage_control_plan.v1",
          object: "ioi.model_mount_storage_control_plan",
          status: "planned",
          rust_core_boundary: "model_mount.storage_control",
          operation_kind: request.operation_kind,
          source: request.source,
          record_dir: "model-downloads",
          record_id: record.id,
          record,
          public_response: record.public_response,
          receipt_refs: request.receipt_refs ?? [],
          authority_grant_refs: request.authority_grant_refs ?? [],
          authority_receipt_refs: request.authority_receipt_refs ?? [],
          evidence_refs: record.evidence_refs,
          control_hash: "sha256:direct-storage-control",
          authority_hash: "sha256:direct-storage-authority",
        },
        record_dir: "model-downloads",
        record_id: record.id,
        record,
        public_response: record.public_response,
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.storage_control",
        control_hash: "sha256:direct-storage-control",
        authority_hash: "sha256:direct-storage-authority",
      };
    },
    planModelMountMcpWorkflow(request) {
      modelMountCalls.push({ method: "planModelMountMcpWorkflow", request });
      const record = {
        id: "mcp_import.direct",
        object: "ioi.model_mount_mcp_workflow",
        status: "committed",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.mcp_workflow",
        details: {
          server_ids: ["mcp.direct"],
          js_registry_mutation: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "rust_daemon_core_model_mount_mcp_workflow",
          "agentgres_mcp_workflow_truth_required",
        ],
        workflow_hash: "sha256:direct-mcp-workflow",
        authority_hash: "sha256:direct-mcp-authority",
      };
      return {
        source: "direct_model_mount_api",
        status: "committed",
        rust_core_boundary: "model_mount.mcp_workflow",
        operation_kind: request.operation_kind,
        record_dir: "mcp-servers",
        record_id: record.id,
        record,
        public_response: {
          status: "committed",
          operation_kind: request.operation_kind,
          server_ids: ["mcp.direct"],
        },
        receipt_refs: request.receipt_refs ?? [],
        authority_grant_refs: request.authority_grant_refs ?? [],
        authority_receipt_refs: request.authority_receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        workflow_hash: record.workflow_hash,
        authority_hash: record.authority_hash,
      };
    },
    planModelMountServerControl(request) {
      modelMountCalls.push({ method: "planModelMountServerControl", request });
      const record = {
        id: "server-control.direct",
        object: "ioi.model_mount_server_control_record",
        status: "planned",
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.server_control",
        public_response: {
          object: "ioi.model_mount_server_control",
          status: "planned",
          operation_kind: request.operation_kind,
          server_status: "start_planned",
          js_transport_execution: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_server_control_js_facade_retired",
          "rust_daemon_core_server_control",
          "agentgres_server_control_truth_required",
        ],
        control_hash: "sha256:direct-server-control",
      };
      return {
        source: "direct_model_mount_api",
        status: "planned",
        rust_core_boundary: "model_mount.server_control",
        operation_kind: request.operation_kind,
        record_dir: "model-server-controls",
        record_id: record.id,
        record,
        public_response: record.public_response,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: record.evidence_refs,
        control_hash: record.control_hash,
      };
    },
  };
  const directModelMountCore = createModelMountCore({
    daemonCoreInvoker: failCommandInvoker,
    daemonCoreModelMountApi,
  });
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountCore: {
      admitInvocation(request) {
        return directModelMountCore.admitInvocation(request);
      },
      admitProviderExecution(request) {
        return directModelMountCore.admitProviderExecution(request);
      },
      executeProviderInvocation(request) {
        return directModelMountCore.executeProviderInvocation(request);
      },
      executeProviderStreamInvocation(request) {
        return directModelMountCore.executeProviderStreamInvocation(request);
      },
      planProviderLifecycle(request) {
        return directModelMountCore.planProviderLifecycle(request);
      },
      planProviderInventory(request) {
        return directModelMountCore.planProviderInventory(request);
      },
      planInstanceLifecycle(request) {
        return directModelMountCore.planInstanceLifecycle(request);
      },
      admitProviderResult(request) {
        return directModelMountCore.admitProviderResult(request);
      },
      planArtifactEndpoint(request) {
        return directModelMountCore.planArtifactEndpoint(request);
      },
      planReadProjection(request) {
        const projection = {
          schemaVersion: request.schema_version,
          source: "agentgres_model_mounting_projection",
        };
        return {
          source: "rust_model_mount_read_projection_command",
          backend: "rust_model_mount_read_projection",
          projection_kind: request.projection_kind,
          evidence_refs: [
            "rust_daemon_core_model_mount_projection",
            "agentgres_model_mount_read_truth",
            "model_mount_js_read_projection_authoring_retired",
          ],
          projection,
        };
      },
      planStorageControl(request) {
        return directModelMountCore.planStorageControl(request);
      },
      planMcpWorkflow(request) {
        return directModelMountCore.planMcpWorkflow(request);
      },
      planServerControl(request) {
        return directModelMountCore.planServerControl(request);
      },
    },
    daemonCoreInvoker: failCommandInvoker,
    daemonCoreModelMountApi,
    daemonCoreContextLifecycleApi: {
      evaluateContextBudgetPolicy(request) {
        contextLifecycleCalls.push({ method: "evaluateContextBudgetPolicy", request });
        return {
          source: "direct_context_lifecycle_api",
          backend: "rust_policy",
          status: "allowed",
          mode: "monitor",
          usage_telemetry: request.usage_telemetry,
          usage_summary: request.usage_telemetry,
          policy_decision_refs: ["policy://direct-context-budget"],
        };
      },
    },
    daemonCoreRuntimeControlApi: {
      planRunCancelStateUpdate(request) {
        runtimeControlCalls.push({ method: "planRunCancelStateUpdate", request });
        return {
          source: "direct_runtime_control_api",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "run.cancel",
          updated_at: request.canceled_at,
          run: {
            id: request.run_id,
            status: "canceled",
            events: [{ type: "canceled" }],
          },
        };
      },
    },
    daemonCoreThreadLifecycleApi: {
      planAgentCreateStateUpdate(request) {
        threadLifecycleCalls.push({ method: "planAgentCreateStateUpdate", request });
        return {
          source: "direct_thread_lifecycle_api",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "agent.create",
          created_at: request.agent?.createdAt,
          updated_at: request.agent?.updatedAt,
          agent: {
            id: request.agent?.id,
            status: request.agent?.status ?? "active",
          },
        };
      },
    },
    daemonCoreWorkspaceTrustApi: {
      planWorkspaceTrustControlStateUpdate(request) {
        workspaceTrustCalls.push({ method: "planWorkspaceTrustControlStateUpdate", request });
        return {
          source: "direct_workspace_trust_api",
          backend: "rust_policy",
          status: "planned",
          operation_kind: request.operation_kind,
          thread_id: request.thread_id,
          event_stream_id: request.event_stream_id,
          event: {
            event_id: request.event_id,
            thread_id: request.thread_id,
            event_kind: "workspace.trust_warning",
            receipt_refs: ["receipt://workspace-trust/direct"],
          },
        };
      },
    },
    daemonCoreMcpApi: {
      planMcpManagerStatusProjection(request) {
        mcpCalls.push({ method: "planMcpManagerStatusProjection", request });
        return {
          source: "direct_mcp_api",
          backend: "rust_policy",
          status: "ready",
          server_count: request.servers?.length ?? 0,
          tool_count: request.tools?.length ?? 0,
          resource_count: request.resources?.length ?? 0,
          prompt_count: request.prompts?.length ?? 0,
          enabled_server_count: request.servers?.filter((server) => server?.enabled !== false).length ?? 0,
          enabled_tool_count: request.enabled_tools?.length ?? 0,
          servers: request.servers ?? [],
          tools: request.tools ?? [],
          resources: request.resources ?? [],
          prompts: request.prompts ?? [],
          validation: request.validation ?? {},
          routes: request.routes ?? {},
        };
      },
    },
    daemonCoreThreadMemoryApi: {
      planRuntimeMemoryControl(request) {
        threadMemoryCalls.push({ method: "planRuntimeMemoryControl", request });
        return {
          source: "direct_thread_memory_api",
          backend: "rust_memory",
          status: "planned",
          operation: request.operation,
          operation_kind: request.operation_kind,
          memory_state_kind: "record",
          state_id: "memory_direct",
          thread_id: request.thread_id,
          agent_id: request.agent_id,
          workspace_root: request.workspace_root,
          payload: {
            schema_version: "ioi.agent-runtime.memory.v1",
            object: "ioi.agent_memory_record",
            id: "memory_direct",
            thread_id: request.thread_id,
            agent_id: request.agent_id,
            fact: request.request?.text ?? "direct memory",
            receipt_refs: ["receipt://thread-memory/direct"],
          },
          receipt_refs: ["receipt://thread-memory/direct"],
        };
      },
    },
    daemonCoreAgentgresApi: {
      commitRuntimeRunState(request) {
        agentgresCalls.push({ method: "commitRuntimeRunState", request });
        return {
          source: "direct_agentgres_api",
          backend: "rust_agentgres_storage",
          commit_hash: "sha256:direct-agentgres-commit",
          record: {
            run_id: request.request.run_id,
          },
        };
      },
    },
    daemonCoreApprovalApi: {
      projectApprovalQueue(request) {
        approvalCalls.push({ method: "projectApprovalQueue", request });
        return {
          source: "direct_approval_api",
          backend: "rust_authority",
          status: "projected",
          operation_kind: "approval.queue_projection",
          thread_id: request.thread_id,
          approvals: [],
          pending_count: 0,
          resolved_count: 0,
        };
      },
    },
    daemonCoreGovernedAdmissionApi: {
      admitL1SettlementAttempt(attempt, context) {
        governedAdmissionCalls.push({ attempt, context });
        return {
          source: "direct_governed_admission_api",
          backend: "l1_settlement_guard",
          thread_id: context.thread_id,
          agent_id: context.agent_id,
          settlement_admitted: true,
          record: {
            settlement_ref: attempt.settlement_ref,
            trigger_refs: attempt.trigger_refs,
            receipt_refs: attempt.receipt_refs,
          },
        };
      },
    },
  });

  const result = store.l1SettlementCore.admitAttempt(
    {
      settlement_ref: "settlement://direct",
      trigger_refs: ["trigger://direct"],
    },
    {
      thread_id: "thread_direct",
      agent_id: "agent_direct",
    },
  );

  assert.equal(calls.length, 0);
  const contextBudget = store.contextPolicyCore.evaluateContextBudgetPolicy({
    usage_telemetry: { total_tokens: 12 },
    mode: "monitor",
    thread_id: "thread_direct",
  });
  assert.equal(calls.length, 0);
  assert.equal(contextLifecycleCalls.length, 1);
  assert.equal(contextLifecycleCalls[0].method, "evaluateContextBudgetPolicy");
  assert.equal(contextLifecycleCalls[0].request.schema_version, "ioi.runtime.context-budget-policy-request.v1");
  assert.equal(Object.hasOwn(contextLifecycleCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(contextLifecycleCalls[0].request, "backend"), false);
  assert.equal(contextBudget.source, "direct_context_lifecycle_api");
  assert.deepEqual(contextBudget.policy_decision_refs, ["policy://direct-context-budget"]);
  const cancelPlan = store.contextPolicyCore.planRunCancelStateUpdate({
    run_id: "run_direct",
    run: { id: "run_direct", status: "running" },
    canceled_at: "2026-06-14T18:30:00.000Z",
  });
  assert.equal(calls.length, 0);
  assert.equal(runtimeControlCalls.length, 1);
  assert.equal(runtimeControlCalls[0].method, "planRunCancelStateUpdate");
  assert.equal(runtimeControlCalls[0].request.schema_version, "ioi.runtime.run-cancel-state-update-request.v1");
  assert.equal(Object.hasOwn(runtimeControlCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(runtimeControlCalls[0].request, "backend"), false);
  assert.equal(cancelPlan.source, "direct_runtime_control_api");
  assert.equal(cancelPlan.run.status, "canceled");
  const agentPlan = store.contextPolicyCore.planAgentCreateStateUpdate({
    agent: {
      id: "agent_direct",
      status: "active",
      createdAt: "2026-06-14T18:35:00.000Z",
      updatedAt: "2026-06-14T18:35:00.000Z",
    },
  });
  assert.equal(calls.length, 0);
  assert.equal(threadLifecycleCalls.length, 1);
  assert.equal(threadLifecycleCalls[0].method, "planAgentCreateStateUpdate");
  assert.equal(
    threadLifecycleCalls[0].request.schema_version,
    "ioi.runtime.agent-create-state-update-request.v1",
  );
  assert.equal(Object.hasOwn(threadLifecycleCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(threadLifecycleCalls[0].request, "backend"), false);
  assert.equal(agentPlan.source, "direct_thread_lifecycle_api");
  assert.equal(agentPlan.operation_kind, "agent.create");
  assert.equal(agentPlan.agent.id, "agent_direct");
  const workspaceTrustPlan = store.contextPolicyCore.planWorkspaceTrustControlStateUpdate({
    operation_kind: "workspace_trust.warning",
    thread_id: "thread_direct",
    event_stream_id: "thread_direct:events",
    agent: { id: "agent_direct", cwd: stateDir },
    controls: { mode: "review", approval_mode: "human_required" },
    event_id: "evt_workspace_trust_direct",
    created_at: "2026-06-14T18:36:00.000Z",
  });
  assert.equal(calls.length, 0);
  assert.equal(workspaceTrustCalls.length, 1);
  assert.equal(workspaceTrustCalls[0].method, "planWorkspaceTrustControlStateUpdate");
  assert.equal(
    workspaceTrustCalls[0].request.schema_version,
    "ioi.runtime.workspace-trust-control-state-update-request.v1",
  );
  assert.equal(Object.hasOwn(workspaceTrustCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(workspaceTrustCalls[0].request, "backend"), false);
  assert.equal(workspaceTrustPlan.source, "direct_workspace_trust_api");
  assert.equal(workspaceTrustPlan.event.event_kind, "workspace.trust_warning");
  const mcpStatus = store.contextPolicyCore.planMcpManagerStatusProjection({
    servers: [{ id: "mcp.docs", enabled: true }],
    tools: [{ stable_tool_id: "mcp.docs.search" }],
    resources: [],
    prompts: [],
    enabled_tools: [{ stable_tool_id: "mcp.docs.search" }],
  });
  assert.equal(calls.length, 0);
  assert.equal(mcpCalls.length, 1);
  assert.equal(mcpCalls[0].method, "planMcpManagerStatusProjection");
  assert.equal(
    mcpCalls[0].request.schema_version,
    "ioi.runtime.mcp-manager-status-projection-request.v1",
  );
  assert.equal(Object.hasOwn(mcpCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(mcpCalls[0].request, "backend"), false);
  assert.equal(mcpStatus.source, "direct_mcp_api");
  assert.equal(mcpStatus.server_count, 1);
  const invocationAdmission = store.modelMounting.admitModelMountInvocation({
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: "model-invocation://direct",
    route_decision_ref: "model_mount://route_decision/direct",
    route_receipt_ref: "receipt://route/direct",
    invocation_receipt_ref: "receipt://invocation/direct",
    receipt_refs: ["receipt://route/direct", "receipt://invocation/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "admitModelMountInvocation",
    "ioi.model_mount.invocation_admission.v1",
  );
  assert.equal(invocationAdmission.source, "direct_model_mount_api");
  assert.equal(invocationAdmission.invocation_admission_hash, "sha256:direct-invocation");
  const providerExecution = store.modelMounting.admitModelMountProviderExecution({
    schema_version: "ioi.model_mount.provider_execution.v1",
    invocation_ref: "model-provider-execution://direct",
    route_decision_ref: "model_mount://route_decision/direct",
    route_receipt_ref: "receipt://route/direct",
    request_hash: "sha256:direct-request",
    receipt_refs: ["receipt://route/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "admitModelMountProviderExecution",
    "ioi.model_mount.provider_execution.v1",
  );
  assert.equal(providerExecution.provider_execution_hash, "sha256:direct-provider-execution");
  const providerInvocation = store.modelMounting.executeModelMountProviderInvocation({
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: providerExecution.provider_execution_ref,
    provider_execution_hash: providerExecution.provider_execution_hash,
    provider_ref: "provider.local",
    provider_kind: "local_folder",
    execution_backend: "rust_model_mount_fixture",
    backend_ref: "backend.fixture",
    input: "hello",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "executeModelMountProviderInvocation",
    "ioi.model_mount.provider_invocation.v1",
  );
  assert.equal(providerInvocation.outputText, "direct provider invocation");
  const providerStream = store.modelMounting.executeModelMountProviderStreamInvocation({
    schema_version: "ioi.model_mount.provider_invocation.v1",
    provider_execution_ref: providerExecution.provider_execution_ref,
    provider_execution_hash: providerExecution.provider_execution_hash,
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    execution_backend: "rust_model_mount_native_local_stream",
    backend_ref: "backend.autopilot.native-local.fixture",
    stream_status: "started",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "executeModelMountProviderStreamInvocation",
    "ioi.model_mount.provider_invocation.v1",
  );
  assert.equal(providerStream.streamKind, "openai_responses_native_local");
  const providerLifecycle = store.modelMounting.planModelMountProviderLifecycle({
    schema_version: "ioi.model_mount.provider_lifecycle.v1",
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    action: "load",
    execution_backend: "rust_model_mount_native_local_lifecycle",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountProviderLifecycle",
    "ioi.model_mount.provider_lifecycle.v1",
  );
  assert.equal(providerLifecycle.lifecycle_hash, "sha256:direct-provider-lifecycle");
  const providerInventory = store.modelMounting.planModelMountProviderInventory({
    schema_version: "ioi.model_mount.provider_inventory.v1",
    provider_ref: "provider.autopilot.local",
    provider_kind: "ioi_native_local",
    action: "list_loaded",
    execution_backend: "rust_model_mount_native_local_inventory",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountProviderInventory",
    "ioi.model_mount.provider_inventory.v1",
  );
  assert.deepEqual(providerInventory.itemRefs, ["model_instance://native/direct"]);
  const instanceLifecycle = store.modelMounting.planModelMountInstanceLifecycle({
    schema_version: "ioi.model_mount.instance_lifecycle.v1",
    instance_ref: "model_instance://native/direct",
    provider_ref: "provider.autopilot.local",
    action: "load",
    execution_backend: "rust_model_mount_instance_lifecycle",
    driver: "native_local",
    backend_ref: "backend.autopilot.native-local.fixture",
    provider_lifecycle_hash: providerLifecycle.lifecycle_hash,
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountInstanceLifecycle",
    "ioi.model_mount.instance_lifecycle.v1",
  );
  assert.equal(instanceLifecycle.instance_lifecycle_hash, "sha256:direct-instance-lifecycle");
  const providerResult = store.modelMounting.admitModelMountProviderResult({
    schema_version: "ioi.model_mount.provider_result.v1",
    provider_execution_ref: providerExecution.provider_execution_ref,
    provider_execution_hash: providerExecution.provider_execution_hash,
    invocation_hash: providerStream.invocation_hash,
    execution_backend: "rust_model_mount_native_local_stream",
    output_hash: "sha256:direct-output",
    receipt_refs: ["receipt://invocation/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "admitModelMountProviderResult",
    "ioi.model_mount.provider_result.v1",
  );
  assert.equal(providerResult.provider_result_hash, "sha256:direct-provider-result");
  const artifactEndpointPlan = store.modelMounting.planArtifactEndpoint({
    schema_version: "ioi.model_mount.artifact_endpoint.v1",
    operation_kind: "model_mount.endpoint.mount",
    source: "runtime-daemon.model_mounting.artifact_endpoint",
    body: {
      model_id: "model.direct",
      provider_id: "provider.direct",
    },
    receipt_refs: ["receipt://artifact-endpoint/direct"],
    authority_grant_refs: ["grant://wallet/artifact-endpoint-direct"],
    authority_receipt_refs: ["receipt://wallet/artifact-endpoint-direct"],
    custody_ref: "ctee://custody/artifact-endpoint-direct",
    required_scope: "model.endpoint.mount:model.direct",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountArtifactEndpoint",
    "ioi.model_mount.artifact_endpoint.v1",
  );
  assert.equal(artifactEndpointPlan.source, "direct_model_mount_api");
  assert.equal(artifactEndpointPlan.record_id, "endpoint.direct");
  assert.equal(artifactEndpointPlan.rust_core_boundary, "model_mount.artifact_endpoint");
  const storagePlan = store.modelMounting.planStorageControl({
    schema_version: "ioi.model_mount.storage_control.v1",
    operation_kind: "model_mount.download.queue",
    source: "runtime-daemon.model_mounting.storage_control",
    body: {
      model_id: "local:direct",
      receipt_refs: ["receipt://storage/direct"],
    },
    receipt_refs: ["receipt://storage/direct"],
    authority_grant_refs: ["grant://wallet/storage-direct"],
    authority_receipt_refs: ["receipt://wallet/storage-direct"],
    required_scope: "model.download.queue:local:direct",
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountStorageControl",
    "ioi.model_mount.storage_control.v1",
  );
  assert.equal(storagePlan.source, "direct_model_mount_api");
  assert.equal(storagePlan.record_id, "download.direct");
  assert.equal(storagePlan.rust_core_boundary, "model_mount.storage_control");
  const mcpPlan = store.modelMounting.planModelMountMcpWorkflow({
    schema_version: "ioi.model_mount.mcp_workflow.v1",
    operation_kind: "model_mount.mcp_server.import",
    source: "runtime-daemon.model_mounting.mcp_workflow",
    body: {
      mcp_servers: {
        Direct: {
          url: "https://example.test/mcp",
          allowed_tools: ["search"],
        },
      },
    },
    receipt_refs: ["receipt://mcp/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountMcpWorkflow",
    "ioi.model_mount.mcp_workflow.v1",
  );
  assert.equal(mcpPlan.source, "direct_model_mount_api");
  assert.equal(mcpPlan.record_id, "mcp_import.direct");
  assert.equal(mcpPlan.rust_core_boundary, "model_mount.mcp_workflow");
  const serverPlan = store.modelMounting.planServerControl({
    schema_version: "ioi.model_mount.server_control.v1",
    operation_kind: "model_mount.server_control.start",
    source: "runtime-daemon.model_mounting.server_control",
    server_control_id: "server-control.direct",
    body: {
      base_url: "http://daemon.direct",
    },
    receipt_refs: ["receipt://server-control/direct"],
  });
  assert.equal(calls.length, 0);
  assertModelMountDirectApiCall(
    modelMountCalls.at(-1),
    "planModelMountServerControl",
    "ioi.model_mount.server_control.v1",
  );
  assert.equal(serverPlan.source, "direct_model_mount_api");
  assert.equal(serverPlan.record_id, "server-control.direct");
  assert.equal(serverPlan.rust_core_boundary, "model_mount.server_control");
  const memoryPlan = store.contextPolicyCore.planRuntimeMemoryControl({
    operation: "write",
    operation_kind: "memory.write",
    thread_id: "thread_direct",
    agent_id: "agent_direct",
    workspace_root: stateDir,
    state_dir: stateDir,
    request: { text: "direct memory" },
  });
  assert.equal(calls.length, 0);
  assert.equal(threadMemoryCalls.length, 1);
  assert.equal(threadMemoryCalls[0].method, "planRuntimeMemoryControl");
  assert.equal(
    threadMemoryCalls[0].request.schema_version,
    "ioi.runtime.memory-control-request.v1",
  );
  assert.equal(Object.hasOwn(threadMemoryCalls[0].request, "backend"), false);
  assert.notEqual(threadMemoryCalls[0].request.operation, "plan_runtime_memory_control");
  assert.equal(threadMemoryCalls[0].request.operation_kind, "memory.write");
  assert.equal(memoryPlan.source, "direct_thread_memory_api");
  assert.equal(memoryPlan.payload.id, "memory_direct");
  const queue = store.approvalStateCore.projectApprovalQueue({
    thread_id: "thread_direct",
    state_dir: stateDir,
  });
  assert.equal(calls.length, 0);
  assert.equal(approvalCalls.length, 1);
  assert.equal(approvalCalls[0].request.thread_id, "thread_direct");
  assert.equal(Object.hasOwn(approvalCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(approvalCalls[0].request, "backend"), false);
  assert.equal(queue.source, "direct_approval_api");
  assert.equal(queue.operation_kind, "approval.queue_projection");

  const commit = store.commitRuntimeRunState({
    schema_version: "ioi.runtime_run_state_commit.v1",
    run_id: "run_direct",
  });
  assert.equal(calls.length, 0);
  assert.equal(agentgresCalls.length, 1);
  assert.equal(agentgresCalls[0].method, "commitRuntimeRunState");
  assert.equal(agentgresCalls[0].request.state_dir, stateDir);
  assert.equal(agentgresCalls[0].request.request.run_id, "run_direct");
  assert.equal(Object.hasOwn(agentgresCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(agentgresCalls[0].request, "backend"), false);
  assert.equal(commit.source, "direct_agentgres_api");
  assert.equal(commit.commit_hash, "sha256:direct-agentgres-commit");

  assert.equal(governedAdmissionCalls.length, 1);
  assert.deepEqual(governedAdmissionCalls[0].context, {
    thread_id: "thread_direct",
    agent_id: "agent_direct",
  });
  assert.equal(Object.hasOwn(governedAdmissionCalls[0], "operation"), false);
  assert.equal(result.source, "direct_governed_admission_api");
  assert.equal(result.settlement_admitted, true);
  assert.equal(Object.hasOwn(result, "settlement_ref"), false);
  assert.equal(result.record.settlement_ref, "settlement://direct");
});
