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
  const daemonCoreModelMountApi = {
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
  };
  const directModelMountCore = createModelMountCore({
    daemonCoreInvoker: failCommandInvoker,
    daemonCoreModelMountApi,
  });
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountCore: {
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
  assert.equal(modelMountCalls.length, 1);
  assert.equal(modelMountCalls[0].method, "planModelMountStorageControl");
  assert.equal(modelMountCalls[0].request.schema_version, "ioi.model_mount.storage_control.v1");
  assert.equal(Object.hasOwn(modelMountCalls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(modelMountCalls[0].request, "backend"), false);
  assert.equal(storagePlan.source, "direct_model_mount_api");
  assert.equal(storagePlan.record_id, "download.direct");
  assert.equal(storagePlan.rust_core_boundary, "model_mount.storage_control");
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
