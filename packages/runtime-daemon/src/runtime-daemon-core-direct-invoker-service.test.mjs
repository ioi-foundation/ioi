import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("daemon-level typed APIs feed migrated daemon-core surfaces", () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-daemon-core-direct-"));
  const calls = [];
  const contextLifecycleCalls = [];
  const runtimeControlCalls = [];
  const agentgresCalls = [];
  const approvalCalls = [];
  const governedAdmissionCalls = [];
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
    },
    daemonCoreInvoker(request) {
      calls.push(request);
      throw new Error(`generic command invoker must not run migrated typed APIs: ${request?.operation}`);
    },
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
